"""Security and lifecycle tests for generic OIDC authentication."""

import base64
import hashlib
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import Response
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from sqlalchemy import select

from cfproxy.auth import oidc
from cfproxy.core.crypto import encrypt_secret
from cfproxy.core.security import MANAGEMENT_SESSION_COOKIE, hash_session_token
from cfproxy.db.models import ManagementSession, OIDCConfig, User
from cfproxy.main import create_app
from cfproxy.services import oidc_service


def _client_config(issuer: str = "https://id.example.com/realm/") -> oidc.OIDCClientConfig:
    """Build deterministic generic OIDC client settings."""
    return oidc.OIDCClientConfig(
        issuer=issuer,
        client_id="cfproxy-client",
        client_secret="client-secret",
        scopes="openid profile email",
        redirect_uri="https://app.example.com/api/v1/auth/oidc/callback",
    )


def _rsa_material() -> tuple[object, dict]:
    """Return an RSA private key and matching signing JWKS."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    public_jwk.update({"kid": "key-1", "use": "sig", "alg": "RS256"})
    return private_key, {"keys": [public_jwk]}


def _metadata(config: oidc.OIDCClientConfig, *, userinfo: bool = False) -> dict:
    """Build valid discovery metadata for a test provider."""
    value = {
        "issuer": config.issuer,
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
        "jwks_uri": "https://id.example.com/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    if userinfo:
        value["userinfo_endpoint"] = "https://id.example.com/userinfo"
    return value


def _claims(config: oidc.OIDCClientConfig, nonce: str, **overrides) -> dict:
    """Build baseline valid ID token claims."""
    now = int(time.time())
    value = {
        "iss": config.issuer,
        "aud": config.client_id,
        "sub": "subject-1",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
    }
    value.update(overrides)
    return value


def test_issuer_identity_preserves_a_legal_trailing_slash() -> None:
    """Issuer normalization does not change a legal, case-sensitive identity URI."""
    issuer = "https://id.example.com/realm/"
    assert oidc.normalize_issuer(issuer) == issuer
    assert oidc.discovery_url(issuer) == "https://id.example.com/realm/.well-known/openid-configuration"


@pytest.mark.parametrize("address", ["::ffff:127.0.0.1", "::ffff:169.254.169.254"])
def test_mapped_ipv4_loopback_and_metadata_are_always_blocked(address: str) -> None:
    """IPv4-mapped IPv6 syntax cannot bypass endpoint network restrictions."""
    assert oidc._is_blocked_address(address, allow_private_network=True)


def test_cgnat_is_blocked_without_private_network_opt_in() -> None:
    """Non-global CGNAT destinations require explicit private-network opt-in."""
    assert oidc._is_blocked_address("100.64.0.1", allow_private_network=False)


def test_ipv6_site_local_requires_private_network_opt_in() -> None:
    """Deprecated site-local IPv6 space is not treated as a public endpoint."""
    assert oidc._is_blocked_address("fec0::1", allow_private_network=False)
    assert not oidc._is_blocked_address("fec0::1", allow_private_network=True)


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_validate_id_token_accepts_supported_signatures_and_hashes(algorithm: str) -> None:
    """Supported asymmetric signatures bind the access token and authorization code."""
    config = _client_config()
    if algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_jwk = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        public_jwk.update({"kid": "key-1", "use": "sig", "alg": algorithm})
        jwks = {"keys": [public_jwk]}
    else:
        private_key, jwks = _rsa_material()
        jwks["keys"][0]["alg"] = algorithm
    metadata = _metadata(config)
    metadata["id_token_signing_alg_values_supported"] = [algorithm]
    access_token = "access-token"
    code = "authorization-code"
    access_hash = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest()[:16]).rstrip(b"=").decode("ascii")
    code_hash = base64.urlsafe_b64encode(hashlib.sha256(code.encode("ascii")).digest()[:16]).rstrip(b"=").decode("ascii")
    token = jwt.encode(
        _claims(config, "nonce-1", at_hash=access_hash, c_hash=code_hash),
        private_key,
        algorithm=algorithm,
        headers={"kid": "key-1"},
    )
    claims = oidc.validate_id_token(
        token, metadata, jwks, config, "nonce-1", access_token=access_token, code=code
    )
    assert claims["sub"] == "subject-1"
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, metadata, jwks, config, "nonce-1", access_token="wrong", code=code)
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, metadata, jwks, config, "nonce-1", access_token=access_token, code="wrong")


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example.com/realm/"},
        {"aud": "other-client"},
        {"nonce": "wrong"},
        {"nonce": "잘못된-nonce"},
        {"exp": 1},
        {"iat": 4102444800},
    ],
)
def test_validate_id_token_rejects_invalid_identity_and_time_claims(overrides: dict) -> None:
    """Valid signatures cannot bypass identity, replay, or token lifetime checks."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    claims = _claims(config, "nonce-1")
    claims.update(overrides)
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, _metadata(config), jwks, config, "nonce-1")


@pytest.mark.parametrize("algorithm", ["RS256", "HS256", "none"])
def test_validate_id_token_rejects_wrong_key_and_algorithm_confusion(algorithm: str) -> None:
    """Wrong asymmetric keys, symmetric signatures, and unsigned tokens are rejected."""
    config = _client_config()
    _, jwks = _rsa_material()
    if algorithm == "RS256":
        key, _ = _rsa_material()
    elif algorithm == "HS256":
        key = "attacker-controlled-signing-secret"
    else:
        key = None
    token = jwt.encode(_claims(config, "nonce-1"), key, algorithm=algorithm, headers={"kid": "key-1"})
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, _metadata(config), jwks, config, "nonce-1")


def test_validate_id_token_rejects_multi_audience_without_matching_azp() -> None:
    """A multi-audience token must explicitly name this client as authorized party."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    token = jwt.encode(
        _claims(config, "nonce-1", aud=[config.client_id, "other"], azp="other"),
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, _metadata(config), jwks, config, "nonce-1")


def test_validate_id_token_rejects_missing_subject() -> None:
    """An otherwise valid token without sub cannot identify a service user."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    claims = _claims(config, "nonce-1")
    del claims["sub"]
    token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "key-1"})
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, _metadata(config), jwks, config, "nonce-1")


def test_validate_id_token_rejects_malformed_algorithm_metadata_without_crashing() -> None:
    """Non-string signing algorithm metadata produces a controlled token error."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    token = jwt.encode(
        _claims(config, "nonce-1"), private_key, algorithm="RS256", headers={"kid": "key-1"}
    )
    metadata = _metadata(config)
    metadata["id_token_signing_alg_values_supported"] = [{"alg": "RS256"}]
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(token, metadata, jwks, config, "nonce-1")


def test_validate_id_token_rejects_non_string_hash_source_without_crashing() -> None:
    """Malformed token endpoint fields cannot raise an unhandled hash exception."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    token = jwt.encode(
        _claims(config, "nonce-1", at_hash="invalid"),
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(
            token, _metadata(config), jwks, config, "nonce-1", access_token=123
        )


def test_validate_id_token_rejects_non_ascii_hash_source_without_crashing() -> None:
    """A non-ASCII token endpoint value produces a controlled token error."""
    config = _client_config()
    private_key, jwks = _rsa_material()
    token = jwt.encode(
        _claims(config, "nonce-1", at_hash="invalid"),
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    with pytest.raises(oidc.OIDCTokenError):
        oidc.validate_id_token(
            token, _metadata(config), jwks, config, "nonce-1", access_token="비ASCII"
        )


async def test_userinfo_subject_must_match_id_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """UserInfo cannot substitute a different identity after ID token validation."""
    async def fake_get_json(*args, **kwargs) -> dict:
        return {"sub": "attacker", "email": "attacker@example.com"}

    monkeypatch.setattr(oidc, "_get_json", fake_get_json)
    config = _client_config()
    with pytest.raises(oidc.OIDCTokenError):
        await oidc.fetch_userinfo(_metadata(config, userinfo=True), config, "access", "subject-1")


async def _configure_provider(db_session) -> OIDCConfig:
    """Enable the singleton provider for service lifecycle tests."""
    config = await db_session.get(OIDCConfig, 1)
    config.label = "Company SSO"
    config.issuer = "https://id.example.com/realm"
    config.client_id = "cfproxy-client"
    config.client_secret_enc = encrypt_secret("client-secret")
    config.scopes = "openid profile email"
    config.enabled = True
    config.revision = 4
    config.allowed_endpoint_origins = []
    await db_session.commit()
    return config


async def _install_callback_stubs(monkeypatch: pytest.MonkeyPatch, claims: dict) -> None:
    """Replace provider I/O while retaining state, identity, and session logic."""
    async def fake_discovery(config) -> dict:
        return _metadata(_client_config(issuer=config.issuer))

    async def fake_exchange(metadata, config, code, verifier) -> dict:
        return {"id_token": "signed-token", "access_token": "unused-access"}

    async def fake_jwks(metadata, config) -> dict:
        return {"keys": []}

    monkeypatch.setattr(oidc_service, "fetch_discovery", fake_discovery)
    monkeypatch.setattr(oidc_service, "exchange_code", fake_exchange)
    monkeypatch.setattr(oidc_service, "fetch_jwks", fake_jwks)
    monkeypatch.setattr(oidc_service, "validate_id_token", lambda *args, **kwargs: claims)


async def _store_callback_state(revision: int, state: str, binding: str) -> None:
    """Store one browser-bound callback state record."""
    await oidc_service._store_state(
        state,
        {
            "verifier": "verifier",
            "nonce": "nonce",
            "browser_binding_hash": oidc_service._binding_hash(binding),
            "provider_revision": revision,
        },
    )


async def test_oidc_jit_user_is_non_admin_and_external_roles_are_ignored(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    """First login creates an active ordinary user regardless of external role claims."""
    config = await _configure_provider(db_session)
    claims = {
        "sub": "subject-1",
        "email": "operator@example.com",
        "name": "Operator",
        "roles": ["admin"],
        "groups": ["administrators"],
    }
    await _install_callback_stubs(monkeypatch, claims)
    await _store_callback_state(config.revision, "state-1", "browser-1")
    response = Response()

    user = await oidc_service.complete_oidc_login(
        db_session, response, "code", "state-1", "browser-1"
    )

    assert user.auth_provider == "oidc"
    assert user.is_active is True
    assert user.is_admin is False
    assert user.oidc_issuer == config.issuer
    assert user.oidc_sub == "subject-1"
    assert "__Host-cfproxy_session=" in response.headers["set-cookie"]


async def test_oidc_profile_refresh_preserves_local_admin_permission(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    """OIDC profile updates never reset locally managed authorization fields."""
    config = await _configure_provider(db_session)
    user = User(
        auth_provider="oidc",
        oidc_issuer=config.issuer,
        oidc_sub="subject-1",
        email="old@example.com",
        display_name="Old Name",
        is_active=True,
        is_admin=True,
    )
    db_session.add(user)
    await db_session.commit()
    await _install_callback_stubs(
        monkeypatch,
        {"sub": "subject-1", "email": "new@example.com", "name": "New Name", "roles": []},
    )
    await _store_callback_state(config.revision, "state-2", "browser-2")

    authenticated = await oidc_service.complete_oidc_login(
        db_session, Response(), "code", "state-2", "browser-2"
    )

    assert authenticated.id == user.id
    assert authenticated.email == "new@example.com"
    assert authenticated.display_name == "New Name"
    assert authenticated.is_admin is True
    assert authenticated.is_active is True


async def test_oidc_state_is_browser_bound_and_single_use(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    """A stolen or replayed state value cannot complete authentication."""
    config = await _configure_provider(db_session)
    await _install_callback_stubs(monkeypatch, {"sub": "subject-1"})
    await _store_callback_state(config.revision, "state-3", "browser-3")

    with pytest.raises(oidc_service.OIDCStateError):
        await oidc_service.complete_oidc_login(
            db_session, Response(), "code", "state-3", "attacker-browser"
        )
    with pytest.raises(oidc_service.OIDCStateError):
        await oidc_service.complete_oidc_login(
            db_session, Response(), "code", "state-3", "browser-3"
        )


async def test_admin_config_requires_initial_secret_and_never_returns_it(db_session) -> None:
    """The initialized empty singleton cannot be enabled without a new secret."""
    value = oidc_service.OIDCConfigInput(
        enabled=True,
        label="Company SSO",
        issuer="https://id.example.com/realm",
        client_id="cfproxy-client",
        client_secret=None,
    )
    with pytest.raises(oidc.OIDCConfigurationError):
        await oidc_service.save_oidc_config(db_session, value)

    saved = await oidc_service.save_oidc_config(
        db_session,
        oidc_service.OIDCConfigInput(
            **{**value.__dict__, "client_secret": "secret-value"}
        ),
    )
    payload = oidc_service.config_response(saved)
    assert payload["has_secret"] is True
    assert "client_secret" not in payload
    assert "secret-value" not in str(payload)


async def test_admin_config_save_rejects_stale_oidc_admin_session(db_session) -> None:
    """A provider revision race cannot let an invalidated OIDC session save settings."""
    config = await _configure_provider(db_session)
    admin = User(
        auth_provider="oidc",
        oidc_issuer=config.issuer,
        oidc_sub="admin-subject",
        is_active=True,
        is_admin=True,
    )
    db_session.add(admin)
    await db_session.flush()
    management_session = ManagementSession(
        token_hash="d" * 64,
        user_id=admin.id,
        auth_method="oidc",
        provider_revision=config.revision - 1,
        csrf_secret="csrf",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(management_session)
    await db_session.commit()
    original_revision = config.revision

    with pytest.raises(oidc_service.OIDCAdminSessionError):
        await oidc_service.save_oidc_config(
            db_session,
            oidc_service.OIDCConfigInput(
                enabled=True,
                label="Changed",
                issuer=config.issuer,
                client_id=config.client_id,
                client_secret=None,
            ),
            actor_id=admin.id,
            actor_session_id=management_session.id,
        )
    await db_session.rollback()
    await db_session.refresh(config)
    assert config.revision == original_revision


async def _persist_http_session(db_session, user: User, raw_token: str, csrf_token: str) -> None:
    """Persist a local management session for HTTP authorization tests."""
    db_session.add(
        ManagementSession(
            token_hash=hash_session_token(raw_token),
            user_id=user.id,
            auth_method="local",
            csrf_secret=csrf_token,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
    )
    await db_session.commit()


async def test_oidc_admin_http_boundaries_and_public_config(db_session, async_client_factory) -> None:
    """HTTP configuration routes expose only public data and enforce admin CSRF checks."""
    ordinary = User(email="ordinary@example.com", auth_provider="oidc", is_active=True)
    admin = User(
        local_login="admin@example.com",
        email="admin@example.com",
        auth_provider="local",
        is_active=True,
        is_admin=True,
    )
    db_session.add_all([ordinary, admin])
    await db_session.flush()
    await _persist_http_session(db_session, ordinary, "ordinary-session", "ordinary-csrf")
    await _persist_http_session(db_session, admin, "admin-session", "admin-csrf")
    payload = {
        "enabled": True,
        "label": "Company SSO",
        "issuer": "https://id.example.com/realm",
        "client_id": "cfproxy-client",
        "client_secret": "client-secret",
        "scopes": "openid profile email",
        "allowed_endpoint_origins": [],
        "allow_private_network": False,
    }

    async with async_client_factory(create_app()) as client:
        public_before = await client.get("/api/v1/auth/oidc")
        unauthenticated_admin = await client.get("/api/v1/admin/oidc")
        client.cookies.set(MANAGEMENT_SESSION_COOKIE, "ordinary-session")
        non_admin = await client.get("/api/v1/admin/oidc")

        client.cookies.set(MANAGEMENT_SESSION_COOKIE, "admin-session")
        missing_csrf = await client.put("/api/v1/admin/oidc", json=payload)
        saved = await client.put(
            "/api/v1/admin/oidc",
            json=payload,
            headers={"Origin": "https://testserver", "X-CSRF-Token": "admin-csrf"},
        )
        public_after = await client.get("/api/v1/auth/oidc")

    assert public_before.status_code == 200
    assert set(public_before.json()["data"]) == {"enabled", "label"}
    assert unauthenticated_admin.status_code == 401
    assert non_admin.status_code == 403
    assert missing_csrf.status_code == 403
    assert saved.status_code == 200
    assert saved.json()["data"]["has_secret"] is True
    assert "client_secret" not in saved.json()["data"]
    assert public_after.status_code == 200
    assert public_after.json()["data"] == {"enabled": True, "label": "Company SSO"}


async def test_oidc_http_pkce_callback_issues_ordinary_service_session(db_session, async_client_factory, monkeypatch: pytest.MonkeyPatch) -> None:
    """The HTTP PKCE callback creates a non-admin session and ignores external roles."""
    await _configure_provider(db_session)
    await _install_callback_stubs(
        monkeypatch,
        {
            "sub": "http-subject",
            "email": "http-user@example.com",
            "name": "HTTP User",
            "roles": ["admin"],
            "groups": ["administrators"],
        },
    )

    async with async_client_factory(create_app()) as client:
        login = await client.get("/api/v1/auth/oidc/login", follow_redirects=False)
        authorize = urlsplit(login.headers["location"])
        authorize_query = parse_qs(authorize.query)
        callback = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": "authorization-code", "state": authorize_query["state"][0]},
            follow_redirects=False,
        )
        me = await client.get("/api/v1/auth/me")

    assert login.status_code == 302
    assert authorize_query["response_type"] == ["code"]
    assert authorize_query["code_challenge_method"] == ["S256"]
    assert authorize_query["code_challenge"][0]
    assert authorize_query["nonce"][0]
    assert callback.status_code == 302
    assert callback.headers["location"] == "https://testserver/"
    assert me.status_code == 200
    assert me.json()["data"]["user"]["email"] == "http-user@example.com"
    assert me.json()["data"]["user"]["is_admin"] is False
    assert me.json()["data"]["user"]["is_active"] is True
