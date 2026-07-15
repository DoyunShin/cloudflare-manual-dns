"""Tests for cfproxy.auth.oauth_cf (Cloudflare OAuth2/OIDC login helpers)."""

import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cfproxy.auth import oauth_cf
from cfproxy.config import get_settings

CF_KID = "test-signing-key-1"


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    """Ensure the module-level JWKS cache never leaks between tests."""
    oauth_cf.clear_jwks_cache()
    yield
    oauth_cf.clear_jwks_cache()


@pytest.fixture
def settings_override(monkeypatch: pytest.MonkeyPatch):
    """Point oauth_cf at deterministic OAuth client settings for this test."""
    base = get_settings()
    overridden = base.model_copy(
        update={
            "cf_oauth_client_id": "test-client-id",
            "cf_oauth_client_secret": "test-client-secret",
            "cf_oauth_redirect_uri": "https://app.example.com/auth/cf/callback",
            "cf_oauth_issuer": "https://dash.cloudflare.com",
            "upstream_base_url": "https://api.cloudflare.com",
            "access_token_skew": 60,
        }
    )
    monkeypatch.setattr(oauth_cf, "get_settings", lambda: overridden)
    return overridden


@pytest.fixture
def rsa_keypair():
    """Generate a fresh RSA keypair for signing test id_tokens."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def _build_jwks(public_key, kid: str) -> dict:
    """Build a JWKS document exposing a single RSA public key.

    Args:
        public_key: An RSA public key object.
        kid(str): The key id to publish.

    Return:
        jwks(dict): A JWKS document with one key.
    """
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


def _sign_id_token(private_key, kid: str, claims: dict) -> str:
    """Sign an id_token with the given RSA private key.

    Args:
        private_key: An RSA private key object.
        kid(str): The key id to place in the JWT header.
        claims(dict): The JWT payload claims.

    Return:
        token(str): The encoded RS256 JWT.
    """
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


def _base_claims(settings, nonce: str, **overrides) -> dict:
    """Build a valid baseline set of id_token claims.

    Args:
        settings: The Settings object whose issuer/client_id the claims target.
        nonce(str): The nonce claim to embed.
        **overrides: Claim overrides applied on top of the baseline.

    Return:
        claims(dict): The assembled claim set.
    """
    now = int(time.time())
    claims = {
        "iss": settings.cf_oauth_issuer,
        "aud": settings.cf_oauth_client_id,
        "sub": "cf-user-abc123",
        "exp": now + 300,
        "iat": now,
        "nbf": now,
        "nonce": nonce,
    }
    claims.update(overrides)
    return claims


def test_make_pkce_generates_valid_pair() -> None:
    """make_pkce returns a verifier and its correctly-derived S256 challenge."""
    verifier, challenge = oauth_cf.make_pkce()

    assert 43 <= len(verifier) <= 128
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected_challenge
    assert "=" not in challenge

    verifier2, challenge2 = oauth_cf.make_pkce()
    assert verifier != verifier2
    assert challenge != challenge2


def test_build_authorize_url_has_required_params(settings_override) -> None:
    """build_authorize_url points at the issuer with every required OAuth param."""
    url = oauth_cf.build_authorize_url(state="state-123", nonce="nonce-456", code_challenge="chal-789")

    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}" == settings_override.cf_oauth_issuer
    assert parts.path == "/oauth2/auth"

    params = parse_qs(parts.query)
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [settings_override.cf_oauth_client_id]
    assert params["redirect_uri"] == [settings_override.cf_oauth_redirect_uri]
    assert params["state"] == ["state-123"]
    assert params["nonce"] == ["nonce-456"]
    assert params["code_challenge"] == ["chal-789"]
    assert params["code_challenge_method"] == ["S256"]
    assert "openid" in params["scope"][0]
    assert "offline_access" in params["scope"][0]


async def test_exchange_code_parses_tokens(settings_override) -> None:
    """exchange_code POSTs to /oauth2/token and returns the parsed token response."""
    token_response = {
        "access_token": "at-abc",
        "refresh_token": "rt-abc",
        "id_token": "header.payload.sig",
        "token_type": "bearer",
        "expires_in": 3600,
    }

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        route = mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=token_response))

        result = await oauth_cf.exchange_code("auth-code-1", "verifier-1")

        assert result == token_response
        assert route.called
        sent_body = route.calls.last.request.content.decode()
        assert "grant_type=authorization_code" in sent_body
        assert "code=auth-code-1" in sent_body
        assert "code_verifier=verifier-1" in sent_body
        assert f"client_id={settings_override.cf_oauth_client_id}" in sent_body


async def test_refresh_access_token_parses_tokens(settings_override) -> None:
    """refresh_access_token POSTs a refresh_token grant and returns the parsed response."""
    token_response = {
        "access_token": "at-new",
        "refresh_token": "rt-rotated",
        "token_type": "bearer",
        "expires_in": 3600,
    }

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        route = mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=token_response))

        result = await oauth_cf.refresh_access_token("rt-abc")

        assert result == token_response
        sent_body = route.calls.last.request.content.decode()
        assert "grant_type=refresh_token" in sent_body
        assert "refresh_token=rt-abc" in sent_body


async def test_fetch_userinfo_sends_bearer_and_parses(settings_override) -> None:
    """fetch_userinfo sends the access token as a Bearer header and returns the JSON body."""
    userinfo = {"sub": "cf-user-abc123"}

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        route = mock.get("/oauth2/userinfo").mock(return_value=httpx.Response(200, json=userinfo))

        result = await oauth_cf.fetch_userinfo("at-abc")

        assert result == userinfo
        assert route.calls.last.request.headers["authorization"] == "Bearer at-abc"


async def test_discover_dns_scope_returns_list(settings_override) -> None:
    """discover_dns_scope GETs the CF scopes endpoint and returns scope literal names."""
    body = {
        "success": True,
        "errors": [],
        "messages": [],
        "result": ["com.cloudflare.api.account.zone.dns_records.edit", "com.cloudflare.api.account.zone.read"],
    }

    async with respx.mock(base_url="https://api.cloudflare.com") as mock:
        mock.get("/client/v4/oauth/scopes").mock(return_value=httpx.Response(200, json=body))

        scopes = await oauth_cf.discover_dns_scope()

        assert scopes == body["result"]


async def test_validate_id_token_accepts_valid_token(settings_override, rsa_keypair) -> None:
    """A correctly-signed id_token with matching iss/aud/nonce/alg passes validation."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-valid"
    claims = _base_claims(settings_override, nonce)
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        result = await oauth_cf.validate_id_token(token, nonce)

    assert result["sub"] == "cf-user-abc123"
    assert result["nonce"] == nonce


async def test_validate_id_token_rejects_bad_issuer(settings_override, rsa_keypair) -> None:
    """An id_token with the wrong iss claim is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-1"
    claims = _base_claims(settings_override, nonce, iss="https://evil.example.com")
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(token, nonce)


async def test_validate_id_token_rejects_bad_audience(settings_override, rsa_keypair) -> None:
    """An id_token with the wrong aud claim is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-1"
    claims = _base_claims(settings_override, nonce, aud="some-other-client")
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(token, nonce)


async def test_validate_id_token_rejects_bad_nonce(settings_override, rsa_keypair) -> None:
    """An id_token whose nonce claim does not match the stored nonce is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    claims = _base_claims(settings_override, "nonce-that-was-sent")
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(token, "nonce-attacker-supplied")


async def test_validate_id_token_rejects_alg_none(settings_override, rsa_keypair) -> None:
    """An unsigned id_token asserting alg=none is rejected before any JWKS lookup."""
    _private_key, public_key = rsa_keypair
    nonce = "nonce-1"
    claims = _base_claims(settings_override, nonce)

    header_b64 = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    import json as _json

    payload_b64 = base64.urlsafe_b64encode(_json.dumps(claims).encode()).rstrip(b"=").decode()
    forged_token = f"{header_b64}.{payload_b64}."

    async with respx.mock(base_url="https://dash.cloudflare.com", assert_all_called=False) as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=_build_jwks(public_key, CF_KID)))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(forged_token, nonce)


def _expected_hash(value: str) -> str:
    """Compute the expected OIDC left-half hash the same way the code does (RS256/sha256).

    Args:
        value(str): The access token or authorization code to hash.

    Return:
        half_hash(str): The base64url (unpadded) left-half SHA-256 digest.
    """
    digest = hashlib.sha256(value.encode("ascii")).digest()
    half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(half).rstrip(b"=").decode("ascii")


async def test_validate_id_token_accepts_matching_at_hash_and_c_hash(
    settings_override, rsa_keypair
) -> None:
    """A valid id_token whose at_hash/c_hash match the access token/code is accepted."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-athash"
    access_token = "at-real-access-token"
    code = "auth-code-real"
    claims = _base_claims(
        settings_override,
        nonce,
        at_hash=_expected_hash(access_token),
        c_hash=_expected_hash(code),
    )
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        result = await oauth_cf.validate_id_token(
            token, nonce, access_token=access_token, code=code
        )

    assert result["sub"] == "cf-user-abc123"


async def test_validate_id_token_rejects_wrong_at_hash(settings_override, rsa_keypair) -> None:
    """An id_token whose at_hash does not match the supplied access token is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-badathash"
    claims = _base_claims(settings_override, nonce, at_hash=_expected_hash("some-other-token"))
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(
                token, nonce, access_token="at-real-access-token", code=None
            )


async def test_validate_id_token_rejects_at_hash_without_access_token(
    settings_override, rsa_keypair
) -> None:
    """An id_token carrying at_hash with no access_token supplied to verify it is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-noaccesstoken"
    claims = _base_claims(settings_override, nonce, at_hash=_expected_hash("at-real-access-token"))
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(token, nonce, access_token=None, code=None)


async def test_validate_id_token_rejects_wrong_c_hash(settings_override, rsa_keypair) -> None:
    """An id_token whose c_hash does not match the supplied authorization code is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-badchash"
    claims = _base_claims(settings_override, nonce, c_hash=_expected_hash("some-other-code"))
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(
                token, nonce, access_token=None, code="auth-code-real"
            )


async def test_validate_id_token_rejects_expired(settings_override, rsa_keypair) -> None:
    """An id_token whose exp claim is in the past is rejected."""
    private_key, public_key = rsa_keypair
    jwks = _build_jwks(public_key, CF_KID)
    nonce = "nonce-1"
    now = int(time.time())
    claims = _base_claims(settings_override, nonce, exp=now - 3600, iat=now - 7200, nbf=now - 7200)
    token = _sign_id_token(private_key, CF_KID, claims)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        with pytest.raises(jwt.InvalidTokenError):
            await oauth_cf.validate_id_token(token, nonce)
