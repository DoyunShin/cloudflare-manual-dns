"""Tests for the cfproxy.services layer (credential, token, oauth, audit).

Covers: credential register+verify, scoped-token mint (raw token returned
exactly once, only its hash persisted), rotate/revoke (version bump + Redis
cache invalidation), the CF OAuth callback happy path, and cross-user IDOR
protection across every id-addressed operation.
"""

import time
from uuid import uuid4

import httpx
import jwt as pyjwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import Response
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth import oauth_cf
from cfproxy.cache.redis import cache_get_json, cache_set_json, rules_key
from cfproxy.config import get_settings
from cfproxy.core.crypto import decrypt_secret, hash_token
from cfproxy.db.models import ScopedToken, User
from cfproxy.services import oauth_service
from cfproxy.services.audit_service import list_audit_logs, write_audit
from cfproxy.services.credential_service import (
    NotFoundError,
    delete_credential,
    get_owned_credential,
    list_credential_zones,
    list_credentials,
    register_credential,
    verify_credential,
)
from cfproxy.services.token_service import (
    get_scoped_token_detail,
    list_scoped_tokens,
    mint_scoped_token,
    revoke_scoped_token,
    rotate_scoped_token,
)

BASE_URL = get_settings().upstream_base_url
CF_KID = "test-signing-key-1"


async def _make_user(db_session: AsyncSession) -> User:
    """Create and persist a bare local user with a unique email."""
    user = User(email=f"user-{uuid4().hex}@example.com", auth_provider="local")
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user


def _record_ids_rule(**overrides) -> dict:
    """Build a minimal record_ids-pinned scope rule dict (no upstream zone lookup needed)."""
    rule = {
        "zone_id": "zone1",
        "record_ids": ["rec1"],
        "record_types": ["*"],
        "allow_read": True,
        "allow_create": False,
        "allow_write": False,
        "allow_delete": False,
    }
    rule.update(overrides)
    return rule


# ---------------------------------------------------------------------------
# credential_service: register + verify
# ---------------------------------------------------------------------------


async def test_register_credential_encrypts_secret(db_session: AsyncSession) -> None:
    """register_credential never stores the plaintext token."""
    user = await _make_user(db_session)

    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token-abc"
    )

    assert credential.secret_enc != "cf-plain-token-abc"
    assert decrypt_secret(credential.secret_enc) == "cf-plain-token-abc"


async def test_register_credential_global_key_stores_email_and_key(db_session: AsyncSession) -> None:
    """A global_key credential's secret_enc decrypts to a JSON {email, key} blob."""
    user = await _make_user(db_session)

    credential = await register_credential(
        db_session,
        user.id,
        label="legacy",
        cred_type="global_key",
        global_key="global-key-123",
        cf_account_email="ops@example.com",
    )

    assert credential.cf_account_email == "ops@example.com"
    assert "global-key-123" in decrypt_secret(credential.secret_enc)


async def test_register_credential_rejects_missing_secret(db_session: AsyncSession) -> None:
    """register_credential validates required fields at the boundary."""
    user = await _make_user(db_session)

    with pytest.raises(ValueError):
        await register_credential(db_session, user.id, label="prod", cred_type="token")


async def test_verify_credential_marks_active_on_success(
    db_session: AsyncSession, respx_mock
) -> None:
    """A successful upstream verify sets verify_status='active' and verified_at."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    respx_mock.get(f"{BASE_URL}/client/v4/user/tokens/verify").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [{"code": 10000, "message": "This API Token is valid."}],
                "result": {"id": "tok1", "status": "active"},
            },
        )
    )

    verified = await verify_credential(db_session, user.id, credential.id)

    assert verified.verify_status == "active"
    assert verified.verified_at is not None


async def test_verify_credential_marks_invalid_on_failure(
    db_session: AsyncSession, respx_mock
) -> None:
    """A failed upstream verify sets verify_status='invalid'."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="bad-token"
    )

    respx_mock.get(f"{BASE_URL}/client/v4/user/tokens/verify").mock(
        return_value=Response(
            401,
            json={
                "success": False,
                "errors": [{"code": 1000, "message": "Invalid API Token"}],
                "messages": [],
                "result": None,
            },
        )
    )

    verified = await verify_credential(db_session, user.id, credential.id)

    assert verified.verify_status == "invalid"


async def test_list_and_delete_credential_cascade_revokes_tokens(
    db_session: AsyncSession
) -> None:
    """delete_credential revokes every active dependent scoped token and bumps its version."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="dependent-token",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    assert len(await list_credentials(db_session, user.id)) == 1

    await delete_credential(db_session, user.id, credential.id)

    with pytest.raises(NotFoundError):
        await get_owned_credential(db_session, user.id, credential.id)

    row = (
        await db_session.execute(select(ScopedToken).where(ScopedToken.id == minted["id"]))
    ).scalar_one()
    assert row.status == "revoked"
    assert row.version == 2
    assert row.revoked_at is not None


async def test_list_credential_zones_caches_result(db_session: AsyncSession, respx_mock) -> None:
    """list_credential_zones serves a second call from cache without another HTTP request."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    route = respx_mock.get(f"{BASE_URL}/client/v4/zones").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": [{"id": "zone1", "name": "example.com"}],
                "result_info": {"page": 1, "per_page": 50, "count": 1, "total_count": 1, "total_pages": 1},
            },
        )
    )

    first = await list_credential_zones(db_session, user.id, credential.id)
    second = await list_credential_zones(db_session, user.id, credential.id)

    assert first == second == [{"id": "zone1", "name": "example.com"}]
    assert route.call_count == 1


# ---------------------------------------------------------------------------
# token_service: mint returns raw token once, stores only the hash
# ---------------------------------------------------------------------------


async def test_mint_scoped_token_returns_raw_once_and_persists_only_hash(
    db_session: AsyncSession, respx_mock
) -> None:
    """mint_scoped_token returns the full raw token, and only its hash is ever stored."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": {"id": "zone1", "name": "example.com"},
            },
        )
    )

    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="staging",
        upstream_credential_id=credential.id,
        scope_rules=[
            {
                "zone_id": "zone1",
                "name_pattern": "home.example.com",
                "name_match": "exact",
                "record_types": ["A"],
                "allow_read": True,
                "allow_create": True,
            }
        ],
    )

    assert minted["token"].startswith(f"{get_settings().token_brand}_")

    row = (
        await db_session.execute(select(ScopedToken).where(ScopedToken.id == minted["id"]))
    ).scalar_one()
    assert row.token_hash == hash_token(minted["token"])

    # The raw token must never appear anywhere on the persisted row.
    for column, value in vars(row).items():
        if column.startswith("_"):
            continue
        if isinstance(value, str):
            assert minted["token"] not in value


async def test_mint_scoped_token_rejects_rule_without_pattern_or_ids(
    db_session: AsyncSession
) -> None:
    """A scope rule with neither name_pattern nor record_ids is rejected."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    with pytest.raises(ValueError):
        await mint_scoped_token(
            db_session,
            user.id,
            name="bad",
            upstream_credential_id=credential.id,
            scope_rules=[{"zone_id": "zone1", "record_types": ["A"], "allow_read": True}],
        )


async def test_mint_scoped_token_record_ids_rule_skips_zone_lookup(
    db_session: AsyncSession
) -> None:
    """A record_ids-only rule never calls upstream (no respx route registered/needed)."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )

    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="pinned",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    assert minted["status"] == "active"
    assert minted["version"] == 1


async def test_get_scoped_token_detail_and_list(db_session: AsyncSession) -> None:
    """get_scoped_token_detail returns the token with its rules; list returns every owned token."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )
    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="detail-token",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    detail = await get_scoped_token_detail(db_session, user.id, minted["id"])
    assert detail.token.id == minted["id"]
    assert len(detail.rules) == 1
    assert detail.rules[0].zone_id == "zone1"

    listed = await list_scoped_tokens(db_session, user.id)
    assert [t.id for t in listed] == [minted["id"]]


# ---------------------------------------------------------------------------
# token_service: rotate/revoke bump version + invalidate Redis cache
# ---------------------------------------------------------------------------


async def test_rotate_scoped_token_bumps_version_and_invalidates_cache(
    db_session: AsyncSession
) -> None:
    """rotate_scoped_token issues a new token, bumps version, and invalidates the old cache key."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )
    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="rotate-me",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    row = (
        await db_session.execute(select(ScopedToken).where(ScopedToken.id == minted["id"]))
    ).scalar_one()
    old_lookup_id, old_version = row.lookup_id, row.version

    # Simulate a prior proxy request having warmed the version-keyed rules cache.
    await cache_set_json(rules_key(old_lookup_id, old_version), [{"zone_id": "zone1"}], 300)

    rotated = await rotate_scoped_token(db_session, user.id, minted["id"])

    assert rotated["token"] != minted["token"]
    assert rotated["version"] == old_version + 1

    await db_session.refresh(row)
    assert row.lookup_id != old_lookup_id
    assert row.version == old_version + 1
    assert row.token_hash == hash_token(rotated["token"])

    assert await cache_get_json(rules_key(old_lookup_id, old_version)) is None


async def test_revoke_scoped_token_bumps_version_and_invalidates_cache(
    db_session: AsyncSession
) -> None:
    """revoke_scoped_token marks the token revoked, bumps version, and invalidates the cache."""
    user = await _make_user(db_session)
    credential = await register_credential(
        db_session, user.id, label="prod", cred_type="token", api_token="cf-plain-token"
    )
    minted = await mint_scoped_token(
        db_session,
        user.id,
        name="revoke-me",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    row = (
        await db_session.execute(select(ScopedToken).where(ScopedToken.id == minted["id"]))
    ).scalar_one()
    lookup_id, old_version = row.lookup_id, row.version

    await cache_set_json(rules_key(lookup_id, old_version), [{"zone_id": "zone1"}], 300)

    await revoke_scoped_token(db_session, user.id, minted["id"])

    await db_session.refresh(row)
    assert row.status == "revoked"
    assert row.version == old_version + 1
    assert row.revoked_at is not None

    assert await cache_get_json(rules_key(lookup_id, old_version)) is None


# ---------------------------------------------------------------------------
# oauth_service: CF OAuth callback happy path
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    """Ensure the module-level JWKS cache never leaks between tests."""
    oauth_cf.clear_jwks_cache()
    yield
    oauth_cf.clear_jwks_cache()


@pytest.fixture
def oauth_settings(monkeypatch: pytest.MonkeyPatch):
    """Point oauth_cf at deterministic OAuth client settings for this test."""
    base = get_settings()
    overridden = base.model_copy(
        update={
            "cf_oauth_client_id": "test-client-id",
            "cf_oauth_client_secret": "test-client-secret",
            "cf_oauth_redirect_uri": "https://app.example.com/auth/cf/callback",
            "cf_oauth_issuer": "https://dash.cloudflare.com",
        }
    )
    monkeypatch.setattr(oauth_cf, "get_settings", lambda: overridden)
    monkeypatch.setattr(oauth_service, "get_settings", lambda: overridden)
    return overridden


def _build_jwks(public_key, kid: str) -> dict:
    """Build a JWKS document exposing a single RSA public key."""
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


async def test_oauth_callback_happy_path(
    db_session: AsyncSession, oauth_settings
) -> None:
    """A full login->callback round trip upserts the user, stores the oauth
    credential, and issues a valid session JWT."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwks = _build_jwks(public_key, CF_KID)

    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        mock.get("/.well-known/jwks.json").mock(return_value=httpx.Response(200, json=jwks))

        authorize_url = await oauth_service.start_cf_oauth_login()
        assert "state=" in authorize_url
        state = authorize_url.split("state=")[1].split("&")[0]

        stored = await cache_get_json(f"oauth_state:{state}")
        nonce = stored["nonce"]

        now = int(time.time())
        claims = {
            "iss": oauth_settings.cf_oauth_issuer,
            "aud": oauth_settings.cf_oauth_client_id,
            "sub": "cf-user-abc123",
            "email": "operator@example.com",
            "exp": now + 300,
            "iat": now,
            "nbf": now,
            "nonce": nonce,
        }
        id_token = pyjwt.encode(claims, private_key, algorithm="RS256", headers={"kid": CF_KID})

        token_response = {
            "access_token": "at-abc",
            "refresh_token": "rt-abc",
            "id_token": id_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "openid offline_access",
        }
        mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=token_response))

        user, session_jwt = await oauth_service.handle_cf_oauth_callback(
            db_session, code="auth-code-1", state=state
        )

    assert user.cf_sub == "cf-user-abc123"
    assert user.email == "operator@example.com"
    assert user.auth_provider == "cloudflare_oauth"
    assert session_jwt

    result = await db_session.execute(
        select(User).where(User.cf_sub == "cf-user-abc123")
    )
    persisted_user = result.scalar_one()
    assert persisted_user.id == user.id

    # The oauth state is single-use: replaying it must fail.
    with pytest.raises(ValueError):
        await oauth_service.handle_cf_oauth_callback(db_session, code="auth-code-2", state=state)


# ---------------------------------------------------------------------------
# Cross-user IDOR: user B cannot act on user A's credential or scoped token
# ---------------------------------------------------------------------------


async def test_idor_cross_user_credential_and_token_denied(
    db_session: AsyncSession, respx_mock
) -> None:
    """Every id-addressed operation raises NotFoundError for a non-owning user."""
    user_a = await _make_user(db_session)
    user_b = await _make_user(db_session)

    credential = await register_credential(
        db_session, user_a.id, label="prod", cred_type="token", api_token="secret-a"
    )

    with pytest.raises(NotFoundError):
        await get_owned_credential(db_session, user_b.id, credential.id)

    with pytest.raises(NotFoundError):
        await verify_credential(db_session, user_b.id, credential.id)

    with pytest.raises(NotFoundError):
        await delete_credential(db_session, user_b.id, credential.id)

    with pytest.raises(NotFoundError):
        await mint_scoped_token(
            db_session,
            user_b.id,
            name="cross-user",
            upstream_credential_id=credential.id,
            scope_rules=[_record_ids_rule()],
        )

    assert credential.id not in [c.id for c in await list_credentials(db_session, user_b.id)]

    minted = await mint_scoped_token(
        db_session,
        user_a.id,
        name="a-owns-this",
        upstream_credential_id=credential.id,
        scope_rules=[_record_ids_rule()],
    )

    with pytest.raises(NotFoundError):
        await get_scoped_token_detail(db_session, user_b.id, minted["id"])

    with pytest.raises(NotFoundError):
        await rotate_scoped_token(db_session, user_b.id, minted["id"])

    with pytest.raises(NotFoundError):
        await revoke_scoped_token(db_session, user_b.id, minted["id"])

    assert minted["id"] not in [t.id for t in await list_scoped_tokens(db_session, user_b.id)]

    # user A can still act on their own resources -- confirms the denial above
    # was ownership-based, not a general breakage.
    detail = await get_scoped_token_detail(db_session, user_a.id, minted["id"])
    assert detail.token.id == minted["id"]


# ---------------------------------------------------------------------------
# audit_service
# ---------------------------------------------------------------------------


async def test_write_and_list_audit_logs_scoped_by_user(db_session: AsyncSession) -> None:
    """write_audit persists a row; list_audit_logs is scoped by user_id and paginates."""
    user_a = await _make_user(db_session)
    user_b = await _make_user(db_session)

    await write_audit(
        db_session,
        user_id=user_a.id,
        method="GET",
        path="/client/v4/zones/zone1/dns_records",
        decision="allow",
        zone_id="zone1",
    )
    await write_audit(
        db_session,
        user_id=user_b.id,
        method="GET",
        path="/client/v4/zones/zone2/dns_records",
        decision="deny",
        zone_id="zone2",
        deny_reason="insufficient scope",
    )

    entries, result_info = await list_audit_logs(db_session, user_a.id)

    assert len(entries) == 1
    assert entries[0].zone_id == "zone1"
    assert result_info["total_count"] == 1
