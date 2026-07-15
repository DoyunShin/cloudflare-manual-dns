"""Tests for scoped-token resolution (`cfproxy.auth.proxy_auth`)."""

from datetime import datetime, timedelta, UTC
from uuid import uuid4

import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.proxy_auth import ProxyAuthContext, require_scoped_token, resolve_scoped_token
from cfproxy.cache.redis import rules_key
from cfproxy.core.crypto import generate_scoped_token
from cfproxy.db.models import ScopedToken, ScopeRule, UpstreamCredential, User
from cfproxy.db.session import get_session


async def _make_scoped_token(
    db_session: AsyncSession,
    *,
    status: str = "active",
    expires_at: datetime | None = None,
    version: int = 1,
) -> tuple[ScopedToken, str, UpstreamCredential]:
    """Create a user, credential, and scoped token row for test fixtures.

    Return:
        row(tuple[ScopedToken, str, UpstreamCredential]): The persisted
            `ScopedToken`, the full plaintext token string, and the
            persisted `UpstreamCredential`.
    """
    user = User(email=f"user-{uuid4().hex}@example.com", auth_provider="local")
    db_session.add(user)
    await db_session.flush()

    credential = UpstreamCredential(
        user_id=user.id,
        label="primary",
        cred_type="token",
        secret_enc="encrypted-secret",
    )
    db_session.add(credential)
    await db_session.flush()

    generated = generate_scoped_token()
    scoped_token = ScopedToken(
        user_id=user.id,
        upstream_credential_id=credential.id,
        name="test token",
        lookup_id=generated["lookup_id"],
        token_prefix=generated["token_prefix"],
        token_hash=generated["token_hash"],
        version=version,
        status=status,
        expires_at=expires_at,
    )
    db_session.add(scoped_token)
    await db_session.flush()
    await db_session.commit()

    return scoped_token, generated["full"], credential


async def _add_rule(db_session: AsyncSession, scoped_token: ScopedToken, **overrides) -> ScopeRule:
    """Attach a `ScopeRule` row to a scoped token.

    Return:
        rule(ScopeRule): The persisted rule row.
    """
    defaults = dict(
        scoped_token_id=scoped_token.id,
        zone_id="zone1",
        name_pattern="home.example.com",
        name_match="exact",
        record_types=["A"],
        record_ids=None,
        allow_read=True,
        allow_create=False,
        allow_write=False,
        allow_delete=False,
    )
    defaults.update(overrides)
    rule = ScopeRule(**defaults)
    db_session.add(rule)
    await db_session.flush()
    await db_session.commit()
    return rule


@pytest.mark.asyncio
async def test_resolve_valid_token_returns_context_with_rules_and_credential(
    db_session: AsyncSession, fake_redis
) -> None:
    """A valid, active, non-expired token resolves with its rules and credential."""
    scoped_token, full_token, credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token)

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert isinstance(context, ProxyAuthContext)
    assert context.token.id == scoped_token.id
    assert context.credential.id == credential.id
    assert len(context.rules) == 1
    assert context.rules[0].zone_id == "zone1"
    assert context.rules[0].name_pattern == "home.example.com"
    assert context.rules[0].allow_read is True


@pytest.mark.asyncio
async def test_resolve_malformed_token_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A malformed token string is rejected without touching the database."""
    context = await resolve_scoped_token(db_session, "not-a-valid-token", fake_redis)
    assert context is None


@pytest.mark.asyncio
async def test_resolve_wrong_secret_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A token with the correct lookup_id but a tampered secret is rejected."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    brand, lookup_id, _secret = full_token.split("_")
    tampered = f"{brand}_{lookup_id}_{'z' * 40}"

    context = await resolve_scoped_token(db_session, tampered, fake_redis)

    assert context is None


@pytest.mark.asyncio
async def test_resolve_unknown_lookup_id_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A well-formed token whose lookup_id has no matching row is rejected."""
    generated = generate_scoped_token()
    context = await resolve_scoped_token(db_session, generated["full"], fake_redis)
    assert context is None


@pytest.mark.asyncio
async def test_resolve_revoked_token_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A token whose status is not 'active' is rejected."""
    _scoped_token, full_token, _credential = await _make_scoped_token(
        db_session, status="revoked"
    )

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert context is None


@pytest.mark.asyncio
async def test_resolve_expired_token_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A token past its expires_at is rejected."""
    _scoped_token, full_token, _credential = await _make_scoped_token(
        db_session, expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert context is None


@pytest.mark.asyncio
async def test_resolve_future_expiry_still_valid(db_session: AsyncSession, fake_redis) -> None:
    """A token with an expires_at in the future is still accepted."""
    scoped_token, full_token, _credential = await _make_scoped_token(
        db_session, expires_at=datetime.now(UTC) + timedelta(days=1)
    )
    await _add_rule(db_session, scoped_token)

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert context is not None
    assert context.token.id == scoped_token.id


@pytest.mark.asyncio
async def test_resolve_caches_rules_in_redis(db_session: AsyncSession, fake_redis) -> None:
    """Resolving a token populates the version-keyed Redis rules cache."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token)

    await resolve_scoped_token(db_session, full_token, fake_redis)

    cached = await fake_redis.get(rules_key(scoped_token.lookup_id, scoped_token.version))
    assert cached is not None


@pytest.mark.asyncio
async def test_resolve_version_bump_invalidates_cache(
    db_session: AsyncSession, fake_redis
) -> None:
    """Bumping a token's version reaches a fresh cache key, never serving the
    stale rules cached under the old version."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session, version=1)
    await _add_rule(db_session, scoped_token, allow_read=True, allow_write=False)

    first_context = await resolve_scoped_token(db_session, full_token, fake_redis)
    assert first_context.rules[0].allow_write is False

    # Simulate a rule-set change that bumps the token's version (as revoke,
    # rotate, or a rule edit would in the management API), without deleting
    # the previously-cached entry.
    existing_rule = (
        await db_session.execute(
            select(ScopeRule).where(ScopeRule.scoped_token_id == scoped_token.id)
        )
    ).scalar_one()
    existing_rule.allow_write = True
    scoped_token.version = 2
    await db_session.commit()

    second_context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert second_context is not None
    assert second_context.rules[0].allow_write is True

    # The old version's cache entry is still present (best-effort, no
    # explicit invalidation), but it is no longer reachable because the key
    # is derived from the current version.
    old_cached = await fake_redis.get(rules_key(scoped_token.lookup_id, 1))
    assert old_cached is not None


@pytest.mark.asyncio
async def test_resolve_uses_cached_rules_on_second_call(
    db_session: AsyncSession, fake_redis
) -> None:
    """A second resolution for the same version reads rules from cache, not
    the database (verified by mutating the DB row without bumping version)."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_read=True)

    await resolve_scoped_token(db_session, full_token, fake_redis)

    rule = (
        await db_session.execute(
            select(ScopeRule).where(ScopeRule.scoped_token_id == scoped_token.id)
        )
    ).scalar_one()
    rule.allow_read = False
    await db_session.commit()

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert context.rules[0].allow_read is True


@pytest.mark.asyncio
async def test_resolve_missing_credential_rejected(db_session: AsyncSession, fake_redis) -> None:
    """A token whose upstream credential row is gone is rejected."""
    scoped_token, full_token, credential = await _make_scoped_token(db_session)
    await db_session.delete(credential)
    await db_session.commit()

    context = await resolve_scoped_token(db_session, full_token, fake_redis)

    assert context is None


def _build_app_with_dependency() -> FastAPI:
    """Build a minimal FastAPI app exposing `require_scoped_token` for
    dependency-level testing.

    Return:
        app(FastAPI): The app with a single probe endpoint.
    """
    app = FastAPI()

    @app.get("/probe")
    async def probe(context: ProxyAuthContext = Depends(require_scoped_token)) -> dict:
        return {"token_id": context.token.id}

    return app


@pytest.mark.asyncio
async def test_require_scoped_token_missing_header_rejected(
    db_session: AsyncSession, async_client_factory, fake_redis
) -> None:
    """The dependency rejects a request with no Authorization header."""
    app = _build_app_with_dependency()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get("/probe")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == 1000


@pytest.mark.asyncio
async def test_require_scoped_token_valid_header_resolves(
    db_session: AsyncSession, async_client_factory, fake_redis
) -> None:
    """The dependency resolves a valid Bearer token into a context."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token)

    app = _build_app_with_dependency()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/probe", headers={"Authorization": f"Bearer {full_token}"}
        )

    assert response.status_code == 200
    assert response.json()["token_id"] == scoped_token.id


@pytest.mark.asyncio
async def test_require_scoped_token_invalid_header_rejected(
    db_session: AsyncSession, async_client_factory, fake_redis
) -> None:
    """The dependency rejects a bad Bearer token with a CF-style error payload."""
    app = _build_app_with_dependency()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/probe", headers={"Authorization": "Bearer garbage"}
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == 1000
