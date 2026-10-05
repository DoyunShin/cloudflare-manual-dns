"""Opt-in integration checks; recreate managed tables in an isolated MySQL DB."""

import asyncio
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit
from http.cookies import SimpleCookie

import pytest
import pytest_asyncio
from fastapi import HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from cfproxy.core.crypto import decrypt_secret, encrypt_secret
from cfproxy.db.models import Base, OIDCConfig, ScopedToken, ScopeRule, UpstreamCredential, User
from cfproxy.core.security import MANAGEMENT_SESSION_COOKIE, create_service_session, get_current_user
from cfproxy.services.credential_service import delete_credential
from cfproxy.upstream.client import get_valid_access_token
from cfproxy.routers.admin import update_user
from cfproxy.schemas.management import UserAdminUpdateRequest
from cfproxy.services.oidc_service import OIDCConfigInput, save_oidc_config
from cfproxy.services import oauth_service
from cfproxy.auth import oauth_cf
from cfproxy.config import get_settings

_MYSQL_URL = os.environ.get("CFPROXY_TEST_MYSQL_URL", "")
pytestmark = pytest.mark.skipif(not _MYSQL_URL, reason="CFPROXY_TEST_MYSQL_URL is not configured")


@pytest_asyncio.fixture
async def mysql_sessions() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """Reset tables only in the explicitly isolated integration-test database."""
    engine = create_async_engine(_MYSQL_URL)
    if engine.url.database != "cfproxy_oidc_test":
        await engine.dispose()
        raise ValueError("MySQL tests require the isolated cfproxy_oidc_test database")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)
        await connection.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def test_mysql_credential_delete_preserves_revoked_token_history(mysql_sessions: async_sessionmaker[AsyncSession]) -> None:
    """Real FK enforcement permits deletion while retaining revoked token rules."""
    async with mysql_sessions() as session:
        user = User(email=f"mysql-{uuid4().hex}@example.com")
        session.add(user)
        await session.flush()
        credential = UpstreamCredential(user_id=user.id, label="mysql-delete", cred_type="token", secret_enc=encrypt_secret("hidden"))
        session.add(credential)
        await session.flush()
        token = ScopedToken(user_id=user.id, upstream_credential_id=credential.id, name="history", lookup_id=uuid4().hex[:16], token_prefix="cfsx", token_hash=uuid4().hex + uuid4().hex)
        session.add(token)
        await session.flush()
        session.add(ScopeRule(scoped_token_id=token.id, zone_id="zone1", record_types=["A"], record_ids=["rec1"], allow_read=True, allow_create=False, allow_write=True, allow_delete=False))
        await session.commit()
        token_id, user_id, credential_id = token.id, user.id, credential.id
        await delete_credential(session, user_id, credential_id)
    async with mysql_sessions() as session:
        token = await session.get(ScopedToken, token_id)
        assert token.status == "revoked"
        assert token.upstream_credential_id is None
        assert token.revoked_at.tzinfo is UTC
        assert (await session.execute(select(ScopeRule).where(ScopeRule.scoped_token_id == token_id))).scalar_one()


async def test_mysql_concurrent_refresh_reads_winning_rotated_grant(mysql_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """A lock waiter refreshes its identity map and never reuses the old grant."""
    async with mysql_sessions() as session:
        user = User(email=f"refresh-{uuid4().hex}@example.com")
        session.add(user)
        await session.flush()
        credential = UpstreamCredential(user_id=user.id, label="mysql-refresh", cred_type="oauth", access_token_enc=encrypt_secret("old-access"), refresh_token_enc=encrypt_secret("old-refresh"), token_expires_at=datetime.now(UTC) - timedelta(minutes=1))
        session.add(credential)
        await session.commit()
        credential_id = credential.id
    calls = []

    async def refresh(token: str) -> dict:
        calls.append(token)
        await asyncio.sleep(0.05)
        return {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}

    monkeypatch.setattr("cfproxy.auth.oauth_cf.refresh_access_token", refresh)
    async with mysql_sessions() as first, mysql_sessions() as second:
        first_row = await first.get(UpstreamCredential, credential_id)
        second_row = await second.get(UpstreamCredential, credential_id)
        assert await asyncio.gather(get_valid_access_token(first, first_row), get_valid_access_token(second, second_row)) == ["new-access", "new-access"]
    assert calls == ["old-refresh"]
    async with mysql_sessions() as session:
        row = await session.get(UpstreamCredential, credential_id)
        assert row.cred_version == 2
        assert decrypt_secret(row.refresh_token_enc) == "new-refresh"


async def test_mysql_concurrent_last_local_admin_changes_are_serialized(mysql_sessions: async_sessionmaker[AsyncSession]) -> None:
    """Competing demotions cannot remove both remaining recovery administrators."""
    async with mysql_sessions() as session:
        admins = [User(local_login=f"admin-{uuid4().hex}@example.com", auth_provider="local", is_admin=True, is_active=True) for _ in range(2)]
        session.add_all(admins)
        await session.commit()
        ids = [admin.id for admin in admins]
    async with mysql_sessions() as first, mysql_sessions() as second:
        first_admin = await first.get(User, ids[0])
        second_admin = await second.get(User, ids[1])
        responses = await asyncio.gather(update_user(ids[0], UserAdminUpdateRequest(is_admin=False), first_admin, first), update_user(ids[1], UserAdminUpdateRequest(is_admin=False), second_admin, second))
    assert sorted(response.status_code for response in responses) == [200, 409]
    async with mysql_sessions() as session:
        active_admins = (await session.execute(select(User).where(User.auth_provider == "local", User.is_admin.is_(True), User.is_active.is_(True)))).scalars().all()
        assert len(active_admins) == 1
        await session.execute(delete(User).where(User.id.in_(ids)))
        await session.commit()


async def test_mysql_oidc_identity_is_case_and_whitespace_sensitive(mysql_sessions: async_sessionmaker[AsyncSession]) -> None:
    """MySQL's default case-insensitive collation cannot merge external identities."""
    issuer = f"https://id.example.com/{uuid4().hex}"
    identities = [(issuer, "Person"), (issuer, "person"), (issuer, "person "), (issuer.upper(), "person")]
    async with mysql_sessions() as session:
        session.add_all([User(auth_provider="oidc", oidc_issuer=iss, oidc_sub=sub) for iss, sub in identities])
        await session.commit()
        for iss, sub in identities:
            row = (await session.execute(select(User).where(User.oidc_issuer == iss, User.oidc_sub == sub))).scalar_one()
            assert (row.oidc_issuer, row.oidc_sub) == (iss, sub)


async def test_mysql_config_revision_is_atomic_and_invalidates_old_session(mysql_sessions: async_sessionmaker[AsyncSession]) -> None:
    """Concurrent saves increment revision twice and invalidate pre-change sessions."""
    async with mysql_sessions() as session:
        config = await session.get(OIDCConfig, 1)
        if config is None:
            config = OIDCConfig(id=1, label="OIDC", issuer="https://id.example.com", client_id="cfproxy", client_secret_enc=encrypt_secret("secret"), enabled=True, revision=1)
            session.add(config)
        else:
            config.enabled = True
        user = User(auth_provider="oidc", oidc_issuer=f"https://id.example.com/{uuid4().hex}", oidc_sub="subject")
        session.add(user)
        await session.commit()
        previous_revision = config.revision
        response = Response()
        await create_service_session(response, user, session, "oidc", previous_revision)
        await session.commit()
        cookies = SimpleCookie()
        cookies.load(response.headers["set-cookie"])
        raw_token = cookies[MANAGEMENT_SESSION_COOKIE].value
    async with mysql_sessions() as first, mysql_sessions() as second:
        values = [OIDCConfigInput(label=label, issuer="https://id.example.com", client_id="cfproxy", client_secret="secret", enabled=True) for label in ("First", "Second")]
        await asyncio.gather(save_oidc_config(first, values[0]), save_oidc_config(second, values[1]))
    async with mysql_sessions() as session:
        assert (await session.get(OIDCConfig, 1)).revision == previous_revision + 2
        request = Request({"type": "http", "method": "GET", "path": "/api/v1/auth/me", "headers": [(b"cookie", f"{MANAGEMENT_SESSION_COOKIE}={raw_token}".encode())]})
        with pytest.raises(HTTPException) as caught:
            await get_current_user(request, session)
        assert caught.value.status_code == 401


async def test_mysql_cloudflare_connect_and_reconnect_commit_safely(mysql_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """Credential linking commits without leaking/using a closed advisory-lock connection."""
    settings = get_settings().model_copy(update={"cf_oauth_client_id": "cf-test-client", "cf_oauth_client_secret": "cf-secret"})
    monkeypatch.setattr(oauth_service, "get_settings", lambda: settings)
    monkeypatch.setattr(oauth_cf, "get_settings", lambda: settings)

    async def exchange(code: str, verifier: str) -> dict:
        return {"access_token": f"access-{code}", "refresh_token": f"refresh-{code}", "expires_in": 3600, "scope": "dns"}

    monkeypatch.setattr(oauth_service, "exchange_code", exchange)
    async with mysql_sessions() as session:
        user = User(auth_provider="local", is_active=True, is_admin=True)
        session.add(user)
        await session.flush()
        management_session, _csrf = await create_service_session(Response(), user, session)
        await session.commit()
        credential_id = None
        for revision in (1, 2):
            url = await oauth_service.start_cf_oauth_connect(user.id, management_session.id)
            state = parse_qs(urlsplit(url).query)["state"][0]
            credential = await oauth_service.complete_cf_oauth_connect(session, str(revision), state, user.id, management_session.id)
            if credential_id is not None:
                assert credential.id == credential_id
            credential_id = credential.id
            assert credential.cred_version == revision
            assert decrypt_secret(credential.access_token_enc) == f"access-{revision}"


async def test_mysql_cloudflare_callback_rejects_oidc_revision_changed_during_exchange(mysql_sessions: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch) -> None:
    """A concurrent config commit invalidates consent before credential persistence."""
    settings = get_settings().model_copy(update={"cf_oauth_client_id": "cf-test-client", "cf_oauth_client_secret": "cf-secret"})
    monkeypatch.setattr(oauth_service, "get_settings", lambda: settings)
    monkeypatch.setattr(oauth_cf, "get_settings", lambda: settings)

    async def exchange(code: str, verifier: str) -> dict:
        async with mysql_sessions() as changes:
            config = await changes.get(OIDCConfig, 1)
            config.revision += 1
            await changes.commit()
        return {"access_token": "new-access", "refresh_token": "new-refresh", "expires_in": 3600}

    monkeypatch.setattr(oauth_service, "exchange_code", exchange)
    async with mysql_sessions() as session:
        config = OIDCConfig(id=1, label="OIDC", issuer="https://id.example.com", client_id="cfproxy", client_secret_enc=encrypt_secret("secret"), enabled=True, revision=4)
        user = User(auth_provider="oidc", oidc_issuer="https://id.example.com", oidc_sub="subject")
        session.add_all([config, user])
        await session.flush()
        management_session, _csrf = await create_service_session(Response(), user, session, "oidc", 4)
        await session.commit()
        url = await oauth_service.start_cf_oauth_connect(user.id, management_session.id)
        state = parse_qs(urlsplit(url).query)["state"][0]
        with pytest.raises(oauth_service.CloudflareOAuthStateError):
            await oauth_service.complete_cf_oauth_connect(session, "auth-code", state, user.id, management_session.id)
        assert (await session.execute(select(UpstreamCredential).where(UpstreamCredential.user_id == user.id))).scalars().all() == []
