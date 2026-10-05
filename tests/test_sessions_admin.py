"""Tests for database-backed sessions and service-local user administration."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request, Response
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

from cfproxy.config import get_settings
from cfproxy.core.security import MANAGEMENT_SESSION_COOKIE, hash_password, hash_session_token
from cfproxy.db.models import ManagementSession, OIDCConfig, User
from cfproxy.db.session import Sessionmaker, _initialize_schema
from cfproxy.routers.admin import router as admin_router
from cfproxy.routers import auth as auth_module
from cfproxy.routers.auth import router as auth_router
from cfproxy.schemas.management import LoginRequest


def _build_app() -> FastAPI:
    """Build the authentication and user-administration test app."""
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(admin_router)
    return app


async def _create_user(*, is_admin: bool, is_active: bool = True) -> tuple[User, str]:
    """Create a local user with a unique login and return its password."""
    password = "correct-horse-battery"
    email = f"{uuid4().hex}@example.com"
    async with Sessionmaker() as session:
        user = User(
            local_login=email,
            email=email,
            password_hash=hash_password(password),
            auth_provider="local",
            is_admin=is_admin,
            is_active=is_active,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        session.expunge(user)
    return user, password


async def _login(client, user: User, password: str) -> tuple[str, str]:
    """Log in a local administrator and return CSRF and raw session tokens."""
    response = await client.post(
        "/api/v1/auth/login",
        headers={"Origin": get_settings().app_base_url},
        json={"email": user.local_login, "password": password},
    )
    assert response.status_code == 200, response.text
    raw_token = client.cookies.get(MANAGEMENT_SESSION_COOKIE)
    assert raw_token is not None
    return response.json()["data"]["csrf_token"], raw_token


def _mutation_headers(csrf_token: str) -> dict[str, str]:
    """Build trusted-origin CSRF headers for an authenticated mutation."""
    return {
        "Origin": get_settings().app_base_url,
        "X-CSRF-Token": csrf_token,
    }


@pytest.mark.asyncio
async def test_local_admin_login_uses_hashed_server_session(async_client_factory) -> None:
    """Login stores only a token hash and returns a secure host cookie."""
    user, password = await _create_user(is_admin=True)
    async with async_client_factory(_build_app()) as client:
        csrf_token, raw_token = await _login(client, user, password)
        response = await client.get("/api/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["data"]["csrf_token"] == csrf_token
    assert response.json()["data"]["user"]["is_admin"] is True
    set_cookie = response.request.headers.get("cookie", "")
    assert MANAGEMENT_SESSION_COOKIE in set_cookie
    async with Sessionmaker() as session:
        stored = (
            await session.execute(
                select(ManagementSession).where(
                    ManagementSession.token_hash == hash_session_token(raw_token)
                )
            )
        ).scalar_one()
    assert stored.token_hash != raw_token
    assert stored.expires_at.tzinfo == UTC


@pytest.mark.asyncio
async def test_local_non_admin_cannot_use_recovery_login(async_client_factory) -> None:
    """Password login is restricted to active local administrators."""
    user, password = await _create_user(is_admin=False)
    async with async_client_factory(_build_app()) as client:
        response = await client.post(
            "/api/v1/auth/login",
            headers={"Origin": get_settings().app_base_url},
            json={"email": user.local_login, "password": password},
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_rechecks_admin_state_after_password_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    """A concurrent demotion observed by the locked reload prevents session issuance."""
    initial = User(
        id=str(uuid4()),
        local_login="admin@example.com",
        email="admin@example.com",
        password_hash="verified-hash",
        auth_provider="local",
        is_admin=True,
        is_active=True,
    )
    demoted = User(
        id=initial.id,
        local_login=initial.local_login,
        email=initial.email,
        password_hash=initial.password_hash,
        auth_provider="local",
        is_admin=False,
        is_active=True,
    )

    class FakeSession:
        """Return pre- and post-verification user snapshots."""

        def __init__(self) -> None:
            self.results = iter((initial, demoted))
            self.rolled_back = False

        async def execute(self, statement: object) -> SimpleNamespace:
            del statement
            return SimpleNamespace(scalar_one_or_none=lambda: next(self.results))

        def get_bind(self) -> SimpleNamespace:
            return SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        async def rollback(self) -> None:
            self.rolled_back = True

    async def allow_rate_limit(request: Request) -> None:
        del request

    fake_session = FakeSession()
    monkeypatch.setattr(auth_module, "_check_login_rate_limit", allow_rate_limit)
    monkeypatch.setattr(auth_module, "verify_password", lambda password, password_hash: True)
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/login",
            "headers": [
                (b"origin", get_settings().app_base_url.encode()),
                (b"content-type", b"application/json"),
            ],
        }
    )
    response = Response()

    body = await auth_module.login(
        LoginRequest(email="admin@example.com", password="password"),
        request,
        response,
        fake_session,
    )

    assert response.status_code == 401
    assert body["status"] == 401
    assert fake_session.rolled_back is True


@pytest.mark.asyncio
async def test_admin_mutation_requires_csrf_and_preserves_last_local_admin(async_client_factory) -> None:
    """User authorization is service-local and the recovery admin cannot be removed."""
    admin, password = await _create_user(is_admin=True)
    ordinary, _ = await _create_user(is_admin=False)
    async with async_client_factory(_build_app()) as client:
        csrf_token, _raw_token = await _login(client, admin, password)

        missing_csrf = await client.patch(
            f"/api/v1/admin/users/{ordinary.id}",
            headers={"Origin": get_settings().app_base_url},
            json={"is_admin": True},
        )
        assert missing_csrf.status_code == 403

        protected = await client.patch(
            f"/api/v1/admin/users/{admin.id}",
            headers=_mutation_headers(csrf_token),
            json={"is_active": False},
        )
        assert protected.status_code == 409

        promoted = await client.patch(
            f"/api/v1/admin/users/{ordinary.id}",
            headers=_mutation_headers(csrf_token),
            json={"is_admin": True},
        )
        assert promoted.status_code == 200
        assert promoted.json()["data"]["is_admin"] is True


@pytest.mark.asyncio
async def test_logout_revokes_only_service_session(async_client_factory) -> None:
    """Logout revokes the database session and clears the cookie locally."""
    user, password = await _create_user(is_admin=True)
    async with async_client_factory(_build_app()) as client:
        csrf_token, raw_token = await _login(client, user, password)
        response = await client.post(
            "/api/v1/auth/logout",
            headers=_mutation_headers(csrf_token),
        )
        assert response.status_code == 200
        assert client.cookies.get(MANAGEMENT_SESSION_COOKIE) is None
        assert (await client.get("/api/v1/auth/me")).status_code == 401

    async with Sessionmaker() as session:
        stored = (
            await session.execute(
                select(ManagementSession).where(
                    ManagementSession.token_hash == hash_session_token(raw_token)
                )
            )
        ).scalar_one()
    assert stored.revoked_at is not None


@pytest.mark.asyncio
async def test_oidc_config_revision_invalidates_oidc_session(async_client_factory) -> None:
    """An OIDC session becomes invalid after its configured provider revision changes."""
    user = User(
        email="oidc@example.com",
        auth_provider="oidc",
        oidc_issuer="https://id.example.com",
        oidc_sub="subject",
        is_active=True,
    )
    raw_token = "opaque-oidc-session-token"
    async with Sessionmaker() as session:
        config = await session.get(OIDCConfig, 1)
        config.enabled = True
        config.revision = 4
        session.add(user)
        await session.flush()
        session.add(
            ManagementSession(
                token_hash=hash_session_token(raw_token),
                user_id=user.id,
                auth_method="oidc",
                provider_revision=4,
                csrf_secret="csrf",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        await session.commit()

    async with async_client_factory(_build_app()) as client:
        client.cookies.set(MANAGEMENT_SESSION_COOKIE, raw_token)
        assert (await client.get("/api/v1/auth/me")).status_code == 200
        async with Sessionmaker() as session:
            config = await session.get(OIDCConfig, 1)
            config.revision = 5
            await session.commit()
        assert (await client.get("/api/v1/auth/me")).status_code == 401


@pytest.mark.asyncio
async def test_sqlite_connections_enforce_foreign_keys(db_session) -> None:
    """Every configured SQLite connection enables foreign-key enforcement."""
    enabled = (await db_session.execute(text("PRAGMA foreign_keys"))).scalar_one()
    assert enabled == 1


@pytest.mark.asyncio
async def test_init_rejects_old_schema_before_creating_v2_tables(tmp_path) -> None:
    """An old initialized database is rejected without adding v2 tables."""
    database = tmp_path / "old-schema.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{database}")
    try:
        async with test_engine.connect() as connection:
            await connection.execute(text("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)"))
            await connection.execute(text("INSERT INTO schema_version (version) VALUES (1)"))
            await connection.commit()
            with pytest.raises(RuntimeError, match="Unsupported cfproxy schema version"):
                await _initialize_schema(connection)
            tables = (
                await connection.run_sync(
                    lambda sync_connection: set(
                        __import__("sqlalchemy").inspect(sync_connection).get_table_names()
                    )
                )
            )
    finally:
        await test_engine.dispose()
    assert tables == {"schema_version"}
