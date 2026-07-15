"""Shared pytest fixtures for cfproxy tests.

Sets up an isolated SQLite test database and required secrets in the
environment BEFORE any `cfproxy` module is imported (settings are read at
import time by `cfproxy.db.session`), creates all tables, and injects a
fakeredis client wherever the application would otherwise reach for a real
Redis connection.
"""

import os
import secrets
import tempfile
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet

_tmp_db_fd, _tmp_db_path = tempfile.mkstemp(suffix=".db")
os.close(_tmp_db_fd)

os.environ.setdefault("DB_URL", f"sqlite+aiosqlite:///{_tmp_db_path}")
os.environ.setdefault("PROXY_SECRET_KEY", Fernet.generate_key().decode())
os.environ.setdefault("JWT_SECRET", secrets.token_urlsafe(32))

import fakeredis.aioredis
import httpx
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.cache import redis as cache_redis
from cfproxy.db.models import Base
from cfproxy.db.session import Sessionmaker, engine


@pytest_asyncio.fixture(autouse=True)
async def _create_tables() -> AsyncIterator[None]:
    """Ensure all tables exist before every test (idempotent, cheap on SQLite)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture(autouse=True)
async def fake_redis() -> AsyncIterator["fakeredis.aioredis.FakeRedis"]:
    """Inject a fresh fakeredis client in place of the real Redis connection."""
    client = fakeredis.aioredis.FakeRedis()
    cache_redis.set_redis_for_test(client)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """Provide an isolated async database session for a single test."""
    async with Sessionmaker() as session:
        yield session
        await session.rollback()


@asynccontextmanager
async def _async_client_for_app(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """Build an httpx.AsyncClient bound to a FastAPI app via ASGITransport.

    Args:
        app(FastAPI): The FastAPI application to bind the client to.

    Return:
        client(httpx.AsyncClient): An async client that routes requests directly
            to the given app, without touching the network.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture
def async_client_factory() -> Callable[[FastAPI], AsyncIterator[httpx.AsyncClient]]:
    """Fixture exposing `_async_client_for_app` as an async-context-manager factory."""
    return _async_client_for_app
