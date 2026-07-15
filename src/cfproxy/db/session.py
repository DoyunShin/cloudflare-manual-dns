"""Async database engine, session factory, and initialization helpers."""

from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cfproxy.config import get_settings
from cfproxy.db.locks import advisory_lock
from cfproxy.db.models import Base, SchemaVersion

CURRENT_SCHEMA_VERSION = 1


def _create_engine(url: str) -> AsyncEngine:
    """Create an async engine, using a NullPool for SQLite to avoid connections
    leaking across event loops between test cases.

    Args:
        url(str): SQLAlchemy async database URL.

    Return:
        engine(AsyncEngine): The configured async engine.
    """
    if url.startswith("sqlite"):
        return create_async_engine(url, poolclass=NullPool)
    return create_async_engine(url)


engine: AsyncEngine = _create_engine(get_settings().db_url)
Sessionmaker = async_sessionmaker(engine, expire_on_commit=False)


def configure_engine(url: str) -> None:
    """Reconfigure the module-level engine and sessionmaker to point at a new URL.

    Used by tests to bind the application to an isolated SQLite database.

    Args:
        url(str): SQLAlchemy async database URL.

    Return:
        None
    """
    global engine, Sessionmaker
    engine = _create_engine(url)
    Sessionmaker = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an active async database session.

    Return:
        session(AsyncSession): An open session bound to the current engine.
    """
    async with Sessionmaker() as session:
        yield session


async def init_db() -> None:
    """Create all tables and record the schema version, idempotently.

    On MySQL, an advisory lock guards concurrent initialization across
    multiple worker processes. On SQLite, tables are created directly.

    Return:
        None
    """
    async with engine.connect() as conn:
        if conn.dialect.name == "mysql":
            async with advisory_lock(conn, "cfproxy_init_db"):
                await conn.run_sync(Base.metadata.create_all)
                await conn.commit()
        else:
            await conn.run_sync(Base.metadata.create_all)
            await conn.commit()

    async with Sessionmaker() as session:
        existing = await session.get(SchemaVersion, CURRENT_SCHEMA_VERSION)
        if existing is None:
            session.add(SchemaVersion(version=CURRENT_SCHEMA_VERSION))
            await session.commit()
