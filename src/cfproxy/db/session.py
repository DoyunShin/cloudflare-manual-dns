"""Async database engine, session factory, and initialization helpers."""

from typing import AsyncIterator

from sqlalchemy import event, inspect, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from cfproxy.config import get_settings
from cfproxy.db.locks import advisory_lock
from cfproxy.db.models import Base, OIDCConfig, SchemaVersion

CURRENT_SCHEMA_VERSION = 2


def _enable_sqlite_foreign_keys(dbapi_connection: object, connection_record: object) -> None:
    """Enable SQLite foreign-key enforcement for every new connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _register_engine_events(created_engine: AsyncEngine) -> None:
    """Register dialect-specific connection initialization events."""
    if created_engine.url.get_backend_name() == "sqlite":
        event.listen(created_engine.sync_engine, "connect", _enable_sqlite_foreign_keys)


def _create_engine(url: str) -> AsyncEngine:
    """Create an async engine, using a NullPool for SQLite to avoid connections
    leaking across event loops between test cases.

    Args:
        url(str): SQLAlchemy async database URL.

    Return:
        engine(AsyncEngine): The configured async engine.
    """
    if url.startswith("sqlite"):
        created_engine = create_async_engine(url, poolclass=NullPool)
    else:
        created_engine = create_async_engine(url)
    _register_engine_events(created_engine)
    return created_engine


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


def _existing_tables(sync_connection: object) -> set[str]:
    """Return table names currently present in the connected database."""
    return set(inspect(sync_connection).get_table_names())


def _schema_structure_errors(sync_connection: object) -> list[str]:
    """Return missing-table and column mismatches for an initialized schema."""
    inspector = inspect(sync_connection)
    existing_tables = set(inspector.get_table_names())
    errors: list[str] = []
    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            errors.append(f"missing table {table_name}")
            continue
        actual_columns = {column["name"] for column in inspector.get_columns(table_name)}
        expected_columns = set(table.columns.keys())
        if actual_columns != expected_columns:
            missing = sorted(expected_columns - actual_columns)
            unexpected = sorted(actual_columns - expected_columns)
            if missing:
                errors.append(f"{table_name} missing columns {', '.join(missing)}")
            if unexpected:
                errors.append(f"{table_name} has unexpected columns {', '.join(unexpected)}")
    return errors


async def _validate_schema_before_ddl(conn: object) -> bool:
    """Validate an existing schema and report whether this is an empty database."""
    existing_tables = await conn.run_sync(_existing_tables)
    managed_tables = set(Base.metadata.tables)
    present_managed_tables = existing_tables & managed_tables
    if not present_managed_tables:
        return True
    if "schema_version" not in existing_tables:
        raise RuntimeError(
            "Existing cfproxy tables have no schema version; use an empty database for schema v2"
        )
    result = await conn.execute(select(SchemaVersion.version))
    versions = sorted(result.scalars().all())
    if versions != [CURRENT_SCHEMA_VERSION]:
        found = ", ".join(str(version) for version in versions) or "none"
        raise RuntimeError(
            f"Unsupported cfproxy schema version ({found}); schema v{CURRENT_SCHEMA_VERSION} "
            "requires a new empty database"
        )
    structure_errors = await conn.run_sync(_schema_structure_errors)
    if structure_errors:
        raise RuntimeError(
            "Incompatible cfproxy schema v2: " + "; ".join(structure_errors)
        )
    return False


async def _initialize_schema(conn: object) -> None:
    """Validate the schema before DDL, then initialize an empty database."""
    is_empty = await _validate_schema_before_ddl(conn)
    if is_empty:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(
            SchemaVersion.__table__.insert().values(version=CURRENT_SCHEMA_VERSION)
        )
        await conn.execute(
            OIDCConfig.__table__.insert().values(
                id=1,
                label="OIDC",
                issuer="",
                client_id="",
                client_secret_enc="",
                scopes="openid profile email",
                enabled=False,
                revision=1,
                allowed_endpoint_origins=[],
                allow_private_network=False,
            )
        )
    await conn.commit()


async def init_db() -> None:
    """Create all tables and record the schema version, idempotently.

    On MySQL, an advisory lock guards concurrent initialization across
    multiple worker processes. On SQLite, tables are created directly.

    Return:
        None
    """
    async with engine.connect() as conn:
        async with advisory_lock(conn, "cfproxy_init_db"):
            await _initialize_schema(conn)
