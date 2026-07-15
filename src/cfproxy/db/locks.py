"""Dialect-guarded advisory and row locking helpers.

MySQL uses `GET_LOCK`/`RELEASE_LOCK` for advisory locks and
`SELECT ... FOR UPDATE` for row locks. SQLite (tests/dev) falls back to a
best-effort, single-process `asyncio.Lock` and a plain (unlocked) select,
since SQLite has no equivalent server-side locking primitive.
"""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import Select, text
from sqlalchemy.ext.asyncio import AsyncConnection


class LockUnavailable(Exception):
    """Raised when an advisory lock could not be acquired within the timeout."""


_process_local_locks: dict[str, asyncio.Lock] = {}


def _get_process_local_lock(name: str) -> asyncio.Lock:
    """Return (creating if needed) a process-local asyncio.Lock keyed by name.

    Args:
        name(str): The lock name.

    Return:
        lock(asyncio.Lock): The lock instance associated with `name`.
    """
    if name not in _process_local_locks:
        _process_local_locks[name] = asyncio.Lock()
    return _process_local_locks[name]


@asynccontextmanager
async def advisory_lock(
    conn: AsyncConnection, name: str, timeout: int = 10
) -> AsyncIterator[None]:
    """Acquire a named advisory lock for the duration of the context.

    Args:
        conn(AsyncConnection): Active database connection.
        name(str): Lock name to acquire.
        timeout(int, optional): Seconds to wait for the lock (MySQL only).

    Return:
        None
    """
    if conn.dialect.name == "mysql":
        result = await conn.execute(text("SELECT GET_LOCK(:n, :t)"), {"n": name, "t": timeout})
        acquired = result.scalar()
        if not acquired:
            raise LockUnavailable(f"Could not acquire advisory lock '{name}'")
        try:
            yield
        finally:
            await conn.execute(text("SELECT RELEASE_LOCK(:n)"), {"n": name})
    else:
        lock = _get_process_local_lock(name)
        try:
            await asyncio.wait_for(lock.acquire(), timeout=timeout)
        except TimeoutError:
            raise LockUnavailable(f"Could not acquire advisory lock '{name}'")
        try:
            yield
        finally:
            lock.release()


def mutation_lock_name(zone_id: str, record_id: str) -> str:
    """Derive a bounded-length advisory lock name for a zone/record mutation.

    Args:
        zone_id(str): The Cloudflare zone id.
        record_id(str): The Cloudflare DNS record id.

    Return:
        name(str): A lock name of at most 64 characters.
    """
    digest = hashlib.sha256(f"{zone_id}:{record_id}".encode()).hexdigest()
    return "m" + digest[:60]


def with_row_lock(session, stmt: Select) -> Select:
    """Apply row-level locking to a select statement when supported.

    Args:
        session: The active database session (sync or async).
        stmt(Select): The select statement to lock.

    Return:
        stmt(Select): The statement with `.with_for_update()` applied on MySQL,
            unchanged on SQLite.
    """
    bind = session.get_bind()
    if bind.dialect.name == "mysql":
        return stmt.with_for_update()
    return stmt
