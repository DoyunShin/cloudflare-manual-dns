"""Persisting and querying proxy-request audit log entries."""

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.db.models import AuditLog


async def write_audit(
    session: AsyncSession,
    *,
    method: str,
    path: str,
    decision: str,
    user_id: str | None = None,
    scoped_token_id: str | None = None,
    token_prefix: str | None = None,
    zone_id: str | None = None,
    record_id: str | None = None,
    record_name: str | None = None,
    record_type: str | None = None,
    pre_image: dict | None = None,
    post_image: dict | None = None,
    deny_reason: str | None = None,
    upstream_status: int | None = None,
    client_ip: str | None = None,
    latency_ms: int | None = None,
) -> AuditLog:
    """Persist a single audit log row describing one proxy request decision.

    Args:
        session(AsyncSession): Database session.
        method(str): The HTTP method of the proxied request.
        path(str): The request path.
        decision(str): Either "allow" or "deny".
        user_id(str, optional): The owning user's id (the scoped token's owner).
        scoped_token_id(str, optional): The scoped token id used, if any.
        token_prefix(str, optional): The scoped token's display prefix.
        zone_id(str, optional): The Cloudflare zone id involved.
        record_id(str, optional): The Cloudflare record id involved.
        record_name(str, optional): The DNS record name involved.
        record_type(str, optional): The DNS record type involved.
        pre_image(dict, optional): The record's state before the request.
        post_image(dict, optional): The record's state after the request.
        deny_reason(str, optional): Why the request was denied, when applicable.
        upstream_status(int, optional): The Cloudflare upstream HTTP status, if forwarded.
        client_ip(str, optional): The client's source IP address.
        latency_ms(int, optional): Total request latency in milliseconds.

    Return:
        entry(AuditLog): The persisted audit log row.
    """
    entry = AuditLog(
        user_id=user_id,
        scoped_token_id=scoped_token_id,
        token_prefix=token_prefix,
        method=method,
        path=path,
        zone_id=zone_id,
        record_id=record_id,
        record_name=record_name,
        record_type=record_type,
        pre_image=pre_image,
        post_image=post_image,
        decision=decision,
        deny_reason=deny_reason,
        upstream_status=upstream_status,
        client_ip=client_ip,
        latency_ms=latency_ms,
    )
    session.add(entry)
    await session.commit()
    await session.refresh(entry)
    return entry


async def list_audit_logs(
    session: AsyncSession,
    user_id: str,
    *,
    token_id: str | None = None,
    zone_id: str | None = None,
    since: datetime | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[AuditLog], dict[str, Any]]:
    """List audit log entries owned by a user, most recent first, with optional filters.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The owning user's id (IDOR scope).
        token_id(str, optional): Filter to a single scoped token id.
        zone_id(str, optional): Filter to a single Cloudflare zone id.
        since(datetime, optional): Only include entries at or after this timestamp.
        page(int, optional): 1-indexed page number.
        per_page(int, optional): Number of entries per page.

    Return:
        result(tuple[list[AuditLog], dict[str, Any]]): `(entries, result_info)`
            where `result_info` has keys `page`, `per_page`, `count`, `total_count`.
    """
    base_stmt = select(AuditLog).where(AuditLog.user_id == user_id)
    if token_id is not None:
        base_stmt = base_stmt.where(AuditLog.scoped_token_id == token_id)
    if zone_id is not None:
        base_stmt = base_stmt.where(AuditLog.zone_id == zone_id)
    if since is not None:
        base_stmt = base_stmt.where(AuditLog.ts >= since)

    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total_count = (await session.execute(count_stmt)).scalar_one()

    page_stmt = (
        base_stmt.order_by(AuditLog.ts.desc()).offset((page - 1) * per_page).limit(per_page)
    )
    page_entries = list((await session.execute(page_stmt)).scalars().all())

    result_info = {
        "page": page,
        "per_page": per_page,
        "count": len(page_entries),
        "total_count": total_count,
    }
    return page_entries, result_info
