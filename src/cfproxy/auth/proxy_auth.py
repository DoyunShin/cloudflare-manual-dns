"""Resolution of scoped proxy tokens (`/client/v4` machine plane) into an
authorization context.

The authoritative source of truth for every decision is a per-request,
indexed SELECT against `scoped_tokens.lookup_id` -- status, version, expiry
and the token hash are always re-read from the database, so a revoke or
rotation is visible immediately even if the Redis rules cache is stale or
down. Redis only accelerates the expensive join of scope rules + upstream
credential, keyed by the token's `version` so a version bump (revoke,
rotate, rule edit) makes the previous cache entry unreachable without
requiring an explicit invalidation.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, UTC
from types import SimpleNamespace
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.cache.redis import get_redis, rules_key
from cfproxy.config import get_settings
from cfproxy.core import cf_errors
from cfproxy.core.crypto import parse_scoped_token, verify_token
from cfproxy.db.models import ScopedToken, ScopeRule, UpstreamCredential
from cfproxy.db.session import get_session

logger = logging.getLogger(__name__)


@dataclass
class ProxyAuthContext:
    """Resolved authorization context for an authenticated scoped-token request.

    Args:
        token(ScopedToken): The authoritative scoped token row.
        rules(list): The token's scope rules (`ScopeRule` rows, or
            attribute-equivalent objects restored from cache).
        credential(UpstreamCredential): The upstream Cloudflare credential the
            token is bound to.
    """

    token: ScopedToken
    rules: list
    credential: UpstreamCredential


def _rule_to_cache_dict(rule: ScopeRule) -> dict:
    """Serialize a `ScopeRule` row into a JSON-safe dict for caching.

    Args:
        rule(ScopeRule): The rule row to serialize.

    Return:
        data(dict): A plain dict with the fields `match_rules`/`is_lock_exempt`
            read via attribute access.
    """
    return {
        "zone_id": rule.zone_id,
        "name_pattern": rule.name_pattern,
        "name_match": rule.name_match,
        "record_types": rule.record_types,
        "record_ids": rule.record_ids,
        "allow_read": rule.allow_read,
        "allow_create": rule.allow_create,
        "allow_write": rule.allow_write,
        "allow_delete": rule.allow_delete,
    }


def _cache_dict_to_rule(data: dict) -> SimpleNamespace:
    """Reconstruct a rule-shaped object from a dict cached by `_rule_to_cache_dict`.

    Args:
        data(dict): The cached rule dict.

    Return:
        rule(SimpleNamespace): An object exposing the same attributes as a
            `ScopeRule` row.
    """
    return SimpleNamespace(**data)


async def _get_cached_rules(redis: Redis, key: str) -> list[dict] | None:
    """Fetch and JSON-decode a cached rule list, tolerating Redis errors.

    Args:
        redis(Redis): The Redis client to read from.
        key(str): The cache key to fetch.

    Return:
        rules(list[dict] | None): The cached rule dicts, or None on a cache
            miss or any Redis/decode error.
    """
    try:
        raw = await redis.get(key)
    except Exception:
        logger.exception("proxy_auth rules cache read failed for key=%s", key)
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        logger.exception("proxy_auth rules cache decode failed for key=%s", key)
        return None


async def _set_cached_rules(redis: Redis, key: str, rules: list[dict], ttl: int) -> None:
    """JSON-encode and store a rule list in the cache, tolerating Redis errors.

    Args:
        redis(Redis): The Redis client to write to.
        key(str): The cache key to store under.
        rules(list[dict]): The rule dicts to cache.
        ttl(int): Time-to-live in seconds.

    Return:
        None
    """
    try:
        await redis.set(key, json.dumps(rules), ex=ttl)
    except Exception:
        logger.exception("proxy_auth rules cache write failed for key=%s", key)


async def _load_rules(session: AsyncSession, scoped_token: ScopedToken, redis: Redis) -> list:
    """Load a scoped token's scope rules, preferring the version-keyed Redis cache.

    Args:
        session(AsyncSession): Database session.
        scoped_token(ScopedToken): The authoritative scoped token row.
        redis(Redis): Redis client used as a caching accelerator.

    Return:
        rules(list): The token's `ScopeRule` rows, or attribute-equivalent
            objects restored from cache.
    """
    key = rules_key(scoped_token.lookup_id, scoped_token.version)

    cached = await _get_cached_rules(redis, key)
    if cached is not None:
        return [_cache_dict_to_rule(item) for item in cached]

    result = await session.execute(
        select(ScopeRule).where(ScopeRule.scoped_token_id == scoped_token.id)
    )
    rules = list(result.scalars().all())

    await _set_cached_rules(
        redis, key, [_rule_to_cache_dict(rule) for rule in rules], get_settings().rules_cache_ttl
    )
    return rules


async def resolve_scoped_token(
    session: AsyncSession, full_token: str, redis: Redis
) -> ProxyAuthContext | None:
    """Resolve a full scoped token string into its authorization context.

    Steps: parse the token into `(lookup_id, secret)`; perform the
    authoritative indexed SELECT of the `ScopedToken` by `lookup_id`;
    constant-time verify the presented token against the stored hash; require
    `status == "active"` and a non-expired token; then load the token's scope
    rules (version-keyed Redis cache, falling back to the database and
    populating the cache) and its upstream credential. Any failure at any
    step returns None.

    Args:
        session(AsyncSession): Database session.
        full_token(str): The full scoped token string presented by the client.
        redis(Redis): Redis client used as a caching accelerator.

    Return:
        context(ProxyAuthContext | None): The resolved authorization context,
            or None if the token is malformed, unknown, invalid, inactive,
            expired, or its credential cannot be found.
    """
    parsed = parse_scoped_token(full_token)
    if parsed is None:
        return None
    lookup_id, _secret = parsed

    result = await session.execute(
        select(ScopedToken).where(ScopedToken.lookup_id == lookup_id)
    )
    scoped_token = result.scalar_one_or_none()
    if scoped_token is None:
        return None

    if not verify_token(full_token, scoped_token.token_hash):
        return None

    if scoped_token.status != "active":
        return None

    if scoped_token.expires_at is not None and scoped_token.expires_at < datetime.now(UTC):
        return None

    credential_result = await session.execute(
        select(UpstreamCredential).where(
            UpstreamCredential.id == scoped_token.upstream_credential_id
        )
    )
    credential = credential_result.scalar_one_or_none()
    if credential is None:
        return None

    rules = await _load_rules(session, scoped_token, redis)

    return ProxyAuthContext(token=scoped_token, rules=rules, credential=credential)


async def require_scoped_token(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    redis: Annotated[Any, Depends(get_redis)],
) -> ProxyAuthContext:
    """FastAPI dependency resolving the scoped-token auth context for a proxy request.

    Args:
        request(Request): The incoming `/client/v4` request.
        session(AsyncSession): Database session.
        redis(Redis): Redis client used as a caching accelerator.

    Return:
        context(ProxyAuthContext): The resolved authorization context for the
            presented `Authorization: Bearer <token>` header.
    """
    authorization = request.headers.get("Authorization", "")
    scheme, _, full_token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not full_token:
        raise HTTPException(
            status_code=401,
            detail={"code": cf_errors.TOKEN_INVALID, "message": "Invalid API Token"},
        )

    context = await resolve_scoped_token(session, full_token, redis)
    if context is None:
        raise HTTPException(
            status_code=401,
            detail={"code": cf_errors.TOKEN_INVALID, "message": "Invalid API Token"},
        )

    return context
