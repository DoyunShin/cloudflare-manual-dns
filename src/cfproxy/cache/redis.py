"""Redis-backed caching accelerator.

Every function here tolerates Redis being absent or erroring by logging and
falling back to a no-op / None result -- callers must always be able to fall
through to their authoritative database path.
"""

import json
import logging
from typing import Any

import redis.asyncio as redis_asyncio

from cfproxy.config import get_settings

logger = logging.getLogger(__name__)

_redis_client: "redis_asyncio.Redis | None" = None


def get_redis() -> "redis_asyncio.Redis":
    """Return the shared Redis client, creating it from settings if needed.

    Return:
        client(redis.asyncio.Redis): The shared Redis client instance.
    """
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_asyncio.from_url(get_settings().redis_url)
    return _redis_client


def set_redis_for_test(client: "redis_asyncio.Redis") -> None:
    """Override the shared Redis client, for use by tests (e.g. fakeredis).

    Args:
        client(redis.asyncio.Redis): The client instance to use in place of
            the real Redis connection.

    Return:
        None
    """
    global _redis_client
    _redis_client = client


async def cache_get_json(key: str) -> Any | None:
    """Fetch and JSON-decode a cached value.

    Args:
        key(str): The cache key.

    Return:
        value(Any | None): The decoded value, or None if missing or on error.
    """
    try:
        raw = await get_redis().get(key)
    except Exception:
        logger.exception("cache_get_json failed for key=%s", key)
        return None
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        logger.exception("cache_get_json failed to decode key=%s", key)
        return None


async def cache_set_json(key: str, value: Any, ttl: int) -> None:
    """JSON-encode and store a value in the cache with a TTL.

    Args:
        key(str): The cache key.
        value(Any): The JSON-serializable value to store.
        ttl(int): Time-to-live in seconds.

    Return:
        None
    """
    try:
        await get_redis().set(key, json.dumps(value), ex=ttl)
    except Exception:
        logger.exception("cache_set_json failed for key=%s", key)


async def cache_del(*keys: str) -> None:
    """Delete one or more cache keys.

    Args:
        *keys(str): Cache keys to delete.

    Return:
        None
    """
    if not keys:
        return
    try:
        await get_redis().delete(*keys)
    except Exception:
        logger.exception("cache_del failed for keys=%s", keys)


async def rate_limit_incr(key: str, window: int) -> int:
    """Increment a rate-limit counter, setting its expiry on first increment.

    Args:
        key(str): The rate-limit counter key.
        window(int): Expiry window in seconds, applied when the counter is new.

    Return:
        count(int): The counter value after incrementing, or 0 on error.
    """
    try:
        client = get_redis()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window)
        return count
    except Exception:
        logger.exception("rate_limit_incr failed for key=%s", key)
        return 0


def rules_key(lookup_id: str, version: int) -> str:
    """Build the cache key for a scoped token's rule set.

    Args:
        lookup_id(str): The scoped token's lookup id.
        version(int): The scoped token's rule version.

    Return:
        key(str): The Redis key for the cached rules.
    """
    return f"rules:{lookup_id}:{version}"


def oauth_at_key(cred_id: str) -> str:
    """Build the cache key for a credential's encrypted OAuth access token.

    Args:
        cred_id(str): The upstream credential id.

    Return:
        key(str): The Redis key for the cached access token.
    """
    return f"oauth_at:{cred_id}"


def zones_key(cred_id: str) -> str:
    """Build the cache key for a credential's cached zone list.

    Args:
        cred_id(str): The upstream credential id.

    Return:
        key(str): The Redis key for the cached zones.
    """
    return f"zones:{cred_id}"


def oauth_state_key(state: str) -> str:
    """Build the cache key for an in-flight OAuth state value.

    Args:
        state(str): The OAuth state parameter.

    Return:
        key(str): The Redis key for the cached OAuth state.
    """
    return f"oauth_state:{state}"
