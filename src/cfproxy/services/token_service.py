"""Business logic for minting, inspecting, rotating, and revoking
record-scoped proxy tokens.

Every lookup by id is scoped by the owning `user_id` (anti-IDOR): a scoped
token, or upstream credential, that exists but belongs to a different user
raises `cfproxy.services.credential_service.NotFoundError`, identical to a
truly missing id.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.authz.scope import validate_name_pattern
from cfproxy.cache.redis import cache_del, rules_key
from cfproxy.core.crypto import generate_scoped_token
from cfproxy.db.models import ScopedToken, ScopeRule, UpstreamCredential
from cfproxy.services.credential_service import NotFoundError, get_owned_credential
from cfproxy.upstream.client import forward_request, resolve_upstream_auth


@dataclass
class ScopedTokenDetail:
    """A scoped token together with its scope rules.

    Args:
        token(ScopedToken): The scoped token row.
        rules(list[ScopeRule]): The token's scope rules.
    """

    token: ScopedToken
    rules: list[ScopeRule]


async def _resolve_zone_name(zone_id: str, auth_headers: dict[str, str], cache: dict[str, str]) -> str:
    """Resolve a Cloudflare zone id to its zone name, memoizing within one call.

    Args:
        zone_id(str): The Cloudflare zone id.
        auth_headers(dict[str, str]): The upstream authentication headers to forward.
        cache(dict[str, str]): A per-call memo of already-resolved zone names.

    Return:
        zone_name(str): The zone's FQDN.

    Raises:
        ValueError: If the zone id does not exist upstream.
    """
    if zone_id in cache:
        return cache[zone_id]

    response = await forward_request(
        "GET",
        f"/client/v4/zones/{zone_id}",
        headers=None,
        params=None,
        content=None,
        auth_headers=auth_headers,
    )
    if response.status_code == 404:
        raise ValueError(f"zone {zone_id!r} not found upstream")
    response.raise_for_status()

    zone_name = response.json()["result"]["name"]
    cache[zone_id] = zone_name
    return zone_name


async def _validate_scope_rules(
    session: AsyncSession, credential: UpstreamCredential, scope_rules: list[dict]
) -> None:
    """Validate a batch of scope-rule dicts before persisting them.

    Each rule must carry at least one of `name_pattern` / `record_ids`; a
    present `name_pattern` is further checked against the rule's zone name
    via `authz.scope.validate_name_pattern` (the zone name is fetched
    upstream and memoized per zone id for the duration of this call).

    Args:
        session(AsyncSession): Database session, used to resolve a bearer
            token for the zone-name lookup.
        credential(UpstreamCredential): The upstream credential the new
            token will forward through.
        scope_rules(list[dict]): The candidate rule dicts.

    Return:
        None

    Raises:
        ValueError: If `scope_rules` is empty, a rule is missing both
            `name_pattern`/`record_ids`, or its `name_pattern` does not
            validate against the zone.
    """
    if not scope_rules:
        raise ValueError("at least one scope rule is required")

    zone_name_cache: dict[str, str] = {}
    auth_headers: dict[str, str] | None = None

    for rule in scope_rules:
        if not rule.get("name_pattern") and not rule.get("record_ids"):
            raise ValueError("each scope rule requires a name_pattern or record_ids")

        if rule.get("name_pattern"):
            if auth_headers is None:
                auth_headers = await resolve_upstream_auth(session, credential)
            zone_name = await _resolve_zone_name(rule["zone_id"], auth_headers, zone_name_cache)
            validate_name_pattern(rule["name_pattern"], rule.get("name_match", "exact"), zone_name)


async def mint_scoped_token(
    session: AsyncSession,
    user_id: str,
    name: str,
    upstream_credential_id: str,
    scope_rules: list[dict],
    expires_at: datetime | None = None,
) -> dict:
    """Mint a new record-scoped proxy token.

    Validates that `upstream_credential_id` is owned by `user_id`, validates
    every scope rule, generates a new token, and persists the `ScopedToken`
    plus its `ScopeRule` rows. The raw token string is returned exactly once
    here -- only its SHA-256 hash is ever written to the database.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The owning user's id.
        name(str): A human-readable name for the token.
        upstream_credential_id(str): The upstream credential this token forwards through.
        scope_rules(list[dict]): Rule dicts with keys `zone_id`, `name_pattern`,
            `name_match`, `record_types`, `record_ids`, `allow_read`,
            `allow_create`, `allow_write`, `allow_delete`, `content_lock`.
        expires_at(datetime, optional): Optional expiration timestamp.

    Return:
        minted(dict): `{"id", "name", "token", "token_prefix", "status",
            "version", "expires_at", "created_at"}` -- `token` is the raw,
            one-time-visible scoped token string.

    Raises:
        NotFoundError: If `upstream_credential_id` is not owned by `user_id`.
        ValueError: If a scope rule is invalid.
    """
    credential = await get_owned_credential(session, user_id, upstream_credential_id)
    await _validate_scope_rules(session, credential, scope_rules)

    generated = generate_scoped_token()

    scoped_token = ScopedToken(
        user_id=user_id,
        upstream_credential_id=upstream_credential_id,
        name=name,
        lookup_id=generated["lookup_id"],
        token_prefix=generated["token_prefix"],
        token_hash=generated["token_hash"],
        expires_at=expires_at,
    )
    session.add(scoped_token)
    await session.flush()

    for rule in scope_rules:
        session.add(
            ScopeRule(
                scoped_token_id=scoped_token.id,
                zone_id=rule["zone_id"],
                name_pattern=rule.get("name_pattern"),
                name_match=rule.get("name_match", "exact"),
                record_types=rule["record_types"],
                record_ids=rule.get("record_ids"),
                allow_read=rule.get("allow_read", False),
                allow_create=rule.get("allow_create", False),
                allow_write=rule.get("allow_write", False),
                allow_delete=rule.get("allow_delete", False),
                content_lock=rule.get("content_lock"),
            )
        )

    await session.commit()
    await session.refresh(scoped_token)

    return {
        "id": scoped_token.id,
        "name": scoped_token.name,
        "token": generated["full"],
        "token_prefix": scoped_token.token_prefix,
        "status": scoped_token.status,
        "version": scoped_token.version,
        "expires_at": scoped_token.expires_at,
        "created_at": scoped_token.created_at,
    }


async def _get_owned_scoped_token(session: AsyncSession, user_id: str, token_id: str) -> ScopedToken:
    """Load a scoped token scoped to its owning user.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id.
        token_id(str): The scoped token id to load.

    Return:
        scoped_token(ScopedToken): The owned scoped token row.

    Raises:
        NotFoundError: If no scoped token with this id is owned by `user_id`.
    """
    result = await session.execute(
        select(ScopedToken).where(ScopedToken.id == token_id, ScopedToken.user_id == user_id)
    )
    scoped_token = result.scalar_one_or_none()
    if scoped_token is None:
        raise NotFoundError(f"scoped token {token_id!r} not found")
    return scoped_token


async def list_scoped_tokens(session: AsyncSession, user_id: str) -> list[ScopedToken]:
    """List every scoped token owned by a user.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The owning user's id.

    Return:
        scoped_tokens(list[ScopedToken]): The user's scoped token rows.
    """
    result = await session.execute(select(ScopedToken).where(ScopedToken.user_id == user_id))
    return list(result.scalars().all())


async def get_scoped_token_detail(
    session: AsyncSession, user_id: str, token_id: str
) -> ScopedTokenDetail:
    """Load a scoped token and its scope rules, scoped to its owning user.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id.
        token_id(str): The scoped token id to load.

    Return:
        detail(ScopedTokenDetail): The token row and its scope rules.

    Raises:
        NotFoundError: If the token does not exist or is not owned by `user_id`.
    """
    scoped_token = await _get_owned_scoped_token(session, user_id, token_id)
    result = await session.execute(
        select(ScopeRule).where(ScopeRule.scoped_token_id == scoped_token.id)
    )
    return ScopedTokenDetail(token=scoped_token, rules=list(result.scalars().all()))


async def rotate_scoped_token(session: AsyncSession, user_id: str, token_id: str) -> dict:
    """Rotate a scoped token: issue a new secret, bump its version, invalidate the cache.

    A fresh `lookup_id` + `secret` pair is generated (stronger than reusing
    the old `lookup_id`, since the compromised raw token can then never be
    revalidated even by lookup_id alone); the token's `version` is bumped so
    a stale rules-cache read under the old `(lookup_id, version)` key can
    never resolve to this row again, and that old cache key is explicitly
    invalidated.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        token_id(str): The scoped token id to rotate.

    Return:
        rotated(dict): `{"id", "token", "token_prefix", "version"}` -- `token`
            is the new raw scoped token string, visible only once.

    Raises:
        NotFoundError: If the token does not exist or is not owned by `user_id`.
    """
    scoped_token = await _get_owned_scoped_token(session, user_id, token_id)

    old_lookup_id = scoped_token.lookup_id
    old_version = scoped_token.version

    generated = generate_scoped_token()
    scoped_token.lookup_id = generated["lookup_id"]
    scoped_token.token_prefix = generated["token_prefix"]
    scoped_token.token_hash = generated["token_hash"]
    scoped_token.version = old_version + 1

    await session.commit()
    await session.refresh(scoped_token)

    await cache_del(rules_key(old_lookup_id, old_version))

    return {
        "id": scoped_token.id,
        "token": generated["full"],
        "token_prefix": scoped_token.token_prefix,
        "version": scoped_token.version,
    }


async def revoke_scoped_token(session: AsyncSession, user_id: str, token_id: str) -> None:
    """Revoke a scoped token: mark it revoked, bump its version, invalidate the cache.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        token_id(str): The scoped token id to revoke.

    Return:
        None

    Raises:
        NotFoundError: If the token does not exist or is not owned by `user_id`.
    """
    scoped_token = await _get_owned_scoped_token(session, user_id, token_id)

    old_version = scoped_token.version
    scoped_token.status = "revoked"
    scoped_token.revoked_at = datetime.now(UTC)
    scoped_token.version = old_version + 1

    await session.commit()

    await cache_del(rules_key(scoped_token.lookup_id, old_version))
