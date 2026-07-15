"""Business logic for registering, verifying, listing, and deleting stored
upstream Cloudflare credentials (pasted API tokens and Global API Keys), plus
the scope-builder helpers that list a credential's visible zones/records.

Every lookup by id is scoped by the owning `user_id` -- a credential id that
exists but belongs to a different user is treated identically to a missing
one (`NotFoundError`), never leaking its existence (anti-IDOR).
"""

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.cache.redis import (
    cache_del,
    cache_get_json,
    cache_set_json,
    oauth_at_key,
    rules_key,
    zones_key,
)
from cfproxy.config import get_settings
from cfproxy.core.crypto import encrypt_secret
from cfproxy.db.models import ScopedToken, UpstreamCredential
from cfproxy.upstream.client import (
    forward_request,
    list_all_records,
    resolve_upstream_auth,
    verify_upstream,
)

_SUPPORTED_CRED_TYPES = {"token", "global_key"}


class NotFoundError(Exception):
    """Raised when an id-addressed resource does not exist or is not owned by the caller."""


async def get_owned_credential(
    session: AsyncSession, user_id: str, credential_id: str
) -> UpstreamCredential:
    """Load an upstream credential scoped to its owning user.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id.
        credential_id(str): The credential id to load.

    Return:
        credential(UpstreamCredential): The owned credential row.

    Raises:
        NotFoundError: If no credential with this id is owned by `user_id`.
    """
    result = await session.execute(
        select(UpstreamCredential).where(
            UpstreamCredential.id == credential_id, UpstreamCredential.user_id == user_id
        )
    )
    credential = result.scalar_one_or_none()
    if credential is None:
        raise NotFoundError(f"upstream credential {credential_id!r} not found")
    return credential


async def register_credential(
    session: AsyncSession,
    user_id: str,
    label: str,
    cred_type: str,
    *,
    api_token: str | None = None,
    global_key: str | None = None,
    cf_account_email: str | None = None,
) -> UpstreamCredential:
    """Register a new pasted upstream Cloudflare credential.

    `cred_type="token"` stores the plaintext API token, Fernet-encrypted.
    `cred_type="global_key"` stores a Fernet-encrypted JSON blob of
    `{"email", "key"}`, since a Global API Key must always be paired with
    its account email to authenticate.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The owning user's id.
        label(str): A user-chosen label, unique per user.
        cred_type(str): Either "token" or "global_key".
        api_token(str, optional): The plaintext API token (required for "token").
        global_key(str, optional): The plaintext Global API Key (required for "global_key").
        cf_account_email(str, optional): The Cloudflare account email (required for "global_key").

    Return:
        credential(UpstreamCredential): The persisted credential row.

    Raises:
        ValueError: If `cred_type` is unsupported or a required secret is missing.
    """
    if cred_type not in _SUPPORTED_CRED_TYPES:
        raise ValueError(f"unsupported cred_type: {cred_type!r}")

    if cred_type == "token":
        if not api_token:
            raise ValueError("api_token is required for cred_type='token'")
        secret_plain = api_token
    else:
        if not global_key or not cf_account_email:
            raise ValueError(
                "global_key and cf_account_email are required for cred_type='global_key'"
            )
        secret_plain = json.dumps({"email": cf_account_email, "key": global_key})

    credential = UpstreamCredential(
        user_id=user_id,
        label=label,
        cred_type=cred_type,
        secret_enc=encrypt_secret(secret_plain),
        cf_account_email=cf_account_email,
    )
    session.add(credential)
    await session.commit()
    await session.refresh(credential)
    return credential


async def verify_credential(
    session: AsyncSession, user_id: str, credential_id: str
) -> UpstreamCredential:
    """Verify a stored upstream credential against the real Cloudflare API.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        credential_id(str): The credential id to verify.

    Return:
        credential(UpstreamCredential): The credential row, updated with the
            latest `verify_status` and `verified_at`.

    Raises:
        NotFoundError: If the credential does not exist or is not owned by `user_id`.
    """
    credential = await get_owned_credential(session, user_id, credential_id)
    auth_headers = await resolve_upstream_auth(session, credential)
    envelope = await verify_upstream(auth_headers)

    credential.verify_status = "active" if envelope.get("success") else "invalid"
    credential.verified_at = datetime.now(UTC)

    result = envelope.get("result")
    if isinstance(result, dict) and result.get("email"):
        credential.cf_account_email = result["email"]

    await session.commit()
    await session.refresh(credential)
    return credential


async def list_credentials(session: AsyncSession, user_id: str) -> list[UpstreamCredential]:
    """List every upstream credential owned by a user.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The owning user's id.

    Return:
        credentials(list[UpstreamCredential]): The user's credential rows.
    """
    result = await session.execute(
        select(UpstreamCredential).where(UpstreamCredential.user_id == user_id)
    )
    return list(result.scalars().all())


async def delete_credential(session: AsyncSession, user_id: str, credential_id: str) -> None:
    """Delete an upstream credential, cascade-revoking every scoped token bound to it.

    Every still-active `ScopedToken` referencing this credential is marked
    revoked and has its `version` bumped (invalidating its cached rules)
    before the credential row itself is deleted.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        credential_id(str): The credential id to delete.

    Return:
        None

    Raises:
        NotFoundError: If the credential does not exist or is not owned by `user_id`.
    """
    credential = await get_owned_credential(session, user_id, credential_id)

    dependent_tokens = await session.execute(
        select(ScopedToken).where(
            ScopedToken.upstream_credential_id == credential_id,
            ScopedToken.status == "active",
        )
    )
    for scoped_token in dependent_tokens.scalars().all():
        old_lookup_id = scoped_token.lookup_id
        old_version = scoped_token.version
        scoped_token.status = "revoked"
        scoped_token.revoked_at = datetime.now(UTC)
        scoped_token.version = old_version + 1
        await cache_del(rules_key(old_lookup_id, old_version))

    await cache_del(oauth_at_key(credential_id), zones_key(credential_id))
    await session.delete(credential)
    await session.commit()


async def list_credential_zones(
    session: AsyncSession, user_id: str, credential_id: str
) -> list[dict]:
    """List the Cloudflare zones visible to a stored credential (Redis-cached).

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        credential_id(str): The credential whose zones to list.

    Return:
        zones(list[dict]): The concatenated `result` items across all upstream pages.

    Raises:
        NotFoundError: If the credential does not exist or is not owned by `user_id`.
    """
    credential = await get_owned_credential(session, user_id, credential_id)

    key = zones_key(credential_id)
    cached = await cache_get_json(key)
    if cached is not None:
        return cached

    auth_headers = await resolve_upstream_auth(session, credential)

    zones: list[dict] = []
    page = 1
    while True:
        response = await forward_request(
            "GET",
            "/client/v4/zones",
            headers=None,
            params={"page": page, "per_page": 50},
            content=None,
            auth_headers=auth_headers,
        )
        response.raise_for_status()
        body = response.json()
        zones.extend(body.get("result") or [])
        result_info = body.get("result_info") or {}
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1

    await cache_set_json(key, zones, get_settings().rules_cache_ttl)
    return zones


async def list_credential_zone_records(
    session: AsyncSession,
    user_id: str,
    credential_id: str,
    zone_id: str,
    params: dict | None = None,
) -> list[dict]:
    """List every DNS record in a zone visible to a stored credential.

    Args:
        session(AsyncSession): Database session.
        user_id(str): The requesting user's id (ownership check).
        credential_id(str): The credential to list records through.
        zone_id(str): The Cloudflare zone id to list records for.
        params(dict, optional): Client-supplied list filters (e.g. `type`, `name`).

    Return:
        records(list[dict]): The concatenated `result` items across all upstream pages.

    Raises:
        NotFoundError: If the credential does not exist or is not owned by `user_id`.
    """
    credential = await get_owned_credential(session, user_id, credential_id)
    auth_headers = await resolve_upstream_auth(session, credential)
    return await list_all_records(zone_id, params, auth_headers)
