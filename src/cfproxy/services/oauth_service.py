"""Cloudflare OAuth state handling and delegated credential persistence."""

import json
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.oauth_cf import build_authorize_url, exchange_code, make_pkce
from cfproxy.cache.redis import cache_del, get_redis, oauth_at_key, zones_key
from cfproxy.config import get_settings
from cfproxy.core.crypto import encrypt_secret
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import ManagementSession, OIDCConfig, UpstreamCredential, User


_OAUTH_CREDENTIAL_LABEL = "cloudflare-oauth"
_CF_STATE_PREFIX = "cf_oauth_state:"


class CloudflareOAuthError(Exception):
    """Raised for safe Cloudflare OAuth flow failures."""


class CloudflareOAuthStateError(CloudflareOAuthError):
    """Raised when single-use state is unavailable or session-mismatched."""


async def _store_state(state: str, payload: dict[str, Any]) -> None:
    """Store security-critical Cloudflare OAuth state, failing closed."""
    try:
        stored = await get_redis().set(
            f"{_CF_STATE_PREFIX}{state}",
            json.dumps(payload),
            ex=get_settings().oauth_state_ttl,
        )
    except Exception as exc:
        raise CloudflareOAuthStateError("Cloudflare OAuth state is unavailable") from exc
    if not stored:
        raise CloudflareOAuthStateError("Cloudflare OAuth state could not be stored")


async def _consume_state(state: str, user_id: str, management_session_id: str) -> dict[str, Any]:
    """Consume state and require the initiating user and service session."""
    try:
        raw = await get_redis().getdel(f"{_CF_STATE_PREFIX}{state}")
    except Exception as exc:
        raise CloudflareOAuthStateError("Cloudflare OAuth state is unavailable") from exc
    if raw is None:
        raise CloudflareOAuthStateError("Cloudflare OAuth state is invalid or expired")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise CloudflareOAuthStateError("Cloudflare OAuth state is malformed") from exc
    if payload.get("user_id") != user_id or payload.get("management_session_id") != management_session_id:
        raise CloudflareOAuthStateError("Cloudflare OAuth state does not match this session")
    return payload


async def start_cf_oauth_connect(user_id: str, management_session_id: str) -> str:
    """Start Cloudflare consent bound to an active service session.

    Args:
        user_id: Authenticated service user initiating consent.
        management_session_id: Active session that must complete consent.

    Returns:
        Cloudflare authorization URL containing single-use state and PKCE.
    """
    settings = get_settings()
    if not settings.cf_oauth_client_id or not settings.cf_oauth_client_secret:
        raise CloudflareOAuthError("Cloudflare OAuth is not configured")
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(32)
    await _store_state(
        state,
        {
            "verifier": verifier,
            "user_id": user_id,
            "management_session_id": management_session_id,
        },
    )
    return build_authorize_url(state, challenge)


async def reject_cf_oauth_callback(state: str, user_id: str, management_session_id: str) -> None:
    """Consume and validate state for a provider-declined callback.

    Args:
        state: Single-use callback state.
        user_id: Authenticated service user completing consent.
        management_session_id: Session that initiated consent.

    Returns:
        None.
    """
    await _consume_state(state, user_id, management_session_id)


def _parse_expiry(tokens: dict[str, Any]) -> datetime | None:
    """Convert a provider expires_in value to an absolute UTC timestamp."""
    expires_in = tokens.get("expires_in")
    if expires_in is None:
        return None
    if isinstance(expires_in, bool):
        raise CloudflareOAuthError("Cloudflare token expiry is invalid")
    try:
        seconds = int(expires_in)
    except (TypeError, ValueError) as exc:
        raise CloudflareOAuthError("Cloudflare token expiry is invalid") from exc
    if seconds <= 0 or seconds > 31_536_000:
        raise CloudflareOAuthError("Cloudflare token expiry is invalid")
    return datetime.now(UTC) + timedelta(seconds=seconds)


async def complete_cf_oauth_connect(session: AsyncSession, code: str, state: str, user_id: str, management_session_id: str) -> UpstreamCredential:
    """Attach a Cloudflare OAuth grant to the initiating service user.

    Args:
        session: Database session used to validate and persist the grant.
        code: Cloudflare authorization code.
        state: Single-use state bound to the initiating session.
        user_id: Authenticated service user completing consent.
        management_session_id: Session that initiated consent.

    Returns:
        Stored or reconnected delegated Cloudflare credential.
    """
    stored = await _consume_state(state, user_id, management_session_id)
    try:
        tokens = await exchange_code(code, stored["verifier"])
    except Exception as exc:
        raise CloudflareOAuthError("Cloudflare token exchange failed") from exc
    if not isinstance(tokens, dict):
        raise CloudflareOAuthError("Cloudflare token response is invalid")
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not access_token:
        raise CloudflareOAuthError("Cloudflare token response is missing access_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise CloudflareOAuthError("Cloudflare token response is missing refresh_token")
    if len(access_token.encode("utf-8")) > 2800 or len(refresh_token.encode("utf-8")) > 2800:
        raise CloudflareOAuthError("Cloudflare token response is too large")
    expires_at = _parse_expiry(tokens)

    config_result = await session.execute(
        with_row_lock(
            session,
            select(OIDCConfig)
            .where(OIDCConfig.id == 1)
            .execution_options(populate_existing=True),
        )
    )
    config = config_result.scalar_one_or_none()
    user_result = await session.execute(
        with_row_lock(
            session,
            select(User)
            .where(User.id == user_id)
            .execution_options(populate_existing=True),
        )
    )
    active_user = user_result.scalar_one_or_none()
    session_result = await session.execute(
        with_row_lock(
            session,
            select(ManagementSession)
            .where(
                ManagementSession.id == management_session_id,
                ManagementSession.user_id == user_id,
            )
            .execution_options(populate_existing=True),
        )
    )
    active_session = session_result.scalar_one_or_none()
    now = datetime.now(UTC)
    if (
        active_user is None
        or not active_user.is_active
        or active_session is None
        or active_session.revoked_at is not None
        or active_session.expires_at <= now
        or (
            active_session.auth_method == "oidc"
            and (
                config is None
                or not config.enabled
                or active_session.provider_revision != config.revision
            )
        )
    ):
        raise CloudflareOAuthStateError("The initiating service session is no longer active")
    statement = (
        select(UpstreamCredential)
        .where(
            UpstreamCredential.user_id == user_id,
            UpstreamCredential.label == _OAUTH_CREDENTIAL_LABEL,
        )
        .execution_options(populate_existing=True)
    )
    result = await session.execute(with_row_lock(session, statement))
    credential = result.scalar_one_or_none()
    old_version: int | None = None
    if credential is None:
        credential = UpstreamCredential(
            user_id=user_id,
            label=_OAUTH_CREDENTIAL_LABEL,
            cred_type="oauth",
            cred_version=1,
        )
        session.add(credential)
    elif credential.cred_type != "oauth":
        raise CloudflareOAuthError("The reserved Cloudflare OAuth credential label is in use")
    else:
        old_version = credential.cred_version
        credential.cred_version += 1
    credential.access_token_enc = encrypt_secret(access_token)
    credential.refresh_token_enc = encrypt_secret(refresh_token)
    credential.token_expires_at = expires_at
    scope = tokens.get("scope")
    if isinstance(scope, str) and scope:
        credential.oauth_scopes = scope
    await session.commit()
    await session.refresh(credential)
    if old_version is not None:
        await cache_del(
            oauth_at_key(credential.id, old_version),
            zones_key(credential.id, old_version),
        )
    return credential
