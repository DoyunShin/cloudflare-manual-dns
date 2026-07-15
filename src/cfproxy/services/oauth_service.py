"""Business logic for the Cloudflare OAuth2/OIDC login + delegation flow.

The same consent that authenticates the user (via `sub`) also yields a
delegated upstream credential (`cred_type="oauth"`) the proxy can use to
forward authorized DNS requests on the user's behalf.
"""

import json
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.oauth_cf import build_authorize_url, exchange_code, make_pkce, validate_id_token
from cfproxy.cache.redis import cache_set_json, get_redis, oauth_state_key
from cfproxy.config import get_settings
from cfproxy.core.crypto import encrypt_secret
from cfproxy.core.security import create_jwt
from cfproxy.db.models import UpstreamCredential, User

_OAUTH_CREDENTIAL_LABEL = "cloudflare-oauth"


async def start_cf_oauth_login() -> str:
    """Begin a Cloudflare OAuth login.

    Generates a PKCE verifier/challenge pair plus a random state and nonce,
    persists `{verifier, nonce}` in Redis keyed by `state` (single-use,
    TTL-bounded), and returns the authorize URL to redirect the user to.

    Return:
        authorize_url(str): The Cloudflare `/oauth2/auth` URL to redirect to.
    """
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)

    await cache_set_json(
        oauth_state_key(state),
        {"verifier": verifier, "nonce": nonce},
        get_settings().oauth_state_ttl,
    )
    return build_authorize_url(state, nonce, challenge)


async def _consume_oauth_state(state: str) -> dict | None:
    """Atomically fetch-and-delete a stored OAuth state, enforcing single use.

    Args:
        state(str): The `state` query parameter returned to the callback.

    Return:
        stored(dict | None): `{"verifier", "nonce"}`, or None if the state is
            unknown, already consumed, expired, or Redis errored.
    """
    try:
        raw = await get_redis().getdel(oauth_state_key(state))
    except Exception:
        return None
    if raw is None:
        return None
    return json.loads(raw)


async def handle_cf_oauth_callback(
    session: AsyncSession, code: str, state: str
) -> tuple[User, str]:
    """Handle a Cloudflare OAuth callback.

    Consumes the single-use `state`, exchanges `code` for tokens, strictly
    validates the `id_token`, upserts the user by `cf_sub`, stores the same
    consent's delegated tokens as an `oauth` upstream credential, and issues
    a session JWT.

    Args:
        session(AsyncSession): Database session.
        code(str): The authorization code returned to the callback.
        state(str): The state parameter returned to the callback.

    Return:
        result(tuple[User, str]): `(user, jwt)` for the newly authenticated session.

    Raises:
        ValueError: If `state` is missing, expired, or already consumed, or
            the token response is missing an `id_token`.
    """
    stored = await _consume_oauth_state(state)
    if stored is None:
        raise ValueError("invalid or expired oauth state")

    tokens = await exchange_code(code, stored["verifier"])
    id_token = tokens.get("id_token")
    if not id_token:
        raise ValueError("token response is missing id_token")

    claims = await validate_id_token(
        id_token,
        stored["nonce"],
        access_token=tokens.get("access_token"),
        code=code,
    )
    cf_sub = claims["sub"]
    email = claims.get("email")
    now = datetime.now(UTC)

    result = await session.execute(select(User).where(User.cf_sub == cf_sub))
    user = result.scalar_one_or_none()
    if user is None:
        user = User(email=email, auth_provider="cloudflare_oauth", cf_sub=cf_sub)
        session.add(user)
        await session.flush()
    elif email:
        user.email = email
        user.updated_at = now

    credential_result = await session.execute(
        select(UpstreamCredential).where(
            UpstreamCredential.user_id == user.id,
            UpstreamCredential.label == _OAUTH_CREDENTIAL_LABEL,
        )
    )
    credential = credential_result.scalar_one_or_none()

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in")
    token_expires_at = now + timedelta(seconds=expires_in) if expires_in is not None else None

    if credential is None:
        credential = UpstreamCredential(
            user_id=user.id,
            label=_OAUTH_CREDENTIAL_LABEL,
            cred_type="oauth",
            oauth_scopes=tokens.get("scope"),
        )
        session.add(credential)
    else:
        credential.oauth_scopes = tokens.get("scope") or credential.oauth_scopes
        credential.cred_version += 1

    if access_token:
        credential.access_token_enc = encrypt_secret(access_token)
    if refresh_token:
        credential.refresh_token_enc = encrypt_secret(refresh_token)
    credential.token_expires_at = token_expires_at

    await session.commit()
    await session.refresh(user)

    return user, create_jwt(user.id)
