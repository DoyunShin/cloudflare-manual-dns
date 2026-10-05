"""Password hashing and server-side management session helpers."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.config import get_settings
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import ManagementSession, OIDCConfig, User
from cfproxy.db.session import get_session

MANAGEMENT_SESSION_COOKIE = "__Host-cfproxy_session"
CSRF_HEADER = "X-CSRF-Token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_password_hasher = PasswordHasher()


def hash_password(pw: str) -> str:
    """Hash a plaintext password using Argon2.

    Args:
        pw: Plaintext password.

    Returns:
        Argon2 password hash.
    """
    return _password_hasher.hash(pw)


def verify_password(pw: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2 hash.

    Args:
        pw: Plaintext password to check.
        password_hash: Stored Argon2 password hash.

    Returns:
        True when the password matches the hash.
    """
    try:
        return _password_hasher.verify(password_hash, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_session_token(raw_token: str) -> str:
    """Hash an opaque management session token for database lookup.

    Args:
        raw_token: Opaque token held by the browser.

    Returns:
        Lowercase SHA-256 digest.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


def validate_same_origin_request(request: Request) -> None:
    """Reject a browser mutation that does not originate from APP_BASE_URL.

    Args:
        request: Incoming management request.

    Returns:
        None.
    """
    if request.headers.get("origin") != get_settings().app_base_url:
        raise HTTPException(status_code=403, detail="Invalid request origin")


def set_management_session_cookie(response: Response, raw_token: str) -> None:
    """Attach a secure management-session cookie to a response.

    Args:
        response: Response receiving the cookie.
        raw_token: Opaque session token.

    Returns:
        None.
    """
    response.set_cookie(
        key=MANAGEMENT_SESSION_COOKIE,
        value=raw_token,
        max_age=get_settings().session_ttl_seconds,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def clear_management_session_cookie(response: Response) -> None:
    """Expire the browser management-session cookie.

    Args:
        response: Response clearing the cookie.

    Returns:
        None.
    """
    response.delete_cookie(
        key=MANAGEMENT_SESSION_COOKIE,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


async def _revoke_request_session(request: Request, session: AsyncSession) -> None:
    """Revoke the active cookie session, if the request carries one."""
    raw_token = request.cookies.get(MANAGEMENT_SESSION_COOKIE)
    if raw_token is None:
        return
    stmt = select(ManagementSession).where(
        ManagementSession.token_hash == hash_session_token(raw_token),
        ManagementSession.revoked_at.is_(None),
    )
    result = await session.execute(with_row_lock(session, stmt))
    current_session = result.scalar_one_or_none()
    if current_session is not None:
        current_session.revoked_at = datetime.now(UTC)


async def create_service_session(response: Response, user: User, session: AsyncSession, auth_method: str = "local", provider_revision: int | None = None, request: Request | None = None) -> tuple[ManagementSession, str]:
    """Create a database-backed service session and set its browser cookie.

    Args:
        response: Response receiving the opaque session cookie.
        user: Authenticated service user.
        session: Active database transaction.
        auth_method: Authentication method, either ``local`` or ``oidc``.
        provider_revision: OIDC configuration revision used for authentication.
        request: Optional request whose previous session should be revoked.

    Returns:
        Created session row and the CSRF token returned to the browser.
    """
    if auth_method == "oidc" and provider_revision is None:
        raise ValueError("OIDC sessions require a provider revision")
    if request is not None:
        await _revoke_request_session(request, session)

    raw_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    management_session = ManagementSession(
        token_hash=hash_session_token(raw_token),
        user_id=user.id,
        auth_method=auth_method,
        provider_revision=provider_revision,
        csrf_secret=csrf_token,
        expires_at=datetime.now(UTC) + timedelta(seconds=get_settings().session_ttl_seconds),
    )
    session.add(management_session)
    await session.flush()
    set_management_session_cookie(response, raw_token)
    return management_session, csrf_token


async def _load_management_session(raw_token: str, session: AsyncSession) -> ManagementSession:
    """Resolve and validate an opaque management session token."""
    result = await session.execute(
        select(ManagementSession).where(
            ManagementSession.token_hash == hash_session_token(raw_token)
        )
    )
    management_session = result.scalar_one_or_none()
    now = datetime.now(UTC)
    if (
        management_session is None
        or management_session.revoked_at is not None
        or management_session.expires_at <= now
    ):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if management_session.auth_method == "oidc":
        oidc_config = await session.get(OIDCConfig, 1)
        if (
            oidc_config is None
            or not oidc_config.enabled
            or management_session.provider_revision != oidc_config.revision
        ):
            raise HTTPException(status_code=401, detail="OIDC session is no longer valid")
    return management_session


def _validate_csrf(request: Request, management_session: ManagementSession) -> None:
    """Validate same-origin and CSRF credentials for a state-changing request."""
    if request.method in _SAFE_METHODS:
        return
    validate_same_origin_request(request)
    csrf_token = request.headers.get(CSRF_HEADER)
    if csrf_token is None or not secrets.compare_digest(csrf_token, management_session.csrf_secret):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


async def get_current_user(request: Request, session: Annotated[AsyncSession, Depends(get_session)]) -> User:
    """Resolve an active user from the server-side session cookie.

    Args:
        request: Incoming management request.
        session: Database session.

    Returns:
        Authenticated active user.
    """
    raw_token = request.cookies.get(MANAGEMENT_SESSION_COOKIE)
    if raw_token is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    management_session = await _load_management_session(raw_token, session)
    user = await session.get(User, management_session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or inactive user")
    _validate_csrf(request, management_session)
    request.state.management_session = management_session
    return user


async def require_admin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Require an authenticated service administrator.

    Args:
        current_user: Authenticated active user.

    Returns:
        Authenticated administrator.
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Administrator access required")
    return current_user


async def require_csrf(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Require cookie authentication and CSRF validation for mutations.

    Args:
        current_user: User already validated by ``get_current_user``.

    Returns:
        Authenticated user.
    """
    return current_user
