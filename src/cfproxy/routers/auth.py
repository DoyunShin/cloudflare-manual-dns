"""Local recovery-admin authentication and service session endpoints."""

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.cache.redis import get_redis
from cfproxy.core.security import (
    clear_management_session_cookie,
    create_service_session,
    get_current_user,
    validate_same_origin_request,
    verify_password,
)
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import ManagementSession, User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import LoginRequest, SessionResponse, UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])
_LOGIN_RATE_LIMIT = 5
_LOGIN_RATE_WINDOW_SECONDS = 300


def _response_doc(description: str, status: int, message: str) -> dict[str, Any]:
    """Build compact OpenAPI documentation for an envelope response."""
    return {
        "description": description,
        "content": {
            "application/json": {
                "example": {"status": status, "message": message, "data": None}
            }
        },
    }


def _envelope(status: int, message: str, data: Any = None) -> dict[str, Any]:
    """Build a management response envelope for FastAPI serialization."""
    return {"status": status, "message": message, "data": data}


def _user_response_data(user: User) -> dict[str, Any]:
    """Serialize a User row into JSON-safe response data."""
    return UserResponse.model_validate(user).model_dump(mode="json")


def _client_ip(request: Request) -> str:
    """Return the direct peer address used for local-login rate limiting."""
    return request.client.host if request.client is not None else "unknown"


async def _check_login_rate_limit(request: Request) -> None:
    """Enforce the fail-closed Redis login rate limit."""
    key = f"login_rate:{_client_ip(request)}"
    try:
        redis = get_redis()
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, _LOGIN_RATE_WINDOW_SECONDS)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Login service temporarily unavailable") from exc
    if count > _LOGIN_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many login attempts")


@router.post(
    "/login",
    responses={
        200: {
            "description": "Local administrator login successful",
            "content": {
                "application/json": {
                    "example": {
                        "status": 200,
                        "message": "Login successful",
                        "data": {
                            "user": {
                                "id": "5b1e2f0a-9a3b-4a0e-9c1a-8f6d3c2b7a10",
                                "email": "admin@example.com",
                                "display_name": None,
                                "auth_provider": "local",
                                "is_admin": True,
                                "is_active": True,
                                "created_at": "2026-07-15T09:30:00+00:00",
                            },
                            "csrf_token": "opaque-csrf-token",
                        },
                    }
                }
            },
        },
        401: _response_doc("Invalid credentials", 401, "Invalid email or password"),
        403: _response_doc("Invalid request origin", 403, "Invalid request origin"),
        415: _response_doc(
            "Unsupported request body", 415, "Content-Type must be application/json"
        ),
        422: _response_doc("Invalid login payload", 422, "Validation error"),
        429: _response_doc("Login rate limit exceeded", 429, "Too many login attempts"),
        503: _response_doc(
            "Redis rate limiter unavailable", 503, "Login service temporarily unavailable"
        ),
    },
)
async def login(body: LoginRequest, request: Request, response: Response, session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    """Authenticate an active local recovery administrator.

    Args:
        body: Local administrator credentials.
        request: Incoming browser request.
        response: Response receiving the secure service cookie.
        session: Database session.

    Returns:
        Standard envelope with current user and CSRF token.
    """
    if not request.headers.get("content-type", "").lower().startswith("application/json"):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")
    validate_same_origin_request(request)
    await _check_login_rate_limit(request)

    result = await session.execute(
        select(User).where(
            User.local_login == body.email.casefold(),
            User.auth_provider == "local",
        )
    )
    user = result.scalar_one_or_none()
    if (
        user is None
        or user.password_hash is None
        or not user.is_active
        or not user.is_admin
        or not verify_password(body.password, user.password_hash)
    ):
        response.status_code = 401
        return _envelope(401, "Invalid email or password")

    verified_password_hash = user.password_hash
    locked_result = await session.execute(
        with_row_lock(
            session,
            select(User)
            .where(User.id == user.id)
            .execution_options(populate_existing=True),
        )
    )
    user = locked_result.scalar_one_or_none()
    if (
        user is None
        or not user.is_active
        or not user.is_admin
        or user.auth_provider != "local"
        or user.local_login != body.email.casefold()
        or user.password_hash != verified_password_hash
    ):
        await session.rollback()
        response.status_code = 401
        return _envelope(401, "Invalid email or password")

    response.status_code = 200
    _management_session, csrf_token = await create_service_session(
        response,
        user,
        session,
        auth_method="local",
        request=request,
    )
    await session.commit()
    data = SessionResponse(
        user=UserResponse.model_validate(user),
        csrf_token=csrf_token,
    ).model_dump(mode="json")
    return _envelope(200, "Login successful", data)


@router.get(
    "/me",
    responses={
        200: _response_doc("Current service user and CSRF token", 200, "Current user"),
        401: _response_doc(
            "Missing, expired, revoked, or inactive session", 401, "Not authenticated"
        ),
    },
)
async def read_me(request: Request, current_user: Annotated[User, Depends(get_current_user)]) -> dict[str, Any]:
    """Return the authenticated user and the current session's CSRF token.

    Args:
        request: Request carrying the resolved management session state.
        current_user: Authenticated active service user.

    Returns:
        Standard envelope with current user and CSRF token.
    """
    management_session: ManagementSession = request.state.management_session
    data = SessionResponse(
        user=UserResponse.model_validate(current_user),
        csrf_token=management_session.csrf_secret,
    ).model_dump(mode="json")
    return _envelope(200, "Current user", data)


@router.post(
    "/logout",
    responses={
        200: _response_doc("Service session revoked", 200, "Logged out"),
        401: _response_doc("Missing or invalid service session", 401, "Not authenticated"),
        403: _response_doc("Invalid origin or CSRF token", 403, "Invalid CSRF token"),
    },
)
async def logout(request: Request, response: Response, current_user: Annotated[User, Depends(get_current_user)], session: Annotated[AsyncSession, Depends(get_session)]) -> dict[str, Any]:
    """Revoke only the local service session without contacting the IdP.

    Args:
        request: Request carrying the resolved management session state.
        response: Response clearing the session cookie.
        current_user: Authenticated service user.
        session: Database session.

    Returns:
        Empty standard success envelope.
    """
    del current_user
    management_session: ManagementSession = request.state.management_session
    management_session.revoked_at = datetime.now(UTC)
    await session.commit()
    clear_management_session_cookie(response)
    return _envelope(200, "Logged out")
