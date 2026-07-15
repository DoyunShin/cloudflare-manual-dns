"""Management API router: local account registration/login and Cloudflare OAuth login."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.core.security import create_jwt, get_current_user, hash_password, verify_password
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from cfproxy.services import oauth_service

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


def _user_response_data(user: User) -> dict:
    """Serialize a User row into JSON-safe UserResponse data.

    Args:
        user(User): The user row to serialize.

    Return:
        data(dict): The `UserResponse` payload with datetimes as ISO strings.
    """
    return UserResponse.model_validate(user).model_dump(mode="json")


@router.post(
    "/register",
    responses={
        201: {
            "description": "User registered",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Successful registration",
                            "value": {
                                "status": 201,
                                "message": "User registered",
                                "data": {
                                    "id": "5b1e2f0a-9a3b-4a0e-9c1a-8f6d3c2b7a10",
                                    "email": "operator@example.com",
                                    "auth_provider": "local",
                                    "is_active": True,
                                    "created_at": "2026-07-15T09:30:00+00:00",
                                },
                            },
                        },
                    },
                },
            },
        },
        409: {
            "description": "Email already registered",
            "content": {
                "application/json": {
                    "examples": {
                        "conflict": {
                            "summary": "Duplicate email",
                            "value": {
                                "status": 409,
                                "message": "Email already registered",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def register(
    body: RegisterRequest, session: Annotated[AsyncSession, Depends(get_session)]
) -> JSONResponse:
    """Register a new local management-plane account.

    Args:
        body(RegisterRequest): The account's email and plaintext password.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping the created `UserResponse`.
    """
    existing = await session.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none() is not None:
        return make_response(409, "Email already registered")

    user = User(
        email=body.email,
        password_hash=hash_password(body.password),
        auth_provider="local",
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    return make_response(201, "User registered", _user_response_data(user))


@router.post(
    "/login",
    responses={
        200: {
            "description": "Login successful",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Valid credentials",
                            "value": {
                                "status": 200,
                                "message": "Login successful",
                                "data": {
                                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                    "token_type": "bearer",
                                },
                            },
                        },
                    },
                },
            },
        },
        401: {
            "description": "Invalid email or password",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid": {
                            "summary": "Bad credentials",
                            "value": {
                                "status": 401,
                                "message": "Invalid email or password",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def login(
    body: LoginRequest, session: Annotated[AsyncSession, Depends(get_session)]
) -> JSONResponse:
    """Authenticate a local account and issue a session JWT.

    Args:
        body(LoginRequest): The account's email and plaintext password.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a `TokenResponse`.
    """
    result = await session.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()
    if user is None or user.password_hash is None or not user.is_active:
        return make_response(401, "Invalid email or password")
    if not verify_password(body.password, user.password_hash):
        return make_response(401, "Invalid email or password")

    token = TokenResponse(access_token=create_jwt(user.id))
    return make_response(200, "Login successful", token.model_dump(mode="json"))


@router.get(
    "/me",
    responses={
        200: {
            "description": "Current user",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Authenticated user",
                            "value": {
                                "status": 200,
                                "message": "Current user",
                                "data": {
                                    "id": "5b1e2f0a-9a3b-4a0e-9c1a-8f6d3c2b7a10",
                                    "email": "operator@example.com",
                                    "auth_provider": "local",
                                    "is_active": True,
                                    "created_at": "2026-07-15T09:30:00+00:00",
                                },
                            },
                        },
                    },
                },
            },
        },
        401: {
            "description": "Not authenticated",
            "content": {
                "application/json": {
                    "examples": {
                        "unauthenticated": {
                            "summary": "Missing or invalid bearer token",
                            "value": {"detail": "Not authenticated"},
                        },
                    },
                },
            },
        },
    },
)
async def read_me(current_user: Annotated[User, Depends(get_current_user)]) -> JSONResponse:
    """Return the authenticated user's profile.

    Args:
        current_user(User): The authenticated user, resolved from the JWT.

    Return:
        response(JSONResponse): The standard envelope wrapping a `UserResponse`.
    """
    return make_response(200, "Current user", _user_response_data(current_user))


@router.get(
    "/cf/login",
    status_code=302,
    responses={
        302: {"description": "Redirect to the Cloudflare OAuth authorize endpoint"},
    },
)
async def cf_login() -> RedirectResponse:
    """Begin the Cloudflare OAuth login flow with a redirect.

    Return:
        response(RedirectResponse): A 302 redirect to Cloudflare's `/oauth2/auth` endpoint.
    """
    authorize_url = await oauth_service.start_cf_oauth_login()
    return RedirectResponse(url=authorize_url, status_code=302)


@router.get(
    "/cf/callback",
    responses={
        200: {
            "description": "Cloudflare login successful",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Valid OAuth callback",
                            "value": {
                                "status": 200,
                                "message": "Cloudflare login successful",
                                "data": {
                                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                                    "token_type": "bearer",
                                },
                            },
                        },
                    },
                },
            },
        },
        400: {
            "description": "Invalid or expired OAuth state, or malformed token response",
            "content": {
                "application/json": {
                    "examples": {
                        "bad_state": {
                            "summary": "Expired or replayed state",
                            "value": {
                                "status": 400,
                                "message": "invalid or expired oauth state",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def cf_callback(
    code: str, state: str, session: Annotated[AsyncSession, Depends(get_session)]
) -> JSONResponse:
    """Complete the Cloudflare OAuth login flow.

    Args:
        code(str): The authorization code returned to the callback.
        state(str): The state parameter returned to the callback.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a `TokenResponse`.
    """
    try:
        _user, jwt_token = await oauth_service.handle_cf_oauth_callback(session, code, state)
    except ValueError as exc:
        return make_response(400, str(exc))

    token = TokenResponse(access_token=jwt_token)
    return make_response(200, "Cloudflare login successful", token.model_dump(mode="json"))
