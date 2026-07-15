"""Password hashing and JWT-based authentication helpers."""

from datetime import datetime, timedelta, UTC
from typing import Annotated

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.config import get_settings
from cfproxy.db.models import User
from cfproxy.db.session import get_session

_password_hasher = PasswordHasher()
_bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(pw: str) -> str:
    """Hash a plaintext password using argon2.

    Args:
        pw(str): Plaintext password.

    Return:
        hashed(str): Argon2 password hash.
    """
    return _password_hasher.hash(pw)


def verify_password(pw: str, h: str) -> bool:
    """Verify a plaintext password against an argon2 hash.

    Args:
        pw(str): Plaintext password to check.
        h(str): Stored argon2 password hash.

    Return:
        is_valid(bool): True if the password matches the hash.
    """
    try:
        return _password_hasher.verify(h, pw)
    except VerifyMismatchError:
        return False


def create_jwt(sub: str) -> str:
    """Create a signed JWT for the given subject.

    Args:
        sub(str): The subject claim (typically a user id).

    Return:
        token(str): Encoded HS256 JWT string.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": sub,
        "iat": now,
        "exp": now + timedelta(seconds=settings.jwt_ttl_seconds),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_jwt(token: str) -> dict:
    """Decode and validate a JWT produced by `create_jwt`.

    Args:
        token(str): Encoded JWT string.

    Return:
        payload(dict): Decoded JWT claims.
    """
    settings = get_settings()
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    """FastAPI dependency resolving the active user from a Bearer JWT.

    Args:
        credentials(HTTPAuthorizationCredentials | None): Parsed Authorization header.
        session(AsyncSession): Database session.

    Return:
        user(User): The authenticated, active user.
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_jwt(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or inactive user")
    return user
