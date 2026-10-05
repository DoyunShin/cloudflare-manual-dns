"""Service-user administration endpoints."""

from math import ceil
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.core.security import require_admin
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import (
    ResultInfo,
    UserAdminUpdateRequest,
    UserListResponse,
    UserResponse,
)

router = APIRouter(prefix="/api/v1/admin/users", tags=["Admin users"])


def _response_doc(description: str, status: int, message: str) -> dict:
    """Build compact OpenAPI documentation for an envelope response."""
    return {
        "description": description,
        "content": {
            "application/json": {
                "example": {"status": status, "message": message, "data": None}
            }
        },
    }


def _serialize_user(user: User) -> UserResponse:
    """Serialize a user row for management API responses."""
    return UserResponse.model_validate(user)


@router.get(
    "",
    responses={
        200: _response_doc("Paginated service users", 200, "Users listed"),
        401: _response_doc("Not authenticated", 401, "Not authenticated"),
        403: _response_doc(
            "Administrator access required", 403, "Administrator access required"
        ),
        422: _response_doc("Invalid pagination", 422, "Validation error"),
    },
)
async def list_users(current_admin: Annotated[User, Depends(require_admin)], session: Annotated[AsyncSession, Depends(get_session)], page: Annotated[int, Query(ge=1)] = 1, per_page: Annotated[int, Query(ge=1, le=100)] = 20) -> JSONResponse:
    """List service users for authorization administration.

    Args:
        current_admin: Authenticated service administrator.
        session: Database session.
        page: One-based result page.
        per_page: Maximum rows per page.

    Returns:
        Standard envelope containing users and pagination metadata.
    """
    del current_admin
    total_count = int((await session.execute(select(func.count()).select_from(User))).scalar_one())
    result = await session.execute(
        select(User)
        .order_by(User.created_at.asc(), User.id.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    users = list(result.scalars().all())
    result_info = ResultInfo(
        page=page,
        per_page=per_page,
        count=len(users),
        total_count=total_count,
        total_pages=ceil(total_count / per_page) if total_count else 0,
    )
    data = UserListResponse(
        items=[_serialize_user(user) for user in users],
        result_info=result_info,
    )
    return make_response(200, "Users listed", data.model_dump(mode="json"))


@router.patch(
    "/{user_id}",
    responses={
        200: _response_doc("Service authorization updated", 200, "User updated"),
        401: _response_doc("Not authenticated", 401, "Not authenticated"),
        403: _response_doc(
            "Administrator access or CSRF validation failed", 403, "Invalid CSRF token"
        ),
        404: _response_doc("User not found", 404, "User not found"),
        409: _response_doc(
            "Last active local administrator is protected",
            409,
            "Cannot disable the last active local administrator",
        ),
        422: _response_doc("Unsupported authorization update", 422, "Validation error"),
    },
)
async def update_user(user_id: str, body: UserAdminUpdateRequest, current_admin: Annotated[User, Depends(require_admin)], session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Change service-local administrator and activation flags.

    Args:
        user_id: User to update.
        body: Service-local authorization changes.
        current_admin: Authenticated administrator initiating the change.
        session: Database transaction.

    Returns:
        Standard envelope containing the updated user.
    """
    result = await session.execute(
        with_row_lock(
            session,
            select(User).order_by(User.id.asc()).execution_options(populate_existing=True),
        )
    )
    locked_users = list(result.scalars().all())
    users_by_id = {user.id: user for user in locked_users}
    locked_admin = users_by_id.get(current_admin.id)
    if locked_admin is None or not locked_admin.is_active:
        return make_response(401, "Invalid or inactive user")
    if not locked_admin.is_admin:
        return make_response(403, "Administrator access required")

    target = users_by_id.get(user_id)
    if target is None:
        return make_response(404, "User not found")

    resulting_is_admin = body.is_admin if body.is_admin is not None else target.is_admin
    resulting_is_active = body.is_active if body.is_active is not None else target.is_active
    if target.auth_provider == "local" and target.is_admin and target.is_active:
        other_recovery_admin_exists = any(
            user.id != target.id
            and user.auth_provider == "local"
            and user.is_admin
            and user.is_active
            for user in locked_users
        )
        if (not resulting_is_admin or not resulting_is_active) and not other_recovery_admin_exists:
            return make_response(409, "Cannot disable the last active local administrator")

    target.is_admin = resulting_is_admin
    target.is_active = resulting_is_active
    await session.commit()
    await session.refresh(target)
    return make_response(
        200,
        "User updated",
        _serialize_user(target).model_dump(mode="json"),
    )
