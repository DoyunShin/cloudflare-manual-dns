"""Management API router: minting, inspecting, rotating, and revoking
record-scoped proxy tokens.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.core.security import get_current_user
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import (
    ScopedTokenCreateRequest,
    ScopedTokenCreateResponse,
    ScopedTokenDetailResponse,
    ScopedTokenResponse,
    ScopedTokenRotateResponse,
    ScopeRuleResponse,
)
from cfproxy.services import credential_service, token_service

router = APIRouter(prefix="/api/v1/scoped-tokens", tags=["Scoped Tokens"])

_NOT_FOUND_EXAMPLE = {
    "description": "Scoped token not found",
    "content": {
        "application/json": {
            "examples": {
                "not_found": {
                    "summary": "Token does not exist or is not owned by the caller",
                    "value": {
                        "status": 404,
                        "message": "scoped token not found",
                        "data": None,
                    },
                },
            },
        },
    },
}


def _token_response_data(scoped_token) -> dict:
    """Serialize a ScopedToken row into JSON-safe response data.

    Args:
        scoped_token(ScopedToken): The scoped token row to serialize.

    Return:
        data(dict): The `ScopedTokenResponse` payload, the raw secret never included.
    """
    return ScopedTokenResponse.model_validate(scoped_token).model_dump(mode="json")


@router.post(
    "",
    responses={
        201: {
            "description": "Scoped token minted",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "New record-scoped token minted",
                            "value": {
                                "status": 201,
                                "message": "Scoped token minted",
                                "data": {
                                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "name": "staging-acme-dns",
                                    "token": "cfsx_AbCdEf0123456789AbCd_"
                                    "1234567890abcdefghijklmnopqrstuvwxyzABCD",
                                    "token_prefix": "cfsx_AbCdEf",
                                    "expires_at": None,
                                    "created_at": "2026-07-15T09:32:00+00:00",
                                },
                            },
                        },
                    },
                },
            },
        },
        400: {
            "description": "Invalid scope rules",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid": {
                            "summary": "A scope rule was missing name_pattern and record_ids",
                            "value": {
                                "status": 400,
                                "message": "each scope rule requires a name_pattern or record_ids",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
        404: {
            "description": "Upstream credential not found",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "upstream_credential_id is not owned by the caller",
                            "value": {
                                "status": 404,
                                "message": "upstream credential not found",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def mint_scoped_token(
    body: ScopedTokenCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Mint a new record-scoped proxy token.

    Args:
        body(ScopedTokenCreateRequest): The token name, upstream credential id, and scope rules.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a `ScopedTokenCreateResponse`,
            whose `token` field is the raw scoped token, visible only in this response.
    """
    try:
        minted = await token_service.mint_scoped_token(
            session,
            current_user.id,
            body.name,
            body.upstream_credential_id,
            [rule.model_dump() for rule in body.scope_rules],
            expires_at=body.expires_at,
        )
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))
    except ValueError as exc:
        return make_response(400, str(exc))

    data = ScopedTokenCreateResponse.model_validate(minted).model_dump(mode="json")
    return make_response(201, "Scoped token minted", data)


@router.get(
    "",
    responses={
        200: {
            "description": "Scoped tokens listed",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One active scoped token",
                            "value": {
                                "status": 200,
                                "message": "Scoped tokens listed",
                                "data": [
                                    {
                                        "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                        "name": "staging-acme-dns",
                                        "token_prefix": "cfsx_AbCdEf",
                                        "status": "active",
                                        "version": 1,
                                        "expires_at": None,
                                        "last_used_at": None,
                                        "created_at": "2026-07-15T09:32:00+00:00",
                                        "revoked_at": None,
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
    },
)
async def list_scoped_tokens(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """List every scoped token owned by the authenticated user.

    Args:
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a list of `ScopedTokenResponse`.
    """
    scoped_tokens = await token_service.list_scoped_tokens(session, current_user.id)
    return make_response(
        200, "Scoped tokens listed", [_token_response_data(t) for t in scoped_tokens]
    )


@router.get(
    "/{token_id}",
    responses={
        200: {
            "description": "Scoped token detail",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Token with its scope rules",
                            "value": {
                                "status": 200,
                                "message": "Scoped token detail",
                                "data": {
                                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "name": "staging-acme-dns",
                                    "token_prefix": "cfsx_AbCdEf",
                                    "status": "active",
                                    "version": 1,
                                    "expires_at": None,
                                    "last_used_at": None,
                                    "created_at": "2026-07-15T09:32:00+00:00",
                                    "revoked_at": None,
                                    "rules": [
                                        {
                                            "id": "2b3c4d5e-6f70-4a5b-8c6d-7e8f9a0b1c2d",
                                            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                                            "name_pattern": "*.staging",
                                            "name_match": "wildcard",
                                            "record_types": ["A", "CNAME"],
                                            "record_ids": None,
                                            "allow_read": True,
                                            "allow_create": True,
                                            "allow_write": True,
                                            "allow_delete": False,
                                            "content_lock": None,
                                            "created_at": "2026-07-15T09:32:00+00:00",
                                        },
                                    ],
                                },
                            },
                        },
                    },
                },
            },
        },
        404: _NOT_FOUND_EXAMPLE,
    },
)
async def get_scoped_token(
    token_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Fetch a scoped token together with its scope rules.

    Args:
        token_id(str): The scoped token id to load.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a `ScopedTokenDetailResponse`.
    """
    try:
        detail = await token_service.get_scoped_token_detail(session, current_user.id, token_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    payload = {
        **ScopedTokenResponse.model_validate(detail.token).model_dump(mode="json"),
        "rules": [
            ScopeRuleResponse.model_validate(rule).model_dump(mode="json")
            for rule in detail.rules
        ],
    }
    data = ScopedTokenDetailResponse.model_validate(payload).model_dump(mode="json")
    return make_response(200, "Scoped token detail", data)


@router.post(
    "/{token_id}/rotate",
    responses={
        200: {
            "description": "Scoped token rotated",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "New raw token issued, old secret invalidated",
                            "value": {
                                "status": 200,
                                "message": "Scoped token rotated",
                                "data": {
                                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "token": "cfsx_ZzYyXxWwVvUuTtSsRrQq_"
                                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
                                    "token_prefix": "cfsx_ZzYyXx",
                                    "version": 2,
                                },
                            },
                        },
                    },
                },
            },
        },
        404: _NOT_FOUND_EXAMPLE,
    },
)
async def rotate_scoped_token(
    token_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Rotate a scoped token, issuing a new raw secret and invalidating the old one.

    Args:
        token_id(str): The scoped token id to rotate.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a `ScopedTokenRotateResponse`,
            whose `token` field is the new raw scoped token, visible only in this response.
    """
    try:
        rotated = await token_service.rotate_scoped_token(session, current_user.id, token_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    data = ScopedTokenRotateResponse.model_validate(rotated).model_dump(mode="json")
    return make_response(200, "Scoped token rotated", data)


@router.delete(
    "/{token_id}",
    responses={
        200: {
            "description": "Scoped token revoked",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Token revoked",
                            "value": {
                                "status": 200,
                                "message": "Scoped token revoked",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
        404: _NOT_FOUND_EXAMPLE,
    },
)
async def revoke_scoped_token(
    token_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Revoke a scoped token.

    Args:
        token_id(str): The scoped token id to revoke.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope, 404 if not owned by the caller.
    """
    try:
        await token_service.revoke_scoped_token(session, current_user.id, token_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    return make_response(200, "Scoped token revoked")
