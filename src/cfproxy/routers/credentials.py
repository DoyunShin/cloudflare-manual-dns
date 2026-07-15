"""Management API router: registering, verifying, listing, and deleting stored
upstream Cloudflare credentials, plus the scope-builder helpers that list a
credential's visible zones and records.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.core.security import get_current_user
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import UpstreamCredentialCreateRequest, UpstreamCredentialResponse
from cfproxy.services import credential_service

router = APIRouter(prefix="/api/v1/upstream-credentials", tags=["Upstream Credentials"])

_NOT_FOUND_EXAMPLE = {
    "description": "Upstream credential not found",
    "content": {
        "application/json": {
            "examples": {
                "not_found": {
                    "summary": "Credential does not exist or is not owned by the caller",
                    "value": {
                        "status": 404,
                        "message": "upstream credential not found",
                        "data": None,
                    },
                },
            },
        },
    },
}


def _credential_response_data(credential) -> dict:
    """Serialize an UpstreamCredential row into JSON-safe response data.

    Args:
        credential(UpstreamCredential): The credential row to serialize.

    Return:
        data(dict): The `UpstreamCredentialResponse` payload, secrets never included.
    """
    return UpstreamCredentialResponse.model_validate(credential).model_dump(mode="json")


@router.post(
    "",
    responses={
        201: {
            "description": "Upstream credential registered",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Registered a pasted API token",
                            "value": {
                                "status": 201,
                                "message": "Upstream credential registered",
                                "data": {
                                    "id": "9d2c1b0a-3e4f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "label": "prod-dns-token",
                                    "cred_type": "token",
                                    "cf_account_email": None,
                                    "verify_status": None,
                                    "verified_at": None,
                                    "created_at": "2026-07-15T09:30:00+00:00",
                                },
                            },
                        },
                    },
                },
            },
        },
        400: {
            "description": "Invalid credential payload",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid": {
                            "summary": "Missing required secret for the given cred_type",
                            "value": {
                                "status": 400,
                                "message": "api_token is required for cred_type='token'",
                                "data": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def create_credential(
    body: UpstreamCredentialCreateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Register a new stored upstream Cloudflare credential.

    Args:
        body(UpstreamCredentialCreateRequest): The credential label, type, and secret material.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping an `UpstreamCredentialResponse`.
    """
    try:
        credential = await credential_service.register_credential(
            session,
            current_user.id,
            body.label,
            body.cred_type,
            api_token=body.api_token,
            global_key=body.global_key,
            cf_account_email=body.cf_account_email,
        )
    except ValueError as exc:
        return make_response(400, str(exc))

    return make_response(201, "Upstream credential registered", _credential_response_data(credential))


@router.get(
    "",
    responses={
        200: {
            "description": "Upstream credentials listed",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One stored credential",
                            "value": {
                                "status": 200,
                                "message": "Upstream credentials listed",
                                "data": [
                                    {
                                        "id": "9d2c1b0a-3e4f-4a5b-8c6d-7e8f9a0b1c2d",
                                        "label": "prod-dns-token",
                                        "cred_type": "token",
                                        "cf_account_email": "operator@example.com",
                                        "verify_status": "active",
                                        "verified_at": "2026-07-15T09:31:00+00:00",
                                        "created_at": "2026-07-15T09:30:00+00:00",
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
async def list_credentials(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """List every upstream credential owned by the authenticated user.

    Args:
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping a list of `UpstreamCredentialResponse`.
    """
    credentials = await credential_service.list_credentials(session, current_user.id)
    return make_response(
        200, "Upstream credentials listed", [_credential_response_data(c) for c in credentials]
    )


@router.delete(
    "/{credential_id}",
    responses={
        200: {
            "description": "Upstream credential deleted",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Credential removed",
                            "value": {
                                "status": 200,
                                "message": "Upstream credential deleted",
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
async def delete_credential(
    credential_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Delete a stored upstream credential, cascade-revoking dependent scoped tokens.

    Args:
        credential_id(str): The credential id to delete.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope, 404 if not owned by the caller.
    """
    try:
        await credential_service.delete_credential(session, current_user.id, credential_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    return make_response(200, "Upstream credential deleted")


@router.post(
    "/{credential_id}/verify",
    responses={
        200: {
            "description": "Upstream credential verified",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Credential is valid upstream",
                            "value": {
                                "status": 200,
                                "message": "Upstream credential verified",
                                "data": {
                                    "id": "9d2c1b0a-3e4f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "label": "prod-dns-token",
                                    "cred_type": "token",
                                    "cf_account_email": "operator@example.com",
                                    "verify_status": "active",
                                    "verified_at": "2026-07-15T09:31:00+00:00",
                                    "created_at": "2026-07-15T09:30:00+00:00",
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
async def verify_credential(
    credential_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Verify a stored upstream credential against the real Cloudflare API.

    Args:
        credential_id(str): The credential id to verify.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping the updated `UpstreamCredentialResponse`.
    """
    try:
        credential = await credential_service.verify_credential(session, current_user.id, credential_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    return make_response(200, "Upstream credential verified", _credential_response_data(credential))


@router.get(
    "/{credential_id}/zones",
    responses={
        200: {
            "description": "Zones listed",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One visible zone",
                            "value": {
                                "status": 200,
                                "message": "Zones listed",
                                "data": [
                                    {
                                        "id": "023e105f4ecef8ad9ca31a8372d0c353",
                                        "name": "example.com",
                                        "status": "active",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        404: _NOT_FOUND_EXAMPLE,
    },
)
async def list_zones(
    credential_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """List the Cloudflare zones visible to a stored credential.

    Args:
        credential_id(str): The credential whose zones to list.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.

    Return:
        response(JSONResponse): The standard envelope wrapping the raw Cloudflare zone list.
    """
    try:
        zones = await credential_service.list_credential_zones(session, current_user.id, credential_id)
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    return make_response(200, "Zones listed", zones)


@router.get(
    "/{credential_id}/zones/{zone_id}/records",
    responses={
        200: {
            "description": "DNS records listed",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One DNS record",
                            "value": {
                                "status": 200,
                                "message": "DNS records listed",
                                "data": [
                                    {
                                        "id": "rec1",
                                        "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                                        "type": "A",
                                        "name": "app.example.com",
                                        "content": "203.0.113.10",
                                    },
                                ],
                            },
                        },
                    },
                },
            },
        },
        404: _NOT_FOUND_EXAMPLE,
    },
)
async def list_zone_records(
    credential_id: str,
    zone_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    type: Annotated[str | None, Query()] = None,
    name: Annotated[str | None, Query()] = None,
) -> JSONResponse:
    """List every DNS record in a zone visible to a stored credential.

    Args:
        credential_id(str): The credential to list records through.
        zone_id(str): The Cloudflare zone id to list records for.
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.
        type(str, optional): Filter to a single Cloudflare DNS record type.
        name(str, optional): Filter to a single record name.

    Return:
        response(JSONResponse): The standard envelope wrapping the raw Cloudflare DNS record list.
    """
    params = {k: v for k, v in {"type": type, "name": name}.items() if v is not None}
    try:
        records = await credential_service.list_credential_zone_records(
            session, current_user.id, credential_id, zone_id, params or None
        )
    except credential_service.NotFoundError as exc:
        return make_response(404, str(exc))

    return make_response(200, "DNS records listed", records)
