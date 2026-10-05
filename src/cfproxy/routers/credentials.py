"""Management API router: registering, verifying, listing, and deleting stored
upstream Cloudflare credentials, plus the scope-builder helpers that list a
credential's visible zones and records.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.config import get_settings
from cfproxy.core.security import get_current_user, require_csrf
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import UpstreamCredentialCreateRequest, UpstreamCredentialResponse
from cfproxy.services import credential_service, oauth_service

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


def _cf_callback_redirect(status: str) -> RedirectResponse:
    """Build a fixed-origin credential-page redirect for Cloudflare OAuth."""
    query = "cf_status=connected" if status == "success" else f"cf_error={status}"
    return RedirectResponse(
        f"{get_settings().app_base_url}/credentials?{query}", status_code=302
    )


def _cf_oauth_response_doc(status: int, summary: str, message: str, data: Any = None) -> dict[str, Any]:
    """Document a Cloudflare credential-consent management response."""
    return {
        "description": summary,
        "content": {
            "application/json": {
                "examples": {
                    "result": {
                        "summary": summary,
                        "value": {"status": status, "message": message, "data": data},
                    }
                }
            }
        },
    }


@router.post(
    "/cf/connect",
    responses={
        200: _cf_oauth_response_doc(200, "Cloudflare authorization URL created", "Cloudflare authorization started", {"authorization_url": "https://dash.cloudflare.com/oauth2/auth?response_type=code&client_id=cfproxy&state=single-use-state"}),
        400: _cf_oauth_response_doc(400, "Cloudflare OAuth is not configured", "Cloudflare OAuth is not configured"),
        401: _cf_oauth_response_doc(401, "Not authenticated", "Not authenticated"),
        403: _cf_oauth_response_doc(403, "CSRF validation failed", "Invalid CSRF token"),
        503: _cf_oauth_response_doc(503, "OAuth state storage unavailable", "Cloudflare OAuth is temporarily unavailable"),
    },
)
async def connect_cloudflare_oauth(request: Request, current_user: Annotated[User, Depends(require_csrf)]) -> JSONResponse:
    """Start Cloudflare OAuth consent for the active service user.

    Args:
        request: Browser request carrying the validated service session.
        current_user: Authenticated user with validated CSRF credentials.

    Returns:
        Standard envelope containing the authorization URL or a safe error.
    """
    management_session = request.state.management_session
    try:
        authorization_url = await oauth_service.start_cf_oauth_connect(
            current_user.id, management_session.id
        )
    except oauth_service.CloudflareOAuthStateError:
        return make_response(503, "Cloudflare OAuth is temporarily unavailable")
    except oauth_service.CloudflareOAuthError as exc:
        return make_response(400, str(exc))
    return make_response(200, "Cloudflare authorization started", {"authorization_url": authorization_url})


@router.get(
    "/cf/callback",
    responses={
        302: {
            "description": "Redirect to the fixed credential-page result",
            "headers": {"Location": {"schema": {"type": "string"}, "example": "https://app.example.com/credentials?cf_status=connected"}},
        },
        401: _cf_oauth_response_doc(401, "The initiating service session is no longer active", "Invalid or expired session"),
        422: _cf_oauth_response_doc(422, "Invalid callback query parameters", "Validation error", [{"type": "string_too_long", "loc": ["query", "state"], "msg": "String should have at most 1024 characters"}]),
    },
)
async def complete_cloudflare_oauth(request: Request, current_user: Annotated[User, Depends(get_current_user)], session: Annotated[AsyncSession, Depends(get_session)], state: Annotated[str | None, Query(max_length=1024)] = None, code: Annotated[str | None, Query(max_length=8192)] = None, error: Annotated[str | None, Query(max_length=255)] = None) -> RedirectResponse:
    """Attach delegated Cloudflare tokens to the initiating service user.

    Args:
        request: Browser request carrying the initiating service session.
        current_user: Authenticated service user.
        session: Database session used to persist the delegated credential.
        state: Single-use Cloudflare consent state.
        code: Provider authorization code when consent succeeds.
        error: Provider error when consent is declined.

    Returns:
        Fixed-origin redirect to the credential page with the consent result.
    """
    management_session = request.state.management_session
    try:
        if state is None:
            raise oauth_service.CloudflareOAuthStateError("Cloudflare OAuth state is missing")
        if error is not None:
            await oauth_service.reject_cf_oauth_callback(
                state, current_user.id, management_session.id
            )
            return _cf_callback_redirect("provider")
        if code is None:
            raise oauth_service.CloudflareOAuthStateError("Cloudflare OAuth code is missing")
        await oauth_service.complete_cf_oauth_connect(
            session,
            code,
            state,
            current_user.id,
            management_session.id,
        )
    except oauth_service.CloudflareOAuthStateError:
        await session.rollback()
        return _cf_callback_redirect("state")
    except oauth_service.CloudflareOAuthError:
        await session.rollback()
        return _cf_callback_redirect("provider")
    return _cf_callback_redirect("success")


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
