"""Public OIDC login and administrator provider configuration endpoints."""

from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.oidc import OIDCConfigurationError, OIDCProviderError, OIDCTokenError
from cfproxy.core.envelopes import make_response
from cfproxy.core.security import require_admin, require_csrf
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.services import oidc_service


router = APIRouter(prefix="/api/v1/auth/oidc", tags=["OIDC Authentication"])
admin_router = APIRouter(prefix="/api/v1/admin/oidc", tags=["OIDC Administration"])


def _envelope_response(description: str, status: int, message: str, *, data=None) -> dict:
    """Build OpenAPI documentation for one standard JSON envelope."""
    return {
        "description": description,
        "content": {
            "application/json": {
                "examples": {
                    "response": {
                        "summary": description,
                        "value": {"status": status, "message": message, "data": data},
                    }
                }
            }
        },
    }


def _redirect_response(description: str, location: str) -> dict:
    """Build OpenAPI documentation for one fixed-purpose redirect."""
    return {
        "description": description,
        "headers": {
            "Location": {
                "description": "Redirect destination",
                "schema": {"type": "string"},
                "example": location,
            }
        },
    }


class OIDCConfigRequest(BaseModel):
    """Administrator-supplied OIDC provider configuration."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "enabled": True,
                "label": "Company SSO",
                "issuer": "https://id.example.com/realms/company",
                "client_id": "cfproxy",
                "client_secret": "replace-with-client-secret",
                "scopes": "openid profile email",
                "allowed_endpoint_origins": [],
                "allow_private_network": False,
            }
        }
    )

    enabled: bool = False
    label: str = Field(min_length=1, max_length=255)
    issuer: str = Field(min_length=1, max_length=512)
    client_id: str = Field(min_length=1, max_length=1024)
    client_secret: str | None = Field(default=None, max_length=2048)
    scopes: str = Field(default="openid profile email", min_length=1, max_length=1024)
    allowed_endpoint_origins: list[str] = Field(default_factory=list, max_length=32)
    allow_private_network: bool = False


def _service_input(body: OIDCConfigRequest) -> oidc_service.OIDCConfigInput:
    """Convert an API request into a service-layer provider configuration."""
    return oidc_service.OIDCConfigInput(
        enabled=body.enabled,
        label=body.label,
        issuer=body.issuer,
        client_id=body.client_id,
        client_secret=body.client_secret,
        scopes=body.scopes,
        allowed_endpoint_origins=tuple(body.allowed_endpoint_origins),
        allow_private_network=body.allow_private_network,
    )


def _callback_redirect(status: str) -> RedirectResponse:
    """Build a fixed-origin SPA redirect for OIDC callback results."""
    path = "/" if status == "success" else f"/login?oidc_error={status}"
    return RedirectResponse(f"{oidc_service.get_settings().app_base_url}{path}", status_code=302)


@router.get(
    "",
    responses={
        200: {
            "description": "Public OIDC availability",
            "content": {
                "application/json": {
                    "example": {
                        "status": 200,
                        "message": "OIDC configuration",
                        "data": {"enabled": True, "label": "Company SSO"},
                    }
                }
            },
        }
    },
)
async def get_public_oidc_config(session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Return the public provider label and enabled state.

    Args:
        session: Active database session.

    Returns:
        Standard envelope containing public provider availability.
    """
    config = await oidc_service.get_oidc_config(session)
    return make_response(200, "OIDC configuration", oidc_service.public_config_response(config))


@router.get(
    "/login",
    response_model=None,
    responses={
        302: _redirect_response(
            "Redirect to the configured identity provider",
            "https://id.example.com/authorize?response_type=code&client_id=cfproxy",
        ),
        404: _envelope_response("OIDC login is disabled", 404, "OIDC login is not enabled"),
        502: _envelope_response(
            "OIDC provider is unavailable or invalid",
            502,
            "OIDC provider is unavailable or invalid",
        ),
        503: _envelope_response(
            "Security state storage is unavailable",
            503,
            "OIDC login is temporarily unavailable",
        ),
    },
)
async def start_oidc_login(session: Annotated[AsyncSession, Depends(get_session)], browser_binding: Annotated[str | None, Cookie(alias=oidc_service.OIDC_BINDING_COOKIE)] = None) -> JSONResponse | RedirectResponse:
    """Start a browser-bound Authorization Code and PKCE login.

    Args:
        session: Active database session.
        browser_binding: Existing browser-binding cookie, if present.

    Returns:
        Provider redirect or a standard error envelope.
    """
    try:
        started = await oidc_service.start_oidc_login(session, browser_binding)
    except oidc_service.OIDCNotConfiguredError:
        return make_response(404, "OIDC login is not enabled")
    except oidc_service.OIDCStateError:
        return make_response(503, "OIDC login is temporarily unavailable")
    except (OIDCConfigurationError, OIDCProviderError):
        return make_response(502, "OIDC provider is unavailable or invalid")
    response = RedirectResponse(started.authorization_url, status_code=302)
    response.set_cookie(
        oidc_service.OIDC_BINDING_COOKIE,
        started.browser_binding,
        max_age=oidc_service.get_settings().oauth_state_ttl,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get(
    "/callback",
    responses={
        302: _redirect_response(
            "Redirect to a fixed SPA success or error page",
            "https://app.example.com/login?oidc_error=provider",
        ),
        422: _envelope_response(
            "Invalid callback query parameters", 422, "Validation error", data=[]
        ),
    },
)
async def complete_oidc_login(request: Request, session: Annotated[AsyncSession, Depends(get_session)], state: Annotated[str | None, Query(max_length=1024)] = None, code: Annotated[str | None, Query(max_length=8192)] = None, error: Annotated[str | None, Query(max_length=255)] = None, browser_binding: Annotated[str | None, Cookie(alias=oidc_service.OIDC_BINDING_COOKIE)] = None) -> RedirectResponse:
    """Complete OIDC authentication and issue a local service session.

    Args:
        request: Current browser request.
        session: Active database session.
        state: Single-use provider state.
        code: Provider authorization code.
        error: Provider error identifier, if authorization was denied.
        browser_binding: Binding cookie from the initiating browser.

    Returns:
        A fixed SPA success or safe error redirect.
    """
    response = _callback_redirect("success")
    try:
        if state is None:
            raise oidc_service.OIDCStateError("OIDC state is missing")
        if error is not None:
            await oidc_service.reject_oidc_login(state, browser_binding)
            response = _callback_redirect("provider")
        elif code is None:
            raise oidc_service.OIDCStateError("OIDC code is missing")
        else:
            await oidc_service.complete_oidc_login(
                session, response, code, state, browser_binding, request
            )
    except oidc_service.OIDCUserDisabledError:
        await session.rollback()
        response = _callback_redirect("inactive")
    except oidc_service.OIDCStateError:
        await session.rollback()
        response = _callback_redirect("state")
    except (OIDCConfigurationError, OIDCProviderError, OIDCTokenError):
        await session.rollback()
        response = _callback_redirect("provider")
    response.delete_cookie(oidc_service.OIDC_BINDING_COOKIE, path="/", secure=True, httponly=True)
    return response


@admin_router.get(
    "",
    responses={
        200: {
            "description": "Current OIDC configuration",
            "content": {
                "application/json": {
                    "example": {
                        "status": 200,
                        "message": "OIDC configuration",
                        "data": {
                            "enabled": True,
                            "label": "Company SSO",
                            "issuer": "https://id.example.com/realms/company",
                            "client_id": "cfproxy",
                            "scopes": "openid profile email",
                            "has_secret": True,
                            "allowed_endpoint_origins": [],
                            "allow_private_network": False,
                        },
                    }
                }
            },
        },
        401: _envelope_response("Not authenticated", 401, "Not authenticated"),
        403: _envelope_response(
            "Administrator access required", 403, "Administrator access required"
        ),
    },
)
async def get_admin_oidc_config(_admin: Annotated[User, Depends(require_admin)], session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Return the complete non-secret provider configuration.

    Args:
        _admin: Authenticated service administrator.
        session: Active database session.

    Returns:
        Standard envelope containing non-secret provider configuration.
    """
    config = await oidc_service.get_oidc_config(session)
    return make_response(200, "OIDC configuration", oidc_service.config_response(config))


@admin_router.put(
    "",
    responses={
        200: _envelope_response(
            "OIDC configuration saved",
            200,
            "OIDC configuration saved",
            data={
                "enabled": True,
                "label": "Company SSO",
                "issuer": "https://id.example.com/realms/company",
                "client_id": "cfproxy",
                "scopes": "openid profile email",
                "has_secret": True,
                "allowed_endpoint_origins": [],
                "allow_private_network": False,
            },
        ),
        400: _envelope_response(
            "Invalid provider configuration", 400, "OIDC scopes must include openid"
        ),
        401: _envelope_response(
            "Not authenticated or session invalidated",
            401,
            "Administrator session is no longer valid",
        ),
        403: _envelope_response(
            "Administrator access or CSRF validation failed",
            403,
            "Administrator access required",
        ),
        422: _envelope_response("Invalid request body", 422, "Validation error", data=[]),
    },
)
async def put_admin_oidc_config(request: Request, body: OIDCConfigRequest, _admin: Annotated[User, Depends(require_admin)], _csrf: Annotated[None, Depends(require_csrf)], session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Atomically save the singleton provider configuration.

    Args:
        request: Current administrator request.
        body: Provider configuration to save.
        _admin: Authenticated service administrator.
        _csrf: Successful CSRF validation dependency.
        session: Active database session.

    Returns:
        Standard success or error envelope.
    """
    try:
        config = await oidc_service.save_oidc_config(
            session,
            _service_input(body),
            actor_id=_admin.id,
            actor_session_id=request.state.management_session.id,
        )
    except oidc_service.OIDCAdminSessionError as exc:
        await session.rollback()
        return make_response(401, str(exc))
    except oidc_service.OIDCAdminAuthorizationError as exc:
        await session.rollback()
        return make_response(403, str(exc))
    except OIDCConfigurationError as exc:
        await session.rollback()
        return make_response(400, str(exc))
    return make_response(200, "OIDC configuration saved", oidc_service.config_response(config))


@admin_router.post(
    "/test",
    responses={
        200: _envelope_response(
            "Discovery and JWKS validated; secret was not verified",
            200,
            "OIDC discovery and JWKS validated",
            data={
                "issuer": "https://id.example.com/realms/company",
                "signing_algorithms": ["RS256"],
                "signing_key_count": 2,
                "client_secret_verified": False,
            },
        ),
        400: _envelope_response(
            "Invalid provider configuration", 400, "OIDC client_secret is required"
        ),
        401: _envelope_response("Not authenticated", 401, "Not authenticated"),
        403: _envelope_response(
            "Administrator access or CSRF validation failed",
            403,
            "Invalid CSRF token",
        ),
        422: _envelope_response("Invalid request body", 422, "Validation error", data=[]),
        502: _envelope_response(
            "Provider discovery or JWKS request failed",
            502,
            "OIDC provider is unavailable or invalid",
        ),
    },
)
async def test_admin_oidc_config(body: OIDCConfigRequest, _admin: Annotated[User, Depends(require_admin)], _csrf: Annotated[None, Depends(require_csrf)], session: Annotated[AsyncSession, Depends(get_session)]) -> JSONResponse:
    """Test unsaved provider discovery and JWKS settings.

    Args:
        body: Unsaved provider configuration to test.
        _admin: Authenticated service administrator.
        _csrf: Successful CSRF validation dependency.
        session: Active database session.

    Returns:
        Standard envelope with discovery and key validation results.
    """
    try:
        result = await oidc_service.test_oidc_config(session, _service_input(body))
    except OIDCConfigurationError as exc:
        return make_response(400, str(exc))
    except OIDCProviderError:
        return make_response(502, "OIDC provider is unavailable or invalid")
    return make_response(200, "OIDC discovery and JWKS validated", result)
