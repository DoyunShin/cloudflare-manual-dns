"""Proxy router emulating Cloudflare's `GET /client/v4/user/tokens/verify`.

This never forwards to the real Cloudflare API -- it verifies OUR scoped
token (via `require_scoped_token`) and reports its own status, matching the
shape a Cloudflare API-token verify call would return.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from cfproxy.auth.proxy_auth import ProxyAuthContext, require_scoped_token
from cfproxy.core.cf_errors import TOKEN_VALID
from cfproxy.core.envelopes import make_cf_response

router = APIRouter(tags=["Proxy: Verify"])


@router.get(
    "/client/v4/user/tokens/verify",
    responses={
        200: {
            "description": "The scoped token is active",
            "content": {
                "application/json": {
                    "examples": {
                        "active": {
                            "summary": "Token resolved and active",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [
                                    {"code": 10000, "message": "This API Token is valid and active"}
                                ],
                                "result": {
                                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                    "status": "active",
                                },
                            },
                        },
                    },
                },
            },
        },
        401: {
            "description": "The presented token is missing, malformed, unknown, or inactive",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid": {
                            "summary": "Invalid API Token",
                            "value": {
                                "success": False,
                                "errors": [{"code": 1000, "message": "Invalid API Token"}],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
    },
)
async def verify_token(
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
) -> JSONResponse:
    """Emulate a Cloudflare token-verify call for our own scoped token.

    Reaching this handler at all implies `require_scoped_token` already
    resolved an active, non-expired token, so the response is always the
    "active" shape; an invalid/inactive/expired token never reaches here --
    `require_scoped_token` raises a 401 first.

    Args:
        context(ProxyAuthContext): The resolved scoped-token authorization context.

    Return:
        response(JSONResponse): The Cloudflare-shaped verify envelope.
    """
    return make_cf_response(
        {"id": context.token.id, "status": "active"},
        messages=[{"code": TOKEN_VALID, "message": "This API Token is valid and active"}],
    )
