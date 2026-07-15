"""Proxy router for explicitly blocked bulk operations and the catch-all.

Cloudflare's DNS-record batch/import/export endpoints operate on many
records at once and cannot be authorized against per-record scope rules, so
they are unconditionally rejected. Any other `/client/v4` path that no other
proxy router matched falls through to the catch-all, which always answers
with a Cloudflare-shaped 404 (never FastAPI's default HTML/`{detail}` body).

Route registration order matters: these routes must be included in the
FastAPI app AFTER `proxy_verify`/`proxy_dns` so that the literal
`batch`/`import`/`export` segments intercept only those bulk paths, and the
catch-all is registered last so it never shadows a real endpoint.
"""

from fastapi.responses import JSONResponse
from fastapi import APIRouter

from cfproxy.core.cf_errors import FORBIDDEN, ROUTE_NOT_FOUND
from cfproxy.core.envelopes import make_cf_error

router = APIRouter(tags=["Proxy: Blocked"])

_BULK_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@router.api_route(
    "/client/v4/zones/{zone_id}/dns_records/batch",
    methods=_BULK_METHODS,
    responses={
        403: {
            "description": "Batch operations are not supported by the scoped proxy",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Batch mutation blocked",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 9109,
                                        "message": "Authorization error: insufficient scope",
                                    }
                                ],
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
async def blocked_dns_records_batch(zone_id: str) -> JSONResponse:
    """Reject DNS-record batch operations, which cannot be scope-authorized.

    Args:
        zone_id(str): The Cloudflare zone id from the request path (unused).

    Return:
        response(JSONResponse): A Cloudflare-shaped 403 error envelope.
    """
    return make_cf_error(403, FORBIDDEN, "Authorization error: insufficient scope")


@router.api_route(
    "/client/v4/zones/{zone_id}/dns_records/import",
    methods=_BULK_METHODS,
    responses={
        403: {
            "description": "Import operations are not supported by the scoped proxy",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Import mutation blocked",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 9109,
                                        "message": "Authorization error: insufficient scope",
                                    }
                                ],
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
async def blocked_dns_records_import(zone_id: str) -> JSONResponse:
    """Reject DNS-record import operations, which cannot be scope-authorized.

    Args:
        zone_id(str): The Cloudflare zone id from the request path (unused).

    Return:
        response(JSONResponse): A Cloudflare-shaped 403 error envelope.
    """
    return make_cf_error(403, FORBIDDEN, "Authorization error: insufficient scope")


@router.api_route(
    "/client/v4/zones/{zone_id}/dns_records/export",
    methods=_BULK_METHODS,
    responses={
        403: {
            "description": "Export operations are not supported by the scoped proxy",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Export blocked",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 9109,
                                        "message": "Authorization error: insufficient scope",
                                    }
                                ],
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
async def blocked_dns_records_export(zone_id: str) -> JSONResponse:
    """Reject DNS-record export operations, which cannot be scope-authorized.

    Args:
        zone_id(str): The Cloudflare zone id from the request path (unused).

    Return:
        response(JSONResponse): A Cloudflare-shaped 403 error envelope.
    """
    return make_cf_error(403, FORBIDDEN, "Authorization error: insufficient scope")


@router.api_route(
    "/client/v4/{path:path}",
    methods=_BULK_METHODS,
    responses={
        404: {
            "description": "No proxy endpoint matches this path",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "Unknown route",
                            "value": {
                                "success": False,
                                "errors": [{"code": 7003, "message": "Not found."}],
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
async def catch_all(path: str) -> JSONResponse:
    """Answer every unmatched `/client/v4` path with a Cloudflare-shaped 404.

    Args:
        path(str): The unmatched remainder of the request path (unused).

    Return:
        response(JSONResponse): A Cloudflare-shaped 404 error envelope.
    """
    return make_cf_error(404, ROUTE_NOT_FOUND, "Not found.")
