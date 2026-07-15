"""Proxy router for Cloudflare zone and DNS-record operations.

Every endpoint authorizes against the caller's scoped-token rules before
touching Cloudflare: zone listing is filtered to in-scope zones; record
listing is filtered to readable records and re-paginated locally; by-id and
create/update/delete operations are authorized via
`cfproxy.authz.authorizer.authorize_dns_request` before anything is
forwarded upstream. Mutations that are not lock-exempt acquire the MySQL
advisory mutation lock (a no-op on SQLite) BEFORE the pre-image fetch and
hold it across fetch -> authorize -> forward (closing the rename/retype
TOCTOU window), failing closed with a 503 if the lock cannot be obtained.
Denies and mutations are written to the audit log before responding.
"""

from typing import Annotated, Any, Mapping

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.proxy_auth import ProxyAuthContext, require_scoped_token
from cfproxy.authz.authorizer import authorize_dns_request
from cfproxy.authz.scope import is_lock_exempt
from cfproxy.core.cf_errors import INTERNAL
from cfproxy.core.envelopes import make_cf_error, make_cf_response
from cfproxy.db.locks import LockUnavailable, advisory_lock, mutation_lock_name
from cfproxy.db.session import engine, get_session
from cfproxy.filtering.list_filter import filter_records, paginate_and_result_info
from cfproxy.services.audit_service import write_audit
from cfproxy.upstream.client import (
    fetch_cf_record,
    forward_request,
    list_all_records,
    resolve_upstream_auth,
)

router = APIRouter(tags=["Proxy: DNS"])

_DEFAULT_PAGE = 1
_DEFAULT_PER_PAGE = 20
_LOCK_UNAVAILABLE_MESSAGE = "Could not acquire the record mutation lock, please retry."


def _client_ip(request: Request) -> str | None:
    """Return the client's source IP for audit records, if known.

    Args:
        request(Request): The incoming request.

    Return:
        ip(str | None): The client host, or None if unavailable.
    """
    return request.client.host if request.client else None


async def _record_audit(
    session: AsyncSession,
    context: ProxyAuthContext,
    *,
    method: str,
    path: str,
    decision: str,
    zone_id: str | None = None,
    record_id: str | None = None,
    record_name: str | None = None,
    record_type: str | None = None,
    pre_image: dict | None = None,
    post_image: dict | None = None,
    deny_reason: str | None = None,
    upstream_status: int | None = None,
    client_ip: str | None = None,
) -> None:
    """Durably record a proxy decision, swallowing audit-store failures.

    Denies and mutations are audited before the response is returned. An audit
    write must never mask an already-performed upstream mutation, so storage
    errors are swallowed (best-effort durability) rather than surfaced.

    Args:
        session(AsyncSession): Database session.
        context(ProxyAuthContext): The resolved scoped-token context (owner/token identity).
        method(str): The proxied HTTP method.
        path(str): The proxied request path.
        decision(str): Either "allow" or "deny".
        zone_id(str, optional): The Cloudflare zone id involved.
        record_id(str, optional): The Cloudflare record id involved.
        record_name(str, optional): The DNS record name involved.
        record_type(str, optional): The DNS record type involved.
        pre_image(dict, optional): The record state before the request.
        post_image(dict, optional): The record state after the request.
        deny_reason(str, optional): Why the request was denied.
        upstream_status(int, optional): The upstream HTTP status, when forwarded.
        client_ip(str, optional): The client source IP.

    Return:
        None
    """
    try:
        await write_audit(
            session,
            method=method,
            path=path,
            decision=decision,
            user_id=context.token.user_id,
            scoped_token_id=context.token.id,
            token_prefix=context.token.token_prefix,
            zone_id=zone_id,
            record_id=record_id,
            record_name=record_name,
            record_type=record_type,
            pre_image=pre_image,
            post_image=post_image,
            deny_reason=deny_reason,
            upstream_status=upstream_status,
            client_ip=client_ip,
        )
    except Exception:
        # Best-effort: never let an audit-store failure break the proxied response.
        pass


def _pop_pagination(query_params: Mapping[str, str]) -> tuple[int, int, dict[str, Any]]:
    """Split client-requested pagination out of a query-parameter mapping.

    Args:
        query_params(Mapping[str, str]): The raw client query parameters.

    Return:
        parsed(tuple[int, int, dict[str, Any]]): `(page, per_page, remaining_params)`
            where `remaining_params` no longer contains `page`/`per_page`.
    """
    remaining = dict(query_params)
    page = int(remaining.pop("page", _DEFAULT_PAGE) or _DEFAULT_PAGE)
    per_page = int(remaining.pop("per_page", _DEFAULT_PER_PAGE) or _DEFAULT_PER_PAGE)
    return page, per_page, remaining


async def _fetch_all_zones(
    auth_headers: Mapping[str, str], params: dict[str, Any]
) -> list[dict]:
    """Fetch every page of the caller's Cloudflare zone list.

    Args:
        auth_headers(Mapping[str, str]): The upstream authentication headers.
        params(dict[str, Any]): Client-supplied filters (e.g. `name`, `status`),
            forwarded on every page request.

    Return:
        zones(list[dict]): The concatenated `result` items across all pages.
    """
    zones: list[dict] = []
    page = 1
    while True:
        page_params = dict(params)
        page_params["page"] = page
        page_params.setdefault("per_page", 50)
        response = await forward_request(
            "GET",
            "/client/v4/zones",
            headers=None,
            params=page_params,
            content=None,
            auth_headers=auth_headers,
        )
        body = response.json()
        if response.status_code >= 400 or not body.get("success", False):
            return zones
        zones.extend(body.get("result") or [])
        result_info = body.get("result_info") or {}
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1
    return zones


@router.get(
    "/client/v4/zones",
    responses={
        200: {
            "description": "Zones the scoped token has any rule for",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One in-scope zone",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": [
                                    {"id": "zone1", "name": "example.com", "status": "active"}
                                ],
                                "result_info": {
                                    "page": 1,
                                    "per_page": 20,
                                    "count": 1,
                                    "total_count": 1,
                                    "total_pages": 1,
                                },
                            },
                        },
                    },
                },
            },
        },
    },
)
async def list_zones(
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """List the Cloudflare zones the caller's scoped token has any rule for.

    Forwards to Cloudflare for zone metadata, then filters `result[]` down to
    the distinct zone ids referenced by the token's scope rules and
    recomputes `result_info` over that filtered subset.

    Args:
        request(Request): The incoming request (used for its query string).
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): The Cloudflare-shaped, zone-filtered zone list.
    """
    page, per_page, remaining_params = _pop_pagination(request.query_params)

    auth_headers = await resolve_upstream_auth(session, context.credential)

    all_zones = await _fetch_all_zones(auth_headers, remaining_params)

    in_scope_zone_ids = {rule.zone_id for rule in context.rules}
    zones = [zone for zone in all_zones if zone.get("id") in in_scope_zone_ids]

    page_zones, result_info = paginate_and_result_info(zones, page, per_page)
    return make_cf_response(page_zones, result_info=result_info)


@router.get(
    "/client/v4/zones/{zone_id}/dns_records",
    responses={
        200: {
            "description": "Records the scoped token is authorized to read",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One authorized record",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": [
                                    {
                                        "id": "rec1",
                                        "zone_id": "zone1",
                                        "type": "A",
                                        "name": "home.example.com",
                                        "content": "1.2.3.4",
                                    }
                                ],
                                "result_info": {
                                    "page": 1,
                                    "per_page": 20,
                                    "count": 1,
                                    "total_count": 1,
                                    "total_pages": 1,
                                },
                            },
                        },
                    },
                },
            },
        },
    },
)
async def list_dns_records(
    zone_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """List the DNS records in a zone the caller's scoped token may read.

    A token with no rule at all for `zone_id` never touches Cloudflare and
    gets an empty, zeroed result. Otherwise every upstream page is fetched,
    filtered to read-authorized records, and re-paginated locally so the
    client's pagination reflects the authorized subset.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        request(Request): The incoming request (used for its query string).
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): The Cloudflare-shaped, read-filtered record list.
    """
    page, per_page, remaining_params = _pop_pagination(request.query_params)

    if not any(rule.zone_id == zone_id for rule in context.rules):
        _, result_info = paginate_and_result_info([], page, per_page)
        return make_cf_response([], result_info=result_info)

    auth_headers = await resolve_upstream_auth(session, context.credential)

    all_records = await list_all_records(zone_id, remaining_params, auth_headers)
    authorized = filter_records(all_records, context.rules, zone_id)

    page_records, result_info = paginate_and_result_info(authorized, page, per_page)
    return make_cf_response(page_records, result_info=result_info)


@router.post(
    "/client/v4/zones/{zone_id}/dns_records",
    responses={
        200: {
            "description": "Record created and forwarded verbatim from Cloudflare",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Record created",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": {
                                    "id": "rec1",
                                    "zone_id": "zone1",
                                    "type": "A",
                                    "name": "home.example.com",
                                    "content": "1.2.3.4",
                                },
                            },
                        },
                    },
                },
            },
        },
        403: {
            "description": "The scoped token's rules do not grant create for this name/type",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Out of scope",
                            "value": {
                                "success": False,
                                "errors": [
                                    {"code": 9109, "message": "Authorization error: insufficient scope"}
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
async def create_dns_record(
    zone_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Create a DNS record, authorized from the request body's name/type.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        request(Request): The incoming request, whose JSON body is authorized then forwarded verbatim.
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): The Cloudflare error envelope if unauthorized, else
            Cloudflare's verbatim create response.
    """
    body = await request.json()
    path = f"/client/v4/zones/{zone_id}/dns_records"
    record_name = body.get("name") if isinstance(body, dict) else None
    record_type = body.get("type") if isinstance(body, dict) else None

    async def _unused_fetch_record(_zone_id: str, _record_id: str | None) -> dict | None:
        return None

    decision = await authorize_dns_request(
        rules=context.rules,
        method="POST",
        zone_id=zone_id,
        record_id=None,
        body=body,
        fetch_record=_unused_fetch_record,
    )
    if not decision.allowed:
        status, code, message = decision.error
        await _record_audit(
            session,
            context,
            method="POST",
            path=path,
            decision="deny",
            zone_id=zone_id,
            record_name=record_name,
            record_type=record_type,
            deny_reason=f"{code}: {message}",
            client_ip=_client_ip(request),
        )
        return make_cf_error(status, code, message)

    auth_headers = await resolve_upstream_auth(session, context.credential)
    response = await forward_request(
        "POST",
        path,
        headers=None,
        params=None,
        content=await request.body(),
        auth_headers=auth_headers,
    )
    response_body = response.json()
    await _record_audit(
        session,
        context,
        method="POST",
        path=path,
        decision="allow",
        zone_id=zone_id,
        record_name=record_name,
        record_type=record_type,
        post_image=response_body.get("result") if isinstance(response_body, dict) else None,
        upstream_status=response.status_code,
        client_ip=_client_ip(request),
    )
    return JSONResponse(status_code=response.status_code, content=response_body)


async def _authorize_by_id(
    *,
    context: ProxyAuthContext,
    method: str,
    zone_id: str,
    record_id: str,
    body: dict | None,
    auth_headers: Mapping[str, str],
):
    """Run `authorize_dns_request` for a by-id operation using the live upstream fetch.

    Args:
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        method(str): The HTTP method of the proxied request.
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        body(dict | None): The parsed JSON request body, when present.
        auth_headers(Mapping[str, str]): The upstream authentication headers to use.

    Return:
        decision(cfproxy.authz.authorizer.AuthDecision): The authorization outcome.
    """

    async def _fetch_record(fetch_zone_id: str, fetch_record_id: str) -> dict | None:
        return await fetch_cf_record(fetch_zone_id, fetch_record_id, auth_headers)

    return await authorize_dns_request(
        rules=context.rules,
        method=method,
        zone_id=zone_id,
        record_id=record_id,
        body=body,
        fetch_record=_fetch_record,
    )


async def _mutate_dns_record_by_id(
    *,
    method: str,
    zone_id: str,
    record_id: str,
    body: dict | None,
    content: bytes | None,
    context: ProxyAuthContext,
    session: AsyncSession,
    request: Request,
) -> JSONResponse:
    """Authorize and forward a by-id DNS-record mutation (PATCH/PUT/DELETE).

    The MySQL advisory mutation lock (a no-op on SQLite) is acquired BEFORE
    the pre-image fetch/authorize step for any operation that is not
    lock-exempt, and held across fetch -> authorize -> forward, closing the
    TOCTOU window between reading the record's current name/type and
    forwarding the mutation. Denies and successful mutations are both
    durably audited before the response is returned.

    Args:
        method(str): The HTTP method to authorize and forward (PATCH/PUT/DELETE).
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        body(dict | None): The parsed JSON request body, when present (None for DELETE).
        content(bytes | None): The raw request body to forward, if any (None for DELETE).
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used for the lock connection's
            audit write and to resolve the upstream credential.
        request(Request): The incoming request, used for the client IP in audit rows.

    Return:
        response(JSONResponse): Cloudflare's verbatim response, a leak-safe 404,
            a 403 on rename/retype escape, or a fail-closed 503 Cloudflare-shaped
            error if the mutation lock could not be acquired.
    """
    path = f"/client/v4/zones/{zone_id}/dns_records/{record_id}"
    op = "delete" if method.upper() == "DELETE" else "write"
    exempt = is_lock_exempt(context.rules, zone_id, record_id, op)
    auth_headers = await resolve_upstream_auth(session, context.credential)

    async def _authorize_and_forward():
        decision = await _authorize_by_id(
            context=context,
            method=method,
            zone_id=zone_id,
            record_id=record_id,
            body=body,
            auth_headers=auth_headers,
        )
        if not decision.allowed:
            return decision, None
        upstream = await forward_request(
            method, path, headers=None, params=None, content=content, auth_headers=auth_headers
        )
        return decision, upstream

    if exempt:
        decision, upstream = await _authorize_and_forward()
    else:
        try:
            async with engine.connect() as conn:
                async with advisory_lock(conn, mutation_lock_name(zone_id, record_id)):
                    decision, upstream = await _authorize_and_forward()
        except LockUnavailable:
            return make_cf_error(503, INTERNAL, _LOCK_UNAVAILABLE_MESSAGE)

    pre_image = decision.pre_image

    if not decision.allowed:
        status, code, message = decision.error
        await _record_audit(
            session,
            context,
            method=method,
            path=path,
            decision="deny",
            zone_id=zone_id,
            record_id=record_id,
            record_name=pre_image.get("name") if pre_image else None,
            record_type=pre_image.get("type") if pre_image else None,
            pre_image=pre_image,
            deny_reason=f"{code}: {message}",
            client_ip=_client_ip(request),
        )
        return make_cf_error(status, code, message)

    body_json = upstream.json()
    post_image = body_json.get("result") if isinstance(body_json, dict) else None
    await _record_audit(
        session,
        context,
        method=method,
        path=path,
        decision="allow",
        zone_id=zone_id,
        record_id=record_id,
        record_name=pre_image.get("name") if pre_image else None,
        record_type=pre_image.get("type") if pre_image else None,
        pre_image=pre_image,
        post_image=post_image,
        upstream_status=upstream.status_code,
        client_ip=_client_ip(request),
    )
    return JSONResponse(status_code=upstream.status_code, content=body_json)


@router.get(
    "/client/v4/zones/{zone_id}/dns_records/{record_id}",
    responses={
        200: {
            "description": "The authorized record",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Record fetched",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": {
                                    "id": "rec1",
                                    "zone_id": "zone1",
                                    "type": "A",
                                    "name": "home.example.com",
                                    "content": "1.2.3.4",
                                },
                            },
                        },
                    },
                },
            },
        },
        404: {
            "description": "Record missing, cross-zone, or not read-authorized",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "Record does not exist",
                            "value": {
                                "success": False,
                                "errors": [{"code": 81044, "message": "Record does not exist."}],
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
async def get_dns_record(
    zone_id: str,
    record_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Fetch a single DNS record, authorized against the token's rules.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        request(Request): The incoming request, used for the client IP in audit rows.
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): The Cloudflare-shaped record, or a 404 leak-safe error.
    """
    auth_headers = await resolve_upstream_auth(session, context.credential)

    decision = await _authorize_by_id(
        context=context,
        method="GET",
        zone_id=zone_id,
        record_id=record_id,
        body=None,
        auth_headers=auth_headers,
    )
    if not decision.allowed:
        status, code, message = decision.error
        pre_image = decision.pre_image
        await _record_audit(
            session,
            context,
            method="GET",
            path=f"/client/v4/zones/{zone_id}/dns_records/{record_id}",
            decision="deny",
            zone_id=zone_id,
            record_id=record_id,
            record_name=pre_image.get("name") if pre_image else None,
            record_type=pre_image.get("type") if pre_image else None,
            pre_image=pre_image,
            deny_reason=f"{code}: {message}",
            client_ip=_client_ip(request),
        )
        return make_cf_error(status, code, message)

    return make_cf_response(decision.pre_image)


@router.patch(
    "/client/v4/zones/{zone_id}/dns_records/{record_id}",
    responses={
        200: {
            "description": "Record patched and forwarded verbatim from Cloudflare",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Record patched",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": {
                                    "id": "rec1",
                                    "zone_id": "zone1",
                                    "type": "A",
                                    "name": "home.example.com",
                                    "content": "5.6.7.8",
                                },
                            },
                        },
                    },
                },
            },
        },
        403: {
            "description": "The rename/retype would escape the token's scope",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Rename escape",
                            "value": {
                                "success": False,
                                "errors": [
                                    {"code": 9109, "message": "Authorization error: insufficient scope"}
                                ],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
        404: {
            "description": "Record missing, cross-zone, or not write-authorized",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "Record does not exist",
                            "value": {
                                "success": False,
                                "errors": [{"code": 81044, "message": "Record does not exist."}],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
        503: {
            "description": "The mutation lock could not be acquired",
            "content": {
                "application/json": {
                    "examples": {
                        "locked": {
                            "summary": "Fail-closed on lock timeout",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 1000,
                                        "message": "Could not acquire the record mutation lock, please retry.",
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
async def patch_dns_record(
    zone_id: str,
    record_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Patch a DNS record, authorizing both the old and (if changed) new name/type.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        request(Request): The incoming request, whose JSON body is authorized then forwarded verbatim.
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): Cloudflare's verbatim patch response, a leak-safe 404,
            a 403 on rename/retype escape, or a fail-closed 503 on a lock timeout.
    """
    body = await request.json()
    content = await request.body()

    return await _mutate_dns_record_by_id(
        method="PATCH",
        zone_id=zone_id,
        record_id=record_id,
        body=body,
        content=content,
        context=context,
        session=session,
        request=request,
    )


@router.put(
    "/client/v4/zones/{zone_id}/dns_records/{record_id}",
    responses={
        200: {
            "description": "Record replaced and forwarded verbatim from Cloudflare",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Record replaced",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": {
                                    "id": "rec1",
                                    "zone_id": "zone1",
                                    "type": "A",
                                    "name": "home.example.com",
                                    "content": "5.6.7.8",
                                },
                            },
                        },
                    },
                },
            },
        },
        403: {
            "description": "The rename/retype would escape the token's scope",
            "content": {
                "application/json": {
                    "examples": {
                        "forbidden": {
                            "summary": "Rename escape",
                            "value": {
                                "success": False,
                                "errors": [
                                    {"code": 9109, "message": "Authorization error: insufficient scope"}
                                ],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
        404: {
            "description": "Record missing, cross-zone, or not write-authorized",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "Record does not exist",
                            "value": {
                                "success": False,
                                "errors": [{"code": 81044, "message": "Record does not exist."}],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
        503: {
            "description": "The mutation lock could not be acquired",
            "content": {
                "application/json": {
                    "examples": {
                        "locked": {
                            "summary": "Fail-closed on lock timeout",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 1000,
                                        "message": "Could not acquire the record mutation lock, please retry.",
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
async def put_dns_record(
    zone_id: str,
    record_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Replace a DNS record, authorizing both the old and new name/type.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        request(Request): The incoming request, whose JSON body is authorized then forwarded verbatim.
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): Cloudflare's verbatim put response, a leak-safe 404,
            a 403 on rename/retype escape, or a fail-closed 503 on a lock timeout.
    """
    body = await request.json()
    content = await request.body()

    return await _mutate_dns_record_by_id(
        method="PUT",
        zone_id=zone_id,
        record_id=record_id,
        body=body,
        content=content,
        context=context,
        session=session,
        request=request,
    )


@router.delete(
    "/client/v4/zones/{zone_id}/dns_records/{record_id}",
    responses={
        200: {
            "description": "Record deleted and forwarded verbatim from Cloudflare",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "Record deleted",
                            "value": {
                                "success": True,
                                "errors": [],
                                "messages": [],
                                "result": {"id": "rec1"},
                            },
                        },
                    },
                },
            },
        },
        404: {
            "description": "Record missing, cross-zone, or not delete-authorized",
            "content": {
                "application/json": {
                    "examples": {
                        "not_found": {
                            "summary": "Record does not exist",
                            "value": {
                                "success": False,
                                "errors": [{"code": 81044, "message": "Record does not exist."}],
                                "messages": [],
                                "result": None,
                            },
                        },
                    },
                },
            },
        },
        503: {
            "description": "The mutation lock could not be acquired",
            "content": {
                "application/json": {
                    "examples": {
                        "locked": {
                            "summary": "Fail-closed on lock timeout",
                            "value": {
                                "success": False,
                                "errors": [
                                    {
                                        "code": 1000,
                                        "message": "Could not acquire the record mutation lock, please retry.",
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
async def delete_dns_record(
    zone_id: str,
    record_id: str,
    request: Request,
    context: Annotated[ProxyAuthContext, Depends(require_scoped_token)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> JSONResponse:
    """Delete a DNS record, authorized against the token's rules.

    Args:
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str): The Cloudflare record id from the request path.
        request(Request): The incoming request, used for the client IP in audit rows.
        context(ProxyAuthContext): The resolved scoped-token authorization context.
        session(AsyncSession): Database session, used to resolve the upstream credential.

    Return:
        response(JSONResponse): Cloudflare's verbatim delete response, a leak-safe 404,
            or a fail-closed 503 on a lock timeout.
    """
    return await _mutate_dns_record_by_id(
        method="DELETE",
        zone_id=zone_id,
        record_id=record_id,
        body=None,
        content=None,
        context=context,
        session=session,
        request=request,
    )
