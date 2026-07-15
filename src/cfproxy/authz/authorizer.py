"""DNS-record request authorization decision layer.

Wraps the pure predicates in `cfproxy.authz.scope` with the per-HTTP-method
decision flow: whether a mutation lock is required, whether/when to fetch
the upstream pre-image, and the exact allow/deny + leak-policy outcome for
each Cloudflare DNS-record operation. Performs no direct HTTP I/O itself --
the upstream record fetch is injected via the `fetch_record` callable so
this module stays independently testable.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from cfproxy.authz.scope import is_lock_exempt, match_rules, merge_patch_image
from cfproxy.core.cf_errors import FORBIDDEN, RECORD_NOT_FOUND

_MUTATION_OPS = {
    "PATCH": "write",
    "PUT": "write",
    "DELETE": "delete",
}

_RENAME_METHODS = {"PATCH", "PUT"}


@dataclass
class AuthDecision:
    """Outcome of authorizing a single DNS-record request.

    Args:
        allowed(bool): Whether the request is authorized to proceed.
        needs_lock(bool): Whether the mutation lock must be acquired before
            fetching the pre-image (only meaningful for by-id mutations).
        error(tuple[int, int, str] | None): `(http_status, cf_code, message)`
            to return to the caller when `allowed` is False.
        pre_image(dict | None): The fetched upstream record, when a fetch
            was performed and returned a record for this zone.
    """

    allowed: bool
    needs_lock: bool = False
    error: tuple[int, int, str] | None = None
    pre_image: dict | None = None


async def authorize_dns_request(
    *,
    rules: Any,
    method: str,
    zone_id: str,
    record_id: str | None,
    body: dict | None,
    fetch_record: Callable[[str, str], Awaitable[dict | None]],
) -> AuthDecision:
    """Authorize a single proxied Cloudflare DNS-record request.

    `POST` (create) is authorized from the request body's `name`/`type`
    against `match_rules(..., 'create')`; no upstream fetch or lock is
    involved. `GET`/`PATCH`/`PUT`/`DELETE` are by-id operations: the lock
    exemption is computed from `record_id` + `rules` alone (no circular
    dependency on the pre-image), then the record is fetched. A missing or
    cross-zone record, or a record the rules do not authorize for the old
    image, is denied as 404 (no existence leak to unauthorized callers).
    For `PATCH`/`PUT`, when the request would change the record's name or
    type, the new (post) name/type must also be authorized, else 403
    (rename/retype escape).

    Args:
        rules(Any): The scoped token's scope rules (`ScopeRule`-like
            objects, see `cfproxy.authz.scope`).
        method(str): The HTTP method of the proxied request.
        zone_id(str): The Cloudflare zone id from the request path.
        record_id(str | None): The Cloudflare record id from the request
            path, or None for `POST` (create).
        body(dict | None): The parsed JSON request body, when present.
        fetch_record(Callable[[str, str], Awaitable[dict | None]]): Async
            callable `(zone_id, record_id) -> record | None` used to fetch
            the current upstream record for by-id operations.

    Return:
        decision(AuthDecision): The authorization outcome.
    """
    method_upper = method.upper()

    if method_upper == "POST":
        name = (body or {}).get("name")
        rtype = (body or {}).get("type")
        if match_rules(rules, zone_id, name, rtype, None, "create"):
            return AuthDecision(allowed=True)
        return AuthDecision(
            allowed=False,
            error=(403, FORBIDDEN, "Authorization error: insufficient scope"),
        )

    if method_upper == "GET":
        op = "read"
    elif method_upper in _MUTATION_OPS:
        op = _MUTATION_OPS[method_upper]
    else:
        return AuthDecision(
            allowed=False,
            error=(403, FORBIDDEN, "Authorization error: unsupported method"),
        )

    needs_lock = False
    if method_upper in _MUTATION_OPS:
        needs_lock = not is_lock_exempt(rules, zone_id, record_id, op)

    pre = await fetch_record(zone_id, record_id)
    if pre is None or pre.get("zone_id") not in (None, zone_id):
        return AuthDecision(
            allowed=False,
            needs_lock=needs_lock,
            error=(404, RECORD_NOT_FOUND, "Record does not exist."),
        )

    pre_name = pre.get("name")
    pre_type = pre.get("type")

    if not match_rules(rules, zone_id, pre_name, pre_type, record_id, op):
        return AuthDecision(
            allowed=False,
            needs_lock=needs_lock,
            error=(404, RECORD_NOT_FOUND, "Record does not exist."),
            pre_image=pre,
        )

    if method_upper in _RENAME_METHODS:
        post_name, post_type = merge_patch_image(pre, body or {})
        if (post_name, post_type) != (pre_name, pre_type):
            if not match_rules(rules, zone_id, post_name, post_type, record_id, op):
                return AuthDecision(
                    allowed=False,
                    needs_lock=needs_lock,
                    error=(403, FORBIDDEN, "Authorization error: insufficient scope"),
                    pre_image=pre,
                )

    return AuthDecision(allowed=True, needs_lock=needs_lock, pre_image=pre)
