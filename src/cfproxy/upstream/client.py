"""HTTP client for forwarding authorized requests to the real Cloudflare API.

All outbound traffic is pinned to the single permitted Cloudflare API origin
via a shared, connection-pooled `httpx.AsyncClient` -- the proxy never accepts
a caller-supplied upstream host, and refuses to start forwarding if
`settings.upstream_base_url` has been pointed anywhere other than
`https://api.cloudflare.com` (SSRF / credential-exfiltration guard).

Upstream authentication is resolved into a header mapping by
`resolve_upstream_auth`: `token`/`oauth` credentials produce an
`Authorization: Bearer <token>` header, while legacy `global_key` credentials
produce the `X-Auth-Email` + `X-Auth-Key` header pair Cloudflare requires.
Every forward strips ALL client-supplied authentication headers before
injecting the resolved upstream ones.
"""

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.cache.redis import cache_get_json, cache_set_json, oauth_at_key
from cfproxy.config import get_settings
from cfproxy.core.crypto import decrypt_secret, encrypt_secret
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import UpstreamCredential

_cf_client: httpx.AsyncClient | None = None

# The only origin the proxy is ever allowed to forward decrypted credentials to.
_ALLOWED_UPSTREAM_ORIGIN = "https://api.cloudflare.com"

# Client-supplied authentication headers that must never be forwarded upstream.
_STRIPPED_AUTH_HEADERS = frozenset(
    {"authorization", "x-auth-email", "x-auth-key", "x-auth-user-service-key"}
)


def _assert_pinned_origin(base_url: str) -> None:
    """Reject any upstream base URL whose origin is not the Cloudflare API.

    Args:
        base_url(str): The configured upstream base URL.

    Raises:
        RuntimeError: If the URL's scheme/host/port is not exactly
            `https://api.cloudflare.com`.
    """
    parts = urlsplit(base_url)
    origin = f"{parts.scheme}://{parts.netloc}".lower().rstrip("/")
    if origin != _ALLOWED_UPSTREAM_ORIGIN:
        raise RuntimeError(
            f"upstream_base_url must be {_ALLOWED_UPSTREAM_ORIGIN!r}, refusing to forward to {origin!r}"
        )


def get_cf_client() -> httpx.AsyncClient:
    """Return the shared httpx client pinned to the Cloudflare API base URL.

    Creates the client on first use (module-level singleton) so all requests
    share one connection pool; the client is closed by the app lifespan. The
    configured origin is asserted to be the Cloudflare API before any request
    can be issued.

    Return:
        client(httpx.AsyncClient): The process-wide client instance.
    """
    global _cf_client
    if _cf_client is None:
        base_url = get_settings().upstream_base_url
        _assert_pinned_origin(base_url)
        _cf_client = httpx.AsyncClient(base_url=base_url)
    return _cf_client


async def close_cf_client() -> None:
    """Close the shared Cloudflare httpx client (for app lifespan shutdown).

    Return:
        None
    """
    global _cf_client
    if _cf_client is not None:
        await _cf_client.aclose()
        _cf_client = None


async def forward_request(
    method: str,
    path: str,
    *,
    headers: Mapping[str, str] | None,
    params: Mapping[str, Any] | None,
    content: bytes | None,
    auth_headers: Mapping[str, str],
) -> httpx.Response:
    """Forward a request to the real Cloudflare API, swapping the credential.

    Every client-supplied authentication header (`Authorization`,
    `X-Auth-Email`, `X-Auth-Key`, `X-Auth-User-Service-Key`) is stripped before
    forwarding; the resolved `auth_headers` are injected in their place. The
    request always goes to `{settings.upstream_base_url}{path}`.

    Args:
        method(str): HTTP method to forward.
        path(str): Request path (e.g. "/client/v4/zones/z1/dns_records").
        headers(Mapping[str, str] | None): Client-supplied headers to forward,
            minus every authentication header.
        params(Mapping[str, Any] | None): Query parameters to forward.
        content(bytes | None): Raw request body to forward.
        auth_headers(Mapping[str, str]): The upstream authentication headers to
            inject (e.g. `{"Authorization": "Bearer <token>"}` or the
            `X-Auth-Email`/`X-Auth-Key` pair).

    Return:
        response(httpx.Response): The upstream Cloudflare response.
    """
    forwarded_headers = {
        key: value
        for key, value in (headers or {}).items()
        if key.lower() not in _STRIPPED_AUTH_HEADERS
    }
    forwarded_headers.update(auth_headers)
    client = get_cf_client()
    return await client.request(
        method,
        path,
        headers=forwarded_headers,
        params=params,
        content=content,
    )


async def fetch_cf_record(
    zone_id: str, record_id: str, auth_headers: Mapping[str, str]
) -> dict | None:
    """Fetch a single DNS record from Cloudflare.

    Args:
        zone_id(str): The Cloudflare zone id.
        record_id(str): The Cloudflare DNS record id.
        auth_headers(Mapping[str, str]): The upstream authentication headers.

    Return:
        record(dict | None): The record's `result` payload, or None on a 404.
    """
    response = await forward_request(
        "GET",
        f"/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers=None,
        params=None,
        content=None,
        auth_headers=auth_headers,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()["result"]


async def list_all_records(
    zone_id: str, params: Mapping[str, Any] | None, auth_headers: Mapping[str, str]
) -> list[dict]:
    """Fetch every page of a DNS-record list from Cloudflare.

    Args:
        zone_id(str): The Cloudflare zone id.
        params(Mapping[str, Any] | None): Client-supplied list filters (e.g.
            `type`, `name`) forwarded on every page request.
        auth_headers(Mapping[str, str]): The upstream authentication headers.

    Return:
        records(list[dict]): The concatenated `result` items across all pages.
    """
    records: list[dict] = []
    page = 1
    while True:
        page_params = dict(params or {})
        page_params["page"] = page
        page_params.setdefault("per_page", 100)
        response = await forward_request(
            "GET",
            f"/client/v4/zones/{zone_id}/dns_records",
            headers=None,
            params=page_params,
            content=None,
            auth_headers=auth_headers,
        )
        response.raise_for_status()
        body = response.json()
        records.extend(body.get("result") or [])
        result_info = body.get("result_info") or {}
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages:
            break
        page += 1
    return records


async def verify_upstream(auth_headers: Mapping[str, str]) -> dict:
    """Verify an upstream Cloudflare credential via the token-verify endpoint.

    Args:
        auth_headers(Mapping[str, str]): The upstream authentication headers.

    Return:
        envelope(dict): The parsed Cloudflare response envelope.
    """
    response = await forward_request(
        "GET",
        "/client/v4/user/tokens/verify",
        headers=None,
        params=None,
        content=None,
        auth_headers=auth_headers,
    )
    return response.json()


async def resolve_upstream_auth(
    session: AsyncSession, credential: UpstreamCredential
) -> dict[str, str]:
    """Resolve the upstream authentication headers for a stored credential.

    `token` and `oauth` credentials yield an `Authorization: Bearer` header
    (OAuth credentials are refreshed as needed via `get_valid_access_token`).
    Legacy `global_key` credentials yield the `X-Auth-Email` + `X-Auth-Key`
    header pair Cloudflare requires -- a Global API Key cannot authenticate as
    a Bearer token.

    Args:
        session(AsyncSession): Active database session (used for OAuth refresh).
        credential(UpstreamCredential): The stored upstream credential.

    Return:
        headers(dict[str, str]): The authentication headers to inject upstream.
    """
    if credential.cred_type == "global_key":
        data = json.loads(decrypt_secret(credential.secret_enc))
        return {"X-Auth-Email": data["email"], "X-Auth-Key": data["key"]}
    token = await get_valid_access_token(session, credential)
    return {"Authorization": f"Bearer {token}"}


async def get_valid_access_token(session: AsyncSession, credential: UpstreamCredential) -> str:
    """Resolve a usable bearer token for a stored upstream credential.

    Token credentials are decrypted directly. OAuth credentials are served
    from an encrypted access-token cache when present; otherwise the
    credential row is locked (`with_row_lock`), expiry is re-checked inside
    the lock (a waiter may find a concurrent refresher already rotated it),
    and only then is the refresh grant performed. The rotated tokens are
    persisted with a conditional `cred_version` bump (fences stale writers)
    and re-cached encrypted.

    Args:
        session(AsyncSession): Active database session, used for the row lock
            and for persisting rotated tokens.
        credential(UpstreamCredential): The stored upstream credential to
            resolve a token for.

    Return:
        token(str): The raw bearer token string (without a "Bearer " prefix).
    """
    if credential.cred_type != "oauth":
        return decrypt_secret(credential.secret_enc)

    settings = get_settings()
    skew = timedelta(seconds=settings.access_token_skew)

    cached_enc = await cache_get_json(oauth_at_key(credential.id))
    if cached_enc:
        return decrypt_secret(cached_enc)

    stmt = with_row_lock(
        session, select(UpstreamCredential).where(UpstreamCredential.id == credential.id)
    )
    result = await session.execute(stmt)
    locked = result.scalar_one()

    now = datetime.now(UTC)
    if locked.token_expires_at is not None and locked.token_expires_at - skew > now:
        return decrypt_secret(locked.access_token_enc)

    from cfproxy.auth.oauth_cf import refresh_access_token

    token_data = await refresh_access_token(decrypt_secret(locked.refresh_token_enc))

    new_access_token = token_data["access_token"]
    new_refresh_token = token_data.get("refresh_token") or decrypt_secret(locked.refresh_token_enc)
    expires_in = token_data.get("expires_in")
    new_expires_at = now + timedelta(seconds=expires_in) if expires_in is not None else None

    await session.execute(
        update(UpstreamCredential)
        .where(
            UpstreamCredential.id == credential.id,
            UpstreamCredential.cred_version == locked.cred_version,
        )
        .values(
            access_token_enc=encrypt_secret(new_access_token),
            refresh_token_enc=encrypt_secret(new_refresh_token),
            token_expires_at=new_expires_at,
            cred_version=locked.cred_version + 1,
        )
    )
    await session.commit()

    if expires_in is not None:
        ttl = max(int(expires_in) - settings.access_token_skew, 1)
        await cache_set_json(oauth_at_key(credential.id), encrypt_secret(new_access_token), ttl)

    return new_access_token
