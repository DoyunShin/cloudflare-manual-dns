"""Tests for the `/client/v4` proxy routers (`proxy_verify`, `proxy_dns`,
`proxy_blocked`), driven end-to-end through an httpx client bound to a
minimal FastAPI app assembling the three routers -- Cloudflare HTTP is
mocked with respx, and the request-scoped database session is swapped for
the isolated per-test session.
"""

from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from httpx import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.config import get_settings
from cfproxy.core.cf_errors import INTERNAL
from cfproxy.core.crypto import encrypt_secret, generate_scoped_token
from cfproxy.core.envelopes import make_cf_error
from cfproxy.db.models import AuditLog, ScopedToken, ScopeRule, UpstreamCredential, User
from cfproxy.db.session import get_session
from cfproxy.routers import proxy_blocked, proxy_dns, proxy_verify

BASE_URL = get_settings().upstream_base_url


def _build_app() -> FastAPI:
    """Assemble a minimal FastAPI app exposing all three proxy routers.

    Routers are included in the order the real app must use: `proxy_verify`
    and `proxy_dns` first (so their concrete paths win), `proxy_blocked`
    last (its literal batch/import/export routes still win over `proxy_dns`'s
    by-id routes since they are registered by-router, and its catch-all is
    declared after them within the same router). A local `HTTPException`
    handler reformats dependency-raised errors (e.g. `require_scoped_token`)
    into the Cloudflare envelope, mirroring the proxy-scope handler the Wire
    phase registers in `main.py`.

    Return:
        app(FastAPI): The assembled app, ready for `dependency_overrides`.
    """
    app = FastAPI()
    app.include_router(proxy_verify.router)
    app.include_router(proxy_dns.router)
    app.include_router(proxy_blocked.router)

    @app.exception_handler(HTTPException)
    async def _handle_proxy_http_exception(request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "code" in detail:
            return make_cf_error(exc.status_code, detail["code"], detail.get("message", ""))
        return make_cf_error(exc.status_code, INTERNAL, str(detail))

    return app


async def _make_scoped_token(db_session: AsyncSession) -> tuple[ScopedToken, str, UpstreamCredential]:
    """Create a user, a token-type upstream credential, and an active scoped token.

    Return:
        row(tuple[ScopedToken, str, UpstreamCredential]): The persisted
            `ScopedToken`, the full plaintext token string, and the
            persisted `UpstreamCredential`.
    """
    user = User(email=f"user-{uuid4().hex}@example.com", auth_provider="local")
    db_session.add(user)
    await db_session.flush()

    credential = UpstreamCredential(
        user_id=user.id,
        label="primary",
        cred_type="token",
        secret_enc=encrypt_secret("cf-upstream-token"),
    )
    db_session.add(credential)
    await db_session.flush()

    generated = generate_scoped_token()
    scoped_token = ScopedToken(
        user_id=user.id,
        upstream_credential_id=credential.id,
        name="test token",
        lookup_id=generated["lookup_id"],
        token_prefix=generated["token_prefix"],
        token_hash=generated["token_hash"],
        version=1,
        status="active",
    )
    db_session.add(scoped_token)
    await db_session.flush()
    await db_session.commit()

    return scoped_token, generated["full"], credential


async def _add_rule(db_session: AsyncSession, scoped_token: ScopedToken, **overrides) -> ScopeRule:
    """Attach a `ScopeRule` row to a scoped token.

    Return:
        rule(ScopeRule): The persisted rule row.
    """
    defaults = dict(
        scoped_token_id=scoped_token.id,
        zone_id="zone1",
        name_pattern="home.example.com",
        name_match="exact",
        record_types=["A"],
        record_ids=None,
        allow_read=True,
        allow_create=False,
        allow_write=False,
        allow_delete=False,
    )
    defaults.update(overrides)
    rule = ScopeRule(**defaults)
    db_session.add(rule)
    await db_session.flush()
    await db_session.commit()
    return rule


def _auth_headers(full_token: str) -> dict[str, str]:
    """Build an `Authorization: Bearer <token>` header dict.

    Return:
        headers(dict[str, str]): The header mapping for a request.
    """
    return {"Authorization": f"Bearer {full_token}"}


# ---------------------------------------------------------------------------
# GET /client/v4/user/tokens/verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_active_token_returns_200(
    db_session: AsyncSession, async_client_factory
) -> None:
    """An active scoped token is reported as valid and active."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/user/tokens/verify", headers=_auth_headers(full_token)
        )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"] == {"id": scoped_token.id, "status": "active"}
    assert body["messages"][0]["code"] == 10000


@pytest.mark.asyncio
async def test_verify_invalid_token_returns_401(
    db_session: AsyncSession, async_client_factory
) -> None:
    """A malformed/unknown token yields a Cloudflare-shaped 401."""
    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/user/tokens/verify", headers=_auth_headers("garbage")
        )

    assert response.status_code == 401
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 1000


# ---------------------------------------------------------------------------
# POST /client/v4/zones/{zone_id}/dns_records (create)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_dns_record_in_scope_returns_200(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A create request matching an `allow_create` rule is forwarded and returns 200."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_create=True, allow_read=False)

    upstream_result = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    route = respx_mock.post(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": upstream_result}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.post(
            "/client/v4/zones/zone1/dns_records",
            headers=_auth_headers(full_token),
            json={"type": "A", "name": "home.example.com", "content": "1.2.3.4"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"] == upstream_result
    assert route.call_count == 1
    assert route.calls.last.request.headers["Authorization"] == "Bearer cf-upstream-token"


@pytest.mark.asyncio
async def test_create_dns_record_out_of_scope_returns_403(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A create request with no matching `allow_create` rule is denied 403/9109 without forwarding."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_create=False, allow_read=True)

    route = respx_mock.post(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": {"id": "rec1"},
            },
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.post(
            "/client/v4/zones/zone1/dns_records",
            headers=_auth_headers(full_token),
            json={"type": "A", "name": "home.example.com", "content": "1.2.3.4"},
        )

    assert response.status_code == 403
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 9109
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# GET /client/v4/zones/{zone_id}/dns_records/{record_id} (by-id read)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_dns_record_authorized_returns_200(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A read-authorized record is returned in the Cloudflare envelope."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_read=True)

    upstream_result = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": upstream_result}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/zones/zone1/dns_records/rec1", headers=_auth_headers(full_token)
        )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"] == upstream_result


@pytest.mark.asyncio
async def test_get_dns_record_out_of_scope_returns_404_not_403(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A record that exists upstream but is not read-authorized leaks nothing: 404/81044."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_read=True)

    upstream_result = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "other.example.com",
        "content": "1.2.3.4",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": upstream_result}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/zones/zone1/dns_records/rec1", headers=_auth_headers(full_token)
        )

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 81044


@pytest.mark.asyncio
async def test_get_dns_record_missing_returns_404(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A record missing upstream is reported the same leak-safe 404/81044."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_read=True)

    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/missing").mock(
        return_value=Response(
            404,
            json={
                "success": False,
                "errors": [{"code": 81044, "message": "Record does not exist."}],
                "messages": [],
                "result": None,
            },
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/zones/zone1/dns_records/missing", headers=_auth_headers(full_token)
        )

    assert response.status_code == 404
    body = response.json()
    assert body["errors"][0]["code"] == 81044


# ---------------------------------------------------------------------------
# PATCH/PUT /client/v4/zones/{zone_id}/dns_records/{record_id} (rename escape)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_rename_escape_returns_403(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """Renaming an authorized record outside the rule's pattern is denied 403/9109."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_write=True, allow_read=False)

    pre_image = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": pre_image}
        )
    )
    patch_route = respx_mock.patch(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": {}}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.patch(
            "/client/v4/zones/zone1/dns_records/rec1",
            headers=_auth_headers(full_token),
            json={"name": "escaped.other-zone.com"},
        )

    assert response.status_code == 403
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 9109
    assert patch_route.call_count == 0


@pytest.mark.asyncio
async def test_put_rename_escape_returns_403(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """Replacing an authorized record with an out-of-scope name is denied 403/9109."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_write=True, allow_read=False)

    pre_image = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": pre_image}
        )
    )
    put_route = respx_mock.put(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": {}}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.put(
            "/client/v4/zones/zone1/dns_records/rec1",
            headers=_auth_headers(full_token),
            json={"name": "escaped.other-zone.com", "type": "A", "content": "1.2.3.4"},
        )

    assert response.status_code == 403
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 9109
    assert put_route.call_count == 0


# ---------------------------------------------------------------------------
# PATCH /client/v4/zones/{zone_id}/dns_records/{record_id} (authorized mutation + audit)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_dns_record_authorized_returns_200_and_audits_allow(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """An authorized PATCH is forwarded, and a durable allow audit row is written."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_write=True, allow_read=False)

    pre_image = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    post_image = {**pre_image, "content": "5.6.7.8"}
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": pre_image}
        )
    )
    patch_route = respx_mock.patch(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": post_image}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.patch(
            "/client/v4/zones/zone1/dns_records/rec1",
            headers=_auth_headers(full_token),
            json={"content": "5.6.7.8"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["result"] == post_image
    assert patch_route.call_count == 1
    assert patch_route.calls.last.request.headers["Authorization"] == "Bearer cf-upstream-token"

    audit_rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.scoped_token_id == scoped_token.id)
            )
        )
        .scalars()
        .all()
    )
    allow_rows = [row for row in audit_rows if row.decision == "allow"]
    assert len(allow_rows) == 1
    allow_row = allow_rows[0]
    assert allow_row.zone_id == "zone1"
    assert allow_row.record_id == "rec1"
    assert allow_row.record_name == "home.example.com"
    assert allow_row.record_type == "A"
    assert allow_row.pre_image == pre_image
    assert allow_row.post_image == post_image
    assert allow_row.upstream_status == 200


@pytest.mark.asyncio
async def test_create_dns_record_out_of_scope_writes_deny_audit(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """An out-of-scope create is denied and a durable deny audit row is written."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_create=False, allow_read=True)

    respx_mock.post(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": {"id": "rec1"}}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.post(
            "/client/v4/zones/zone1/dns_records",
            headers=_auth_headers(full_token),
            json={"type": "A", "name": "home.example.com", "content": "1.2.3.4"},
        )

    assert response.status_code == 403

    audit_rows = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.scoped_token_id == scoped_token.id)
            )
        )
        .scalars()
        .all()
    )
    deny_rows = [row for row in audit_rows if row.decision == "deny"]
    assert len(deny_rows) == 1
    deny_row = deny_rows[0]
    assert deny_row.zone_id == "zone1"
    assert deny_row.record_name == "home.example.com"
    assert deny_row.record_type == "A"
    assert deny_row.deny_reason is not None


# ---------------------------------------------------------------------------
# GET /client/v4/zones/{zone_id}/dns_records (list, filtered + re-paginated)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_dns_records_returns_only_scoped_subset_with_result_info(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """Listing filters out unauthorized records and recomputes result_info over the subset."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, allow_read=True)

    in_scope_record = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    out_of_scope_record = {
        "id": "rec2",
        "zone_id": "zone1",
        "type": "A",
        "name": "other.example.com",
        "content": "5.6.7.8",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": [in_scope_record, out_of_scope_record],
                "result_info": {
                    "page": 1,
                    "per_page": 100,
                    "count": 2,
                    "total_count": 2,
                    "total_pages": 1,
                },
            },
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/zones/zone1/dns_records",
            headers=_auth_headers(full_token),
            params={"page": 1, "per_page": 10},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["result"] == [in_scope_record]
    assert body["result_info"] == {
        "page": 1,
        "per_page": 10,
        "count": 1,
        "total_count": 1,
        "total_pages": 1,
    }


@pytest.mark.asyncio
async def test_list_dns_records_no_rule_for_zone_skips_upstream(
    db_session: AsyncSession, async_client_factory, respx_mock
) -> None:
    """A token with no rule at all for the zone gets an empty, zeroed result without a CF call."""
    scoped_token, full_token, _credential = await _make_scoped_token(db_session)
    await _add_rule(db_session, scoped_token, zone_id="other-zone", allow_read=True)

    route = respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": []}
        )
    )

    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get(
            "/client/v4/zones/zone1/dns_records", headers=_auth_headers(full_token)
        )

    assert response.status_code == 200
    body = response.json()
    assert body["result"] == []
    assert body["result_info"]["total_count"] == 0
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# Blocked bulk operations and the catch-all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dns_records_batch_returns_403(
    db_session: AsyncSession, async_client_factory
) -> None:
    """Batch mutation requests are unconditionally rejected 403/9109."""
    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.post("/client/v4/zones/zone1/dns_records/batch", json={})

    assert response.status_code == 403
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 9109


@pytest.mark.asyncio
async def test_catch_all_returns_404_with_cf_envelope(
    db_session: AsyncSession, async_client_factory
) -> None:
    """Any unmatched `/client/v4` path answers 404/7003 in the Cloudflare envelope."""
    app = _build_app()
    app.dependency_overrides[get_session] = lambda: db_session

    async with async_client_factory(app) as client:
        response = await client.get("/client/v4/does/not/exist")

    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"][0]["code"] == 7003
