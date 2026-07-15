"""Tests for the cfproxy management routers (auth, credentials, tokens, audit).

Covers: register->login->mint-token happy path; unauthorized 401 on every
protected endpoint; cross-user IDOR (404, not another user's data) across
credentials and scoped tokens; and the {status,message,data} envelope shape.

Builds a small FastAPI app assembling only these routers (main.py is owned
by the Wire phase and does not exist yet); mocks all Cloudflare HTTP with
respx and never touches the network.
"""

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import Response

from cfproxy.config import get_settings
from cfproxy.routers.audit import router as audit_router
from cfproxy.routers.auth import router as auth_router
from cfproxy.routers.credentials import router as credentials_router
from cfproxy.routers.tokens import router as tokens_router

BASE_URL = get_settings().upstream_base_url


def _build_app() -> FastAPI:
    """Build a FastAPI app exposing only the management routers under test.

    Return:
        app(FastAPI): The app with auth/credentials/tokens/audit routers mounted.
    """
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(credentials_router)
    app.include_router(tokens_router)
    app.include_router(audit_router)
    return app


def _record_ids_rule(**overrides) -> dict:
    """Build a minimal record_ids-pinned scope rule payload (no upstream zone lookup needed)."""
    rule = {
        "zone_id": "zone1",
        "record_ids": ["rec1"],
        "record_types": ["*"],
        "allow_read": True,
        "allow_create": False,
        "allow_write": False,
        "allow_delete": False,
    }
    rule.update(overrides)
    return rule


async def _register_and_login(client, email: str, password: str = "correct-horse-battery") -> str:
    """Register a fresh local account and log in, returning its bearer JWT.

    Args:
        client: The httpx.AsyncClient bound to the app under test.
        email(str): A unique email address for the new account.
        password(str): The account's plaintext password.

    Return:
        jwt(str): The issued session JWT.
    """
    register_resp = await client.post(
        "/api/v1/auth/register", json={"email": email, "password": password}
    )
    assert register_resp.status_code == 201, register_resp.text

    login_resp = await client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert login_resp.status_code == 200, login_resp.text
    return login_resp.json()["data"]["access_token"]


def _auth_headers(jwt: str) -> dict:
    """Build an Authorization header dict for the given JWT."""
    return {"Authorization": f"Bearer {jwt}"}


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_response_envelope_shape(async_client_factory) -> None:
    """register returns the {status, message, data} envelope with a UserResponse."""
    app = _build_app()
    async with async_client_factory(app) as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": f"{uuid4().hex}@example.com", "password": "pw-12345678"},
        )

    assert response.status_code == 201
    body = response.json()
    assert set(body.keys()) == {"status", "message", "data"}
    assert body["status"] == 201
    assert set(body["data"].keys()) == {
        "id",
        "email",
        "auth_provider",
        "is_active",
        "created_at",
    }


@pytest.mark.asyncio
async def test_register_duplicate_email_conflict(async_client_factory) -> None:
    """Registering the same email twice is rejected with a 409 envelope."""
    app = _build_app()
    email = f"{uuid4().hex}@example.com"
    async with async_client_factory(app) as client:
        first = await client.post(
            "/api/v1/auth/register", json={"email": email, "password": "pw-12345678"}
        )
        assert first.status_code == 201

        second = await client.post(
            "/api/v1/auth/register", json={"email": email, "password": "pw-12345678"}
        )

    assert second.status_code == 409
    body = second.json()
    assert body["status"] == 409
    assert body["data"] is None


@pytest.mark.asyncio
async def test_login_wrong_password_rejected(async_client_factory) -> None:
    """Logging in with the wrong password returns a 401 envelope."""
    app = _build_app()
    email = f"{uuid4().hex}@example.com"
    async with async_client_factory(app) as client:
        await client.post(
            "/api/v1/auth/register", json={"email": email, "password": "right-password"}
        )
        response = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": "wrong-password"}
        )

    assert response.status_code == 401
    assert response.json()["data"] is None


# ---------------------------------------------------------------------------
# Register -> login -> mint scoped token happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_login_mint_token_flow(async_client_factory) -> None:
    """A user can register, log in, register a credential, and mint a scoped token."""
    app = _build_app()
    async with async_client_factory(app) as client:
        jwt = await _register_and_login(client, f"{uuid4().hex}@example.com")
        headers = _auth_headers(jwt)

        me_resp = await client.get("/api/v1/auth/me", headers=headers)
        assert me_resp.status_code == 200
        assert me_resp.json()["data"]["email"] is not None

        cred_resp = await client.post(
            "/api/v1/upstream-credentials",
            headers=headers,
            json={"label": "prod", "cred_type": "token", "api_token": "cf-plain-token-abc"},
        )
        assert cred_resp.status_code == 201, cred_resp.text
        credential_id = cred_resp.json()["data"]["id"]

        list_cred_resp = await client.get("/api/v1/upstream-credentials", headers=headers)
        assert list_cred_resp.status_code == 200
        assert len(list_cred_resp.json()["data"]) == 1

        mint_resp = await client.post(
            "/api/v1/scoped-tokens",
            headers=headers,
            json={
                "name": "staging-dns",
                "upstream_credential_id": credential_id,
                "scope_rules": [_record_ids_rule()],
            },
        )
        assert mint_resp.status_code == 201, mint_resp.text
        mint_data = mint_resp.json()["data"]
        assert mint_data["token"].startswith("cfsx_")
        token_id = mint_data["id"]

        list_tokens_resp = await client.get("/api/v1/scoped-tokens", headers=headers)
        assert list_tokens_resp.status_code == 200
        assert len(list_tokens_resp.json()["data"]) == 1
        assert "token" not in list_tokens_resp.json()["data"][0]

        detail_resp = await client.get(f"/api/v1/scoped-tokens/{token_id}", headers=headers)
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()["data"]
        assert detail_data["id"] == token_id
        assert len(detail_data["rules"]) == 1
        assert detail_data["rules"][0]["record_ids"] == ["rec1"]

        rotate_resp = await client.post(
            f"/api/v1/scoped-tokens/{token_id}/rotate", headers=headers
        )
        assert rotate_resp.status_code == 200
        rotated = rotate_resp.json()["data"]
        assert rotated["token"] != mint_data["token"]
        assert rotated["token"].startswith("cfsx_")

        revoke_resp = await client.delete(
            f"/api/v1/scoped-tokens/{token_id}", headers=headers
        )
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["data"] is None

        detail_after_revoke = await client.get(
            f"/api/v1/scoped-tokens/{token_id}", headers=headers
        )
        assert detail_after_revoke.status_code == 200
        assert detail_after_revoke.json()["data"]["status"] == "revoked"


@pytest.mark.asyncio
async def test_verify_credential_upstream(respx_mock, async_client_factory) -> None:
    """Verifying a credential calls the mocked Cloudflare token-verify endpoint."""
    respx_mock.get(f"{BASE_URL}/client/v4/user/tokens/verify").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": {"id": "tok1", "status": "active", "email": "cf-user@example.com"},
            },
        )
    )

    app = _build_app()
    async with async_client_factory(app) as client:
        jwt = await _register_and_login(client, f"{uuid4().hex}@example.com")
        headers = _auth_headers(jwt)

        cred_resp = await client.post(
            "/api/v1/upstream-credentials",
            headers=headers,
            json={"label": "prod", "cred_type": "token", "api_token": "cf-plain-token-abc"},
        )
        credential_id = cred_resp.json()["data"]["id"]

        verify_resp = await client.post(
            f"/api/v1/upstream-credentials/{credential_id}/verify", headers=headers
        )

    assert verify_resp.status_code == 200
    data = verify_resp.json()["data"]
    assert data["verify_status"] == "active"
    assert data["cf_account_email"] == "cf-user@example.com"


@pytest.mark.asyncio
async def test_audit_logs_listed_with_result_info(async_client_factory) -> None:
    """audit-logs returns an empty list with result_info for a user with no entries."""
    app = _build_app()
    async with async_client_factory(app) as client:
        jwt = await _register_and_login(client, f"{uuid4().hex}@example.com")

        response = await client.get("/api/v1/audit-logs", headers=_auth_headers(jwt))

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["items"] == []
    assert data["result_info"] == {"page": 1, "per_page": 50, "count": 0, "total_count": 0}


@pytest.mark.asyncio
async def test_cf_login_redirects(async_client_factory) -> None:
    """GET /auth/cf/login issues a 302 redirect to the Cloudflare authorize endpoint."""
    app = _build_app()
    async with async_client_factory(app) as client:
        response = await client.get("/api/v1/auth/cf/login", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].startswith(get_settings().cf_oauth_issuer)


# ---------------------------------------------------------------------------
# Unauthorized 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/upstream-credentials"),
        ("GET", "/api/v1/scoped-tokens"),
        ("GET", "/api/v1/audit-logs"),
    ],
)
async def test_protected_endpoints_reject_missing_token(
    async_client_factory, method: str, path: str
) -> None:
    """Every protected endpoint rejects a request with no Authorization header."""
    app = _build_app()
    async with async_client_factory(app) as client:
        response = await client.request(method, path)

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Cross-user IDOR
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_user_idor_returns_404(async_client_factory) -> None:
    """User B cannot read, verify, rotate, or delete user A's owned resources."""
    app = _build_app()
    async with async_client_factory(app) as client:
        jwt_a = await _register_and_login(client, f"{uuid4().hex}@example.com")
        jwt_b = await _register_and_login(client, f"{uuid4().hex}@example.com")
        headers_a = _auth_headers(jwt_a)
        headers_b = _auth_headers(jwt_b)

        cred_resp = await client.post(
            "/api/v1/upstream-credentials",
            headers=headers_a,
            json={"label": "prod", "cred_type": "token", "api_token": "cf-plain-token-abc"},
        )
        credential_id = cred_resp.json()["data"]["id"]

        mint_resp = await client.post(
            "/api/v1/scoped-tokens",
            headers=headers_a,
            json={
                "name": "staging-dns",
                "upstream_credential_id": credential_id,
                "scope_rules": [_record_ids_rule()],
            },
        )
        token_id = mint_resp.json()["data"]["id"]

        # User B cannot see user A's credential or token in their own listing.
        list_cred_b = await client.get("/api/v1/upstream-credentials", headers=headers_b)
        assert list_cred_b.json()["data"] == []
        list_tokens_b = await client.get("/api/v1/scoped-tokens", headers=headers_b)
        assert list_tokens_b.json()["data"] == []

        # User B cannot verify, list zones for, or delete user A's credential.
        verify_b = await client.post(
            f"/api/v1/upstream-credentials/{credential_id}/verify", headers=headers_b
        )
        assert verify_b.status_code == 404

        zones_b = await client.get(
            f"/api/v1/upstream-credentials/{credential_id}/zones", headers=headers_b
        )
        assert zones_b.status_code == 404

        delete_cred_b = await client.delete(
            f"/api/v1/upstream-credentials/{credential_id}", headers=headers_b
        )
        assert delete_cred_b.status_code == 404

        # User B cannot read, rotate, or revoke user A's scoped token.
        detail_b = await client.get(f"/api/v1/scoped-tokens/{token_id}", headers=headers_b)
        assert detail_b.status_code == 404

        rotate_b = await client.post(
            f"/api/v1/scoped-tokens/{token_id}/rotate", headers=headers_b
        )
        assert rotate_b.status_code == 404

        revoke_b = await client.delete(f"/api/v1/scoped-tokens/{token_id}", headers=headers_b)
        assert revoke_b.status_code == 404

        # User A's resources are unaffected and still fully usable.
        detail_a = await client.get(f"/api/v1/scoped-tokens/{token_id}", headers=headers_a)
        assert detail_a.status_code == 200
        assert detail_a.json()["data"]["status"] == "active"
