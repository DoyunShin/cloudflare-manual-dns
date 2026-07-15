"""respx-mocked tests for the Cloudflare upstream HTTP client."""

import json
import sys
import types
from datetime import UTC, datetime, timedelta

import pytest
from httpx import Response

from cfproxy.cache.redis import cache_get_json, cache_set_json, oauth_at_key
from cfproxy.config import get_settings
from cfproxy.core.crypto import decrypt_secret, encrypt_secret
from cfproxy.db.models import UpstreamCredential, User
from cfproxy.upstream.client import (
    fetch_cf_record,
    forward_request,
    get_valid_access_token,
    list_all_records,
    resolve_upstream_auth,
    verify_upstream,
)

BASE_URL = get_settings().upstream_base_url


# ---------------------------------------------------------------------------
# fetch_cf_record
# ---------------------------------------------------------------------------


async def test_fetch_cf_record_200(respx_mock) -> None:
    """A 200 response returns the record's `result` payload."""
    payload = {
        "id": "rec1",
        "zone_id": "zone1",
        "type": "A",
        "name": "home.example.com",
        "content": "1.2.3.4",
    }
    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records/rec1").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": payload}
        )
    )
    record = await fetch_cf_record("zone1", "rec1", {"Authorization": "Bearer upstream-token"})
    assert record == payload


async def test_fetch_cf_record_404(respx_mock) -> None:
    """A 404 response returns None instead of raising or forwarding the error body."""
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
    record = await fetch_cf_record("zone1", "missing", {"Authorization": "Bearer upstream-token"})
    assert record is None


# ---------------------------------------------------------------------------
# list_all_records
# ---------------------------------------------------------------------------


async def test_list_all_records_multi_page(respx_mock) -> None:
    """list_all_records loops through every upstream page and concatenates results."""
    page1 = [{"id": "rec1", "name": "a.example.com", "type": "A"}]
    page2 = [{"id": "rec2", "name": "b.example.com", "type": "A"}]

    def responder(request):
        page = int(request.url.params.get("page", "1"))
        result = page1 if page == 1 else page2
        return Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": result,
                "result_info": {
                    "page": page,
                    "per_page": 1,
                    "count": len(result),
                    "total_count": 2,
                    "total_pages": 2,
                },
            },
        )

    respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(side_effect=responder)

    records = await list_all_records(
        "zone1", {"per_page": 1}, {"Authorization": "Bearer upstream-token"}
    )
    assert records == page1 + page2


async def test_list_all_records_single_page(respx_mock) -> None:
    """A single-page result does not request a second page."""
    only_page = [{"id": "rec1", "name": "a.example.com", "type": "A"}]
    route = respx_mock.get(f"{BASE_URL}/client/v4/zones/zone1/dns_records").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "errors": [],
                "messages": [],
                "result": only_page,
                "result_info": {
                    "page": 1,
                    "per_page": 100,
                    "count": 1,
                    "total_count": 1,
                    "total_pages": 1,
                },
            },
        )
    )
    records = await list_all_records("zone1", None, {"Authorization": "Bearer upstream-token"})
    assert records == only_page
    assert route.call_count == 1


# ---------------------------------------------------------------------------
# verify_upstream
# ---------------------------------------------------------------------------


async def test_verify_upstream(respx_mock) -> None:
    """verify_upstream returns the parsed Cloudflare verify envelope."""
    envelope = {
        "success": True,
        "errors": [],
        "messages": [{"code": 10000, "message": "This API Token is valid."}],
        "result": {"id": "tok1", "status": "active"},
    }
    respx_mock.get(f"{BASE_URL}/client/v4/user/tokens/verify").mock(
        return_value=Response(200, json=envelope)
    )
    result = await verify_upstream({"Authorization": "Bearer upstream-token"})
    assert result == envelope


# ---------------------------------------------------------------------------
# forward_request
# ---------------------------------------------------------------------------


async def test_forward_request_injects_authorization(respx_mock) -> None:
    """forward_request injects auth_headers and strips any client-supplied Authorization."""
    route = respx_mock.get(f"{BASE_URL}/client/v4/zones").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": []}
        )
    )
    response = await forward_request(
        "GET",
        "/client/v4/zones",
        headers={"Authorization": "Bearer client-supplied", "X-Custom": "keep-me"},
        params=None,
        content=None,
        auth_headers={"Authorization": "Bearer upstream-token"},
    )
    assert response.status_code == 200
    sent_request = route.calls.last.request
    assert sent_request.headers["Authorization"] == "Bearer upstream-token"
    assert sent_request.headers["X-Custom"] == "keep-me"


async def test_forward_request_strips_global_key_headers(respx_mock) -> None:
    """forward_request strips a client-supplied X-Auth-Email/X-Auth-Key pair before injecting."""
    route = respx_mock.get(f"{BASE_URL}/client/v4/zones").mock(
        return_value=Response(
            200, json={"success": True, "errors": [], "messages": [], "result": []}
        )
    )
    response = await forward_request(
        "GET",
        "/client/v4/zones",
        headers={
            "Authorization": "Bearer client-supplied",
            "X-Auth-Email": "attacker@example.com",
            "X-Auth-Key": "attacker-key",
            "X-Custom": "keep-me",
        },
        params=None,
        content=None,
        auth_headers={"X-Auth-Email": "real@example.com", "X-Auth-Key": "real-key"},
    )
    assert response.status_code == 200
    sent_request = route.calls.last.request
    assert "Authorization" not in sent_request.headers
    assert sent_request.headers["X-Auth-Email"] == "real@example.com"
    assert sent_request.headers["X-Auth-Key"] == "real-key"
    assert sent_request.headers["X-Custom"] == "keep-me"


# ---------------------------------------------------------------------------
# resolve_upstream_auth
# ---------------------------------------------------------------------------


async def test_resolve_upstream_auth_token_credential(db_session) -> None:
    """A cred_type='token' credential resolves to an Authorization Bearer header."""
    user = User(email="resolve-token@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="prod",
        cred_type="token",
        secret_enc=encrypt_secret("cf-plain-token"),
    )
    db_session.add(credential)
    await db_session.commit()

    headers = await resolve_upstream_auth(db_session, credential)
    assert headers == {"Authorization": "Bearer cf-plain-token"}


async def test_resolve_upstream_auth_global_key_credential(db_session) -> None:
    """A cred_type='global_key' credential resolves to X-Auth-Email/X-Auth-Key, not Bearer."""
    user = User(email="resolve-global-key@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="legacy",
        cred_type="global_key",
        secret_enc=encrypt_secret(json.dumps({"email": "owner@example.com", "key": "the-global-key"})),
    )
    db_session.add(credential)
    await db_session.commit()

    headers = await resolve_upstream_auth(db_session, credential)
    assert headers == {"X-Auth-Email": "owner@example.com", "X-Auth-Key": "the-global-key"}
    assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# origin pinning (SSRF / credential-exfiltration guard)
# ---------------------------------------------------------------------------


def test_get_cf_client_raises_on_non_cloudflare_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_cf_client refuses to build a client pointed anywhere but the Cloudflare API."""
    import cfproxy.upstream.client as client_module

    settings = get_settings()
    evil_settings = settings.model_copy(update={"upstream_base_url": "https://evil.example.com"})
    monkeypatch.setattr(client_module, "get_settings", lambda: evil_settings)

    previous_client = client_module._cf_client
    client_module._cf_client = None
    try:
        with pytest.raises(RuntimeError):
            client_module.get_cf_client()
    finally:
        client_module._cf_client = previous_client


# ---------------------------------------------------------------------------
# get_valid_access_token
# ---------------------------------------------------------------------------


async def test_get_valid_access_token_token_credential(db_session) -> None:
    """A cred_type='token' credential returns its decrypted secret directly."""
    user = User(email="tok@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="prod",
        cred_type="token",
        secret_enc=encrypt_secret("cf-plain-token"),
    )
    db_session.add(credential)
    await db_session.commit()

    token = await get_valid_access_token(db_session, credential)
    assert token == "cf-plain-token"


async def test_get_valid_access_token_oauth_cache_hit(db_session) -> None:
    """An OAuth credential with a valid cached access token skips the DB refresh path."""
    user = User(email="oauth-cache@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="oauth",
        cred_type="oauth",
        access_token_enc=encrypt_secret("stale-would-not-be-used"),
        refresh_token_enc=encrypt_secret("refresh-token"),
        token_expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    db_session.add(credential)
    await db_session.commit()

    await cache_set_json(oauth_at_key(credential.id), encrypt_secret("cached-access-token"), 300)

    token = await get_valid_access_token(db_session, credential)
    assert token == "cached-access-token"


async def test_get_valid_access_token_oauth_still_valid_skips_refresh(db_session) -> None:
    """An OAuth credential whose stored token has not yet expired is reused without refreshing."""
    user = User(email="oauth-valid@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="oauth",
        cred_type="oauth",
        access_token_enc=encrypt_secret("still-good"),
        refresh_token_enc=encrypt_secret("refresh-token"),
        token_expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(credential)
    await db_session.commit()

    token = await get_valid_access_token(db_session, credential)
    assert token == "still-good"


async def test_get_valid_access_token_oauth_refreshes_when_expired(db_session, monkeypatch) -> None:
    """An expired OAuth credential is refreshed, persisted (with cred_version bump), and cached."""
    user = User(email="oauth-refresh@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="oauth",
        cred_type="oauth",
        access_token_enc=encrypt_secret("old-access-token"),
        refresh_token_enc=encrypt_secret("old-refresh-token"),
        token_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        cred_version=1,
    )
    db_session.add(credential)
    await db_session.commit()

    fake_module = types.ModuleType("cfproxy.auth.oauth_cf")

    async def fake_refresh_access_token(refresh_token: str) -> dict:
        assert refresh_token == "old-refresh-token"
        return {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
        }

    fake_module.refresh_access_token = fake_refresh_access_token
    monkeypatch.setitem(sys.modules, "cfproxy.auth.oauth_cf", fake_module)

    token = await get_valid_access_token(db_session, credential)
    assert token == "new-access-token"

    await db_session.refresh(credential)
    assert decrypt_secret(credential.access_token_enc) == "new-access-token"
    assert decrypt_secret(credential.refresh_token_enc) == "new-refresh-token"
    assert credential.cred_version == 2

    cached = await cache_get_json(oauth_at_key(credential.id))
    assert decrypt_secret(cached) == "new-access-token"


async def test_get_valid_access_token_oauth_refresh_reuses_refresh_token_if_not_rotated(
    db_session, monkeypatch
) -> None:
    """If the refresh grant does not return a new refresh_token, the old one is kept."""
    user = User(email="oauth-norotate@example.com")
    db_session.add(user)
    await db_session.flush()
    credential = UpstreamCredential(
        user_id=user.id,
        label="oauth",
        cred_type="oauth",
        access_token_enc=encrypt_secret("old-access-token"),
        refresh_token_enc=encrypt_secret("stable-refresh-token"),
        token_expires_at=datetime.now(UTC) - timedelta(seconds=1),
        cred_version=1,
    )
    db_session.add(credential)
    await db_session.commit()

    fake_module = types.ModuleType("cfproxy.auth.oauth_cf")

    async def fake_refresh_access_token(refresh_token: str) -> dict:
        return {"access_token": "new-access-token", "expires_in": 3600}

    fake_module.refresh_access_token = fake_refresh_access_token
    monkeypatch.setitem(sys.modules, "cfproxy.auth.oauth_cf", fake_module)

    token = await get_valid_access_token(db_session, credential)
    assert token == "new-access-token"

    await db_session.refresh(credential)
    assert decrypt_secret(credential.refresh_token_enc) == "stable-refresh-token"
