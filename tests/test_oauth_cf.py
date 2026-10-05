"""Tests for Cloudflare OAuth credential-connection helpers."""

from urllib.parse import parse_qs, urlsplit

import httpx
import respx

from cfproxy.auth import oauth_cf
from cfproxy.config import get_settings


def _settings(monkeypatch):
    """Install deterministic Cloudflare OAuth settings for one test."""
    settings = get_settings().model_copy(
        update={
            "app_base_url": "https://app.example.com",
            "cf_oauth_client_id": "client-id",
            "cf_oauth_client_secret": "client-secret",
            "cf_oauth_issuer": "https://dash.cloudflare.com",
            "cf_oauth_base_scopes": "openid offline_access",
            "cf_oauth_dns_scope": "dns.write",
            "upstream_base_url": "https://api.cloudflare.com",
        }
    )
    monkeypatch.setattr(oauth_cf, "get_settings", lambda: settings)
    return settings


def test_authorize_url_is_code_pkce_credential_consent(monkeypatch) -> None:
    """Authorization requests use the fixed credential callback and PKCE."""
    settings = _settings(monkeypatch)
    url = oauth_cf.build_authorize_url("state-value", "challenge-value")
    parts = urlsplit(url)
    params = parse_qs(parts.query)

    assert f"{parts.scheme}://{parts.netloc}" == settings.cf_oauth_issuer
    assert params["response_type"] == ["code"]
    assert params["redirect_uri"] == [
        "https://app.example.com/api/v1/upstream-credentials/cf/callback"
    ]
    assert params["state"] == ["state-value"]
    assert params["code_challenge"] == ["challenge-value"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["scope"] == ["openid offline_access dns.write"]
    assert "nonce" not in params


async def test_exchange_code_uses_trusted_redirect_and_client_secret(monkeypatch) -> None:
    """The code exchange submits the trusted callback and confidential-client secret."""
    _settings(monkeypatch)
    tokens = {"access_token": "access", "refresh_token": "refresh", "expires_in": 3600}
    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        route = mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=tokens))
        result = await oauth_cf.exchange_code("code-value", "verifier-value")

    assert result == tokens
    body = route.calls.last.request.content.decode()
    assert "code=code-value" in body
    assert "code_verifier=verifier-value" in body
    assert "client_secret=client-secret" in body
    assert "redirect_uri=https%3A%2F%2Fapp.example.com%2Fapi%2Fv1%2Fupstream-credentials%2Fcf%2Fcallback" in body


async def test_refresh_access_token_keeps_refresh_grant(monkeypatch) -> None:
    """Stored refresh tokens can obtain a rotated delegated access token."""
    _settings(monkeypatch)
    tokens = {"access_token": "new-access", "refresh_token": "new-refresh"}
    async with respx.mock(base_url="https://dash.cloudflare.com") as mock:
        route = mock.post("/oauth2/token").mock(return_value=httpx.Response(200, json=tokens))
        result = await oauth_cf.refresh_access_token("old-refresh")

    assert result == tokens
    assert "grant_type=refresh_token" in route.calls.last.request.content.decode()


async def test_discover_dns_scope_authenticates_and_returns_ids(monkeypatch) -> None:
    """Scope discovery sends a Bearer token and returns IDs instead of labels."""
    _settings(monkeypatch)
    body = {
        "result": [
            {"id": "scope-id-1", "name": "DNS Write"},
            {"id": "scope-id-2", "name": "Zone Read"},
        ]
    }
    async with respx.mock(base_url="https://api.cloudflare.com") as mock:
        route = mock.get("/client/v4/oauth/scopes").mock(
            return_value=httpx.Response(200, json=body)
        )
        scopes = await oauth_cf.discover_dns_scope("api-token")

    assert scopes == ["scope-id-1", "scope-id-2"]
    assert route.calls.last.request.headers["authorization"] == "Bearer api-token"
