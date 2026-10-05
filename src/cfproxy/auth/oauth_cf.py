"""Cloudflare OAuth helpers for attaching a delegated upstream credential."""

from typing import Any
from urllib.parse import urlencode

import httpx

from cfproxy.auth.oidc import make_pkce
from cfproxy.config import get_settings


_HTTP_TIMEOUT_SECONDS = 10.0


def cf_redirect_uri() -> str:
    """Return the Cloudflare OAuth callback at the trusted application origin.

    Returns:
        Absolute callback URL for credential consent.
    """
    return f"{get_settings().app_base_url}/api/v1/upstream-credentials/cf/callback"


def build_authorize_url(state: str, code_challenge: str) -> str:
    """Build the Cloudflare OAuth authorization URL for credential consent.

    Args:
        state: Single-use state bound to the initiating service session.
        code_challenge: S256 challenge for the stored PKCE verifier.

    Returns:
        Provider authorization URL.
    """
    settings = get_settings()
    scopes = settings.cf_oauth_base_scopes
    if settings.cf_oauth_dns_scope:
        scopes = f"{scopes} {settings.cf_oauth_dns_scope}"
    params = {
        "response_type": "code",
        "client_id": settings.cf_oauth_client_id,
        "redirect_uri": cf_redirect_uri(),
        "scope": scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{settings.cf_oauth_issuer.rstrip('/')}/oauth2/auth?{urlencode(params)}"


async def exchange_code(code: str, code_verifier: str) -> dict[str, Any]:
    """Exchange a Cloudflare authorization code for delegated tokens.

    Args:
        code: Provider-issued authorization code.
        code_verifier: PKCE verifier stored for the initiating session.

    Returns:
        Delegated token response from Cloudflare.
    """
    settings = get_settings()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cf_redirect_uri(),
        "client_id": settings.cf_oauth_client_id,
        "client_secret": settings.cf_oauth_client_secret,
        "code_verifier": code_verifier,
    }
    async with httpx.AsyncClient(follow_redirects=False, timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{settings.cf_oauth_issuer.rstrip('/')}/oauth2/token", data=data
        )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError("Cloudflare token endpoint returned a non-object JSON response")
    return value


async def refresh_access_token(refresh_token: str) -> dict[str, Any]:
    """Refresh a stored Cloudflare OAuth access token.

    Args:
        refresh_token: Decrypted delegated Cloudflare refresh token.

    Returns:
        Token response containing the refreshed grant.
    """
    settings = get_settings()
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.cf_oauth_client_id,
        "client_secret": settings.cf_oauth_client_secret,
    }
    async with httpx.AsyncClient(follow_redirects=False, timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{settings.cf_oauth_issuer.rstrip('/')}/oauth2/token", data=data
        )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError("Cloudflare token endpoint returned a non-object JSON response")
    return value


async def discover_dns_scope(api_token: str) -> list[str]:
    """Return Cloudflare OAuth scope IDs visible to an authenticated API token.

    Args:
        api_token: Cloudflare API token authorized to list OAuth scopes.

    Returns:
        Scope IDs returned by Cloudflare.
    """
    if not api_token:
        raise ValueError("Cloudflare API token is required to discover OAuth scopes")
    settings = get_settings()
    async with httpx.AsyncClient(follow_redirects=False, timeout=_HTTP_TIMEOUT_SECONDS) as client:
        response = await client.get(
            f"{settings.upstream_base_url}/client/v4/oauth/scopes",
            headers={"Authorization": f"Bearer {api_token}"},
        )
    response.raise_for_status()
    body = response.json()
    result = body.get("result", []) if isinstance(body, dict) else []
    return [str(item["id"]) for item in result if isinstance(item, dict) and item.get("id")]
