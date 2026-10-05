"""Generic OpenID Connect authorization-code client helpers."""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import secrets
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx
import jwt


ALLOWED_SIGNING_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_BLOCKED_METADATA_ADDRESSES = frozenset(
    {ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("169.254.169.254")}
)
_HTTP_TIMEOUT_SECONDS = 10.0


class OIDCError(Exception):
    """Base class for safe OIDC failures."""


class OIDCConfigurationError(OIDCError):
    """Raised when provider configuration is invalid or unsafe."""


class OIDCProviderError(OIDCError):
    """Raised when the provider returns an invalid or unsuccessful response."""


class OIDCTokenError(OIDCError):
    """Raised when an ID token or UserInfo document fails validation."""


@dataclass(frozen=True)
class OIDCClientConfig:
    """Decrypted OIDC client settings used for one authorization flow."""

    issuer: str
    client_id: str
    client_secret: str
    scopes: str
    redirect_uri: str
    allowed_endpoint_origins: tuple[str, ...] = ()
    allow_private_network: bool = False


def make_pkce() -> tuple[str, str]:
    """Generate a PKCE verifier and its S256 challenge.

    Returns:
        The verifier and matching base64url-encoded challenge.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def normalize_issuer(issuer: str) -> str:
    """Validate and normalize an HTTPS issuer URL.

    Args:
        issuer: Provider issuer identifier.

    Returns:
        The whitespace-trimmed issuer without changing its identity path.
    """
    normalized = issuer.strip()
    parts = urlsplit(normalized)
    if parts.scheme != "https" or not parts.hostname:
        raise OIDCConfigurationError("OIDC issuer must be an absolute HTTPS URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise OIDCConfigurationError("OIDC issuer must not contain credentials, query, or fragment")
    if len(normalized) > 512:
        raise OIDCConfigurationError("OIDC issuer must not exceed 512 characters")
    return normalized


def endpoint_origin(url: str) -> str:
    """Return the normalized origin for an absolute HTTPS URL.

    Args:
        url: Provider endpoint URL.

    Returns:
        The endpoint's normalized HTTPS origin.
    """
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise OIDCConfigurationError("OIDC endpoints must use HTTPS")
    if parts.username or parts.password or parts.fragment:
        raise OIDCConfigurationError("OIDC endpoints must not contain credentials or fragments")
    port = parts.port
    default_port = port is None or port == 443
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}" if default_port else f"https://{host}:{port}"


def discovery_url(issuer: str) -> str:
    """Build the OpenID Provider Configuration endpoint URL.

    Args:
        issuer: Valid provider issuer identifier.

    Returns:
        The discovery document URL for the issuer.
    """
    return f"{normalize_issuer(issuer).rstrip('/')}/.well-known/openid-configuration"


def _is_blocked_address(address: str, allow_private_network: bool) -> bool:
    """Return whether an endpoint address violates the network policy."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in _BLOCKED_METADATA_ADDRESSES:
        return True
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return True
    if not allow_private_network and (
        not ip.is_global or getattr(ip, "is_site_local", False)
    ):
        return True
    return False


async def validate_endpoint_url(url: str, allowed_origins: set[str], allow_private_network: bool) -> None:
    """Validate an OIDC endpoint origin and its currently resolved addresses.

    Args:
        url: Provider endpoint URL to validate.
        allowed_origins: Normalized origins trusted for this provider.
        allow_private_network: Whether private network destinations are allowed.

    Returns:
        None.
    """
    origin = endpoint_origin(url)
    if origin not in allowed_origins:
        raise OIDCConfigurationError(f"OIDC endpoint origin is not allowed: {origin}")

    host = urlsplit(url).hostname
    if host is None:
        raise OIDCConfigurationError("OIDC endpoint has no hostname")
    try:
        literal = ipaddress.ip_address(host)
        addresses = {str(literal)}
    except ValueError:
        try:
            entries = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OIDCConfigurationError("OIDC endpoint hostname could not be resolved") from exc
        addresses = {entry[4][0] for entry in entries}
    if not addresses or any(_is_blocked_address(address, allow_private_network) for address in addresses):
        raise OIDCConfigurationError("OIDC endpoint resolves to a disallowed network address")


def allowed_origins(config: OIDCClientConfig) -> set[str]:
    """Return the normalized endpoint origin allowlist for a client.

    Args:
        config: OIDC client and endpoint policy settings.

    Returns:
        The issuer origin plus explicitly trusted endpoint origins.
    """
    origins = {endpoint_origin(config.issuer)}
    for origin in config.allowed_endpoint_origins:
        normalized = endpoint_origin(origin)
        if urlsplit(origin).path not in ("", "/") or urlsplit(origin).query:
            raise OIDCConfigurationError("Allowed endpoint origins must be origins, not URLs with paths")
        origins.add(normalized)
    return origins


async def _get_json(url: str, config: OIDCClientConfig, *, bearer_token: str | None = None) -> dict[str, Any]:
    """Fetch a JSON object from an allowlisted provider endpoint."""
    await validate_endpoint_url(url, allowed_origins(config), config.allow_private_network)
    headers = {"Accept": "application/json"}
    if bearer_token is not None:
        headers["Authorization"] = f"Bearer {bearer_token}"
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=_HTTP_TIMEOUT_SECONDS, trust_env=False
        ) as client:
            response = await client.get(url, headers=headers)
        response.raise_for_status()
        value = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCProviderError("OIDC provider request failed") from exc
    if not isinstance(value, dict):
        raise OIDCProviderError("OIDC provider returned a non-object JSON response")
    return value


async def fetch_discovery(config: OIDCClientConfig) -> dict[str, Any]:
    """Fetch and validate OpenID Provider Configuration metadata.

    Args:
        config: OIDC client and endpoint policy settings.

    Returns:
        Validated provider discovery metadata.
    """
    normalized_issuer = normalize_issuer(config.issuer)
    metadata = await _get_json(discovery_url(normalized_issuer), config)
    if metadata.get("issuer") != normalized_issuer:
        raise OIDCConfigurationError("OIDC discovery issuer does not match configured issuer")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value:
            raise OIDCConfigurationError(f"OIDC discovery is missing {field}")
        await validate_endpoint_url(value, allowed_origins(config), config.allow_private_network)
    userinfo_endpoint = metadata.get("userinfo_endpoint")
    if userinfo_endpoint is not None:
        if not isinstance(userinfo_endpoint, str) or not userinfo_endpoint:
            raise OIDCConfigurationError("OIDC userinfo_endpoint is malformed")
        await validate_endpoint_url(
            userinfo_endpoint, allowed_origins(config), config.allow_private_network
        )
    supported = metadata.get("id_token_signing_alg_values_supported")
    if not isinstance(supported, list) or not ALLOWED_SIGNING_ALGORITHMS.intersection(supported):
        raise OIDCConfigurationError("OIDC provider has no supported ID token signing algorithm")
    return metadata


async def fetch_jwks(metadata: dict[str, Any], config: OIDCClientConfig) -> dict[str, Any]:
    """Fetch and validate the provider JSON Web Key Set.

    Args:
        metadata: Validated provider discovery metadata.
        config: OIDC client and endpoint policy settings.

    Returns:
        A JSON Web Key Set containing a keys list.
    """
    jwks = await _get_json(str(metadata["jwks_uri"]), config)
    if not isinstance(jwks.get("keys"), list):
        raise OIDCProviderError("OIDC JWKS response is missing keys")
    return jwks


def build_authorization_url(metadata: dict[str, Any], config: OIDCClientConfig, state: str, nonce: str, code_challenge: str) -> str:
    """Build an OIDC authorization URL for a code and PKCE flow.

    Args:
        metadata: Validated provider discovery metadata.
        config: OIDC client settings.
        state: Single-use request state.
        nonce: ID token replay-protection nonce.
        code_challenge: PKCE S256 challenge.

    Returns:
        The provider authorization URL.
    """
    endpoint = str(metadata["authorization_endpoint"])
    parts = urlsplit(endpoint)
    query = urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": config.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    if parts.query:
        query = f"{parts.query}&{query}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _token_auth_method(metadata: dict[str, Any]) -> str:
    """Select a supported confidential-client authentication method."""
    methods = metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
    if "client_secret_basic" in methods:
        return "client_secret_basic"
    if "client_secret_post" in methods:
        return "client_secret_post"
    raise OIDCConfigurationError("OIDC token endpoint does not support a configured client secret")


async def exchange_code(metadata: dict[str, Any], config: OIDCClientConfig, code: str, verifier: str) -> dict[str, Any]:
    """Exchange an authorization code for OIDC tokens.

    Args:
        metadata: Validated provider discovery metadata.
        config: OIDC client settings.
        code: Authorization code returned by the provider.
        verifier: PKCE verifier associated with the authorization request.

    Returns:
        The provider token response object.
    """
    endpoint = str(metadata["token_endpoint"])
    await validate_endpoint_url(endpoint, allowed_origins(config), config.allow_private_network)
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.redirect_uri,
        "client_id": config.client_id,
        "code_verifier": verifier,
    }
    headers = {"Accept": "application/json"}
    method = _token_auth_method(metadata)
    if method == "client_secret_basic":
        encoded_id = quote(config.client_id, safe="")
        encoded_secret = quote(config.client_secret, safe="")
        encoded_credentials = base64.b64encode(
            f"{encoded_id}:{encoded_secret}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_credentials}"
    else:
        data["client_secret"] = config.client_secret
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=_HTTP_TIMEOUT_SECONDS, trust_env=False
        ) as client:
            response = await client.post(endpoint, data=data, headers=headers)
        response.raise_for_status()
        tokens = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OIDCProviderError("OIDC token exchange failed") from exc
    if not isinstance(tokens, dict):
        raise OIDCProviderError("OIDC token endpoint returned a non-object JSON response")
    return tokens


def _eligible_jwk(jwk: dict[str, Any], kid: str | None, algorithm: str) -> bool:
    """Return whether a JWK is suitable for the requested signature."""
    expected_kty = "EC" if algorithm.startswith("ES") else "RSA"
    return (
        jwk.get("kty") == expected_kty
        and jwk.get("use", "sig") == "sig"
        and jwk.get("alg", algorithm) == algorithm
        and (kid is None or jwk.get("kid") == kid)
    )


def _resolve_signing_key(jwks: dict[str, Any], kid: str | None, algorithm: str) -> Any:
    """Resolve exactly one compatible signing key from a JWKS document."""
    matches = [
        key
        for key in jwks.get("keys", [])
        if isinstance(key, dict) and _eligible_jwk(key, kid, algorithm)
    ]
    if len(matches) != 1:
        raise OIDCTokenError("ID token signing key could not be resolved uniquely")
    try:
        return jwt.PyJWK.from_dict(matches[0], algorithm=algorithm).key
    except (jwt.PyJWTError, ValueError) as exc:
        raise OIDCTokenError("ID token signing key is invalid") from exc


def _compute_oidc_hash(value: str, algorithm: str) -> str:
    """Compute the OIDC left-half hash for supported SHA-256 algorithms."""
    if algorithm not in ALLOWED_SIGNING_ALGORITHMS:
        raise OIDCTokenError("ID token uses an unsupported hash algorithm")
    try:
        encoded_value = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise OIDCTokenError("OIDC hash source must contain only ASCII characters") from exc
    digest = hashlib.sha256(encoded_value).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode("ascii")


def _safe_text_equal(left: Any, right: str) -> bool:
    """Compare text values without raising on malformed Unicode or non-strings."""
    if not isinstance(left, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeEncodeError:
        return False


def validate_id_token(id_token: str, metadata: dict[str, Any], jwks: dict[str, Any], config: OIDCClientConfig, nonce: str, *, access_token: str | None = None, code: str | None = None) -> dict[str, Any]:
    """Validate an OIDC ID token and return its claims.

    Args:
        id_token: Encoded provider ID token.
        metadata: Validated provider discovery metadata.
        jwks: Provider signing keys.
        config: OIDC client settings.
        nonce: Nonce stored for the authorization request.
        access_token: Access token used to verify at_hash when present.
        code: Authorization code used to verify c_hash when present.

    Returns:
        Verified ID token claims.
    """
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OIDCTokenError("ID token header is invalid") from exc
    algorithm = header.get("alg")
    supported = {
        value
        for value in metadata.get("id_token_signing_alg_values_supported", [])
        if isinstance(value, str)
    }
    if not isinstance(algorithm, str):
        raise OIDCTokenError("ID token uses an unsupported signing algorithm")
    if algorithm not in ALLOWED_SIGNING_ALGORITHMS or algorithm not in supported:
        raise OIDCTokenError("ID token uses an unsupported signing algorithm")
    key = _resolve_signing_key(jwks, header.get("kid"), algorithm)
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=normalize_issuer(config.issuer),
            leeway=60,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise OIDCTokenError("ID token validation failed") from exc
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise OIDCTokenError("ID token subject is invalid")
    if not _safe_text_equal(claims.get("nonce"), nonce):
        raise OIDCTokenError("ID token nonce mismatch")
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != config.client_id:
        raise OIDCTokenError("ID token authorized party mismatch")
    if claims.get("azp") is not None and claims.get("azp") != config.client_id:
        raise OIDCTokenError("ID token authorized party mismatch")
    for claim_name, source in (("at_hash", access_token), ("c_hash", code)):
        claim_value = claims.get(claim_name)
        if claim_value is None:
            continue
        if not isinstance(claim_value, str) or not isinstance(source, str):
            raise OIDCTokenError(f"ID token {claim_name} cannot be verified")
        if not _safe_text_equal(claim_value, _compute_oidc_hash(source, algorithm)):
            raise OIDCTokenError(f"ID token {claim_name} mismatch")
    return claims


async def fetch_userinfo(metadata: dict[str, Any], config: OIDCClientConfig, access_token: str, expected_sub: str) -> dict[str, Any]:
    """Fetch UserInfo and require it to describe the ID token subject.

    Args:
        metadata: Validated provider discovery metadata.
        config: OIDC client and endpoint policy settings.
        access_token: Provider access token for UserInfo.
        expected_sub: Subject verified in the ID token.

    Returns:
        Validated UserInfo claims.
    """
    endpoint = metadata.get("userinfo_endpoint")
    if endpoint is None:
        raise OIDCConfigurationError("OIDC provider has no UserInfo endpoint")
    claims = await _get_json(str(endpoint), config, bearer_token=access_token)
    sub = claims.get("sub")
    if not _safe_text_equal(sub, expected_sub):
        raise OIDCTokenError("OIDC UserInfo subject mismatch")
    return claims
