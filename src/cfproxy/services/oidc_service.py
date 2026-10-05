"""OIDC configuration, authorization flow, and local identity lifecycle."""

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.auth.oidc import (
    OIDCClientConfig,
    OIDCConfigurationError,
    OIDCError,
    OIDCProviderError,
    OIDCTokenError,
    build_authorization_url,
    endpoint_origin,
    exchange_code,
    fetch_discovery,
    fetch_jwks,
    fetch_userinfo,
    make_pkce,
    normalize_issuer,
    validate_id_token,
)
from cfproxy.cache.redis import get_redis
from cfproxy.config import get_settings
from cfproxy.core.crypto import decrypt_secret, encrypt_secret
from cfproxy.core.security import create_service_session
from cfproxy.db.locks import with_row_lock
from cfproxy.db.models import ManagementSession, OIDCConfig, User


OIDC_CONFIG_ID = 1
OIDC_BINDING_COOKIE = "__Host-cfproxy_oidc_binding"
_OIDC_STATE_PREFIX = "oidc_state:"
_DEFAULT_SCOPES = "openid profile email"


class OIDCNotConfiguredError(OIDCError):
    """Raised when login is attempted without an enabled provider."""


class OIDCStateError(OIDCError):
    """Raised when state is unavailable, expired, reused, or browser-mismatched."""


class OIDCUserDisabledError(OIDCError):
    """Raised when a valid external identity maps to a disabled local user."""


class OIDCAdminAuthorizationError(OIDCError):
    """Raised when the saving administrator lost local authorization."""


class OIDCAdminSessionError(OIDCError):
    """Raised when the saving administrator's session is no longer valid."""


@dataclass(frozen=True)
class OIDCConfigInput:
    """Validated administrator input for the singleton provider configuration."""

    label: str
    issuer: str
    client_id: str
    client_secret: str | None
    scopes: str = _DEFAULT_SCOPES
    enabled: bool = False
    allowed_endpoint_origins: tuple[str, ...] = ()
    allow_private_network: bool = False


@dataclass(frozen=True)
class OIDCLoginStart:
    """Authorization URL and browser-binding cookie for a new login attempt."""

    authorization_url: str
    browser_binding: str


def oidc_redirect_uri() -> str:
    """Return the callback URI derived from the trusted application origin.

    Returns:
        The fixed OIDC callback URI.
    """
    return f"{get_settings().app_base_url}/api/v1/auth/oidc/callback"


def _validate_config_input(value: OIDCConfigInput, *, has_existing_secret: bool) -> OIDCConfigInput:
    """Validate provider settings without contacting the provider."""
    label = value.label.strip()
    issuer = normalize_issuer(value.issuer)
    client_id = value.client_id.strip()
    scopes = " ".join(value.scopes.split())
    if not label or len(label) > 255:
        raise OIDCConfigurationError("OIDC label must contain 1 to 255 characters")
    if not client_id or len(client_id) > 1024:
        raise OIDCConfigurationError("OIDC client_id must contain 1 to 1024 characters")
    if "openid" not in scopes.split():
        raise OIDCConfigurationError("OIDC scopes must include openid")
    if value.client_secret == "":
        raise OIDCConfigurationError("OIDC client_secret must not be empty")
    if value.client_secret is not None and len(value.client_secret.encode("utf-8")) > 2048:
        raise OIDCConfigurationError("OIDC client_secret must not exceed 2048 UTF-8 bytes")
    if not value.client_secret and not has_existing_secret:
        raise OIDCConfigurationError("OIDC client_secret is required")
    origins: list[str] = []
    for origin in value.allowed_endpoint_origins:
        stripped = origin.strip().rstrip("/")
        endpoint_origin(stripped)
        parsed_origin = urlsplit(stripped)
        if parsed_origin.path or parsed_origin.query:
            raise OIDCConfigurationError("Allowed endpoint origins must not contain a path or query")
        if len(stripped) > 2048:
            raise OIDCConfigurationError("Allowed endpoint origins must not exceed 2048 characters")
        if stripped and stripped not in origins:
            origins.append(stripped)
    return OIDCConfigInput(
        label=label,
        issuer=issuer,
        client_id=client_id,
        client_secret=value.client_secret,
        scopes=scopes,
        enabled=value.enabled,
        allowed_endpoint_origins=tuple(origins),
        allow_private_network=value.allow_private_network,
    )


def config_response(config: OIDCConfig | None) -> dict[str, Any]:
    """Serialize provider settings without exposing the client secret.

    Args:
        config: Stored provider configuration, if initialized.

    Returns:
        Non-secret administrator configuration fields.
    """
    if config is None:
        return {
            "enabled": False,
            "label": "OIDC",
            "issuer": "",
            "client_id": "",
            "scopes": _DEFAULT_SCOPES,
            "has_secret": False,
            "allowed_endpoint_origins": [],
            "allow_private_network": False,
        }
    return {
        "enabled": config.enabled,
        "label": config.label,
        "issuer": config.issuer,
        "client_id": config.client_id,
        "scopes": config.scopes,
        "has_secret": bool(config.client_secret_enc),
        "allowed_endpoint_origins": list(config.allowed_endpoint_origins or []),
        "allow_private_network": config.allow_private_network,
    }


def public_config_response(config: OIDCConfig | None) -> dict[str, Any]:
    """Serialize only public provider availability information.

    Args:
        config: Stored provider configuration, if initialized.

    Returns:
        Public enabled state and provider label.
    """
    return {
        "enabled": bool(config and config.enabled),
        "label": config.label if config else "OIDC",
    }


async def get_oidc_config(session: AsyncSession) -> OIDCConfig | None:
    """Load the singleton OIDC provider configuration.

    Args:
        session: Active database session.

    Returns:
        The singleton configuration row, or None when absent.
    """
    return await session.get(OIDCConfig, OIDC_CONFIG_ID)


def _client_config(row: OIDCConfig, secret_override: str | None = None) -> OIDCClientConfig:
    """Build decrypted client settings from a stored provider row."""
    secret = secret_override or decrypt_secret(row.client_secret_enc)
    return OIDCClientConfig(
        issuer=row.issuer,
        client_id=row.client_id,
        client_secret=secret,
        scopes=row.scopes,
        redirect_uri=oidc_redirect_uri(),
        allowed_endpoint_origins=tuple(row.allowed_endpoint_origins or []),
        allow_private_network=row.allow_private_network,
    )


def _input_client_config(value: OIDCConfigInput, existing: OIDCConfig | None) -> OIDCClientConfig:
    """Build client settings for an unsaved administrator connection test."""
    secret = value.client_secret
    if secret is None and existing is not None:
        secret = decrypt_secret(existing.client_secret_enc)
    if secret is None:
        raise OIDCConfigurationError("OIDC client_secret is required")
    return OIDCClientConfig(
        issuer=value.issuer,
        client_id=value.client_id,
        client_secret=secret,
        scopes=value.scopes,
        redirect_uri=oidc_redirect_uri(),
        allowed_endpoint_origins=value.allowed_endpoint_origins,
        allow_private_network=value.allow_private_network,
    )


async def test_oidc_config(session: AsyncSession, value: OIDCConfigInput) -> dict[str, Any]:
    """Validate unsaved discovery and JWKS settings without testing the secret.

    Args:
        session: Active database session used to retain an omitted stored secret.
        value: Unsaved provider settings to test.

    Returns:
        Discovery issuer, supported algorithms, key count, and secret test status.
    """
    existing = await get_oidc_config(session)
    checked = _validate_config_input(
        value, has_existing_secret=bool(existing and existing.client_secret_enc)
    )
    client_config = _input_client_config(checked, existing)
    metadata = await fetch_discovery(client_config)
    jwks = await fetch_jwks(metadata, client_config)
    return {
        "issuer": metadata["issuer"],
        "signing_algorithms": sorted(
            {str(item) for item in metadata["id_token_signing_alg_values_supported"]}
        ),
        "signing_key_count": len(jwks["keys"]),
        "client_secret_verified": False,
    }


async def save_oidc_config(session: AsyncSession, value: OIDCConfigInput, actor_id: str | None = None, actor_session_id: str | None = None) -> OIDCConfig:
    """Atomically create or update the singleton provider configuration.

    Args:
        session: Active database session.
        value: Validated administrator configuration input.
        actor_id: Administrator user id to revalidate before an API mutation.
        actor_session_id: Administrator session id to revalidate before mutation.

    Returns:
        The persisted singleton configuration row.
    """
    statement = select(OIDCConfig).where(OIDCConfig.id == OIDC_CONFIG_ID).execution_options(
        populate_existing=True
    )
    result = await session.execute(with_row_lock(session, statement))
    config = result.scalar_one_or_none()
    if actor_id is not None:
        actor_result = await session.execute(
            with_row_lock(
                session,
                select(User)
                .where(User.id == actor_id)
                .execution_options(populate_existing=True),
            )
        )
        actor = actor_result.scalar_one_or_none()
        if actor is None or not actor.is_active or not actor.is_admin:
            raise OIDCAdminAuthorizationError("Administrator access required")
        if actor_session_id is None:
            raise OIDCAdminSessionError("Administrator session is no longer valid")
        management_result = await session.execute(
            with_row_lock(
                session,
                select(ManagementSession)
                .where(
                    ManagementSession.id == actor_session_id,
                    ManagementSession.user_id == actor_id,
                )
                .execution_options(populate_existing=True),
            )
        )
        management_session = management_result.scalar_one_or_none()
        now = datetime.now(UTC)
        if (
            management_session is None
            or management_session.revoked_at is not None
            or management_session.expires_at <= now
            or (
                management_session.auth_method == "oidc"
                and (
                    config is None
                    or not config.enabled
                    or management_session.provider_revision != config.revision
                )
            )
        ):
            raise OIDCAdminSessionError("Administrator session is no longer valid")
    checked = _validate_config_input(
        value, has_existing_secret=bool(config and config.client_secret_enc)
    )
    if config is None:
        if checked.client_secret is None:
            raise OIDCConfigurationError("OIDC client_secret is required")
        config = OIDCConfig(id=OIDC_CONFIG_ID, issuer=checked.issuer, client_id=checked.client_id)
        session.add(config)
    config.label = checked.label
    config.issuer = checked.issuer
    config.client_id = checked.client_id
    config.scopes = checked.scopes
    config.enabled = checked.enabled
    config.allowed_endpoint_origins = list(checked.allowed_endpoint_origins)
    config.allow_private_network = checked.allow_private_network
    if checked.client_secret is not None:
        config.client_secret_enc = encrypt_secret(checked.client_secret)
    if config.revision is None:
        config.revision = 1
    elif config not in session.new:
        config.revision += 1
    await session.commit()
    await session.refresh(config)
    return config


def _binding_hash(browser_binding: str) -> str:
    """Hash a browser-binding cookie before placing it in Redis."""
    return hashlib.sha256(browser_binding.encode("ascii")).hexdigest()


async def _store_state(state: str, payload: dict[str, Any]) -> None:
    """Persist security-critical state and fail closed if Redis is unavailable."""
    try:
        stored = await get_redis().set(
            f"{_OIDC_STATE_PREFIX}{state}",
            json.dumps(payload),
            ex=get_settings().oauth_state_ttl,
        )
    except Exception as exc:
        raise OIDCStateError("OIDC login state is unavailable") from exc
    if not stored:
        raise OIDCStateError("OIDC login state could not be stored")


async def _consume_state(state: str, browser_binding: str | None) -> dict[str, Any]:
    """Atomically consume state and verify the initiating browser binding."""
    if browser_binding is None:
        raise OIDCStateError("OIDC browser binding is missing")
    try:
        raw = await get_redis().getdel(f"{_OIDC_STATE_PREFIX}{state}")
    except Exception as exc:
        raise OIDCStateError("OIDC login state is unavailable") from exc
    if raw is None:
        raise OIDCStateError("OIDC login state is invalid or expired")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise OIDCStateError("OIDC login state is malformed") from exc
    expected = str(payload.get("browser_binding_hash", ""))
    if not hmac.compare_digest(expected, _binding_hash(browser_binding)):
        raise OIDCStateError("OIDC browser binding does not match")
    return payload


async def reject_oidc_login(state: str, browser_binding: str | None) -> None:
    """Consume and validate state for an authorization error callback.

    Args:
        state: State returned by the provider.
        browser_binding: Binding cookie from the initiating browser.

    Returns:
        None.
    """
    await _consume_state(state, browser_binding)


async def start_oidc_login(session: AsyncSession, browser_binding: str | None) -> OIDCLoginStart:
    """Create a browser-bound, single-use OIDC authorization request.

    Args:
        session: Active database session.
        browser_binding: Existing binding cookie, if present.

    Returns:
        Provider authorization URL and browser-binding value.
    """
    config = await get_oidc_config(session)
    if config is None or not config.enabled:
        raise OIDCNotConfiguredError("OIDC login is not enabled")
    client_config = _client_config(config)
    metadata = await fetch_discovery(client_config)
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    binding = browser_binding or secrets.token_urlsafe(32)
    await _store_state(
        state,
        {
            "verifier": verifier,
            "nonce": nonce,
            "browser_binding_hash": _binding_hash(binding),
            "provider_revision": config.revision,
        },
    )
    return OIDCLoginStart(
        authorization_url=build_authorization_url(metadata, client_config, state, nonce, challenge),
        browser_binding=binding,
    )


def _profile_value(claims: dict[str, Any], key: str, max_length: int) -> str | None:
    """Return a bounded string profile claim or None."""
    value = claims.get(key)
    if not isinstance(value, str) or not value:
        return None
    return value[:max_length]


async def _upsert_oidc_user(session: AsyncSession, issuer: str, claims: dict[str, Any]) -> User:
    """Create or update one local user by immutable issuer/subject identity."""
    subject = claims["sub"]
    if len(subject) > 255:
        raise OIDCTokenError("OIDC subject is too long")
    statement = (
        select(User)
        .where(User.oidc_issuer == issuer, User.oidc_sub == subject)
        .execution_options(populate_existing=True)
    )
    result = await session.execute(with_row_lock(session, statement))
    user = result.scalar_one_or_none()
    if user is None:
        try:
            async with session.begin_nested():
                user = User(
                    auth_provider="oidc",
                    oidc_issuer=issuer,
                    oidc_sub=subject,
                    email=_profile_value(claims, "email", 255),
                    display_name=_profile_value(claims, "name", 255),
                    is_admin=False,
                    is_active=True,
                )
                session.add(user)
                await session.flush()
        except IntegrityError:
            result = await session.execute(statement.execution_options(populate_existing=True))
            user = result.scalar_one()
    if not user.is_active:
        raise OIDCUserDisabledError("OIDC user is disabled")
    user.email = _profile_value(claims, "email", 255)
    user.display_name = _profile_value(claims, "name", 255)
    user.updated_at = datetime.now(UTC)
    return user


async def complete_oidc_login(session: AsyncSession, response: Response, code: str, state: str, browser_binding: str | None, request: Request | None = None) -> User:
    """Validate an OIDC callback, update the local profile, and issue a session.

    Args:
        session: Active database session.
        response: Response receiving the service-session cookie.
        code: Authorization code returned by the provider.
        state: Single-use state returned by the provider.
        browser_binding: Binding cookie from the initiating browser.
        request: Current request used to rotate an existing service session.

    Returns:
        The authenticated local service user.
    """
    stored = await _consume_state(state, browser_binding)
    initial = await get_oidc_config(session)
    if initial is None or not initial.enabled or initial.revision != stored.get("provider_revision"):
        raise OIDCStateError("OIDC configuration changed during login")
    client_config = _client_config(initial)
    metadata = await fetch_discovery(client_config)
    tokens = await exchange_code(metadata, client_config, code, stored["verifier"])
    id_token = tokens.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise OIDCProviderError("OIDC token response is missing id_token")
    jwks = await fetch_jwks(metadata, client_config)
    claims = validate_id_token(
        id_token,
        metadata,
        jwks,
        client_config,
        stored["nonce"],
        access_token=tokens.get("access_token"),
        code=code,
    )
    if metadata.get("userinfo_endpoint") is not None:
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise OIDCProviderError("OIDC token response is missing access_token for UserInfo")
        claims = {
            **claims,
            **await fetch_userinfo(metadata, client_config, access_token, claims["sub"]),
            "sub": claims["sub"],
        }

    statement = select(OIDCConfig).where(OIDCConfig.id == OIDC_CONFIG_ID).execution_options(
        populate_existing=True
    )
    result = await session.execute(with_row_lock(session, statement))
    current = result.scalar_one_or_none()
    if current is None or not current.enabled or current.revision != stored["provider_revision"]:
        raise OIDCStateError("OIDC configuration changed during login")
    user = await _upsert_oidc_user(session, current.issuer, claims)
    await create_service_session(
        response,
        user,
        session,
        auth_method="oidc",
        provider_revision=current.revision,
        request=request,
    )
    await session.commit()
    return user
