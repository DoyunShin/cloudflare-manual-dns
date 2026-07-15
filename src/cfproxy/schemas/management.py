"""Pydantic request/response models for the management (`/api/v1`) API."""

from datetime import datetime

from pydantic import BaseModel


class RegisterRequest(BaseModel):
    """Request body for local account registration.

    Args:
        email(str): The account's email address.
        password(str): The account's plaintext password.
    """

    email: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "operator@example.com", "password": "correct-horse-battery-staple"},
            ],
        },
    }


class LoginRequest(BaseModel):
    """Request body for local account login.

    Args:
        email(str): The account's email address.
        password(str): The account's plaintext password.
    """

    email: str
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "operator@example.com", "password": "correct-horse-battery-staple"},
            ],
        },
    }


class TokenResponse(BaseModel):
    """Response body containing an issued JWT session token.

    Args:
        access_token(str): The signed JWT.
        token_type(str): The token type, always "bearer".
    """

    access_token: str
    token_type: str = "bearer"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer",
                },
            ],
        },
    }


class UserResponse(BaseModel):
    """Response body describing a management-plane user.

    Args:
        id(str): The user's id.
        email(str, optional): The user's email address.
        auth_provider(str): The authentication provider ("local" or "cloudflare").
        is_active(bool): Whether the account is active.
        created_at(datetime): Account creation timestamp.
    """

    id: str
    email: str | None
    auth_provider: str
    is_active: bool
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "5b1e2f0a-9a3b-4a0e-9c1a-8f6d3c2b7a10",
                    "email": "operator@example.com",
                    "auth_provider": "local",
                    "is_active": True,
                    "created_at": "2026-07-15T09:30:00+00:00",
                },
            ],
        },
    }


class UpstreamCredentialCreateRequest(BaseModel):
    """Request body for registering a Cloudflare upstream credential.

    Args:
        label(str): A user-chosen label identifying this credential.
        cred_type(str): The credential kind, e.g. "token" or "global_key".
        api_token(str, optional): A Cloudflare scoped API token (for cred_type="token").
        global_key(str, optional): A Cloudflare Global API Key (for cred_type="global_key").
        cf_account_email(str, optional): The Cloudflare account email (for global_key auth).
    """

    label: str
    cred_type: str
    api_token: str | None = None
    global_key: str | None = None
    cf_account_email: str | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "label": "prod-dns-token",
                    "cred_type": "token",
                    "api_token": "AbCdEf1234567890ghijklmnopqrstuvwxyz",
                },
            ],
        },
    }


class UpstreamCredentialResponse(BaseModel):
    """Response body describing a stored upstream credential (secrets never included).

    Args:
        id(str): The credential's id.
        label(str): The credential's label.
        cred_type(str): The credential kind.
        cf_account_email(str, optional): The associated Cloudflare account email.
        verify_status(str, optional): Result of the last upstream verification.
        verified_at(datetime, optional): When the credential was last verified.
        created_at(datetime): Creation timestamp.
    """

    id: str
    label: str
    cred_type: str
    cf_account_email: str | None
    verify_status: str | None
    verified_at: datetime | None
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "9d2c1b0a-3e4f-4a5b-8c6d-7e8f9a0b1c2d",
                    "label": "prod-dns-token",
                    "cred_type": "token",
                    "cf_account_email": "operator@example.com",
                    "verify_status": "active",
                    "verified_at": "2026-07-15T09:31:00+00:00",
                    "created_at": "2026-07-15T09:30:00+00:00",
                },
            ],
        },
    }


class ScopeRuleRequest(BaseModel):
    """Request body describing a single scope rule attached to a scoped token.

    Args:
        zone_id(str): The Cloudflare zone id this rule applies to.
        name_pattern(str, optional): A name pattern to match; None matches by record_ids only.
        name_match(str): Matching mode, "exact" or "wildcard".
        record_types(list[str]): Allowed DNS record types, or ["*"] for any type.
        record_ids(list[str], optional): Specific Cloudflare record ids this rule pins to.
        allow_read(bool): Whether reads are permitted.
        allow_create(bool): Whether record creation is permitted.
        allow_write(bool): Whether updates are permitted.
        allow_delete(bool): Whether deletion is permitted.
        content_lock(str, optional): Optional content constraint for this rule.
    """

    zone_id: str
    name_pattern: str | None = None
    name_match: str = "exact"
    record_types: list[str]
    record_ids: list[str] | None = None
    allow_read: bool = True
    allow_create: bool = False
    allow_write: bool = False
    allow_delete: bool = False
    content_lock: str | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                    "name_pattern": "*.staging",
                    "name_match": "wildcard",
                    "record_types": ["A", "CNAME"],
                    "record_ids": None,
                    "allow_read": True,
                    "allow_create": True,
                    "allow_write": True,
                    "allow_delete": False,
                    "content_lock": None,
                },
            ],
        },
    }


class ScopedTokenCreateRequest(BaseModel):
    """Request body for minting a new record-scoped proxy token.

    Args:
        name(str): A human-readable name for the token.
        upstream_credential_id(str): The upstream credential this token forwards through.
        expires_at(datetime, optional): Optional expiration timestamp.
        scope_rules(list[ScopeRuleRequest]): The rules granted to this token.
    """

    name: str
    upstream_credential_id: str
    expires_at: datetime | None = None
    scope_rules: list[ScopeRuleRequest]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "name": "staging-acme-dns",
                    "upstream_credential_id": "9d2c1b0a-3e4f-4a5b-8c6d-7e8f9a0b1c2d",
                    "expires_at": None,
                    "scope_rules": [
                        {
                            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                            "name_pattern": "*.staging",
                            "name_match": "wildcard",
                            "record_types": ["A", "CNAME"],
                            "record_ids": None,
                            "allow_read": True,
                            "allow_create": True,
                            "allow_write": True,
                            "allow_delete": False,
                            "content_lock": None,
                        },
                    ],
                },
            ],
        },
    }


class ScopedTokenCreateResponse(BaseModel):
    """Response body returned once, at mint time, containing the raw scoped token.

    Args:
        id(str): The scoped token's id.
        name(str): The scoped token's name.
        token(str): The raw scoped token string (shown only at mint time).
        token_prefix(str): A display-safe prefix of the token.
        expires_at(datetime, optional): Optional expiration timestamp.
        created_at(datetime): Creation timestamp.
    """

    id: str
    name: str
    token: str
    token_prefix: str
    expires_at: datetime | None
    created_at: datetime

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                    "name": "staging-acme-dns",
                    "token": "cfsx_AbCdEf0123456789AbCd_"
                    "1234567890abcdefghijklmnopqrstuvwxyzABCD",
                    "token_prefix": "cfsx_AbCdEf",
                    "expires_at": None,
                    "created_at": "2026-07-15T09:32:00+00:00",
                },
            ],
        },
    }


class ScopedTokenResponse(BaseModel):
    """Response body describing a scoped token without exposing its secret.

    Args:
        id(str): The scoped token's id.
        name(str): The scoped token's name.
        token_prefix(str): A display-safe prefix of the token.
        status(str): Current status ("active" or "revoked").
        version(int): Current rule version (bumped on rotate/revoke/rule change).
        expires_at(datetime, optional): Optional expiration timestamp.
        last_used_at(datetime, optional): When the token was last used.
        created_at(datetime): Creation timestamp.
        revoked_at(datetime, optional): When the token was revoked, if applicable.
    """

    id: str
    name: str
    token_prefix: str
    status: str
    version: int
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                    "name": "staging-acme-dns",
                    "token_prefix": "cfsx_AbCdEf",
                    "status": "active",
                    "version": 1,
                    "expires_at": None,
                    "last_used_at": "2026-07-15T10:00:00+00:00",
                    "created_at": "2026-07-15T09:32:00+00:00",
                    "revoked_at": None,
                },
            ],
        },
    }


class ScopeRuleResponse(BaseModel):
    """Response body describing a persisted scope rule attached to a scoped token.

    Args:
        id(str): The scope rule's id.
        zone_id(str): The Cloudflare zone id this rule applies to.
        name_pattern(str, optional): The name pattern this rule matches, if any.
        name_match(str): Matching mode, "exact" or "wildcard".
        record_types(list[str]): Allowed DNS record types, or ["*"] for any type.
        record_ids(list[str], optional): Specific Cloudflare record ids this rule pins to.
        allow_read(bool): Whether reads are permitted.
        allow_create(bool): Whether record creation is permitted.
        allow_write(bool): Whether updates are permitted.
        allow_delete(bool): Whether deletion is permitted.
        content_lock(str, optional): Optional content constraint for this rule.
        created_at(datetime): Creation timestamp.
    """

    id: str
    zone_id: str
    name_pattern: str | None
    name_match: str
    record_types: list[str]
    record_ids: list[str] | None
    allow_read: bool
    allow_create: bool
    allow_write: bool
    allow_delete: bool
    content_lock: str | None
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "2b3c4d5e-6f70-4a5b-8c6d-7e8f9a0b1c2d",
                    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                    "name_pattern": "*.staging",
                    "name_match": "wildcard",
                    "record_types": ["A", "CNAME"],
                    "record_ids": None,
                    "allow_read": True,
                    "allow_create": True,
                    "allow_write": True,
                    "allow_delete": False,
                    "content_lock": None,
                    "created_at": "2026-07-15T09:32:00+00:00",
                },
            ],
        },
    }


class ScopedTokenDetailResponse(BaseModel):
    """Response body describing a scoped token together with its scope rules.

    Args:
        id(str): The scoped token's id.
        name(str): The scoped token's name.
        token_prefix(str): A display-safe prefix of the token.
        status(str): Current status ("active" or "revoked").
        version(int): Current rule version (bumped on rotate/revoke/rule change).
        expires_at(datetime, optional): Optional expiration timestamp.
        last_used_at(datetime, optional): When the token was last used.
        created_at(datetime): Creation timestamp.
        revoked_at(datetime, optional): When the token was revoked, if applicable.
        rules(list[ScopeRuleResponse]): The token's scope rules.
    """

    id: str
    name: str
    token_prefix: str
    status: str
    version: int
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None
    rules: list[ScopeRuleResponse]

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                    "name": "staging-acme-dns",
                    "token_prefix": "cfsx_AbCdEf",
                    "status": "active",
                    "version": 1,
                    "expires_at": None,
                    "last_used_at": "2026-07-15T10:00:00+00:00",
                    "created_at": "2026-07-15T09:32:00+00:00",
                    "revoked_at": None,
                    "rules": [
                        {
                            "id": "2b3c4d5e-6f70-4a5b-8c6d-7e8f9a0b1c2d",
                            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                            "name_pattern": "*.staging",
                            "name_match": "wildcard",
                            "record_types": ["A", "CNAME"],
                            "record_ids": None,
                            "allow_read": True,
                            "allow_create": True,
                            "allow_write": True,
                            "allow_delete": False,
                            "content_lock": None,
                            "created_at": "2026-07-15T09:32:00+00:00",
                        },
                    ],
                },
            ],
        },
    }


class ScopedTokenRotateResponse(BaseModel):
    """Response body returned once, at rotate time, containing the new raw scoped token.

    Args:
        id(str): The scoped token's id.
        token(str): The new raw scoped token string (shown only at rotate time).
        token_prefix(str): A display-safe prefix of the new token.
        version(int): The rule version after rotation.
    """

    id: str
    token: str
    token_prefix: str
    version: int

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                    "token": "cfsx_ZzYyXxWwVvUuTtSsRrQq_"
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
                    "token_prefix": "cfsx_ZzYyXx",
                    "version": 2,
                },
            ],
        },
    }


class AuditLogResponse(BaseModel):
    """Response body describing a single audit log entry.

    Args:
        id(str): The audit log entry's id.
        ts(datetime): When the request was recorded.
        scoped_token_id(str, optional): The scoped token id used, if any.
        token_prefix(str, optional): The scoped token's display prefix.
        method(str): The HTTP method of the proxied request.
        path(str): The request path.
        zone_id(str, optional): The Cloudflare zone id involved.
        record_id(str, optional): The Cloudflare record id involved.
        record_name(str, optional): The DNS record name involved.
        record_type(str, optional): The DNS record type involved.
        decision(str): Either "allow" or "deny".
        deny_reason(str, optional): Why the request was denied, when applicable.
        upstream_status(int, optional): The Cloudflare upstream HTTP status, if forwarded.
        client_ip(str, optional): The client's source IP address.
        latency_ms(int, optional): Total request latency in milliseconds.
    """

    id: str
    ts: datetime
    scoped_token_id: str | None
    token_prefix: str | None
    method: str
    path: str
    zone_id: str | None
    record_id: str | None
    record_name: str | None
    record_type: str | None
    decision: str
    deny_reason: str | None
    upstream_status: int | None
    client_ip: str | None
    latency_ms: int | None

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": "3c4d5e6f-7081-4a5b-8c6d-7e8f9a0b1c2d",
                    "ts": "2026-07-15T10:05:00+00:00",
                    "scoped_token_id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                    "token_prefix": "cfsx_AbCdEf",
                    "method": "PATCH",
                    "path": "/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/rec1",
                    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                    "record_id": "rec1",
                    "record_name": "app.staging.example.com",
                    "record_type": "A",
                    "decision": "allow",
                    "deny_reason": None,
                    "upstream_status": 200,
                    "client_ip": "203.0.113.7",
                    "latency_ms": 42,
                },
            ],
        },
    }
