"""SQLAlchemy 2.0 ORM models for cfproxy.

All columns use generic SQLAlchemy types (String, Integer, Boolean, JSON,
DateTime) so the schema is portable between MySQL (production) and SQLite
(tests/dev). No MySQL-only column types are used.
"""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Declarative base class for all cfproxy ORM models."""


def _new_uuid() -> str:
    """Generate a new UUID4 string for use as a primary key default."""
    return str(uuid4())


def _utcnow() -> datetime:
    """Return the current UTC datetime for use as a timestamp column default."""
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC as a naive database value and return UTC-aware datetimes."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        """Normalize a datetime to naive UTC before persistence."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        """Attach UTC to the naive value returned by the database."""
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class User(Base):
    """A management-plane user account."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    local_login: Mapped[str | None] = mapped_column(String(255), unique=True, nullable=True)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local")
    oidc_issuer: Mapped[str | None] = mapped_column(
        String(512).with_variant(String(512, collation="utf8mb4_0900_bin"), "mysql"),
        nullable=True,
    )
    oidc_sub: Mapped[str | None] = mapped_column(
        String(255).with_variant(String(255, collation="utf8mb4_0900_bin"), "mysql"),
        nullable=True,
    )
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        UniqueConstraint("oidc_issuer", "oidc_sub", name="uq_users_oidc_identity"),
    )


class ManagementSession(Base):
    """A revocable server-side management session."""

    __tablename__ = "management_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    auth_method: Mapped[str] = mapped_column(String(32))
    provider_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    csrf_secret: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class OIDCConfig(Base):
    """Singleton configuration for the external OIDC provider."""

    __tablename__ = "oidc_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    label: Mapped[str] = mapped_column(String(255), default="OIDC")
    issuer: Mapped[str] = mapped_column(String(512))
    client_id: Mapped[str] = mapped_column(String(1024))
    client_secret_enc: Mapped[str] = mapped_column(String(4096))
    scopes: Mapped[str] = mapped_column(String(1024), default="openid profile email")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    allowed_endpoint_origins: Mapped[list] = mapped_column(JSON, default=list)
    allow_private_network: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, onupdate=_utcnow)


class UpstreamCredential(Base):
    """A stored Cloudflare credential (API token or OAuth grant) owned by a user."""

    __tablename__ = "upstream_credentials"
    __table_args__ = (UniqueConstraint("user_id", "label"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    label: Mapped[str] = mapped_column(String(255))
    cred_type: Mapped[str] = mapped_column(String(32))
    secret_enc: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    access_token_enc: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    refresh_token_enc: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    oauth_scopes: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
    cred_version: Mapped[int] = mapped_column(Integer, default=1)
    cf_account_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    verify_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class ScopedToken(Base):
    """A record-scoped proxy token issued to a user for a given credential."""

    __tablename__ = "scoped_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), index=True)
    upstream_credential_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("upstream_credentials.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255))
    lookup_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(16), default="active")
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class ScopeRule(Base):
    """An authorization rule bound to a scoped token."""

    __tablename__ = "scope_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    scoped_token_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scoped_tokens.id"), index=True
    )
    zone_id: Mapped[str] = mapped_column(String(64))
    name_pattern: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name_match: Mapped[str] = mapped_column(String(16), default="exact")
    record_types: Mapped[list] = mapped_column(JSON)
    record_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    allow_read: Mapped[bool] = mapped_column(Boolean)
    allow_create: Mapped[bool] = mapped_column(Boolean)
    allow_write: Mapped[bool] = mapped_column(Boolean)
    allow_delete: Mapped[bool] = mapped_column(Boolean)
    content_lock: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)


class AuditLog(Base):
    """An immutable audit record of a proxy request decision."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_new_uuid)
    ts: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow, index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    scoped_token_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    token_prefix: Mapped[str | None] = mapped_column(String(32), nullable=True)
    method: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(String(1024))
    zone_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    record_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    record_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    pre_image: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    post_image: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    decision: Mapped[str] = mapped_column(String(16))
    deny_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    upstream_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


class SchemaVersion(Base):
    """Tracks the currently applied schema version for migration bookkeeping."""

    __tablename__ = "schema_version"

    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)
