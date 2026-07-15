"""Application settings for cfproxy."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables and .env file.

    Args:
        db_url(str): SQLAlchemy async database URL.
        redis_url(str): Redis connection URL.
        proxy_secret_key(str): Fernet key used to encrypt/decrypt stored secrets.
        jwt_secret(str): HMAC secret used to sign management JWTs.
        jwt_ttl_seconds(int): Lifetime of issued JWTs in seconds.
        upstream_base_url(str): Base URL for the Cloudflare API.
        cf_oauth_issuer(str): Cloudflare OAuth issuer base URL.
        cf_oauth_client_id(str): OAuth client id registered with Cloudflare.
        cf_oauth_client_secret(str): OAuth client secret registered with Cloudflare.
        cf_oauth_redirect_uri(str): OAuth redirect URI registered with Cloudflare.
        cf_oauth_base_scopes(str): Space-separated base OAuth scopes to request.
        cf_oauth_dns_scope(str): DNS-specific OAuth scope to request.
        token_brand(str): Prefix used for scoped token strings.
        oauth_state_ttl(int): TTL in seconds for OAuth state values.
        rules_cache_ttl(int): TTL in seconds for cached scope rules.
        access_token_skew(int): Seconds of skew allowed before refreshing access tokens.
        web_concurrency(int): Number of worker processes for the web server.
    """

    model_config = SettingsConfigDict(env_prefix="", env_file=".env", extra="ignore")

    db_url: str
    redis_url: str = "redis://localhost:6379/0"
    proxy_secret_key: str
    jwt_secret: str
    jwt_ttl_seconds: int = 86400
    upstream_base_url: str = "https://api.cloudflare.com"
    cf_oauth_issuer: str = "https://dash.cloudflare.com"
    cf_oauth_client_id: str = ""
    cf_oauth_client_secret: str = ""
    cf_oauth_redirect_uri: str = ""
    cf_oauth_base_scopes: str = "openid offline_access"
    cf_oauth_dns_scope: str = ""
    token_brand: str = "cfsx"
    oauth_state_ttl: int = 600
    rules_cache_ttl: int = 300
    access_token_skew: int = 60
    web_concurrency: int = 4


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    Return:
        settings(Settings): The process-wide application settings.
    """
    return Settings()
