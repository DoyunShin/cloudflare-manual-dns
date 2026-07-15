# BUILD SPEC — Cloudflare Record-Scoped DNS Proxy (v1)

Authoritative interface contract. Every module MUST match the signatures/behavior here so parallel
work integrates. Plan of record: `~/.claude/plans/cloudflare-api-key-unified-donut.md`.

## Global rules
- Python >= 3.11 (uv manages 3.12). Package mgmt: `uv`. SQLAlchemy 2.0 async.
- Functions named `{action}_{name}`, full type hints + docstrings. No emoji anywhere (code, logs, comments).
- CLI/human output via `prompt_toolkit` (never bare `print`).
- Two envelope styles, never mixed:
  - Management `/api/v1/*` → `{status,message,data}` via `make_response`.
  - Proxy `/client/v4/*` → Cloudflare envelope verbatim via `make_cf_response` / `make_cf_error`.
- DB portability: use ONLY generic SQLAlchemy types (`String`, `Integer`, `Boolean`, `JSON`, `DateTime`).
  Prod = MySQL (`mysql+asyncmy`), tests/dev = SQLite (`sqlite+aiosqlite`). No MySQL-only column types.
  MySQL-specific ops (`GET_LOCK`, `SELECT ... FOR UPDATE`) MUST be dialect-guarded (no-op/fallback on sqlite).

## Testing conventions (how every agent validates)
- Run: `uv run pytest -q` (from repo root). Add `pytest-asyncio` mode `auto`.
- `tests/conftest.py` provides: an in-memory-ish SQLite async engine, tables created, a `settings` override
  with a freshly generated Fernet `proxy_secret_key` + a `jwt_secret`, a FastAPI app, an `httpx.AsyncClient`
  bound to the app (ASGITransport), and a `fakeredis.aioredis` client injected in place of `get_redis`.
- Mock all Cloudflare HTTP with `respx` (base `https://api.cloudflare.com`) and CF OAuth with `respx`
  (base `https://dash.cloudflare.com`). Never hit the network in tests.
- Each slice ships its own tests and must be green before the slice is "done".

## config.py — `Settings(BaseSettings)` (pydantic-settings), env-prefix none, `.env` supported
Fields (with defaults):
- `db_url: str` (e.g. `mysql+asyncmy://user:pass@mysql:3306/db`)
- `redis_url: str = "redis://localhost:6379/0"`
- `proxy_secret_key: str` (a valid Fernet key, 44-char urlsafe b64)
- `jwt_secret: str`
- `jwt_ttl_seconds: int = 86400`
- `upstream_base_url: str = "https://api.cloudflare.com"`
- `cf_oauth_issuer: str = "https://dash.cloudflare.com"`
- `cf_oauth_client_id: str = ""`, `cf_oauth_client_secret: str = ""`, `cf_oauth_redirect_uri: str = ""`
- `cf_oauth_base_scopes: str = "openid offline_access"`, `cf_oauth_dns_scope: str = ""`
- `token_brand: str = "cfsx"`
- `oauth_state_ttl: int = 600`, `rules_cache_ttl: int = 300`, `access_token_skew: int = 60`
- `web_concurrency: int = 4`
Provide `get_settings() -> Settings` (lru_cache). Tests override via env / dependency override.

## core/cf_errors.py — integer constants
`TOKEN_VALID = 10000`, `TOKEN_INVALID = 1000`, `RECORD_NOT_FOUND = 81044`, `FORBIDDEN = 9109`,
`ROUTE_NOT_FOUND = 7003`, `INTERNAL = 1000`.

## core/envelopes.py
```python
def make_response(status: int, message: str, data: Any = None) -> JSONResponse:
    # content {"status": status, "message": message, "data": data}, status_code=status

def make_cf_response(result: Any, *, status: int = 200,
                     messages: list[dict] | None = None,
                     result_info: dict | None = None) -> JSONResponse:
    # {"success": True, "errors": [], "messages": messages or [], "result": result}
    # + "result_info" key only when result_info is not None

def make_cf_error(status: int, code: int, message: str) -> JSONResponse:
    # {"success": False, "errors": [{"code": code, "message": message}], "messages": [], "result": None}
```

## core/crypto.py
- Token layout: `f"{brand}_{lookup_id}_{secret}"`. `lookup_id` and `secret` use alphabet `[A-Za-z0-9]`
  ONLY (no `_`/`-`) so `full.split("_")` == `[brand, lookup_id, secret]`. `lookup_id` len 16, `secret` len 40.
- `encrypt_secret(plaintext: str) -> str` / `decrypt_secret(ciphertext: str) -> str` (Fernet w/ settings key).
- `generate_scoped_token() -> dict` returning `{"lookup_id","secret","full","token_hash","token_prefix"}`
  where `token_hash = sha256_hex(full)`, `token_prefix = f"{brand}_{lookup_id[:6]}"` (display only).
- `parse_scoped_token(full: str) -> tuple[str, str] | None` → `(lookup_id, secret)` or None if malformed.
- `hash_token(full: str) -> str` (sha256 hex). `verify_token(full: str, token_hash: str) -> bool` (compare_digest).

## core/security.py
- `hash_password(pw: str) -> str` / `verify_password(pw: str, h: str) -> bool` (argon2-cffi).
- `create_jwt(sub: str) -> str` / `decode_jwt(token: str) -> dict` (pyjwt HS256, settings.jwt_secret, exp).
- FastAPI dep `get_current_user(...) -> User` (reads `Authorization: Bearer <jwt>`, loads active user; 401 else).

## db/models.py — SQLAlchemy 2.0 (`DeclarativeBase`, `Mapped`, `mapped_column`)
IDs: `String(36)` default `lambda: str(uuid4())`. Timestamps: `DateTime` default `datetime.now(UTC)`.
JSON columns via `JSON`. Booleans `Boolean`. Match plan's Data model exactly:
- `User`: id, email(unique,nullable), password_hash(nullable), auth_provider(String, default 'local'),
  cf_sub(String,unique,nullable), is_active(Boolean,default True), created_at, updated_at.
- `UpstreamCredential`: id, user_id(FK users.id, index), label, cred_type(String),
  secret_enc(nullable), access_token_enc(nullable), refresh_token_enc(nullable), token_expires_at(nullable),
  oauth_scopes(nullable), key_version(Integer,default 1), cred_version(Integer,default 1),
  cf_account_email(nullable), verify_status(nullable), verified_at(nullable), created_at.
  UniqueConstraint(user_id, label).
- `ScopedToken`: id, user_id(FK,index), upstream_credential_id(FK), name,
  lookup_id(String,unique,index), token_prefix, token_hash(unique), version(Integer,default 1),
  status(String,default 'active'), expires_at(nullable), last_used_at(nullable), created_at, revoked_at(nullable).
- `ScopeRule`: id, scoped_token_id(FK,index), zone_id, name_pattern(nullable),
  name_match(String,default 'exact'), record_types(JSON), record_ids(JSON,nullable),
  allow_read(Boolean), allow_create(Boolean), allow_write(Boolean), allow_delete(Boolean),
  content_lock(nullable), created_at.
- `AuditLog`: id, ts(index), user_id(nullable), scoped_token_id(nullable), token_prefix(nullable),
  method, path, zone_id(nullable), record_id(nullable), record_name(nullable), record_type(nullable),
  pre_image(JSON,nullable), post_image(JSON,nullable), decision(String), deny_reason(nullable),
  upstream_status(Integer,nullable), client_ip(nullable), latency_ms(Integer,nullable).
- `SchemaVersion`: version(Integer, pk), applied_at.
Export `Base` (metadata).

## db/session.py
- `engine = create_async_engine(get_settings().db_url, ...)`, `Sessionmaker = async_sessionmaker(engine, expire_on_commit=False)`.
- `async def get_session() -> AsyncIterator[AsyncSession]` (FastAPI dep).
- `async def init_db() -> None`: on MySQL, take advisory lock (db/locks) + create tables via `Base.metadata.create_all`
  + upsert `SchemaVersion`; on SQLite, just `create_all`. Idempotent.
- Allow tests to swap engine (module-level, or a `configure_engine(url)` helper).

## db/locks.py
- `advisory_lock(conn, name: str, timeout: int = 10)` async context manager. MySQL: `SELECT GET_LOCK(:n,:t)`;
  raise `LockUnavailable` if 0/None; `finally SELECT RELEASE_LOCK(:n)`. SQLite/other: process-local
  `asyncio.Lock` keyed by name (best-effort, single-process). Class `LockUnavailable(Exception)`.
- `mutation_lock_name(zone_id: str, record_id: str) -> str` = `"m" + sha256_hex(f"{zone_id}:{record_id}")[:60]` (<=64).
- `with_row_lock(session, stmt)` helper: adds `.with_for_update()` on MySQL, plain on SQLite.

## cache/redis.py — accelerator only; every function tolerates Redis being absent/erroring (fail to caller's DB path)
- `get_redis()` → shared `redis.asyncio.Redis` (from settings.redis_url). Overridable in tests (fakeredis).
- `async cache_get_json(key) -> Any|None`, `async cache_set_json(key, value, ttl)`, `async cache_del(*keys)`.
- `async rate_limit_incr(key, window) -> int`.
- Key helpers: `rules_key(lookup_id, version)`, `oauth_at_key(cred_id)`, `zones_key(cred_id)`,
  `oauth_state_key(state)`.
- On any redis error: log + return None / no-op (NEVER raise into the request path).

## authz/scope.py — PURE (no I/O)
- `normalize_fqdn(name: str) -> str`: lowercase, strip trailing dot, IDNA-encode (punycode) each label.
- `validate_name_pattern(pattern: str, name_match: str, zone_name: str) -> None`: raise `ValueError` unless
  valid. `exact`: any FQDN ending in `zone_name` (or `@`/zone apex). `wildcard`: exactly ONE `*` occupying a
  whole leftmost-or-deeper label, remainder ends in `zone_name`; reject bare `*`, `>1` `*`, mid-label `*`,
  suffix != zone.
- `name_matches(pattern: str, name_match: str, target: str) -> bool`: canonicalize both; `exact` → equality;
  `wildcard` → the `*` matches EXACTLY ONE label (no dot crossing; apex excluded).
- `match_rules(rules, zone_id, name, rtype, record_id, need) -> bool` — signature & body per plan
  (`need ∈ {"read","create","write","delete"}`; record_ids pin; name_pattern label-aware; per-op flags).
- `is_lock_exempt(rules, zone_id, path_record_id, op) -> bool`: True iff some rule granting `op` has
  `record_ids` containing `path_record_id`, `record_types == ["*"]`, and `name_pattern is None`.
- `merge_patch_image(pre: dict, body: dict) -> tuple[str, str]` → `(post_name, post_type)` (absent = unchanged).
`rules` is an iterable of `ScopeRule` (attrs: zone_id, name_pattern, name_match, record_types, record_ids,
allow_read/create/write/delete). Tests may pass simple namespaces with the same attrs.

## authz/authorizer.py — decision layer (no direct HTTP; fetch via injected callable)
```python
@dataclass
class AuthDecision:
    allowed: bool
    needs_lock: bool = False                 # acquire mutation lock BEFORE fetch
    error: tuple[int, int, str] | None = None  # (http_status, cf_code, message) when not allowed
    pre_image: dict | None = None

async def authorize_dns_request(
    *, rules, method: str, zone_id: str, record_id: str | None,
    body: dict | None, fetch_record: Callable[[str, str], Awaitable[dict | None]],
) -> AuthDecision
```
Implements per-method logic from the plan (create=body; GET/PATCH/PUT/DELETE by-id = decide lock exemption
from path+rules, then `pre = await fetch_record(zone_id, record_id)`; None/cross-zone → 404 81044; authz OLD;
PATCH/PUT authz NEW on rename/retype → 403 9109; leak policy 404 vs 403 exactly as plan).
Lock exemption is computed from `record_id`+`rules` BEFORE fetching (no circular dependency).

## auth/oauth_cf.py — CF OAuth (respx-mocked in tests)
- `build_authorize_url(state: str, nonce: str, code_challenge: str) -> str`.
- `make_pkce() -> tuple[str, str]` → `(verifier, s256_challenge)`.
- `async exchange_code(code: str, code_verifier: str) -> dict` (POST issuer `/oauth2/token`).
- `async refresh_access_token(refresh_token: str) -> dict`.
- `async fetch_jwks() -> dict` (cached) ; `validate_id_token(id_token, nonce) -> dict` (JWKS sig, alg allowlist
  RS256, iss==issuer, aud==client_id, exp/iat/nbf, nonce, at_hash/c_hash when present) → claims incl `sub`.
- `async fetch_userinfo(access_token: str) -> dict`.
- `async discover_dns_scope() -> list[str]` (GET `{upstream_base_url}/client/v4/oauth/scopes`).

## upstream/client.py — httpx pinned to Cloudflare (respx-mocked)
- Module-level `httpx.AsyncClient` factory `get_cf_client()` (base = settings.upstream_base_url), lifespan-closed.
- `async forward_request(method, path, *, headers, params, content, auth_header) -> httpx.Response`
  (always to `{upstream_base_url}{path}`; inject `Authorization: auth_header`; strip client Authorization).
- `async fetch_cf_record(zone_id, record_id, auth_header) -> dict | None` (GET one; None on 404).
- `async list_all_records(zone_id, params, auth_header) -> list[dict]` (loop all pages).
- `async verify_upstream(auth_header) -> dict` (GET `/client/v4/user/tokens/verify`).
- `async get_valid_access_token(session, credential) -> str`: token cred → decrypt secret_enc;
  oauth cred → encrypted `oauth_at` cache → else `with_row_lock` on the credential row, double-check expiry,
  `refresh_access_token`, persist rotated tokens with conditional `cred_version` bump, cache encrypted. Returns
  the bearer string WITHOUT the `Bearer ` prefix caller adds, OR the full header — pick one: RETURN RAW TOKEN.

## filtering/list_filter.py
- `filter_records(records: list[dict], rules, zone_id) -> list[dict]` (keep read-authorized).
- `paginate_and_result_info(records, page, per_page) -> tuple[list[dict], dict]` (local slice + result_info
  {page, per_page, count, total_count, total_pages}).

## auth/proxy_auth.py
- `async resolve_scoped_token(session, full_token: str, redis) -> ScopedToken|None` plus loaded rules+credential.
  Steps: parse → authoritative SELECT by lookup_id → constant-time hash verify → status active + not expired →
  load rules+credential (Redis `rules_key(lookup_id, version)` cache, else DB then cache). Returns a context
  object `ProxyAuthContext(token, rules, credential)` or None. FastAPI dep `require_scoped_token`.

## Management endpoints (routers, `{status,message,data}`, JWT; every id op scoped by current_user.id — IDOR)
Per plan "Management endpoints". Explicit OpenAPI `responses=` examples on each. Services in `services/`.

## Proxy endpoints (routers, CF envelope, `/client/v4`)
Per plan "Proxy endpoints". Catch-all → 404 7003. batch/import/export → 403 9109. verify emulated.
Proxy-scoped exception handlers always emit CF envelope.

## main.py
`create_app()`: include routers, register exception handlers (mgmt HTTPException/validation → make_response;
proxy scope → CF envelope), `lifespan` opens engine/httpx/redis pools (NO DDL), `GET /healthz` (liveness 200),
`GET /readyz` (200 if MySQL `SELECT 1`; Redis PING fail → 200 `{"redis":"degraded"}`; 503 only if MySQL down).

## cli/console.py (prompt_toolkit)
`init-db` (calls init_db with advisory lock + schema_version), `bootstrap-admin`, `discover-scope`
(prints `discover_dns_scope`), `tail-audit`, `health`. Entrypoint `python -m cfproxy.cli <cmd>`.
