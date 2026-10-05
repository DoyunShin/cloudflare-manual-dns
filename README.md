# Cloudflare Record-Scoped DNS Proxy

A self-hosted proxy that sits in front of the Cloudflare API and issues
record-scoped tokens: each token is restricted to specific zones, record
name patterns, record types, and operations (read/create/write/delete),
so a single leaked token cannot touch DNS records outside its scope.

## Quickstart

### 1. Prepare a new installation

This version requires a fresh database. `init-db` refuses incompatible or
partially initialized schemas before performing DDL. It does not migrate,
reset, or delete an existing database. Back up any previous installation
and provision a separate empty database.

### 2. Configure environment

```sh
cp .env.example .env
```

Fill in `.env`:

- Generate `PROXY_SECRET_KEY` once (command in `.env.example`) and keep it
  stable. It encrypts stored Cloudflare credentials and OIDC client secrets.
- Set `APP_BASE_URL` to the public HTTPS origin, without a path. The UI and
  API must share this origin; management authentication uses Secure cookies.
- Set `MYSQL_*` / `REDIS_PASSWORD` and matching `DB_URL` / `REDIS_URL`.

### 3. Start the stack

```sh
docker compose up -d
```

This brings up, in order:
- `mysql` and `redis` -- the datastore and cache, reachable only on the
  internal `backend` network.
- `migrate` -- a one-shot job that creates the schema (`init-db`) and
  exits; `app` will not start until it completes successfully.
- `app` -- the FastAPI proxy, bound to `127.0.0.1:8080` on the host only.

Check readiness:

```sh
curl -sf http://127.0.0.1:8080/readyz
```

### 4. TLS

The `app` service is intentionally bound to loopback only and never
serves plaintext to the network. Either:
- enable the bundled `tls` profile, which starts a Caddy reverse proxy
  terminating TLS and forwarding to `app:8080`:
  ```sh
  docker compose --profile tls up -d
  ```
  (requires a `Caddyfile` alongside `compose.yaml`), or
- front the loopback-bound app with your own externally managed TLS
  terminator (load balancer, existing reverse proxy, etc.).

### 5. Bootstrap a local administrator and configure OIDC

```sh
docker compose exec app python -m cfproxy.cli bootstrap-admin
```

Sign in at `/admin/login`. Use `/admin/oidc` to configure one standard OIDC
provider (including Keycloak): issuer, client ID, client secret, and scopes.
Register `${APP_BASE_URL}/api/v1/auth/oidc/callback` at the provider. Use a
confidential Authorization Code client with PKCE S256. The default scopes
are `openid profile email`; service authentication does not request offline
access or store provider tokens.

The connection test verifies discovery metadata and JWKS, not the client
secret. Secrets are write-only; leaving the secret blank keeps the saved one.
Endpoints must use HTTPS and the issuer origin unless an administrator
explicitly allowlists another origin. Private-network endpoints require an
explicit opt-in; loopback and link-local/metadata endpoints remain blocked.
Enforce outbound network restrictions at deployment: DNS prechecks do not
guarantee protection against DNS rebinding.

OIDC only authenticates and supplies profile information. Users are keyed
by `(issuer, sub)`, never automatically linked by email. First login creates
an active ordinary user. Provider roles/groups are ignored. Manage service
administrator status and account activation at `/admin/users`; profile
updates never overwrite these permissions. The last active local recovery
administrator cannot be demoted or deactivated.

Public registration and ordinary password login are unavailable. Keep the
local administrator for provider/configuration recovery. OIDC configuration
changes invalidate previous OIDC sessions and pending logins, while local
administrator sessions remain valid.

### 6. Connect a Cloudflare credential

Authenticated users can paste an API Token or Global API Key on the
credential page. Cloudflare OAuth is an optional credential connection,
not a separate service login. To enable it, configure `CF_OAUTH_CLIENT_ID`
and `CF_OAUTH_CLIENT_SECRET`. Register
`${APP_BASE_URL}/api/v1/upstream-credentials/cf/callback` at Cloudflare;
the service derives this callback from `APP_BASE_URL`.

Run `docker compose exec app python -m cfproxy.cli discover-scope` and supply
an authorized API token at its hidden prompt. Set `CF_OAUTH_DNS_SCOPE` to
the returned scope ID. Cloudflare refresh tokens remain stored encrypted
because credential access may need refreshing; this is separate from OIDC
service authentication.

Mint scoped tokens restricted to the desired zones, record patterns, and
operations. An optional `content_lock` requires exact literal equality of
the resulting DNS content on creation/update. PATCH may omit content only
when the existing value satisfies the lock; locked PUT must provide it.

### 7. Point your tooling at the proxy

Any client that speaks the Cloudflare `/client/v4` API can be redirected
to the proxy by overriding its base URL and supplying the scoped token
in place of a real Cloudflare API token.

**Terraform:**

```hcl
provider "cloudflare" {
  api_token = "<scoped-token>"
  base_url  = "https://your-domain.example/client/v4"
}
```

**ddclient** (`ddclient.conf`):

```
protocol=cloudflare
server=your-domain.example
ssl=yes
password=<scoped-token>
```

**acme.sh** (via its `dns_cf` hook, pointed at the proxy's base URL):

```sh
export CF_Token="<scoped-token>"
acme.sh --issue --dns dns_cf -d example.com \
  --server https://your-domain.example/client/v4
```

## Operations

- Management sessions are stored in MySQL; the browser receives a Secure,
  HttpOnly, SameSite=Lax cookie. The default absolute lifetime is 24 hours
  (`SESSION_TTL_SECONDS`). Mutating API calls require the CSRF token from
  `GET /api/v1/auth/me` and the configured origin.
- Logout revokes only this service session. It never invokes provider
  logout, token revocation, or backchannel logout, and does not automatically
  start a new OIDC login. IdP account/session changes do not revoke an
  already established service session; service account deactivation does.
- Redis failure does not invalidate existing service sessions or their
  management requests. New local logins fail closed when rate limiting is
  unavailable, and OIDC flows fail closed when state storage is unavailable.
- Local login permits five attempts per peer IP per five minutes. Behind
  Caddy or another TLS proxy, configure `FORWARDED_ALLOW_IPS` with only the
  trusted proxy addresses/CIDRs. Otherwise clients share the proxy's rate
  limit. Do not trust arbitrary forwarded headers or use a wildcard trust
  list on a network reachable by untrusted peers.
- `GET /healthz` -- liveness probe (process is up).
- `GET /readyz` -- readiness probe (200 once MySQL answers; Redis
  degradation returns 200 with `{"redis":"degraded"}` rather than
  failing readiness).
- `python -m cfproxy.cli tail-audit` -- follow the audit log.
- `python -m cfproxy.cli health` -- one-shot health check from the CLI.

## Scaling

`app` is stateless; users, permissions, and sessions live in MySQL. Redis
stores transient login state, rate limits, and disposable upstream caches.
Increasing `WEB_CONCURRENCY` or running multiple `app` replicas is safe
as long as MySQL's `max_connections` is sized for the total connection
count across every replica and worker (see comments in `.env.example`).

## Verification

Run `uv run pytest` from the repository root and `npm run build` from
`frontend`. Optional MySQL
integration tests use `CFPROXY_TEST_MYSQL_URL` and require a dedicated
database named `cfproxy_oidc_test`. They recreate the managed tables before
each test: never point this variable at an operational database. These tests
cover FK deletion, concurrent refresh, recovery-admin protection, exact OIDC
identity matching, configuration revision races, and Cloudflare reconnect.
