# Cloudflare Record-Scoped DNS Proxy

A self-hosted proxy that sits in front of the Cloudflare API and issues
record-scoped tokens: each token is restricted to specific zones, record
name patterns, record types, and operations (read/create/write/delete),
so a single leaked token cannot touch DNS records outside its scope.

## Quickstart

### 1. Register a Cloudflare OAuth client

In the Cloudflare dashboard, register an OAuth application and note the
client id, client secret, and redirect URI. The redirect URI must point
back at this proxy, e.g. `https://your-domain.example/api/v1/auth/cf/callback`.

Cloudflare's OAuth **requires HTTPS** for the redirect URI, so the proxy
must be served over TLS in production (see "TLS" below).

### 2. Configure environment

```sh
cp .env.example .env
```

Fill in `.env`:
- Generate `PROXY_SECRET_KEY` and `JWT_SECRET` once (commands are in the
  comments of `.env.example`) and keep them stable -- rotating either one
  invalidates stored credentials or active sessions respectively.
- Set `MYSQL_*` / `REDIS_PASSWORD` and matching `DB_URL` / `REDIS_URL`.
- Set `CF_OAUTH_CLIENT_ID`, `CF_OAUTH_CLIENT_SECRET`, `CF_OAUTH_REDIRECT_URI`.
- Run `docker compose run --rm app python -m cfproxy.cli discover-scope`
  (after the stack is up) to find the DNS OAuth scope, then set
  `CF_OAUTH_DNS_SCOPE`.

### 3. Start the stack

```sh
docker compose up -d
```

This brings up, in order:
- `migrate` -- a one-shot job that creates the schema (`init-db`) and
  exits; `app` will not start until it completes successfully.
- `mysql` and `redis` -- the datastore and cache, reachable only on the
  internal `backend` network.
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

### 5. Bootstrap an admin user and mint a scoped token

```sh
docker compose exec app python -m cfproxy.cli bootstrap-admin
```

Then, through the management API (`/api/v1/*`), register an upstream
Cloudflare credential and mint a scoped token restricted to the zones,
record patterns, and operations you want to expose.

### 6. Point your tooling at the proxy

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

- `GET /healthz` -- liveness probe (process is up).
- `GET /readyz` -- readiness probe (200 once MySQL answers; Redis
  degradation returns 200 with `{"redis":"degraded"}` rather than
  failing readiness).
- `python -m cfproxy.cli tail-audit` -- follow the audit log.
- `python -m cfproxy.cli health` -- one-shot health check from the CLI.

## Scaling

`app` is stateless; all authoritative state lives in MySQL and Redis.
Increasing `WEB_CONCURRENCY` or running multiple `app` replicas is safe
as long as MySQL's `max_connections` is sized for the total connection
count across every replica and worker (see comments in `.env.example`).
