"""FastAPI application factory.

Assembles every management (`/api/v1/*`) and proxy (`/client/v4/*`) router,
registers envelope-shaping exception handlers so the two API surfaces never
leak into each other's response shape, and manages the lifespan of the
process-wide database engine, Cloudflare httpx client, and Redis connection.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from cfproxy.cache.redis import get_redis
from cfproxy.core.cf_errors import INTERNAL
from cfproxy.core.envelopes import make_cf_error, make_response
from cfproxy.db.session import engine
from cfproxy.routers import audit, auth, credentials, proxy_blocked, proxy_dns, proxy_verify, tokens
from cfproxy.upstream.client import close_cf_client, get_cf_client

logger = logging.getLogger(__name__)

_PROXY_PATH_PREFIX = "/client/v4"


def _is_proxy_path(path: str) -> bool:
    """Determine whether a request path belongs to the proxy (`/client/v4`) API surface.

    Args:
        path(str): The incoming request's URL path.

    Return:
        is_proxy(bool): True if the path is under the proxy API surface.
    """
    return path.startswith(_PROXY_PATH_PREFIX)


def _http_exception_to_cf_response(exc: HTTPException) -> JSONResponse:
    """Reformat a raised `HTTPException` into the Cloudflare error envelope.

    Args:
        exc(HTTPException): The exception raised while handling a proxy request.

    Return:
        response(JSONResponse): A Cloudflare-shaped error envelope.
    """
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        return make_cf_error(exc.status_code, detail["code"], str(detail.get("message", "")))
    return make_cf_error(exc.status_code, INTERNAL, str(detail))


async def check_database() -> bool:
    """Check database connectivity with a plain `SELECT 1`.

    Return:
        is_ready(bool): True if the database answered successfully.
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        logger.exception("readiness check: database is unavailable")
        return False


async def check_redis() -> bool:
    """Check Redis connectivity with a `PING`.

    Return:
        is_ready(bool): True if Redis answered successfully.
    """
    try:
        await get_redis().ping()
        return True
    except Exception:
        logger.exception("readiness check: redis is unavailable")
        return False


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open the shared database engine, Cloudflare httpx client, and Redis
    connection pools for the app's lifetime, closing them on shutdown.

    Performs no schema DDL -- database initialization is an explicit
    operator action via `python -m cfproxy.cli init-db`.

    Args:
        app(FastAPI): The application whose lifetime is being managed.

    Return:
        None
    """
    get_cf_client()
    get_redis()
    try:
        yield
    finally:
        await close_cf_client()
        try:
            await get_redis().aclose()
        except Exception:
            logger.exception("lifespan shutdown: failed to close redis connection")
        await engine.dispose()


def create_app() -> FastAPI:
    """Assemble the full cfproxy FastAPI application.

    Includes every management and proxy router (in the order the proxy
    routers require -- `proxy_verify`/`proxy_dns` before `proxy_blocked` so
    its catch-all never shadows a real endpoint), registers exception
    handlers that keep the management `{status,message,data}` envelope and
    the Cloudflare envelope from leaking into each other, and wires the
    lifespan that owns the engine/httpx/redis pools.

    Return:
        app(FastAPI): The assembled FastAPI application.
    """
    app = FastAPI(title="cfproxy", lifespan=_lifespan)

    app.include_router(auth.router)
    app.include_router(credentials.router)
    app.include_router(tokens.router)
    app.include_router(audit.router)
    app.include_router(proxy_verify.router)
    app.include_router(proxy_dns.router)
    app.include_router(proxy_blocked.router)

    @app.exception_handler(HTTPException)
    async def handle_http_exception(request: Request, exc: HTTPException) -> JSONResponse:
        if _is_proxy_path(request.url.path):
            return _http_exception_to_cf_response(exc)
        return make_response(exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        if _is_proxy_path(request.url.path):
            return make_cf_error(400, INTERNAL, "Invalid request")
        return make_response(422, "Validation error", exc.errors())

    @app.exception_handler(Exception)
    async def handle_generic_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled exception while processing %s %s", request.method, request.url.path)
        if _is_proxy_path(request.url.path):
            return make_cf_error(500, INTERNAL, "Internal server error")
        return make_response(500, "Internal server error")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """Liveness probe: the process is up and serving requests."""
        return JSONResponse(status_code=200, content={"status": "ok"})

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Readiness probe: the database must be reachable; Redis is a
        best-effort accelerator, so its failure only degrades this probe
        rather than failing it.
        """
        if not await check_database():
            return JSONResponse(status_code=503, content={"status": "unavailable", "db": "down"})
        if not await check_redis():
            return JSONResponse(status_code=200, content={"status": "ok", "redis": "degraded"})
        return JSONResponse(status_code=200, content={"status": "ok", "redis": "ok"})

    return app


app = create_app()
