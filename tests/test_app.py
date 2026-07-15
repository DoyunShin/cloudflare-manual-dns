"""Tests for `cfproxy.main.create_app`: health/readiness probes, the proxy
catch-all's Cloudflare-shaped 404, and that a management route is reachable
end-to-end through the fully assembled app.
"""

from collections.abc import Callable, AsyncIterator
from contextlib import AbstractAsyncContextManager

import httpx
import pytest
from fastapi import FastAPI

from cfproxy.main import create_app


class _BrokenRedis:
    """A minimal stand-in for a Redis client whose `ping` always fails."""

    async def ping(self) -> bool:
        """Simulate an unreachable Redis server."""
        raise ConnectionError("redis unavailable")


@pytest.fixture
async def client(
    async_client_factory: Callable[[FastAPI], AbstractAsyncContextManager[httpx.AsyncClient]],
) -> AsyncIterator[httpx.AsyncClient]:
    """An httpx client bound to the fully assembled cfproxy app."""
    async with async_client_factory(create_app()) as async_client:
        yield async_client


async def test_healthz_returns_200(client: httpx.AsyncClient) -> None:
    """The liveness probe always answers 200 while the process is up."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readyz_ok_then_degrades_when_redis_down(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """readyz is 200 with redis "ok" normally, and 200 with redis "degraded"
    (never 503) when only Redis -- not the database -- is unreachable.
    """
    response = await client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "redis": "ok"}

    monkeypatch.setattr("cfproxy.main.get_redis", lambda: _BrokenRedis())

    degraded_response = await client.get("/readyz")
    assert degraded_response.status_code == 200
    assert degraded_response.json() == {"status": "ok", "redis": "degraded"}


async def test_catch_all_proxy_route_returns_cf_404(client: httpx.AsyncClient) -> None:
    """An unmatched `/client/v4` path always answers with the Cloudflare
    404 envelope (error code 7003), never FastAPI's default `{detail}`/HTML.
    """
    response = await client.get("/client/v4/x")
    assert response.status_code == 404
    body = response.json()
    assert body["success"] is False
    assert body["errors"] == [{"code": 7003, "message": "Not found."}]
    assert body["result"] is None


async def test_mgmt_register_route_is_reachable(client: httpx.AsyncClient) -> None:
    """A management route (`POST /api/v1/auth/register`) is wired up and
    answers with the standard `{status,message,data}` envelope.
    """
    response = await client.post(
        "/api/v1/auth/register",
        json={"email": "app-smoke-test@example.com", "password": "correct-horse-battery-staple"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["status"] == 201
    assert body["message"] == "User registered"
    assert body["data"]["email"] == "app-smoke-test@example.com"
