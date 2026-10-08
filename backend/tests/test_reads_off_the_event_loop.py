"""A slow read does not stall every other request.

The backend runs one uvicorn process with one event loop. Route handlers
declared `async def` that make blocking DuckDB or SQLite calls run *on* that
loop, so on 2026-10-08 a 40s shadow-mode request held /healthz for 39.75s -
and with it CI ingestion, the deploy gate's lookups and the container
healthcheck (5s timeout). A plain `def` handler runs on FastAPI's threadpool.
"""

from __future__ import annotations

import ast
import inspect
import socket
import textwrap
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import uvicorn
from fastapi.routing import APIRoute

from mykronos.main import create_app


def _get(url: str, headers: dict[str, str] | None = None, timeout: float = 30) -> int:
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as error:
        return int(error.code)


def _awaits(fn) -> bool:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    return any(isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith)) for n in ast.walk(tree))


def _api_routes(routes) -> list[APIRoute]:
    """Every APIRoute, including those behind `include_router`, which this
    FastAPI keeps as `_IncludedRouter` wrappers rather than flattening."""
    found: list[APIRoute] = []
    for route in routes:
        if isinstance(route, APIRoute):
            found.append(route)
        elif hasattr(route, "original_router"):
            found += _api_routes(route.original_router.routes)
        elif hasattr(route, "routes"):
            found += _api_routes(route.routes)
    return found


def test_the_walk_reaches_the_api(settings) -> None:
    """Without this the guard below passes vacuously - it did, once."""
    paths = {r.path for r in _api_routes(create_app(settings).routes)}
    assert "/api/oracle/shadow-mode" in paths
    assert len(paths) > 100


def test_no_get_handler_is_async_without_awaiting(settings) -> None:
    """An `async def` that never awaits gains nothing and blocks the loop."""
    offenders = [
        f"{route.path} ({route.endpoint.__module__}.{route.endpoint.__name__})"
        for route in _api_routes(create_app(settings).routes)
        if isinstance(route, APIRoute)
        and "GET" in route.methods
        # The API modules, where handlers reach the lake and the database.
        # main.py's /healthz does no I/O and belongs on the loop: it must
        # answer even when the threadpool is busy.
        and route.endpoint.__module__.startswith("mykronos.api.")
        and inspect.iscoroutinefunction(route.endpoint)
        and not _awaits(route.endpoint)
        # Writes and deletes a probe file; kept on the loop so two calls
        # cannot interleave on it.
        and route.endpoint.__name__ != "health"
    ]
    assert offenders == []


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_a_slow_read_does_not_hold_healthz(settings, monkeypatch) -> None:
    from mykronos.oracle import service

    def slow_report(self, **_kwargs):
        time.sleep(3)
        return {}

    monkeypatch.setattr(service.OracleService, "shadow_mode_report", slow_report)
    app = create_app(settings)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                _get(f"{base}/healthz", timeout=1)
                break
            except OSError:
                time.sleep(0.05)
        admin = {"Authorization": f"Bearer {settings.admin_token}"}
        with ThreadPoolExecutor(2) as pool:
            slow = pool.submit(_get, f"{base}/api/oracle/shadow-mode", admin)
            time.sleep(0.5)
            started = time.perf_counter()
            health = _get(f"{base}/healthz")
            elapsed = time.perf_counter() - started
            assert slow.result() == 200
        assert health == 200
        assert elapsed < 1.0, f"/healthz waited {elapsed:.2f}s behind a slow read"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
