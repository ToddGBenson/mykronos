"""The dashboard has its own perimeter gate (frontend/proxy.ts, lib/gate.ts).

The browser never reaches the API: Next calls it server-side with the admin
token, so the backend's gate only ever sees Next. Without a gate in the
frontend, publishing the dashboard publishes admin. The frontend has no test
runner, so its behaviour was verified against a running container (401 for
absent, wrong, prefetch and `/api/*` POST; 200 for header, cookie and the
healthcheck; `?_token=` sets a Secure HttpOnly cookie behind HTTPS and
redirects). These pin the properties a later edit could quietly remove.
"""

from __future__ import annotations

import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


def _proxy() -> str:
    return (FRONTEND / "proxy.ts").read_text(encoding="utf-8")


def _gate() -> str:
    return (FRONTEND / "lib" / "gate.ts").read_text(encoding="utf-8")


def test_the_matcher_covers_everything_but_build_assets():
    """The old matcher skipped `/api` and prefetches; route handlers there
    carry the admin token too."""
    matcher = re.search(r"matcher:\s*\[([^\]]*)\]", _proxy())
    assert matcher, "proxy config has no matcher"
    assert matcher.group(1).strip() == '"/((?!_next/static|_next/image|favicon.ico).*)"'
    assert "missing:" not in _proxy()


def test_the_gate_runs_before_anything_is_served():
    src = _proxy()
    gate = src.index("tokensMatch(presented, expected)")
    assert gate < src.index("return withCsp(request)")
    assert gate < src.index("return NextResponse.next()")


def test_only_the_healthcheck_is_exempt():
    assert re.search(r'return path === "/api/healthz";', _gate())
    assert "startsWith" not in _gate()


def test_the_comparison_is_constant_time():
    src = _gate()
    assert 'crypto.subtle.digest("SHA-256"' in src
    assert "diff |= x[i] ^ y[i]" in src
    assert "presented === expected" not in src + _proxy()


def test_the_link_cookie_is_httponly_and_secure_behind_https():
    src = _proxy()
    assert "httpOnly: true" in src
    assert 'secure: proto === "https"' in src
    assert "searchParams.append" in src and "key !== TOKEN_QUERY" in src


def test_the_image_healthcheck_uses_the_exempt_path():
    dockerfile = (FRONTEND / "Dockerfile").read_text(encoding="utf-8")
    assert "fetch('http://localhost:3100/api/healthz')" in dockerfile
