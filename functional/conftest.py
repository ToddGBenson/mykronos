"""Functional tests against a running Mykronos (PIP-2).

Not unit tests, and kept out of `backend/tests` for that reason: these need a
deployed application, they speak HTTP, and they are the traffic source for the
DAST lane (PIP-3). Running them in the unit suite would make the unit suite
depend on a deployment.

Every request goes through `httpx2` with `trust_env` left on, so
`HTTP_PROXY`/`HTTPS_PROXY` route the whole suite through ZAP without a single
line here knowing about it. That is the seam: functional tests already know
how to authenticate and drive multi-step flows, and a spider starting at the
login page never sees any of it.
"""

from __future__ import annotations

import os

import httpx2
import pytest

FRONTEND = os.environ.get("DEMO_FRONTEND_URL", "http://frontend:3100")
BACKEND = os.environ.get("DEMO_BACKEND_URL", "http://backend:8100")
GATE_TOKEN = os.environ.get("DEMO_GATE_TOKEN", "demo-gate-token-not-a-secret")
ADMIN_TOKEN = os.environ.get("DEMO_ADMIN_TOKEN", "demo-admin-token-not-a-secret")


@pytest.fixture(scope="session")
def anonymous() -> httpx2.Client:
    """No credentials, against the dashboard."""
    with httpx2.Client(base_url=FRONTEND, timeout=60, follow_redirects=True) as client:
        yield client


@pytest.fixture(scope="session")
def anonymous_api() -> httpx2.Client:
    """No credentials, against the API - which is where the gate lives."""
    with httpx2.Client(base_url=BACKEND, timeout=60) as client:
        yield client


@pytest.fixture(scope="session")
def browser() -> httpx2.Client:
    """A signed-in session, as a person's browser would hold it."""
    with httpx2.Client(
        base_url=FRONTEND,
        timeout=60,
        follow_redirects=True,
        cookies={"hub_token": GATE_TOKEN},
    ) as client:
        yield client


@pytest.fixture(scope="session")
def api() -> httpx2.Client:
    with httpx2.Client(
        base_url=BACKEND,
        timeout=60,
        headers={
            "Authorization": f"Bearer {ADMIN_TOKEN}",
            "X-Hub-Token": GATE_TOKEN,
        },
    ) as client:
        yield client


@pytest.fixture(scope="session")
def seeded_repos(api: httpx2.Client) -> list[dict]:
    """The repositories the seed created.

    A session fixture rather than a per-test call so the suite fails once,
    loudly, if the environment was never seeded — rather than every test
    failing separately on an empty portfolio and burying the cause.
    """
    response = api.get("/api/dashboard/portfolio")
    response.raise_for_status()
    repos = response.json()["repos"]
    assert repos, (
        "The demo environment has no repositories. The seed did not run, or "
        "ran against a different instance — every flow below would fail for "
        "that one reason."
    )
    return repos
