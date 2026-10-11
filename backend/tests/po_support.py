"""A fake TheHub and onboarding helpers for the Product Owner console's phase 2
tests (spec 35 §8).

Separate from `test_product_owner.py` so the phase 2 tests do not collect, or
depend on, the phase 1 module's test classes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos import product_owner as po
from mykronos.db.models import AuditLogEntry, Organization, RepoOnboarding
from tests.conftest import INSTALLATION, REPO

MANIFEST = """
version: 1
name: keel-style
spine_map:
  G1: ready
  G2: building
gates:
  - id: G1
    name: Ready
    recommends: Product Owner
    approves: Delivery Lead
    story_gates: [clarified, designed]
    checklist:
      - id: ac
        text: Acceptance criteria
        evidence: acceptance_criteria
  - id: G2
    name: Building
    recommends: Developer
    approves: Reviewer agent
    story_gates: [ready, in_progress]
  - id: G3
    name: Verify
    story_gates: [tested]
backlog:
  source: thehub
  tag: repo:payments-api
  include_untagged: false
"""


def story(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 1,
        "title": "A story",
        "detail": "",
        "bucket": "backlog",
        "tags": ["repo:payments-api"],
        "acceptance_criteria": ["it works"],
        "gate": "clarified",
        "size": "S",
        "retrospective_md": None,
        "created_at": "2026-10-01T00:00:00",
        "updated_at": "2026-10-02T00:00:00",
        "moved_at": None,
        "closed_at": None,
    }
    base.update(overrides)
    return base


class FakeHub:
    """Answers the reads the console makes, and records every request."""

    def __init__(self, stories: list[dict[str, Any]]) -> None:
        self.stories = {s["id"]: dict(s) for s in stories}
        self.runs: dict[int, list[dict[str, Any]]] = {}
        self.verification: dict[int, dict[str, Any]] = {}
        self.deploys: dict[int, list[dict[str, Any]]] = {}
        self.dashboard: dict[str, Any] = {
            "in_flight": [],
            "last_7d_outcomes": {},
            "daily_cost_used_usd": 0.0,
            "daily_cost_cap_usd": 5.0,
            "rooms_enabled": [],
            "kill_switch_active": False,
            "dry_run_default": True,
        }
        #: Paths that answer HTTP 500, to prove one failed read marks one
        #: story unread rather than failing the view.
        self.failing: set[str] = set()
        self.calls: list[tuple[str, str, Any]] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.calls.append((request.method, path, body))
        if path in self.failing:
            return httpx2.Response(500, json={"detail": "boom"})
        if request.method == "GET" and path == "/api/dev/stories":
            bucket = request.url.params.get("bucket")
            return httpx2.Response(
                200, json=[s for s in self.stories.values() if s["bucket"] == bucket]
            )
        if request.method == "GET" and path == "/api/devops/autonomy/dashboard":
            return httpx2.Response(200, json=self.dashboard)
        if request.method == "GET" and path.startswith("/api/dev/stories/"):
            parts = path.split("/")
            sid = int(parts[4])
            if sid not in self.stories:
                return httpx2.Response(404, json={"detail": "Story not found"})
            if len(parts) == 5:
                return httpx2.Response(200, json=self.stories[sid])
            leaf = parts[5]
            if leaf == "autonomy-cost":
                runs = self.runs.get(sid, [])
                return httpx2.Response(
                    200,
                    json={
                        "story_id": sid,
                        "run_count": len(runs),
                        "total_cost_usd": sum(r.get("cost_usd") or 0 for r in runs),
                        "runs": runs,
                    },
                )
            if leaf == "notes":
                docs = {"verification": self.verification[sid]} if sid in self.verification else {}
                return httpx2.Response(200, json={"story_id": sid, "phase_docs": docs})
            if leaf == "deploys":
                deploys = self.deploys.get(sid, [])
                return httpx2.Response(
                    200, json={"story_id": sid, "deploys": deploys, "count": len(deploys)}
                )
        return httpx2.Response(404, json={"detail": "Not Found"})

    def reads(self, leaf: str) -> list[str]:
        return [path for method, path, _ in self.calls if method == "GET" and path.endswith(leaf)]


def onboard(
    client: TestClient,
    repo: str = REPO,
    *,
    org: str | None = None,
    deployed_revision: str | None = None,
) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        login = org or repo.split("/")[0]
        existing = session.query(Organization).filter_by(github_org_login=login).first()
        if existing is None:
            existing = Organization(github_org_login=login)
            session.add(existing)
            session.flush()
        row = RepoOnboarding(
            org_id=existing.id,
            github_repo_full_name=repo,
            github_installation_id=INSTALLATION,
            status="active",
            enabled_capabilities=["sast"],
            default_branch="main",
            deployed_revision=deployed_revision,
            deployment_probe_status="ok" if deployed_revision else "not_configured",
        )
        session.add(row)
        session.flush()
        return row.id


def attach_hub(client: TestClient, hub: FakeHub) -> None:
    client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
        "http://hub.test", "hub-secret", transport=httpx2.MockTransport(hub.handler)
    )


@pytest.fixture
def connect(client: TestClient, github: Any) -> Callable[..., tuple[str, FakeHub]]:
    def _connect(
        stories: list[dict[str, Any]],
        manifest: str | None = MANIFEST,
        deployed_revision: str | None = None,
    ) -> tuple[str, FakeHub]:
        repo_id = onboard(client, deployed_revision=deployed_revision)
        if manifest is not None:
            github.repos[REPO].branches["main"][po.MANIFEST_PATH] = manifest
        hub = FakeHub(stories)
        attach_hub(client, hub)
        return repo_id, hub

    return _connect


def audit_entries(client: TestClient, action: str) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = session.query(AuditLogEntry).filter(AuditLogEntry.action == action).all()
        session.expunge_all()
        return rows
