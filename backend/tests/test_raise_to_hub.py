"""Raise a Hub incident or story from where the problem is seen (TheHub #60911).

Using Mykronos as the one tool, nothing could be reported from it:
`/api/dashboard/incident` is a CVE lookup, not an incident record, and
there was no bug or feature intake. Everything had to be filed by leaving
Mykronos for the Hub API. TheHub already has `/api/incidents` and
`/api/dev/stories`, so Mykronos hands off to them with the evidence attached
rather than growing its own tracker.

- The evidence is built by the backend from its own records (the last
  scans of a lane, a finding and its newest scan, a dependency's
  self-check), never taken from the browser.
- Every raise is audited with the principal's actor, kind and provenance,
  so a person and an agent credential are told apart.
- The row it was raised from shows the linked Hub id and its live status.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.db.models import AuditLogEntry
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.po_support import FakeHub, attach_hub, onboard

RAW = "raw/sast/run-3.sarif"


class RaiseHub(FakeHub):
    """FakeHub that also takes incidents and stories, and reports them back."""

    def __init__(self) -> None:
        super().__init__([])
        self.incidents: dict[int, dict[str, Any]] = {}
        self.created: dict[int, dict[str, Any]] = {}
        self.next_id = 900

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if path in self.failing:
            return super().handler(request)
        if request.method == "POST" and path in ("/api/incidents", "/api/dev/stories"):
            body = json.loads(request.content)
            self.calls.append((request.method, path, body))
            self.next_id += 1
            record = {"id": self.next_id, "status": "open", **body}
            (self.incidents if path == "/api/incidents" else self.created)[self.next_id] = record
            return httpx2.Response(201, json=record)
        if request.method == "GET" and path.startswith("/api/incidents/"):
            found = self.incidents.get(int(path.rsplit("/", 1)[1]))
            return httpx2.Response(200, json=found) if found else httpx2.Response(404)
        if request.method == "GET" and path.startswith("/api/dev/stories/"):
            sid = int(path.split("/")[4])
            if sid in self.created:
                return httpx2.Response(200, json={**self.created[sid], "gate": "clarified"})
        return super().handler(request)


def scan(n: int, **overrides: Any) -> dict[str, Any]:
    at = utcnow() - timedelta(hours=10 - n)
    row: dict[str, Any] = {
        "scan_run_id": f"run-{n}",
        "repo_full_name": REPO,
        "capability": "sast",
        "tool_name": "codeql",
        "tool_version": "2",
        "commit_sha": f"{n:x}" * 40,
        "branch": "main",
        "pr_number": None,
        "triggered_by": "push",
        "github_workflow_run_id": f"99001{n}",
        "started_at": at,
        "completed_at": at,
        "scan_status": "failure" if n == 3 else "success",
        "finding_count": 0,
        "raw_output_ref": f"raw/sast/run-{n}.sarif",
        "ingested_at": at,
    }
    row.update(overrides)
    return row


@pytest.fixture
def hub(client: TestClient) -> RaiseHub:
    fake = RaiseHub()
    attach_hub(client, fake)
    return fake


@pytest.fixture
def lane(client: TestClient, buffer: Any, run_compaction: Any) -> str:
    onboard(client)
    buffer.append("scan_runs", [scan(1), scan(2), scan(3)])
    run_compaction()
    return f"{REPO}:sast"


def _draft(client: TestClient, auth: dict[str, str], kind: str, subject: str) -> Any:
    return client.get(
        "/api/dashboard/raise/draft", params={"kind": kind, "subject": subject}, headers=auth
    )


def _raise(client: TestClient, auth: dict[str, str], **body: Any) -> Any:
    return client.post("/api/dashboard/raise", json=body, headers=auth)


def _audits(client: TestClient) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = list(
            session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "hub_raised")
            ).scalars()
        )
        session.expunge_all()
        return rows


class TestTheDraftCarriesTheEvidence:
    def test_a_failing_lane_names_its_last_builds_shas_and_raw_output(
        self, client: TestClient, viewer_auth: dict[str, str], lane: str
    ) -> None:
        response = _draft(client, viewer_auth, "lane", lane)
        assert response.status_code == 200, response.text
        draft = response.json()
        assert "sast" in draft["title"] and REPO in draft["title"]
        evidence = draft["evidence"]
        # The last three builds, newest first, each with sha, status and run.
        assert "3" * 12 in evidence and "1" * 12 in evidence
        assert "failure" in evidence
        assert RAW in evidence
        assert f"https://github.com/{REPO}/actions/runs/990013" in evidence

    def test_a_finding_names_its_rule_location_and_newest_scan(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        lane: str,
        auth: dict[str, str],
        run_compaction: Any,
        catalog: Any,
    ) -> None:
        from tests.conftest import finding_payload, post_findings, post_scan

        post_scan(client, auth, scan_run_id="run-f", commit_sha="f" * 40)
        post_findings(
            client, auth, [finding_payload(rule_id="CWE-89", severity="high")], scan_run_id="run-f"
        )
        run_compaction()
        finding_id = catalog.query("SELECT finding_id FROM findings LIMIT 1")[0][0]

        draft = _draft(client, viewer_auth, "finding", finding_id).json()

        assert "CWE-89" in draft["title"]
        assert "high" in draft["evidence"]
        assert finding_id in draft["evidence"]
        assert REPO in draft["evidence"]

    def test_a_health_dependency_names_its_check(
        self, client: TestClient, viewer_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos import raise_to_hub
        from mykronos.jobs import ReachabilityResult

        async def checks(settings: Any) -> list[tuple[str, Any]]:
            return [("vault", ReachabilityResult(reachable=False, detail="sealed"))]

        monkeypatch.setattr(raise_to_hub, "self_check", checks)
        draft = _draft(client, viewer_auth, "health", "vault").json()
        assert "vault" in draft["title"]
        assert "unreachable" in draft["evidence"] and "sealed" in draft["evidence"]

    def test_an_unknown_subject_is_404(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        assert _draft(client, viewer_auth, "finding", "no-such-finding").status_code == 404
        assert _draft(client, viewer_auth, "lane", f"{REPO}:never").status_code == 404


class TestRaising:
    def test_an_incident_carries_the_evidence_and_is_attributed(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        response = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["hub_kind"] == "incident" and body["hub_id"] == 901

        sent = hub.incidents[901]
        assert sent["room"] == "devops"
        assert RAW in sent["detail"]
        # The evidence is the backend's, and the raiser is named in it.
        assert "Raised from MyKronos by" in sent["detail"]
        assert sent["source_ref"] == f"mykronos:lane:{lane}"

        [entry] = _audits(client)
        assert entry.entity_type == "lane" and entity_id(entry) == lane
        assert entry.detail["hub_id"] == 901 and entry.detail["hub_kind"] == "incident"
        assert entry.actor_kind == "human"

    def test_a_story_goes_to_the_backlog_with_the_note(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        response = _raise(
            client,
            admin_auth,
            kind="lane",
            subject=lane,
            raise_as="story",
            title="sast lane red",
            note="Seen on the repo page.",
        )
        assert response.status_code == 201, response.text
        sent = hub.created[response.json()["hub_id"]]
        assert sent["bucket"] == "backlog"
        assert sent["title"] == "sast lane red"
        assert "Seen on the repo page." in sent["detail"] and RAW in sent["detail"]
        assert f"repo:{REPO}" in sent["tags"]

    def test_an_agent_is_attributed_as_an_agent(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        minted = client.post(
            "/api/agents/credentials",
            json={"family": "claude-opus-5.5", "purpose": "triage"},
            headers=admin_auth,
        ).json()
        agent = {"Authorization": f"Bearer {minted['token']}"}

        response = _raise(client, agent, kind="lane", subject=lane, raise_as="incident")

        assert response.status_code == 201, response.text
        [entry] = _audits(client)
        assert entry.actor == minted["actor"]
        assert entry.actor_kind == "agent"
        assert minted["actor"] in hub.incidents[response.json()["hub_id"]]["detail"]

    def test_a_viewer_cannot_raise(
        self, client: TestClient, viewer_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        response = _raise(client, viewer_auth, kind="lane", subject=lane, raise_as="incident")
        assert response.status_code == 403
        assert hub.incidents == {} and _audits(client) == []

    def test_thehub_not_connected_says_so(
        self, client: TestClient, admin_auth: dict[str, str], lane: str
    ) -> None:
        client.app.state.hub = None  # type: ignore[attr-defined]
        response = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")
        assert response.status_code == 503
        assert "not connected" in response.json()["detail"]
        assert _audits(client) == []

    def test_a_hub_refusal_is_passed_on_and_nothing_is_linked(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        hub.failing.add("/api/incidents")
        response = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")
        assert response.status_code == 502
        assert "TheHub" in response.json()["detail"]
        assert _audits(client) == []


class TestTheRowShowsTheLink:
    def test_the_linked_hub_id_and_its_live_status(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        hub_id = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident").json()[
            "hub_id"
        ]
        hub.incidents[hub_id]["status"] = "acknowledged"

        body = client.get(
            "/api/dashboard/raised",
            params={"kind": "lane", "subject": [lane, f"{REPO}:sca"]},
            headers=admin_auth,
        ).json()

        links = {link["subject"]: link for link in body["links"]}
        assert set(links) == {lane}
        assert links[lane]["hub_id"] == hub_id
        assert links[lane]["hub_kind"] == "incident"
        assert links[lane]["status"] == "acknowledged"
        assert links[lane]["raised_by"]

    def test_an_unreadable_status_is_unknown_not_blank(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        hub_id = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident").json()[
            "hub_id"
        ]
        hub.failing.add(f"/api/incidents/{hub_id}")

        body = client.get(
            "/api/dashboard/raised", params={"kind": "lane", "subject": lane}, headers=admin_auth
        ).json()

        assert body["links"][0]["status"] == "unknown"


def entity_id(entry: AuditLogEntry) -> str:
    return str(entry.entity_id)
