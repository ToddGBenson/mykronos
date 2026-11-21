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
            self.calls.append((request.method, path, None))
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
        assert "unreachable" in draft["evidence"]

    def test_a_health_draft_carries_no_url_or_host(
        self, client: TestClient, viewer_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """self_check's detail is `<url> answered HTTP ...`: the internal
        dependency address. The Hub item carries the name and the status only."""
        from mykronos import raise_to_hub
        from mykronos.jobs import ReachabilityResult

        async def checks(settings: Any) -> list[tuple[str, Any]]:
            return [
                (
                    "vault",
                    ReachabilityResult(
                        reachable=False,
                        url="https://vault.internal.example:8200/v1/sys/health",
                        status_code=503,
                        detail=(
                            "https://vault.internal.example:8200/v1/sys/health "
                            "answered HTTP 503"
                        ),
                    ),
                )
            ]

        monkeypatch.setattr(raise_to_hub, "self_check", checks)
        draft = _draft(client, viewer_auth, "health", "vault").json()

        evidence = draft["evidence"]
        assert "vault" in evidence and "503" in evidence and "unreachable" in evidence
        for leaked in ("http://", "https://", "internal.example", "8200", "/v1/sys"):
            assert leaked not in evidence and leaked not in draft["title"]

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
        assert f"repo:{REPO.rsplit('/', 1)[-1].lower()}" in sent["tags"]
        assert f"repo:{REPO}" not in sent["tags"]

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


class TestAFindingLinksToItsRealRepositoryPage:
    def test_the_evidence_link_names_the_onboarding_id_and_it_resolves(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        lane: str,
        auth: dict[str, str],
        run_compaction: Any,
        catalog: Any,
    ) -> None:
        import re

        from tests.conftest import finding_payload, post_findings, post_scan

        post_scan(client, auth, scan_run_id="run-f", commit_sha="f" * 40)
        post_findings(client, auth, [finding_payload()], scan_run_id="run-f")
        run_compaction()
        finding_id = catalog.query("SELECT finding_id FROM findings LIMIT 1")[0][0]

        evidence = _draft(client, viewer_auth, "finding", finding_id).json()["evidence"]

        match = re.search(r"/repos/([^/\s]+)/findings/" + re.escape(finding_id), evidence)
        assert match, evidence
        repo_id = match.group(1)
        assert repo_id != "-"
        # The id in the link is one the dashboard's own repo routes accept.
        page = client.get(f"/api/dashboard/repos/{repo_id}/coverage", headers=viewer_auth)
        assert page.status_code == 200, page.text
        assert page.json()["repo_full_name"] == REPO


class TestTheRaisedListReadsTheHubOncePerTtl:
    def test_n_subjects_cost_n_reads_then_none_until_the_ttl_passes(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        lane: str,
        hub: RaiseHub,
        buffer: Any,
        run_compaction: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mykronos.api import raise_hub

        clock = [1_000.0]
        monkeypatch.setattr(raise_hub, "_now", lambda: clock[0])
        buffer.append(
            "scan_runs",
            [scan(4, capability="sca", scan_run_id="run-s4", scan_status="failure")],
        )
        run_compaction()
        subjects = [lane, f"{REPO}:sca"]
        for subject in subjects:
            assert _raise(
                client, admin_auth, kind="lane", subject=subject, raise_as="incident"
            ).status_code == 201

        def reads() -> int:
            return len(
                [c for c in hub.calls if c[0] == "GET" and c[1].startswith("/api/incidents/")]
            )

        def page() -> list[dict[str, Any]]:
            response = client.get(
                "/api/dashboard/raised",
                params={"kind": "lane", "subject": subjects},
                headers=admin_auth,
            )
            assert response.status_code == 200, response.text
            return response.json()["links"]

        # Raising reads each incident once to look for an open duplicate; start from there.
        before = reads()
        assert len(page()) == 2
        first = reads() - before
        assert first <= 2
        for _ in range(3):
            assert len(page()) == 2
        assert reads() - before == first, "re-rendering inside the TTL must not read the Hub"

        clock[0] += raise_hub.STATUS_TTL_SECONDS + 1
        assert len(page()) == 2
        assert reads() - before == first + 2

    def test_a_failed_read_is_not_cached(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        lane: str,
        hub: RaiseHub,
    ) -> None:
        hub_id = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident").json()[
            "hub_id"
        ]
        hub.failing.add(f"/api/incidents/{hub_id}")
        params = {"kind": "lane", "subject": lane}
        assert client.get("/api/dashboard/raised", params=params, headers=admin_auth).json()[
            "links"
        ][0]["status"] == "unknown"
        hub.failing.discard(f"/api/incidents/{hub_id}")
        hub.incidents[hub_id]["status"] = "acknowledged"
        assert client.get("/api/dashboard/raised", params=params, headers=admin_auth).json()[
            "links"
        ][0]["status"] == "acknowledged"


class TestOneSubjectIsRaisedOnce:
    def test_two_raises_for_one_source_ref_open_one_incident(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        first = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")
        second = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")

        assert first.status_code == 201 and second.status_code == 200
        assert second.json()["hub_id"] == first.json()["hub_id"]
        assert second.json()["already_raised"] is True
        assert first.json()["already_raised"] is False
        assert len(hub.incidents) == 1
        assert len(_audits(client)) == 1

    def test_an_agent_cannot_file_the_same_incident_twice_either(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        agent = _agent(client, admin_auth)
        _raise(client, agent, kind="lane", subject=lane, raise_as="incident")
        _raise(client, agent, kind="lane", subject=lane, raise_as="incident")
        assert len(hub.incidents) == 1

    def test_a_closed_incident_may_be_raised_again(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        first = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")
        hub.incidents[first.json()["hub_id"]]["status"] = "resolved"

        second = _raise(client, admin_auth, kind="lane", subject=lane, raise_as="incident")

        assert second.status_code == 201
        assert second.json()["hub_id"] != first.json()["hub_id"]
        assert len(hub.incidents) == 2

    def test_a_story_and_an_incident_for_one_subject_are_different_raises(
        self, client: TestClient, admin_auth: dict[str, str], lane: str, hub: RaiseHub
    ) -> None:
        assert _raise(
            client, admin_auth, kind="lane", subject=lane, raise_as="incident"
        ).status_code == 201
        assert _raise(
            client, admin_auth, kind="lane", subject=lane, raise_as="story"
        ).status_code == 201


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    minted = client.post(
        "/api/agents/credentials",
        json={"family": "claude-opus-5.5", "purpose": "raise-limit"},
        headers=admin_auth,
    ).json()
    return {"Authorization": f"Bearer {minted['token']}"}


class TestARaiseIsLimitedPerActor:
    @pytest.fixture
    def lanes(
        self, client: TestClient, buffer: Any, run_compaction: Any, lane: str
    ) -> list[str]:
        buffer.append(
            "scan_runs",
            [
                scan(4, capability="sca", scan_run_id="run-s4", scan_status="failure"),
                scan(5, capability="iac", scan_run_id="run-i5", scan_status="failure"),
            ],
        )
        run_compaction()
        return [lane, f"{REPO}:sca", f"{REPO}:iac"]

    def test_an_actor_over_the_limit_is_refused_with_a_clear_message(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        lanes: list[str],
        hub: RaiseHub,
    ) -> None:
        from mykronos.ratelimit import SlidingWindowLimiter

        client.app.state.raise_limiter = SlidingWindowLimiter(2, 3600.0)  # type: ignore[attr-defined]
        agent = _agent(client, admin_auth)

        codes = [
            _raise(client, agent, kind="lane", subject=subject, raise_as="incident").status_code
            for subject in lanes
        ]

        assert codes == [201, 201, 429]
        assert len(hub.incidents) == 2
        refused = _raise(client, agent, kind="lane", subject=lanes[2], raise_as="incident")
        assert refused.status_code == 429
        assert "Retry-After" in refused.headers
        detail = refused.json()["detail"]
        assert "2" in detail and "hour" in detail
        assert len(_audits(client)) == 2

    def test_one_actors_limit_is_not_anothers(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        lanes: list[str],
        hub: RaiseHub,
    ) -> None:
        from mykronos.ratelimit import SlidingWindowLimiter

        client.app.state.raise_limiter = SlidingWindowLimiter(1, 3600.0)  # type: ignore[attr-defined]
        agent = _agent(client, admin_auth)
        assert _raise(
            client, agent, kind="lane", subject=lanes[0], raise_as="incident"
        ).status_code == 201
        assert _raise(
            client, agent, kind="lane", subject=lanes[1], raise_as="incident"
        ).status_code == 429
        assert _raise(
            client, admin_auth, kind="lane", subject=lanes[1], raise_as="incident"
        ).status_code == 201

    def test_a_duplicate_does_not_spend_the_limit(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        lanes: list[str],
        hub: RaiseHub,
    ) -> None:
        from mykronos.ratelimit import SlidingWindowLimiter

        client.app.state.raise_limiter = SlidingWindowLimiter(1, 3600.0)  # type: ignore[attr-defined]
        for _ in range(3):
            assert _raise(
                client, admin_auth, kind="lane", subject=lanes[0], raise_as="incident"
            ).status_code in (200, 201)
        assert len(hub.incidents) == 1

    def test_the_default_limit_is_a_setting(self, settings: Any) -> None:
        assert settings.hub_filings_per_actor_per_hour >= 1
