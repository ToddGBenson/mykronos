"""The Product Owner tab (spec 35 §6).

TheHub is mocked with `httpx2.MockTransport`, so every call the tab makes to
it is recorded in order -- which is what the sprint-pull tests are about. The
order of the autonomy toggle and the move is the safety property of the
feature, and a test that only checked the end state could pass with the calls
the wrong way round.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos import product_owner as po
from mykronos.db.models import AuditLogEntry, Organization, RepoOnboarding
from tests.conftest import INSTALLATION, REPO

VALID = """
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
    doc: process/gates/g1-ready.md
    story_gates: [clarified, designed]
    checklist:
      - id: ac-binary
        text: Acceptance criteria are binary and observable
        evidence: acceptance_criteria
      - id: sized
        text: Sized
        evidence: sized
      - id: reviewed
        text: A second person read it
  - id: G2
    name: Building
    story_gates: [ready, in_progress]
    checklist:
      - id: ac
        text: Has acceptance criteria
        evidence: acceptance_criteria
backlog:
  source: thehub
  tag: repo:payments-api
  include_untagged: false
delivery:
  summary: PR to main
  steps: [pr, human-merge]
automation_policy:
  - id: P1
    text: Credential is the CLI login
    met: true
docs:
  - {label: Roles, path: docs/01-roles.md}
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
        "created_at": "2026-10-01T00:00:00",
        "updated_at": "2026-10-02T00:00:00",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# Manifest validation
# --------------------------------------------------------------------------


class TestManifest:
    def test_a_valid_manifest_parses(self) -> None:
        state = po.parse_manifest(VALID)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        assert state.manifest.gates[0].checklist[0].evidence == "acceptance_criteria"
        assert state.manifest.backlog.tag == "repo:payments-api"

    def test_an_unknown_key_is_refused(self) -> None:
        """A typo is reported, not silently ignored."""
        state = po.parse_manifest(VALID + "\nautomation_polcy: []\n")
        assert state.state == "invalid"
        assert state.manifest is None
        assert "automation_polcy" in (state.error or "")
        assert "unknown key" in (state.error or "")

    def test_an_unknown_nested_key_is_refused(self) -> None:
        state = po.parse_manifest(VALID.replace("recommends:", "recomends:"))
        assert state.state == "invalid"
        assert "recomends" in (state.error or "")

    def test_an_unknown_evidence_key_is_refused(self) -> None:
        state = po.parse_manifest(VALID.replace("evidence: sized", "evidence: vibes"))
        assert state.state == "invalid"

    def test_a_doc_link_must_stay_inside_the_repository(self) -> None:
        """Rendered as a link, so a scheme or a traversal must not get through."""
        for bad in ("javascript:alert(1)", "../../etc/passwd", "/abs/path", "https://x.test"):
            text = VALID.replace("docs/01-roles.md", bad)
            assert po.parse_manifest(text).state == "invalid", bad

    def test_yaml_that_does_not_parse_is_invalid_not_absent(self) -> None:
        state = po.parse_manifest("version: [1\n")
        assert state.state == "invalid"
        assert "YAML" in (state.error or "")

    def test_this_repositorys_own_manifest_is_valid(self) -> None:
        """MyKronos declares its own process (D-132), and the tab must not
        show its own repository's manifest as invalid."""
        text = (Path(__file__).resolve().parents[2] / ".sdlc" / "process.yaml").read_text(
            encoding="utf-8"
        )
        state = po.parse_manifest(text)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        assert state.manifest.backlog.tag == "repo:mykronos"
        assert state.manifest.backlog.include_untagged is False

    def test_an_absent_manifest_yields_absent_and_the_default_spine(self) -> None:
        state = po.parse_manifest(None)
        assert state.state == "absent"
        assert state.spine_is_default is True
        assert po.spine_step(story(gate="intake"), None) == "idea"
        assert po.spine_step(story(gate="in_progress"), None) == "building"
        assert po.spine_step(story(gate="verified"), None) == "done"


# --------------------------------------------------------------------------
# Gate checks
# --------------------------------------------------------------------------


class TestGateChecks:
    def test_each_evidence_key_passes_and_fails(self) -> None:
        cases = {
            "acceptance_criteria": (
                story(acceptance_criteria=["x"]),
                story(acceptance_criteria=[]),
            ),
            "detail_500": (story(detail="x" * 500), story(detail="x" * 499)),
            "sized": (story(size="M"), story(size=None)),
            "sprint": (story(bucket="sprint"), story(bucket="backlog")),
            "threat_model": (
                story(inception_draft={"threat_model_md": ""}),
                story(inception_draft={"clear_value_md": "x"}),
            ),
        }
        for key, (passing, failing) in cases.items():
            assert po.check_evidence(key, passing) == "passed", key
            assert po.check_evidence(key, failing) == "failed", key

    def test_an_item_with_no_evidence_key_is_manual(self) -> None:
        assert po.check_evidence(None, story()) == "manual"

    def test_a_threat_model_the_hub_did_not_send_is_unavailable_not_failed(self) -> None:
        """TheHub's story response does not carry inception_draft today."""
        assert po.check_evidence("threat_model", story()) == "unavailable"

    def test_a_story_is_checked_against_the_gate_covering_its_hub_gate(self) -> None:
        manifest = po.parse_manifest(VALID).manifest
        check = po.check_story(story(gate="designed", size=None), manifest)
        assert check.gate_name == "Ready"
        assert (check.passed, check.failed, check.manual, check.total) == (1, 1, 1, 2)
        assert po.spine_step(story(gate="designed"), manifest) == "ready"
        assert po.spine_step(story(gate="in_progress"), manifest) == "building"


# --------------------------------------------------------------------------
# Repository membership
# --------------------------------------------------------------------------


class TestMembership:
    def test_by_tag(self) -> None:
        assert po.belongs(story(tags=["repo:keel"]), "repo:keel", False)
        assert not po.belongs(story(tags=["repo:thehub"]), "repo:keel", False)
        assert not po.belongs(story(tags=[]), "repo:keel", False)

    def test_include_untagged_takes_stories_with_no_repo_tag(self) -> None:
        """TheHub's own stories carry no repo tag at all."""
        assert po.belongs(story(tags=[]), "repo:thehub", True)
        assert po.belongs(story(tags=["security"]), "repo:thehub", True)
        assert not po.belongs(story(tags=["repo:keel"]), "repo:thehub", True)

    def test_the_default_tag_is_the_repository_name(self) -> None:
        assert po.default_tag("ToddGBenson/TheHub") == "repo:thehub"


# --------------------------------------------------------------------------
# A fake TheHub
# --------------------------------------------------------------------------


class FakeHub:
    """Records every request, in order, and answers from a story table."""

    def __init__(self, stories: list[dict[str, Any]]) -> None:
        self.stories = {s["id"]: dict(s) for s in stories}
        self.calls: list[tuple[str, str, Any]] = []
        self.toggle_status = 200
        self.move_status = 200
        self.move_detail: Any = None
        self.rank_status = 200
        self.rank_detail: Any = None
        self.tokens: list[str | None] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body))
        self.tokens.append(request.headers.get("X-Hub-Token"))
        path = request.url.path
        if request.method == "GET" and path == "/api/dev/stories":
            bucket = request.url.params.get("bucket")
            return httpx2.Response(
                200, json=[s for s in self.stories.values() if s["bucket"] == bucket]
            )
        if request.method == "GET" and path.startswith("/api/dev/stories/"):
            sid = int(path.rsplit("/", 1)[-1])
            if sid not in self.stories:
                return httpx2.Response(404, json={"detail": "Story not found"})
            return httpx2.Response(200, json=self.stories[sid])
        if request.method == "PATCH" and path.startswith("/api/dev/stories/"):
            # TheHub's `po_rank` (migration 329): the only field the tab sends.
            sid = int(path.rsplit("/", 1)[-1])
            if self.rank_status != 200:
                return httpx2.Response(self.rank_status, json={"detail": self.rank_detail})
            self.stories[sid].update(body)
            return httpx2.Response(200, json=self.stories[sid])
        if path.endswith("/toggle-autonomy"):
            sid = int(path.split("/")[-2])
            if self.toggle_status != 200:
                return httpx2.Response(self.toggle_status, json={"detail": "story not found"})
            self.stories[sid]["autonomy_disabled"] = body["autonomy_disabled"]
            return httpx2.Response(200, json={"autonomy_disabled": body["autonomy_disabled"]})
        if path.endswith("/move"):
            sid = int(path.split("/")[-2])
            if self.move_status != 200:
                return httpx2.Response(self.move_status, json={"detail": self.move_detail})
            self.stories[sid]["bucket"] = body["bucket"]
            return httpx2.Response(200, json=self.stories[sid])
        return httpx2.Response(404, json={"detail": "Not Found"})

    def writes(self) -> list[tuple[str, Any]]:
        return [(path, body) for method, path, body in self.calls if method == "POST"]

    def patches(self) -> list[tuple[str, Any]]:
        return [(path, body) for method, path, body in self.calls if method == "PATCH"]


def onboard(client: TestClient) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        org = Organization(github_org_login=REPO.split("/")[0])
        session.add(org)
        session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=REPO,
            github_installation_id=INSTALLATION,
            status="active",
            enabled_capabilities=["sast"],
            default_branch="main",
        )
        session.add(row)
        session.flush()
        return row.id


@pytest.fixture
def connect(client: TestClient, github: Any) -> Callable[..., tuple[str, FakeHub]]:
    def _connect(
        stories: list[dict[str, Any]], manifest: str | None = VALID
    ) -> tuple[str, FakeHub]:
        repo_id = onboard(client)
        if manifest is not None:
            github.repos[REPO].branches["main"][po.MANIFEST_PATH] = manifest
        hub = FakeHub(stories)
        client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
            "http://hub.test", "hub-secret", transport=httpx2.MockTransport(hub.handler)
        )
        return repo_id, hub

    return _connect


def audit_entries(client: TestClient, action: str) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = session.query(AuditLogEntry).filter(AuditLogEntry.action == action).all()
        session.expunge_all()
        return rows


# --------------------------------------------------------------------------
# The read
# --------------------------------------------------------------------------


class TestTheTab:
    def test_it_shows_the_repositorys_own_stories_only(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect(
            [
                story(id=1),
                story(id=2, tags=["repo:keel"]),
                story(id=3, bucket="sprint", gate="in_progress"),
            ]
        )
        response = client.get(f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["manifest"]["state"] == "valid"
        assert [s["id"] for s in body["backlog"]] == [1]
        assert [s["id"] for s in body["sprint"]] == [3]
        assert body["sprint"][0]["spine"] == "building"
        assert body["counts"]["ready"] == 1 and body["counts"]["building"] == 1
        assert body["can_write"] is True
        assert set(hub.tokens) == {"hub-secret"}

    def test_an_absent_manifest_says_so_and_uses_the_default_spine(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()
        assert body["manifest"]["state"] == "absent"
        assert body["manifest"]["manifest"] is None
        assert body["spine_is_default"] is True
        assert body["membership_source"] == "default"
        assert body["backlog_tag"] == "repo:payments-api"

    def test_an_invalid_manifest_is_shown_as_invalid_and_needs_a_human(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=VALID + "\nbogus: 1\n")
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()
        assert body["manifest"]["state"] == "invalid"
        assert body["manifest"]["manifest"] is None
        assert "bogus" in body["manifest"]["error"]
        assert body["needs_human"][0]["kind"] == "invalid_manifest"

    def test_needs_a_human_lists_failing_sprint_stories_and_manual_ready_items(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect(
            [
                story(id=1, gate="designed"),
                story(id=2, bucket="sprint", gate="ready", acceptance_criteria=[]),
            ]
        )
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()
        kinds = {(n["kind"], n["story_id"]) for n in body["needs_human"]}
        assert ("sprint_gate_failed", 2) in kinds
        assert ("ready_manual_item", 1) in kinds

    def test_no_hub_means_not_connected_and_the_manifest_still_shows(
        self, client: TestClient, admin_auth: dict[str, str], github: Any
    ) -> None:
        repo_id = onboard(client)
        github.repos[REPO].branches["main"][po.MANIFEST_PATH] = VALID
        client.app.state.hub = None  # type: ignore[attr-defined]
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()
        assert body["hub"] == {"connected": False, "error": "TheHub is not connected."}
        assert body["manifest"]["state"] == "valid"
        assert body["backlog"] == []

    def test_an_unreachable_hub_never_leaks_the_exception(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client)

        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connect to http://hub.test:8000 secret-detail")

        client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
            "http://hub.test", "t", transport=httpx2.MockTransport(refuse)
        )
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()
        assert body["hub"] == {"connected": False, "error": "TheHub could not be reached."}
        assert "secret-detail" not in json.dumps(body)

    def test_a_viewer_reads_the_tab_without_write_rights(
        self, client: TestClient, viewer_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect([story(id=1)])
        response = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=viewer_auth
        )
        assert response.status_code == 200
        assert response.json()["can_write"] is False


# --------------------------------------------------------------------------
# Sprint pull order
# --------------------------------------------------------------------------


class TestSprintPull:
    def _pull(self, client: TestClient, repo_id: str, sid: int, auth: dict[str, str]) -> Any:
        return client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/stories/{sid}/pull", headers=auth
        )

    def test_the_autonomy_toggle_runs_before_the_move(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7)])
        response = self._pull(client, repo_id, 7, admin_auth)
        assert response.status_code == 200, response.text
        assert hub.writes() == [
            ("/api/devops/autonomy/stories/7/toggle-autonomy", {"autonomy_disabled": True}),
            ("/api/dev/stories/7/move", {"bucket": "sprint"}),
        ]
        assert hub.stories[7]["bucket"] == "sprint"
        assert hub.stories[7]["autonomy_disabled"] is True

    def test_if_the_toggle_fails_no_move_happens(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7)])
        hub.toggle_status = 403
        response = self._pull(client, repo_id, 7, admin_auth)
        assert response.status_code == 409
        assert [path for path, _ in hub.writes()] == [
            "/api/devops/autonomy/stories/7/toggle-autonomy"
        ]
        assert hub.stories[7]["bucket"] == "backlog"

    def test_if_the_move_fails_autonomy_stays_off_and_the_refusal_is_shown(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7)])
        hub.move_status = 400
        hub.move_detail = {
            "error": "inception_checklist_incomplete",
            "missing_fields": ["threat_model_md"],
        }
        response = self._pull(client, repo_id, 7, admin_auth)
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "inception_checklist_incomplete" in detail
        assert "threat_model_md" in detail
        assert "autonomy off" in detail
        assert hub.stories[7]["bucket"] == "backlog"
        assert hub.stories[7]["autonomy_disabled"] is True
        # Never retried.
        assert len(hub.writes()) == 2

    def test_a_string_refusal_is_surfaced_verbatim(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7)])
        hub.move_status = 409
        hub.move_detail = "Sprint pull blocked: gate must be >= clarified"
        detail = self._pull(client, repo_id, 7, admin_auth).json()["detail"]
        assert "Sprint pull blocked: gate must be >= clarified" in detail

    def test_another_repositorys_story_cannot_be_pulled_through_this_tab(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7, tags=["repo:keel"])])
        assert self._pull(client, repo_id, 7, admin_auth).status_code == 404
        assert hub.writes() == []

    def test_back_to_backlog_is_one_move(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=8, bucket="sprint")])
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/stories/8/return", headers=admin_auth
        )
        assert response.status_code == 200, response.text
        assert hub.writes() == [("/api/dev/stories/8/move", {"bucket": "backlog"})]


# --------------------------------------------------------------------------
# Auth and audit
# --------------------------------------------------------------------------


class TestAuth:
    def test_a_viewer_cannot_write(
        self, client: TestClient, viewer_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7), story(id=8, bucket="sprint")])
        base = f"/api/dashboard/repos/{repo_id}/product-owner"
        for response in (
            client.post(f"{base}/stories/7/pull", headers=viewer_auth),
            client.post(f"{base}/stories/8/return", headers=viewer_auth),
            client.post(f"{base}/rank", json={"story_id": 7, "direction": "up"},
                        headers=viewer_auth),
        ):
            assert response.status_code == 403
        assert hub.calls == []

    def test_every_write_is_audit_logged(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7), story(id=9), story(id=8, bucket="sprint")])
        base = f"/api/dashboard/repos/{repo_id}/product-owner"
        assert client.post(f"{base}/stories/7/pull", headers=admin_auth).status_code == 200
        assert client.post(f"{base}/stories/8/return", headers=admin_auth).status_code == 200
        assert client.post(
            f"{base}/rank", json={"story_id": 9, "direction": "up"}, headers=admin_auth
        ).status_code == 200

        for action, sid in (("po.sprint_pull", 7), ("po.return_to_backlog", 8), ("po.rank", 9)):
            entries = audit_entries(client, action)
            assert len(entries) == 1, action
            entry = entries[0]
            assert entry.actor == "admin"
            assert entry.entity_id == str(sid)
            assert entry.detail["repo_full_name"] == REPO
            assert entry.detail["story_id"] == sid

    def test_a_refused_write_is_audit_logged_too(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=7)])
        hub.move_status = 400
        hub.move_detail = "nope, not ready"
        client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/stories/7/pull", headers=admin_auth
        )
        (entry,) = audit_entries(client, "po.sprint_pull")
        assert entry.detail["outcome"] == "refused_at_move"
        assert entry.detail["autonomy_disabled"] is True


# --------------------------------------------------------------------------
# Rank
# --------------------------------------------------------------------------


class TestRank:
    def test_unranked_stories_order_by_gate_then_age(self) -> None:
        stories = [
            story(id=1, gate="intake", created_at="2026-01-01"),
            story(id=2, gate="designed", created_at="2026-03-01"),
            story(id=3, gate="designed", created_at="2026-02-01"),
        ]
        assert [s["id"] for s in po.order_backlog(stories, {})] == [3, 2, 1]
        assert [s["id"] for s in po.order_backlog(stories, {1: 1})] == [1, 3, 2]

    def test_rank_is_stored_in_the_hub_and_orders_the_backlog(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect(
            [
                story(id=1, created_at="2026-01-01"),
                story(id=2, created_at="2026-02-01"),
                story(id=3, created_at="2026-03-01"),
            ]
        )
        base = f"/api/dashboard/repos/{repo_id}/product-owner"

        def order() -> list[int]:
            return [s["id"] for s in client.get(base, headers=admin_auth).json()["backlog"]]

        assert order() == [1, 2, 3]
        response = client.post(
            f"{base}/rank", json={"story_id": 3, "direction": "up"}, headers=admin_auth
        )
        assert response.status_code == 200, response.text
        assert order() == [1, 3, 2]
        client.post(f"{base}/rank", json={"story_id": 3, "direction": "up"}, headers=admin_auth)
        assert order() == [3, 1, 2]
        ranks = {
            s["id"]: s["rank"] for s in client.get(base, headers=admin_auth).json()["backlog"]
        }
        assert ranks == {3: 1, 1: 2, 2: 3}
        # The Hub holds it, not MyKronos.
        assert {sid: s["po_rank"] for sid, s in hub.stories.items()} == {3: 1, 1: 2, 2: 3}

    def test_the_rank_is_read_from_the_hub(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect(
            [
                story(id=1, created_at="2026-01-01", po_rank=None),
                story(id=2, created_at="2026-02-01", po_rank=2),
                story(id=3, created_at="2026-03-01", po_rank=1),
            ]
        )
        backlog = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth
        ).json()["backlog"]
        assert [(s["id"], s["rank"]) for s in backlog] == [(3, 1), (2, 2), (1, None)]

    def test_only_changed_positions_are_patched_and_only_po_rank_is_sent(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect(
            [
                story(id=1, created_at="2026-01-01", po_rank=1),
                story(id=2, created_at="2026-02-01", po_rank=2),
                story(id=3, created_at="2026-03-01", po_rank=3),
                story(id=4, created_at="2026-04-01", po_rank=4),
            ]
        )
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 3, "direction": "up"},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        assert hub.patches() == [
            ("/api/dev/stories/3", {"po_rank": 2}),
            ("/api/dev/stories/2", {"po_rank": 3}),
        ]
        assert hub.writes() == []

    def test_a_refused_rank_is_shown_verbatim_and_not_retried(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect(
            [story(id=1, created_at="2026-01-01"), story(id=2, created_at="2026-02-01")]
        )
        hub.rank_status = 422
        hub.rank_detail = "po_rank must be at most 2147483647"
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 2, "direction": "up"},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert response.json()["detail"] == (
            "TheHub refused the rank: po_rank must be at most 2147483647"
        )
        assert len(hub.patches()) == 1
        (entry,) = audit_entries(client, "po.rank")
        assert entry.detail["outcome"] == "refused"
        assert entry.detail["written"] == []
        assert entry.detail["hub_detail"] == "po_rank must be at most 2147483647"

    def test_a_hub_failure_on_rank_is_not_passed_on(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect(
            [story(id=1, created_at="2026-01-01"), story(id=2, created_at="2026-02-01")]
        )
        hub.rank_status = 500
        hub.rank_detail = "Traceback (most recent call last): psycopg.errors..."
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 2, "direction": "up"},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "Traceback" not in response.text
        assert "TheHub failed (HTTP 500)." in response.json()["detail"]

    def test_a_press_that_moves_nothing_writes_nothing(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, hub = connect([story(id=1, created_at="2026-01-01"), story(id=2)])
        client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 1, "direction": "up"},
            headers=admin_auth,
        )
        assert hub.patches() == []
        (entry,) = audit_entries(client, "po.rank")
        assert entry.detail["outcome"] == "unchanged"

    def test_the_top_story_cannot_move_up(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect([story(id=1, created_at="2026-01-01"), story(id=2)])
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 1, "direction": "up"},
            headers=admin_auth,
        )
        assert response.status_code == 200
        assert response.json()["moved"] is False

    def test_a_story_not_in_the_backlog_cannot_be_ranked(
        self, client: TestClient, admin_auth: dict[str, str], connect: Callable[..., Any]
    ) -> None:
        repo_id, _ = connect([story(id=1)])
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/rank",
            json={"story_id": 99, "direction": "down"},
            headers=admin_auth,
        )
        assert response.status_code == 404
