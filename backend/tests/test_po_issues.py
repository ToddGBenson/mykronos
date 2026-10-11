"""The Product Owner tab over GitHub Issues (spec 35 §9, B-072, D-156).

GitHub is the in-memory `FakeGitHubClient`, which enforces the App's
permissions: narrowing them is how these tests prove the tab says why it fell
back to labels, or why it shows no issues, rather than showing an empty board.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos import po_issues
from mykronos import product_owner as po
from mykronos.github.client import OPTIONAL_PERMISSIONS, REQUIRED_PERMISSIONS, FakeGitHubClient
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.po_support import FakeHub, attach_hub, audit_entries, onboard

OWNER = REPO.split("/")[0]

ISSUES_MANIFEST = """
version: 1
name: keel (G0-G5)
spine_map:
  G0: idea
  G1: ready
  G2: ready
  G3: building
  G4: verifying
  G5: shipping
gates:
  - id: G0
    name: Intake
  - id: G1
    name: Ready
    checklist:
      - id: ac
        text: Acceptance criteria
        evidence: acceptance_criteria
      - id: sized
        text: Sized
        evidence: sized
      - id: flags
        text: Flags triaged
  - id: G3
    name: Code Complete
backlog:
  source: github_issues
  labels: [story]
  project: 3
"""


def manifest(text: str = ISSUES_MANIFEST) -> po.ProcessManifest:
    state = po.parse_manifest(text)
    assert state.manifest is not None, state.error
    return state.manifest


def issue(number: int, *labels: str, state: str = "open", **extra: Any) -> dict[str, Any]:
    now = utcnow()
    return {
        "number": number,
        "title": f"Issue {number}",
        "body": extra.pop("body", ""),
        "labels": list(labels),
        "state": state,
        "created_at": extra.pop("created_at", now - timedelta(days=30 - number)),
        "updated_at": extra.pop("updated_at", now),
        "closed_at": now if state == "closed" else None,
        **extra,
    }


@pytest.fixture
def board(client: TestClient, github: FakeGitHubClient) -> Any:
    def _board(issues: list[dict[str, Any]], text: str = ISSUES_MANIFEST) -> str:
        repo_id = onboard(client)
        github.repos[REPO].branches["main"][po.MANIFEST_PATH] = text
        github.repos[REPO].issues = issues
        return repo_id

    return _board


def read(client: TestClient, repo_id: str, auth: dict[str, str]) -> dict[str, Any]:
    response = client.get(f"/api/dashboard/repos/{repo_id}/product-owner", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


class TestManifest:
    def test_github_issues_is_accepted_with_its_settings(self) -> None:
        backlog = manifest().backlog
        assert isinstance(backlog, po.GithubIssuesBacklog)
        assert backlog.labels == ["story"]
        assert backlog.project == 3
        assert backlog.gate_field == "Gate"
        assert backlog.sprint_labels == ["ready"]

    def test_the_settings_are_optional(self) -> None:
        text = ISSUES_MANIFEST.replace("  labels: [story]\n  project: 3\n", "")
        backlog = manifest(text).backlog
        assert isinstance(backlog, po.GithubIssuesBacklog)
        assert backlog.labels == [] and backlog.project is None

    def test_a_tag_is_refused_on_a_github_issues_backlog(self) -> None:
        state = po.parse_manifest(ISSUES_MANIFEST.replace("project: 3", "tag: repo:keel"))
        assert state.state == "invalid"
        assert "unknown key" in (state.error or "")

    def test_any_other_source_is_still_refused(self) -> None:
        state = po.parse_manifest(ISSUES_MANIFEST.replace("github_issues", "jira"))
        assert state.state == "invalid"
        assert "backlog" in (state.error or "")


class TestMapping:
    def test_gate_from_a_project_option(self) -> None:
        m = manifest()
        assert po_issues.gate_from_option("G1 ready", m) == "G1"
        assert po_issues.gate_from_option("g3", m) == "G3"
        assert po_issues.gate_from_option("G9 nowhere", m) is None
        assert po_issues.gate_from_option(None, m) is None

    def test_gate_from_labels_takes_the_furthest(self) -> None:
        m = manifest()
        assert po_issues.gate_from_labels(("gate:G0", "gate:G3", "x"), "gate:", m) == "G3"
        assert po_issues.gate_from_labels(("bug",), "gate:", m) is None

    def test_an_issue_in_the_story_shape(self) -> None:
        m = manifest()
        backlog = m.backlog
        assert isinstance(backlog, po.GithubIssuesBacklog)
        info = po_issues.IssueInfo(
            number=12,
            title="T",
            state="open",
            labels=("story", "gate:G1", "size:S"),
            url="https://github.com/o/r/issues/12",
        )
        story = po_issues.to_story(info, m, backlog, None)
        assert (story["id"], story["ref"], story["gate"], story["gate_name"]) == (
            12,
            "#12",
            "G1",
            "Ready",
        )
        assert (story["spine"], story["size"], story["bucket"]) == ("ready", "S", "backlog")
        # sized passes from the label; AC is in the body, which is not parsed.
        statuses = {i["id"]: i["status"] for i in story["check"]["items"]}
        assert statuses == {"ac": "unavailable", "sized": "passed", "flags": "manual"}


class TestRead:
    def test_project_gates_are_used_when_the_project_is_readable(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient, board: Any
    ) -> None:
        repo_id = board([issue(1, "story", "gate:G0"), issue(2, "story")])
        github.permissions["organization_projects"] = "read"
        github.projects[(OWNER, 3)] = {REPO: {1: "G3 code complete", 2: "G1 ready"}}
        body = read(client, repo_id, admin_auth)
        assert body["backlog_source"] == "github_issues"
        assert body["issues"]["gate_source"] == "project"
        assert body["issues"]["gate_note"] is None
        # The project wins over the label on #1.
        assert {s["ref"]: s["gate"] for s in body["backlog"]} == {"#1": "G3", "#2": "G1"}

    def test_falls_back_to_labels_and_says_why(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient, board: Any
    ) -> None:
        # The default fake App, like the real one, holds no Projects permission.
        assert "organization_projects" not in github.permissions
        repo_id = board([issue(1, "story", "gate:G1")])
        body = read(client, repo_id, admin_auth)
        assert body["issues"]["gate_source"] == "labels"
        assert "organization_projects" in body["issues"]["gate_note"]
        assert "gate:G<n>" in body["issues"]["gate_note"]
        assert body["backlog"][0]["gate"] == "G1"

    def test_backlog_and_sprint_split_on_the_sprint_labels(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        repo_id = board(
            [
                issue(1, "story", "gate:G0"),
                issue(2, "story", "gate:G1", "ready"),
                issue(3, "story", "gate:G3", "ready"),
                issue(4, "story", "ready", state="closed"),
                issue(5, "story", state="closed"),
                issue(6, "bug", "gate:G1"),
            ]
        )
        body = read(client, repo_id, admin_auth)
        # #6 lacks the `story` label; #5 is closed and was never in the sprint.
        assert [s["ref"] for s in body["backlog"]] == ["#1"]
        assert [(s["ref"], s["spine"]) for s in body["sprint"]] == [
            ("#2", "ready"),
            ("#3", "building"),
            ("#4", "done"),
        ]
        assert body["sprint_progress"] == {"done": 1, "committed": 3}
        assert body["sprint"][2]["state"] == "closed"
        assert body["sprint"][0]["url"] == f"https://github.com/{REPO}/issues/2"

    def test_any_sprint_label_puts_an_issue_in_the_sprint(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        text = ISSUES_MANIFEST.replace("  project: 3\n", "  sprint_labels: [ready, sprint]\n")
        repo_id = board(
            [issue(1, "story", "ready"), issue(2, "story", "Sprint"), issue(3, "story")], text
        )
        body = read(client, repo_id, admin_auth)
        assert [s["ref"] for s in body["sprint"]] == ["#1", "#2"]
        assert [s["ref"] for s in body["backlog"]] == ["#3"]
        assert body["issues"]["sprint_labels"] == ["ready", "sprint"]

    def test_backlog_is_ordered_by_gate_then_age(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        old = utcnow() - timedelta(days=60)
        repo_id = board(
            [
                issue(1, "story", "gate:G0", created_at=old),
                issue(2, "story", "gate:G1"),
                issue(3, "story", "gate:G1", created_at=old),
                issue(4, "story"),
            ]
        )
        body = read(client, repo_id, admin_auth)
        assert [s["ref"] for s in body["backlog"]] == ["#3", "#2", "#1", "#4"]
        assert body["backlog"][3]["gate"] == "none"

    def test_ready_issues_with_manual_items_need_a_human(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        repo_id = board([issue(2, "story", "gate:G1", "size:M")])
        body = read(client, repo_id, admin_auth)
        assert [(n["kind"], n["story_id"]) for n in body["needs_human"]] == [
            ("ready_manual_item", 2)
        ]

    def test_without_issues_read_the_tab_says_so(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient, board: Any
    ) -> None:
        github.permissions = {
            k: v
            for k, v in {**REQUIRED_PERMISSIONS, **OPTIONAL_PERMISSIONS}.items()
            if k != "issues"
        }
        repo_id = board([issue(1, "story")])
        body = read(client, repo_id, admin_auth)
        assert body["hub"]["connected"] is False
        assert "issues: read" in body["hub"]["error"]
        assert body["backlog"] == [] and body["sprint"] == []

    def test_thehub_is_not_asked(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        repo_id = board([issue(1, "story")])
        hub = FakeHub([])
        attach_hub(client, hub)
        read(client, repo_id, admin_auth)
        assert not [c for c in hub.calls if c[1] == "/api/dev/stories"]

    def test_a_thehub_backlog_is_unchanged(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        text = ISSUES_MANIFEST.replace(
            "  source: github_issues\n  labels: [story]\n  project: 3\n",
            "  source: thehub\n  tag: repo:payments-api\n",
        )
        repo_id = board([issue(1, "story")], text)
        hub = FakeHub(
            [
                {
                    "id": 9,
                    "title": "Hub",
                    "bucket": "backlog",
                    "gate": "intake",
                    "tags": ["repo:payments-api"],
                }
            ]
        )
        attach_hub(client, hub)
        body = read(client, repo_id, admin_auth)
        assert body["backlog_source"] == "thehub"
        assert body["writes_refused"] is None and body["issues"] is None
        assert body["can_write"] is True
        assert [s["id"] for s in body["backlog"]] == [9]


class TestWritesRefused:
    @pytest.mark.parametrize(
        ("path", "payload", "action"),
        [
            ("stories/2/pull", None, "po.sprint_pull"),
            ("stories/2/return", None, "po.return_to_backlog"),
            ("rank", {"story_id": 2, "direction": "up"}, "po.rank"),
        ],
    )
    def test_every_write_is_refused_and_audited(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        board: Any,
        path: str,
        payload: dict[str, Any] | None,
        action: str,
    ) -> None:
        repo_id = board([issue(2, "story", "gate:G1")])
        hub = FakeHub([])
        attach_hub(client, hub)
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/{path}",
            headers=admin_auth,
            json=payload,
        )
        assert response.status_code == 409
        assert "./keel sprint" in response.json()["detail"]
        assert "ADR 0093" in response.json()["detail"]
        assert hub.calls == []  # TheHub was never asked
        entries = audit_entries(client, action)
        assert [e.detail["outcome"] for e in entries] == ["refused_read_only_source"]

    def test_the_read_says_writes_are_refused(
        self, client: TestClient, admin_auth: dict[str, str], board: Any
    ) -> None:
        body = read(client, board([issue(2, "story")]), admin_auth)
        assert body["can_write"] is False
        assert body["writes_refused"] == po_issues.WRITES_REFUSED


class TestRestClient:
    """The live client's GitHub shapes, over a mock transport."""

    def _client(self, handler: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
        from mykronos.github import client as gh

        rest = gh.RestGitHubClient.__new__(gh.RestGitHubClient)
        rest.base_url = "https://api.github.test"

        async def request(method: str, path: str, **kwargs: Any) -> httpx2.Response:
            return handler(method, path, kwargs)

        async def json_call(method: str, path: str, **kwargs: Any) -> Any:
            return handler(method, path, kwargs).json()

        monkeypatch.setattr(rest, "_request", request, raising=False)
        monkeypatch.setattr(rest, "_json", json_call, raising=False)
        return rest

    async def test_pull_requests_are_not_issues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(method: str, path: str, kwargs: dict[str, Any]) -> httpx2.Response:
            assert kwargs["params"]["labels"] == "story,ready"
            return httpx2.Response(
                200,
                json=[
                    {
                        "number": 1,
                        "title": "i",
                        "state": "open",
                        "labels": [{"name": "story"}],
                        "created_at": "2026-10-01T00:00:00Z",
                        "html_url": "u",
                    },
                    {"number": 2, "title": "p", "state": "open", "labels": [], "pull_request": {}},
                ],
            )

        rest = self._client(handler, monkeypatch)
        issues = await rest.list_issues("o/r", labels=["story", "ready"])
        assert [(i.number, i.labels) for i in issues] == [(1, ("story",))]
        assert issues[0].created_at == datetime(2026, 10, 1)

    async def test_an_issues_404_is_the_apps_permission(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos.github.client import PermissionDeniedError

        rest = self._client(lambda *_: httpx2.Response(404, json={}), monkeypatch)
        with pytest.raises(PermissionDeniedError, match="issues: read"):
            await rest.list_issues("o/r")

    async def test_an_invisible_project_is_permission_denied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos.github.client import PermissionDeniedError

        body = {"data": {"repositoryOwner": {"projectV2": None}}, "errors": [{"type": "NOT_FOUND"}]}
        rest = self._client(lambda *_: httpx2.Response(200, json=body), monkeypatch)
        with pytest.raises(PermissionDeniedError, match="NOT_FOUND"):
            await rest.project_field_values("o", 3, "Gate")

    async def test_project_values_by_repository(self, monkeypatch: pytest.MonkeyPatch) -> None:
        body = {
            "data": {
                "repositoryOwner": {
                    "projectV2": {
                        "items": {
                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                            "nodes": [
                                {
                                    "content": {
                                        "number": 4,
                                        "repository": {"nameWithOwner": "o/r"},
                                    },
                                    "fieldValueByName": {"name": "G2 designed"},
                                },
                                {
                                    "content": {
                                        "number": 5,
                                        "repository": {"nameWithOwner": "o/r"},
                                    },
                                    "fieldValueByName": None,
                                },
                                {"content": {}, "fieldValueByName": {"name": "G1 ready"}},
                            ],
                        }
                    }
                }
            }
        }
        rest = self._client(lambda *_: httpx2.Response(200, json=body), monkeypatch)
        assert await rest.project_field_values("o", 3, "Gate") == {"o/r": {4: "G2 designed"}}
