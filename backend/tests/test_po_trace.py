"""The delivery trace for one story (spec 35 §8.5, D-146).

Commits come from the fake GitHub's default branch, scans and decisions from
the lake, deploys from the fake TheHub, and the running revision from the
onboarding row the deployment probe writes.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import po_trace
from mykronos.github.client import CommitInfo
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.po_support import connect, story  # noqa: F401
from tests.test_po_console import scan

SID = 60584
FULL = "f" * 40
OTHER = "e" * 40
PROSE = "9" * 40


def commit(sha: str, message: str) -> CommitInfo:
    return CommitInfo(
        sha=sha,
        message=message,
        url=f"https://github.com/{REPO}/commit/{sha}",
        committed_at=datetime.now(UTC) - timedelta(days=1),
    )


def trace(client: TestClient, repo_id: str, auth: dict[str, str], sid: int = SID) -> Any:
    response = client.get(
        f"/api/dashboard/repos/{repo_id}/product-owner/trace",
        params={"story_id": sid},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    return response.json()


def created() -> str:
    return (utcnow() - timedelta(days=10)).isoformat()


class TestTrailer:
    def test_only_the_trailer_credits_a_story(self) -> None:
        body = "fix: the parser\n\nNOT DONE: #60584 still needs a test.\n\nStories: #1 #2\n"
        assert po_trace.trailer_ids(body) == [1, 2]
        assert not po_trace.credits(body, SID)
        assert po_trace.mentions(body, SID)

    def test_a_commit_with_no_trailer_credits_nothing(self) -> None:
        """Unlike TheHub's legacy fallback, a bare #id in prose is not credit."""
        assert po_trace.trailer_ids("feat: builds #60584") is None
        assert not po_trace.credits("feat: builds #60584", SID)

    def test_the_trailer_key_is_a_line_of_its_own(self) -> None:
        assert po_trace.credits("x\n\nstories: #60584, #3", SID)
        assert not po_trace.credits("x\n\nThe Stories: #60584 trailer is missing", SID)


class TestTheTrace:
    def test_the_full_chain_is_linked_to_its_sources(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        github: Any,
        connect: Callable[..., Any],  # noqa: F811
        buffer: Any,
        run_compaction: Callable[[], Any],
    ) -> None:
        repo_id, hub = connect(
            [story(id=SID, bucket="done", gate="verified", created_at=created())],
            deployed_revision=FULL[:12],
        )
        github.repos[REPO].commits = [
            commit(FULL, f"feat: the trace (#77)\n\nStories: #{SID}\n"),
            commit(PROSE, f"docs: why #{SID} is not the Delivery list\n\nStories: #1\n"),
        ]
        buffer.append(
            "scan_runs",
            [
                scan(FULL),
                scan("a" * 40, branch="feat", pr_number=77, triggered_by="pull_request"),
            ],
        )
        run_compaction()
        hub.deploys[SID] = [
            {"id": 3, "deploy_id": "dep-3", "sha": FULL[:12], "final_status": "success"},
            {"id": 4, "deploy_id": "dep-4", "sha": PROSE[:12], "final_status": "success"},
        ]

        body = trace(client, repo_id, admin_auth)["trace"]
        [only] = body["commits"]
        assert only["sha"] == FULL
        assert only["url"] == f"https://github.com/{REPO}/commit/{FULL}"
        assert [(p["number"], p["source"]) for p in only["prs"]] == [(77, "GitHub merge subject")]
        assert {s["of"] for s in only["scans"]} == {"commit", "pull request #77"}
        assert only["scans"][0]["run_url"].endswith("/actions/runs/9900123")
        # Only the deploy of the credited commit: the prose commit's is not
        # this story's, whatever TheHub's loose attribution said.
        assert [d["id"] for d in only["deploys"]] == ["dep-3"]
        assert only["running"] is True
        assert only["missing"] is None
        assert body["first_missing"] is None
        assert body["prose_mentions"] == 1

    def test_the_first_missing_link_is_named(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        github: Any,
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect(
            [story(id=SID, bucket="sprint", gate="in_progress", created_at=created())]
        )
        github.repos[REPO].commits = [commit(FULL, f"feat: part one (#80)\n\nStories: #{SID}")]
        body = trace(client, repo_id, admin_auth)["trace"]
        assert body["links"] == {"commit": True, "pr": True, "scan": False, "deploy": False}
        assert body["first_missing"] == "committed, never scanned"
        assert body["commits"][0]["missing"] == "committed, never scanned"

    def test_a_scanned_commit_never_deployed_says_so(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        github: Any,
        connect: Callable[..., Any],  # noqa: F811
        buffer: Any,
        run_compaction: Callable[[], Any],
    ) -> None:
        repo_id, _ = connect([story(id=SID, bucket="sprint", created_at=created())])
        github.repos[REPO].commits = [commit(OTHER, f"feat: x (#81)\n\nStories: #{SID}")]
        buffer.append("scan_runs", [scan(OTHER)])
        run_compaction()
        body = trace(client, repo_id, admin_auth)["trace"]
        assert body["first_missing"] == "scanned, never deployed"

    def test_a_story_with_no_commit_says_so(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        github: Any,
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=SID, bucket="sprint", created_at=created())])
        github.repos[REPO].commits = [commit(PROSE, f"docs: mentions #{SID} only")]
        body = trace(client, repo_id, admin_auth)["trace"]
        assert body["commits"] == []
        assert body["first_missing"] == "no commit names this story"
        assert body["prose_mentions"] == 1

    def test_github_unreadable_is_not_reported_as_no_commit(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        github: Any,
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=SID, bucket="sprint", created_at=created())])

        async def broken(*args: Any, **kwargs: Any) -> list[CommitInfo]:
            raise RuntimeError("secret upstream detail")

        github.list_commits = broken
        body = trace(client, repo_id, admin_auth)["trace"]
        assert body["first_missing"] == "commits could not be read from GitHub"
        assert body["github_error"] == "Commits on main could not be read from GitHub."
        assert "secret" not in str(body)

    def test_another_repositorys_story_is_not_traced_here(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=SID, tags=["repo:keel"])])
        response = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner/trace",
            params={"story_id": SID},
            headers=admin_auth,
        )
        assert response.status_code == 404

    def test_without_a_story_it_offers_the_sprint_and_recent_closes(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect(
            [
                story(id=1, bucket="sprint"),
                story(id=2, bucket="done", closed_at=created()),
                story(id=3, bucket="backlog"),
            ]
        )
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/product-owner/trace", headers=viewer_auth
        ).json()
        assert [s["id"] for s in body["stories"]] == [1, 2]
        assert body["trace"] is None
