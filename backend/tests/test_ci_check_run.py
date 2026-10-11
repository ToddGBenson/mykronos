"""`Concourse / thehub`: a pipeline's verdict on a commit, as a check run (D-136).

Concourse reports a job's start and end to `POST /api/ingest/check-runs`, and
the platform posts one GitHub check run per commit through the App. These pin
the contract: the repository's own token, its own repository only, one check
run per commit however many reports arrive, and no raw error text back.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.db.models import AuditLogEntry, CiCheckRun
from mykronos.github import FakeGitHubClient
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard

SHA = "0123456789abcdef0123456789abcdef01234567"
NAME = "Concourse / payments-api"
URL = "/api/ingest/check-runs"


def _post(client: TestClient, token: str, **overrides: Any):
    body: dict[str, Any] = {
        "repo_full_name": REPO,
        "commit_sha": SHA,
        "job": "unit",
        "phase": "start",
        **overrides,
    }
    return client.post(URL, json=body, headers={"Authorization": f"Bearer {token}"})


def _runs(github: FakeGitHubClient) -> list[dict[str, Any]]:
    return [r for r in github.repos[REPO].check_runs if r["name"] == NAME]


class TestAuth:
    def test_no_token_is_401(self, client: TestClient, github: FakeGitHubClient) -> None:
        response = client.post(URL, json={"repo_full_name": REPO})

        assert response.status_code == 401
        assert _runs(github) == []

    def test_an_unknown_token_is_401(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)

        response = _post(client, "not-a-real-token")

        assert response.status_code == 401
        assert _runs(github) == []

    def test_a_token_cannot_post_for_another_repository(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        github.add_repo("example-org/other")
        onboard(client, admin_auth, repo="example-org/other")
        token = issue_token(client, REPO)

        response = _post(client, token, repo_full_name="example-org/other")

        assert response.status_code == 403
        assert github.repos["example-org/other"].check_runs == []

    def test_no_capability_grant_is_needed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """A build's verdict is not a capability, as with `/lane-failure`."""
        onboard(client, admin_auth)
        token = issue_token(client, REPO)  # deliberately no grants

        assert _post(client, token).status_code == 200


class TestValidation:
    def test_a_start_cannot_carry_a_conclusion(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        assert _post(client, token, conclusion="success").status_code == 422

    def test_an_end_must_carry_one(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        assert _post(client, token, phase="end").status_code == 422

    def test_only_success_or_failure(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        assert _post(client, token, phase="end", conclusion="neutral").status_code == 422

    def test_a_short_or_symbolic_sha_is_refused(self, client: TestClient) -> None:
        token = issue_token(client, REPO)

        assert _post(client, token, commit_sha="HEAD").status_code == 422
        assert _post(client, token, commit_sha="abc1234").status_code == 422


class TestOneCheckRunPerCommit:
    def test_start_posts_in_progress_under_the_pipelines_name(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        body = _post(client, token).json()

        assert body["name"] == NAME
        assert body["status"] == "in_progress"
        assert body["outcome"] == "created"
        (run,) = _runs(github)
        assert run["head_sha"] == SHA
        assert run["conclusion"] is None  # in_progress

    def test_start_then_end_updates_the_same_run(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        started = _post(client, token).json()
        ended = _post(
            client, token, job="oracle-gate", phase="end", conclusion="success"
        ).json()

        assert ended["check_run_id"] == started["check_run_id"]
        assert ended["outcome"] == "updated"
        (run,) = _runs(github)
        assert run["conclusion"] == "success"
        assert ("update_check_run", f"{REPO}#{started['check_run_id']}") in github.calls

    def test_a_lane_failure_is_a_failure_conclusion(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        _post(client, token)
        body = _post(client, token, job="sast", phase="end", conclusion="failure").json()

        assert body["conclusion"] == "failure"
        (run,) = _runs(github)
        assert run["conclusion"] == "failure"
        assert "sast" in run["title"]

    def test_a_re_run_that_passes_replaces_the_failure(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        _post(client, token)
        _post(client, token, job="sast", phase="end", conclusion="failure")
        again = _post(client, token).json()  # the re-run's start
        _post(client, token, job="oracle-gate", phase="end", conclusion="success")

        assert again["outcome"] == "unchanged"
        assert again["conclusion"] == "failure"  # a start does not reopen a verdict
        (run,) = _runs(github)
        assert run["conclusion"] == "success"

    def test_an_end_with_no_start_still_posts_one(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        _post(client, token, job="unit", phase="end", conclusion="failure")
        _post(client, token, job="sast", phase="end", conclusion="failure")

        (run,) = _runs(github)
        assert run["conclusion"] == "failure"

    def test_another_commit_is_another_run(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        _post(client, token)
        _post(client, token, commit_sha="f" * 40)

        assert {r["head_sha"] for r in _runs(github)} == {SHA, "f" * 40}

    def test_the_run_and_an_audit_entry_are_recorded(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)

        _post(client, token)
        _post(client, token, job="oracle-gate", phase="end", conclusion="success")

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            (row,) = session.execute(select(CiCheckRun)).scalars().all()
            entries = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.entity_type == "ci_check_run")
            ).scalars().all()
        assert (row.status, row.conclusion, row.last_job) == ("completed", "success", "oracle-gate")
        assert [e.action for e in entries] == ["ci_check_run.posted", "ci_check_run.posted"]
        assert entries[-1].actor == f"ingest:{REPO}"
        assert entries[-1].detail["conclusion"] == "success"


class TestNoCheckRunIsVisible:
    def test_a_repository_with_no_installation_is_409(
        self, client: TestClient, github: FakeGitHubClient
    ) -> None:
        token = issue_token(client, REPO)  # never onboarded

        response = _post(client, token)

        assert response.status_code == 409
        assert _runs(github) == []

    def test_a_github_refusal_is_502_with_no_raw_error(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client, admin_auth)
        token = issue_token(client, REPO)
        github.permissions.pop("checks")

        response = _post(client, token)

        assert response.status_code == 502
        detail = response.json()["detail"]
        # The fake's refusal names the missing permission; none of it leaks.
        assert "checks: write" not in detail and "D-008" not in detail
        assert _runs(github) == []
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            failed = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "ci_check_run.post_failed")
            ).scalars().all()
            assert session.execute(select(CiCheckRun)).first() is None
        assert len(failed) == 1
