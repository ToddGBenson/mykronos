"""The tests view says whether the tests pass, not only whether they run (TheHub #60922).

On 2026-10-21 every functional upload on main was a failure (incident
#36403), and `GET /repos/{id}/tests` said the functional kind was `observed`
because "the functional lane is reporting runs". Both statements were true;
the answer to the question somebody actually asks -- are they passing? --
was not on the page.

Presence stays: a failing suite is still a suite. What changes is that each
lane carries its latest outcome on its branch, recent counts and when it last
passed, and the evidence sentence stops reading as healthy when it is red.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import test_estate
from tests.conftest import REPO, issue_token, post_scan
from tests.test_onboarding import onboard

PR_BRANCH = "feat/some-change"


def _at(days_ago: float) -> str:
    moment = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=days_ago)
    return moment.isoformat()


def _run(
    client: TestClient,
    auth: dict[str, str],
    run_id: str,
    status: str,
    days_ago: float,
    branch: str = "main",
    capability: str = "functional",
) -> None:
    response = post_scan(
        client,
        auth,
        scan_run_id=run_id,
        capability=capability,
        tool_name="junit",
        branch=branch,
        scan_status=status,
        started_at=_at(days_ago),
        completed_at=_at(days_ago),
    )
    assert response.status_code < 300, response.text


def _estate(client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
    repo_id = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0][
        "repo_id"
    ]
    response = client.get(f"/api/dashboard/repos/{repo_id}/tests", headers=admin_auth)
    assert response.status_code == 200, response.text
    return response.json()


def _lane(body: dict[str, Any], capability: str = "functional") -> dict[str, Any]:
    return next(lane for lane in body["lanes"] if lane["capability"] == capability)


def _kind(body: dict[str, Any], key: str = "functional") -> dict[str, Any]:
    return next(kind for kind in body["kinds"] if kind["key"] == key)


class TestTheIncidentShape:
    def test_a_red_lane_is_observed_and_says_it_is_failing(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """Incident #36403's day: it passed once, then every run on main
        failed. Presence must stay observed; the view must say failing."""
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'functional')}"}
        _run(client, auth, "f-1", "success", days_ago=3)
        _run(client, auth, "f-2", "failure", days_ago=2)
        _run(client, auth, "f-3", "failure", days_ago=1)
        run_compaction()

        body = _estate(client, admin_auth)
        lane = _lane(body)
        kind = _kind(body)

        assert lane["outcome"] == "failing"
        assert lane["outcome_branch"] == "main"
        assert lane["latest_status"] == "failure"
        assert lane["window_passed"] == 1
        assert lane["window_failed"] == 2
        assert lane["last_passed_at"] is not None
        assert lane["last_passed_at"] < lane["latest_run_at"]

        assert kind["presence"] == "observed"
        assert kind["outcome"] == "failing"
        (sentence,) = kind["evidence"]
        assert "failed" in sentence
        assert sentence != "the functional lane is reporting runs"

    def test_a_green_lane_says_so(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'functional')}"}
        _run(client, auth, "f-1", "failure", days_ago=2)
        _run(client, auth, "f-2", "success", days_ago=1)
        run_compaction()

        body = _estate(client, admin_auth)

        assert _lane(body)["outcome"] == "passing"
        assert _kind(body)["outcome"] == "passing"
        assert "passed" in _kind(body)["evidence"][0]


class TestTheOutcomeIsTheDefaultBranch:
    def test_a_green_pull_request_does_not_make_main_look_fixed(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'functional')}"}
        _run(client, auth, "main-1", "failure", days_ago=2)
        _run(client, auth, "pr-1", "success", days_ago=1, branch=PR_BRANCH)
        run_compaction()

        lane = _lane(_estate(client, admin_auth))

        assert lane["outcome"] == "failing"
        assert lane["window_passed"] == 0
        assert lane["last_passed_at"] is None

    def test_a_red_pull_request_does_not_make_main_look_broken(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'functional')}"}
        _run(client, auth, "main-1", "success", days_ago=2)
        _run(client, auth, "pr-1", "failure", days_ago=1, branch=PR_BRANCH)
        run_compaction()

        lane = _lane(_estate(client, admin_auth))

        assert lane["outcome"] == "passing"
        assert lane["window_failed"] == 0


class TestTheWindow:
    def test_runs_older_than_the_window_are_not_counted_but_still_last_passed(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """A lane that last passed a month ago and has failed since must say
        when it last passed, and the window must not count that old pass."""
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'functional')}"}
        _run(client, auth, "old", "success", days_ago=30)
        _run(client, auth, "new", "failure", days_ago=1)
        run_compaction()

        lane = _lane(_estate(client, admin_auth))

        assert lane["window_days"] == test_estate.OUTCOME_WINDOW_DAYS
        assert lane["window_runs"] == 1
        assert lane["window_passed"] == 0
        assert lane["window_failed"] == 1
        assert lane["last_passed_at"] is not None
        assert lane["outcome"] == "failing"


class TestNoRunsIsUnknownNeverPassing:
    def test_a_lane_that_never_ran_is_unknown(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        body = _estate(client, admin_auth)

        for lane in body["lanes"]:
            assert lane["outcome"] == "unknown", lane["capability"]
            assert lane["last_passed_at"] is None
            assert lane["window_runs"] == 0
