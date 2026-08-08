"""Gate outcomes and the shadow-mode report — spec 09 §6, open question 5.

Advisory-by-default is a safety choice, but it is also a measurement: while
Oracle cannot block anything, every `no_go` that merged anyway is a natural
experiment in what blocking mode would have cost. These tests cover the
plumbing that makes that measurable, because the alternative argument for
turning blocking on is "the scanner said so" — which is the argument that
gets security gates switched off.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import deliver, onboard


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


def judge(client, oracle_auth, run_compaction, *, pr_number: int, criticals: int) -> str:
    """Put `criticals` open findings in the lake and score a PR against them."""
    post_scan(client, oracle_auth, scan_run_id=f"scan-{pr_number}")
    post_findings(
        client,
        oracle_auth,
        [
            finding_payload(rule_id=f"R{i}", severity="critical", symbol=f"s{i}")
            for i in range(criticals)
        ],
        scan_run_id=f"scan-{pr_number}",
    )
    run_compaction()

    response = client.post(
        "/api/oracle/evaluate",
        json={
            "decision_type": "pr_gate",
            "commit_sha": f"sha{pr_number}",
            "pr_number": pr_number,
        },
        headers=oracle_auth,
    )
    assert response.status_code == 200, response.text
    run_compaction()
    return response.json()["decision_id"]


def close_pr(client, pr_number: int, *, merged: bool, repo: str = REPO):
    return deliver(
        client,
        "pull_request",
        {
            "action": "closed",
            "pull_request": {
                "number": pr_number,
                "merged": merged,
                "head": {"ref": "feature/whatever"},
            },
            "repository": {"full_name": repo},
        },
    )


class TestGateOutcome:
    def test_merging_records_the_outcome_against_the_decision(
        self, client, admin_auth, oracle_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        decision_id = judge(client, oracle_auth, run_compaction, pr_number=7, criticals=6)

        close_pr(client, 7, merged=True)
        run_compaction()

        assert catalog.query(
            "SELECT recommendation, gate_outcome FROM risk_decisions WHERE decision_id = ?",
            [decision_id],
        ) == [("no_go", "merged")]

    def test_closing_without_merging_is_a_different_outcome(
        self, client, admin_auth, oracle_auth, run_compaction, catalog
    ) -> None:
        """Not the same event at all: an abandoned PR is not evidence that
        anything was shipped."""
        onboard(client, admin_auth)
        decision_id = judge(client, oracle_auth, run_compaction, pr_number=8, criticals=6)

        close_pr(client, 8, merged=False)
        run_compaction()

        assert catalog.query(
            "SELECT gate_outcome FROM risk_decisions WHERE decision_id = ?", [decision_id]
        ) == [("closed_unmerged",)]

    def test_only_the_latest_decision_for_the_pr_is_marked(
        self, client, admin_auth, oracle_auth, run_compaction, catalog
    ) -> None:
        """Earlier decisions were superseded by later pushes and were never
        the standing verdict when the merge button was pressed."""
        onboard(client, admin_auth)
        first = judge(client, oracle_auth, run_compaction, pr_number=9, criticals=6)
        second = judge(client, oracle_auth, run_compaction, pr_number=9, criticals=6)
        assert first != second

        close_pr(client, 9, merged=True)
        run_compaction()

        outcomes = dict(
            catalog.query(
                "SELECT decision_id, gate_outcome FROM risk_decisions WHERE pr_number = 9"
            )
        )
        assert outcomes[second] == "merged"
        assert outcomes[first] is None

    def test_redelivery_does_not_rewrite_the_outcome(
        self, client, admin_auth, oracle_auth, run_compaction, catalog
    ) -> None:
        """GitHub redelivers, and a PR can be reopened and re-closed. The
        outcome that mattered is the first one recorded."""
        onboard(client, admin_auth)
        decision_id = judge(client, oracle_auth, run_compaction, pr_number=10, criticals=6)

        close_pr(client, 10, merged=True)
        run_compaction()
        close_pr(client, 10, merged=False)
        run_compaction()

        assert catalog.query(
            "SELECT gate_outcome FROM risk_decisions WHERE decision_id = ?", [decision_id]
        ) == [("merged",)]

    def test_a_pr_oracle_never_judged_records_nothing(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)

        response = close_pr(client, 404, merged=True)

        assert response.status_code == 200
        assert "gate_outcome_recorded_for" not in response.json()
        assert catalog.count("risk_decisions") == 0

    def test_a_broken_lake_does_not_fail_the_webhook(
        self, client, admin_auth, monkeypatch
    ) -> None:
        """GitHub disables a webhook that fails often enough. Losing install-PR
        promotion to save a metric would be a bad trade."""
        onboard(client, admin_auth)
        monkeypatch.setattr(
            client.app.state.catalog,
            "query",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lake is on fire")),
        )

        assert close_pr(client, 11, merged=True).status_code == 200


class TestShadowModeReport:
    def test_counts_the_merges_blocking_would_have_stopped(
        self, client, admin_auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        judge(client, oracle_auth, run_compaction, pr_number=1, criticals=6)  # no_go
        close_pr(client, 1, merged=True)
        judge(client, oracle_auth, run_compaction, pr_number=2, criticals=6)  # no_go
        close_pr(client, 2, merged=False)
        run_compaction()

        report = client.get("/api/oracle/shadow-mode", headers=viewer_auth).json()

        assert report["decisions_with_a_known_outcome"] == 2
        assert report["would_have_blocked"] == 1
        assert report["merged"] == 1
        assert report["closed_unmerged"] == 1
        assert report["by_recommendation"]["no_go"] == {
            "merged": 1,
            "closed_unmerged": 1,
        }

    def test_a_clean_merge_is_not_counted_as_blocked(
        self, client, admin_auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        judge(client, oracle_auth, run_compaction, pr_number=3, criticals=0)  # go
        close_pr(client, 3, merged=True)
        run_compaction()

        report = client.get("/api/oracle/shadow-mode", headers=viewer_auth).json()

        assert report["would_have_blocked"] == 0
        assert report["by_recommendation"] == {"go": {"merged": 1, "closed_unmerged": 0}}

    def test_decisions_with_no_outcome_yet_are_excluded(
        self, client, admin_auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        """An open PR is not evidence of anything yet, and counting it as a
        clean merge would flatter the report."""
        onboard(client, admin_auth)
        judge(client, oracle_auth, run_compaction, pr_number=4, criticals=6)
        run_compaction()

        report = client.get("/api/oracle/shadow-mode", headers=viewer_auth).json()

        assert report["decisions_with_a_known_outcome"] == 0

    def test_an_override_on_a_would_have_blocked_merge_is_visible(
        self, client, admin_auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        """The counter-evidence, in the same table as the evidence: somebody
        looked at this no_go, wrote down why it was acceptable, and shipped."""
        onboard(client, admin_auth)
        decision_id = judge(client, oracle_auth, run_compaction, pr_number=5, criticals=6)
        client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "All six are in a vendored test fixture."},
            headers=admin_auth,
        )
        close_pr(client, 5, merged=True)
        run_compaction()

        report = client.get("/api/oracle/shadow-mode", headers=viewer_auth).json()

        assert report["would_have_blocked"] == 1
        assert report["would_have_blocked_and_overridden"] == 1

    def test_the_window_is_configurable_and_bounded(
        self, client, viewer_auth
    ) -> None:
        assert client.get(
            "/api/oracle/shadow-mode?days=30", headers=viewer_auth
        ).json()["window_days"] == 30
        assert (
            client.get("/api/oracle/shadow-mode?days=0", headers=viewer_auth).status_code
            == 422
        )

    def test_it_is_not_shadowed_by_the_decisions_route(
        self, client, viewer_auth
    ) -> None:
        """`/decisions/{repo_id}` is a sibling path parameter; a literal route
        registered after it would be swallowed."""
        response = client.get("/api/oracle/shadow-mode", headers=viewer_auth)

        assert response.status_code == 200
        assert "would_have_blocked" in response.json()

    def test_it_needs_authentication(self, client) -> None:
        assert client.get("/api/oracle/shadow-mode").status_code == 401
