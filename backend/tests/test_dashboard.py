"""Dashboard query service and API — spec 10 §2, §4, §5, §7; spec 12 §5."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.schemas import Severity
from tests.conftest import (
    CAPABILITY,
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard


@pytest.fixture
def seeded(client: TestClient, admin_auth: dict[str, str], run_compaction):
    """An onboarded repo with sast enabled and a few findings in the lake."""
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast"]},
        headers=admin_auth,
    )

    token = issue_token(client, REPO, CAPABILITY)
    auth = {"Authorization": f"Bearer {token}"}
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
            finding_payload(rule_id="CWE-79", severity="high", symbol="b"),
            finding_payload(rule_id="CWE-22", severity="low", symbol="c"),
        ],
        scan_run_id="run-1",
    )
    run_compaction()
    return repo_id


class TestPortfolio:
    def test_counts_open_findings_by_severity(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get("/api/dashboard/portfolio", headers=admin_auth).json()

        row = body["repos"][0]
        assert row["repo_full_name"] == REPO
        assert row["severity_counts"]["critical"] == 1
        assert row["severity_counts"]["high"] == 1
        assert row["total_open"] == 3

    def test_summary_cards_aggregate_the_portfolio(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        summary = client.get("/api/dashboard/portfolio", headers=admin_auth).json()[
            "summary"
        ]
        assert summary["open_critical"] == 1
        assert summary["open_high"] == 1

    def test_a_freshly_onboarded_repo_says_awaiting_first_scan(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """spec 10 §7: not a blank "0 findings", which reads as clean."""
        onboard(client, admin_auth)

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["awaiting_first_scan"] is True
        assert row["last_scan_at"] is None

    def test_per_capability_scan_state_is_reported(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """A repo can have one capability scanning and another that has never
        run; a single repo-level flag would hide that."""
        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        # sast is pending until its PR merges, so enabled_capabilities is still
        # empty and there is nothing to report per capability yet.
        assert row["pending_capabilities"] == ["sast"]
        assert row["enabled_capabilities"] == []

    def test_risk_score_is_null_not_zero(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """Oracle lands in Phase 3. Zero would read as "assessed, no risk"."""
        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        assert row["risk_score"] is None
        assert row["recommendation"] is None

    def test_offboarded_repos_are_hidden_but_retrievable(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 10 §7: excluded by default, available for audit."""
        client.delete(f"/api/repos/{seeded}", headers=admin_auth)

        assert client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"] == []

        including = client.get(
            "/api/dashboard/portfolio",
            params={"include_removed": True},
            headers=admin_auth,
        ).json()
        assert including["repos"][0]["status"] == "removed"

    def test_an_empty_portfolio_is_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
        assert body["repos"] == []
        assert body["summary"]["open_critical"] == 0


class TestFindings:
    def test_lists_findings_worst_first(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """The top of the list should be what to work on."""
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings", headers=admin_auth
        ).json()

        assert body["total"] == 3
        assert [f["severity"] for f in body["findings"]] == ["critical", "high", "low"]

    def test_filters_by_severity(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"severity": "critical"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 1

    def test_paginates(self, client: TestClient, admin_auth: dict[str, str], seeded) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"limit": 2, "offset": 2},
            headers=admin_auth,
        ).json()
        assert body["total"] == 3
        assert len(body["findings"]) == 1

    def test_a_repo_name_is_not_a_valid_path_id(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """`owner/repo` has a slash in it, so it cannot be one path segment.
        The endpoint takes the onboarding id and says so."""
        response = client.get(
            f"/api/dashboard/repos/{REPO}/findings", headers=admin_auth
        )
        assert response.status_code == 404

    def test_an_unknown_repo_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert (
            client.get("/api/dashboard/repos/nope/findings", headers=admin_auth).status_code
            == 404
        )


class TestRawOutputIsAdminOnly:
    """spec 12 §5 — a Secrets finding's raw record quotes the secret."""

    def test_admins_receive_raw_output(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings", headers=admin_auth
        ).json()
        assert body["raw_output_included"] is True
        assert "raw_finding_json" in body["findings"][0]

    def test_viewers_do_not(
        self, client: TestClient, viewer_auth: dict[str, str], seeded
    ) -> None:
        """Withheld at the query layer, not hidden in the UI — "not rendered"
        is not "not sent"."""
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings", headers=viewer_auth
        ).json()

        assert body["raw_output_included"] is False
        assert "raw_finding_json" not in body["findings"][0]
        assert "code_snippet" not in body["findings"][0]

    def test_viewers_can_still_see_the_findings_themselves(
        self, client: TestClient, viewer_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings", headers=viewer_auth
        ).json()
        assert body["total"] == 3
        assert body["findings"][0]["severity"] == "critical"


class TestStatusWriteBack:
    def _first_finding(self, client: TestClient, auth: dict[str, str], repo_id: str) -> str:
        body = client.get(f"/api/dashboard/repos/{repo_id}/findings", headers=auth).json()
        return str(body["findings"][0]["finding_id"])

    def test_marking_a_false_positive_persists(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "generated code directory"},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json()["reason_supplied"] is True

        after = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"finding_status": "false_positive"},
            headers=admin_auth,
        ).json()
        assert after["total"] == 1

    def test_a_reason_free_dismissal_is_recorded_but_flagged(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 11 §4: reasons are what make a learning actionable rather than
        a statistic, so a bare click is low-confidence."""
        finding_id = self._first_finding(client, admin_auth, seeded)

        body = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive"},
            headers=admin_auth,
        ).json()

        assert body["reason_supplied"] is False
        assert "low-confidence" in body["retro_signal"]

    def test_a_human_cannot_hand_set_fixed(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """That would put a claim in the lake no scan supports, and MTTF would
        start measuring opinions."""
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "fixed"},
            headers=admin_auth,
        )

        assert response.status_code == 422
        assert "observations" in response.json()["detail"]

    def test_viewers_cannot_change_status(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth, seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "x"},
            headers=viewer_auth,
        )
        assert response.status_code == 403

    def test_the_change_is_audited(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 12 §7."""
        from mykronos.db.models import AuditLogEntry

        finding_id = self._first_finding(client, admin_auth, seeded)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "accepted_risk", "reason": "staging only"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            entry = (
                session.query(AuditLogEntry)
                .filter(AuditLogEntry.action == "finding.status")
                .one()
            )
        assert entry.detail["reason"] == "staging only"
        assert entry.detail["new_status"] == "accepted_risk"

    def test_an_unknown_finding_is_404(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        assert (
            client.patch(
                "/api/dashboard/findings/nope/status",
                json={"status": "false_positive"},
                headers=admin_auth,
            ).status_code
            == 404
        )

    def test_a_dismissed_finding_leaves_the_open_counts(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "x"},
            headers=admin_auth,
        )

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        assert row["severity_counts"]["critical"] == 0
        assert row["total_open"] == 2


class TestScanHealth:
    def test_reports_runs_and_failure_rate(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-2", scan_status="failure")
        run_compaction()

        body = client.get(
            f"/api/dashboard/repos/{seeded}/scan-health", headers=admin_auth
        ).json()

        sast = next(c for c in body["capabilities"] if c["capability"] == "sast")
        assert sast["runs"] == 2
        assert sast["failed"] == 1
        assert sast["failure_rate"] == 0.5

    def test_a_repo_with_no_scans_reports_nothing_rather_than_failing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        body = client.get(
            f"/api/dashboard/repos/{repo_id}/scan-health", headers=admin_auth
        ).json()
        assert body["capabilities"] == []


def test_severity_enum_covers_every_portfolio_bucket() -> None:
    """A new severity must not silently vanish from the summary."""
    from mykronos.dashboard import SEVERITIES

    assert set(SEVERITIES) == {s.value for s in Severity}
