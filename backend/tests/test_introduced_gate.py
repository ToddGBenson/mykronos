"""The gate blocks on what a commit introduced, not on the backlog (D-048).

The failure this replaces: Oracle scores the whole open backlog, so once a
repository carries a few hundred findings every commit is refused regardless
of content. A gate that refuses everything is not a gate — it gets switched
off, and then it protects nothing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.dashboard import DashboardQueries
from mykronos.lake.mutate import locate_findings, update_findings
from tests.conftest import (
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    """`oracle` has to be granted explicitly - the default fixture token is
    scoped to one capability, and evaluating is a separate grant (D-009)."""
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


OLD = "a" * 40
NEW = "b" * 40


def _scan(client, auth, run_compaction, scan_run_id, commit, findings):
    post_scan(client, auth, scan_run_id=scan_run_id, commit_sha=commit)
    post_findings(client, auth, findings, scan_run_id=scan_run_id)
    run_compaction()


class TestIntroducedBy:
    def test_a_finding_from_this_commit_counts(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        introduced = DashboardQueries(catalog).introduced_by(REPO, NEW)

        assert introduced.get("critical") == 1

    def test_a_finding_from_an_earlier_commit_does_not(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The whole point. Backlog is not the commit's fault, and counting it
        is what made every build red."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [finding_payload(rule_id="OLD1", severity="critical")],
        )
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="NEW1", severity="low")],
        )

        introduced = DashboardQueries(catalog).introduced_by(REPO, NEW)

        assert introduced.get("critical") is None
        assert introduced.get("low") == 1

    def test_a_finding_that_persists_is_still_attributed_to_its_first_sighting(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """Reported by both scans, introduced by the first. Otherwise every
        unfixed finding would be re-introduced on every commit and the gate
        would be the backlog gate again by another route."""
        payload = [finding_payload(rule_id="R1", severity="high")]
        _scan(client, auth, run_compaction, "run-old", OLD, payload)
        _scan(client, auth, run_compaction, "run-new", NEW, payload)

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {}
        assert DashboardQueries(catalog).introduced_by(REPO, OLD).get("high") == 1

    def test_a_dispositioned_finding_does_not_block_its_own_commit(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """An accepted risk with a reason is a decision, not an obstacle."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        update_findings(
            catalog, locate_findings(catalog, ids), "status = 'accepted_risk'", []
        )

        assert DashboardQueries(catalog).introduced_by(REPO, NEW) == {}

    def test_an_unknown_commit_introduced_nothing(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        assert DashboardQueries(catalog).introduced_by(REPO, "c" * 40) == {}


class TestTheGateDecision:
    def test_the_evaluate_response_carries_the_floor(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="critical")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is True
        assert body["introduced"]["critical"] == 1

    def test_a_clean_commit_does_not_block_despite_a_backlog(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        """The case that motivated D-048: a large standing backlog and a
        commit that adds nothing serious. The score stays bad; the gate
        passes."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-old",
            OLD,
            [
                finding_payload(rule_id=f"OLD{i}", severity="critical")
                for i in range(5)
            ],
        )
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="NEW1", severity="low")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is False
        assert body["recommendation"] == "no_go", "the backlog is still bad"

    def test_a_new_high_blocks(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="high")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is True

    def test_a_new_medium_does_not(
        self, client, auth, oracle_auth, run_compaction
    ) -> None:
        """The floor is critical and high. Mediums are recorded and triaged;
        blocking on them is how a floor becomes something people lower."""
        _scan(
            client,
            auth,
            run_compaction,
            "run-new",
            NEW,
            [finding_payload(rule_id="R1", severity="medium")],
        )

        body = client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": NEW, "decision_type": "portfolio"},
            headers=oracle_auth,
        ).json()

        assert body["introduced_blocking"] is False
