"""What happens when a Patchwork draft closes — spec 08 §4, spec 11 §9.

Two consequences, and the second is easy to forget: the discount has to
*expire*. An abandoned auto-fix that keeps lowering a repository's score is
worse than no auto-fix at all, because the score looks attended to.
"""

from __future__ import annotations

import pytest

from mykronos.config import get_settings
from mykronos.oracle import load_policy
from mykronos.oracle.engine import OracleEngine
from tests.conftest import REPO, issue_token
from tests.test_onboarding import deliver, onboard
from tests.test_patchwork import REQUIREMENTS, dependency_finding, put_file, seed


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'patchwork')}"
    }


@pytest.fixture
def with_open_fix(client, admin_auth, auth, run_compaction, github) -> int:
    """A repository with one Patchwork draft pull request open."""
    onboard(client, admin_auth)
    put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
    seed(client, auth, run_compaction, [dependency_finding()])
    client.post("/api/patchwork/run", json={}, headers=auth)
    run_compaction()
    return github.repos[REPO].pull_requests[-1].number


def close_pr(client, number: int, *, merged: bool):
    return deliver(
        client,
        "pull_request",
        {
            "action": "closed",
            "pull_request": {
                "number": number,
                "merged": merged,
                "head": {"ref": f"mykronos/fix-{number}"},
            },
            "repository": {"full_name": REPO},
        },
    )


def engine(client) -> OracleEngine:
    return OracleEngine(
        client.app.state.catalog, load_policy(get_settings().oracle_policy_path)
    )


class TestStatusSync:
    def test_merging_records_the_outcome(
        self, client, with_open_fix, run_compaction, catalog
    ) -> None:
        close_pr(client, with_open_fix, merged=True)
        run_compaction()

        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("merged",)
        ]

    def test_closing_unmerged_is_a_different_outcome(
        self, client, with_open_fix, run_compaction, catalog
    ) -> None:
        close_pr(client, with_open_fix, merged=False)
        run_compaction()

        assert catalog.query("SELECT pr_status FROM remediation_events") == [
            ("closed_unmerged",)
        ]

    def test_a_pull_request_that_is_not_ours_is_ignored(
        self, client, admin_auth, run_compaction, catalog
    ) -> None:
        """The webhook fires for every pull request in the repository."""
        onboard(client, admin_auth)

        response = close_pr(client, 999, merged=True)

        assert response.status_code == 200
        assert "remediation_outcome_recorded_for" not in response.json()

    def test_a_broken_lake_does_not_fail_the_webhook(
        self, client, with_open_fix, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            client.app.state.catalog,
            "query",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("lake is on fire")),
        )

        assert close_pr(client, with_open_fix, merged=True).status_code == 200


class TestTheDiscountExpires:
    def test_a_merged_fix_stops_discounting(
        self, client, with_open_fix, run_compaction
    ) -> None:
        """Once merged, the fix is not "in flight" — and the finding itself
        stays open until a scan confirms otherwise, which is correct."""
        while_open = engine(client).evaluate(REPO).overall_risk_score

        close_pr(client, with_open_fix, merged=True)
        run_compaction()
        after = engine(client).evaluate(REPO)

        assert after.overall_risk_score > while_open
        assert after.inputs_snapshot["remediation_in_flight"]["covered_findings"] == 0

    def test_an_abandoned_fix_stops_discounting_too(
        self, client, with_open_fix, run_compaction
    ) -> None:
        """The important half. A closed-unmerged auto-fix that kept lowering
        the score forever would make the repository look attended to when
        nobody attended to it."""
        while_open = engine(client).evaluate(REPO).overall_risk_score

        close_pr(client, with_open_fix, merged=False)
        run_compaction()

        assert engine(client).evaluate(REPO).overall_risk_score > while_open


class TestItBecomesALearning:
    def test_a_merged_fix_is_recorded(
        self, client, with_open_fix, run_compaction
    ) -> None:
        close_pr(client, with_open_fix, merged=True)

        entries = [
            e
            for e in client.app.state.knowledge.list_entries()
            if e.source_type == "remediation_outcome"
        ]
        assert len(entries) == 1
        assert entries[0].subject == "merged"
        assert "merged as-is" in entries[0].text

    def test_an_abandoned_fix_is_recorded_separately(
        self, client, with_open_fix, run_compaction
    ) -> None:
        """"Auto-fixes get merged here" and "auto-fixes get closed here" are
        different facts about a repository, and only one of them means the
        capability is working."""
        close_pr(client, with_open_fix, merged=False)

        entries = [
            e
            for e in client.app.state.knowledge.list_entries()
            if e.source_type == "remediation_outcome"
        ]
        assert entries[0].subject == "closed_unmerged"
        assert "wrong or simply unwanted" in entries[0].text

    def test_it_carries_no_reason_and_so_cannot_dampen(
        self, client, with_open_fix, run_compaction
    ) -> None:
        """Nobody typed anything. It is evidence a pattern recurs and no
        evidence at all about why — the same treatment every unreasoned signal
        gets (spec 11 §4)."""
        close_pr(client, with_open_fix, merged=False)

        entry = next(
            e
            for e in client.app.state.knowledge.list_entries()
            if e.source_type == "remediation_outcome"
        )
        assert entry.has_reason is False
        assert entry.confidence <= 0.25

    def test_repeated_outcomes_reconfirm_rather_than_pile_up(
        self, client, admin_auth, auth, run_compaction, github
    ) -> None:
        """A repository where nine fixes were closed unmerged is telling you
        something; nine separate rows saying it once each are not."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\nrequests==2.0.0\n")
        seed(
            client,
            auth,
            run_compaction,
            [
                dependency_finding(symbol="a", code_snippet="a()"),
                dependency_finding(
                    package_name="requests",
                    symbol="b",
                    code_snippet="b()",
                    raw_finding_json={"fixed_version": "2.32.0"},
                ),
            ],
        )
        client.post("/api/patchwork/run", json={}, headers=auth)
        run_compaction()

        for pr in github.repos[REPO].pull_requests:
            close_pr(client, pr.number, merged=False)

        entries = [
            e
            for e in client.app.state.knowledge.list_entries()
            if e.source_type == "remediation_outcome"
        ]
        assert len(entries) == 1
        assert entries[0].observations == 2
