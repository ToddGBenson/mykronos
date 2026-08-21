"""Per-fixer efficacy (spec 25 §3).

Before the verification loop, a fixer that opened pull requests nobody merged
and one that silently removed real risk every week both showed as `pr_opened`
rows. These tests pin the distinction.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def seed_event(
    client: TestClient,
    run_compaction: Any,
    *,
    finding_id: str,
    event_id: str,
    fixer_name: str | None = "python-pin",
    pr_status: str | None = "merged",
    outcome: str | None = None,
    elapsed: int | None = None,
) -> None:
    client.app.state.buffer.append(  # type: ignore[attr-defined]
        "remediation_events",
        [
            {
                "event_id": event_id,
                "repo_full_name": REPO,
                "finding_id": finding_id,
                "toxic_combination_id": None,
                "contributing_finding_ids": json.dumps([]),
                "pipeline_stage_reached": "pr_opened",
                "triage_classification": "true_positive",
                "fix_pr_number": 1 if pr_status else None,
                "fix_pr_url": "https://example.invalid/1" if pr_status else None,
                "pr_status": pr_status,
                "rationale": "pinned",
                "fixer_name": fixer_name,
                "verification_commit_sha": None,
                "verification_dispatched_at": None,
                "verification_scan_run_id": None,
                "verification_outcome": outcome,
                "verified_at": None,
                "time_to_verified_seconds": elapsed,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    run_compaction()


def seed_findings(
    client: TestClient, auth: dict[str, str], run_compaction: Any, n: int
) -> list[str]:
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=f"CWE-{i}", symbol=f"fn_{i}") for i in range(n)],
    )
    run_compaction()
    return [
        str(row[0])
        for row in client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings ORDER BY rule_id"
        )
    ]


def efficacy(client: TestClient, auth: dict[str, str]) -> dict[str, Any]:
    return client.get("/api/patchwork/efficacy", headers=auth).json()


class TestTheScoreboard:
    def test_nothing_run_says_so(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        body = efficacy(client, viewer_auth)
        assert body["by_fixer"] == []
        assert "has not run" in body["note"]

    def test_a_verified_fix_counts_as_removed_risk(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        ids = seed_findings(client, auth, run_compaction, 1)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e1",
            outcome="verified_fixed",
            elapsed=600,
        )

        row = efficacy(client, viewer_auth)["by_fixer"][0]

        assert row["key"] == "python-pin"
        assert (row["attempts"], row["merged"], row["verified"]) == (1, 1, 1)
        assert row["median_seconds_to_verified"] == 600

    def test_merged_but_unestablished_is_not_a_failure(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        """The scan did not answer, which is not the same as the fix not
        working."""
        ids = seed_findings(client, auth, run_compaction, 1)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e1",
            outcome="inconclusive",
        )

        row = efficacy(client, viewer_auth)["by_fixer"][0]

        assert (row["verified"], row["still_open"], row["unverified"]) == (0, 0, 1)

    def test_a_fixer_nobody_merges_is_visible(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        """The whole point: three opened, none merged, zero verified."""
        ids = seed_findings(client, auth, run_compaction, 3)
        for index, finding_id in enumerate(ids):
            seed_event(
                client,
                run_compaction,
                finding_id=finding_id,
                event_id=f"e{index}",
                fixer_name="npm-pin",
                pr_status="closed_unmerged",
            )

        row = efficacy(client, viewer_auth)["by_fixer"][0]

        assert (row["attempts"], row["rejected"], row["verified"]) == (3, 3, 0)

    def test_still_open_is_its_own_column(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        ids = seed_findings(client, auth, run_compaction, 1)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e1",
            outcome="still_open",
        )

        row = efficacy(client, viewer_auth)["by_fixer"][0]

        assert (row["verified"], row["still_open"], row["unverified"]) == (0, 1, 0)

    def test_two_fixers_are_ranked_by_verified(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        ids = seed_findings(client, auth, run_compaction, 2)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e0",
            fixer_name="works",
            outcome="verified_fixed",
            elapsed=10,
        )
        seed_event(
            client,
            run_compaction,
            finding_id=ids[1],
            event_id="e1",
            fixer_name="does-not",
            pr_status="closed_unmerged",
        )

        keys = [row["key"] for row in efficacy(client, viewer_auth)["by_fixer"]]

        assert keys == ["works", "does-not"]

    def test_a_by_rule_breakdown_is_reported_too(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        """A fixer that works everywhere except one rule is a different
        problem from a fixer nobody trusts."""
        ids = seed_findings(client, auth, run_compaction, 1)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e1",
            outcome="verified_fixed",
        )

        by_rule = efficacy(client, viewer_auth)["by_rule"]

        assert [row["key"] for row in by_rule] == ["CWE-0"]
        assert by_rule[0]["verified"] == 1

    def test_an_event_with_no_fixer_is_excluded(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        """A triaged-only event is not a fix attempt, and counting it would
        make every fixer look worse than it is."""
        ids = seed_findings(client, auth, run_compaction, 1)
        seed_event(
            client,
            run_compaction,
            finding_id=ids[0],
            event_id="e1",
            fixer_name=None,
            pr_status=None,
        )

        assert efficacy(client, viewer_auth)["by_fixer"] == []
