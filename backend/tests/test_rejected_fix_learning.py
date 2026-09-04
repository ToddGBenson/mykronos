"""Learning from a fix somebody closed (spec 25 §3.3).

The two codes pull in opposite directions, and the tests that matter most here
are the ones pinning what must *not* happen: an unwanted fix dampening
anything, and a rejected fix reaching the finding.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.lake.catalog import Catalog
from mykronos.patchwork.outcomes import record_pr_outcome
from mykronos.patchwork.rejection import (
    FIX_WAS_UNWANTED,
    FIX_WAS_WRONG,
    REJECTION_MARKER,
    UNSTATED,
    is_dampened,
    parse_rejection,
    rejection_prompt,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan


class TestParsing:
    def test_an_unedited_body_is_unstated(self) -> None:
        assert parse_rejection(rejection_prompt()) == (UNSTATED, "")

    def test_no_body_at_all_is_unstated(self) -> None:
        assert parse_rejection(None) == (UNSTATED, "")
        assert parse_rejection("") == (UNSTATED, "")

    def test_a_stated_code_is_read(self) -> None:
        body = f"{REJECTION_MARKER}\nreason: fix_was_wrong it pinned the wrong extra\n"
        assert parse_rejection(body) == (FIX_WAS_WRONG, "it pinned the wrong extra")

    def test_a_code_with_no_prose_is_still_read(self) -> None:
        assert parse_rejection("reason: fix_was_unwanted") == (FIX_WAS_UNWANTED, "")

    def test_case_is_ignored(self) -> None:
        assert parse_rejection("Reason: FIX_WAS_WRONG nope")[0] == FIX_WAS_WRONG

    def test_an_unknown_code_is_unstated(self) -> None:
        """Not an error, and not a guess: the platform records that nobody
        said anything it understands."""
        assert parse_rejection("reason: because_i_said_so")[0] == UNSTATED

    def test_the_first_code_wins(self) -> None:
        body = "reason: fix_was_wrong a\nreason: fix_was_unwanted b"
        assert parse_rejection(body) == (FIX_WAS_WRONG, "a")

    def test_the_prompt_round_trips_its_own_marker(self) -> None:
        assert REJECTION_MARKER in rejection_prompt()


def seed(
    client: TestClient,
    auth: dict[str, str],
    run_compaction: Any,
    *,
    rule_id: str = "CWE-89",
    event_id: str = "e1",
    pr_number: int = 1,
    fixer_name: str = "python-pin",
) -> str:
    post_scan(client, auth, scan_run_id=f"run-{event_id}")
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=rule_id, symbol=f"fn_{event_id}")],
        scan_run_id=f"run-{event_id}",
    )
    run_compaction()
    finding_id = str(
        client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings WHERE rule_id = ? ORDER BY symbol", [rule_id]
        )[-1][0]
    )
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
                "fix_pr_number": pr_number,
                "fix_pr_url": f"https://example.invalid/{pr_number}",
                "pr_status": "draft_open",
                "rationale": "pinned",
                "fixer_name": fixer_name,
                "rejection_reason_code": None,
                "rejection_reason": None,
                "verification_commit_sha": None,
                "verification_dispatched_at": None,
                "verification_scan_run_id": None,
                "verification_outcome": None,
                "verified_at": None,
                "time_to_verified_seconds": None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    run_compaction()
    return finding_id


def stored(catalog: Catalog, event_id: str = "e1") -> tuple[Any, Any]:
    row = catalog.query(
        "SELECT rejection_reason_code, rejection_reason FROM remediation_events "
        "WHERE event_id = ?",
        [event_id],
    )[0]
    return (row[0], row[1])


class TestRecording:
    def test_a_close_records_the_stated_reason(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)

        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            1,
            merged=False,
            store=client.app.state.knowledge,  # type: ignore[attr-defined]
            pr_body="reason: fix_was_wrong pinned the wrong extra",
        )
        run_compaction()

        assert stored(catalog) == (FIX_WAS_WRONG, "pinned the wrong extra")

    def test_a_merge_asks_no_question(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A merge answers it by itself, and a body still carrying the
        template must not be read as a rejection."""
        seed(client, auth, run_compaction)

        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            1,
            merged=True,
            merge_commit_sha="abc",
            pr_body="reason: fix_was_wrong ignore me",
        )
        run_compaction()

        assert stored(catalog) == (None, None)

    def test_an_unstated_reason_is_recorded_as_such(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        seed(client, auth, run_compaction)

        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            1,
            merged=False,
            pr_body=rejection_prompt(),
        )
        run_compaction()

        assert stored(catalog)[0] == UNSTATED


class TestDampening:
    def _reject(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
        *,
        n: int,
        code: str,
    ) -> None:
        for index in range(n):
            seed(
                client,
                auth,
                run_compaction,
                event_id=f"e{index}",
                pr_number=index + 1,
            )
            record_pr_outcome(
                catalog,
                client.app.state.buffer,  # type: ignore[attr-defined]
                REPO,
                index + 1,
                merged=False,
                pr_body=f"reason: {code} nope",
            )
            run_compaction()

    def test_one_rejection_does_not_dampen(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """One rejection is a judgement about one diff, and may be about that
        file rather than about the fixer."""
        self._reject(client, auth, catalog, run_compaction, n=1, code=FIX_WAS_WRONG)

        skip, count = is_dampened(
            catalog, repo_full_name=REPO, rule_id="CWE-89", fixer_name="python-pin"
        )

        assert (skip, count) == (False, 1)

    def test_two_rejections_dampen(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._reject(client, auth, catalog, run_compaction, n=2, code=FIX_WAS_WRONG)

        skip, count = is_dampened(
            catalog, repo_full_name=REPO, rule_id="CWE-89", fixer_name="python-pin"
        )

        assert (skip, count) == (True, 2)

    def test_unwanted_never_dampens(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A correct fix nobody wanted is a scheduling disagreement. Treating
        it as a defect would make a team that defers work look like a team
        whose fixer is broken."""
        self._reject(client, auth, catalog, run_compaction, n=3, code=FIX_WAS_UNWANTED)

        skip, count = is_dampened(
            catalog, repo_full_name=REPO, rule_id="CWE-89", fixer_name="python-pin"
        )

        assert (skip, count) == (False, 0)

    def test_another_fixer_is_unaffected(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._reject(client, auth, catalog, run_compaction, n=2, code=FIX_WAS_WRONG)

        skip, _ = is_dampened(
            catalog, repo_full_name=REPO, rule_id="CWE-89", fixer_name="npm-pin"
        )

        assert skip is False

    def test_another_repository_is_unaffected(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A fleet-wide veto learned from one repository would be the platform
        generalising from a sample of one."""
        self._reject(client, auth, catalog, run_compaction, n=2, code=FIX_WAS_WRONG)

        skip, _ = is_dampened(
            catalog,
            repo_full_name="other-org/other",
            rule_id="CWE-89",
            fixer_name="python-pin",
        )

        assert skip is False


class TestItNeverReachesTheFinding:
    def test_a_rejected_fix_does_not_dampen_the_rule(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """`dampened_rules` reads `finding_dismissal` only. "We did not want
        this patch" must never become "this was a false positive"."""
        from mykronos.knowledge.dampening import dampened_rules

        seed(client, auth, run_compaction)
        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            1,
            merged=False,
            store=client.app.state.knowledge,  # type: ignore[attr-defined]
            pr_body="reason: fix_was_wrong it broke the build",
        )
        run_compaction()

        assert (
            dampened_rules(
                catalog,
                client.app.state.knowledge,  # type: ignore[attr-defined]
                REPO,
                threshold=0.0,
                min_observations=1,
                min_confidence=0.0,
            )
            == {}
        )

    def test_the_finding_stays_open(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        finding_id = seed(client, auth, run_compaction)
        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            1,
            merged=False,
            pr_body="reason: fix_was_wrong",
        )
        run_compaction()

        status = catalog.query(
            "SELECT status FROM findings WHERE finding_id = ?", [finding_id]
        )[0][0]
        assert status == "open"


class TestThePipelineSkips:
    @pytest.mark.asyncio
    async def test_a_dampened_fixer_is_not_offered_again(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """Offering the same wrong diff a third time is how a fix pipeline
        gets muted."""
        from mykronos.patchwork.rejection import REJECTION_FLOOR

        assert REJECTION_FLOOR == 2
        for index in range(2):
            seed(client, auth, run_compaction, event_id=f"e{index}", pr_number=index + 1)
            record_pr_outcome(
                catalog,
                client.app.state.buffer,  # type: ignore[attr-defined]
                REPO,
                index + 1,
                merged=False,
                pr_body="reason: fix_was_wrong",
            )
            run_compaction()

        skip, count = is_dampened(
            catalog, repo_full_name=REPO, rule_id="CWE-89", fixer_name="python-pin"
        )
        assert skip and count == 2
