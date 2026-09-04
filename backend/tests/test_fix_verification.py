"""Did the fix work? (spec 25 §1, §2)

Patchwork could report that it opened pull requests and never that it removed
a vulnerability. These tests pin the loop that closes: scan the merge commit,
then attribute the finding's fate to the change that caused it — including the
two outcomes that are neither success nor failure, because folding those into
either one would slander a fix that worked or flatter one that did not.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.lake.catalog import Catalog
from mykronos.patchwork.verification import (
    VERIFICATION_DEADLINE,
    dispatch_pending,
    resolve_pending,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan

MERGE_SHA = "cafe1234cafe1234cafe1234cafe1234cafe1234"


class Dispatcher:
    """Records what it was asked to scan, and can be told to fail."""

    def __init__(self, *, succeed: bool = True) -> None:
        self.calls: list[tuple[str, str]] = []
        self.succeed = succeed

    async def __call__(self, repo_full_name: str, capability: str) -> bool:
        self.calls.append((repo_full_name, capability))
        return self.succeed


def seed_finding(client: TestClient, auth: dict[str, str], run_compaction: Any) -> str:
    post_scan(client, auth, scan_run_id="run-1", commit_sha="a91f2c7")
    post_findings(client, auth, [finding_payload()], scan_run_id="run-1")
    run_compaction()
    return str(client.app.state.catalog.query("SELECT finding_id FROM findings")[0][0])  # type: ignore[attr-defined]


def seed_event(
    client: TestClient,
    catalog: Catalog,
    run_compaction: Any,
    finding_id: str,
    *,
    pr_status: str = "merged",
    outcome: str | None = "pending",
    commit: str | None = MERGE_SHA,
    dispatched_at: Any = None,
) -> str:
    event_id = f"event-{finding_id[:8]}"
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
                "fix_pr_number": 77,
                "fix_pr_url": "https://example.invalid/pr/77",
                "pr_status": pr_status,
                "rationale": "pinned urllib3",
                "verification_commit_sha": commit,
                "verification_dispatched_at": dispatched_at,
                "verification_scan_run_id": None,
                "verification_outcome": outcome,
                "verified_at": None,
                "time_to_verified_seconds": None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    run_compaction()
    return event_id


def event(catalog: Catalog) -> dict[str, Any]:
    row = catalog.query(
        "SELECT verification_outcome, verification_scan_run_id, "
        "verification_dispatched_at, time_to_verified_seconds, rationale "
        "FROM remediation_events"
    )[0]
    return {
        "outcome": row[0],
        "scan_run_id": row[1],
        "dispatched_at": row[2],
        "elapsed": row[3],
        "rationale": row[4],
    }


class TestTheWebhookMarksItPending:
    def test_a_merged_fix_becomes_pending_with_its_merge_commit(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        from mykronos.patchwork.outcomes import record_pr_outcome

        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id, outcome=None, commit=None)

        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            77,
            merged=True,
            merge_commit_sha=MERGE_SHA,
        )
        run_compaction()

        assert event(catalog)["outcome"] == "pending"

    def test_an_abandoned_fix_is_never_pending(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """An abandoned fix is not verified and must not look like one that
        is still being checked."""
        from mykronos.patchwork.outcomes import record_pr_outcome

        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id, outcome=None, commit=None)

        record_pr_outcome(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            REPO,
            77,
            merged=False,
        )
        run_compaction()

        assert event(catalog)["outcome"] is None


class TestDispatch:
    @pytest.mark.asyncio
    async def test_it_scans_only_the_capability_that_found_it(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A full fifteen-check re-run on every fix merge is a cost this
        platform cannot afford at the cadence merges happen."""
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id)
        dispatcher = Dispatcher()

        result = await dispatch_pending(
            catalog, client.app.state.buffer, dispatch=dispatcher  # type: ignore[attr-defined]
        )
        run_compaction()

        assert dispatcher.calls == [(REPO, "sast")]
        assert result.dispatched == 1
        assert event(catalog)["dispatched_at"] is not None

    @pytest.mark.asyncio
    async def test_an_unmerged_event_is_not_dispatched(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id, pr_status="closed_unmerged")
        dispatcher = Dispatcher()

        await dispatch_pending(
            catalog, client.app.state.buffer, dispatch=dispatcher  # type: ignore[attr-defined]
        )

        assert dispatcher.calls == []

    @pytest.mark.asyncio
    async def test_a_merge_with_no_commit_is_not_scanned(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """Better than scanning the branch head and attributing whatever it
        finds to this fix."""
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id, commit=None)
        dispatcher = Dispatcher()

        result = await dispatch_pending(
            catalog, client.app.state.buffer, dispatch=dispatcher  # type: ignore[attr-defined]
        )
        run_compaction()

        assert dispatcher.calls == []
        assert result.not_scanned == 1
        assert event(catalog)["outcome"] == "not_scanned"

    @pytest.mark.asyncio
    async def test_a_failed_dispatch_stays_pending_for_the_next_pass(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id)

        result = await dispatch_pending(
            catalog,
            client.app.state.buffer,  # type: ignore[attr-defined]
            dispatch=Dispatcher(succeed=False),
        )
        run_compaction()

        assert result.dispatch_failed == 1
        assert event(catalog)["outcome"] == "pending"
        assert event(catalog)["dispatched_at"] is None

    @pytest.mark.asyncio
    async def test_it_does_not_dispatch_twice(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(client, catalog, run_compaction, finding_id)
        dispatcher = Dispatcher()
        buffer = client.app.state.buffer  # type: ignore[attr-defined]

        await dispatch_pending(catalog, buffer, dispatch=dispatcher)
        run_compaction()
        await dispatch_pending(catalog, buffer, dispatch=dispatcher)

        assert len(dispatcher.calls) == 1


class TestResolution:
    def _dispatched(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
        *,
        ago: timedelta = timedelta(minutes=5),
    ) -> str:
        finding_id = seed_finding(client, auth, run_compaction)
        seed_event(
            client,
            catalog,
            run_compaction,
            finding_id,
            dispatched_at=utcnow() - ago,
        )
        return finding_id

    def test_a_finding_that_is_gone_is_verified_fixed(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(client, auth, catalog, run_compaction)
        # The verifying scan runs against the merge commit and does not report
        # the finding. No reconciliation involved — see the next test for why
        # that matters.
        post_scan(client, auth, scan_run_id="verify-1", commit_sha=MERGE_SHA)
        post_findings(client, auth, [], scan_run_id="verify-1")
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.verified_fixed == 1
        stored = event(catalog)
        assert stored["outcome"] == "verified_fixed"
        assert stored["scan_run_id"] == "verify-1"
        assert stored["elapsed"] >= 0

    def test_it_concludes_without_waiting_for_reconciliation(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A finding is not marked `fixed` until it has been absent from two
        consecutive scans — flap protection, which answers a different
        question. Coupling to it would report a working fix as unverified
        until an unrelated second scan happened to run."""
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(client, auth, scan_run_id="verify-1", commit_sha=MERGE_SHA)
        post_findings(client, auth, [], scan_run_id="verify-1")
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.verified_fixed == 1
        # Still open in the lake, and that is correct: closure is the
        # platform's own conservative rule, and this column reports what one
        # scan of one commit observed.
        assert catalog.query("SELECT status FROM findings")[0][0] == "open"

    def test_a_partial_failure_is_inconclusive(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """The file this finding lives in may be exactly the target that did
        not get scanned."""
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(
            client,
            auth,
            scan_run_id="verify-1",
            commit_sha=MERGE_SHA,
            scan_status="partial_failure",
        )
        post_findings(client, auth, [], scan_run_id="verify-1")
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.inconclusive == 1
        assert event(catalog)["outcome"] == "inconclusive"

    def test_a_finding_the_verifying_run_re_reported_is_still_open(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(client, auth, scan_run_id="verify-1", commit_sha=MERGE_SHA)
        post_findings(client, auth, [finding_payload()], scan_run_id="verify-1")
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.still_open == 1
        assert event(catalog)["outcome"] == "still_open"

    def test_a_scan_that_has_not_run_yet_waits(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(client, auth, catalog, run_compaction)

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.waiting == 1
        assert event(catalog)["outcome"] == "pending"

    def test_a_scan_that_never_runs_is_not_scanned_after_the_deadline(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(
            client, auth, catalog, run_compaction, ago=VERIFICATION_DEADLINE + timedelta(hours=1)
        )

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.not_scanned == 1
        assert event(catalog)["outcome"] == "not_scanned"

    def test_a_failed_verifying_scan_is_inconclusive(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """Not `still_open`: that would slander a fix that may well have
        worked."""
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(
            client,
            auth,
            scan_run_id="verify-1",
            commit_sha=MERGE_SHA,
            scan_status="failure",
        )
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.inconclusive == 1
        assert event(catalog)["outcome"] == "inconclusive"

    def test_a_scan_with_nothing_to_scan_is_inconclusive(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(
            client,
            auth,
            scan_run_id="verify-1",
            commit_sha=MERGE_SHA,
            scan_status="no_applicable_targets",
        )
        run_compaction()

        result = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert result.inconclusive == 1

    def test_a_verdict_is_not_revisited(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(client, auth, scan_run_id="verify-1", commit_sha=MERGE_SHA)
        post_findings(client, auth, [finding_payload()], scan_run_id="verify-1")
        run_compaction()
        resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        again = resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]

        assert again.still_open == 0
        assert again.waiting == 0

    def test_the_rationale_survives_a_verdict(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """The resolver writes a whole row; a null rationale would blank the
        one column the Remediation tab renders as prose."""
        self._dispatched(client, auth, catalog, run_compaction)
        post_scan(client, auth, scan_run_id="verify-1", commit_sha=MERGE_SHA)
        post_findings(client, auth, [finding_payload()], scan_run_id="verify-1")
        run_compaction()

        resolve_pending(catalog, client.app.state.buffer)  # type: ignore[attr-defined]
        run_compaction()

        assert event(catalog)["rationale"] == "pinned urllib3"
