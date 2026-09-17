"""An unscanned repository must not read like a clean one (issue #341).

`0/100, go` is the correct output for a repository that was fully scanned and
found clean. It was also the output for `ToddGBenson/apc` — no ingestion token,
no scan run, no code — scored every day beside the repositories that are
actually scanned, and nothing in the decision told the two apart.

That is the absence of evidence rendering as evidence of safety, which is the
one direction a security platform must never be wrong in. `surfaces.py` states
the rule for exposure and `risk_profile_builder.py` states it for an absent
profile field: unknown is a real answer, and the wrong direction to be wrong in
is the one that reads as reassurance.

The tests below split into three claims worth keeping apart:

* nothing looked → the verdict says so, in every surface that carries it;
* something looked and found nothing → still `go`, unchanged. This is the
  half the fix could most easily break, and a fix that made every clean
  repository look unscanned would be worse than the bug;
* nothing looked but something was found anyway → the finding wins. Missing
  evidence may withhold a `go`; it may never quieten a verdict.
"""

from __future__ import annotations

import pytest

from mykronos.config import get_settings
from mykronos.oracle import NOT_ASSESSED, OracleEngine, load_policy, render_reasoning
from mykronos.oracle.service import _CONCLUSION, render_check_run_summary
from tests.conftest import REPO, finding_payload, post_findings, post_scan


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


@pytest.fixture
def engine(catalog, policy):
    return OracleEngine(catalog, policy)


def critical(index: int = 0, **overrides):
    return finding_payload(
        rule_id=f"CWE-89-{index}",
        severity="critical",
        symbol=f"fn_{index}",
        code_snippet=f"unsafe_{index}()",
        **overrides,
    )


class TestNothingHasLooked:
    def test_a_repo_with_no_scan_run_is_not_assessed_rather_than_go(
        self, catalog, engine
    ) -> None:
        """The whole bug in one assertion.

        No token, no scan run, no code. The score is genuinely 0 and that is
        not a false statement — the false statement is `go`, which claims
        somebody looked.
        """
        decision = engine.evaluate(REPO)

        assert decision.overall_risk_score == 0
        assert decision.recommendation == NOT_ASSESSED

    def test_a_lane_that_only_ever_failed_is_not_evidence(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """A scanner that crashes is not a scanner that found nothing.

        Counting a failed run as evidence would reproduce the same bug one
        level down: a permanently broken lane would score identically to a
        clean tree.
        """
        post_scan(client, auth, scan_run_id="broke", scan_status="failure")
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.recommendation == NOT_ASSESSED
        evidence = decision.inputs_snapshot["evidence"]
        assert evidence["scan_runs"] == 1
        assert evidence["reporting_scan_runs"] == 0

    def test_the_snapshot_records_why(self, catalog, engine) -> None:
        """spec 09 §9: the reasoning may only say what the snapshot recorded."""
        evidence = engine.evaluate(REPO).inputs_snapshot["evidence"]

        assert evidence["available"] is False
        assert evidence["go_withheld"] is True
        assert evidence["capabilities_reported"] == []
        assert evidence["last_scan_at"] is None
        assert "has ever reported a scan run" in evidence["reason"]

    def test_the_reasoning_disowns_the_zero(self, catalog, engine) -> None:
        decision = engine.evaluate(REPO)

        assert decision.reasoning.startswith("Not assessed.")
        assert "absence of evidence, not evidence of safety" in decision.reasoning
        # The sentence is a pure function of the snapshot, so it cannot be
        # saying anything the stored inputs do not carry.
        assert render_reasoning(decision.inputs_snapshot) == decision.reasoning

    def test_the_path_to_green_does_not_read_as_praise(self, catalog, engine) -> None:
        """"Nothing to clear" is true here, and true for the wrong reason."""
        path = engine.evaluate(REPO).inputs_snapshot["path_to_green"]

        assert path["reaches"] == NOT_ASSESSED
        assert path["available"] is False
        assert "nothing to clear" not in path["note"]
        assert "Nothing has scanned this repository" in path["note"]


class TestSomethingLooked:
    """The half a careless fix breaks."""

    def test_a_scanned_repo_with_no_findings_is_still_go(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """spec 09 §10: a real decision, not 'no data'.

        A tool ran and found nothing. That is evidence, the `go` is earned, and
        nothing about this case may change.
        """
        post_scan(client, auth, scan_run_id="clean")
        post_findings(client, auth, [], scan_run_id="clean")
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.overall_risk_score == 0
        assert decision.recommendation == "go"

    def test_no_applicable_targets_counts_as_having_looked(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """"There is no Python here" is an answer about the repository.

        A tool ran, read the tree and reported what it saw. Whether the right
        tools ran for this tree is issue #318's question and a different one.
        """
        post_scan(
            client, auth, scan_run_id="empty", scan_status="no_applicable_targets"
        )
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.recommendation == "go"

    def test_the_evidence_names_what_reported(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        post_scan(client, auth, scan_run_id="one")
        run_compaction()

        evidence = engine.evaluate(REPO).inputs_snapshot["evidence"]

        assert evidence["capabilities_reported"] == ["sast"]
        assert evidence["reporting_scan_runs"] == 1
        assert evidence["last_scan_at"] is not None
        assert evidence["go_withheld"] is False

    def test_the_reasoning_is_unchanged_when_something_looked(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        post_scan(client, auth, scan_run_id="clean")
        post_findings(client, auth, [], scan_run_id="clean")
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.reasoning.startswith("Go at 0/100.")
        assert "Nothing scored" in decision.reasoning


class TestMissingEvidenceNeverQuietens:
    def test_a_finding_keeps_its_verdict_without_a_reporting_scan_run(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """Absent evidence may withhold a `go`. It may never withhold a `no_go`.

        Three open criticals are three open criticals whether or not the run
        that carried them is recorded as having succeeded — something plainly
        looked, or there would be nothing to count.
        """
        post_scan(client, auth, scan_run_id="broke", scan_status="failure")
        post_findings(
            client, auth, [critical(i) for i in range(3)], scan_run_id="broke"
        )
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.recommendation == "no_go"

    def test_a_scored_decision_is_never_flagged_as_withheld(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """The flag the reasoning and the check run both read.

        Separate from the guard above so the two claims fail separately: one
        is "the verdict survives", the other is "nothing tells the reader it
        was withheld when it was not".
        """
        post_scan(client, auth, scan_run_id="broke", scan_status="failure")
        post_findings(
            client, auth, [critical(i) for i in range(3)], scan_run_id="broke"
        )
        run_compaction()

        evidence = engine.evaluate(REPO).inputs_snapshot["evidence"]

        assert evidence["available"] is False
        assert evidence["go_withheld"] is False


class TestTheCheckRunIsNotGreen:
    def test_not_assessed_is_never_a_success_conclusion(self) -> None:
        """A green tick is the reassurance this whole issue is about."""
        assert _CONCLUSION[NOT_ASSESSED] == "neutral"
        assert _CONCLUSION["go"] == "success"

    def test_the_summary_says_so_above_the_arithmetic(
        self, catalog, engine
    ) -> None:
        decision = engine.evaluate(REPO, decision_type="pr_gate", pr_number=1)

        summary = render_check_run_summary(decision, blocking=False)

        assert "Not Assessed — 0/100" in summary
        assert "nothing has scanned this repository" in summary.lower()
        assert summary.index("Not assessed") < summary.index(
            "How this score was reached"
        )
