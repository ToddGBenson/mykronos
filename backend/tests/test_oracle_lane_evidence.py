"""A gate must not say `go` when a lane it relies on said nothing (TheHub #60848).

`evidence` (issue #341) answers "has anything ever looked at this repository",
and deliberately repository-wide. That left the per-commit version of the same
hole open: a required scan lane that uploaded nothing for the commit under
evaluation was invisible, because the lane's runs on *earlier* commits were
still evidence that something had looked. A gate could therefore record `go`
on a commit whose secrets scan never reached Mykronos.

Option A from the story: each lane the policy requires per commit is judged on
its own. A lane with no reporting scan run for the commit is
`insufficient_evidence`, and a verdict that would have been `go` becomes
`insufficient_evidence` too. The same two rules as `not_assessed` hold:

* missing evidence may withhold a `go`, never quieten a worse verdict;
* a lane this repository has never run is not required of it. Whether it
  *should* run that lane is coverage's question, not the gate's, and making
  every repository without containers fail every gate would be the toggle
  pressure `composition.py` warns about.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from mykronos.config import get_settings
from mykronos.oracle import (
    INSUFFICIENT_EVIDENCE,
    OracleEngine,
    PolicyError,
    load_policy,
    parse_policy,
    render_reasoning,
)
from mykronos.oracle.service import _CONCLUSION, render_check_run_summary
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan

COMMIT = "c0ffee0000000000000000000000000000000001"
EARLIER = "c0ffee0000000000000000000000000000000000"


@pytest.fixture
def policy():
    return replace(
        load_policy(get_settings().oracle_policy_path),
        lanes_required_per_commit=("sast", "secrets"),
    )


@pytest.fixture
def engine(catalog, policy):
    return OracleEngine(catalog, policy)


@pytest.fixture
def lanes_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'secrets')}"}


def scan(client, auth, capability: str, commit: str, run: str, status: str = "success"):
    response = post_scan(
        client,
        auth,
        scan_run_id=run,
        capability=capability,
        commit_sha=commit,
        scan_status=status,
    )
    assert response.status_code < 300, response.text
    post_findings(client, auth, [], scan_run_id=run, capability=capability)


def gate(engine, commit: str = COMMIT):
    return engine.evaluate(REPO, decision_type="commit_gate", commit_sha=commit)


class TestALaneThatSaidNothing:
    def test_a_required_lane_silent_on_this_commit_withholds_go(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        """The bug: secrets ran before, not on this commit, and the gate said go."""
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        run_compaction()

        decision = gate(engine)

        assert decision.overall_risk_score == 0
        assert decision.recommendation == INSUFFICIENT_EVIDENCE
        lanes = decision.inputs_snapshot["lane_evidence"]
        assert lanes["evaluated"] is True
        assert lanes["go_withheld"] is True
        assert lanes["insufficient"] == ["secrets"]
        by_lane = {lane["capability"]: lane["status"] for lane in lanes["lanes"]}
        assert by_lane == {"sast": "reported", "secrets": INSUFFICIENT_EVIDENCE}

    def test_a_failed_run_on_this_commit_is_not_evidence(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        """A lane that crashed on the commit read nothing of it."""
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        scan(client, lanes_auth, "secrets", COMMIT, "secrets-broke", status="failure")
        run_compaction()

        decision = gate(engine)

        assert decision.recommendation == INSUFFICIENT_EVIDENCE
        lane = next(
            lane
            for lane in decision.inputs_snapshot["lane_evidence"]["lanes"]
            if lane["capability"] == "secrets"
        )
        assert lane["status"] == INSUFFICIENT_EVIDENCE
        assert "failed" in lane["reason"]

    def test_the_reasoning_names_the_silent_lane(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        run_compaction()

        decision = gate(engine)

        assert decision.reasoning.startswith("Insufficient evidence.")
        assert "secrets" in decision.reasoning
        assert render_reasoning(decision.inputs_snapshot) == decision.reasoning

    def test_the_check_run_is_not_green(self, client, lanes_auth, run_compaction, engine) -> None:
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        run_compaction()

        summary = render_check_run_summary(gate(engine), blocking=False)

        assert _CONCLUSION[INSUFFICIENT_EVIDENCE] == "neutral"
        assert "Insufficient Evidence — 0/100" in summary
        assert summary.index("secrets") < summary.index("How this score was reached")


class TestTheHalfAFixCouldBreak:
    def test_every_required_lane_reported_on_this_commit_is_still_go(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", COMMIT, "secrets-now")
        run_compaction()

        decision = gate(engine)

        assert decision.recommendation == "go"
        assert decision.inputs_snapshot["lane_evidence"]["insufficient"] == []
        assert decision.reasoning.startswith("Go at 0/100.")

    def test_a_lane_this_repository_never_ran_is_not_required(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        """Required means "required of a repository that runs it"."""
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        run_compaction()

        decision = gate(engine)

        assert decision.recommendation == "go"
        lanes = {
            lane["capability"]: lane["status"]
            for lane in decision.inputs_snapshot["lane_evidence"]["lanes"]
        }
        assert lanes["secrets"] == "not_run_here"

    def test_a_portfolio_decision_is_not_judged_per_commit(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        scan(client, lanes_auth, "sast", COMMIT, "sast-now")
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.recommendation == "go"
        assert decision.inputs_snapshot["lane_evidence"]["evaluated"] is False

    def test_missing_lane_evidence_never_quietens_a_no_go(
        self, client, lanes_auth, run_compaction, engine
    ) -> None:
        scan(client, lanes_auth, "secrets", EARLIER, "secrets-before")
        post_scan(client, lanes_auth, scan_run_id="sast-now", commit_sha=COMMIT)
        post_findings(
            client,
            lanes_auth,
            [
                finding_payload(rule_id=f"CWE-89-{i}", symbol=f"f{i}", code_snippet=f"x{i}()")
                for i in range(3)
            ],
            scan_run_id="sast-now",
        )
        run_compaction()

        decision = gate(engine)

        assert decision.recommendation == "no_go"
        assert decision.inputs_snapshot["lane_evidence"]["insufficient"] == ["secrets"]
        assert decision.inputs_snapshot["lane_evidence"]["go_withheld"] is False


class TestThePolicy:
    def test_the_shipped_policy_requires_the_per_commit_scan_lanes(self) -> None:
        shipped = load_policy(get_settings().oracle_policy_path)

        assert set(shipped.lanes_required_per_commit) == {
            "secrets",
            "atlas",
            "sast",
            "iac",
            "containers",
        }

    def test_an_unknown_capability_is_refused(self) -> None:
        document = load_policy(get_settings().oracle_policy_path).raw
        scope = {**document["scope"], "lanes_required_per_commit": ["sasst"]}
        broken = {**document, "scope": scope}

        with pytest.raises(PolicyError, match="sasst"):
            parse_policy(broken)
