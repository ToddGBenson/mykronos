"""Oracle consuming Aegis and Atlas — specs 06 §8, 07 §9, 09 §4.

Until Phase 4 these two categories were structural placeholders: present in
every snapshot, explicitly null, with a reason naming the phase that would
fill them in. These tests are about them carrying real numbers, and about the
boundaries that keep insider risk from being used in ways spec 06 §9 forbids.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.config import get_settings
from mykronos.oracle import load_policy
from mykronos.oracle.engine import OracleEngine
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan


@pytest.fixture
def engine(catalog):
    return OracleEngine(catalog, load_policy(get_settings().oracle_policy_path))


@pytest.fixture
def aegis_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'aegis')}"}


@pytest.fixture
def atlas_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}


def one_critical(client, run_compaction) -> None:
    """A baseline of 40 points, so a modifier's contribution is visible."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="base")
    post_findings(
        client, auth, [finding_payload(severity="critical")], scan_run_id="base"
    )
    run_compaction()


#: Per-signal ceilings, so a helper asking for N points spreads them across
#: enough signals to actually reach N rather than being silently capped.
_SPREAD = ["sensitive_path", "access_anomaly", "author_baseline", "ai_authorship"]


def score_aegis(client, auth, *, pr_number=2841, points=60, commit="a91f2c7"):
    from mykronos.aegis import SIGNAL_CAP

    signals = []
    remaining = points
    for key in _SPREAD:
        if remaining <= 0:
            break
        take = min(remaining, SIGNAL_CAP[key])
        signals.append({"key": key, "score": take, "rationale": f"{key} fired"})
        remaining -= take
    assert remaining == 0, f"cannot reach {points} points within the signal caps"

    return client.post(
        "/api/ingest/aegis",
        json={
            "pr_number": pr_number,
            "commit_sha": commit,
            "author_login": "octocat",
            "signals": signals,
        },
        headers=auth,
    )


def record_atlas(client, auth, *, criticals=0, commit="a91f2c7"):
    return client.post(
        "/api/ingest/atlas",
        json={
            "commit_sha": commit,
            "ecosystems": [
                {
                    "ecosystem": "npm",
                    "dependency_count": 200,
                    "critical_vulns": criticals,
                }
            ],
        },
        headers=auth,
    )


class TestInsiderRisk:
    def test_it_contributes_to_a_pull_request_gate(
        self, client, admin_auth, aegis_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, points=60)
        run_compaction()

        decision = engine.evaluate(REPO, decision_type="pr_gate", pr_number=2841)
        insider = decision.inputs_snapshot["insider_risk"]

        assert insider["available"] is True
        assert insider["score"] == 60
        assert insider["contribution"] == 18.0  # 60 × 0.3
        assert "insider-risk score 60" in decision.reasoning

    def test_it_is_not_consulted_for_a_portfolio_score(
        self, client, admin_auth, aegis_auth, run_compaction, engine
    ) -> None:
        """A standing repo score is not about anybody's pull request, and
        rolling one in would be the per-author aggregation spec 06 §9
        forbids."""
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, points=90)
        run_compaction()

        insider = engine.evaluate(REPO).inputs_snapshot["insider_risk"]

        assert insider["available"] is False
        assert insider["contribution"] == 0.0
        assert "specific pull request" in insider["reason"]

    def test_another_pull_requests_score_is_not_borrowed(
        self, client, admin_auth, aegis_auth, run_compaction, engine
    ) -> None:
        """The sharpest form of the same rule: one contributor's signal must
        never reach an unrelated colleague's decision."""
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, pr_number=1, points=90)
        run_compaction()

        insider = engine.evaluate(
            REPO, decision_type="pr_gate", pr_number=2
        ).inputs_snapshot["insider_risk"]

        assert insider["available"] is False
        assert insider["contribution"] == 0.0

    def test_the_latest_assessment_of_the_pr_wins(
        self, client, admin_auth, aegis_auth, run_compaction, engine
    ) -> None:
        """A PR is rescored on every push; the decision uses the current one."""
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, commit="aaa", points=90)
        run_compaction()
        score_aegis(client, aegis_auth, commit="bbb", points=40)
        run_compaction()

        insider = engine.evaluate(
            REPO, decision_type="pr_gate", pr_number=2841
        ).inputs_snapshot["insider_risk"]

        assert insider["score"] == 40
        assert insider["assessed_commit"] == "bbb"

    def test_absence_is_explained_rather_than_scored_as_zero(
        self, client, admin_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)

        insider = engine.evaluate(
            REPO, decision_type="pr_gate", pr_number=2841
        ).inputs_snapshot["insider_risk"]

        assert insider["available"] is False
        assert insider["score"] is None
        assert "not enabled" in insider["reason"] or "has not run" in insider["reason"]


class TestSupplyChainTrust:
    def test_a_low_trust_score_adds_a_penalty(
        self, client, admin_auth, atlas_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)
        record_atlas(client, atlas_auth, criticals=8)
        run_compaction()

        decision = engine.evaluate(REPO)
        sscs = decision.inputs_snapshot["sscs_trust"]

        assert sscs["available"] is True
        assert sscs["trust_score"] < 100
        assert sscs["contribution"] > 0
        assert "supply-chain trust" in decision.reasoning

    def test_the_penalty_is_capped(
        self, client, admin_auth, atlas_auth, run_compaction, engine
    ) -> None:
        """A bad dependency tree must not dominate a decision about the code
        somebody actually wrote."""
        one_critical(client, run_compaction)
        record_atlas(client, atlas_auth, criticals=100_000)
        run_compaction()

        sscs = engine.evaluate(REPO).inputs_snapshot["sscs_trust"]

        assert sscs["trust_score"] == 0
        assert sscs["contribution"] == sscs["penalty_cap"] == 20.0

    def test_a_perfect_tree_contributes_nothing(
        self, client, admin_auth, atlas_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)
        record_atlas(client, atlas_auth, criticals=0)
        run_compaction()

        sscs = engine.evaluate(REPO).inputs_snapshot["sscs_trust"]

        assert sscs["available"] is True, "evaluated, and found nothing wrong"
        assert sscs["trust_score"] == 100
        assert sscs["contribution"] == 0.0

    def test_it_applies_to_portfolio_scores_too(
        self, client, admin_auth, atlas_auth, run_compaction, engine
    ) -> None:
        """Unlike insider risk: a dependency tree is a property of the repo,
        not of one pull request."""
        one_critical(client, run_compaction)
        record_atlas(client, atlas_auth, criticals=8)
        run_compaction()

        portfolio = engine.evaluate(REPO).inputs_snapshot["sscs_trust"]
        gate = engine.evaluate(
            REPO, decision_type="pr_gate", pr_number=1
        ).inputs_snapshot["sscs_trust"]

        assert portfolio["contribution"] == gate["contribution"] > 0

    def test_absence_is_explained_rather_than_scored_as_zero(
        self, client, admin_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)

        sscs = engine.evaluate(REPO).inputs_snapshot["sscs_trust"]

        assert sscs["available"] is False
        assert sscs["trust_score"] is None
        assert sscs["contribution"] == 0.0


class TestTogether:
    def test_both_modifiers_appear_in_the_same_decision(
        self, client, admin_auth, aegis_auth, atlas_auth, run_compaction, engine
    ) -> None:
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, points=60)
        record_atlas(client, atlas_auth, criticals=8)
        run_compaction()

        decision = engine.evaluate(REPO, decision_type="pr_gate", pr_number=2841)
        keys = {term["key"] for term in decision.inputs_snapshot["terms"]}

        assert {"findings.critical", "insider_risk", "sscs_trust"} <= keys

    def test_the_score_is_still_reproducible(
        self, client, admin_auth, aegis_auth, atlas_auth, run_compaction, engine
    ) -> None:
        """spec 09 §9. New inputs must not introduce non-determinism."""
        one_critical(client, run_compaction)
        score_aegis(client, aegis_auth, points=60)
        record_atlas(client, atlas_auth, criticals=8)
        run_compaction()

        first = engine.evaluate(REPO, decision_type="pr_gate", pr_number=2841)
        second = engine.evaluate(REPO, decision_type="pr_gate", pr_number=2841)

        assert first.overall_risk_score == second.overall_risk_score
        assert first.reasoning == second.reasoning
