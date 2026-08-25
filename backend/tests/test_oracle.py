"""Oracle — spec 09.

Two things are under test that matter more than the arithmetic:

**Determinism** (spec 09 §9). Identical inputs and policy version must produce
an identical score, forever. The golden values below are pinned deliberately:
a policy change that does not update them fails the build, which is the point
— nobody should alter how risk is scored by accident.

**No hidden inputs** (spec 09 §5, §9). The reasoning is generated from the
snapshot alone, so anything it says must be traceable to a recorded term.
"""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from mykronos.config import get_settings
from mykronos.oracle import OracleEngine, load_policy, parse_policy, render_reasoning
from mykronos.oracle.policy import PolicyError
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


@pytest.fixture
def engine(catalog, policy):
    return OracleEngine(catalog, policy)


def seed(client, auth, run_compaction, findings: list[dict], run_id: str = "run-1"):
    post_scan(client, auth, scan_run_id=run_id)
    post_findings(client, auth, findings, scan_run_id=run_id)
    run_compaction()


def critical(index: int = 0, **overrides):
    return finding_payload(
        rule_id=f"CWE-89-{index}",
        severity="critical",
        symbol=f"fn_{index}",
        code_snippet=f"unsafe_{index}()",
        **overrides,
    )


class TestPolicyValidation:
    def test_the_shipped_policy_loads(self, policy) -> None:
        assert policy.version == "1.8"
        assert policy.severity_weights["critical"] == 40

    def test_an_unknown_curve_is_refused(self) -> None:
        """A curve this code does not implement would be silently ignored,
        which is worse than refusing to start."""
        document = _valid_policy()
        document["findings"]["curve"] = "quadratic"
        with pytest.raises(PolicyError, match="Unsupported findings curve"):
            parse_policy(document)

    def test_a_missing_severity_weight_is_refused(self) -> None:
        """An absent weight defaults to zero and silently stops scoring a
        whole band."""
        document = _valid_policy()
        del document["findings"]["weights"]["high"]
        with pytest.raises(PolicyError, match="missing weights for: high"):
            parse_policy(document)

    def test_inverted_thresholds_are_refused(self) -> None:
        """Otherwise no score can ever land on 'review'."""
        document = _valid_policy()
        document["thresholds"]["review_recommended"] = 90
        with pytest.raises(PolicyError, match="must be below no_go"):
            parse_policy(document)

    def test_a_missing_policy_file_is_fatal(self, tmp_path) -> None:
        """Falling back to a built-in default would mean scoring against
        weights nobody reviewed."""
        from mykronos.oracle import load_policy as load

        with pytest.raises(PolicyError, match="No Oracle policy"):
            load(tmp_path / "absent.yaml")


class TestScoringGoldenValues:
    """spec 09 §9: the same inputs always produce the same score."""

    @pytest.mark.parametrize(
        ("count", "expected"),
        [
            (1, 40),   # 40 × log2(2)
            (2, 63),   # 40 × log2(3)
            (3, 80),   # 40 × log2(4)
            (7, 120),  # clamps to 100
        ],
    )
    def test_critical_band_follows_the_curve(
        self, client, auth, catalog, run_compaction, engine, count: int, expected: int
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(count)])

        decision = engine.evaluate(REPO, decision_type="portfolio")

        assert decision.inputs_snapshot["totals"]["raw_score"] == pytest.approx(
            40 * math.log2(1 + count), abs=0.01
        )
        assert decision.overall_risk_score == min(100, expected)

    def test_the_saturation_fix_keeps_repos_rankable(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """The reason for D-018.

        Under the original linear policy three criticals hit the clamp and so
        did three hundred, so every vulnerable repo scored 100 and the
        portfolio could not be ranked. The raw score preserves order past the
        ceiling.
        """
        seed(client, auth, run_compaction, [critical(i) for i in range(8)])
        eight = engine.evaluate(REPO).inputs_snapshot["totals"]

        seed(
            client,
            auth,
            run_compaction,
            [critical(i) for i in range(40)],
            run_id="run-2",
        )
        forty = engine.evaluate(REPO).inputs_snapshot["totals"]

        assert eight["overall_risk_score"] == forty["overall_risk_score"] == 100
        assert forty["raw_score"] > eight["raw_score"], (
            "both clamp to 100, so ranking has to come from the raw score"
        )
        assert forty["clamped"] is True

    def test_mixed_severities_sum_per_band(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        seed(
            client,
            auth,
            run_compaction,
            [
                critical(0),
                finding_payload(rule_id="a", severity="high", symbol="a"),
                finding_payload(rule_id="b", severity="high", symbol="b"),
                finding_payload(rule_id="c", severity="medium", symbol="c"),
            ],
        )

        raw = engine.evaluate(REPO).inputs_snapshot["totals"]["raw_score"]

        expected = 40 * math.log2(2) + 20 * math.log2(3) + 5 * math.log2(2)
        assert raw == pytest.approx(expected, abs=0.01)

    def test_info_findings_never_contribute(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """Ingested for trend data, weighted zero for risk (spec 04 §5)."""
        seed(
            client,
            auth,
            run_compaction,
            [finding_payload(rule_id=f"i{i}", severity="info", symbol=f"s{i}") for i in range(20)],
        )
        assert engine.evaluate(REPO).overall_risk_score == 0

    def test_a_clean_repo_scores_zero_and_goes(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """spec 09 §10: a real decision, not 'no data'."""
        post_scan(client, auth, scan_run_id="clean")
        post_findings(client, auth, [], scan_run_id="clean")
        run_compaction()

        decision = engine.evaluate(REPO)

        assert decision.overall_risk_score == 0
        assert decision.recommendation == "go"
        assert decision.inputs_snapshot["findings"]["counts_by_severity"]["critical"] == 0

    def test_evaluation_is_reproducible(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(3)])
        moment = utcnow()

        first = engine.evaluate(REPO, as_of=moment)
        second = engine.evaluate(REPO, as_of=moment)

        assert first.overall_risk_score == second.overall_risk_score
        assert first.reasoning == second.reasoning
        assert first.inputs_snapshot == second.inputs_snapshot


class TestThresholds:
    @pytest.mark.parametrize(
        ("count", "recommendation"),
        [(0, "go"), (1, "review_recommended"), (3, "no_go")],
    )
    def test_recommendation_bands(
        self, client, auth, catalog, run_compaction, engine, count, recommendation
    ) -> None:
        if count:
            seed(client, auth, run_compaction, [critical(i) for i in range(count)])
        else:
            post_scan(client, auth, scan_run_id="none")
            post_findings(client, auth, [], scan_run_id="none")
            run_compaction()

        assert engine.evaluate(REPO).recommendation == recommendation


class TestScope:
    def test_human_dispositions_are_not_rescored(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """Re-scoring a finding somebody accepted would mean Oracle overruling
        them every night."""
        from tests.test_lake import set_status

        seed(client, auth, run_compaction, [critical(0)])
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]
        set_status(catalog, finding_id, "accepted_risk")

        assert engine.evaluate(REPO).overall_risk_score == 0

    def test_network_findings_are_excluded_from_gates_but_not_portfolio(
        self, client, catalog, run_compaction, engine
    ) -> None:
        """spec 14 §7: a host with an open port did not arrive with this pull
        request and will not leave with it."""
        from tests.conftest import issue_token

        token = issue_token(client, REPO, "cloud")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="net", capability="cloud")
        post_findings(
            client,
            auth,
            [critical(0)],
            scan_run_id="net",
            capability="cloud",
        )
        run_compaction()

        # The policy excludes 'network'; 'cloud' is not excluded, so this
        # asserts the mechanism rather than the specific capability.
        gate = engine.evaluate(REPO, decision_type="pr_gate")
        portfolio = engine.evaluate(REPO, decision_type="portfolio")

        assert gate.inputs_snapshot["decision_scope"]["capabilities_excluded"] == ["network"]
        assert portfolio.inputs_snapshot["decision_scope"]["capabilities_excluded"] == []

    def test_an_unknown_decision_type_is_refused(self, engine) -> None:
        with pytest.raises(ValueError, match="Unknown decision_type"):
            engine.evaluate(REPO, decision_type="vibes")


class TestAgeEscalation:
    def test_an_aged_critical_adds_its_penalty(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """What stops 'accepted for now' quietly becoming 'accepted forever'."""
        seed(client, auth, run_compaction, [critical(0)])

        fresh = engine.evaluate(REPO)
        later = engine.evaluate(REPO, as_of=utcnow() + timedelta(days=45))

        assert later.overall_risk_score > fresh.overall_risk_score
        keys = [t["key"] for t in later.inputs_snapshot["terms"]]
        assert "age.critical" in keys
        assert "age.critical" not in [t["key"] for t in fresh.inputs_snapshot["terms"]]

    def test_age_depends_on_first_seen_surviving_refactors(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """Age is only meaningful because identity is anchored to code rather
        than line numbers (D-001) — otherwise every refactor resets the clock
        and nothing ever looks old."""
        seed(client, auth, run_compaction, [critical(0, line_start=10)])
        seed(
            client,
            auth,
            run_compaction,
            [critical(0, line_start=250)],
            run_id="after-refactor",
        )

        later = engine.evaluate(REPO, as_of=utcnow() + timedelta(days=45))
        assert "age.critical" in [t["key"] for t in later.inputs_snapshot["terms"]]


class TestSnapshotCompleteness:
    """spec 09 §9: no input category is silently omitted.

    As of Phase 6 every category spec 09 §4 names is implemented, so this no
    longer tests for placeholders. What it still tests — and what matters
    more — is that each category is *present* and either carries data or says
    why it does not. A score whose inputs you cannot enumerate is a score you
    cannot audit, whether the gap is an unbuilt capability or one that had
    nothing to report.
    """

    CATEGORIES = [
        "insider_risk",
        "sscs_trust",
        "remediation_in_flight",
        "false_positive_dampening",
    ]

    def test_every_category_is_present(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        seed(client, auth, run_compaction, [critical(0)])
        snapshot = engine.evaluate(REPO).inputs_snapshot

        for category in self.CATEGORIES:
            assert category in snapshot, f"{category} was omitted entirely"
            assert "available" in snapshot[category]
            assert "contribution" in snapshot[category]

    def test_an_unavailable_category_explains_itself(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """'We looked and found nothing' and 'we never looked' produce the
        same score and very different levels of trust."""
        seed(client, auth, run_compaction, [critical(0)])
        snapshot = engine.evaluate(REPO).inputs_snapshot

        for category in self.CATEGORIES:
            entry = snapshot[category]
            if entry["available"]:
                continue
            assert entry["contribution"] == 0.0
            assert entry["reason"].strip(), (
                f"{category} is unavailable but does not say why"
            )

    def test_a_category_with_nothing_to_report_still_says_so(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """Patchwork writes no rows for a repository it does not run on, and
        "no open fixes" is the complete answer for one — so the category is
        available with a count of zero rather than unavailable."""
        seed(client, auth, run_compaction, [critical(0)])
        remediation = engine.evaluate(REPO).inputs_snapshot["remediation_in_flight"]

        assert remediation["available"] is True
        assert remediation["covered_findings"] == 0
        assert "No Patchwork pull request is open" in remediation["reason"]

    def test_every_term_carries_its_arithmetic(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """So a human can check the number rather than trust it."""
        seed(client, auth, run_compaction, [critical(0), critical(1)])
        terms = engine.evaluate(REPO).inputs_snapshot["terms"]

        assert terms
        for term in terms:
            assert term["detail"]
            assert term["contribution"] > 0
            assert term["inputs"]

    def test_the_snapshot_records_the_policy_version(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """spec 09 §10: past decisions stay reproducible after a policy change."""
        seed(client, auth, run_compaction, [critical(0)])
        decision = engine.evaluate(REPO)
        assert decision.policy_version == "1.8"
        assert decision.inputs_snapshot["policy_version"] == "1.8"


class TestReasoning:
    def test_reasoning_names_each_contributing_term(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        seed(
            client,
            auth,
            run_compaction,
            [critical(0), critical(1), finding_payload(rule_id="h", severity="high", symbol="h")],
        )
        decision = engine.evaluate(REPO)

        assert "2 open critical findings" in decision.reasoning
        assert "1 open high finding" in decision.reasoning
        assert str(decision.overall_risk_score) in decision.reasoning

    def test_reasoning_is_a_pure_function_of_the_snapshot(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """The mechanism behind "no hidden inputs": rendering can only read
        what was recorded."""
        seed(client, auth, run_compaction, [critical(0)])
        decision = engine.evaluate(REPO)

        assert render_reasoning(decision.inputs_snapshot) == decision.reasoning

    def test_reasoning_discloses_what_was_not_consulted(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        """A partial picture presented as a complete one is the failure mode
        that makes a risk score untrustworthy."""
        seed(client, auth, run_compaction, [critical(0)])
        reasoning = engine.evaluate(REPO).reasoning

        assert "Not yet consulted" in reasoning
        assert "insider_risk" in reasoning
        assert "partial picture" in reasoning

    def test_a_clean_repo_reads_as_a_real_decision(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        post_scan(client, auth, scan_run_id="clean")
        post_findings(client, auth, [], scan_run_id="clean")
        run_compaction()

        reasoning = engine.evaluate(REPO).reasoning
        assert "Go at 0/100" in reasoning
        assert "no open findings in scope" in reasoning

    def test_clamping_is_disclosed(
        self, client, auth, catalog, run_compaction, engine
    ) -> None:
        seed(client, auth, run_compaction, [critical(i) for i in range(10)])
        reasoning = engine.evaluate(REPO).reasoning
        assert "clamped to 100" in reasoning


def _valid_policy() -> dict:
    return {
        "version": "test",
        "findings": {
            "curve": "log2",
            "weights": {"critical": 40, "high": 20, "medium": 5, "low": 1, "info": 0},
        },
        "modifiers": {
            "insider_risk": {"multiplier": 0.3},
            "sscs_trust": {"penalty_cap": 20},
            "remediation_in_flight": {"discount": 0.5},
            "finding_age": {"over_30_days_critical": 15, "over_90_days_high": 10},
            "false_positive_dampening": {"threshold": 0.5, "dampening_factor": 0.5},
        },
        "thresholds": {"no_go": 70, "review_recommended": 30},
        "scope": {"minimum_severity": "low", "statuses_considered": ["open"]},
    }
