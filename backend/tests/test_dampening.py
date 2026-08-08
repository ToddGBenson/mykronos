"""False-positive dampening end to end — spec 11 §6.1, spec 09 §4.

The learning loop's only closed circuit: a human dismisses findings with a
reason, and Oracle's next decision weighs that rule less. Everything else the
Knowledge Store does is advisory, so this is where the care goes — and where
the minimum-observations gate earns its place.

`TestTheRoadmapDemo` is the Phase 5 acceptance demo from
specs/13-build-roadmap.md, executable.
"""

from __future__ import annotations

import pytest

from mykronos.config import get_settings
from mykronos.knowledge import KnowledgeStore
from mykronos.oracle import load_policy
from mykronos.oracle.engine import OracleEngine
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

NOISY = "CKV_AWS_123"


@pytest.fixture
def store(client) -> KnowledgeStore:
    """The app's own store, so the API writes and the engine reads one file."""
    return client.app.state.knowledge


@pytest.fixture
def engine(client, store) -> OracleEngine:
    return OracleEngine(
        client.app.state.catalog,
        load_policy(get_settings().oracle_policy_path),
        store,
    )


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'iac')}"}


def seed_findings(client, auth, run_compaction, *, rule: str, count: int, severity="critical"):
    """`count` distinct findings of one rule, so they are separate rows."""
    post_scan(client, auth, scan_run_id=f"scan-{rule}")
    post_findings(
        client,
        auth,
        [
            finding_payload(
                rule_id=rule,
                severity=severity,
                symbol=f"{rule}_{i}",
                code_snippet=f"resource_{rule}_{i}()",
            )
            for i in range(count)
        ],
        scan_run_id=f"scan-{rule}",
    )
    run_compaction()


def finding_ids(catalog, rule: str) -> list[str]:
    return [
        str(row[0])
        for row in catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = ? ORDER BY finding_id",
            [rule],
        )
    ]


def dismiss(client, admin_auth, finding_id: str, reason: str):
    return client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": reason},
        headers=admin_auth,
    )


class TestTheGate:
    """spec 11 §6.1's minimum. Without it, one click quietens a rule."""

    def test_one_dismissal_does_not_dampen(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        dismiss(client, admin_auth, finding_ids(catalog, NOISY)[0], "generated code")
        run_compaction()

        snapshot = engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"]

        assert snapshot["available"] is True
        assert snapshot["dampened_rules"] == []
        assert "reasoned dismissals" in snapshot["reason"]

    def test_three_reasoned_dismissals_do(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "the whole module is generated")
        run_compaction()

        rules = engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"][
            "dampened_rules"
        ]

        assert [r["rule_id"] for r in rules] == [NOISY]
        assert rules[0]["reasoned_observations"] == 3

    def test_dismissals_without_reasons_never_count(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        """spec 11 §4: reasons are what make a learning actionable rather than
        a statistic, and this is the line where that is enforced."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "")
        run_compaction()

        snapshot = engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"]

        assert snapshot["dampened_rules"] == []

    def test_a_rate_below_threshold_does_not_dampen(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        """Three dismissals out of twenty is not a noisy rule, it is a rule
        that is usually right."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=20)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "generated")
        run_compaction()

        snapshot = engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"]

        assert snapshot["dampened_rules"] == []

    def test_accepted_risk_teaches_nothing_about_the_rule(
        self, client, admin_auth, auth, run_compaction, catalog, engine, store
    ) -> None:
        """It says the finding is real and we are living with it — a statement
        about appetite, not detection quality."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            client.patch(
                f"/api/dashboard/findings/{finding_id}/status",
                json={"status": "accepted_risk", "reason": "scheduled for Q3"},
                headers=admin_auth,
            )
        run_compaction()

        assert store.list_entries() == []
        assert (
            engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"][
                "dampened_rules"
            ]
            == []
        )


class TestTheEffectOnScoring:
    def test_a_dampened_rule_lowers_the_score(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        before = engine.evaluate(REPO).overall_risk_score

        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "generated module")
        run_compaction()
        after = engine.evaluate(REPO).overall_risk_score

        assert after < before

    def test_undampened_rules_in_the_same_band_are_untouched(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        """Halving the whole severity band would quieten the real findings
        alongside the noisy ones, which is why the factor is applied to the
        count inside the curve rather than to the band's weight outside it."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        seed_findings(client, auth, run_compaction, rule="CWE-89", count=2)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "generated module")
        run_compaction()

        term = next(
            t
            for t in engine.evaluate(REPO).inputs_snapshot["terms"]
            if t["key"] == "findings.critical"
        )

        # One noisy finding still open plus two real ones; only the noisy one
        # is discounted.
        assert term["inputs"]["dampened"] == 1
        assert term["inputs"]["count"] == 3
        assert term["inputs"]["effective_count"] == pytest.approx(2.5)

    def test_the_evidence_travels_with_the_decision(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        """A weight that quietly halved is exactly the kind of hidden input
        spec 09 exists to prevent."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "the whole module is generated")
        run_compaction()

        rule = engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"][
            "dampened_rules"
        ][0]

        assert rule["dismissed"] == 3
        assert rule["of_total"] == 4
        assert rule["false_positive_rate"] == pytest.approx(0.75)
        assert rule["weight_multiplier"] == 0.5
        assert "the whole module is generated" in rule["reasons"]

    def test_the_arithmetic_is_shown_in_the_band(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "generated")
        run_compaction()

        term = next(
            t
            for t in engine.evaluate(REPO).inputs_snapshot["terms"]
            if t["key"] == "findings.critical"
        )

        assert "dampened rules" in term["detail"]
        assert "dampened rule" in term["label"]

    def test_no_store_means_no_dampening_not_no_score(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        """spec 11 §6: dampening is an adjustment on top of a correct score."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)

        bare = OracleEngine(
            client.app.state.catalog, load_policy(get_settings().oracle_policy_path)
        )
        snapshot = bare.evaluate(REPO).inputs_snapshot

        assert snapshot["false_positive_dampening"]["available"] is False
        assert bare.evaluate(REPO).overall_risk_score > 0

    def test_dampening_fades_as_the_learning_decays(
        self, client, admin_auth, auth, run_compaction, catalog, store
    ) -> None:
        """An opinion nobody has reconfirmed in years should stop quietening a
        rule. This is the whole reason confidence decays."""
        from datetime import timedelta

        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)
        for finding_id in finding_ids(catalog, NOISY)[:3]:
            dismiss(client, admin_auth, finding_id, "generated")
        run_compaction()

        engine = OracleEngine(
            client.app.state.catalog,
            load_policy(get_settings().oracle_policy_path),
            store,
        )
        entry = store.list_entries()[0]
        much_later = entry.last_confirmed_at + timedelta(days=3_650)

        fresh = engine.evaluate(REPO).overall_risk_score
        stale = engine.evaluate(REPO, as_of=much_later).overall_risk_score

        assert stale > fresh, "a forgotten learning should stop discounting"


class TestTheRoadmapDemo:
    """specs/13-build-roadmap.md, Phase 5:

    "dismiss a finding as a false positive twice across two different PRs on
    the same repo; show Oracle's next decision reflects a dampened weight for
    that rule_id."

    Written as the roadmap describes it, with one correction: the policy's
    `min_observations` is 3, so the demo needs a third dismissal. That is the
    minimum doing its job — two dismissals is the point at which a pattern
    becomes *plausible*, not the point at which it should change a score.
    """

    def test_the_demo(
        self, client, admin_auth, auth, run_compaction, catalog, engine
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=4)

        baseline = engine.evaluate(REPO)
        assert baseline.inputs_snapshot["false_positive_dampening"]["dampened_rules"] == []

        ids = finding_ids(catalog, NOISY)
        dismiss(client, admin_auth, ids[0], "vendored terraform module, not ours")
        run_compaction()
        assert (
            engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"][
                "dampened_rules"
            ]
            == []
        ), "one dismissal is an anecdote"

        dismiss(client, admin_auth, ids[1], "same vendored module")
        run_compaction()
        assert (
            engine.evaluate(REPO).inputs_snapshot["false_positive_dampening"][
                "dampened_rules"
            ]
            == []
        ), "two is a pattern, but not yet evidence"

        dismiss(client, admin_auth, ids[2], "same vendored module again")
        run_compaction()
        final = engine.evaluate(REPO)

        rules = final.inputs_snapshot["false_positive_dampening"]["dampened_rules"]
        assert [r["rule_id"] for r in rules] == [NOISY]
        assert final.overall_risk_score < baseline.overall_risk_score
        assert "dampened" in final.reasoning


class TestOverrideCapture:
    def test_an_override_becomes_a_learning(
        self, client, admin_auth, auth, run_compaction, catalog, store
    ) -> None:
        """spec 09 §6 calls overrides "exactly the data that should most
        influence policy tuning over time"."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule="CWE-89", count=6)
        oracle_auth = {
            "Authorization": f"Bearer {issue_token(client, REPO, 'oracle')}"
        }
        decision_id = client.post(
            "/api/oracle/evaluate",
            json={"decision_type": "pr_gate", "commit_sha": "abc", "pr_number": 1},
            headers=oracle_auth,
        ).json()["decision_id"]
        run_compaction()

        client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "All six are in a test fixture that never ships."},
            headers=admin_auth,
        )

        entries = [e for e in store.list_entries() if e.source_type == "decision_override"]
        assert len(entries) == 1
        assert entries[0].subject == "no_go"
        assert "never ships" in entries[0].reasons[0]

    def test_repeated_overrides_of_the_same_verdict_reconfirm(
        self, client, admin_auth, auth, run_compaction, catalog, store
    ) -> None:
        """What recurs — and what a policy change would address — is "we keep
        overriding no_go on this repo", never "we overrode decision 4f2a"."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule="CWE-89", count=6)
        oracle_auth = {
            "Authorization": f"Bearer {issue_token(client, REPO, 'oracle')}"
        }

        for i in range(2):
            decision_id = client.post(
                "/api/oracle/evaluate",
                json={
                    "decision_type": "pr_gate",
                    "commit_sha": f"sha{i}",
                    "pr_number": i + 1,
                },
                headers=oracle_auth,
            ).json()["decision_id"]
            run_compaction()
            client.post(
                f"/api/oracle/decisions/{decision_id}/override",
                json={"reason": f"fixture, run {i}"},
                headers=admin_auth,
            )

        entries = [e for e in store.list_entries() if e.source_type == "decision_override"]
        assert len(entries) == 1
        assert entries[0].observations == 2


class TestTheDismissalResponse:
    def test_it_says_a_learning_was_recorded(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=2)

        body = dismiss(
            client, admin_auth, finding_ids(catalog, NOISY)[0], "generated"
        ).json()

        assert "recorded a new learning" in body["retro_signal"]

    def test_it_says_when_one_was_reconfirmed(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=2)
        ids = finding_ids(catalog, NOISY)
        dismiss(client, admin_auth, ids[0], "generated")

        body = dismiss(client, admin_auth, ids[1], "generated").json()

        assert "reconfirmed" in body["retro_signal"]
        assert "2 observations" in body["retro_signal"]

    def test_it_says_a_bare_click_is_barred(
        self, client, admin_auth, auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=2)

        body = dismiss(client, admin_auth, finding_ids(catalog, NOISY)[0], "").json()

        assert "barred from promotion or dampening" in body["retro_signal"]

    def test_a_failed_capture_does_not_fail_the_dismissal(
        self, client, admin_auth, auth, run_compaction, catalog, monkeypatch
    ) -> None:
        """The lake is already written by the time we get here. Failing the
        request would undo a real thing to protect a derived one."""
        onboard(client, admin_auth)
        seed_findings(client, auth, run_compaction, rule=NOISY, count=2)
        monkeypatch.setattr(
            client.app.state.knowledge,
            "add_entry",
            lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")),
        )

        response = dismiss(client, admin_auth, finding_ids(catalog, NOISY)[0], "x")

        assert response.status_code == 200
        assert "could not be stored" in response.json()["retro_signal"]
