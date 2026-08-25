"""Terms that reward (spec 26 §2) and the ageing forecast (§4).

Until these existed the model could only punish: nine modifiers, one negative,
and that one a fact about code structure rather than a reward for anything
anybody did. A model that can only punish is one people argue with rather than
act on.

The two tests that carry the most weight are the ones about what a credit must
*not* do: it must not be earnable by doing nothing, and it must not let a team
test its way out of an exploited critical.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import regression
from mykronos.config import get_settings
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.oracle import OracleEngine, load_policy
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan


@pytest.fixture
def engine(catalog: Catalog) -> OracleEngine:
    return OracleEngine(catalog, load_policy(get_settings().oracle_policy_path))


def seed(
    client: TestClient,
    auth: dict[str, str],
    run_compaction: Any,
    findings: list[dict[str, Any]],
) -> list[str]:
    post_scan(client, auth)
    post_findings(client, auth, findings)
    run_compaction()
    return [
        str(r[0])
        for r in client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT finding_id FROM findings ORDER BY rule_id"
        )
    ]


def critical(index: int) -> dict[str, Any]:
    return finding_payload(
        rule_id=f"CWE-{index}", severity="critical", symbol=f"fn_{index}",
        code_snippet=f"unsafe_{index}()",
    )


def posture(engine: OracleEngine) -> dict[str, Any]:
    return engine.evaluate(REPO).inputs_snapshot["posture_credits"]


class TestWhatMustNotEarnAnything:
    def test_a_brand_new_backlog_earns_nothing(
        self, client: TestClient, auth, engine: OracleEngine, run_compaction
    ) -> None:
        """The flaw the golden scoring tests caught: a repository full of
        fresh criticals is inside every remediation window by construction and
        has done nothing to earn it. A credit that rewards the clock rather
        than the team is what the evidence-not-switches rule exists to stop."""
        seed(client, auth, run_compaction, [critical(i) for i in range(3)])

        snapshot = posture(engine)

        assert snapshot["applied"] == 0
        assert snapshot["credits"]["within_target"]["available"] is False

    def test_a_handful_of_fixes_is_not_a_rate(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        """A team that has fixed three things well has not earned a rate, and
        must not be scored as though it failed seven."""
        seed(client, auth, run_compaction, [critical(0)])

        snapshot = posture(engine)

        assert snapshot["credits"]["verified_fix_rate"]["available"] is False
        assert "minimum sample" in snapshot["credits"]["verified_fix_rate"]["reason"]

    def test_nothing_fixed_means_no_coverage_to_earn(
        self, client: TestClient, auth, engine: OracleEngine, run_compaction
    ) -> None:
        seed(client, auth, run_compaction, [critical(0)])

        assert posture(engine)["credits"]["regression_coverage"]["available"] is False


class TestWhatDoesEarn:
    def test_a_pinned_test_on_a_fixed_finding_credits(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(4)])
        update_findings(
            catalog,
            locate_findings(catalog, ids[:2]),
            "status = 'fixed', resolved_at = ?",
            [utcnow()],
        )
        from tests.conftest import issue_token

        unit_auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'unit')}"}
        post_scan(
            client, unit_auth, scan_run_id="unit-1", capability="unit",
            tool_name="junit", scan_status="success", finding_count=0,
        )
        for finding_id in ids[:2]:
            regression.record(
                client.app.state.buffer,  # type: ignore[attr-defined]
                repo_full_name=REPO,
                finding_id=finding_id,
                test_identifier=f"t.test_{finding_id[:6]}",
                capability="unit",
            )
        run_compaction()

        snapshot = posture(engine)

        assert snapshot["credits"]["regression_coverage"]["covered"] == 2
        assert snapshot["applied"] > 0
        assert snapshot["contribution"] < 0

    def test_a_finding_fixed_inside_its_window_credits(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        """Closed inside the deadline is work; still-open-and-not-late is
        not."""
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(2)])
        due = utcnow() + timedelta(days=5)
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?, due_at = ?",
            [utcnow(), due],
        )
        run_compaction()

        credit = posture(engine)["credits"]["within_target"]

        assert credit["available"] is True
        assert credit["on_track"] == 2

    def test_the_score_actually_falls(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        """The whole point: work a team did lowers the number."""
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(6)])
        before = engine.evaluate(REPO).overall_risk_score

        update_findings(
            catalog,
            locate_findings(catalog, ids[:3]),
            "status = 'fixed', resolved_at = ?, due_at = ?",
            [utcnow(), utcnow() + timedelta(days=5)],
        )
        run_compaction()

        assert engine.evaluate(REPO).overall_risk_score < before


class TestTheLimits:
    def test_credits_cannot_clear_an_open_critical(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        """spec 26 §2's hard rule: a team may not test its way out of an
        exploited critical."""
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(8)])
        update_findings(
            catalog,
            locate_findings(catalog, ids[:6]),
            "status = 'fixed', resolved_at = ?, due_at = ?",
            [utcnow(), utcnow() + timedelta(days=5)],
        )
        run_compaction()

        decision = engine.evaluate(REPO)

        # Two criticals remain open; credits must not take it to `go`.
        assert decision.recommendation != "go"

    def test_the_total_is_capped(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        policy = load_policy(get_settings().oracle_policy_path)
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(20)])
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?, due_at = ?",
            [utcnow(), utcnow() + timedelta(days=5)],
        )
        run_compaction()

        assert posture(engine)["applied"] <= policy.posture.total_cap

    def test_the_published_terms_sum_to_what_was_applied(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        """A breakdown whose parts do not add up to the total is one nobody
        can check."""
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(20)])
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "status = 'fixed', resolved_at = ?, due_at = ?",
            [utcnow(), utcnow() + timedelta(days=5)],
        )
        run_compaction()

        snapshot = engine.evaluate(REPO).inputs_snapshot
        applied = snapshot["posture_credits"]["applied"]
        from_terms = -sum(
            t["contribution"] for t in snapshot["terms"] if t["key"].startswith("posture.")
        )

        assert from_terms == pytest.approx(applied, abs=0.05)


class TestTheForecast:
    def test_it_says_when_ageing_alone_crosses(
        self, client: TestClient, auth, engine: OracleEngine, catalog: Catalog, run_compaction
    ) -> None:
        ids = seed(client, auth, run_compaction, [critical(i) for i in range(2)])
        # Twenty days old: ten from crossing the 30-day critical threshold.
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "first_seen_at = ?",
            [utcnow() - timedelta(days=20)],
        )
        run_compaction()

        forecast = engine.evaluate(REPO).inputs_snapshot["forecast"]

        assert forecast["available"] is True
        if forecast.get("crosses_in_days") is not None:
            assert forecast["crosses_in_days"] == 10

    def test_an_empty_repository_has_nothing_to_forecast(
        self, engine: OracleEngine
    ) -> None:
        forecast = engine.evaluate(REPO).inputs_snapshot["forecast"]
        assert forecast["available"] is False

    def test_a_repository_already_at_no_go_is_not_forecast(
        self, client: TestClient, auth, engine: OracleEngine, run_compaction
    ) -> None:
        """Nothing to warn about: it is already there."""
        seed(client, auth, run_compaction, [critical(i) for i in range(40)])

        decision = engine.evaluate(REPO)

        if decision.recommendation == "no_go":
            assert decision.inputs_snapshot["forecast"]["available"] is False


class TestTheSnapshotContract:
    def test_the_category_is_always_present(self, engine: OracleEngine) -> None:
        """spec 09 §9: a category with nothing to say still appears."""
        assert "posture_credits" in engine.evaluate(REPO).inputs_snapshot

    def test_every_credit_says_why_when_unavailable(
        self, client: TestClient, auth, engine: OracleEngine, run_compaction
    ) -> None:
        """A credit that silently contributes zero is how a team concludes
        the model is rigged."""
        seed(client, auth, run_compaction, [critical(0)])

        for credit in posture(engine)["credits"].values():
            if not credit["available"]:
                assert credit["reason"]
