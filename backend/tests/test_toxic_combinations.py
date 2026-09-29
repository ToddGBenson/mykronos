"""Toxic combinations in the risk decision, the briefing and the estate API.

Operator decisions (2026-09-28) these pin:
- a critical combination forces `no_go`; high and medium ones add points;
- accepted findings still count, so accepting half a pair cannot hide it;
- a combination is worse than its worst member, and critical when KEV-listed;
- "none found" names the rules that could not have fired.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest

from mykronos import briefing as briefing_report
from mykronos import toxic
from mykronos.config import get_settings
from mykronos.oracle import OracleEngine, load_policy, parse_policy, render_reasoning
from tests.conftest import REPO, finding_payload, post_findings, post_scan

FILE = "orders/query.py"


def _pair(
    injectable: str = "medium", unauthenticated: str = "medium"
) -> list[dict[str, Any]]:
    """The spec 08 example: an injectable query and a missing auth check, one file."""
    return [
        finding_payload(
            rule_id="CWE-89", title="SQL injection via string concatenation",
            severity=injectable, file_path=FILE, symbol="get_order", code_snippet="q()",
        ),
        finding_payload(
            rule_id="CWE-306", title="Missing authentication for critical function",
            severity=unauthenticated, file_path=FILE, symbol="admin", code_snippet="a()",
        ),
    ]


def _seed(client, auth, run_compaction, findings) -> None:
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(client, auth, findings, scan_run_id="run-1")
    run_compaction()


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


def _terms(decision) -> dict[str, float]:
    return {t["key"]: t["contribution"] for t in decision.inputs_snapshot["terms"]}


class TestSeverity:
    def test_a_combination_is_worse_than_its_worst_member(self) -> None:
        assert toxic.combination_severity(["medium", "low"], kev=False, escalate_steps=1) == "high"

    def test_high_becomes_critical_and_critical_stays(self) -> None:
        assert toxic.combination_severity(["high"], kev=False, escalate_steps=1) == "critical"
        assert toxic.combination_severity(["critical"], kev=False, escalate_steps=3) == "critical"

    def test_a_kev_member_makes_it_critical(self) -> None:
        assert toxic.combination_severity(["low", "low"], kev=True, escalate_steps=0) == "critical"

    def test_zero_steps_is_the_worst_member(self) -> None:
        worst = toxic.combination_severity(["medium", "low"], kev=False, escalate_steps=0)
        assert worst == "medium"


class TestTheRiskDecision:
    def test_a_high_combination_adds_its_points_as_its_own_term(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _seed(client, auth, run_compaction, _pair("medium", "medium"))

        decision = OracleEngine(catalog, policy).evaluate(REPO)

        snap = decision.inputs_snapshot["toxic_combinations"]
        assert snap["count"] == 1
        assert snap["combinations"][0]["severity"] == "high"
        assert snap["forces_no_go"] is False
        assert _terms(decision)["toxic_combinations"] == pytest.approx(25)
        assert "toxic_combination_no_go" not in _terms(decision)

    def test_a_critical_combination_forces_no_go_as_a_listed_term(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _seed(client, auth, run_compaction, _pair("high", "medium"))

        decision = OracleEngine(catalog, policy).evaluate(REPO)

        assert decision.inputs_snapshot["toxic_combinations"]["forces_no_go"] is True
        assert decision.recommendation == "no_go"
        assert decision.overall_risk_score >= policy.no_go
        terms = _terms(decision)
        assert "toxic_combination_no_go" in terms
        # No hidden inputs: the score is still the sum of what is listed.
        assert sum(terms.values()) == pytest.approx(
            decision.inputs_snapshot["totals"]["raw_score"]
        )
        assert "Critical toxic combination" in render_reasoning(decision.inputs_snapshot)

    def test_accepting_half_the_pair_does_not_hide_it(
        self, client, auth, admin_auth, run_compaction, catalog, policy
    ) -> None:
        _seed(client, auth, run_compaction, _pair("medium", "medium"))
        injectable = catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = 'CWE-89'"
        )[0][0]
        response = client.patch(
            f"/api/dashboard/findings/{injectable}/status",
            json={
                "status": "accepted_risk",
                "accepted_reason_code": "compensating_control",
                "accepted_until": (date.today() + timedelta(days=30)).isoformat(),
                "reason": "WAF rule blocks the injection pattern.",
            },
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

        decision = OracleEngine(catalog, policy).evaluate(REPO)

        combo = decision.inputs_snapshot["toxic_combinations"]["combinations"][0]
        assert combo["partly_accepted"] is True
        assert _terms(decision)["toxic_combinations"] == pytest.approx(25)

    def test_the_policy_can_keep_it_reported_but_out_of_the_score(
        self, client, auth, run_compaction, catalog
    ) -> None:
        import yaml

        raw = yaml.safe_load(get_settings().oracle_policy_path.read_text(encoding="utf-8"))
        raw["modifiers"]["toxic_combinations"] = {
            "escalate_steps": 1,
            "critical_forces_no_go": False,
            "points": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "cap": 0,
        }
        _seed(client, auth, run_compaction, _pair("high", "medium"))

        decision = OracleEngine(catalog, parse_policy(raw)).evaluate(REPO)

        assert decision.inputs_snapshot["toxic_combinations"]["count"] == 1
        assert "toxic_combinations" not in _terms(decision)
        assert "toxic_combination_no_go" not in _terms(decision)

    def test_a_decision_stored_before_this_category_still_renders(
        self, client, auth, run_compaction, catalog, policy
    ) -> None:
        _seed(client, auth, run_compaction, _pair("medium", "medium"))
        snapshot = dict(OracleEngine(catalog, policy).evaluate(REPO).inputs_snapshot)
        snapshot.pop("toxic_combinations")

        text = render_reasoning(snapshot)

        assert "toxic_combinations" not in text


class TestSeeingThem:
    def test_the_estate_endpoint_lists_them_with_coverage(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _seed(client, auth, run_compaction, _pair("medium", "medium"))

        body = client.get("/api/dashboard/toxic-combinations", headers=admin_auth).json()

        assert body["count"] == 1
        assert body["by_severity"] == {"high": 1}
        assert body["combinations"][0]["repo_full_name"] == REPO
        dark = {r["rule_id"] for r in body["coverage"]["cannot_fire"]}
        assert "exposed-admin-port-and-weak-app-auth" in dark  # no network data here

    def test_the_repository_view_uses_the_same_severity(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        _seed(client, auth, run_compaction, _pair("medium", "medium"))

        page = client.get(f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth)

        assert page.json()["toxic_combinations"][0]["severity"] == "high"

    def test_the_briefing_leads_with_them(self, catalog) -> None:
        report = briefing_report.build(
            catalog,
            toxic_combinations=[
                {
                    "repo_full_name": REPO, "name": "Unauthenticated injectable endpoint",
                    "severity": "critical", "partly_accepted": True, "kev_cves": [],
                    "members": [
                        {"capability": "sast", "severity": "high",
                         "title": "SQL injection", "status": "accepted_risk"},
                    ],
                }
            ],
            toxic_coverage=toxic.coverage(catalog),
        )

        text = briefing_report.render(report)

        assert "TOXIC COMBINATIONS" in text
        assert text.index("TOXIC COMBINATIONS") < text.index("OPEN FINDINGS")
        assert "[critical]" in text and "partly accepted" in text and "[accepted]" in text

    def test_none_found_still_says_what_could_not_fire(self, catalog) -> None:
        report = briefing_report.build(
            catalog, toxic_combinations=[], toxic_coverage=toxic.coverage(catalog)
        )

        text = briefing_report.render(report)

        assert "None detected" in text
        assert "rules cannot fire" in text

    def test_a_failure_is_not_reported_as_none(self, catalog) -> None:
        text = briefing_report.render(briefing_report.build(catalog))

        assert "Could not be computed" in text


class TestTheVulnerabilityManagementPage:
    """The page's pill said "16 toxic combination(s)": a lifetime count from
    the auto-remediation log, whose findings no longer existed. It now shows
    the live count and list, and the log's number only as dated history."""

    def test_the_live_count_and_list_come_from_detection(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _seed(client, auth, run_compaction, _pair("medium", "medium"))

        body = client.get("/api/dashboard/vulnerability-management", headers=admin_auth).json()

        assert body["toxic_combinations"] == 1
        assert [c["severity"] for c in body["toxic_combination_list"]] == ["high"]

    def test_the_log_is_reported_as_history_not_as_live(
        self, client, admin_auth, catalog
    ) -> None:
        body = client.get("/api/dashboard/vulnerability-management", headers=admin_auth).json()

        assert body["toxic_combinations"] == 0
        assert body["toxic_combination_list"] == []
        assert "toxic_combinations_recorded" in body
