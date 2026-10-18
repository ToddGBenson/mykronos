"""Environmental severity in Oracle, shadow mode first (TheHub #60830).

Epic #60822 decision D2: before environmental CVSS is allowed to move a gate,
Oracle computes - beside every decision - the score and verdict it *would*
have reached counting findings by `EnvironmentalScore.effective_severity`, and
records both. These tests pin the properties that make the shadow safe to run
and worth reading:

- the live score, verdict, terms and reasoning are byte-identical with and
  without environmental data, and with the shadow on or off;
- a lapsed environmental score is not used (the finding falls back to the
  scanner's word), nor is one computed for a different scanner severity;
- a KEV-listed finding is never counted below high;
- a toxic combination's severity, and so `critical_forces_no_go`, uses
  max(scanner, effective) per member;
- the report compares shadow with live, and with `gate_outcome` where known.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timedelta
from typing import Any

import pytest
import yaml

import mykronos.cli as cli
from mykronos.config import get_settings
from mykronos.db.models import EnvironmentalScore, ThreatIntelMatch
from mykronos.oracle import OracleEngine, load_policy, parse_policy
from mykronos.oracle.environmental import build_report
from mykronos.oracle.policy import PolicyError
from mykronos.oracle.service import OracleService
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan

AS_OF = datetime(2026, 10, 18, 12, 0, 0)
FILE = "orders/query.py"


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


def _raw_policy() -> dict[str, Any]:
    return yaml.safe_load(get_settings().oracle_policy_path.read_text(encoding="utf-8"))


def _policy_with(mode: str | None):
    raw = _raw_policy()
    if mode is None:
        raw.pop("environmental", None)
    else:
        raw["environmental"] = {"mode": mode}
    return parse_policy(raw)


def _seed(client, run_compaction, findings: list[dict[str, Any]]) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(client, auth, findings, scan_run_id="run-1")
    run_compaction()


def _ids(catalog) -> dict[str, str]:
    return {str(rule): str(fid) for fid, rule in catalog.query(
        "SELECT finding_id, rule_id FROM findings"
    )}


def _score(
    client,
    finding_id: str,
    *,
    scanner: str,
    effective: str,
    context_id: str = "ctx-aaaaaaaaaaaa",
    facts: list[dict[str, Any]] | None = None,
) -> None:
    with client.app.state.db.session() as session:
        session.merge(
            EnvironmentalScore(
                finding_id=finding_id,
                repo_full_name=REPO,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                vector_version="3.1",
                vector_source="nvd",
                base=9.8,
                environmental=5.0,
                base_band="critical",
                env_band="medium",
                scanner_severity=scanner,
                effective_severity=effective,
                facts_json=facts or [],
                context_id=context_id,
                computed_at=AS_OF - timedelta(hours=1),
            )
        )


def _evaluate(catalog, policy, client, **kwargs):
    return OracleEngine(catalog, policy, db=client.app.state.db).evaluate(
        REPO, as_of=AS_OF, decision_id="d-1", **kwargs
    )


def _without_environmental(snapshot: dict[str, Any]) -> dict[str, Any]:
    clone = copy.deepcopy(snapshot)
    clone.pop("environmental", None)
    return clone


def _cve(rule: str, severity: str, symbol: str) -> dict[str, Any]:
    return finding_payload(rule_id=rule, title=f"{rule} in a dependency", severity=severity,
                           symbol=symbol, code_snippet=f"{symbol}()")


def _pair(injectable: str, unauthenticated: str) -> list[dict[str, Any]]:
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


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


class TestPolicy:
    def test_the_shipped_policy_runs_the_shadow(self, policy) -> None:
        assert policy.environmental.mode == "shadow"
        assert policy.environmental.shadow is True

    def test_a_policy_without_the_block_has_it_off(self) -> None:
        assert _policy_with(None).environmental.mode == "off"

    def test_live_is_refused_until_its_own_change_exists(self) -> None:
        with pytest.raises(PolicyError, match="live"):
            _policy_with("live")

    def test_the_block_documents_the_go_live_conditions(self) -> None:
        text = get_settings().oracle_policy_path.read_text(encoding="utf-8")
        block = text[text.index("# Environmental severity"):]
        assert "Going live is a separate pull request" in block
        assert "internet_facing_points" in block
        assert "governance-class" in block


# --------------------------------------------------------------------------
# The live decision does not move
# --------------------------------------------------------------------------


class TestTheLiveDecisionIsUnchanged:
    def test_identical_verdicts_with_and_without_environmental_data(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "high", "a"),
            _cve("CVE-2024-2222", "medium", "b"),
        ])
        before = _evaluate(catalog, policy, client)

        ids = _ids(catalog)
        _score(client, ids["CVE-2024-1111"], scanner="high", effective="low")
        _score(client, ids["CVE-2024-2222"], scanner="medium", effective="critical")
        after = _evaluate(catalog, policy, client)

        assert after.overall_risk_score == before.overall_risk_score
        assert after.recommendation == before.recommendation
        assert after.reasoning == before.reasoning
        assert _without_environmental(after.inputs_snapshot) == _without_environmental(
            before.inputs_snapshot
        )
        # ...and the shadow did see the difference.
        assert after.inputs_snapshot["environmental"]["would_differ"] is True

    def test_identical_verdicts_with_the_shadow_on_or_off(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low")

        on = _evaluate(catalog, _policy_with("shadow"), client)
        off = _evaluate(catalog, _policy_with("off"), client)

        assert on.overall_risk_score == off.overall_risk_score
        assert on.recommendation == off.recommendation
        assert on.reasoning == off.reasoning
        assert _without_environmental(on.inputs_snapshot) == _without_environmental(
            off.inputs_snapshot
        )
        assert off.inputs_snapshot["environmental"]["mode"] == "off"
        assert off.inputs_snapshot["environmental"]["available"] is False

    def test_with_no_environmental_scores_the_shadow_equals_live(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "critical", "a"),
            _cve("CVE-2024-2222", "high", "b"),
            _cve("CVE-2024-3333", "low", "c"),
        ])
        decision = _evaluate(catalog, policy, client)

        env = decision.inputs_snapshot["environmental"]
        assert env["available"] is True
        assert env["shadow"]["raw_score"] == decision.inputs_snapshot["totals"]["raw_score"]
        assert env["shadow"]["recommendation"] == decision.recommendation
        assert env["would_differ"] is False
        assert env["fallback"]["no_score"] == 3
        assert env["counts_by_effective_severity"] == env["counts_by_scanner_severity"]

    def test_no_database_means_not_available_rather_than_equal(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        decision = OracleEngine(catalog, policy).evaluate(REPO, as_of=AS_OF)
        env = decision.inputs_snapshot["environmental"]
        assert env["mode"] == "shadow"
        assert env["available"] is False
        assert "database" in env["reason"]


# --------------------------------------------------------------------------
# What the shadow computes
# --------------------------------------------------------------------------


class TestTheShadow:
    def test_counts_by_effective_severity_with_the_contexts_used(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "high", "a"),
            _cve("CVE-2024-2222", "medium", "b"),
            _cve("CVE-2024-3333", "medium", "c"),
        ])
        ids = _ids(catalog)
        _score(client, ids["CVE-2024-1111"], scanner="high", effective="low",
               context_id="ctx-one")
        _score(client, ids["CVE-2024-2222"], scanner="medium", effective="medium",
               context_id="ctx-two")

        env = _evaluate(catalog, policy, client).inputs_snapshot["environmental"]

        assert env["counts_by_scanner_severity"]["high"] == 1
        assert env["counts_by_effective_severity"]["high"] == 0
        assert env["counts_by_effective_severity"]["low"] == 1
        assert env["counts_by_effective_severity"]["medium"] == 2
        assert env["context_ids"] == ["ctx-one", "ctx-two"]
        assert env["scored_findings"] == 2
        assert env["fallback"]["no_score"] == 1
        moved = {m["finding_id"]: m for m in env["moved"]}
        assert moved[ids["CVE-2024-1111"]]["counted_as"] == "low"
        assert moved[ids["CVE-2024-1111"]]["context_id"] == "ctx-one"
        assert ids["CVE-2024-2222"] not in moved

    def test_the_shadow_score_recounts_only_the_moved_bands(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "high", "a"),
            _cve("CVE-2024-2222", "medium", "b"),
        ])
        ids = _ids(catalog)
        _score(client, ids["CVE-2024-2222"], scanner="medium", effective="critical")

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]
        w = policy.severity_weights

        live_raw = decision.inputs_snapshot["totals"]["raw_score"]
        # One medium (w × log2 2) out, one critical in.
        assert env["shadow"]["raw_score"] == pytest.approx(
            live_raw - w["medium"] + w["critical"], abs=0.01
        )
        assert decision.recommendation == "go"
        assert env["shadow"]["recommendation"] == "review_recommended"
        assert env["would_differ"] is True
        assert any("critical" in line and "medium" in line for line in env["why"])

    def test_a_lapsed_score_is_not_used(
        self, client, run_compaction, catalog, policy
    ) -> None:
        """S5 reverts lapsed facts on rescore; between rescores the stored row
        still says `low`. Oracle must read it as lapsed, not as `low`."""
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        lapsed_fact = {
            "metric": "MAV", "value": "L", "direction": "lower", "applied": True,
            "source_kind": "observation", "source_id": "obs-1", "tier": "observed",
            "expires_at": (AS_OF - timedelta(days=1)).isoformat(),
        }
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low",
               facts=[lapsed_fact])

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]

        assert env["fallback"]["lapsed"] == 1
        assert env["scored_findings"] == 0
        assert env["counts_by_effective_severity"]["high"] == 1
        assert env["moved"] == []
        assert env["shadow"]["raw_score"] == decision.inputs_snapshot["totals"]["raw_score"]

    def test_an_unexpired_lowering_fact_is_used(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        fresh_fact = {
            "metric": "MAV", "value": "L", "direction": "lower", "applied": True,
            "expires_at": (AS_OF + timedelta(days=3)).isoformat(),
        }
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low",
               facts=[fresh_fact])

        env = _evaluate(catalog, policy, client).inputs_snapshot["environmental"]
        assert env["fallback"]["lapsed"] == 0
        assert env["counts_by_effective_severity"]["low"] == 1

    def test_a_score_for_a_different_scanner_severity_is_not_used(
        self, client, run_compaction, catalog, policy
    ) -> None:
        """The scanner re-rated the finding since the last rescore: the stored
        shift was computed from a word that is no longer the finding's."""
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="medium", effective="low")

        env = _evaluate(catalog, policy, client).inputs_snapshot["environmental"]
        assert env["fallback"]["scanner_severity_changed"] == 1
        assert env["counts_by_effective_severity"]["high"] == 1


# --------------------------------------------------------------------------
# Safety rules
# --------------------------------------------------------------------------


class TestSafetyRules:
    def test_a_kev_listed_finding_is_never_counted_below_high(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-1111", in_kev=True))
        fid = _ids(catalog)["CVE-2024-1111"]
        _score(client, fid, scanner="high", effective="low")

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]

        assert env["kev_floor_applied"] == [fid]
        assert env["counts_by_effective_severity"]["high"] == 1
        assert env["counts_by_effective_severity"]["low"] == 0
        # Floored back to its own band, it scores exactly as live, boost and all.
        assert env["shadow"]["raw_score"] == pytest.approx(
            decision.inputs_snapshot["totals"]["raw_score"]
        )

    def test_the_kev_floor_never_raises_a_finding_above_its_scanner_word(
        self, client, run_compaction, catalog, policy
    ) -> None:
        """A KEV-listed `medium` the environment lowers stays `medium`: the
        floor stops the environment arguing it down, it does not invent a
        harsher verdict than the scanner's."""
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "medium", "a")])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-1111", in_kev=True))
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="medium", effective="low")

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]
        assert env["counts_by_effective_severity"]["medium"] == 1
        assert env["shadow"]["raw_score"] == pytest.approx(
            decision.inputs_snapshot["totals"]["raw_score"]
        )

    def test_a_raising_score_on_a_kev_finding_still_raises(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "medium", "a")])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-1111", in_kev=True))
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="medium", effective="high")

        env = _evaluate(catalog, policy, client).inputs_snapshot["environmental"]
        assert env["counts_by_effective_severity"]["high"] == 1
        assert env["kev_floor_applied"] == []

    def test_lowering_a_member_cannot_lift_a_critical_combinations_no_go(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, _pair("high", "medium"))
        ids = _ids(catalog)
        _score(client, ids["CWE-89"], scanner="high", effective="low")

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]

        assert decision.recommendation == "no_go"
        assert env["toxic_combinations"]["forces_no_go"] is True
        assert env["shadow"]["recommendation"] == "no_go"
        assert env["toxic_combinations"]["combinations"][0]["shadow_severity"] == "critical"

    def test_raising_a_member_can_make_a_combination_force_no_go(
        self, client, run_compaction, catalog, policy
    ) -> None:
        _seed(client, run_compaction, _pair("medium", "medium"))
        _score(client, _ids(catalog)["CWE-89"], scanner="medium", effective="high")

        decision = _evaluate(catalog, policy, client)
        env = decision.inputs_snapshot["environmental"]

        assert decision.inputs_snapshot["toxic_combinations"]["forces_no_go"] is False
        assert decision.recommendation != "no_go"
        assert env["toxic_combinations"]["forces_no_go"] is True
        combo = env["toxic_combinations"]["combinations"][0]
        assert (combo["live_severity"], combo["shadow_severity"]) == ("high", "critical")
        assert env["shadow"]["recommendation"] == "no_go"
        assert any("toxic combination" in line.lower() and "no_go" in line for line in env["why"])


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------


def _service(client) -> OracleService:
    return OracleService(
        client.app.state.catalog,
        client.app.state.buffer,
        client.app.state.oracle_policy,
        client.app.state.knowledge,
        db=client.app.state.db,
    )


def _gate(client, pr: int, sha: str) -> None:
    asyncio.run(
        _service(client).evaluate_and_publish(
            REPO, decision_type="pr_gate", commit_sha=sha, pr_number=pr
        )
    )


class TestTheReport:
    def test_it_compares_shadow_with_live_and_with_the_gate_outcome(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "high", "a"),
            _cve("CVE-2024-2222", "medium", "b"),
        ])
        _gate(client, 1, "aaaa111")  # no environmental data yet: agrees
        _score(client, _ids(catalog)["CVE-2024-2222"], scanner="medium", effective="critical")
        _gate(client, 2, "bbbb222")  # go live, review_recommended in the shadow
        run_compaction()
        assert _service(client).record_gate_outcome(REPO, 2, "merged")
        run_compaction()

        report = _service(client).environmental_shadow_report()

        assert report["decisions"] == 2
        assert report["shadowed"] == 2
        assert report["agree"] == 1
        assert report["differ"] == 1
        assert report["transitions"] == {"go -> review_recommended": 1}
        (row,) = report["differences"]
        assert row["pr_number"] == 2
        assert row["live"] == "go"
        assert row["shadow"] == "review_recommended"
        assert row["gate_outcome"] == "merged"
        assert row["why"]
        outcome = report["against_gate_outcome"]
        assert outcome["decisions_with_a_known_outcome"] == 1
        assert outcome["by_shadow"]["review_recommended"] == {"merged": 1}
        assert outcome["by_live"]["go"] == {"merged": 1}
        assert outcome["differing_and_merged"] == 1

    def test_decisions_from_before_the_shadow_are_counted_not_guessed(self) -> None:
        rows = [
            {"decision_id": "old", "repo_full_name": REPO, "decision_type": "portfolio",
             "pr_number": None, "commit_sha": "", "evaluated_at": AS_OF,
             "overall_risk_score": 40, "recommendation": "review_recommended",
             "gate_outcome": None, "environmental": None},
            {"decision_id": "off", "repo_full_name": REPO, "decision_type": "portfolio",
             "pr_number": None, "commit_sha": "", "evaluated_at": AS_OF,
             "overall_risk_score": 40, "recommendation": "review_recommended",
             "gate_outcome": None,
             "environmental": {"mode": "off", "available": False}},
        ]
        report = build_report(rows)
        assert report["decisions"] == 2
        assert report["shadowed"] == 0
        assert report["not_shadowed"] == 2
        assert report["differ"] == 0

    def test_the_api_serves_it(self, client, admin_auth, run_compaction, catalog) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _gate(client, 1, "aaaa111")
        run_compaction()

        response = client.get(
            "/api/oracle/environmental-shadow", params={"days": 30}, headers=admin_auth
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["window_days"] == 30
        assert body["decisions"] == 1
        assert body["mode"] == "shadow"

    def test_the_cli_prints_it(
        self, client, settings, run_compaction, catalog, monkeypatch, capsys
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _gate(client, 1, "aaaa111")
        run_compaction()
        monkeypatch.setattr(cli, "get_settings", lambda: settings)

        assert cli.main(["oracle", "shadow-report", "--json"]) == 0
        body = json.loads(capsys.readouterr().out)
        assert body["decisions"] == 1

        assert cli.main(["oracle", "shadow-report"]) == 0
        assert "shadow" in capsys.readouterr().out.lower()
