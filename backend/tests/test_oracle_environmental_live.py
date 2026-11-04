"""Environmental scoring live per repository (TheHub #60904).

Epic #60882, operator decision 2026-10-22: environmental scoring (and the
verified controls it reads) goes live repository by repository after a
two-week shadow comparison, review 2026-11-05. These tests pin:

- the switch is per repository, in the governance-class policy file, and each
  entry is a record (who approved it, when, on which comparison) - an entry
  without one is refused at load;
- for a switched repository the decision counts findings by environmental
  effective severity, with the shadow's two safety rules (KEV floor, toxic
  max) intact, and says so in its snapshot and reasoning;
- the risk-profile points that would count the same fact twice are trimmed,
  only where environmental scores exist;
- every repository not switched scores exactly as it does in shadow;
- the comparison report says, per repository, whether the comparison held.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

import pytest

import mykronos.cli as cli
from mykronos.db.models import ThreatIntelMatch
from mykronos.oracle import OracleEngine, parse_policy
from mykronos.oracle.environmental import build_report
from mykronos.oracle.policy import PolicyError
from tests.conftest import REPO
from tests.test_oracle_environmental import (
    AS_OF,
    _cve,
    _evaluate,
    _gate,
    _ids,
    _pair,
    _raw_policy,
    _score,
    _seed,
    _service,
)

OTHER = "acme/other-repo"


def _record(repo: str = REPO, **overrides: Any) -> dict[str, Any]:
    entry = {
        "repo": repo,
        "switched_on": "2026-11-05",
        "approved_by": "operator",
        "comparison": "shadow-report 2026-10-22..2026-11-05: 0 shadow go on a live no_go",
    }
    entry.update(overrides)
    return entry


def _live_policy(*entries: dict[str, Any], mode: str = "shadow"):
    raw = _raw_policy()
    raw["environmental"] = {"mode": mode, "live_repos": list(entries)}
    return parse_policy(raw)


def _shadow_policy():
    raw = _raw_policy()
    raw["environmental"] = {"mode": "shadow"}
    return parse_policy(raw)


def _keys(decision) -> list[str]:
    return [t["key"] for t in decision.inputs_snapshot["terms"]]


# --------------------------------------------------------------------------
# The switch is a record in the policy file
# --------------------------------------------------------------------------


class TestTheSwitch:
    def test_the_shipped_policy_switches_no_repository_yet(self) -> None:
        """Guard: going live is a person's decision, made in its own change."""
        policy = parse_policy(_raw_policy())
        assert policy.environmental.live_repos == ()
        assert policy.environmental.live_for(REPO) is None

    def test_a_switched_repository_carries_its_record(self) -> None:
        policy = _live_policy(_record())
        record = policy.environmental.live_for(REPO)
        assert record is not None
        assert record.repo == REPO
        assert record.switched_on.isoformat() == "2026-11-05"
        assert record.approved_by == "operator"
        assert "shadow-report" in record.comparison
        assert policy.environmental.live_for(OTHER) is None

    @pytest.mark.parametrize("missing", ["repo", "switched_on", "approved_by", "comparison"])
    def test_an_entry_without_its_record_is_refused(self, missing: str) -> None:
        entry = _record()
        entry.pop(missing)
        with pytest.raises(PolicyError, match=missing):
            _live_policy(entry)

    def test_an_unparseable_date_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="switched_on"):
            _live_policy(_record(switched_on="next thursday"))

    def test_a_repository_switched_twice_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="more than once"):
            _live_policy(_record(), _record(approved_by="someone else"))

    def test_live_repositories_need_the_shadow_running(self) -> None:
        """With the shadow off there is no environmental count to go live on."""
        with pytest.raises(PolicyError, match="shadow"):
            _live_policy(_record(), mode="off")


# --------------------------------------------------------------------------
# A switched repository is scored by environmental severity
# --------------------------------------------------------------------------


class TestASwitchedRepository:
    def test_a_raised_finding_raises_the_verdict(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [
            _cve("CVE-2024-1111", "high", "a"),
            _cve("CVE-2024-2222", "medium", "b"),
        ])
        _score(client, _ids(catalog)["CVE-2024-2222"], scanner="medium", effective="critical")

        shadow = _evaluate(catalog, _shadow_policy(), client)
        live = _evaluate(catalog, _live_policy(_record()), client)

        assert shadow.recommendation == "go"
        env = shadow.inputs_snapshot["environmental"]
        assert live.recommendation == env["shadow"]["recommendation"] == "review_recommended"
        assert live.overall_risk_score == env["shadow"]["overall_risk_score"]

        switch = live.inputs_snapshot["environmental"]["live_switch"]
        assert switch["applied"] is True
        assert switch["repo"] == REPO
        assert switch["switched_on"] == "2026-11-05"
        assert switch["approved_by"] == "operator"
        assert switch["comparison"].startswith("shadow-report")
        assert switch["scanner_counted"]["recommendation"] == "go"
        assert switch["scanner_counted"]["overall_risk_score"] == shadow.overall_risk_score
        assert "environmental" in live.reasoning.lower()
        assert live.inputs_snapshot["totals"]["overall_risk_score"] == live.overall_risk_score

    def test_a_lowered_finding_lowers_the_score(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low")

        shadow = _evaluate(catalog, _shadow_policy(), client)
        live = _evaluate(catalog, _live_policy(_record()), client)

        assert live.overall_risk_score < shadow.overall_risk_score
        assert live.overall_risk_score == (
            shadow.inputs_snapshot["environmental"]["shadow"]["overall_risk_score"]
        )

    def test_a_repository_not_switched_scores_exactly_as_in_shadow(
        self, client, run_compaction, catalog
    ) -> None:
        """Guard: switching one repository moves no other."""
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low")

        shadow = _evaluate(catalog, _shadow_policy(), client)
        other = _evaluate(catalog, _live_policy(_record(OTHER)), client)

        assert other.overall_risk_score == shadow.overall_risk_score
        assert other.recommendation == shadow.recommendation
        assert other.reasoning == shadow.reasoning
        assert other.inputs_snapshot == shadow.inputs_snapshot
        assert "live_switch" not in other.inputs_snapshot["environmental"]

    def test_the_kev_floor_holds_live(self, client, run_compaction, catalog) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-1111", in_kev=True))
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low")

        shadow = _evaluate(catalog, _shadow_policy(), client)
        live = _evaluate(catalog, _live_policy(_record()), client)

        assert live.overall_risk_score == shadow.overall_risk_score
        assert live.recommendation == shadow.recommendation

    def test_lowering_a_member_cannot_lift_a_toxic_no_go_live(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, _pair("high", "medium"))
        _score(client, _ids(catalog)["CWE-89"], scanner="high", effective="low")

        live = _evaluate(catalog, _live_policy(_record()), client)

        assert live.recommendation == "no_go"
        assert "toxic_combination_no_go" in _keys(live)

    def test_raising_a_member_can_force_no_go_live(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, _pair("medium", "medium"))
        _score(client, _ids(catalog)["CWE-89"], scanner="medium", effective="high")

        assert _evaluate(catalog, _shadow_policy(), client).recommendation != "no_go"
        assert _evaluate(catalog, _live_policy(_record()), client).recommendation == "no_go"

    def test_without_a_database_it_stays_on_the_scanner_word_and_says_so(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        policy = _live_policy(_record())
        without = OracleEngine(catalog, policy).evaluate(REPO, as_of=AS_OF)
        shadow = OracleEngine(catalog, _shadow_policy()).evaluate(REPO, as_of=AS_OF)

        assert without.overall_risk_score == shadow.overall_risk_score
        switch = without.inputs_snapshot["environmental"]["live_switch"]
        assert switch["applied"] is False
        assert "scanner" in switch["reason"]

    def test_the_evidence_block_marks_environmental_and_controls_scored(
        self, client, run_compaction, catalog
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="low")

        live = _evaluate(catalog, _live_policy(_record()), client)
        shadow = _evaluate(catalog, _shadow_policy(), client)

        live_cats = live.inputs_snapshot["risk_evidence"]["categories"]
        shadow_cats = shadow.inputs_snapshot["risk_evidence"]["categories"]
        assert live_cats["environmental"]["scored"] is True
        assert live_cats["verified_controls"]["scored"] is True
        assert shadow_cats["environmental"]["scored"] is False
        assert shadow_cats["verified_controls"]["scored"] is False


# --------------------------------------------------------------------------
# The same fact is not counted twice
# --------------------------------------------------------------------------


@pytest.fixture
def exposed_profile(monkeypatch):
    profile = {
        "internet_facing": True,
        "data_classification": "confidential",
        "business_criticality": "high",
    }
    monkeypatch.setattr(OracleEngine, "_risk_profile", lambda self, repo: dict(profile))
    return profile


class TestDoubleCounting:
    def test_exposure_and_classification_points_are_trimmed_where_scored(
        self, client, run_compaction, catalog, exposed_profile
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _score(client, _ids(catalog)["CVE-2024-1111"], scanner="high", effective="high")

        shadow = _evaluate(catalog, _shadow_policy(), client)
        live = _evaluate(catalog, _live_policy(_record()), client)

        assert "risk_profile.internet_facing" in _keys(shadow)
        assert "risk_profile.internet_facing" not in _keys(live)
        assert "risk_profile.data_classification" not in _keys(live)
        assert "risk_profile.business_criticality" in _keys(live)
        switch = live.inputs_snapshot["environmental"]["live_switch"]
        assert sorted(switch["trimmed"]) == [
            "risk_profile.data_classification",
            "risk_profile.internet_facing",
        ]
        assert live.overall_risk_score == shadow.overall_risk_score - 20

    def test_nothing_is_trimmed_where_no_finding_has_a_score(
        self, client, run_compaction, catalog, exposed_profile
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])

        shadow = _evaluate(catalog, _shadow_policy(), client)
        live = _evaluate(catalog, _live_policy(_record()), client)

        assert _keys(live) == _keys(shadow)
        assert live.overall_risk_score == shadow.overall_risk_score
        assert live.inputs_snapshot["environmental"]["live_switch"]["trimmed"] == []


# --------------------------------------------------------------------------
# The comparison report, per repository
# --------------------------------------------------------------------------


START = datetime(2026, 10, 22, 12, 0, 0)


def _row(
    repo: str,
    when: datetime,
    *,
    live: str = "review_recommended",
    shadow: str | None = None,
    scored: int = 1,
) -> dict[str, Any]:
    shadow = shadow or live
    return {
        "decision_id": f"{repo}-{when.isoformat()}",
        "repo_full_name": repo,
        "decision_type": "portfolio",
        "pr_number": None,
        "commit_sha": "",
        "evaluated_at": when,
        "overall_risk_score": 40,
        "recommendation": live,
        "gate_outcome": None,
        "environmental": {
            "mode": "shadow",
            "available": True,
            "scored_findings": scored,
            "shadow": {"overall_risk_score": 40, "recommendation": shadow},
            "why": [],
        },
    }


class TestTheComparisonReport:
    def test_two_weeks_with_scores_and_no_lifted_no_go_holds(self) -> None:
        rows = [_row(REPO, START), _row(REPO, START + timedelta(days=14))]
        repo = build_report(rows)["by_repo"][REPO]
        assert repo["shadowed"] == 2
        assert repo["days_observed"] == 14
        assert repo["comparison_holds"] is True
        assert repo["blockers"] == []

    def test_less_than_two_weeks_does_not_hold(self) -> None:
        rows = [_row(REPO, START), _row(REPO, START + timedelta(days=13))]
        repo = build_report(rows)["by_repo"][REPO]
        assert repo["comparison_holds"] is False
        assert any("14" in b for b in repo["blockers"])

    def test_no_environmental_scores_does_not_hold(self) -> None:
        rows = [_row(REPO, START, scored=0), _row(REPO, START + timedelta(days=20), scored=0)]
        repo = build_report(rows)["by_repo"][REPO]
        assert repo["comparison_holds"] is False
        assert any("environmental score" in b for b in repo["blockers"])

    def test_a_shadow_go_on_a_live_no_go_does_not_hold(self) -> None:
        rows = [
            _row(REPO, START),
            _row(REPO, START + timedelta(days=15), live="no_go", shadow="go"),
        ]
        repo = build_report(rows)["by_repo"][REPO]
        assert repo["comparison_holds"] is False
        assert repo["shadow_go_on_live_no_go"] == 1
        assert repo["milder"] == 1
        assert any("no_go" in b for b in repo["blockers"])

    def test_repositories_are_judged_separately(self) -> None:
        rows = [
            _row(REPO, START), _row(REPO, START + timedelta(days=14)),
            _row(OTHER, START + timedelta(days=10)),
            _row(OTHER, START + timedelta(days=11), live="go", shadow="review_recommended"),
        ]
        by_repo = build_report(rows)["by_repo"]
        assert by_repo[REPO]["comparison_holds"] is True
        assert by_repo[OTHER]["comparison_holds"] is False
        assert by_repo[OTHER]["harsher"] == 1
        assert by_repo[OTHER]["differ"] == 1

    def test_a_switched_repository_is_named_with_its_record(self) -> None:
        policy = _live_policy(_record())
        rows = [_row(REPO, START)]
        report = build_report(rows, live_repos=policy.environmental.live_repos)
        assert report["by_repo"][REPO]["live"]["approved_by"] == "operator"
        assert report["live_repos"][0]["repo"] == REPO

    def test_the_service_and_cli_carry_it(
        self, client, settings, run_compaction, catalog, monkeypatch, capsys
    ) -> None:
        _seed(client, run_compaction, [_cve("CVE-2024-1111", "high", "a")])
        _gate(client, 1, "a91f2c7")
        run_compaction()

        report = _service(client).environmental_shadow_report()
        assert REPO in report["by_repo"]
        assert report["live_repos"] == []

        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        assert cli.main(["oracle", "shadow-report", "--json"]) == 0
        assert REPO in json.loads(capsys.readouterr().out)["by_repo"]
        assert cli.main(["oracle", "shadow-report"]) == 0
        out = capsys.readouterr().out
        assert "holds" in out
        assert REPO in out
