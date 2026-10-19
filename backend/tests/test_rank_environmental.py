"""The environmental term in the triage rank (TheHub #60829, S7 of #60822).

Business context reaches the queue through one term: the number of CVSS bands
the environment moved a finding's stored score, times a weight declared in
reviewed policy. These tests pin the arithmetic (exactly the weight per band),
the two ways a finding contributes nothing (no stored score, or a score that
rests on an expired fact) and that both are said rather than left out, that
KEV still dominates, and that the queue's disclosure stopped calling business
context "not consulted" wherever a score is in force.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import environment, environment_view
from mykronos.config import get_settings
from mykronos.dashboard import RANK_INPUTS, rank_terms
from mykronos.db.models import EnvironmentalScore, RepoOnboarding, ThreatIntelMatch
from mykronos.oracle import load_policy
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

HEARTBLEED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5, high


@pytest.fixture(autouse=True)
def _clean_flags():
    environment.clear()
    yield
    environment.clear()


@pytest.fixture
def policy() -> Any:
    return load_policy(get_settings().oracle_policy_path)


def _fact(**overrides: Any) -> dict[str, Any]:
    now = utcnow()
    fact = {
        "metric": "MAV",
        "value": "L",
        "direction": "lower",
        "source_kind": "surface",
        "source_id": "s-1",
        "tier": "observed",
        "asserted_by": "host-collector",
        "verified_at": (now - timedelta(days=3)).isoformat(),
        "expires_at": (now + timedelta(days=11)).isoformat(),
        "applied": True,
        "not_applied_reason": None,
        "because": "'api' is bound to loopback",
        "scope": "s-1",
        "evidence_id": "obs-1",
    }
    fact.update(overrides)
    return fact


def _row(
    finding_id: str = "f-1",
    *,
    base_band: str = "high",
    env_band: str = "medium",
    base: float = 7.5,
    environmental: float = 5.9,
    facts: list[dict[str, Any]] | None = None,
) -> EnvironmentalScore:
    return EnvironmentalScore(
        finding_id=finding_id,
        repo_full_name=REPO,
        vector=HEARTBLEED,
        vector_version="3.1",
        vector_source="nvd",
        base=base,
        environmental=environmental,
        base_band=base_band,
        env_band=env_band,
        scanner_severity="high",
        effective_severity=environment.effective_severity("high", base_band, env_band),
        facts_json=[_fact()] if facts is None else facts,
        context_id="c",
        computed_at=utcnow(),
    )


def _item(reading: Any = None, **overrides: Any) -> dict[str, Any]:
    item = {
        "severity": "high",
        "in_kev": False,
        "epss_score": None,
        "due_state": "on_track",
        "blast_radius_ratio": 0.0,
        "blast_radius_repos": 0,
        "repo_recommendation": "go",
        "effort": "small",
        "environmental": reading,
    }
    item.update(overrides)
    return item


def _env_term(terms: list[dict[str, Any]]) -> dict[str, Any]:
    found = [term for term in terms if term["key"] == "environmental"]
    assert len(found) == 1, terms
    return found[0]


class TestTheWeight:
    def test_the_weight_is_declared_in_policy(self, policy: Any) -> None:
        assert policy.triage_rank.environmental_per_band == 10
        assert policy.version == "1.14"

    def test_the_term_is_declared_for_disclosure(self) -> None:
        assert "environmental" in RANK_INPUTS

    def test_rescored_down_ranks_below_its_twin_by_exactly_the_weight(
        self, policy: Any
    ) -> None:
        now = utcnow()
        down = environment_view.rank_reading(_row(), now)
        plain, plain_terms = rank_terms(_item(None), policy)
        lowered, lowered_terms = rank_terms(_item(down), policy)

        assert plain - lowered == policy.triage_rank.environmental_per_band
        assert _env_term(lowered_terms)["points"] == -policy.triage_rank.environmental_per_band
        assert _env_term(plain_terms)["points"] == 0

    def test_two_bands_are_twice_the_weight(self, policy: Any) -> None:
        reading = environment_view.rank_reading(
            _row(base_band="critical", env_band="medium", base=9.8, environmental=6.1),
            utcnow(),
        )
        score, terms = rank_terms(_item(reading, severity="critical"), policy)
        weight = policy.triage_rank.environmental_per_band
        assert _env_term(terms)["points"] == -2 * weight
        assert score == policy.triage_rank.severity["critical"] - 2 * weight

    def test_rescored_up_ranks_above_by_the_weight(self, policy: Any) -> None:
        reading = environment_view.rank_reading(
            _row(
                base_band="medium",
                env_band="high",
                base=6.5,
                environmental=7.4,
                facts=[_fact(metric="CR", value="H", direction="raise", because="holds pii")],
            ),
            utcnow(),
        )
        plain, _ = rank_terms(_item(None), policy)
        raised, terms = rank_terms(_item(reading), policy)
        assert raised - plain == policy.triage_rank.environmental_per_band
        assert _env_term(terms)["detail"].startswith("rescored up 1 band: CR:H")

    def test_a_move_inside_one_band_is_zero_and_says_so(self, policy: Any) -> None:
        reading = environment_view.rank_reading(
            _row(base_band="high", env_band="high", base=8.1, environmental=7.4),
            utcnow(),
        )
        _, terms = rank_terms(_item(reading), policy)
        term = _env_term(terms)
        assert term["points"] == 0
        assert "within its band" in term["detail"]


class TestTheSummary:
    def test_the_detail_names_the_fact_its_tier_and_age(self, policy: Any) -> None:
        reading = environment_view.rank_reading(_row(), utcnow())
        _, terms = rank_terms(_item(reading), policy)

        assert _env_term(terms)["detail"] == (
            "rescored down 1 band: MAV:L from observed 'api' is bound to loopback, 3d ago"
        )

    def test_only_the_facts_that_moved_it_are_named(self) -> None:
        facts = [
            _fact(),
            _fact(metric="CR", value="H", direction="raise", because="holds pii"),
            _fact(metric="MPR", value="L", applied=False, not_applied_reason="stale"),
        ]
        reading = environment_view.rank_reading(_row(facts=facts), utcnow())
        assert reading is not None
        assert "MAV:L" in reading.summary
        assert "CR:H" not in reading.summary
        assert "MPR" not in reading.summary


class TestNothingToRead:
    def test_no_score_contributes_zero_with_an_explanation(self, policy: Any) -> None:
        plain_without, _ = rank_terms(
            {k: v for k, v in _item().items() if k != "environmental"}, policy
        )
        score, terms = rank_terms(_item(None), policy)

        term = _env_term(terms)
        assert term["points"] == 0
        assert term["detail"].startswith("no environmental score")
        assert score == plain_without

    def test_a_lapsed_score_contributes_zero(self, policy: Any) -> None:
        expired = _fact(expires_at=(utcnow() - timedelta(hours=1)).isoformat())
        reading = environment_view.rank_reading(_row(facts=[expired]), utcnow())
        assert reading is not None and reading.state == "lapsed"

        plain, _ = rank_terms(_item(None), policy)
        lapsed, terms = rank_terms(_item(reading), policy)

        assert lapsed == plain
        term = _env_term(terms)
        assert term["points"] == 0
        assert "expired" in term["detail"]

    def test_an_expired_raising_fact_does_not_lapse_the_score(self) -> None:
        """`environment._lapsed` sets a score aside only for an expired
        lowering fact; the queue reuses it rather than restating the rule."""
        raised = _fact(
            metric="CR",
            value="H",
            direction="raise",
            expires_at=(utcnow() - timedelta(hours=1)).isoformat(),
        )
        reading = environment_view.rank_reading(
            _row(base_band="medium", env_band="high", facts=[raised]), utcnow()
        )
        assert reading is not None and reading.state == "scored"


class TestKevStillDominates:
    def test_an_exploited_finding_rescored_down_two_bands_outranks_its_unlisted_twin(
        self, policy: Any
    ) -> None:
        reading = environment_view.rank_reading(
            _row(base_band="critical", env_band="medium", base=9.8, environmental=6.1),
            utcnow(),
        )
        exploited, _ = rank_terms(_item(reading, severity="critical", in_kev=True), policy)
        quiet, _ = rank_terms(_item(None, severity="critical"), policy)
        assert exploited > quiet

    def test_the_loud_medium_still_beats_a_quiet_critical_rescored_up(
        self, policy: Any
    ) -> None:
        reading = environment_view.rank_reading(
            _row(base_band="high", env_band="critical", base=8.8, environmental=9.3,
                 facts=[_fact(metric="CR", value="H", direction="raise")]),
            utcnow(),
        )
        loud_medium, _ = rank_terms(
            _item(None, severity="medium", in_kev=True, epss_score=0.8,
                  due_state="overdue", effort="one_click"),
            policy,
        )
        quiet_critical, _ = rank_terms(_item(reading, severity="critical"), policy)
        assert loud_medium > quiet_critical


# -- Through the API ------------------------------------------------------


def _seed_twins(client: TestClient, admin_auth: dict[str, str], run_compaction: Any) -> None:
    onboard(client, admin_auth)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).scalars().one()
        row.status = "active"
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id="TWIN-A", severity="high", symbol="a"),
            finding_payload(rule_id="TWIN-B", severity="high", symbol="b"),
        ],
    )
    run_compaction()


def _ranked(client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
    response = client.get(
        "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestTheQueue:
    def test_the_rescored_twin_ranks_below_by_the_weight_and_says_why(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
        policy: Any,
    ) -> None:
        _seed_twins(client, admin_auth, run_compaction)
        ids = {i["rule_id"]: i["finding_id"] for i in _ranked(client, admin_auth)["items"]}
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(_row(ids["TWIN-A"]))

        body = _ranked(client, admin_auth)
        rows = {i["rule_id"]: i for i in body["items"]}

        assert [i["rule_id"] for i in body["items"]] == ["TWIN-B", "TWIN-A"]
        assert rows["TWIN-B"]["rank"] - rows["TWIN-A"]["rank"] == (
            policy.triage_rank.environmental_per_band
        )
        lowered = _env_term(rows["TWIN-A"]["rank_terms"])
        assert lowered["detail"].startswith("rescored down 1 band: MAV:L")
        plain = _env_term(rows["TWIN-B"]["rank_terms"])
        assert plain["points"] == 0
        assert plain["detail"].startswith("no environmental score")

    def test_ranking_inputs_describes_the_term_and_counts_coverage(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _seed_twins(client, admin_auth, run_compaction)
        ids = {i["rule_id"]: i["finding_id"] for i in _ranked(client, admin_auth)["items"]}

        before = _ranked(client, admin_auth)["ranking"]
        assert before["environmental"]["scored"] == 0
        assert before["environmental"]["unscored"] == 2
        assert [g["input"] for g in before["not_consulted"]] == ["business context"]
        assert "none of the 2 open findings" in before["not_consulted"][0]["reason"]

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(_row(ids["TWIN-A"]))
        partial = _ranked(client, admin_auth)["ranking"]
        env = partial["environmental"]
        assert (env["scored"], env["lapsed"], env["unscored"]) == (1, 0, 1)
        assert env["weight_per_band"] == 10
        assert "10 points per CVSS band" in env["description"]
        assert "1 of 2 open findings" in partial["not_consulted"][0]["reason"]

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(_row(ids["TWIN-B"]))
        full = _ranked(client, admin_auth)["ranking"]
        assert full["not_consulted"] == [], (
            "every open finding has a score in force, so business context is consulted"
        )
        assert full["environmental"]["scored"] == 2

    def test_a_lapsed_score_is_not_counted_as_consulted(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _seed_twins(client, admin_auth, run_compaction)
        ids = {i["rule_id"]: i["finding_id"] for i in _ranked(client, admin_auth)["items"]}
        expired = _fact(expires_at=(utcnow() - timedelta(hours=1)).isoformat())
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(_row(ids["TWIN-A"]))
            session.add(_row(ids["TWIN-B"], facts=[expired]))

        body = _ranked(client, admin_auth)
        env = body["ranking"]["environmental"]
        assert (env["scored"], env["lapsed"], env["unscored"]) == (1, 1, 0)
        assert body["ranking"]["not_consulted"], "a lapsed score is not in force"
        rows = {i["rule_id"]: i for i in body["items"]}
        assert _env_term(rows["TWIN-B"]["rank_terms"])["points"] == 0

    def test_kev_still_lifts_through_the_queue(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        onboard(client, admin_auth)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            ).scalars().one().status = "active"
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CVE-2026-7777",
                    title="CVE-2026-7777 in libfoo",
                    severity="high",
                    symbol="kev",
                ),
                finding_payload(rule_id="QUIET", severity="high", symbol="q"),
            ],
        )
        run_compaction()
        ids = {i["rule_id"]: i["finding_id"] for i in _ranked(client, admin_auth)["items"]}
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(ThreatIntelMatch(cve_id="CVE-2026-7777", in_kev=True))
            session.add(
                _row(ids["CVE-2026-7777"], base_band="critical", env_band="medium",
                     base=9.8, environmental=6.1)
            )

        order = [i["rule_id"] for i in _ranked(client, admin_auth)["items"]]
        assert order == ["CVE-2026-7777", "QUIET"]
