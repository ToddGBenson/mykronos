"""Unknown is unknown (TheHub #61349, ARRI spec section 12).

Five places asserted a fact nobody had measured:

1. An unfetched CVE read as "not in KEV", and the Oracle snapshot then said
   "none is in CISA's Known Exploited Vulnerabilities catalog".
2. The queue treated a missing EPSS score as 0.
3. A risk profile's unset `internet_facing` scored exactly like `False`.
4. The profile proposal labelled a *declared* surface `observed`, and a port
   that answered some scanner `observed` internet-facing.
5. The sprint ranking weighed a severity nobody recorded as `low`.

Each test here names the measurement and asserts the unmeasured case is said
to be unmeasured. All data is synthetic.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import risk_profile_builder as builder
from mykronos import sprint_signal
from mykronos.config import get_settings
from mykronos.dashboard import rank_terms
from mykronos.db.models import RepoOnboarding, ThreatIntelMatch
from mykronos.oracle import OracleEngine, load_policy
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard
from tests.test_oracle_risk_profile import put_profile


@pytest.fixture
def policy() -> Any:
    return load_policy(get_settings().oracle_policy_path)


def _seed(client: TestClient, run_compaction: Any, findings: list[dict[str, Any]]) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="run-unknown")
    post_findings(client, auth, findings, scan_run_id="run-unknown")
    run_compaction()


def _activate(client: TestClient) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = (
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            )
            .scalars()
            .one()
        )
        row.status = "active"


# ---------------------------------------------------------------------------
# 1. KEV: never fetched is `not_checked`, not "not listed"
# ---------------------------------------------------------------------------


class TestKevNeverFetchedIsNotChecked:
    def test_an_unfetched_cve_is_not_reported_as_not_in_kev(
        self, catalog: Any, policy: Any, client: TestClient, run_compaction: Any
    ) -> None:
        """The KEV refresh has never written a row for this CVE, so nobody
        knows whether it is listed. The snapshot used to say it is not."""
        _seed(client, run_compaction, [finding_payload(rule_id="CVE-2031-0001", severity="high")])

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        exploitability = decision.inputs_snapshot["exploitability"]
        assert "none is in CISA" not in exploitability["reason"]
        assert "not checked" in exploitability["reason"]
        assert exploitability["kev_not_checked_findings"] == 1
        assert exploitability["kev_checked_findings"] == 0

    def test_a_fetched_unlisted_cve_still_reads_not_listed(
        self, catalog: Any, policy: Any, client: TestClient, run_compaction: Any
    ) -> None:
        _seed(client, run_compaction, [finding_payload(rule_id="CVE-2031-0002", severity="high")])
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-0002", in_kev=False))

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        exploitability = decision.inputs_snapshot["exploitability"]
        assert "none is in CISA" in exploitability["reason"]
        assert exploitability["kev_not_checked_findings"] == 0
        assert exploitability["kev_checked_findings"] == 1

    def test_a_mix_names_both_counts(
        self, catalog: Any, policy: Any, client: TestClient, run_compaction: Any
    ) -> None:
        _seed(
            client,
            run_compaction,
            [
                finding_payload(rule_id="CVE-2031-0003", severity="high", symbol="a"),
                finding_payload(rule_id="CVE-2031-0004", severity="high", symbol="b"),
            ],
        )
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-0003", in_kev=False))

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        reason = decision.inputs_snapshot["exploitability"]["reason"]
        assert "KEV status not checked for 1 CVE" in reason
        # The negative is claimed only for the one that was looked up.
        assert "1 open finding(s) name a CVE that was checked" in reason

    def test_the_queue_row_says_unchecked_with_null_not_false(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        """`in_kev: false` meant "checked and not listed" or "never fetched";
        a reader could not tell which."""
        onboard(client, admin_auth)
        _activate(client)
        _seed(
            client,
            run_compaction,
            [finding_payload(rule_id="CVE-2031-0005", title="CVE-2031-0005 in libx")],
        )

        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        row = next(i for i in body["items"] if i["rule_id"] == "CVE-2031-0005")
        assert row["in_kev"] is None
        assert row["exploit_verdict"] == "not_checked"

    def test_the_threat_intel_list_says_unchecked_with_null(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        onboard(client, admin_auth)
        _seed(client, run_compaction, [finding_payload(rule_id="CVE-2031-0006", severity="high")])

        body = client.get("/api/dashboard/threat-intel", headers=admin_auth).json()

        entry = next(e for e in body if e["cve_id"] == "CVE-2031-0006")
        assert entry["in_kev"] is None
        assert entry["fetched_at"] is None


# ---------------------------------------------------------------------------
# 2. EPSS: null is not 0
# ---------------------------------------------------------------------------


class TestEpssNullIsNotZero:
    def _item(self, **overrides: Any) -> dict[str, Any]:
        item = {
            "severity": "medium",
            "cve_id": "CVE-2031-0100",
            "in_kev": None,
            "epss_score": None,
            "due_state": "on_track",
            "blast_radius_ratio": 0.0,
            "blast_radius_repos": 0,
            "repo_recommendation": "go",
            "effort": "small",
        }
        item.update(overrides)
        return item

    def test_a_null_epss_is_listed_as_unknown(self, policy: Any) -> None:
        _, terms = rank_terms(self._item(), policy)

        epss = [t for t in terms if t["key"] == "epss"]
        assert len(epss) == 1
        assert epss[0]["points"] == 0
        assert "not scored" in epss[0]["detail"]
        assert "unknown" in epss[0]["detail"]

    def test_an_epss_of_zero_is_listed_as_measured(self, policy: Any) -> None:
        _, terms = rank_terms(self._item(in_kev=False, epss_score=0.0), policy)

        epss = [t for t in terms if t["key"] == "epss"]
        assert len(epss) == 1
        assert "EPSS 0.00" in epss[0]["detail"]
        assert "unknown" not in epss[0]["detail"]

    def test_a_row_naming_no_cve_gets_no_epss_term(self, policy: Any) -> None:
        """No CVE means there is nothing to score, which is not unknown EPSS."""
        _, terms = rank_terms(self._item(cve_id=None), policy)
        assert not [t for t in terms if t["key"] == "epss"]

    def test_the_queue_ranks_null_apart_from_zero(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        """Equal points, different knowledge: a measured near-zero EPSS is
        known to be quiet, an unscored one is not. The unscored row is listed
        first, whichever was seen first."""
        onboard(client, admin_auth)
        _activate(client)
        _seed(
            client,
            run_compaction,
            [
                finding_payload(
                    rule_id="CVE-2031-0201",
                    title="CVE-2031-0201 in libmeasured",
                    severity="medium",
                    symbol="measured",
                ),
                finding_payload(
                    rule_id="CVE-2031-0202",
                    title="CVE-2031-0202 in libunscored",
                    severity="medium",
                    symbol="unscored",
                ),
            ],
        )
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-0201", in_kev=False, epss_score=0.0))

        body = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        ).json()

        rows = [i for i in body["items"] if i["rule_id"].startswith("CVE-2031-02")]
        assert [r["rule_id"] for r in rows] == ["CVE-2031-0202", "CVE-2031-0201"]
        assert rows[0]["rank"] == rows[1]["rank"]
        details = {r["rule_id"]: [t["detail"] for t in r["rank_terms"]] for r in rows}
        assert any("not scored" in d for d in details["CVE-2031-0202"])
        assert any("EPSS 0.00" in d for d in details["CVE-2031-0201"])

    def test_the_threat_intel_list_puts_null_after_a_measured_zero(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        """Its docstring always said "nulls last"; `-(None or 0.0)` tied them
        with a measured 0."""
        onboard(client, admin_auth)
        _seed(
            client,
            run_compaction,
            [
                finding_payload(rule_id="CVE-2031-0301", severity="high", symbol="a"),
                finding_payload(rule_id="CVE-2031-0302", severity="high", symbol="b"),
            ],
        )
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2031-0302", in_kev=False, epss_score=0.0))

        body = client.get("/api/dashboard/threat-intel", headers=admin_auth).json()

        ordered = [e["cve_id"] for e in body if e["cve_id"].startswith("CVE-2031-03")]
        assert ordered == ["CVE-2031-0302", "CVE-2031-0301"]


# ---------------------------------------------------------------------------
# 3. internet_facing: unset is not False
# ---------------------------------------------------------------------------


class TestInternetFacingUnsetIsNotFalse:
    def _decide(
        self,
        catalog: Any,
        policy: Any,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
        **profile: Any,
    ) -> Any:
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, **profile)
        _seed(client, run_compaction, [finding_payload(rule_id="CWE-89", severity="high")])
        return OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

    def test_unset_scores_as_its_own_unknown_term(
        self,
        catalog: Any,
        policy: Any,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        decision = self._decide(
            catalog, policy, client, admin_auth, run_compaction, internet_facing=None
        )

        snapshot = decision.inputs_snapshot["risk_profile"]
        assert snapshot["internet_facing_state"] == "unknown"
        terms = {t["key"]: t for t in decision.inputs_snapshot["terms"]}
        assert "risk_profile.internet_facing" not in terms
        unknown = terms["risk_profile.internet_facing_unknown"]
        assert unknown["contribution"] == pytest.approx(
            policy.risk_profile.internet_facing_unknown_points
        )
        assert "not recorded" in unknown["detail"]

    def test_false_is_a_recorded_answer(
        self,
        catalog: Any,
        policy: Any,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        decision = self._decide(
            catalog, policy, client, admin_auth, run_compaction, internet_facing=False
        )

        snapshot = decision.inputs_snapshot["risk_profile"]
        assert snapshot["internet_facing_state"] == "not_internet_facing"
        keys = {t["key"] for t in decision.inputs_snapshot["terms"]}
        assert not any(k.startswith("risk_profile.internet_facing") for k in keys)

    def test_unset_and_false_score_differently(
        self,
        catalog: Any,
        policy: Any,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        """The whole story in one assertion: the two used to be equal."""
        unset = self._decide(
            catalog, policy, client, admin_auth, run_compaction, internet_facing=None
        )
        repo_id = client.get("/api/repos", headers=admin_auth).json()[0]["id"]
        put_profile(client, admin_auth, repo_id, internet_facing=False)
        recorded_false = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        assert unset.overall_risk_score > recorded_false.overall_risk_score

    def test_the_policy_version_moved(self, policy: Any) -> None:
        assert policy.version == "1.19"


# ---------------------------------------------------------------------------
# 4. Declared is never `observed`
# ---------------------------------------------------------------------------


class _Catalog:
    def __init__(self, *, network: int = 0) -> None:
        self._network = network

    def all_files(self, table: str) -> list[str]:
        return ["x"]

    def query(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        if "'cloud', 'network'" in sql or "capability = 'network'" in sql:
            return [(self._network,)]
        if "capability = 'dast'" in sql:
            return [(0,)]
        return []


def _internet(proposal: builder.ProfileProposal) -> builder.Proposal:
    return next(p for p in proposal.proposals if p.field == "internet_facing")


class TestDeclaredIsNeverObserved:
    def test_declared_is_a_confidence(self) -> None:
        assert "declared" in builder.CONFIDENCE

    def test_a_declared_internet_surface_is_declared(self) -> None:
        out = builder.propose(
            _Catalog(), REPO, declared_surfaces=[("Public web app (tcp/443)", "internet")]
        )
        internet = _internet(out)
        assert internet.value is True
        assert internet.confidence == "declared"

    def test_declared_internal_surfaces_are_declared(self) -> None:
        out = builder.propose(
            _Catalog(), REPO, declared_surfaces=[("Admin API (tcp/8080)", "internal")]
        )
        internet = _internet(out)
        assert internet.value is False
        assert internet.confidence == "declared"

    def test_an_answering_port_is_inferred_not_observed(self) -> None:
        """A port that answered a scanner says the scanner could reach it. The
        lake does not record that the scanner stood on the internet: a LAN
        sweep answers the same way."""
        out = builder.propose(_Catalog(network=2), REPO)
        internet = _internet(out)
        assert internet.value is True
        assert internet.confidence == "inferred"
        assert internet.what_would_settle_it


# ---------------------------------------------------------------------------
# 5. Unknown severity is not low
# ---------------------------------------------------------------------------


class TestUnknownSeverityIsNotLow:
    def test_unknown_is_not_weighted_as_low(self) -> None:
        assert sprint_signal.risk({"unknown": 3}) != sprint_signal.risk({"low": 3})

    def test_unknown_carries_no_weight_and_known_risk_is_unchanged(self) -> None:
        assert sprint_signal.risk({"unknown": 3, "high": 1}) == sprint_signal.risk({"high": 1})

    def test_the_weights_say_unknown_is_unweighted(self) -> None:
        assert sprint_signal.weights()["unknown_severity"] is None

    def test_the_line_says_how_many_are_unknown(self) -> None:
        candidate = sprint_signal.Candidate(
            signal_key="0" * 16,
            kind="lane",
            repo_full_name=REPO,
            capability="sast",
            title="Repair the sast lane",
            ref="",
            findings=4,
            risk_removed=sprint_signal.risk({"unknown": 3, "high": 1}),
            risk_basis={"high": 1, "unknown": 3},
            exposure=1.0,
            exposure_basis="no deployment",
            effort=2.0,
            effort_basis="a lane repair",
            score=2.5,
        )
        line = candidate.explain()
        assert "3 of unknown severity" in line
        assert "not weighted" in line
