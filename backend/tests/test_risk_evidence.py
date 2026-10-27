"""One evidence model for acceptance and Oracle (TheHub #60901, epic #60882).

Pinned here:

* both readers go through `risk_evidence`: a fact changed at that one read
  path changes what the Oracle scores *and* what an acceptance refuses;
* both decisions carry a `risk_evidence` block, built by the same function,
  and for the same facts the two blocks agree;
* every category appears in every block, with `scored` saying whether the
  decision's arithmetic read it;
* a declared control is verified only by a fresh observation in its
  affirming state.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import risk_evidence
from mykronos.db.models import (
    ControlObservation,
    EnvironmentalScore,
    RepoControl,
    RepoOnboarding,
    RepoSurface,
    RiskProfile,
    ThreatIntelMatch,
)
from mykronos.oracle import OracleEngine
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_risk_acceptance import IMAGE, OTHER, _agent, _approve, _finding, _propose, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

NOW = datetime(2026, 10, 22, 12, 0, 0)

#: A CVE id `threat_intel.extract_cve` reads (four or more digits): the lake
#: fixture's `CVE-2026-1` is too short for the Oracle to treat as a CVE.
CVE = "CVE-2026-10001"


@pytest.fixture
def cves(lake):
    """The lake fixture's findings again, plus one in scope naming a real-format CVE."""
    lake(
        "scan-2",
        [
            _finding("CVE-2026-1", "high"),
            _finding("CVE-2026-2", "medium"),
            _finding("CVE-2026-3", "low", fixed="2.36-9"),
            _finding("CVE-2026-1", "high", image=OTHER),
            _finding(CVE, "medium", image=IMAGE),
        ],
    )
    return lake


#: An OSV-derived Atlas finding's CVE: its rule id is the GHSA id, and the CVE
#: is only in its title (`threat_intel.extract_cve` reads both).
TITLE_CVE = "CVE-2026-20002"


@pytest.fixture
def title_cve(lake):
    """The lake fixture's findings again, plus one in scope whose CVE is only
    in its title, as an Atlas finding's is."""
    atlas = _finding("GHSA-7f3q-2m9x-qq4w", "medium", image=IMAGE)
    atlas["title"] = f"{TITLE_CVE}: heap overflow in libc6"
    lake(
        "scan-2",
        [
            _finding("CVE-2026-1", "high"),
            _finding("CVE-2026-2", "medium"),
            _finding("CVE-2026-3", "low", fixed="2.36-9"),
            _finding("CVE-2026-1", "high", image=OTHER),
            atlas,
        ],
    )
    return lake


def _oracle(client) -> dict[str, Any]:
    engine = OracleEngine(
        client.app.state.catalog, client.app.state.oracle_policy, db=client.app.state.db
    )
    return dict(engine.evaluate(REPO).inputs_snapshot)


def _estate(client) -> dict[str, str]:
    """A profile, a surface, a control with a fresh affirming observation,
    and threat intel for one CVE in scope."""
    now = utcnow()
    with client.app.state.db.session() as session:
        onboarding = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).one()
        session.add(
            RiskProfile(
                repo_onboarding_id=onboarding.id,
                internet_facing=False,
                data_classification="confidential",
                business_criticality="high",
                compliance_scope=["soc2"],
                updated_by="tgb",
            )
        )
        surface = RepoSurface(
            repo_full_name=REPO,
            kind="asset",
            name="customer db",
            exposure="internal",
            sensitivity="pii",
            selectors={},
        )
        control = RepoControl(
            repo_full_name=REPO, stride="information_disclosure", kind="network_isolation"
        )
        session.add_all([surface, control])
        session.flush()
        session.add(
            ControlObservation(
                id="obs-loopback",
                repo_full_name=REPO,
                subject="tgb-desktop:5432",
                control_id=control.id,
                assertion="bound_loopback",
                state="pass",
                vantage="host",
                collected_at=now - timedelta(hours=2),
                received_at=now - timedelta(hours=2),
            )
        )
        session.add(
            ThreatIntelMatch(cve_id=CVE, in_kev=False, epss_score=0.31, fetched_at=now)
        )
        return {"control_id": control.id, "surface_id": surface.id}


def _acceptance_evidence(client, admin_auth) -> dict[str, Any]:
    proposed = _propose(client, _agent(client, admin_auth))
    assert proposed.status_code == 201, proposed.text
    body = proposed.json()
    with client.app.state.db.session() as session:
        from mykronos.db.models import ApprovalRequest

        request = session.get(ApprovalRequest, body["approval_request_id"])
        assert request is not None
        return dict(request.evidence["risk_evidence"])


class TestBothReadTheSameEvidence:
    def test_one_threat_intel_read_feeds_both(
        self, client, admin_auth, cves, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Change KEV at the shared read and both decisions see it: the Oracle
        boosts the finding, the acceptance is refused."""
        real = risk_evidence.threat_signals

        def kev_everything(session: Any, cves: Any) -> dict[str, risk_evidence.ThreatSignal]:
            signals = real(session, cves)
            return {
                cve: risk_evidence.ThreatSignal(cve, True, NOW.date(), None, NOW)
                for cve in {str(c).upper() for c in cves} | set(signals)
            }

        monkeypatch.setattr(risk_evidence, "threat_signals", kev_everything)

        exploitability = _oracle(client)["exploitability"]
        assert CVE in {m["cve_id"] for m in exploitability["kev_listed_findings"]}

        refused = _propose(client, _agent(client, admin_auth))
        assert refused.status_code == 409
        assert "KEV" in refused.json()["detail"]

    def test_both_decisions_carry_the_same_blocks_for_the_same_facts(
        self, client, admin_auth, cves
    ) -> None:
        _estate(client)
        oracle = _oracle(client)["risk_evidence"]
        acceptance = _acceptance_evidence(client, admin_auth)

        assert oracle["model"] == acceptance["model"] == "risk_evidence/1"
        def facts(block: dict[str, Any], name: str) -> dict[str, Any]:
            return {
                k: v for k, v in block["categories"][name].items() if k not in ("scored", "note")
            }

        for name in ("asset_sensitivity", "exposure", "verified_controls"):
            assert facts(oracle, name) == facts(acceptance, name), name
        # The CVE both cover reads the same.
        assert oracle["categories"]["threat_intel"]["epss"][CVE] == 0.31
        assert acceptance["categories"]["threat_intel"]["epss"][CVE] == 0.31

    def test_a_cve_named_only_in_the_title_is_read_by_both(
        self, client, admin_auth, title_cve
    ) -> None:
        """An Atlas finding's CVE is in its title. The Oracle reads it there;
        the acceptance's block must list the same CVE, not only rule ids."""
        with client.app.state.db.session() as session:
            session.add(
                ThreatIntelMatch(
                    cve_id=TITLE_CVE, in_kev=False, epss_score=0.42, fetched_at=utcnow()
                )
            )
        oracle = _oracle(client)["risk_evidence"]
        acceptance = _acceptance_evidence(client, admin_auth)
        assert oracle["categories"]["threat_intel"]["epss"][TITLE_CVE] == 0.42
        assert acceptance["categories"]["threat_intel"]["epss"].get(TITLE_CVE) == 0.42

    def test_a_kev_listed_cve_in_the_title_is_refused_as_the_oracle_boosts_it(
        self, client, admin_auth, title_cve
    ) -> None:
        with client.app.state.db.session() as session:
            session.add(
                ThreatIntelMatch(
                    cve_id=TITLE_CVE, in_kev=True, kev_added_at=NOW.date(), fetched_at=utcnow()
                )
            )
        exploitability = _oracle(client)["exploitability"]
        assert TITLE_CVE in {m["cve_id"] for m in exploitability["kev_listed_findings"]}

        refused = _propose(client, _agent(client, admin_auth))
        assert refused.status_code == 409, refused.text
        assert TITLE_CVE in refused.json()["detail"]

    def test_every_category_is_present_and_says_whether_it_was_scored(
        self, client, admin_auth, lake
    ) -> None:
        oracle = _oracle(client)["risk_evidence"]
        acceptance = _acceptance_evidence(client, admin_auth)
        for block in (oracle, acceptance):
            assert tuple(block["categories"]) == risk_evidence.CATEGORIES
            assert all(isinstance(c["scored"], bool) for c in block["categories"].values())
        assert oracle["categories"]["threat_intel"]["scored"] is True
        assert oracle["categories"]["asset_sensitivity"]["scored"] is True
        # Shadow until the per-repository go-live (TheHub #60904): shown, not scored.
        assert oracle["categories"]["environmental"]["scored"] is False
        assert "60904" in oracle["categories"]["environmental"]["note"]
        assert oracle["categories"]["verified_controls"]["scored"] is False
        assert acceptance["categories"]["threat_intel"]["scored"] is True

    def test_an_empty_estate_says_unavailable_rather_than_nothing(
        self, client, admin_auth, lake
    ) -> None:
        categories = _oracle(client)["risk_evidence"]["categories"]
        assert categories["asset_sensitivity"]["available"] is False
        assert categories["verified_controls"]["available"] is False
        assert categories["reachability"]["available"] is False


class TestEachDecisionShowsTheEvidenceItUsed:
    def test_the_acceptance_detail_shows_what_the_approver_signed(
        self, client, admin_auth, lake
    ) -> None:
        _estate(client)
        proposed = _propose(client, _agent(client, admin_auth)).json()
        assert _approve(client, admin_auth, proposed).json()["state"] == "approved"
        record_id = proposed["risk_acceptance"]["id"]

        detail = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        block = detail["risk_evidence"]
        assert block["repo"] == REPO
        assert block["findings"] == proposed["risk_acceptance"]["findings"]
        assert block["categories"]["asset_sensitivity"]["data_classification"] == "confidential"
        assert block["categories"]["verified_controls"]["verified"] == 1

    def test_the_oracle_block_never_costs_the_decision(
        self, client, admin_auth, lake, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        before = _oracle(client)

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("unreadable")

        monkeypatch.setattr(risk_evidence, "gather", boom)
        after = _oracle(client)
        assert after["risk_evidence"]["available"] is False
        assert after["totals"] == before["totals"]


class TestVerifiedControls:
    def _row(self, assertion: str, state: str, *, age_days: float = 1) -> ControlObservation:
        return ControlObservation(
            id=f"obs-{assertion}-{state}",
            repo_full_name=REPO,
            subject="host:5432",
            assertion=assertion,
            state=state,
            vantage="lan",
            collected_at=NOW - timedelta(days=age_days),
            received_at=NOW - timedelta(days=age_days),
        )

    @pytest.mark.parametrize(
        ("assertion", "state", "expected"),
        [
            ("bound_loopback", "pass", "verified"),
            ("anonymous_401", "pass", "verified"),
            ("firewall_scope", "fail", "contradicted"),
            # `pass` means the port IS published: the control does not hold.
            ("port_published", "pass", "contradicted"),
            ("port_published", "fail", "verified"),
            ("bound_loopback", "unknown", "unverified"),
        ],
    )
    def test_the_affirming_state_depends_on_the_assertion(
        self, assertion: str, state: str, expected: str
    ) -> None:
        status = risk_evidence.observation_status(self._row(assertion, state), now=NOW)
        assert status.status == expected

    def test_stale_evidence_verifies_nothing(self) -> None:
        row = self._row("bound_loopback", "pass", age_days=20)
        assert risk_evidence.observation_status(row, now=NOW).status == "unverified"
        assert risk_evidence.observation_status(row, now=NOW, fresh_days=30).status == "verified"

    def test_a_declared_control_nothing_observes_is_unverified(self, client, lake) -> None:
        with client.app.state.db.session() as session:
            control = RepoControl(repo_full_name=REPO, stride="spoofing", kind="authentication")
            session.add(control)
            session.flush()
            status = risk_evidence.control_verification(session, REPO, control.id, now=utcnow())
        assert status.status == "unverified"
        assert "declaration is not evidence" in status.reason


# ---------------------------------------------------------------------------
# IN lists are read in chunks (review of #1005)
# ---------------------------------------------------------------------------

#: More ids than SQLite binds in one statement (SQLITE_MAX_VARIABLE_NUMBER
#: is 32766), which a migrated estate's open findings exceed.
MANY = 40_000


class TestManyIdsStillRead:
    """A repository with tens of thousands of open findings must not turn
    the `risk_evidence` block into `available: false` on a bind limit."""

    def test_threat_signals_reads_past_the_bind_limit(self, client) -> None:
        wanted = [f"CVE-2026-{n}" for n in range(10_000, 10_000 + MANY)]
        with client.app.state.db.session() as session:
            session.add(
                ThreatIntelMatch(cve_id=wanted[-1], in_kev=True, fetched_at=utcnow())
            )
            session.flush()
            signals = risk_evidence.threat_signals(session, wanted)
        assert list(signals) == [wanted[-1]]
        assert signals[wanted[-1]].in_kev

    def test_environmental_scores_reads_past_the_bind_limit(self, client) -> None:
        ids = [f"f{n:06d}" for n in range(MANY)]
        with client.app.state.db.session() as session:
            session.add(EnvironmentalScore(finding_id=ids[-1], repo_full_name=REPO))
            session.flush()
            scores = risk_evidence.environmental_scores(session, finding_ids=ids)
        assert list(scores) == [ids[-1]]
