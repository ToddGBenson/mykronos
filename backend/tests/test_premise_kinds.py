"""Every premise kind is monitored or explicitly unmonitorable, and a CVE
joining KEV reopens the acceptance (TheHub #60903, spec 33 §4 and §13).

Pinned here:

* each of `risk_acceptance.PREMISE_TYPES` is in exactly one of
  `premise_monitor.MONITORED` or `premise_monitor.UNMONITORED`, and an
  unmonitored kind says why rather than reading as holding;
* `not_kev_listed` fails on a KEV-listed CVE, holds only on fresh threat
  intel, and is otherwise unverified;
* `path_unreachable` holds when the import analysis proves every path dead,
  and is never failed by it;
* an accepted CVE that joins KEV after the proposal moves the acceptance to
  `premise_failed` and reopens its findings, whether or not it names
  `not_kev_listed`, whatever CISA's `kev_added_at` says; only a CVE the
  approver was shown as KEV-listed (the frozen `risk_evidence` block) does
  not, and a record with no frozen block knew of none.
"""

from __future__ import annotations

import copy
from datetime import date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import premise_monitor as pm
from mykronos import risk_acceptance as ra
from mykronos import risk_evidence
from mykronos.approvals.policy import InterimReview
from mykronos.db.models import (
    ApprovalRequest,
    ReachabilityReport,
    RepoOnboarding,
    RiskAcceptance,
    ThreatIntelMatch,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_notify import RecordingNotifier
from tests.test_premise_monitor import _audits, _record, _run
from tests.test_risk_acceptance import IMAGE, _agent, _approve, _propose, _statuses, lake
from tests.test_risk_evidence import TITLE_CVE, title_cve

__all__ = ["lake", "title_cve"]  # the fixtures, re-exported so pytest finds them here

NOW = datetime(2026, 10, 22, 12, 0, 0)


def _signal(cve: str, *, kev: bool, age_days: float = 1) -> risk_evidence.ThreatSignal:
    return risk_evidence.ThreatSignal(
        cve, kev, NOW.date() if kev else None, None, NOW - timedelta(days=age_days)
    )


def _facts(
    threat: dict[str, risk_evidence.ThreatSignal] | None = None,
    reachability: dict[str, Any] | None = None,
) -> pm.Facts:
    return pm.Facts(
        observations=[],
        surface_hostnames={},
        epss={},
        now=NOW,
        threat=threat or {},
        reachability=reachability,
    )


class TestEveryKindIsAccountedFor:
    def test_each_premise_type_is_monitored_or_explicitly_unmonitorable(self) -> None:
        monitored, unmonitored = set(pm.MONITORED), set(pm.UNMONITORED)
        assert monitored.isdisjoint(unmonitored)
        assert monitored | unmonitored == set(ra.PREMISE_TYPES)

    @pytest.mark.parametrize("kind", sorted(pm.UNMONITORED))
    def test_an_unmonitored_kind_says_why_and_never_holds(self, kind: str) -> None:
        check = pm.evaluate({"type": kind}, _facts(), cves_in_scope=[])
        assert check.status == "unverified"
        assert check.reason == pm.UNMONITORED[kind]


class TestNotKevListed:
    PREMISE = {"type": "not_kev_listed"}

    def test_a_listed_cve_fails_it(self) -> None:
        facts = _facts({"CVE-2026-1": _signal("CVE-2026-1", kev=True)})
        check = pm.evaluate(self.PREMISE, facts, cves_in_scope=["CVE-2026-1", "CVE-2026-2"])
        assert check.status == "failed"
        assert check.evidence[0]["cve"] == "CVE-2026-1"
        assert check.evidence[0]["source"] == "threat_intel"

    def test_fresh_intel_for_every_cve_holds(self) -> None:
        facts = _facts({c: _signal(c, kev=False) for c in ("CVE-2026-1", "CVE-2026-2")})
        check = pm.evaluate(self.PREMISE, facts, cves_in_scope=["CVE-2026-1", "CVE-2026-2"])
        assert check.status == "holds"

    def test_a_cve_the_feed_never_saw_is_unverified(self) -> None:
        facts = _facts({"CVE-2026-1": _signal("CVE-2026-1", kev=False)})
        check = pm.evaluate(self.PREMISE, facts, cves_in_scope=["CVE-2026-1", "CVE-2026-2"])
        assert check.status == "unverified"
        assert "CVE-2026-2" in check.reason

    def test_stale_intel_is_unverified(self) -> None:
        facts = _facts({"CVE-2026-1": _signal("CVE-2026-1", kev=False, age_days=30)})
        assert pm.evaluate(self.PREMISE, facts, cves_in_scope=["CVE-2026-1"]).status == (
            "unverified"
        )

    def test_the_premise_may_name_its_cves(self) -> None:
        facts = _facts({"CVE-2026-9": _signal("CVE-2026-9", kev=True)})
        premise = {"type": "not_kev_listed", "cves": ["cve-2026-9"]}
        assert pm.evaluate(premise, facts, cves_in_scope=[]).status == "failed"


class TestPathUnreachable:
    PREMISE = {"type": "path_unreachable"}
    REPORT = {
        "language": "python",
        "commit_sha": "a91f2c7",
        "orphaned_paths": ["app/legacy.py"],
        "files_analysed": 40,
        "files_unparseable": 0,
    }

    def test_no_analysis_is_unverified(self) -> None:
        check = pm.evaluate(
            self.PREMISE, _facts(), cves_in_scope=[], paths_in_scope=["app/legacy.py"]
        )
        assert check.status == "unverified"

    def test_a_dead_file_holds(self) -> None:
        check = pm.evaluate(
            self.PREMISE,
            _facts(reachability=self.REPORT),
            cves_in_scope=[],
            paths_in_scope=["app/legacy.py"],
        )
        assert check.status == "holds"
        assert check.evidence[0]["orphaned"] == ["app/legacy.py"]

    def test_a_file_not_proven_dead_is_unverified_never_failed(self) -> None:
        check = pm.evaluate(
            self.PREMISE,
            _facts(reachability=self.REPORT),
            cves_in_scope=[],
            paths_in_scope=["app/legacy.py", "app/main.py"],
        )
        assert check.status == "unverified"
        assert "app/main.py" in check.reason

    def test_it_does_not_exempt_an_acceptance_from_interim_review(self) -> None:
        rule = InterimReview()
        assert ra.interim_review_owed("risk_adjustment", [], [self.PREMISE], rule)
        assert not ra.interim_review_owed(
            "risk_adjustment", [], [{"type": "not_kev_listed"}], rule
        )


# ---------------------------------------------------------------------------
# A CVE joining KEV reopens the acceptance
# ---------------------------------------------------------------------------


def _accepted(client, admin_auth, **overrides: Any) -> str:
    proposed = _propose(client, _agent(client, admin_auth), **overrides)
    assert proposed.status_code == 201, proposed.text
    body = proposed.json()
    assert _approve(client, admin_auth, body).json()["state"] == "approved"
    return str(body["risk_acceptance"]["id"])


def _kev(client, cve: str, added: date | None) -> None:
    with client.app.state.db.session() as session:
        session.add(
            ThreatIntelMatch(cve_id=cve, in_kev=True, kev_added_at=added, fetched_at=utcnow())
        )


class TestKnownAtProposal:
    def test_it_reads_the_frozen_threat_intel_block(self) -> None:
        evidence = {
            "risk_evidence": {"categories": {"threat_intel": {"kev": ["cve-2026-7"]}}}
        }
        assert pm.known_at_proposal(evidence) == {"CVE-2026-7"}

    @pytest.mark.parametrize(
        "evidence", [None, {}, {"risk_evidence": {}}, {"risk_evidence": {"categories": {}}}]
    )
    def test_no_frozen_block_knew_of_nothing(self, evidence: dict[str, Any] | None) -> None:
        assert pm.known_at_proposal(evidence) == frozenset()

    def test_kev_join_skips_only_a_known_cve(self) -> None:
        record = RiskAcceptance(covered_finding_ids=["f1", "f2"])
        old = NOW.date() - timedelta(days=90)
        kev = {
            "f1": risk_evidence.ThreatSignal("CVE-2026-1", True, old, None, NOW),
            "f2": risk_evidence.ThreatSignal("CVE-2026-2", True, old, None, NOW),
        }
        check = pm.kev_join(record, kev, frozenset({"CVE-2026-1"}))
        assert check is not None and check.status == "failed"
        assert [e["cve"] for e in check.evidence] == ["CVE-2026-2"]
        assert pm.kev_join(record, kev, frozenset({"CVE-2026-1", "CVE-2026-2"})) is None


class TestKevJoinReopensTheAcceptance:
    def test_a_cve_joining_kev_reopens_an_acceptance_that_never_named_the_premise(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _accepted(client, admin_auth)  # vendor_dependency, no_fixed_version
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"

        _kev(client, "CVE-2026-1", utcnow().date())
        notifier = RecordingNotifier()
        result = _run(client, notifier)

        assert [f.record_id for f in result.failed] == [record_id]
        record = _record(client, record_id)
        assert record.status == "premise_failed"
        assert "not_kev_listed" in (record.closed_reason or "")
        statuses = _statuses(client)
        assert statuses[("CVE-2026-1", IMAGE)][0] == "open"
        assert statuses[("CVE-2026-2", IMAGE)][0] == "open"

        [failed] = _audits(client, "risk_acceptance.premise_failed")
        [check] = (failed.detail or {})["failed"]
        assert check["type"] == "not_kev_listed"
        assert check["index"] == pm.IMPLICIT_KEV_INDEX
        assert len(_audits(client, "finding.reopened_by_premise")) == 2
        [note] = [n for n in notifier.sent if "premise failed" in n.title.lower()]
        assert "CVE-2026-1" in note.detail

    def test_a_cve_the_feed_learned_of_after_approval_reopens_it_whatever_its_cisa_date(
        self, client, admin_auth, lake
    ) -> None:
        """The reviewer's repro on #1005: CISA's date is before the proposal,
        but the platform's feed did not know of the listing then."""
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2026-1", in_kev=False, fetched_at=utcnow()))
        record_id = _accepted(client, admin_auth)
        with client.app.state.db.session() as session:
            row = session.get(ThreatIntelMatch, "CVE-2026-1")
            assert row is not None
            row.in_kev = True
            row.kev_added_at = utcnow().date() - timedelta(days=1)
            row.fetched_at = utcnow()

        assert [f.record_id for f in _run(client).failed] == [record_id]
        assert _record(client, record_id).status == "premise_failed"

    def test_a_cve_cisa_listed_long_before_the_proposal_still_reopens_it(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _accepted(client, admin_auth)
        _kev(client, "CVE-2026-1", utcnow().date() - timedelta(days=30))
        assert [f.record_id for f in _run(client).failed] == [record_id]
        assert _record(client, record_id).status == "premise_failed"

    def test_a_cve_the_approver_was_shown_as_kev_listed_is_not_news(
        self, client, admin_auth, lake
    ) -> None:
        """Where policy lets a KEV-listed CVE be accepted, the frozen evidence
        names it, and the monitor does not reopen what was signed knowingly."""
        record_id = _accepted(client, admin_auth)
        with client.app.state.db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            assert record is not None and record.approval_request_id
            request = session.get(ApprovalRequest, record.approval_request_id)
            assert request is not None
            evidence = copy.deepcopy(request.evidence)
            evidence["risk_evidence"]["categories"]["threat_intel"]["kev"] = ["CVE-2026-1"]
            request.evidence = evidence
        _kev(client, "CVE-2026-1", utcnow().date() - timedelta(days=30))
        assert _run(client).failed == []
        assert _record(client, record_id).status == "active"

    def test_a_record_with_no_frozen_evidence_counts_every_listing_as_joined(
        self, client, admin_auth, lake
    ) -> None:
        """Acceptances approved before the evidence model, including GHSA
        findings whose title CVE was already listed, are reopened."""
        record_id = _accepted(client, admin_auth)
        with client.app.state.db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            assert record is not None
            request = session.get(ApprovalRequest, record.approval_request_id)
            assert request is not None
            request.evidence = {k: v for k, v in request.evidence.items() if k != "risk_evidence"}
        _kev(client, "CVE-2026-1", utcnow().date() - timedelta(days=365))
        assert [f.record_id for f in _run(client).failed] == [record_id]

    def test_a_named_not_kev_listed_premise_fails_once(self, client, admin_auth, lake) -> None:
        record_id = _accepted(
            client,
            admin_auth,
            premises=[{"type": "no_fixed_version"}, {"type": "not_kev_listed"}],
        )
        _kev(client, "CVE-2026-2", utcnow().date())
        result = _run(client)
        [failure] = result.failed
        assert failure.record_id == record_id
        assert [(c.index, c.type) for c in failure.failed] == [(1, "not_kev_listed")]

    def test_an_acceptance_with_no_premises_is_watched_too(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _accepted(client, admin_auth)
        with client.app.state.db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            assert record is not None
            record.premises = []
        _kev(client, "CVE-2026-1", None)  # no date: counted as joined
        assert [f.record_id for f in _run(client).failed] == [record_id]

    def test_findings_outside_any_acceptance_change_nothing(
        self, client, admin_auth, lake
    ) -> None:
        _kev(client, "CVE-2026-1", utcnow().date())
        result = _run(client)
        assert result.failed == [] and result.acceptances == 0

    def test_a_cve_named_only_in_the_title_joining_kev_reopens_it(
        self, client, admin_auth, title_cve
    ) -> None:
        """An Atlas finding's rule id is its GHSA id; its CVE is in the title."""
        record_id = _accepted(client, admin_auth)
        _kev(client, TITLE_CVE, utcnow().date())
        result = _run(client)
        assert [f.record_id for f in result.failed] == [record_id]
        [check] = result.failed[0].failed
        assert check.index == pm.IMPLICIT_KEV_INDEX
        assert TITLE_CVE in check.reason


class TestTheDetailShowsTheNewKinds:
    def test_path_unreachable_reads_the_stored_analysis(self, client, admin_auth, lake) -> None:
        with client.app.state.db.session() as session:
            onboarding = session.scalars(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            ).one()
            session.add(
                ReachabilityReport(
                    repo_onboarding_id=onboarding.id,
                    orphaned_paths=["library/postgres"],
                    files_analysed=3,
                )
            )
        record_id = _accepted(
            client,
            admin_auth,
            deviation_type="risk_adjustment",
            premises=[{"type": "path_unreachable"}],
        )
        detail = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        [check] = detail["premise_checks"]
        assert check["type"] == "path_unreachable"
        assert check["status"] == "holds"
