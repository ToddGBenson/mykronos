"""An acceptance dissolves only the toxic combinations its approver was shown
(TheHub #61013, security-champion review of #1018).

Under #1018 an `accepted_risk` member stopped counting toward any
combination, so an acceptance made *before* a combination formed - a CVE
accepted as "not reachable", later paired with a live disclosure on the same
service - dissolved it silently and nobody decided it again. Pinned here:

1. an accepted member suppresses a combination only when that combination is
   in the acceptance's frozen evidence; one that formed later forms;
2. that acceptance moves to `premise_failed` through spec 33 §4.2's path;
3. a combination the frozen evidence named stays suppressed;
4. unreadable or missing frozen evidence covers nothing.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Any

import pytest

from mykronos import premise_monitor as pm
from mykronos import toxic
from mykronos.db.models import ApprovalRequest, RiskAcceptance
from mykronos.patchwork import correlate
from tests.conftest import (
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard
from tests.test_premise_monitor import _audits, _record, _run
from tests.test_risk_acceptance import _agent, _approve, _propose

CVE = "CVE-2024-4812"
DAST = "ZAP-10037-CWE-497"
PAIR = "vulnerable-image-and-live-service"


def _ingest(client, capability: str, payload: dict[str, Any], run_compaction) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas', 'dast')}"}
    run = str(uuid.uuid4())
    post_scan(client, auth, scan_run_id=run, capability=capability)
    response = post_findings(client, auth, [payload], scan_run_id=run, capability=capability)
    assert response.status_code in (200, 201), response.text
    run_compaction()


def _cve(client, run_compaction) -> None:
    _ingest(client, "atlas", dependency_finding(severity="high"), run_compaction)


def _disclosure(client, run_compaction) -> None:
    _ingest(
        client,
        "dast",
        finding_payload(
            rule_id=DAST,
            title='Server Leaks Information via "X-Powered-By" at GET /',
            severity="low", file_path="/", line_start=None, line_end=None,
            symbol=None, code_snippet=None,
        ),
        run_compaction,
    )


def _accept(client, admin_auth, capability: str, rule_id: str) -> tuple[str, dict[str, Any]]:
    """Propose and approve an acceptance of one rule; (record id, frozen evidence)."""
    proposed = _propose(
        client,
        _agent(client, admin_auth),
        scope={"capability": capability, "rule_ids": [rule_id]},
        deviation_type="risk_adjustment",
        justification="Not reachable from outside: the service is behind the gateway.",
        premises=[{"type": "not_internet_facing"}],
        requested_until=(date.today() + timedelta(days=20)).isoformat(),
    )
    assert proposed.status_code == 201, proposed.text
    body = proposed.json()
    approved = _approve(client, admin_auth, body)
    assert approved.json()["state"] == "approved", approved.text
    evidence = client.get(
        f"/api/approvals/{body['approval_request_id']}/evidence", headers=admin_auth
    ).json()
    return str(body["risk_acceptance"]["id"]), evidence.get("evidence", evidence)


def _detect(client, **kwargs: Any) -> list[toxic.ToxicCombination]:
    with client.app.state.db.session() as session:
        return toxic.detect(client.app.state.catalog, repo=REPO, session=session, **kwargs)


def _frozen_ids(frozen: dict[str, Any]) -> set[str]:
    items = frozen["risk_evidence"]["categories"]["toxic_combinations"]["items"]
    return {i["combination_id"] for i in items}


def _status(client, capability: str) -> str:
    rows = client.app.state.catalog.query(
        "SELECT status FROM findings WHERE capability = ?", [capability]
    )
    return str(rows[0][0])


class TestAnAcceptanceMadeBeforeTheCombination:
    def test_the_combination_forms_and_names_the_acceptance(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        record_id, frozen = _accept(client, admin_auth, "atlas", CVE)
        assert _frozen_ids(frozen) == set()  # nothing to pair with when approved
        assert _status(client, "atlas") == "accepted_risk"

        _disclosure(client, run_compaction)  # the pair forms after the approval

        [combo] = _detect(client)
        assert combo.rule_id == PAIR
        assert combo.severity == "critical"
        assert combo.partly_accepted is True
        assert combo.unanticipated_acceptances == (record_id,)

    def test_the_acceptance_fails_its_premise_and_is_decided_again(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        record_id, _ = _accept(client, admin_auth, "atlas", CVE)
        _disclosure(client, run_compaction)

        result = _run(client)

        [failure] = result.failed
        assert failure.record_id == record_id
        [check] = [c for c in failure.failed if c.type == pm.IMPLICIT_TOXIC_TYPE]
        assert check.index == pm.IMPLICIT_TOXIC_INDEX
        assert PAIR in {e["rule_id"] for e in check.evidence}
        record = _record(client, record_id)
        assert record.status == "premise_failed"
        assert pm.IMPLICIT_TOXIC_TYPE in (record.closed_reason or "")
        assert _status(client, "atlas") == "open"  # reopened for re-decision
        [audit] = _audits(client, "risk_acceptance.premise_failed")
        [compact] = [
            c for c in (audit.detail or {})["failed"] if c["type"] == pm.IMPLICIT_TOXIC_TYPE
        ]
        assert compact["combination_ids"] == [check.evidence[0]["combination_id"]]

        # Once reopened the pair is an ordinary open combination; nothing
        # names an acceptance any more.
        [combo] = _detect(client)
        assert combo.partly_accepted is False and combo.unanticipated_acceptances == ()


class TestACombinationTheApproverWasShown:
    def test_stays_suppressed_and_fails_nothing(self, client, admin_auth, run_compaction) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        _disclosure(client, run_compaction)
        [before] = _detect(client)

        record_id, frozen = _accept(client, admin_auth, "dast", DAST)

        assert before.combination_id in _frozen_ids(frozen)
        assert _status(client, "dast") == "accepted_risk"
        assert _detect(client) == []
        assert [c.combination_id for c in _detect(client, suppress=False)] == [
            before.combination_id
        ]
        assert _run(client).failed == []
        assert _record(client, record_id).status == "active"

    def test_a_later_proposal_is_still_shown_it(
        self, client, admin_auth, run_compaction
    ) -> None:
        """The frozen evidence is read with nothing suppressed, so a renewal,
        or an acceptance of the other half, still names the combination an
        earlier acceptance dissolved - otherwise it would fail on approval."""
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        _disclosure(client, run_compaction)
        [before] = _detect(client)
        _accept(client, admin_auth, "dast", DAST)

        _, frozen = _accept(client, admin_auth, "atlas", CVE)

        assert before.combination_id in _frozen_ids(frozen)
        assert before.combination_id in {c["combination_id"] for c in frozen["combinations"]}
        assert _detect(client) == []
        assert _run(client).failed == []


class TestFailsClosed:
    def test_missing_frozen_evidence_covers_nothing(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        _disclosure(client, run_compaction)
        record_id, _ = _accept(client, admin_auth, "dast", DAST)
        with client.app.state.db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            assert record is not None and record.approval_request_id
            request = session.get(ApprovalRequest, record.approval_request_id)
            assert request is not None
            evidence = dict(request.evidence or {})
            evidence.pop("risk_evidence")
            evidence["combinations"] = "unreadable"
            request.evidence = evidence

        [combo] = _detect(client)
        assert combo.unanticipated_acceptances == (record_id,)
        assert [f.record_id for f in _run(client).failed] == [record_id]

    def test_a_direct_disposition_has_no_evidence_and_dissolves_nothing(
        self, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        _disclosure(client, run_compaction)
        dast = client.app.state.catalog.query(
            "SELECT finding_id FROM findings WHERE capability = 'dast'"
        )[0][0]
        response = client.patch(
            f"/api/dashboard/findings/{dast}/status",
            json={
                "status": "accepted_risk",
                "accepted_reason_code": "compensating_control",
                "accepted_until": (date.today() + timedelta(days=30)).isoformat(),
                "reason": "Behind the gateway.",
            },
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

        [combo] = _detect(client)
        assert combo.partly_accepted is True
        assert combo.unanticipated_acceptances == ()  # no record to fail

    def test_no_session_reads_no_evidence(self, client, admin_auth, run_compaction) -> None:
        onboard(client, admin_auth)
        _cve(client, run_compaction)
        _disclosure(client, run_compaction)
        _accept(client, admin_auth, "dast", DAST)

        assert _detect(client) == []
        assert len(toxic.detect(client.app.state.catalog, repo=REPO)) == 1

    @pytest.mark.parametrize(
        "evidence",
        [
            None,
            "a string",
            {},
            {"risk_evidence": "x"},
            {"risk_evidence": {"categories": {"toxic_combinations": {"items": "x"}}}},
            {"risk_evidence": {"categories": {"toxic_combinations": {"items": [None, 3]}}}},
            {"combinations": [{"combination_id": 7}, {"name": "no id"}]},
        ],
    )
    def test_malformed_evidence_names_nothing(self, evidence: Any) -> None:
        assert toxic.known_combinations(evidence) == frozenset()

    def test_both_frozen_listings_are_read(self) -> None:
        evidence = {
            "risk_evidence": {
                "categories": {"toxic_combinations": {"items": [{"combination_id": "a"}]}}
            },
            "combinations": [{"combination_id": "b"}],
        }
        assert toxic.known_combinations(evidence) == frozenset({"a", "b"})


class TestASuppressedPairNeverHidesAnOpenOne:
    """An accepted member may claim a slot an open finding would have filled;
    when its combination is suppressed, the open findings are detected again
    on their own, so #1018's open-only answer is never lost."""

    @staticmethod
    def _finding(fid: str, rule: str, title: str, status: str) -> dict[str, Any]:
        return {
            "finding_id": fid,
            "repo_full_name": REPO,
            "capability": "sast",
            "rule_id": rule,
            "title": title,
            "severity": "medium",
            "file_path": "orders/query.py",
            "status": status,
        }

    def test_the_open_pair_forms(self, monkeypatch) -> None:
        pool = [
            self._finding("x", "CWE-89", "SQL injection via string concatenation", "accepted_risk"),
            self._finding("y", "CWE-89", "SQL injection via string concatenation", "open"),
            self._finding("z", "CWE-306", "Missing authentication for critical function", "open"),
        ]
        [first] = correlate.detect(pool, discounted=correlate.FALSE_POSITIVE_ONLY)
        assert first.finding_ids == frozenset({"x", "z"})
        monkeypatch.setattr(
            toxic,
            "acceptance_coverage",
            lambda _s, _ids: {"x": [("r1", frozenset({first.combination_id}))]},
        )

        [(kept, unanticipated)] = toxic._combinations(pool, None, suppress=True)

        assert kept.finding_ids == frozenset({"y", "z"})
        assert unanticipated == ()
