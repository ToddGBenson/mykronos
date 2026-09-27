"""Risk acceptance as a governed decision (spec 33, phase 1).

The findings are real lake rows, ingested the way a scan writes them. The
properties pinned here: the tier is computed from the evidence, not chosen; the
acceptance changes nothing until someone independent approves it; the rules
spec 33 §2.2 lists refuse by name; and every lifecycle move is audited.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import risk_acceptance as ra
from mykronos.db.models import AuditLogEntry, RiskAcceptance, ThreatIntelMatch
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard

IMAGE = "postgres:15"
OTHER = "hashicorp/vault:2.1.1"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _finding(rule: str, severity: str, image: str = IMAGE, fixed: str = "") -> dict[str, Any]:
    raw: dict[str, Any] = {"image": image}
    if fixed:
        raw["fixed_version"] = fixed
    return {
        "rule_id": rule,
        "title": f"{rule} in libc6",
        "description": "x",
        "severity": severity,
        "file_path": "library/postgres",
        "package_name": "libc6",
        "package_version": "2.36",
        "raw_finding_json": raw,
    }


@pytest.fixture
def lake(client, admin_auth, run_compaction):
    """Three findings in one image, one in another."""
    onboard(client, admin_auth)
    auth = _bearer(issue_token(client, REPO, "containers"))

    def ingest(run_id: str, findings: list[dict[str, Any]]) -> None:
        client.post(
            "/api/ingest/scan-run",
            json={
                "scan_run_id": run_id,
                "repo_full_name": REPO,
                "capability": "containers",
                "tool_name": "trivy",
                "commit_sha": "a91f2c7",
                "branch": "main",
                "triggered_by": "push",
                "started_at": "2026-09-20T09:00:00",
                "scan_status": "success",
                "finding_count": len(findings),
            },
            headers=auth,
        )
        response = client.post(
            "/api/ingest/findings",
            json={"scan_run_id": run_id, "capability": "containers", "findings": findings},
            headers=auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

    ingest(
        "scan-1",
        [
            _finding("CVE-2026-1", "high"),
            _finding("CVE-2026-2", "medium"),
            _finding("CVE-2026-3", "low", fixed="2.36-9"),
            _finding("CVE-2026-1", "high", image=OTHER),
        ],
    )
    return ingest


def _agent(client, admin_auth, family: str = "claude-opus-5.5") -> dict[str, str]:
    token = client.post(
        "/api/agents/credentials", json={"family": family}, headers=admin_auth
    ).json()["token"]
    return _bearer(token)


def _proposal(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "repo": REPO,
        "scope": {"capability": "containers", "image": IMAGE, "fixed_version": "absent"},
        "deviation_type": "vendor_dependency",
        "justification": "Debian has not published a fix for these packages.",
        "residual_likelihood": "low",
        "residual_impact": "low",
        "risk_owner": "tgb",
        "requested_until": (date.today() + timedelta(days=60)).isoformat(),
        "premises": [{"type": "no_fixed_version"}],
        "milestones": [
            {"title": "Check the vendor", "due": "2026-10-26", "ends_weakness": False},
            {"title": "Apply the fix within 30 days of release", "due": "2026-11-25",
             "ends_weakness": True},
        ],
    }
    body.update(overrides)
    return body


def _propose(client, auth, **overrides: Any):
    return client.post("/api/risk-acceptances", json=_proposal(**overrides), headers=auth)


def _approve(client, auth, proposed: dict[str, Any]):
    return client.post(
        f"/api/approvals/{proposed['approval_request_id']}/decisions",
        json={
            "verdict": "approve",
            "rationale": "Checked the scope and the vendor tracker.",
            "evidence_digest": proposed["evidence_digest"],
        },
        headers=auth,
    )


def _statuses(client) -> dict[tuple[str, str], tuple[str, Any, Any]]:
    rows = client.app.state.catalog.query(
        "SELECT rule_id, json_extract_string(raw_finding_json, '$.image'), status, "
        "accepted_until, accepted_reason_code FROM findings"
    )
    return {(r[0], r[1]): (r[2], r[3], r[4]) for r in rows}


class TestAProposalChangesNothingUntilApproved:
    def test_an_agents_proposal_waits_for_a_person(self, client, admin_auth, lake) -> None:
        agent = _agent(client, admin_auth)
        response = _propose(client, agent)
        assert response.status_code == 201, response.text
        proposed = response.json()
        assert proposed["risk_acceptance"]["status"] == "pending_approval"
        assert proposed["risk_acceptance"]["findings"] == 2  # the fixable one is out of scope
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"

        # The agent cannot approve its own proposal.
        assert _approve(client, agent, proposed).status_code == 409

        approved = _approve(client, admin_auth, proposed)
        assert approved.json()["state"] == "approved", approved.text

        record = client.get(
            f"/api/risk-acceptances/{proposed['risk_acceptance']['id']}", headers=admin_auth
        ).json()
        assert record["status"] == "active"
        assert record["approved_by"] == client.app.state.settings.admin_identity
        status, until, code = _statuses(client)[("CVE-2026-1", IMAGE)]
        assert status == "accepted_risk" and code == "no_vendor_fix"
        assert until is not None

    def test_the_other_image_is_untouched(self, client, admin_auth, lake) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        _approve(client, admin_auth, proposed)
        assert _statuses(client)[("CVE-2026-1", OTHER)][0] == "open"


class TestTheTierIsComputed:
    def test_a_vendor_dependency_cannot_rate_below_the_scanner(
        self, client, admin_auth, lake
    ) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        assert proposed["tier"] == "high"  # low x low requested; a high finding is in scope

    def test_a_risk_adjustment_with_a_premise_may(self, client, admin_auth, lake) -> None:
        proposed = _propose(
            client,
            _agent(client, admin_auth),
            deviation_type="risk_adjustment",
            premises=[{"type": "port_not_published", "container": "mykronos-concourse-db"}],
        ).json()
        assert proposed["tier"] == "low"


class TestTheRulesRefuseByName:
    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"risk_owner": ""}, "names the person"),
            ({"risk_owner": "agent:claude-opus-5.5:abc"}, "names the person"),
            ({"deviation_type": "risk_adjustment", "premises": []}, "at least one premise"),
            ({"premises": [{"type": "trust_me"}]}, "not one the platform can monitor"),
            ({"milestones": [{"title": "x", "ends_weakness": False}]}, "end the weakness"),
            ({"scope": {"capability": "containers"}}, "names its image"),
            ({"scope": {"capability": "containers", "image": IMAGE}}, "name one"),
            ({"requested_until": (date.today() + timedelta(days=400)).isoformat()}, "at most"),
            (
                {
                    "deviation_type": "operational_requirement",
                    "residual_likelihood": "very_high",
                    "residual_impact": "very_high",
                },
                "architecture",
            ),
            ({"scope": {"capability": "containers", "image": "nope:1"}}, "matches no findings"),
        ],
    )
    def test_refused(self, client, admin_auth, lake, overrides, message) -> None:
        response = _propose(client, _agent(client, admin_auth), **overrides)
        assert response.status_code == 409, response.text
        assert message in response.json()["detail"]

    def test_a_kev_listed_cve_is_never_accepted(self, client, admin_auth, lake) -> None:
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2026-1", in_kev=True))
        response = _propose(client, _agent(client, admin_auth))
        assert response.status_code == 409
        assert "KEV-listed" in response.json()["detail"]


class TestRevocation:
    def test_a_person_revokes_and_the_findings_reopen(self, client, admin_auth, lake) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        _approve(client, admin_auth, proposed)
        record_id = proposed["risk_acceptance"]["id"]

        agent_try = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "no"},
            headers=_agent(client, admin_auth),
        )
        assert agent_try.status_code == 403

        response = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "The vendor shipped a fix."},
            headers=admin_auth,
        )
        assert response.json()["findings_reopened"] == 2
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"


class TestTheSweep:
    def _active(self, client, admin_auth) -> str:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        _approve(client, admin_auth, proposed)
        return proposed["risk_acceptance"]["id"]

    def test_review_due_then_expired_each_audited(self, client, admin_auth, lake) -> None:
        record_id = self._active(client, admin_auth)
        db, catalog = client.app.state.db, client.app.state.catalog
        with db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            review_by, expires_at = record.review_by, record.expires_at

        assert ra.sweep(db, catalog, today=review_by).review_due == 1
        assert ra.sweep(db, catalog, today=expires_at).expired == 1
        with db.session() as session:
            actions = [
                e.action
                for e in session.execute(
                    select(AuditLogEntry).where(AuditLogEntry.entity_id == record_id)
                ).scalars()
            ]
        assert "risk_acceptance.review_due" in actions
        assert "risk_acceptance.expired" in actions

    def test_a_new_finding_in_scope_is_drift_not_coverage(self, client, admin_auth, lake) -> None:
        record_id = self._active(client, admin_auth)
        lake("scan-2", [_finding("CVE-2026-9", "medium")])
        result = ra.sweep(client.app.state.db, client.app.state.catalog)
        assert result.drift == 1
        record = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        assert record["drift"] == 1 and record["findings"] == 2
        assert _statuses(client)[("CVE-2026-9", IMAGE)][0] == "open"


class TestRenewal:
    def test_renewal_supersedes_and_is_limited(self, client, admin_auth, lake) -> None:
        agent = _agent(client, admin_auth)
        first = _propose(client, agent).json()
        _approve(client, admin_auth, first)
        until = (date.today() + timedelta(days=80)).isoformat()

        renewal = client.post(
            f"/api/risk-acceptances/{first['risk_acceptance']['id']}/renew",
            json={"requested_until": until, "justification": "Still no fix upstream."},
            headers=agent,
        )
        assert renewal.status_code == 201, renewal.text
        body = renewal.json()
        assert body["risk_acceptance"]["renewal_count"] == 1
        evidence = client.get(
            f"/api/approvals/{body['approval_request_id']}/evidence", headers=admin_auth
        ).json()
        decision = client.post(
            f"/api/approvals/{body['approval_request_id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": "Renewal justified.",
                "evidence_digest": evidence["evidence_digest"],
            },
            headers=admin_auth,
        )
        assert decision.json()["state"] == "approved"
        parent = client.get(
            f"/api/risk-acceptances/{first['risk_acceptance']['id']}", headers=admin_auth
        ).json()
        assert parent["status"] == "closed"
        assert parent["closed_reason"].startswith("renewed by")


class TestLegacyMigration:
    def _accept_rowwise(self, client, admin_auth) -> None:
        rows = client.app.state.catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id IN ('CVE-2026-1', 'CVE-2026-2') "
            "AND json_extract_string(raw_finding_json, '$.image') = ?",
            [IMAGE],
        )
        until = (date.today() + timedelta(days=30)).isoformat()
        for (fid,) in rows:
            response = client.patch(
                f"/api/dashboard/findings/{fid}/status",
                json={
                    "status": "accepted_risk",
                    "accepted_reason_code": "no_vendor_fix",
                    "accepted_until": until,
                    "reason": "No Debian fix.",
                },
                headers=admin_auth,
            )
            assert response.status_code == 200, response.text

    def test_groups_are_proposed_and_findings_untouched(self, client, admin_auth, lake) -> None:
        self._accept_rowwise(client, admin_auth)
        agent = _agent(client, admin_auth)
        dry = client.post(
            "/api/risk-acceptances/migrate-legacy",
            json={"risk_owner": "tgb"},
            headers=agent,
        ).json()
        assert dry["dry_run"] and dry["findings"] == 2
        assert dry["groups"] == 2  # one per severity: high and medium

        real = client.post(
            "/api/risk-acceptances/migrate-legacy",
            json={"risk_owner": "tgb", "dry_run": False},
            headers=agent,
        ).json()
        pending = client.get(
            "/api/risk-acceptances?status_filter=pending_approval", headers=admin_auth
        ).json()
        assert len(pending) == real["groups"] == 2
        assert all(p["legacy"] for p in pending)
        in_image = {
            s[0] for k, s in _statuses(client).items() if k[1] == IMAGE and k[0] != "CVE-2026-3"
        }
        assert in_image == {"accepted_risk"}

        # A second run proposes nothing new: the findings are claimed.
        again = client.post(
            "/api/risk-acceptances/migrate-legacy",
            json={"risk_owner": "tgb"},
            headers=agent,
        ).json()
        assert again["groups"] == 0

    def test_approving_a_legacy_record_keeps_its_original_date(
        self, client, admin_auth, lake
    ) -> None:
        self._accept_rowwise(client, admin_auth)
        client.post(
            "/api/risk-acceptances/migrate-legacy",
            json={"risk_owner": "tgb", "dry_run": False},
            headers=_agent(client, admin_auth),
        )
        pending = client.get(
            "/api/risk-acceptances?status_filter=pending_approval", headers=admin_auth
        ).json()
        medium = next(p for p in pending if p["residual_severity"] == "medium")
        evidence = client.get(
            f"/api/approvals/{medium['approval_request_id']}/evidence", headers=admin_auth
        ).json()
        client.post(
            f"/api/approvals/{medium['approval_request_id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": "Legacy group reviewed.",
                "evidence_digest": evidence["evidence_digest"],
            },
            headers=admin_auth,
        )
        record = client.get(f"/api/risk-acceptances/{medium['id']}", headers=admin_auth).json()
        assert record["status"] == "active"
        assert record["expires_at"] == medium["requested_until"]


class TestTheTierCannotBeForged:
    """A record is activated only by the approval request it was proposed with.

    The risk_acceptance adapter trusts the snapshot in its context, and that
    snapshot is what sets the tier. Anyone who could create a second request
    for the same record with their own snapshot could pick a weaker tier -
    and its longer duration cap - and have that approved instead.
    """

    def _forged_context(self, record_id: str) -> dict[str, Any]:
        return {"snapshot": {"risk_acceptance_id": record_id, "residual": {"severity": "low"}}}

    def test_the_generic_route_refuses_a_hand_built_request(
        self, client, admin_auth, lake
    ) -> None:
        agent = _agent(client, admin_auth)
        proposed = _propose(client, agent).json()
        record_id = proposed["risk_acceptance"]["id"]

        forged = client.post(
            "/api/approvals",
            json={
                "duty": "risk_acceptance",
                "subject_ref": record_id,
                "context": self._forged_context(record_id),
            },
            headers=agent,
        )

        assert forged.status_code == 409, forged.text
        assert "/api/risk-acceptances" in forged.json()["detail"]

    def test_approving_any_other_request_does_not_activate_the_record(
        self, client, admin_auth, lake
    ) -> None:
        from mykronos.adminauth import ActorKind, Principal, Role
        from mykronos.approvals.engine import create_request
        from mykronos.approvals.policy import cached_policy

        proposed = _propose(client, _agent(client, admin_auth)).json()
        record_id = proposed["risk_acceptance"]["id"]
        assert proposed["tier"] == "high"
        # Straight to the engine, past any route: the record itself must refuse.
        forged = create_request(
            client.app.state.db,
            cached_policy(client.app.state.settings.approval_policy_path),
            duty="risk_acceptance",
            subject_ref=record_id,
            requested_by=Principal(
                actor="agent:claude-opus-5.5:forger",
                role=Role.AGENT,
                kind=ActorKind.AGENT,
                provenance={"family": "claude-opus-5.5", "instance": "forger"},
            ),
            context=self._forged_context(record_id),
        )
        assert forged.tier == "low"

        response = _approve(
            client,
            admin_auth,
            {"approval_request_id": forged.id, "evidence_digest": forged.evidence_digest},
        )

        assert response.status_code == 409, response.text
        assert "was proposed with approval request" in response.json()["detail"]
        record = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()
        assert record["status"] == "pending_approval"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"
