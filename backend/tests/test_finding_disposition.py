"""An agent may not close a critical or high finding on its own word (#713).

On 2026-09-27 an agent dispositioned a high ZAP 40012 XSS as a false positive
through the status endpoint - good evidence, right verdict, nobody else's
signature. These tests pin the gap shut: the direct route refuses an agent on a
serious finding, the governed route freezes the evidence and keeps the finding
open, and only an approval applies the disposition. A person's direct call, and
an agent's on medium and below, are unchanged.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from sqlalchemy import select

from mykronos.db.models import AuditLogEntry
from tests.conftest import finding_payload, post_findings, post_scan

REASON = (
    "Reflected value is HTML-entity encoded in markup and \\u003c-escaped inside the "
    "RSC script payload; three breakout payloads were all inert."
)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _agent(client, admin_auth) -> dict[str, str]:
    response = client.post(
        "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
    )
    assert response.status_code == 201, response.text
    return _bearer(response.json()["token"])


def _seed(client, auth, run_compaction, severity: str) -> str:
    post_scan(client, auth)
    post_findings(client, auth, [finding_payload(rule_id=f"R-{severity}", severity=severity)])
    run_compaction()
    rows = client.app.state.catalog.query(
        "SELECT finding_id FROM findings WHERE rule_id = ?", [f"R-{severity}"]
    )
    return str(rows[0][0])


def _status(client, finding_id: str) -> str:
    return str(
        client.app.state.catalog.query(
            "SELECT status FROM findings WHERE finding_id = ?", [finding_id]
        )[0][0]
    )


def _patch(client, headers, finding_id: str, status: str, **extra: Any):
    return client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": status, "reason": REASON, **extra},
        headers=headers,
    )


def _ask(client, headers, finding_id: str, status: str = "false_positive", reason=REASON):
    return client.post(
        f"/api/dashboard/findings/{finding_id}/disposition-requests",
        json={"status": status, "reason": reason},
        headers=headers,
    )


class TestTheDirectRouteRefusesAnAgent:
    def test_a_false_positive_on_a_high_is_refused_and_points_to_the_duty(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")

        response = _patch(client, _agent(client, admin_auth), finding, "false_positive")

        assert response.status_code == 403
        assert "disposition-requests" in response.json()["detail"]
        assert _status(client, finding) == "open"

    def test_an_acceptance_on_a_critical_points_to_risk_acceptances(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "critical")

        response = _patch(
            client, _agent(client, admin_auth), finding, "accepted_risk",
            accepted_reason_code="not_exploitable_here", accepted_until="2099-01-01",
        )

        assert response.status_code == 403
        assert "/api/risk-acceptances" in response.json()["detail"]
        assert _status(client, finding) == "open"

    def test_a_person_is_unchanged(self, client, auth, admin_auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "high")

        response = _patch(client, admin_auth, finding, "false_positive")

        assert response.status_code == 200, response.text

    def test_an_agent_on_a_medium_is_unchanged(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "medium")

        response = _patch(client, _agent(client, admin_auth), finding, "false_positive")

        assert response.status_code == 200, response.text


class TestTheGovernedRoute:
    def test_the_finding_stays_open_until_a_person_approves(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")
        agent = _agent(client, admin_auth)

        asked = _ask(client, agent, finding)

        assert asked.status_code == 201, asked.text
        body = asked.json()
        assert body["tier"] == "high" and body["state"] == "pending"
        assert _status(client, finding) == "open", "nothing applies before approval"

        evidence = client.get(
            f"/api/approvals/{body['approval_request_id']}/evidence", headers=admin_auth
        ).json()
        frozen = evidence.get("evidence", evidence)
        assert frozen["finding"]["finding_id"] == finding
        assert frozen["proposed_status"] == "false_positive"
        assert frozen["reason"] == REASON

        decided = client.post(
            f"/api/approvals/{body['approval_request_id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": "Checked the agent's payload evidence against the raw record.",
                "evidence_digest": body["evidence_digest"],
            },
            headers=admin_auth,
        )
        assert decided.status_code in (200, 201), decided.text
        run_compaction()

        assert _status(client, finding) == "false_positive"
        with client.app.state.db.session() as session:
            entry = session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.entity_id == finding)
                .where(AuditLogEntry.action == "finding.status")
            ).scalar_one()
            assert entry.actor_kind == "agent"
            assert entry.detail["approval_request_id"] == body["approval_request_id"]
            assert entry.detail["applied"] is True

    def test_a_medium_is_not_governed(self, client, auth, admin_auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "medium")

        response = _ask(client, _agent(client, admin_auth), finding)

        assert response.status_code == 409
        assert "directly" in response.json()["detail"]

    def test_a_person_does_not_need_the_duty(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")

        response = _ask(client, admin_auth, finding)

        assert response.status_code == 409

    def test_a_placeholder_reason_is_refused(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")

        response = _ask(client, _agent(client, admin_auth), finding, reason="false positive")

        assert response.status_code == 409

    def test_the_generic_route_cannot_open_one(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        """The tier comes from the finding, so the generic route - where a
        requester supplies the context - is closed to this duty (#706)."""
        finding = _seed(client, auth, run_compaction, "high")

        response = client.post(
            "/api/approvals",
            json={
                "duty": "finding_disposition",
                "subject_ref": finding,
                "statement": "",
                "context": {"status": "false_positive", "reason": REASON},
            },
            headers=_agent(client, admin_auth),
        )

        assert response.status_code in (400, 409, 422), response.text


class TestReopening:
    """There was no way back from false_positive (#713 follow-up)."""

    def test_an_agent_can_reopen_and_then_ask_properly(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")
        assert _patch(client, admin_auth, finding, "false_positive").status_code == 200
        run_compaction()
        agent = _agent(client, admin_auth)

        reopened = client.post(
            f"/api/dashboard/findings/{finding}/reopen",
            json={"reason": "Disposition made before #713; resubmitting for a second signature."},
            headers=agent,
        )

        assert reopened.status_code == 200, reopened.text
        assert reopened.json()["previous_status"] == "false_positive"
        run_compaction()
        assert _status(client, finding) == "open"
        assert _ask(client, agent, finding).status_code == 201
        with client.app.state.db.session() as session:
            entry = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "finding.reopened")
            ).scalar_one()
            assert entry.detail["previous_status"] == "false_positive"

    def test_an_acceptance_is_not_reopened_here(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        until = (date.today() + timedelta(days=30)).isoformat()
        accepted = _patch(
            client, admin_auth, finding, "accepted_risk",
            accepted_reason_code="not_exploitable_here", accepted_until=until,
        )
        assert accepted.status_code == 200, accepted.text
        run_compaction()

        response = client.post(
            f"/api/dashboard/findings/{finding}/reopen",
            json={"reason": "Trying to undo an acceptance the wrong way."},
            headers=admin_auth,
        )

        assert response.status_code == 409
        assert "risk acceptance" in response.json()["detail"]

    def test_an_open_finding_is_not_reopened(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "high")

        response = client.post(
            f"/api/dashboard/findings/{finding}/reopen",
            json={"reason": "Nothing to reopen here at all."},
            headers=admin_auth,
        )

        assert response.status_code == 409

