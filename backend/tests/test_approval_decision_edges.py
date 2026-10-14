"""Approval decisions at their edges (spec 34 §2-§5).

`test_approvals.py` pins each independence rule once. These pin what sits
around a decision: who may not decide at all, the model-lineage reading of
`different_family` on the decisions route (#819), a delegation that stops
counting the moment it is revoked, suspended or past its date, a request that
cannot be decided twice or after it expires, and the audit entry every
decision that stands leaves behind.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos.db.models import ApprovalDecision, ApprovalRequest, AuditLogEntry, Delegation
from mykronos.schemas import utcnow
from tests.test_approvals import (  # noqa: F401
    _bearer,
    _decide,
    _delegate,
    _mint,
    _platform_reviewer,
    _request,
    tiered,
)


def _decisions(client, request_id: str) -> list[ApprovalDecision]:
    with client.app.state.db.session() as session:
        rows = list(
            session.execute(
                select(ApprovalDecision).where(ApprovalDecision.request_id == request_id)
            ).scalars()
        )
        session.expunge_all()
        return rows


def _audit(client, request_id: str, prefix: str = "approval.") -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:
        rows = [
            e
            for e in session.execute(
                select(AuditLogEntry)
                .where(AuditLogEntry.entity_id == request_id)
                .order_by(AuditLogEntry.id)
            ).scalars()
            if e.action.startswith(prefix) and e.action != "approval.requested"
        ]
        session.expunge_all()
        return rows


def _state(client, request_id: str) -> str:
    with client.app.state.db.session() as session:
        return session.get(ApprovalRequest, request_id).state


class TestWhoMayNotDecideAtAll:
    def test_no_credential(self, client, admin_auth, tiered) -> None:  # noqa: F811
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        response = client.post(
            f"/api/approvals/{request['id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": "Premise checked against the evidence bundle.",
                "evidence_digest": request["evidence_digest"],
            },
        )
        assert response.status_code == 401
        assert _decisions(client, request["id"]) == []

    def test_a_viewer(self, client, admin_auth, viewer_auth, tiered) -> None:  # noqa: F811
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        response = _decide(client, viewer_auth, request)
        assert response.status_code == 403
        assert _decisions(client, request["id"]) == []
        assert _state(client, request["id"]) == "pending"

    def test_a_viewer_cannot_request(self, client, viewer_auth, tiered) -> None:  # noqa: F811
        response = client.post(
            "/api/approvals",
            json={"duty": "risk_acceptance", "subject_ref": "acc-1", "context": {"tier": "low"}},
            headers=viewer_auth,
        )
        assert response.status_code == 403

    def test_a_platform_reviewer_cannot_approve_its_own_request(
        self, client, tiered  # noqa: F811
    ) -> None:
        """Every other rule it would pass: delegated family, platform-started.
        The requester is never an approver (spec 34 §3.1)."""
        _delegate(client)
        reviewer = _bearer(_platform_reviewer(client))
        request = _request(client, reviewer)
        response = _decide(client, reviewer, request)
        assert response.status_code == 409
        assert "distinct_principal" in response.json()["detail"]
        assert _decisions(client, request["id"]) == []

    def test_an_agent_cannot_reject_or_query_its_own_request_either(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _bearer(_mint(client, admin_auth)["token"])
        request = _request(client, author)
        for verdict in ("reject", "needs_info"):
            response = _decide(client, author, request, verdict=verdict)
            assert response.status_code == 409, verdict
            assert "distinct_principal" in response.json()["detail"]
        assert _decisions(client, request["id"]) == []

    def test_an_agent_cannot_decide_its_parents_request_on_a_human_tier(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _mint(client, admin_auth)
        child = client.post(
            "/api/agents/credentials",
            json={"family": "gpt-5"},
            headers=_bearer(author["token"]),
        ).json()
        request = _request(client, _bearer(author["token"]), tier="critical")
        response = _decide(client, _bearer(child["token"]), request)
        assert response.status_code == 409
        assert _state(client, request["id"]) == "pending"


class TestDifferentFamilyIsTheModelLineage:
    """#819: `claude-opus-5` reviewing `claude-opus-5.5` used to pass as a
    different family because the strings differ."""

    @pytest.mark.parametrize("reviewer_family", ["claude-opus-5", "claude-sonnet-5"])
    def test_another_claude_is_the_same_family(
        self, client, admin_auth, tiered, reviewer_family  # noqa: F811
    ) -> None:
        _delegate(client, tiers=("high",), families=(reviewer_family,))
        author = _mint(client, admin_auth, family="claude-opus-5.5")
        request = _request(client, _bearer(author["token"]), tier="high")
        response = _decide(client, _bearer(_platform_reviewer(client, reviewer_family)), request)
        assert response.status_code == 409
        assert "different_family" in response.json()["detail"]
        assert "anthropic" in response.json()["detail"]
        assert _decisions(client, request["id"]) == []

    def test_a_different_vendor_passes(self, client, admin_auth, tiered) -> None:  # noqa: F811
        _delegate(client, tiers=("high",), families=("gpt-5",))
        author = _mint(client, admin_auth, family="claude-opus-5.5")
        request = _request(client, _bearer(author["token"]), tier="high")
        response = _decide(client, _bearer(_platform_reviewer(client, "gpt-5")), request)
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"

    def test_the_rule_applies_only_where_the_tier_names_it(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        """`medium` does not list `different_family`; a same-lineage reviewer is
        allowed there, under every other rule."""
        _delegate(client, tiers=("medium",), families=("claude-sonnet-5",))
        author = _mint(client, admin_auth, family="claude-opus-5.5")
        request = _request(client, _bearer(author["token"]), tier="medium")
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 200, response.text


class TestADelegationStopsCountingAtOnce:
    def _pending_for_reviewer(self, client, admin_auth) -> tuple[dict[str, Any], str]:
        delegation = _delegate(client)
        author = _mint(client, admin_auth)
        return _request(client, _bearer(author["token"])), delegation

    def test_revoked_after_the_request_was_made(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        """Revocation takes effect immediately; the request goes back to a
        person (spec 34 §5.1)."""
        request, delegation = self._pending_for_reviewer(client, admin_auth)
        revoked = client.post(
            f"/api/approvals/delegations/{delegation}/revoke", headers=admin_auth
        )
        assert revoked.status_code == 200

        refused = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert refused.status_code == 409
        assert "No active delegation" in refused.json()["detail"]
        assert _state(client, request["id"]) == "pending"

        by_person = _decide(client, admin_auth, request)
        assert by_person.status_code == 200, by_person.text
        assert by_person.json()["state"] == "approved"

    @pytest.mark.parametrize("how", ["suspended", "expired"])
    def test_suspended_or_expired(self, client, admin_auth, tiered, how) -> None:  # noqa: F811
        request, delegation = self._pending_for_reviewer(client, admin_auth)
        with client.app.state.db.session() as session:
            row = session.get(Delegation, delegation)
            if how == "suspended":
                row.suspended_at = utcnow()
                row.suspended_reason = "sampled agreement below threshold"
            else:
                row.expires_at = utcnow() - timedelta(seconds=1)
        refused = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert refused.status_code == 409
        assert "No active delegation" in refused.json()["detail"]
        assert _decisions(client, request["id"]) == []

    def test_an_agent_cannot_revoke_a_delegation(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        delegation = _delegate(client)
        agent = _bearer(_mint(client, admin_auth)["token"])
        response = client.post(f"/api/approvals/delegations/{delegation}/revoke", headers=agent)
        assert response.status_code == 403
        with client.app.state.db.session() as session:
            assert session.get(Delegation, delegation).revoked_at is None

    def test_revoking_twice_is_refused(self, client, admin_auth) -> None:
        delegation = _delegate(client)
        url = f"/api/approvals/delegations/{delegation}/revoke"
        assert client.post(url, headers=admin_auth).status_code == 200
        assert client.post(url, headers=admin_auth).status_code == 409

    def test_an_agent_cannot_review_a_sample(self, client, admin_auth) -> None:
        agent = _bearer(_mint(client, admin_auth)["token"])
        response = client.post(
            "/api/approvals/samples/any-decision", json={"verdict": "agree"}, headers=agent
        )
        assert response.status_code == 403


class TestADecisionIsTakenOnce:
    def test_approving_twice_is_refused_and_records_one_decision(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        assert _decide(client, admin_auth, request).json()["state"] == "approved"

        again = _decide(client, admin_auth, request)
        assert again.status_code == 409
        assert "approved, not pending" in again.json()["detail"]
        assert len(_decisions(client, request["id"])) == 1
        assert [e.action for e in _audit(client, request["id"])] == ["approval.approve"]

    def test_an_approval_cannot_be_turned_into_a_rejection(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        _decide(client, admin_auth, request)
        response = _decide(client, admin_auth, request, verdict="reject")
        assert response.status_code == 409
        assert _state(client, request["id"]) == "approved"

    def test_another_approver_cannot_add_to_a_decided_request(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        _delegate(client)
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        _decide(client, admin_auth, request, verdict="reject")
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 409
        assert len(_decisions(client, request["id"])) == 1

    def test_needs_info_leaves_it_pending_for_a_later_decision(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        asked = _decide(client, admin_auth, request, verdict="needs_info")
        assert asked.status_code == 200, asked.text
        assert asked.json()["state"] == "pending"

        approved = _decide(client, admin_auth, request)
        assert approved.json()["state"] == "approved"
        assert [d.verdict for d in _decisions(client, request["id"])] == [
            "needs_info",
            "approve",
        ]
        chain = client.get(f"/api/approvals/{request['id']}/chain", headers=admin_auth).json()
        assert chain["ok"], chain["detail"]
        assert [e["event"] for e in chain["events"]] == [
            "requested",
            "decision.needs_info",
            "decision.approve",
            "approved",
        ]


class TestAnExpiredRequestIsNotDecided:
    def _expire(self, client, request_id: str) -> None:
        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, request_id)
            row.expires_at = utcnow() - timedelta(seconds=1)

    def test_a_late_decision_is_refused(self, client, admin_auth, tiered) -> None:  # noqa: F811
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        self._expire(client, request["id"])
        response = _decide(client, admin_auth, request)
        assert response.status_code == 409
        assert "expired" in response.json()["detail"]
        assert _decisions(client, request["id"]) == []

    def test_the_refusal_marks_the_request_expired_on_its_chain(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        """spec 34 §4.1: `pending` -> `expired`; an approval request does not
        wait forever. The engine refuses a late decision *and records why*: a
        request left `pending` past its expiry is still in every inbox, and the
        chain never says it ended."""
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        self._expire(client, request["id"])
        _decide(client, admin_auth, request)

        assert _state(client, request["id"]) == "expired"
        chain = client.get(f"/api/approvals/{request['id']}/chain", headers=admin_auth).json()
        assert chain["ok"], chain["detail"]
        assert [e["event"] for e in chain["events"]] == ["requested", "expired"]
        listed = client.get(
            "/api/approvals", params={"state": "pending"}, headers=admin_auth
        ).json()
        assert request["id"] not in {r["id"] for r in listed}

    def test_once_expired_it_says_so_rather_than_expiring_again(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        self._expire(client, request["id"])
        _decide(client, admin_auth, request)
        second = _decide(client, admin_auth, request)
        assert second.status_code == 409
        assert "is expired, not pending" in second.json()["detail"]
        chain = client.get(f"/api/approvals/{request['id']}/chain", headers=admin_auth).json()
        assert [e["event"] for e in chain["events"]].count("expired") == 1


class TestEveryDecisionIsAudited:
    @pytest.mark.parametrize("verdict", ["approve", "reject", "needs_info"])
    def test_a_persons_decision(self, client, admin_auth, tiered, verdict) -> None:  # noqa: F811
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        assert _decide(client, admin_auth, request, verdict=verdict).status_code == 200
        (entry,) = _audit(client, request["id"])
        assert entry.action == f"approval.{verdict}"
        assert entry.actor == client.app.state.settings.admin_identity
        assert entry.actor_kind == "human"
        assert entry.entity_type == "approval_request"
        assert entry.detail["tier"] == "medium"
        assert entry.detail["same_person"] is False

    def test_an_agents_decision_names_the_agent_and_its_delegation(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        delegation = _delegate(client)
        request = _request(client, _bearer(_mint(client, admin_auth)["token"]))
        assert _decide(client, _bearer(_platform_reviewer(client)), request).status_code == 200
        (entry,) = _audit(client, request["id"])
        assert entry.action == "approval.approve"
        assert entry.actor == "agent:claude-sonnet-5:reviewer"
        assert entry.actor_kind == "agent"
        assert entry.actor_provenance["platform_started"] is True
        assert entry.detail["delegation_id"] == delegation

    def test_a_refused_decision_leaves_no_decision_and_no_verdict_entry(
        self, client, admin_auth, tiered  # noqa: F811
    ) -> None:
        author = _bearer(_mint(client, admin_auth)["token"])
        request = _request(client, author)
        assert _decide(client, author, request).status_code == 409
        assert _decide(client, admin_auth, request, digest="f" * 64).status_code == 409
        assert _decisions(client, request["id"]) == []
        assert _audit(client, request["id"]) == []
