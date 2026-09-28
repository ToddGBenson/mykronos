"""The approval engine (spec 34 §2-§5).

Most of these are about who may *not* approve: the requester, a sub-agent of
the requester, an agent that could have seen the requester's reasoning, an
agent with no delegation, and a decision about something other than what was
frozen. Each refusal must name the rule it applied.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from mykronos.agents import TOKEN_PREFIX
from mykronos.approvals import engine
from mykronos.approvals.engine import Subject
from mykronos.approvals.policy import PolicyError, parse_policy
from mykronos.auth import hash_token
from mykronos.db.models import AgentCredential, ApprovalEvent, ApprovalRequest, Delegation
from mykronos.schemas import utcnow


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _mint(client, auth: dict[str, str], family: str = "claude-opus-5.5") -> dict[str, Any]:
    response = client.post("/api/agents/credentials", json={"family": family}, headers=auth)
    assert response.status_code == 201, response.text
    return response.json()


def _platform_reviewer(client, family: str = "claude-sonnet-5") -> str:
    """A reviewer credential as the platform itself would mint it (stage 4)."""
    token = TOKEN_PREFIX + f"platform-reviewer-{family}"
    with client.app.state.db.session() as session:
        session.add(
            AgentCredential(
                token_sha256=hash_token(token),
                actor=f"agent:{family}:reviewer",
                family=family,
                lineage=[],
                on_behalf_of="operator",
                purpose="independent-reviewer",
                minted_by="platform",
                expires_at=utcnow() + timedelta(hours=1),
                platform_started=True,
            )
        )
    return token


@pytest.fixture
def tiered(monkeypatch):
    """Stand in for spec 33's adapter: the tier comes from the test, as it will
    come from the acceptance record's residual severity."""

    def adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
        return Subject(tier=context["tier"], evidence={"subject": subject_ref, **context})

    monkeypatch.setitem(engine._ADAPTERS, "risk_acceptance", adapter)
    # And no spec 33 side effects: these tests are about the engine, and the
    # real handler would look for an acceptance record that does not exist.
    monkeypatch.setitem(engine._ON_APPROVED, "risk_acceptance", lambda session, request: None)
    # The stand-in adapter reads the tier from the context, so these tests
    # create requests through the generic route the real duty refuses.
    monkeypatch.delitem(engine._DEDICATED_ROUTES, "risk_acceptance", raising=False)


def _request(client, auth, tier: str = "medium", subject: str = "acc-1") -> dict[str, Any]:
    response = client.post(
        "/api/approvals",
        json={"duty": "risk_acceptance", "subject_ref": subject, "context": {"tier": tier}},
        headers=auth,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _decide(client, auth, request: dict[str, Any], verdict: str = "approve", digest=None):
    return client.post(
        f"/api/approvals/{request['id']}/decisions",
        json={
            "verdict": verdict,
            "rationale": "Premise checked against the evidence bundle.",
            "evidence_digest": digest or request["evidence_digest"],
        },
        headers=auth,
    )


def _delegate(client, tiers=("medium", "low"), families=("claude-sonnet-5",)) -> str:
    with client.app.state.db.session() as session:
        d = Delegation(
            granted_by="operator",
            grant_request_id="test",
            duty="risk_acceptance",
            tiers=list(tiers),
            approver_families=list(families),
            sampling=0.0,
            expires_at=utcnow() + timedelta(days=1),
        )
        session.add(d)
        session.flush()
        return d.id


class TestThePolicyFile:
    def test_the_shipped_policy_loads(self, client) -> None:
        from mykronos.approvals.policy import load_policy

        policy = load_policy(client.app.state.settings.approval_policy_path)
        assert policy.single_operator
        assert "risk_acceptance" in policy.duties

    @pytest.mark.parametrize(
        ("approvers", "message"),
        [
            ([{"kind": "agent"}], "must require a delegation"),
            ([{"kind": "automation"}], "never an approver"),
            ([], "no approvers"),
        ],
    )
    def test_unsafe_tiers_are_refused_at_load(self, approvers, message) -> None:
        with pytest.raises(PolicyError, match=message):
            parse_policy(
                {"version": "t", "duties": {"d": {"tiers": {"x": {"approvers": approvers}}}}}
            )

    def test_the_requester_rule_cannot_be_removed(self) -> None:
        policy = parse_policy(
            {
                "version": "t",
                "duties": {"d": {"tiers": {"x": {"approvers": [{"kind": "human"}]}}}},
            }
        )
        assert "distinct_principal" in {r.value for r in policy.duty("d").tiers["x"].independence}


class TestTheTierIsComputedNotClaimed:
    def test_a_duty_with_no_adapter_refuses(self, client, admin_auth) -> None:
        response = client.post(
            "/api/approvals",
            json={"duty": "deploy_override", "subject_ref": "sha"},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "No adapter" in response.json()["detail"]


class TestNobodyApprovesTheirOwnWork:
    def test_an_agent_cannot_approve_its_own_request(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(author["token"]), request)
        assert response.status_code == 409
        assert "distinct_principal" in response.json()["detail"]

    def test_a_sub_agent_cannot_approve_its_parents_request(
        self, client, admin_auth, tiered
    ) -> None:
        _delegate(client, families=("claude-opus-5.5",))
        author = _mint(client, admin_auth)
        child = client.post(
            "/api/agents/credentials",
            json={"family": "claude-opus-5.5"},
            headers=_bearer(author["token"]),
        ).json()
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(child["token"]), request)
        assert response.status_code == 409
        assert "outside_lineage" in response.json()["detail"]

    def test_an_agent_that_could_have_seen_the_reasoning_is_not_independent(
        self, client, admin_auth, tiered
    ) -> None:
        """Minted through the API, so nothing proves it saw only the bundle."""
        _delegate(client, families=("claude-opus-5.5",))
        author = _mint(client, admin_auth)
        peer = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(peer["token"]), request)
        assert response.status_code == 409
        assert "fresh_context" in response.json()["detail"]


class TestAnIndependentAgentUnderADelegation:
    def test_a_platform_started_reviewer_approves(self, client, admin_auth, tiered) -> None:
        delegation = _delegate(client)
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        reviewer = _platform_reviewer(client)

        response = _decide(client, _bearer(reviewer), request)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "approved"
        assert body["decisions"][0]["approver_kind"] == "agent"
        assert body["decisions"][0]["delegation_id"] == delegation

    def test_without_a_delegation_an_agent_is_refused(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 409
        assert "No active delegation" in response.json()["detail"]

    def test_a_revoked_delegation_stops_working(self, client, admin_auth, tiered) -> None:
        delegation = _delegate(client)
        assert (
            client.post(
                f"/api/approvals/delegations/{delegation}/revoke", headers=admin_auth
            ).status_code
            == 200
        )
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 409

    def test_a_human_only_tier_refuses_an_agent_even_with_a_delegation(
        self, client, admin_auth, tiered
    ) -> None:
        _delegate(client, tiers=("critical",))
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]), tier="critical")
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 409
        assert "does not admit" in response.json()["detail"]

    def test_the_family_must_be_one_the_delegation_trusts(
        self, client, admin_auth, tiered
    ) -> None:
        _delegate(client, families=("some-other-model",))
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, _bearer(_platform_reviewer(client)), request)
        assert response.status_code == 409


class TestAnApprovalIsOfWhatWasFrozen:
    def test_a_decision_about_another_digest_is_refused(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, admin_auth, request, digest="0" * 64)
        assert response.status_code == 409
        assert "different evidence digest" in response.json()["detail"]

    def test_the_approver_sees_the_bundle_and_the_claim_labelled(
        self, client, admin_auth, tiered
    ) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        seen = client.get(f"/api/approvals/{request['id']}/evidence", headers=admin_auth).json()
        assert seen["evidence_digest"] == request["evidence_digest"]
        assert engine.canonical_digest(seen["evidence"]) == seen["evidence_digest"]


class TestThePersonApprovesAnAgentsRequest:
    def test_the_operator_approves_and_the_chain_verifies(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        response = _decide(client, admin_auth, request)
        assert response.json()["state"] == "approved"
        assert response.json()["decisions"][0]["same_person"] is False

        chain = client.get(f"/api/approvals/{request['id']}/chain", headers=admin_auth).json()
        assert chain["ok"], chain["detail"]
        assert [e["event"] for e in chain["events"]] == [
            "requested",
            "decision.approve",
            "approved",
        ]

    def test_an_altered_event_breaks_the_chain(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        _decide(client, admin_auth, request)
        with client.app.state.db.session() as session:
            from sqlalchemy import select

            first = session.execute(
                select(ApprovalEvent).where(
                    ApprovalEvent.request_id == request["id"], ApprovalEvent.seq == 0
                )
            ).scalar_one()
            first.payload = {**first.payload, "tier": "low"}
        chain = client.get(f"/api/approvals/{request['id']}/chain", headers=admin_auth).json()
        assert not chain["ok"]
        assert "altered" in chain["detail"]

    def test_a_rejection_ends_the_request(self, client, admin_auth, tiered) -> None:
        author = _mint(client, admin_auth)
        request = _request(client, _bearer(author["token"]))
        assert _decide(client, admin_auth, request, verdict="reject").json()["state"] == "rejected"
        assert _decide(client, admin_auth, request).status_code == 409


class TestTheSingleOperatorDeviation:
    def _age(self, client, request_id: str, hours: float) -> None:
        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, request_id)
            row.created_at = row.created_at - timedelta(hours=hours)

    def test_one_person_waits_out_the_cooling_off(self, client, admin_auth, tiered) -> None:
        request = _request(client, admin_auth, tier="critical")
        early = _decide(client, admin_auth, request)
        assert early.status_code == 409
        assert "cooling-off" in early.json()["detail"]

        self._age(client, request["id"], 25)
        late = _decide(client, admin_auth, request)
        assert late.status_code == 200, late.text
        assert late.json()["state"] == "approved"
        assert late.json()["decisions"][0]["same_person"] is True


class TestDelegationsArePeoplesDecisions:
    def _proposal(self, **overrides: Any) -> dict[str, Any]:
        body = {
            "duty": "risk_acceptance",
            "tiers": ["low", "medium"],
            "approver_families": ["claude-sonnet-5"],
            "expires_at": (utcnow() + timedelta(days=30)).isoformat(),
        }
        return {**body, **overrides}

    def test_an_agent_cannot_propose_one(self, client, admin_auth) -> None:
        agent = _mint(client, admin_auth)
        response = client.post(
            "/api/approvals/delegations", json=self._proposal(), headers=_bearer(agent["token"])
        )
        assert response.status_code == 403

    def test_a_delegation_exists_only_once_a_person_approves_it(self, client, admin_auth) -> None:
        proposed = client.post(
            "/api/approvals/delegations", json=self._proposal(), headers=admin_auth
        ).json()
        assert proposed["duty"] == "delegation_grant"
        assert client.get("/api/approvals/delegations", headers=admin_auth).json() == []

        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, proposed["id"])
            row.created_at = row.created_at - timedelta(hours=2)
        approved = _decide(client, admin_auth, proposed)
        assert approved.json()["state"] == "approved", approved.text

        (live,) = client.get("/api/approvals/delegations", headers=admin_auth).json()
        assert live["active"] and live["tiers"] == ["low", "medium"]

    def test_a_delegation_cannot_widen_a_human_only_tier(self, client, admin_auth) -> None:
        response = client.post(
            "/api/approvals/delegations",
            json=self._proposal(tiers=["critical"]),
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "does not admit delegated agents" in response.json()["detail"]

    def test_a_delegation_cannot_run_past_the_maximum(self, client, admin_auth) -> None:
        response = client.post(
            "/api/approvals/delegations",
            json=self._proposal(expires_at=(utcnow() + timedelta(days=400)).isoformat()),
            headers=admin_auth,
        )
        assert response.status_code == 409


class TestAnUnsatisfiableTierIsRefusedAtCreation:
    def test_agent_only_tier_with_no_delegation(self, client, admin_auth, monkeypatch) -> None:
        policy = parse_policy(
            {
                "version": "t",
                "duties": {
                    "agent_only": {
                        "tiers": {
                            "x": {"approvers": [{"kind": "agent", "delegation": "required"}]}
                        }
                    }
                },
            }
        )
        monkeypatch.setitem(
            engine._ADAPTERS, "agent_only", lambda ref, ctx: Subject(tier="x", evidence={})
        )
        from mykronos.adminauth import Principal, Role

        with pytest.raises(engine.ApprovalError, match="Refused now"):
            engine.create_request(
                client.app.state.db,
                policy,
                duty="agent_only",
                subject_ref="s",
                requested_by=Principal(actor="operator", role=Role.ADMIN),
            )


def test_a_delegation_grant_cannot_skip_its_own_route(client, admin_auth) -> None:
    """The generic route would skip propose_delegation's checks: which tiers a
    delegation may cover at all, and how long it may run."""
    response = client.post(
        "/api/approvals",
        json={
            "duty": "delegation_grant",
            "subject_ref": "delegation:risk_acceptance:critical",
            "context": {
                "proposal": {
                    "duty": "risk_acceptance",
                    "tiers": ["critical"],
                    "approver_families": ["claude-opus-5.5"],
                    "expires_at": "2099-01-01T00:00:00",
                }
            },
        },
        headers=admin_auth,
    )
    assert response.status_code == 409
    assert "/api/approvals/delegations" in response.json()["detail"]


class TestARationaleSaysWhy:
    """`...` went into the record as the reason a governance change was
    allowed (2026-09-27). A rationale is what an audit reads; a placeholder
    is a decision with no reason."""

    @pytest.mark.parametrize(
        "rationale",
        ["...", "ok", "LGTM", "n/a", "approved", "  looks good  ", "fine.", "Approve!"],
    )
    def test_a_placeholder_is_refused(self, client, admin_auth, tiered, rationale) -> None:
        request = _request(client, admin_auth)
        response = client.post(
            f"/api/approvals/{request['id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": rationale,
                "evidence_digest": request["evidence_digest"],
            },
            headers=admin_auth,
        )

        assert response.status_code == 409, response.text
        assert "rationale" in response.json()["detail"]

    def test_a_real_reason_is_accepted(self, client, admin_auth, tiered) -> None:
        agent = _mint(client, admin_auth)
        request = _request(client, _bearer(agent["token"]))

        response = _decide(client, admin_auth, request)

        assert response.status_code == 200, response.text
