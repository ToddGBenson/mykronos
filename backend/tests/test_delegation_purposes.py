"""Another agent's low/medium close needs the security champion (TheHub #61158).

Operator decision #61148 (2026-11-01): until this, an agent closed a low or
medium finding on its own word, and only critical and high went through
`finding_disposition` (#713). Now an agent's low or medium false positive
becomes a request, and a delegation can name the credential *purpose* that
may approve it - `security-champion` - not just a model family, because every
agent role mints as the same family (#61147). The champion never approves its
own request, and a credential it mints for itself is not the champion.
A person's direct disposition, and the platform's own (reconciler, re-scans,
auto-triage), are unchanged.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from mykronos.approvals import engine, sampling
from mykronos.approvals.engine import Subject
from mykronos.approvals.policy import Independence, load_policy
from mykronos.db.models import ApprovalDecision, ApprovalRequest, Delegation
from mykronos.schemas import utcnow
from tests.conftest import finding_payload, post_findings, post_scan

REASON = (
    "The flagged value is a constant compiled into the build; no request input "
    "reaches it, checked against the raw record's path and line."
)
RATIONALE = "Checked the reason against the raw scanner record; the path holds."
CHAMPION = "security-champion"


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _mint(client, auth, purpose: str = "author", family: str = "claude-opus-5.5"):
    response = client.post(
        "/api/agents/credentials", json={"family": family, "purpose": purpose}, headers=auth
    )
    assert response.status_code == 201, response.text
    return response.json()


def _seed(client, auth, run_compaction, severity: str, rule: str | None = None) -> str:
    rule_id = rule or f"R61158-{severity}"
    post_scan(client, auth)
    post_findings(client, auth, [finding_payload(rule_id=rule_id, severity=severity)])
    run_compaction()
    rows = client.app.state.catalog.query(
        "SELECT finding_id FROM findings WHERE rule_id = ?", [rule_id]
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


def _ask(client, headers, finding_id: str):
    return client.post(
        f"/api/dashboard/findings/{finding_id}/disposition-requests",
        json={"status": "false_positive", "reason": REASON},
        headers=headers,
    )


def _delegate(
    client,
    duty: str = "finding_disposition",
    tiers=("low", "medium"),
    purposes: tuple[str, ...] | None = (CHAMPION,),
    families=("claude-opus-5.5",),
) -> str:
    with client.app.state.db.session() as session:
        d = Delegation(
            granted_by="operator",
            grant_request_id="test",
            duty=duty,
            tiers=list(tiers),
            approver_families=list(families),
            constraints={"approver_purposes": list(purposes)} if purposes else {},
            sampling=0.0,
            expires_at=utcnow() + timedelta(days=30),
        )
        session.add(d)
        session.flush()
        return d.id


def _decide(client, headers, request_id: str):
    digest = client.get(f"/api/approvals/{request_id}", headers=headers).json()[
        "evidence_digest"
    ]
    return client.post(
        f"/api/approvals/{request_id}/decisions",
        json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
        headers=headers,
    )


class TestThePolicy:
    def test_both_duties_have_low_and_medium_tiers_a_named_agent_can_meet(self, client) -> None:
        policy = load_policy(client.app.state.settings.approval_policy_path)
        for duty in ("finding_disposition", "risk_acceptance"):
            for name in ("low", "medium"):
                tier = policy.duty(duty).tiers[name]
                assert tier.admits("human") is not None
                admits = tier.admits("agent")
                assert admits is not None and admits.delegation_required
                assert {
                    Independence.DISTINCT_PRINCIPAL,
                    Independence.DISTINCT_INSTANCE,
                    Independence.OUTSIDE_LINEAGE,
                } <= tier.independence
                # The champion runs on its own credential, so the tier cannot
                # demand a platform-started reviewer; the engine re-imposes it
                # for any delegation that names no purpose.
                assert Independence.FRESH_CONTEXT not in tier.independence

    def test_critical_stays_human_only(self, client) -> None:
        policy = load_policy(client.app.state.settings.approval_policy_path)
        assert policy.duty("finding_disposition").tiers["critical"].admits("agent") is None


class TestAnAgentsLowOrMediumCloseIsARequest:
    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_the_direct_route_refuses_an_agent(
        self, client, auth, admin_auth, run_compaction, severity
    ) -> None:
        finding = _seed(client, auth, run_compaction, severity)
        agent = _bearer(_mint(client, admin_auth)["token"])

        response = _patch(client, agent, finding, "false_positive")

        assert response.status_code == 403
        assert "disposition-requests" in response.json()["detail"]
        assert _status(client, finding) == "open"

    def test_an_agents_low_acceptance_points_to_risk_acceptances(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "low")
        agent = _bearer(_mint(client, admin_auth)["token"])

        response = _patch(
            client, agent, finding, "accepted_risk",
            accepted_reason_code="not_exploitable_here", accepted_until="2099-01-01",
        )

        assert response.status_code == 403
        assert "/api/risk-acceptances" in response.json()["detail"]

    @pytest.mark.parametrize("severity", ["low", "medium"])
    def test_the_request_is_tiered_by_severity(
        self, client, auth, admin_auth, run_compaction, severity
    ) -> None:
        finding = _seed(client, auth, run_compaction, severity)
        agent = _bearer(_mint(client, admin_auth)["token"])

        asked = _ask(client, agent, finding)

        assert asked.status_code == 201, asked.text
        assert asked.json()["tier"] == severity
        assert _status(client, finding) == "open"

    def test_a_person_is_unchanged(self, client, auth, admin_auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        assert _patch(client, admin_auth, finding, "false_positive").status_code == 200

    def test_an_agent_on_info_is_unchanged(self, client, auth, admin_auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "info")
        agent = _bearer(_mint(client, admin_auth)["token"])
        assert _patch(client, agent, finding, "false_positive").status_code == 200


class TestTheFlagRestoresTheOldBehaviour:
    @pytest.fixture
    def settings(self, settings):
        return settings.model_copy(update={"agent_low_medium_dispositions_governed": False})

    def test_an_agent_closes_a_medium_directly(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        finding = _seed(client, auth, run_compaction, "medium")
        agent = _bearer(_mint(client, admin_auth)["token"])

        assert _patch(client, agent, finding, "false_positive").status_code == 200
        assert _status(client, finding) == "false_positive"

    def test_a_high_is_still_governed(self, client, auth, admin_auth, run_compaction) -> None:
        finding = _seed(client, auth, run_compaction, "high")
        agent = _bearer(_mint(client, admin_auth)["token"])
        assert _patch(client, agent, finding, "false_positive").status_code == 403


class TestOnlyTheNamedPurposeApproves:
    def test_the_champion_approves_another_agents_request(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        delegation = _delegate(client)
        finding = _seed(client, auth, run_compaction, "low")
        author = _bearer(_mint(client, admin_auth)["token"])
        champion = _bearer(_mint(client, admin_auth, purpose=CHAMPION)["token"])
        request_id = _ask(client, author, finding).json()["approval_request_id"]

        response = _decide(client, champion, request_id)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "approved"
        assert body["decisions"][0]["delegation_id"] == delegation
        assert _status(client, finding) == "false_positive"

    def test_a_same_family_agent_with_another_purpose_is_refused(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _delegate(client)
        finding = _seed(client, auth, run_compaction, "medium")
        author = _bearer(_mint(client, admin_auth)["token"])
        sibling = _bearer(_mint(client, admin_auth, purpose="delivery")["token"])
        request_id = _ask(client, author, finding).json()["approval_request_id"]

        response = _decide(client, sibling, request_id)

        assert response.status_code == 409
        assert "approver_purposes" in response.json()["detail"]
        assert _status(client, finding) == "open"

    def test_the_champion_never_approves_its_own_request(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _delegate(client)
        finding = _seed(client, auth, run_compaction, "low")
        champion = _bearer(_mint(client, admin_auth, purpose=CHAMPION)["token"])
        request_id = _ask(client, champion, finding).json()["approval_request_id"]

        response = _decide(client, champion, request_id)

        assert response.status_code == 409
        assert "distinct_principal" in response.json()["detail"]
        assert _status(client, finding) == "open"

    def test_a_credential_an_agent_mints_itself_is_not_the_champion(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        """Purpose is free text, and an agent may mint a child with any: only a
        credential a person minted carries a purpose a delegation trusts."""
        _delegate(client)
        finding = _seed(client, auth, run_compaction, "low")
        author = _bearer(_mint(client, admin_auth)["token"])
        other = _mint(client, admin_auth, purpose="ux")
        forged = _mint(client, _bearer(other["token"]), purpose=CHAMPION)
        request_id = _ask(client, author, finding).json()["approval_request_id"]

        response = _decide(client, _bearer(forged["token"]), request_id)

        assert response.status_code == 409
        assert "minted by a person" in response.json()["detail"]

    def test_a_family_only_delegation_admits_only_a_platform_reviewer(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        """The policy dropped fresh_context so the champion can approve on its
        own credential; without a named purpose the engine puts it back."""
        _delegate(client, purposes=None)
        finding = _seed(client, auth, run_compaction, "low")
        author = _bearer(_mint(client, admin_auth)["token"])
        peer = _bearer(_mint(client, admin_auth, purpose=CHAMPION)["token"])
        request_id = _ask(client, author, finding).json()["approval_request_id"]

        response = _decide(client, peer, request_id)

        assert response.status_code == 409
        assert "fresh_context" in response.json()["detail"]

    def test_a_high_is_not_the_champions_to_approve(
        self, client, auth, admin_auth, run_compaction
    ) -> None:
        _delegate(client)
        finding = _seed(client, auth, run_compaction, "high")
        author = _bearer(_mint(client, admin_auth)["token"])
        champion = _bearer(_mint(client, admin_auth, purpose=CHAMPION)["token"])
        request_id = _ask(client, author, finding).json()["approval_request_id"]

        response = _decide(client, champion, request_id)

        assert response.status_code == 409
        assert _status(client, finding) == "open"


@pytest.fixture
def tiered_acceptance(monkeypatch):
    """risk_acceptance with the tier from the test, as test_approvals does."""

    def adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
        return Subject(tier=context["tier"], evidence={"subject": subject_ref, **context})

    monkeypatch.setitem(engine._ADAPTERS, "risk_acceptance", adapter)
    monkeypatch.setitem(engine._ON_APPROVED, "risk_acceptance", lambda session, request: None)
    monkeypatch.delitem(engine._DEDICATED_ROUTES, "risk_acceptance", raising=False)


class TestRiskAcceptanceTakesTheSameScoping:
    def _request(self, client, headers, tier: str = "medium") -> str:
        response = client.post(
            "/api/approvals",
            json={"duty": "risk_acceptance", "subject_ref": "acc-1", "context": {"tier": tier}},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        return str(response.json()["id"])

    def test_the_champion_approves(self, client, admin_auth, tiered_acceptance) -> None:
        _delegate(client, duty="risk_acceptance")
        author = _bearer(_mint(client, admin_auth)["token"])
        champion = _bearer(_mint(client, admin_auth, purpose=CHAMPION)["token"])

        response = _decide(client, champion, self._request(client, author))

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"

    def test_another_purpose_is_refused(self, client, admin_auth, tiered_acceptance) -> None:
        _delegate(client, duty="risk_acceptance")
        author = _bearer(_mint(client, admin_auth)["token"])
        sibling = _bearer(_mint(client, admin_auth, purpose="author")["token"])

        response = _decide(client, sibling, self._request(client, author, tier="low"))

        assert response.status_code == 409
        assert "approver_purposes" in response.json()["detail"]


class TestStartHeresDelegationShape:
    def _proposal(self, duty: str, **overrides: Any) -> dict[str, Any]:
        return {
            "duty": duty,
            "tiers": ["low", "medium"],
            "approver_families": ["claude-opus-5.5"],
            "constraints": {"approver_purposes": [CHAMPION]},
            "expires_at": (utcnow() + timedelta(days=30)).isoformat(),
            "sampling": 0.2,
            **overrides,
        }

    @pytest.mark.parametrize("duty", ["finding_disposition", "risk_acceptance"])
    def test_it_is_accepted_and_the_constraints_come_back(
        self, client, admin_auth, duty
    ) -> None:
        proposed = client.post(
            "/api/approvals/delegations", json=self._proposal(duty), headers=admin_auth
        )
        assert proposed.status_code == 201, proposed.text
        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, proposed.json()["id"])
            row.created_at = row.created_at - timedelta(hours=2)
        assert _decide(client, admin_auth, proposed.json()["id"]).json()["state"] == "approved"

        (live,) = client.get("/api/approvals/delegations", headers=admin_auth).json()

        assert live["active"] and live["duty"] == duty
        assert live["constraints"] == {"approver_purposes": [CHAMPION]}

    def test_the_listing_tells_the_champions_delegation_from_the_reviewers(
        self, client, admin_auth
    ) -> None:
        """Start-Here filters on constraints.approver_purposes; a family-only
        delegation (the platform reviewer's) must come back with none."""
        champion = _delegate(client, duty="risk_acceptance")
        reviewer = _delegate(
            client, duty="risk_acceptance", purposes=None, families=("claude-opus-5",)
        )

        listed = {
            d["id"]: d for d in client.get("/api/approvals/delegations", headers=admin_auth).json()
        }

        assert listed[champion]["constraints"]["approver_purposes"] == [CHAMPION]
        assert listed[reviewer]["constraints"] == {}

    @pytest.mark.parametrize("purposes", [[], [""], "security-champion", [3]])
    def test_a_malformed_purpose_list_is_refused(self, client, admin_auth, purposes) -> None:
        response = client.post(
            "/api/approvals/delegations",
            json=self._proposal(
                "finding_disposition", constraints={"approver_purposes": purposes}
            ),
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "approver_purposes" in response.json()["detail"]


NOW = datetime(2026, 11, 8, 12, 0, 0)


class TestTheWeeklyAudit:
    def _decision(self, client, delegation: str, at: datetime, verdict: str, subject: str):
        with client.app.state.db.session() as session:
            request = ApprovalRequest(
                duty="finding_disposition",
                tier="low",
                subject_ref=subject,
                evidence={},
                evidence_digest="0" * 64,
                requested_by="agent:claude-opus-5.5:author01",
                requester_kind="agent",
                requester_provenance={},
                state="approved" if verdict == "approve" else "rejected",
                policy_version="t",
                created_at=at - timedelta(minutes=5),
                expires_at=at + timedelta(days=7),
                decided_at=at,
            )
            session.add(request)
            session.flush()
            session.add(
                ApprovalDecision(
                    request_id=request.id,
                    approver="agent:claude-opus-5.5:champion",
                    approver_kind="agent",
                    approver_provenance={"purpose": CHAMPION},
                    verdict=verdict,
                    rationale=RATIONALE,
                    evidence_digest="0" * 64,
                    delegation_id=delegation,
                    sampled=False,
                    created_at=at,
                )
            )

    def test_it_lists_what_the_delegate_approved_in_the_window(
        self, client, admin_auth, monkeypatch
    ) -> None:
        monkeypatch.setattr(sampling, "utcnow", lambda: NOW)
        delegation = _delegate(client)
        self._decision(client, delegation, NOW - timedelta(days=2), "approve", "f-recent")
        self._decision(client, delegation, NOW - timedelta(days=3), "reject", "f-rejected")
        self._decision(client, delegation, NOW - timedelta(days=9), "approve", "f-old")

        response = client.get(
            f"/api/approvals/delegations/{delegation}/stats?days=7", headers=admin_auth
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["window_days"] == 7
        assert body["approved_in_window"] == 1
        assert body["rejected_in_window"] == 1
        assert [a["subject_ref"] for a in body["approved"]] == ["f-recent"]
        assert body["approved"][0]["requested_by"] == "agent:claude-opus-5.5:author01"
        assert body["constraints"] == {"approver_purposes": [CHAMPION]}
        assert body["decisions"] == 3, "the all-time counts are unchanged"
