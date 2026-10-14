"""Risk acceptances at their edges (spec 33, spec 34, #713).

`test_risk_acceptance.py` pins the lifecycle. These pin the refusals around
it: who may propose, renew, revoke and migrate; that an agent cannot get a
high or critical risk accepted on its own word, by approving its own record,
by a reviewer of its own model lineage, or by writing the status directly; and
that an acceptance past its date stops covering its findings.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest

from mykronos import risk_acceptance as ra
from mykronos.db.models import RiskAcceptance
from mykronos.jobs import sweep_acceptances
from tests.test_approvals import _delegate, _platform_reviewer
from tests.test_risk_acceptance import (  # noqa: F401
    IMAGE,
    _agent,
    _approve,
    _bearer,
    _proposal,
    _propose,
    _statuses,
    lake,
)


def _active(client, admin_auth) -> dict[str, Any]:
    proposed = _propose(client, _agent(client, admin_auth)).json()
    assert _approve(client, admin_auth, proposed).json()["state"] == "approved"
    return proposed


def _record(client, record_id: str) -> RiskAcceptance:
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        session.expunge(record)
        return record


def _count(client) -> int:
    with client.app.state.db.session() as session:
        return session.query(RiskAcceptance).count()


class TestOnlyAWriterProposesRenewsOrMigrates:
    def test_no_credential(self, client, lake) -> None:  # noqa: F811
        assert client.post("/api/risk-acceptances", json=_proposal()).status_code == 401

    def test_a_viewer_cannot_propose(self, client, viewer_auth, lake) -> None:  # noqa: F811
        response = _propose(client, viewer_auth)
        assert response.status_code == 403
        assert _count(client) == 0

    def test_a_viewer_cannot_renew(
        self, client, admin_auth, viewer_auth, lake  # noqa: F811
    ) -> None:
        record_id = _active(client, admin_auth)["risk_acceptance"]["id"]
        response = client.post(
            f"/api/risk-acceptances/{record_id}/renew",
            json={
                "requested_until": (date.today() + timedelta(days=80)).isoformat(),
                "justification": "Still no fix upstream.",
            },
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert _count(client) == 1

    @pytest.mark.parametrize("dry_run", [True, False])
    def test_a_viewer_cannot_migrate_legacy(
        self, client, viewer_auth, lake, dry_run  # noqa: F811
    ) -> None:
        response = client.post(
            "/api/risk-acceptances/migrate-legacy",
            json={"risk_owner": "tgb", "dry_run": dry_run},
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert _count(client) == 0

    def test_migrate_legacy_needs_a_credential(self, client, lake) -> None:  # noqa: F811
        response = client.post(
            "/api/risk-acceptances/migrate-legacy", json={"risk_owner": "tgb"}
        )
        assert response.status_code == 401


class TestOnlyAPersonRevokes:
    def test_a_viewer_cannot_revoke(
        self, client, admin_auth, viewer_auth, lake  # noqa: F811
    ) -> None:
        record_id = _active(client, admin_auth)["risk_acceptance"]["id"]
        response = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "No longer needed."},
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert _record(client, record_id).status == "active"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"

    def test_the_agent_that_proposed_it_cannot_revoke_it(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        agent = _agent(client, admin_auth)
        proposed = _propose(client, agent).json()
        _approve(client, admin_auth, proposed)
        record_id = proposed["risk_acceptance"]["id"]
        response = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "I changed my mind."},
            headers=agent,
        )
        assert response.status_code == 403
        assert _record(client, record_id).status == "active"

    def test_an_unknown_record(self, client, admin_auth, lake) -> None:  # noqa: F811
        response = client.post(
            "/api/risk-acceptances/no-such/revoke", json={"reason": "x"}, headers=admin_auth
        )
        assert response.status_code == 409

    def test_revoking_a_pending_proposal_reopens_nothing(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        record_id = proposed["risk_acceptance"]["id"]
        response = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "Withdrawn before approval."},
            headers=admin_auth,
        )
        assert response.json() == {"revoked": record_id, "findings_reopened": 0}
        # And an approval arriving afterwards cannot bring it back to life.
        late = _approve(client, admin_auth, proposed)
        assert late.status_code == 409
        assert _record(client, record_id).status == "revoked"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"


class TestAnAgentCannotAcceptASeriousRiskOnItsOwnWord:
    """#713 closed the direct route; spec 34 governs the record route."""

    def test_not_by_writing_the_status_directly(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        (fid,) = client.app.state.catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = 'CVE-2026-1' "
            "AND json_extract_string(raw_finding_json, '$.image') = ?",
            [IMAGE],
        )[0]
        response = client.patch(
            f"/api/dashboard/findings/{fid}/status",
            json={
                "status": "accepted_risk",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": (date.today() + timedelta(days=30)).isoformat(),
                "reason": "No Debian fix.",
            },
            headers=_agent(client, admin_auth),
        )
        assert response.status_code == 403
        assert "/api/risk-acceptances" in response.json()["detail"]
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"

    def test_not_by_approving_its_own_high_record(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        agent = _agent(client, admin_auth)
        proposed = _propose(client, agent).json()
        assert proposed["tier"] == "high"
        response = _approve(client, agent, proposed)
        assert response.status_code == 409
        assert "distinct_principal" in response.json()["detail"]
        assert _record(client, proposed["risk_acceptance"]["id"]).status == "pending_approval"
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "open"

    def test_not_through_a_reviewer_of_its_own_lineage(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        """High needs `different_family` (#819): a delegated, platform-started
        Claude reviewer still shares the Claude requester's blind spots."""
        _delegate(client, tiers=("high",), families=("claude-sonnet-5",))
        proposed = _propose(client, _agent(client, admin_auth, family="claude-opus-5.5")).json()
        response = _approve(client, _bearer(_platform_reviewer(client)), proposed)
        assert response.status_code == 409
        assert "different_family" in response.json()["detail"]
        assert _record(client, proposed["risk_acceptance"]["id"]).status == "pending_approval"

    def test_a_reviewer_of_another_lineage_under_a_delegation_may(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        _delegate(client, tiers=("high",), families=("gpt-5",))
        proposed = _propose(client, _agent(client, admin_auth, family="claude-opus-5.5")).json()
        response = _approve(client, _bearer(_platform_reviewer(client, "gpt-5")), proposed)
        assert response.status_code == 200, response.text
        assert _record(client, proposed["risk_acceptance"]["id"]).status == "active"

    def test_a_critical_record_needs_a_person_whatever_is_delegated(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        _delegate(client, tiers=("critical",), families=("gpt-5",))
        agent = _agent(client, admin_auth)
        response = _propose(
            client,
            agent,
            deviation_type="risk_adjustment",
            residual_likelihood="very_high",
            residual_impact="very_high",
            premises=[{"type": "port_not_published", "container": "db"}],
            requested_until=(date.today() + timedelta(days=20)).isoformat(),
        )
        assert response.status_code == 201, response.text
        proposed = response.json()
        assert proposed["tier"] == "critical"

        assert _approve(client, agent, proposed).status_code == 409
        by_reviewer = _approve(client, _bearer(_platform_reviewer(client, "gpt-5")), proposed)
        assert by_reviewer.status_code == 409
        assert "does not admit" in by_reviewer.json()["detail"]
        assert _record(client, proposed["risk_acceptance"]["id"]).status == "pending_approval"


class TestAnExpiredAcceptanceStopsCovering:
    def _expire(self, client, admin_auth) -> tuple[str, date]:
        record_id = _active(client, admin_auth)["risk_acceptance"]["id"]
        expires_at = _record(client, record_id).expires_at
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"
        # The scheduled job runs both sweeps, row level then record level.
        sweep_acceptances(client.app.state.catalog, today=expires_at)
        result = ra.sweep(client.app.state.db, client.app.state.catalog, today=expires_at)
        assert result.expired == 1
        return record_id, expires_at

    def test_the_day_before_it_still_covers(self, client, admin_auth, lake) -> None:  # noqa: F811
        record_id = _active(client, admin_auth)["risk_acceptance"]["id"]
        day_before = _record(client, record_id).expires_at - timedelta(days=1)
        sweep_acceptances(client.app.state.catalog, today=day_before)
        swept = ra.sweep(client.app.state.db, client.app.state.catalog, today=day_before)
        assert swept.expired == 0
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"
        assert _record(client, record_id).status in ra.LIVE

    def test_its_findings_reopen(self, client, admin_auth, lake) -> None:  # noqa: F811
        record_id, _ = self._expire(client, admin_auth)
        assert _record(client, record_id).status == "expired"
        for rule in ("CVE-2026-1", "CVE-2026-2"):
            status, until, code = _statuses(client)[(rule, IMAGE)]
            assert (status, until, code) == ("open", None, None)

    def test_it_cannot_be_renewed_or_revoked(self, client, admin_auth, lake) -> None:  # noqa: F811
        record_id, _ = self._expire(client, admin_auth)
        renewal = client.post(
            f"/api/risk-acceptances/{record_id}/renew",
            json={
                "requested_until": (date.today() + timedelta(days=30)).isoformat(),
                "justification": "Still no fix upstream.",
            },
            headers=admin_auth,
        )
        assert renewal.status_code == 409
        revoked = client.post(
            f"/api/risk-acceptances/{record_id}/revoke",
            json={"reason": "Tidying up."},
            headers=admin_auth,
        )
        assert revoked.status_code == 409
        assert _record(client, record_id).status == "expired"

    def test_the_findings_can_be_proposed_again(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        self._expire(client, admin_auth)
        again = _propose(client, _agent(client, admin_auth))
        assert again.status_code == 201, again.text
        assert again.json()["risk_acceptance"]["findings"] == 2


class TestRenewalEdges:
    def test_a_pending_record_cannot_be_renewed(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()
        response = client.post(
            f"/api/risk-acceptances/{proposed['risk_acceptance']['id']}/renew",
            json={
                "requested_until": (date.today() + timedelta(days=30)).isoformat(),
                "justification": "Still no fix upstream.",
            },
            headers=admin_auth,
        )
        assert response.status_code == 409

    def test_the_renewing_agent_cannot_approve_its_renewal(
        self, client, admin_auth, lake  # noqa: F811
    ) -> None:
        agent = _agent(client, admin_auth)
        first = _propose(client, agent).json()
        _approve(client, admin_auth, first)
        renewal = client.post(
            f"/api/risk-acceptances/{first['risk_acceptance']['id']}/renew",
            json={
                "requested_until": (date.today() + timedelta(days=80)).isoformat(),
                "justification": "Still no fix upstream.",
            },
            headers=agent,
        ).json()
        evidence = client.get(
            f"/api/approvals/{renewal['approval_request_id']}/evidence", headers=admin_auth
        ).json()
        response = _approve(
            client,
            agent,
            {
                "approval_request_id": renewal["approval_request_id"],
                "evidence_digest": evidence["evidence_digest"],
            },
        )
        assert response.status_code == 409
        assert _record(client, first["risk_acceptance"]["id"]).status == "active"
        assert _record(client, renewal["risk_acceptance"]["id"]).status == "pending_approval"
