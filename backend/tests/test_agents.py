"""Agent identities (spec 34 §1).

Before these, an agent acted with the operator's admin token and the audit log
recorded both under one name. The tests pin the three properties the rest of
spec 34 is built on: an agent is a distinct, attributable principal; a
sub-agent is visibly in its parent's lineage; and only a person can take
authority away.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from mykronos.adminauth import (
    ActorKind,
    Principal,
    PrincipalContextReset,
    Role,
    current_principal,
)
from mykronos.db.models import AgentCredential, AuditLogEntry
from mykronos.schemas import utcnow


def _mint(client, auth: dict[str, str], **body: Any):
    body.setdefault("family", "claude-opus-5.5")
    return client.post("/api/agents/credentials", json=body, headers=auth)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _audit(client, action: str) -> list[AuditLogEntry]:
    from sqlalchemy import select

    with client.app.state.db.session() as session:
        return list(
            session.execute(select(AuditLogEntry).where(AuditLogEntry.action == action)).scalars()
        )


class TestAnAgentIsItsOwnPrincipal:
    def test_a_person_mints_an_agent_that_acts_for_them(self, client, admin_auth) -> None:
        response = _mint(client, admin_auth, purpose="author")
        assert response.status_code == 201, response.text
        minted = response.json()
        assert minted["token"].startswith("mka_")
        assert minted["lineage"] == []

        me = client.get("/api/agents/whoami", headers=_bearer(minted["token"])).json()
        assert me["kind"] == "agent"
        assert me["actor"] == minted["actor"]
        assert me["provenance"]["family"] == "claude-opus-5.5"
        assert me["provenance"]["on_behalf_of"] == client.app.state.settings.admin_identity

    def test_the_operator_token_is_still_a_person(self, client, admin_auth) -> None:
        me = client.get("/api/agents/whoami", headers=admin_auth).json()
        assert me["kind"] == "human"

    def test_only_the_hash_is_stored(self, client, admin_auth) -> None:
        token = _mint(client, admin_auth).json()["token"]
        with client.app.state.db.session() as session:
            from sqlalchemy import select

            rows = list(session.execute(select(AgentCredential)).scalars())
        assert rows and all(token not in r.token_sha256 for r in rows)

    def test_a_viewer_cannot_mint(self, client, viewer_auth) -> None:
        assert _mint(client, viewer_auth).status_code == 403

    def test_an_expired_credential_is_refused(self, client, admin_auth) -> None:
        minted = _mint(client, admin_auth).json()
        with client.app.state.db.session() as session:
            row = session.get(AgentCredential, _hash(minted["token"]))
            row.expires_at = utcnow() - timedelta(seconds=1)
        assert client.get("/api/agents/whoami", headers=_bearer(minted["token"])).status_code == 401


def _hash(token: str) -> str:
    from mykronos.auth import hash_token

    return hash_token(token)


class TestSubAgentsAreVisiblyInTheirParentsLineage:
    def test_a_child_records_its_parent(self, client, admin_auth) -> None:
        parent = _mint(client, admin_auth).json()
        child = _mint(client, _bearer(parent["token"]), purpose="helper").json()
        assert child["lineage"] == [parent["instance"]]

        grandchild = _mint(client, _bearer(child["token"])).json()
        assert grandchild["lineage"] == [parent["instance"], child["instance"]]

    def test_a_child_acts_for_the_same_person(self, client, admin_auth) -> None:
        parent = _mint(client, admin_auth).json()
        refused = _mint(client, _bearer(parent["token"]), on_behalf_of="someone-else")
        assert refused.status_code == 403
        assert "same human" in refused.json()["detail"]

    def test_a_child_cannot_outlive_its_parent(self, client, admin_auth) -> None:
        parent = _mint(client, admin_auth, ttl_hours=1).json()
        child = _mint(client, _bearer(parent["token"]), ttl_hours=100).json()
        assert child["expires_at"] <= parent["expires_at"]


class TestOnlyAPersonTakesAuthorityAway:
    def test_an_agent_cannot_revoke(self, client, admin_auth) -> None:
        agent = _mint(client, admin_auth).json()
        other = _mint(client, admin_auth).json()
        response = client.post(
            f"/api/agents/credentials/{other['instance']}/revoke", headers=_bearer(agent["token"])
        )
        assert response.status_code == 403

    def test_revoking_a_parent_revokes_its_descendants(self, client, admin_auth) -> None:
        parent = _mint(client, admin_auth).json()
        child = _mint(client, _bearer(parent["token"])).json()
        response = client.post(
            f"/api/agents/credentials/{parent['instance']}/revoke", headers=admin_auth
        )
        assert response.json() == {"revoked": 2}
        for token in (parent["token"], child["token"]):
            assert client.get("/api/agents/whoami", headers=_bearer(token)).status_code == 401


class TestTheAuditLogSaysWhoActed:
    def test_an_agent_action_is_attributed_to_the_agent(self, client, admin_auth) -> None:
        parent = _mint(client, admin_auth).json()
        _mint(client, _bearer(parent["token"]))

        minted = _audit(client, "agent.credential_minted")
        by_agent = [e for e in minted if e.actor == parent["actor"]]
        assert len(by_agent) == 1
        assert by_agent[0].actor_kind == "agent"
        assert by_agent[0].actor_provenance["instance"] == parent["instance"]

    def test_a_person_action_is_attributed_to_the_person(self, client, admin_auth) -> None:
        _mint(client, admin_auth)
        entries = _audit(client, "agent.credential_minted")
        assert entries and entries[-1].actor_kind == "human"

    def test_nothing_authenticated_is_unattributed_not_human(self, client) -> None:
        db = client.app.state.db
        token = current_principal.set(None)
        try:
            with db.session() as session:
                db.audit(session, actor="cli", action="test.cli", entity_type="x", entity_id="1")
        finally:
            current_principal.reset(token)
        (entry,) = _audit(client, "test.cli")
        assert entry.actor_kind == "unattributed"

    def test_automation_is_attributed_as_automation(self, client) -> None:
        db = client.app.state.db
        token = current_principal.set(
            Principal(actor="job:rotation", role=Role.VIEWER, kind=ActorKind.AUTOMATION)
        )
        try:
            with db.session() as session:
                db.audit(
                    session,
                    actor="token-rotator",
                    action="test.job",
                    entity_type="x",
                    entity_id="1",
                )
        finally:
            current_principal.reset(token)
        (entry,) = _audit(client, "test.job")
        assert entry.actor_kind == "automation"


class TestEveryRequestStartsWithNoPrincipal:
    @pytest.mark.anyio
    async def test_the_reset_middleware_clears_a_leftover_principal(self) -> None:
        """A keep-alive connection is one task; a principal left from the last
        request must not be visible to the next."""
        seen: list[Any] = []

        async def app(scope: Any, receive: Any, send: Any) -> None:
            seen.append(current_principal.get())

        leftover = current_principal.set(
            Principal(actor="previous-request", role=Role.ADMIN, kind=ActorKind.HUMAN)
        )
        try:
            await PrincipalContextReset(app)({"type": "http"}, None, None)
            assert seen == [None]
            assert current_principal.get().actor == "previous-request"
        finally:
            current_principal.reset(leftover)
