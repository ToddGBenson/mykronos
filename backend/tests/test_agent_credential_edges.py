"""Agent credentials at their edges (spec 34 §1).

`test_agents.py` pins the happy paths: an agent is its own principal, a
sub-agent is in its parent's lineage, only a person revokes. These pin the
refusals around them - who may not mint, the lifetime bounds, that an expired
or revoked credential stops working on the next request, and that the
plaintext is handed out exactly once.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.agents import (
    MAX_TTL_HOURS,
    TOKEN_PREFIX,
    AgentCredentialError,
    mint_agent_credential,
    revoke_agent_credential,
)
from mykronos.auth import hash_token
from mykronos.db.models import AgentCredential, AuditLogEntry
from mykronos.schemas import utcnow


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _mint(client, auth: dict[str, str], **body: Any):
    body.setdefault("family", "claude-opus-5.5")
    return client.post("/api/agents/credentials", json=body, headers=auth)


def _minted(client, auth: dict[str, str], **body: Any) -> dict[str, Any]:
    response = _mint(client, auth, **body)
    assert response.status_code == 201, response.text
    return response.json()


def _whoami(client, token: str):
    return client.get("/api/agents/whoami", headers=_bearer(token))


class TestWhoMayMint:
    def test_no_credential_cannot_mint(self, client) -> None:
        assert client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}
        ).status_code == 401

    def test_a_viewer_cannot_mint_even_for_itself(self, client, viewer_auth) -> None:
        response = _mint(client, viewer_auth, on_behalf_of="viewer")
        assert response.status_code == 403
        assert "may not mint" in response.json()["detail"]
        with client.app.state.db.session() as session:
            assert list(session.execute(select(AgentCredential)).scalars()) == []

    def test_automation_cannot_mint(self, client) -> None:
        job = Principal(actor="job:rotation", role=Role.ADMIN, kind=ActorKind.AUTOMATION)
        with pytest.raises(AgentCredentialError, match="automation principal may not mint"):
            mint_agent_credential(client.app.state.db, minted_by=job, family="claude-opus-5.5")

    def test_an_agent_may_name_its_own_principal(self, client, admin_auth) -> None:
        """Naming the principal it already acts for is not changing it."""
        parent = _minted(client, admin_auth)
        me = client.app.state.settings.admin_identity
        child = _minted(client, _bearer(parent["token"]), on_behalf_of=me)
        provenance = _whoami(client, child["token"]).json()["provenance"]
        assert provenance["on_behalf_of"] == me
        assert child["lineage"] == [parent["instance"]]

    def test_an_agent_cannot_mint_for_another_person(self, client, admin_auth) -> None:
        parent = _minted(client, admin_auth)
        response = _mint(client, _bearer(parent["token"]), on_behalf_of="someone-else")
        assert response.status_code == 403
        with client.app.state.db.session() as session:
            rows = list(session.execute(select(AgentCredential)).scalars())
        assert [r.instance for r in rows] == [parent["instance"]]

    def test_a_person_may_mint_on_behalf_of_another_person(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth, on_behalf_of="colleague")
        assert _whoami(client, minted["token"]).json()["provenance"]["on_behalf_of"] == (
            "colleague"
        )

    def test_a_child_of_a_platform_reviewer_is_not_platform_started(
        self, client
    ) -> None:
        """`fresh_context` trusts `platform_started`. A reviewer that could hand
        that flag to a sub-agent of its choosing could start its own reviewers."""
        token = TOKEN_PREFIX + "platform-reviewer"
        with client.app.state.db.session() as session:
            session.add(
                AgentCredential(
                    token_sha256=hash_token(token),
                    actor="agent:claude-sonnet-5:reviewer",
                    family="claude-sonnet-5",
                    lineage=[],
                    on_behalf_of="operator",
                    purpose="independent-reviewer",
                    minted_by="platform",
                    expires_at=utcnow() + timedelta(hours=1),
                    platform_started=True,
                )
            )
        child = _minted(client, _bearer(token), family="claude-sonnet-5")
        provenance = _whoami(client, child["token"]).json()["provenance"]
        assert provenance["platform_started"] is False
        assert provenance["on_behalf_of"] == "operator"

    def test_a_family_is_required(self, client, admin_auth) -> None:
        response = _mint(client, admin_auth, family="   ")
        assert response.status_code == 403
        assert "family" in response.json()["detail"]


class TestLifetimeBounds:
    @pytest.mark.parametrize("ttl", [0, -1, MAX_TTL_HOURS + 1, MAX_TTL_HOURS * 10])
    def test_out_of_bounds_ttl_is_refused_at_the_route(self, client, admin_auth, ttl) -> None:
        assert _mint(client, admin_auth, ttl_hours=ttl).status_code == 422
        with client.app.state.db.session() as session:
            assert list(session.execute(select(AgentCredential)).scalars()) == []

    @pytest.mark.parametrize("ttl", [0, -0.5, MAX_TTL_HOURS + 0.01])
    def test_out_of_bounds_ttl_is_refused_by_the_module(self, client, ttl) -> None:
        """The bound is enforced below the route too: other callers mint."""
        person = Principal(actor="operator", role=Role.ADMIN)
        with pytest.raises(AgentCredentialError, match="ttl_hours"):
            mint_agent_credential(
                client.app.state.db, minted_by=person, family="claude-opus-5.5", ttl_hours=ttl
            )

    def test_the_maximum_is_allowed(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth, ttl_hours=MAX_TTL_HOURS)
        assert _whoami(client, minted["token"]).status_code == 200

    def test_a_child_of_a_nearly_expired_parent_expires_with_it(
        self, client, admin_auth
    ) -> None:
        parent = _minted(client, admin_auth, ttl_hours=1)
        child = _minted(client, _bearer(parent["token"]), ttl_hours=MAX_TTL_HOURS)
        assert child["expires_at"] == parent["expires_at"]


class TestExpiredAndRevokedStopAtOnce:
    def _expire(self, client, token: str) -> None:
        with client.app.state.db.session() as session:
            row = session.get(AgentCredential, hash_token(token))
            row.expires_at = utcnow() - timedelta(seconds=1)

    def test_an_expired_credential_cannot_mint_or_list(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        assert _whoami(client, minted["token"]).status_code == 200
        self._expire(client, minted["token"])
        auth = _bearer(minted["token"])
        assert _whoami(client, minted["token"]).status_code == 401
        assert _mint(client, auth).status_code == 401
        assert client.get("/api/agents/credentials", headers=auth).status_code == 401

    def test_a_revoked_credential_is_refused_on_the_next_request(
        self, client, admin_auth
    ) -> None:
        minted = _minted(client, admin_auth)
        assert _whoami(client, minted["token"]).status_code == 200
        revoked = client.post(
            f"/api/agents/credentials/{minted['instance']}/revoke", headers=admin_auth
        )
        assert revoked.json() == {"revoked": 1}
        assert _whoami(client, minted["token"]).status_code == 401
        assert _mint(client, _bearer(minted["token"])).status_code == 401

    def test_a_revoked_and_an_unknown_token_answer_alike(self, client, admin_auth) -> None:
        """Nothing tells a caller holding a dead token why it is dead."""
        minted = _minted(client, admin_auth)
        client.post(f"/api/agents/credentials/{minted['instance']}/revoke", headers=admin_auth)
        dead = _whoami(client, minted["token"])
        unknown = _whoami(client, TOKEN_PREFIX + "never-minted")
        assert dead.status_code == unknown.status_code == 401
        assert dead.json() == unknown.json()

    def test_revoking_twice_is_not_found(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        url = f"/api/agents/credentials/{minted['instance']}/revoke"
        assert client.post(url, headers=admin_auth).status_code == 200
        assert client.post(url, headers=admin_auth).status_code == 404

    def test_revoking_an_unknown_instance_is_not_found(self, client, admin_auth) -> None:
        response = client.post("/api/agents/credentials/no-such/revoke", headers=admin_auth)
        assert response.status_code == 404

    def test_revoking_a_child_leaves_the_parent(self, client, admin_auth) -> None:
        parent = _minted(client, admin_auth)
        child = _minted(client, _bearer(parent["token"]))
        response = client.post(
            f"/api/agents/credentials/{child['instance']}/revoke", headers=admin_auth
        )
        assert response.json() == {"revoked": 1}
        assert _whoami(client, child["token"]).status_code == 401
        assert _whoami(client, parent["token"]).status_code == 200

    def test_revocation_is_audited_with_every_instance_it_took(self, client, admin_auth) -> None:
        parent = _minted(client, admin_auth)
        child = _minted(client, _bearer(parent["token"]))
        client.post(f"/api/agents/credentials/{parent['instance']}/revoke", headers=admin_auth)
        with client.app.state.db.session() as session:
            (entry,) = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "agent.credential_revoked")
            ).scalars()
            assert entry.entity_id == parent["instance"]
            assert sorted(entry.detail["revoked"]) == sorted(
                [parent["instance"], child["instance"]]
            )
            assert entry.actor_kind == "human"


class TestOnlyAPersonRevokes:
    def test_an_agent_cannot_revoke_another_instance(self, client, admin_auth) -> None:
        agent = _minted(client, admin_auth)
        other = _minted(client, admin_auth)
        response = client.post(
            f"/api/agents/credentials/{other['instance']}/revoke",
            headers=_bearer(agent["token"]),
        )
        assert response.status_code == 403
        assert _whoami(client, other["token"]).status_code == 200

    def test_an_agent_cannot_revoke_its_own_child(self, client, admin_auth) -> None:
        parent = _minted(client, admin_auth)
        child = _minted(client, _bearer(parent["token"]))
        response = client.post(
            f"/api/agents/credentials/{child['instance']}/revoke",
            headers=_bearer(parent["token"]),
        )
        assert response.status_code == 403
        assert _whoami(client, child["token"]).status_code == 200

    def test_a_viewer_cannot_revoke(self, client, admin_auth, viewer_auth) -> None:
        agent = _minted(client, admin_auth)
        response = client.post(
            f"/api/agents/credentials/{agent['instance']}/revoke", headers=viewer_auth
        )
        assert response.status_code == 403
        assert _whoami(client, agent["token"]).status_code == 200

    def test_the_module_refuses_an_agent_too(self, client, admin_auth) -> None:
        agent = Principal(
            actor="agent:x", role=Role.AGENT, kind=ActorKind.AGENT, provenance={"instance": "i"}
        )
        with pytest.raises(AgentCredentialError, match="Only a person"):
            revoke_agent_credential(client.app.state.db, instance="i", revoked_by=agent)


class TestThePlaintextIsShownOnce:
    def test_listing_never_returns_a_token_or_its_hash(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        _minted(client, _bearer(minted["token"]))
        for include_inactive in (False, True):
            response = client.get(
                "/api/agents/credentials",
                params={"include_inactive": include_inactive},
                headers=admin_auth,
            )
            assert response.status_code == 200
            rows = response.json()
            assert len(rows) == 2
            for row in rows:
                assert "token" not in row and "token_sha256" not in row
            assert minted["token"] not in response.text
            assert hash_token(minted["token"]) not in response.text

    def test_whoami_never_returns_the_token(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        response = _whoami(client, minted["token"])
        assert minted["token"] not in response.text
        assert hash_token(minted["token"]) not in response.text

    def test_the_mint_audit_entry_carries_no_token(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        with client.app.state.db.session() as session:
            (entry,) = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "agent.credential_minted")
            ).scalars()
            assert minted["token"] not in repr(entry.detail)

    def test_each_mint_is_a_new_token(self, client, admin_auth) -> None:
        tokens = {_minted(client, admin_auth)["token"] for _ in range(3)}
        assert len(tokens) == 3

    def test_inactive_credentials_are_listed_only_on_request(self, client, admin_auth) -> None:
        minted = _minted(client, admin_auth)
        client.post(f"/api/agents/credentials/{minted['instance']}/revoke", headers=admin_auth)
        assert client.get("/api/agents/credentials", headers=admin_auth).json() == []
        (row,) = client.get(
            "/api/agents/credentials", params={"include_inactive": True}, headers=admin_auth
        ).json()
        assert row["active"] is False and row["revoked_at"] is not None

    def test_a_viewer_cannot_list(self, client, admin_auth, viewer_auth) -> None:
        _minted(client, admin_auth)
        assert client.get("/api/agents/credentials", headers=viewer_auth).status_code == 403
