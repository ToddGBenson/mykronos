"""The Product Owner console's routes at their edges (spec 35 §8.8, D-144).

`test_po_console.py` pins what each view shows. These pin who may call them:
every view needs a credential, every view is readable by a viewer, and the one
write - deciding an approval in place - is the operator's alone. An agent,
which may write elsewhere, is refused here. A decision taken in place is
taken once, against a request that has not expired, and both the engine and
the console write it to the audit log.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.auth import hash_token
from mykronos.db.models import AgentCredential, ApprovalDecision, ApprovalRequest
from mykronos.schemas import utcnow
from tests.po_support import audit_entries, connect  # noqa: F401
from tests.test_po_console import RATIONALE, base, make_request

VIEWS = ("delivery", "approvals", "roles", "retro", "trace", "fleet")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, Any]:
    response = client.post(
        "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
    )
    assert response.status_code == 201, response.text
    return response.json()


def _decide(
    client: TestClient,
    repo_id: str,
    request_id: str,
    digest: str,
    auth: dict[str, str] | None,
    verdict: str = "approve",
) -> Any:
    return client.post(
        f"{base(repo_id)}/approvals/{request_id}/decision",
        json={"verdict": verdict, "rationale": RATIONALE, "evidence_digest": digest},
        headers=auth or {},
    )


def _decisions(client: TestClient, request_id: str) -> list[ApprovalDecision]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = session.query(ApprovalDecision).filter_by(request_id=request_id).all()
        session.expunge_all()
        return rows


def _state(client: TestClient, request_id: str) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        return str(session.get(ApprovalRequest, request_id).state)


class TestEveryViewNeedsACredential:
    @pytest.mark.parametrize("view", VIEWS)
    def test_no_credential(
        self,
        client: TestClient,
        connect: Callable[..., Any],  # noqa: F811
        view: str,
    ) -> None:
        repo_id, _ = connect([])
        assert client.get(f"{base(repo_id)}/{view}").status_code == 401

    @pytest.mark.parametrize("view", VIEWS)
    def test_a_token_that_is_not_one(
        self,
        client: TestClient,
        connect: Callable[..., Any],  # noqa: F811
        view: str,
    ) -> None:
        repo_id, _ = connect([])
        response = client.get(f"{base(repo_id)}/{view}", headers=_bearer("not-a-token"))
        assert response.status_code == 401

    @pytest.mark.parametrize("view", VIEWS)
    def test_an_expired_agent_credential(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        view: str,
    ) -> None:
        repo_id, _ = connect([])
        agent = _agent(client, admin_auth)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.get(AgentCredential, hash_token(agent["token"]))
            row.expires_at = utcnow() - timedelta(seconds=1)
        response = client.get(f"{base(repo_id)}/{view}", headers=_bearer(agent["token"]))
        assert response.status_code == 401

    @pytest.mark.parametrize("view", VIEWS)
    def test_a_viewer_reads_every_view(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        view: str,
    ) -> None:
        """spec 35 §8.8: every phase 2 view is read-only, and a viewer sees all
        of them."""
        repo_id, _ = connect([])
        response = client.get(f"{base(repo_id)}/{view}", headers=viewer_auth)
        assert response.status_code == 200, response.text

    def test_a_decision_needs_a_credential(
        self,
        client: TestClient,
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        assert _decide(client, repo_id, request_id, digest, None).status_code == 401
        assert _decisions(client, request_id) == []
        assert audit_entries(client, "po.approval_decision") == []


class TestOnlyTheOperatorDecidesHere:
    def test_an_agent_is_refused(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        """The `agent` role may write elsewhere, and decides through the
        approvals API where its delegation is checked - not here."""
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        agent = _agent(client, admin_auth)
        response = _decide(client, repo_id, request_id, digest, _bearer(agent["token"]))
        assert response.status_code == 403
        assert "'admin' role" in response.json()["detail"]
        assert _decisions(client, request_id) == []
        assert _state(client, request_id) == "pending"

    def test_an_agent_cannot_decide_its_own_request_here(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        agent = _agent(client, admin_auth)
        request_id, digest = make_request(client, requested_by=agent["actor"])
        response = _decide(client, repo_id, request_id, digest, _bearer(agent["token"]))
        assert response.status_code == 403
        assert _decisions(client, request_id) == []

    def test_an_agent_reads_the_inbox_without_the_decide_controls(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        make_request(client)
        agent = _agent(client, admin_auth)
        body = client.get(f"{base(repo_id)}/approvals", headers=_bearer(agent["token"])).json()
        assert body["can_decide"] is False
        assert len(body["pending"]) == 1

    def test_an_unknown_request_is_not_found(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        response = _decide(client, repo_id, "no-such-request", "a" * 64, admin_auth)
        assert response.status_code == 404

    def test_an_unknown_repository_is_not_found(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        connect([])
        request_id, digest = make_request(client)
        response = _decide(client, "no-such-repo", request_id, digest, admin_auth)
        assert response.status_code == 404
        assert _decisions(client, request_id) == []


class TestADecisionInPlaceIsTakenOnce:
    def test_deciding_twice_is_refused_and_both_attempts_are_audited(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        first = _decide(client, repo_id, request_id, digest, admin_auth)
        assert first.json()["state"] == "approved"

        second = _decide(client, repo_id, request_id, digest, admin_auth, verdict="reject")
        assert second.status_code == 409
        assert "approved, not pending" in second.json()["detail"]
        assert [d.verdict for d in _decisions(client, request_id)] == ["approve"]
        assert _state(client, request_id) == "approved"

        outcomes = [e.detail["outcome"] for e in audit_entries(client, "po.approval_decision")]
        assert sorted(outcomes) == ["approved", "refused"]
        assert len(audit_entries(client, "approval.approve")) == 1
        assert audit_entries(client, "approval.reject") == []

    @pytest.mark.parametrize(
        ("verdict", "state"), [("reject", "rejected"), ("needs_info", "pending")]
    )
    def test_every_verdict_is_audited_by_both(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        verdict: str,
        state: str,
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        response = _decide(client, repo_id, request_id, digest, admin_auth, verdict=verdict)
        assert response.status_code == 200, response.text
        assert response.json()["state"] == state
        [engine] = audit_entries(client, f"approval.{verdict}")
        assert engine.entity_id == request_id
        [console] = audit_entries(client, "po.approval_decision")
        assert console.detail["outcome"] == state
        assert console.detail["verdict"] == verdict
        assert console.detail["decision_id"] == response.json()["decision_id"]

    def test_an_overdue_request_is_refused_and_marked_expired(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        """spec 35 §8.2: the expiry check runs unchanged, and the inbox promises
        the engine "will refuse a decision and mark it expired"."""
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.get(ApprovalRequest, request_id)
            row.expires_at = utcnow() - timedelta(seconds=1)
        overdue = client.get(f"{base(repo_id)}/approvals", headers=admin_auth).json()
        assert overdue["pending"][0]["overdue"] is True

        response = _decide(client, repo_id, request_id, digest, admin_auth)
        assert response.status_code == 409
        assert "expired" in response.json()["detail"]
        [entry] = audit_entries(client, "po.approval_decision")
        assert entry.detail["outcome"] == "refused"
        assert _decisions(client, request_id) == []

        assert _state(client, request_id) == "expired"
        after = client.get(f"{base(repo_id)}/approvals", headers=admin_auth).json()
        assert after["pending"] == []
