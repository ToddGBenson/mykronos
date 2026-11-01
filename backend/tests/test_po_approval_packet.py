"""The approval packet in the dashboard (TheHub #61136, v2 design P3).

Review-PendingApprovals.ps1 did four things the dashboard could not: it ran a
verification check and showed its output, it hid requests whose pull request
had moved past the head they name, it let a person concur with the reviewer,
and it decided requests that belong to no onboarded repository. These are the
server's half of that: the check, run by the platform when the packet opens
and again when the decision is recorded; the superseded split; and one route
that decides any pending request through the approvals engine.
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from mykronos.db.models import ApprovalDecision, ApprovalRequest
from mykronos.github.client import FakeGitHubClient
from tests.conftest import REPO
from tests.po_support import audit_entries, onboard
from tests.test_po_review_queue import HEAD, QUEUE, grant_request, open_pr, pr_request

DECIDE = "/api/dashboard/product-owner/approvals/{}/decision"
RATIONALE = "Read the diff at the frozen head and the check output; nothing reaches production."


class TestSupersededRequestsAreHidden:
    def test_a_pending_request_whose_pr_moved_on_leaves_the_pending_list(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        current, _ = pr_request(client, number=41)
        moved, _ = pr_request(client, number=42)
        open_pr(github, 41, HEAD)
        open_pr(github, 42, "e" * 40)

        body = client.get(QUEUE, headers=admin_auth).json()
        assert [i["id"] for i in body["pending"]] == [current]
        [row] = body["superseded"]
        assert row["id"] == moved
        assert row["requested_head_sha"] == HEAD
        assert row["current_head_sha"] == "e" * 40
        assert row["reason"] == "new_commits"
        assert body["counts"]["superseded"] == 1
        # Pending counts only what is left to decide.
        assert body["counts"]["pending"] == 1

    def test_a_merged_or_closed_pr_supersedes_its_request(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        merged, _ = pr_request(client, number=41)
        closed, _ = pr_request(client, number=42)
        open_pr(github, 41, HEAD, state="closed", merged=True)
        open_pr(github, 42, HEAD, state="closed")

        body = client.get(QUEUE, headers=admin_auth).json()
        assert body["pending"] == []
        reasons = {r["id"]: r["reason"] for r in body["superseded"]}
        assert reasons == {merged: "merged", closed: "closed"}

    def test_a_pr_github_cannot_be_asked_about_stays_pending(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Unknown is not superseded: hiding a request because GitHub did not
        answer would hide exactly the ones nobody can check."""
        request_id, _ = pr_request(client, repo="example-org/gone")
        grant = grant_request(client)
        body = client.get(QUEUE, headers=admin_auth).json()
        assert {i["id"] for i in body["pending"]} == {request_id, grant}
        assert body["superseded"] == []


class TestVerificationCheck:
    def test_a_pr_at_its_head_holds(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        request_id, _ = pr_request(client)
        open_pr(github, 41, HEAD)

        check = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()["verification"]
        assert check["holds"] is True
        assert check["ran_at"]
        texts = [line["text"] for line in check["lines"]]
        assert any("hashes to its digest" in t for t in texts)
        assert any(f"#41 is open at {HEAD[:12]}" in t for t in texts)
        assert all(line["ok"] is True for line in check["lines"])

    def test_a_moved_pr_fails_the_check_and_says_superseded(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        request_id, _ = pr_request(client)
        open_pr(github, 41, "e" * 40)

        body = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()
        assert body["superseded"] is True
        check = body["verification"]
        assert check["holds"] is False
        failing = [line["text"] for line in check["lines"] if line["ok"] is False]
        assert any("superseded" in t and ("e" * 12) in t for t in failing)

    def test_an_unanswerable_question_is_unknown_not_a_pass(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, _ = pr_request(client, repo="example-org/gone")
        check = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()["verification"]
        assert check["holds"] is None
        assert any(line["ok"] is None for line in check["lines"])

    def test_a_request_with_no_pull_request_checks_digest_and_expiry(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        grant = grant_request(client)
        check = client.get(f"{QUEUE}/{grant}", headers=admin_auth).json()["verification"]
        assert check["holds"] is True
        assert len(check["lines"]) == 2

    def test_an_expired_request_fails_the_check(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, _ = pr_request(
            client, repo="example-org/gone", expires_in=timedelta(hours=-1)
        )
        check = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()["verification"]
        assert check["holds"] is False


class TestDecideAnyRequest:
    def test_a_request_with_no_onboarded_repository_is_decided_here(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client, repo="example-org/other")
        response = client.post(
            DECIDE.format(request_id),
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            decisions = session.query(ApprovalDecision).filter_by(request_id=request_id).all()
            assert [(d.approver, d.verdict) for d in decisions] == [("admin", "approve")]

    def test_the_check_output_is_frozen_with_the_decision(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        """The platform runs the check again when the decision is recorded and
        stores what it saw, so the record says what was true at that moment,
        not what the page showed some minutes before."""
        onboard(client)
        request_id, digest = pr_request(client)
        open_pr(github, 41, HEAD)
        response = client.post(
            DECIDE.format(request_id),
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        [entry] = audit_entries(client, "po.approval_decision")
        assert entry.detail["outcome"] == "approved"
        assert entry.detail["evidence_digest"] == digest
        assert entry.detail["verification"]["holds"] is True
        lines = entry.detail["verification"]["lines"]
        assert any(f"#41 is open at {HEAD[:12]}" in line["text"] for line in lines)
        assert entry.detail["repo_full_name"] == REPO

    def test_a_decision_without_a_rationale_is_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client, repo="example-org/other")
        for rationale in ("", "   ", "ok"):
            response = client.post(
                DECIDE.format(request_id),
                json={"verdict": "approve", "rationale": rationale, "evidence_digest": digest},
                headers=admin_auth,
            )
            assert response.status_code in (409, 422), rationale
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.get(ApprovalRequest, request_id).state == "pending"
            assert session.query(ApprovalDecision).count() == 0

    def test_the_decision_is_bound_to_the_digest_it_was_shown(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, _ = pr_request(client, repo="example-org/other")
        response = client.post(
            DECIDE.format(request_id),
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": "0" * 64},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "different evidence digest" in response.json()["detail"]
        [entry] = audit_entries(client, "po.approval_decision")
        assert entry.detail["outcome"] == "refused"

    def test_an_unknown_request_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.post(
            DECIDE.format("no-such-request"),
            json={"verdict": "reject", "rationale": RATIONALE, "evidence_digest": "0" * 64},
            headers=admin_auth,
        )
        assert response.status_code == 404

    def test_a_viewer_cannot_decide(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client, repo="example-org/other")
        response = client.post(
            DECIDE.format(request_id),
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert audit_entries(client, "po.approval_decision") == []

    def test_an_agent_cannot_decide_even_its_own_request(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The console's decisions are the operator's (spec 35 §8.8). An agent
        decides through the approvals API, where independence is enforced;
        here it is refused outright, including on a request it raised."""
        minted = client.post(
            "/api/agents/credentials",
            json={"family": "claude-opus-5.5", "purpose": "packet-decide"},
            headers=admin_auth,
        )
        assert minted.status_code == 201, minted.text
        agent = {"Authorization": f"Bearer {minted.json()['token']}"}
        actor = client.get("/api/agents/whoami", headers=agent).json()["actor"]
        request_id, digest = pr_request(client, repo="example-org/other")
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.get(ApprovalRequest, request_id).requested_by = actor
        for verdict in ("approve", "reject"):
            response = client.post(
                DECIDE.format(request_id),
                json={"verdict": verdict, "rationale": RATIONALE, "evidence_digest": digest},
                headers=agent,
            )
            assert response.status_code == 403, response.text
            assert "requires the 'admin' role" in response.json()["detail"]
        assert audit_entries(client, "po.approval_decision") == []
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.get(ApprovalRequest, request_id).state == "pending"
            assert session.query(ApprovalDecision).count() == 0
