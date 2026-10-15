"""The operator's review queue (D-163): what is waiting on a person, estate-wide.

Two reads, no writes. The queue lists every pending approval request with the
requester's claim (labelled as one), the digest of the frozen evidence and the
platform reviewer's latest verdict, and every approved pull request with what
GitHub says about it now. The packet is one request in full: the frozen
evidence, whether it still hashes to the digest an approver decides against,
the duty's review instructions from the policy, and the reviewer's per-claim
checks. Deciding stays where it was: the approvals engine, through the routes
that already call it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos.approvals.engine import canonical_digest
from mykronos.approvals.reviewer import SHADOW_ACTION
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStamp,
    AuditLogEntry,
)
from mykronos.github.client import FakeGitHubClient, PullRequest
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.po_support import onboard

QUEUE = "/api/dashboard/product-owner/review-queue"
HEAD = "d" * 40
CLAIM = "Tightens the parser; the new test fails without it."


def pr_request(
    client: TestClient,
    *,
    repo: str = REPO,
    number: int = 41,
    head: str = HEAD,
    state: str = "pending",
    statement: str = CLAIM,
    expires_in: timedelta = timedelta(days=7),
    tier: str = "production",
) -> tuple[str, str]:
    evidence = {
        "subject_ref": f"{repo}#{number}@{head}",
        "repo": repo,
        "number": number,
        "title": "Tighten the parser",
        "head_sha": head,
        "change_class": tier,
        "files": [{"path": "backend/x.py", "class": tier, "patch": "+x"}],
    }
    digest = canonical_digest(evidence)
    now = utcnow()
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = ApprovalRequest(
            duty="pull_request_merge",
            tier=tier,
            subject_ref=evidence["subject_ref"],
            evidence=evidence,
            evidence_digest=digest,
            requested_by="agent:author-1",
            requester_kind="agent",
            requester_statement=statement,
            requester_provenance={"instance": "run-1"},
            state=state,
            policy_version="test",
            created_at=now,
            expires_at=now + expires_in,
            decided_at=now if state != "pending" else None,
        )
        session.add(row)
        session.flush()
        return row.id, digest


def grant_request(client: TestClient) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = ApprovalRequest(
            duty="delegation_grant",
            tier="any",
            subject_ref="dlg-routine-prs",
            evidence={"proposal": {"duty": "pull_request_merge"}},
            evidence_digest=canonical_digest({"proposal": {"duty": "pull_request_merge"}}),
            requested_by="admin",
            requester_kind="human",
            state="pending",
            expires_at=utcnow() + timedelta(days=1),
        )
        session.add(row)
        session.flush()
        return row.id


def shadow_review(
    client: TestClient,
    request_id: str,
    *,
    verdict: str,
    rationale: str,
    age: timedelta = timedelta(0),
    checks: list[dict[str, Any]] | None = None,
    tier: str = "production",
) -> None:
    db = client.app.state.db  # type: ignore[attr-defined]
    with db.session() as session:
        entry = db.audit(
            session,
            actor="agent:reviewer-x",
            action=SHADOW_ACTION,
            entity_type="approval_request",
            entity_id=request_id,
            verdict=verdict,
            rationale=rationale,
            checks=checks or [],
            duty="pull_request_merge",
            tier=tier,
            model="claude-opus-5",
        )
        entry.created_at = utcnow() - age


def approve(client: TestClient, request_id: str, digest: str, *, stamp_ok: bool = True) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(
            ApprovalDecision(
                request_id=request_id,
                approver="admin",
                approver_kind="human",
                verdict="approve",
                rationale="Read the diff at the frozen head.",
                evidence_digest=digest,
            )
        )
        session.add(
            ApprovalStamp(
                request_id=request_id,
                target=f"github_check:{REPO}@{HEAD}",
                state="approved",
                conclusion="success",
                error=None if stamp_ok else "HTTP 502",
            )
        )


def open_pr(github: FakeGitHubClient, number: int, head: str, **kwargs: Any) -> None:
    github.repos[REPO].pull_requests.append(
        PullRequest(
            number=number,
            url=f"https://github.com/{REPO}/pull/{number}",
            head_branch=f"b{number}",
            head_sha=head,
            title="Tighten the parser",
            **kwargs,
        )
    )


class TestPendingDecisions:
    def test_every_pending_request_is_listed_estate_wide(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client)
        mine, digest = pr_request(client)
        other, _ = pr_request(client, repo="example-org/other", number=7)
        grant = grant_request(client)
        pr_request(client, number=9, state="approved")

        body = client.get(QUEUE, headers=admin_auth).json()
        ids = {item["id"] for item in body["pending"]}
        assert ids == {mine, other, grant}

        item = next(i for i in body["pending"] if i["id"] == mine)
        assert item["evidence_digest"] == digest
        assert item["repo_full_name"] == REPO
        assert item["repo_id"] == repo_id
        # The repository's own tab is where it is decided in place.
        assert item["decide_link"] == f"/repos/{repo_id}?tab=product-owner&view=approvals"
        # The claim is carried, and carried as the requester's.
        assert item["requester_claim"] == CLAIM
        assert item["summary"] == "#41 Tighten the parser"

        estate = next(i for i in body["pending"] if i["id"] == grant)
        assert estate["repo_full_name"] is None
        assert estate["decide_link"] is None

        unonboarded = next(i for i in body["pending"] if i["id"] == other)
        assert unonboarded["repo_full_name"] == "example-org/other"
        assert unonboarded["decide_link"] is None

    def test_the_soonest_to_expire_comes_first(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        late, _ = pr_request(client, number=1, expires_in=timedelta(days=6))
        soon, _ = pr_request(client, number=2, expires_in=timedelta(hours=3))
        body = client.get(QUEUE, headers=admin_auth).json()
        assert [i["id"] for i in body["pending"]] == [soon, late]

    def test_the_reviewers_latest_verdict_sits_beside_the_claim(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        reviewed, _ = pr_request(client, number=1)
        unreviewed, _ = pr_request(client, number=2)
        shadow_review(
            client, reviewed, verdict="approve", rationale="old", age=timedelta(hours=2)
        )
        shadow_review(client, reviewed, verdict="reject", rationale="The test does not fail.")

        body = client.get(QUEUE, headers=admin_auth).json()
        assert body["reviewer"]["mode"] in ("off", "shadow", "live")
        rows = {i["id"]: i for i in body["pending"]}
        review = rows[reviewed]["reviewer"]
        assert review["verdict"] == "reject"
        assert review["rationale"] == "The test does not fail."
        assert review["model"] == "claude-opus-5"
        # Shadow verdicts count for nothing, and the queue says so.
        assert review["counts"] is False
        assert rows[unreviewed]["reviewer"] is None
        assert body["counts"]["pending"] == 2
        assert body["counts"]["unreviewed"] == 1

    def test_a_reject_on_a_human_only_tier_is_marked_procedural(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """On governance the reviewer is told to reject so a person decides
        (approval-policy-v1.yaml), so that reject is advice, not a finding: the
        same rule as scripts/review_inbox.py (#841) and the shadow report's
        `delegable`. The queue must not read it as a red flag."""
        governance, _ = pr_request(client, number=1, tier="governance")
        production, _ = pr_request(client, number=2)
        shadow_review(
            client, governance, verdict="reject", rationale="Goes to a person.", tier="governance"
        )
        shadow_review(client, production, verdict="reject", rationale="The test is missing.")
        rows = {i["id"]: i for i in client.get(QUEUE, headers=admin_auth).json()["pending"]}
        assert rows[governance]["reviewer"]["delegable"] is False
        assert rows[production]["reviewer"]["delegable"] is True

    def test_a_decision_already_recorded_is_shown_with_its_approver(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                ApprovalDecision(
                    request_id=request_id,
                    approver="agent:reviewer-y",
                    approver_kind="agent",
                    verdict="needs_info",
                    rationale="The patch is truncated.",
                    evidence_digest=digest,
                )
            )
        item = client.get(QUEUE, headers=admin_auth).json()["pending"][0]
        assert [(d["approver"], d["verdict"]) for d in item["decisions"]] == [
            ("agent:reviewer-y", "needs_info")
        ]


class TestReadyToMerge:
    def test_an_approved_pr_open_at_the_approved_head_is_ready(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        request_id, digest = pr_request(client, state="approved")
        approve(client, request_id, digest)
        open_pr(github, 41, HEAD)

        body = client.get(QUEUE, headers=admin_auth).json()
        [row] = body["ready_to_merge"]
        assert row["request_id"] == request_id
        assert row["repo_full_name"] == REPO
        assert row["number"] == 41
        assert row["approved_head_sha"] == HEAD
        assert row["github_state"] == "ready"
        assert row["check_posted"] is True
        assert row["ready"] is True
        assert row["approvers"] == ["admin"]
        assert body["counts"]["ready_to_merge"] == 1

    def test_a_new_push_makes_the_approval_stale(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        request_id, digest = pr_request(client, state="approved")
        approve(client, request_id, digest)
        open_pr(github, 41, "e" * 40)

        [row] = client.get(QUEUE, headers=admin_auth).json()["ready_to_merge"]
        assert row["github_state"] == "new_commits"
        assert row["ready"] is False

    def test_a_check_github_never_received_is_not_ready(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        request_id, digest = pr_request(client, state="approved")
        approve(client, request_id, digest, stamp_ok=False)
        open_pr(github, 41, HEAD)

        [row] = client.get(QUEUE, headers=admin_auth).json()["ready_to_merge"]
        assert row["check_posted"] is False
        assert row["ready"] is False

    def test_merged_and_closed_prs_leave_the_list(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        merged, d1 = pr_request(client, number=41, state="approved")
        closed, d2 = pr_request(client, number=42, state="approved")
        approve(client, merged, d1)
        approve(client, closed, d2)
        open_pr(github, 41, HEAD, state="closed", merged=True)
        open_pr(github, 42, HEAD, state="closed")

        assert client.get(QUEUE, headers=admin_auth).json()["ready_to_merge"] == []

    def test_a_repo_github_cannot_be_asked_about_is_unknown_not_ready(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client, repo="example-org/gone", state="approved")
        approve(client, request_id, digest)

        [row] = client.get(QUEUE, headers=admin_auth).json()["ready_to_merge"]
        assert row["github_state"] == "unknown"
        assert row["ready"] is False

    def test_the_queue_writes_nothing(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        onboard(client)
        pending, _ = pr_request(client, number=40)
        request_id, digest = pr_request(client, state="approved")
        approve(client, request_id, digest)
        open_pr(github, 41, HEAD)
        github.calls.clear()

        def snapshot() -> tuple[int, int, int, str]:
            with client.app.state.db.session() as session:  # type: ignore[attr-defined]
                return (
                    session.query(ApprovalDecision).count(),
                    session.query(ApprovalStamp).count(),
                    session.query(AuditLogEntry).count(),
                    str(session.get(ApprovalRequest, pending).state),
                )

        before = snapshot()
        assert client.get(QUEUE, headers=admin_auth).status_code == 200
        assert client.get(f"{QUEUE}/{pending}", headers=admin_auth).status_code == 200
        assert snapshot() == before
        assert {name for name, _ in github.calls} <= {"get_pull_request"}


class TestReviewPacket:
    def test_the_packet_is_claim_evidence_and_verdict_kept_apart(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client)
        checks = [
            {
                "claim": "the new test fails without the change",
                "holds": False,
                "note": "it passes on main",
            }
        ]
        shadow_review(client, request_id, verdict="reject", rationale="Claim fails.", checks=checks)

        body = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()
        assert body["id"] == request_id
        assert body["requester_claim"] == CLAIM
        assert body["evidence"]["head_sha"] == HEAD
        assert body["evidence_digest"] == digest
        assert body["digest_verified"] is True
        assert body["reviewer"]["verdict"] == "reject"
        assert body["reviewer"]["checks"] == checks
        # What the policy asks an approver to check for this duty: the
        # platform's question, never the requester's.
        assert "pull request" in body["review_instructions"]
        assert body["needs"]["quorum"] >= 1

    def test_evidence_altered_after_freezing_is_flagged(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        request_id, digest = pr_request(client)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.get(ApprovalRequest, request_id)
            row.evidence = {**row.evidence, "title": "Something else"}

        body = client.get(f"{QUEUE}/{request_id}", headers=admin_auth).json()
        assert body["evidence_digest"] == digest
        assert body["digest_verified"] is False

    def test_an_unknown_request_is_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert client.get(f"{QUEUE}/no-such-request", headers=admin_auth).status_code == 404


class TestWhoMayRead:
    def test_no_credential_is_refused(self, client: TestClient) -> None:
        assert client.get(QUEUE).status_code == 401
        request_id, _ = pr_request(client)
        assert client.get(f"{QUEUE}/{request_id}").status_code == 401

    def test_a_viewer_reads_both(self, client: TestClient, viewer_auth: dict[str, str]) -> None:
        request_id, _ = pr_request(client)
        assert client.get(QUEUE, headers=viewer_auth).status_code == 200
        assert client.get(f"{QUEUE}/{request_id}", headers=viewer_auth).status_code == 200
