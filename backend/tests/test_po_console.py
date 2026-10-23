"""The Product Owner console's B-071 views (spec 35 §8.1 - §8.4).

Delivery, the Approvals inbox (decided in place through the spec 34 engine),
Roles & agents, and the computed retro.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import deployments
from mykronos.approvals.engine import canonical_digest
from mykronos.db.models import ApprovalDecision, ApprovalRequest, Delegation
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.po_support import audit_entries, connect, onboard, story  # noqa: F401

RATIONALE = "Read the diff at the frozen head and the test results; nothing reaches production."


def base(repo_id: str) -> str:
    return f"/api/dashboard/repos/{repo_id}/product-owner"


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------


def scan(sha: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "scan_run_id": f"scan-{sha}-{overrides.get('capability', 'sast')}",
        "repo_full_name": REPO,
        "capability": "sast",
        "tool_name": "codeql",
        "tool_version": "2",
        "commit_sha": sha,
        "branch": "main",
        "pr_number": None,
        "triggered_by": "push",
        "github_workflow_run_id": "9900123",
        "started_at": utcnow() - timedelta(days=1),
        "completed_at": utcnow() - timedelta(days=1),
        "scan_status": "success",
        "finding_count": 0,
        "raw_output_ref": None,
        "ingested_at": utcnow(),
    }
    row.update(overrides)
    return row


def decision(sha: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "decision_id": f"d-{sha}",
        "repo_full_name": REPO,
        "decision_type": "pull_request",
        "pr_number": 41,
        "release_tag": None,
        "commit_sha": sha,
        "overall_risk_score": 12,
        "recommendation": "go",
        "inputs_snapshot": "{}",
        "reasoning": "",
        "policy_version": "1.1",
        "evaluated_at": utcnow() - timedelta(hours=20),
        "human_override": None,
        "github_check_run_id": None,
        "gate_outcome": "merged",
    }
    row.update(overrides)
    return row


class TestDelivery:
    def test_shipped_commits_join_their_decision_and_the_running_revision(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        buffer: Any,
        run_compaction: Callable[[], Any],
    ) -> None:
        running = "a" * 40
        older = "b" * 40
        review = "c" * 40
        repo_id, _ = connect([], deployed_revision=running[:12])
        buffer.append(
            "scan_runs",
            [
                scan(running),
                scan(older, capability="sca", scan_status="failure"),
                scan(review, branch="feature", pr_number=42, triggered_by="pull_request"),
            ],
        )
        buffer.append("risk_decisions", [decision(running[:7])])
        run_compaction()

        body = client.get(f"{base(repo_id)}/delivery", headers=admin_auth).json()
        shipped = {row["sha"]: row for row in body["shipped"]}
        assert set(shipped) == {running, older}
        # The short sha the decision carries joins the full one: one row.
        assert shipped[running]["decision"]["recommendation"] == "go"
        assert shipped[running]["pr_numbers"] == [41]
        assert shipped[running]["deployed"] == "running"
        # Not the running revision: not recorded, never "not deployed".
        assert shipped[older]["deployed"] == "not_recorded"
        assert shipped[older]["scan_failures"] == 1
        assert shipped[older]["scans"][0]["run_url"].endswith("/actions/runs/9900123")
        assert [row["sha"] for row in body["not_shipped"]] == [review]
        assert body["deployment"]["running_revision"] == running[:12]

    def test_a_derived_probe_reads_configured_not_not_configured(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
    ) -> None:
        """TheHub #60942: the deployments endpoint and the briefing knew TheHub's
        and this platform's probes are derived (#60918); the console did not."""
        settings = client.app.state.settings  # type: ignore[attr-defined]
        settings.hub_api_url = "http://hub.invalid:8000"
        settings.hub_api_token = "t"
        settings.build_sha = "d" * 40
        hub_id = onboard(client, repo="example-org/TheHub")
        self_id = onboard(client, repo="example-org/mykronos")
        lib_id = onboard(client, repo="example-org/a-library")

        hub = client.get(f"{base(hub_id)}/delivery", headers=viewer_auth).json()["deployment"]
        own = client.get(f"{base(self_id)}/delivery", headers=viewer_auth).json()["deployment"]
        lib = client.get(f"{base(lib_id)}/delivery", headers=viewer_auth).json()["deployment"]

        assert hub["probe_source"] == deployments.SOURCE_HUB
        assert own["probe_source"] == deployments.SOURCE_SELF
        # Configured, and the sweep has not answered yet: not "not_configured".
        assert hub["probe_status"] == own["probe_status"] == "awaiting_first_answer"
        assert hub["missing"] == [] and own["missing"] == []
        # The lag is the one a configured probe gets, not omitted as for a library.
        assert hub["lag"] is not None and hub["lag"]["status"] == "unknown"
        # A repository with nothing to probe still says so, and says what it needs.
        assert lib["probe_source"] == ""
        assert lib["probe_status"] == "not_configured"
        assert lib["lag"] is None
        assert lib["missing"] and "deployment probe URL" in lib["missing"][0]

    def test_an_answered_derived_probe_keeps_its_stored_status(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
    ) -> None:
        settings = client.app.state.settings  # type: ignore[attr-defined]
        settings.build_sha = "e" * 40
        repo_id = onboard(client, repo="example-org/mykronos", deployed_revision="e" * 12)
        body = client.get(f"{base(repo_id)}/delivery", headers=viewer_auth).json()
        assert body["deployment"]["probe_status"] == "ok"
        assert body["deployment"]["probe_source"] == deployments.SOURCE_SELF

    def test_an_empty_lake_is_empty_and_says_nothing_failed(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        body = client.get(f"{base(repo_id)}/delivery", headers=viewer_auth).json()
        assert body["shipped"] == [] and body["not_shipped"] == []
        assert body["error"] is None


# --------------------------------------------------------------------------
# Approvals inbox
# --------------------------------------------------------------------------


def make_request(
    client: TestClient,
    *,
    repo: str = REPO,
    tier: str = "production",
    requested_by: str = "agent:author-1",
    requester_kind: str = "agent",
    created_at: Any = None,
) -> tuple[str, str]:
    evidence = {
        "subject_ref": f"{repo}#41@{'d' * 40}",
        "repo": repo,
        "number": 41,
        "title": "Tighten the parser",
        "head_sha": "d" * 40,
        "change_class": tier,
        "files": [],
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
            requested_by=requested_by,
            requester_kind=requester_kind,
            requester_provenance={"instance": "run-1"} if requester_kind == "agent" else {},
            state="pending",
            policy_version="test",
            created_at=created_at or now,
            expires_at=now + timedelta(days=7),
        )
        session.add(row)
        session.flush()
        return row.id, digest


class TestApprovalsInbox:
    def test_it_lists_this_repositorys_pending_requests_only(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        mine, digest = make_request(client)
        make_request(client, repo="example-org/other")
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                ApprovalRequest(
                    duty="delegation_grant",
                    tier="any",
                    subject_ref="dlg",
                    evidence={"proposal": {}},
                    evidence_digest="e" * 64,
                    requested_by="admin",
                    requester_kind="human",
                    state="pending",
                    expires_at=utcnow() + timedelta(days=1),
                )
            )
        body = client.get(f"{base(repo_id)}/approvals", headers=admin_auth).json()
        assert [item["id"] for item in body["pending"]] == [mine]
        item = body["pending"][0]
        assert item["evidence_digest"] == digest
        assert item["summary"] == "#41 Tighten the parser"
        assert "distinct_instance" in item["needs"]["independence"]
        assert body["estate_wide_pending"] == 1
        assert body["can_decide"] is True

    def test_a_decision_in_place_goes_through_the_engine(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        response = client.post(
            f"{base(repo_id)}/approvals/{request_id}/decision",
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "approved"
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            decisions = session.query(ApprovalDecision).filter_by(request_id=request_id).all()
            assert [(d.approver, d.verdict) for d in decisions] == [("admin", "approve")]
        # The engine's own audit entry, and the console's beside it.
        assert audit_entries(client, "approval.approve")
        [entry] = audit_entries(client, "po.approval_decision")
        assert entry.detail["outcome"] == "approved"
        assert entry.detail["repo_full_name"] == REPO

    def test_the_engines_refusal_is_shown_verbatim_and_audited(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        """The operator's own governance-tier request: the single-operator
        cooling-off applies, and the console does not get around it."""
        repo_id, _ = connect([])
        request_id, digest = make_request(
            client, tier="governance", requested_by="admin", requester_kind="human"
        )
        response = client.post(
            f"{base(repo_id)}/approvals/{request_id}/decision",
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=admin_auth,
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert detail.startswith(
            "Same-person approval under single_operator must wait for the 'governance' cooling-off"
        )
        [entry] = audit_entries(client, "po.approval_decision")
        assert entry.detail["outcome"] == "refused"
        assert entry.detail["engine_detail"] == detail
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.get(ApprovalRequest, request_id).state == "pending"

    def test_a_stale_digest_is_refused_by_the_engine(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, _ = make_request(client)
        response = client.post(
            f"{base(repo_id)}/approvals/{request_id}/decision",
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": "0" * 64},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "different evidence digest" in response.json()["detail"]

    def test_another_repositorys_request_cannot_be_decided_here(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client, repo="example-org/other")
        response = client.post(
            f"{base(repo_id)}/approvals/{request_id}/decision",
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=admin_auth,
        )
        assert response.status_code == 404
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.get(ApprovalRequest, request_id).state == "pending"

    def test_a_viewer_reads_the_inbox_and_cannot_decide(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        request_id, digest = make_request(client)
        body = client.get(f"{base(repo_id)}/approvals", headers=viewer_auth).json()
        assert body["can_decide"] is False and len(body["pending"]) == 1
        response = client.post(
            f"{base(repo_id)}/approvals/{request_id}/decision",
            json={"verdict": "approve", "rationale": RATIONALE, "evidence_digest": digest},
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert audit_entries(client, "po.approval_decision") == []


# --------------------------------------------------------------------------
# Roles & agents
# --------------------------------------------------------------------------


class TestRoles:
    def test_declared_gates_sit_beside_what_is_enforced(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([])
        now = utcnow()
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                Delegation(
                    granted_by="admin",
                    grant_request_id="g1",
                    duty="pull_request_merge",
                    tiers=["routine"],
                    approver_families=["claude-opus-5.5"],
                    expires_at=now + timedelta(days=30),
                )
            )
            session.add(
                Delegation(
                    granted_by="admin",
                    grant_request_id="g2",
                    duty="pull_request_merge",
                    tiers=["production"],
                    approver_families=["claude-opus-5.5"],
                    expires_at=now + timedelta(days=30),
                    revoked_at=now,
                )
            )
        body = client.get(f"{base(repo_id)}/roles", headers=viewer_auth).json()
        assert [g["approves"] for g in body["declared"]] == ["Delivery Lead", "Reviewer agent", ""]
        tiers = {(t["duty"], t["tier"]): t for t in body["enforced"]}
        assert tiers[("pull_request_merge", "routine")]["agent_now"] == "yes"
        # A revoked delegation is not one that exists.
        assert tiers[("pull_request_merge", "production")]["agent_now"] == "no_active_delegation"
        assert tiers[("pull_request_merge", "governance")]["agent_now"] == "humans_only"
        assert body["active_delegations"] == 1

    def test_no_manifest_declares_nothing(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([], manifest=None)
        body = client.get(f"{base(repo_id)}/roles", headers=viewer_auth).json()
        assert body["manifest_state"] == "absent"
        assert body["declared"] == []
        assert body["enforced"]


# --------------------------------------------------------------------------
# Retro
# --------------------------------------------------------------------------


def iso_ago(**delta: Any) -> str:
    return (utcnow() - timedelta(**delta)).isoformat()


class TestRetro:
    def test_it_lists_closed_stories_and_the_gates_they_failed(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, hub = connect(
            [
                story(
                    id=1,
                    bucket="done",
                    gate="verified",
                    closed_at=iso_ago(days=2),
                    created_at=iso_ago(days=6),
                    retrospective_md="went fine",
                ),
                story(
                    id=2,
                    bucket="done",
                    gate="verified",
                    closed_at=iso_ago(days=3),
                    created_at=iso_ago(days=5),
                    acceptance_criteria=[],
                ),
                story(id=3, bucket="done", gate="verified", closed_at=iso_ago(days=40)),
                story(id=4, bucket="done", tags=["repo:keel"], closed_at=iso_ago(days=1)),
                story(id=5, bucket="sprint", gate="in_progress", moved_at=iso_ago(days=30)),
            ]
        )
        hub.verification[1] = {"status": "rejected", "reason": "no test for the edge case"}
        hub.runs[2] = [
            {
                "id": 7,
                "status": "aborted_timeout",
                "dry_run": False,
                "started_at": iso_ago(days=4),
                "cost_usd": 0.4,
            },
            {
                "id": 8,
                "status": "dry_run",
                "dry_run": True,
                "started_at": iso_ago(days=4),
                "cost_usd": 0,
            },
        ]
        hub.deploys[2] = [
            {
                "id": 9,
                "deploy_id": "dep-9",
                "sha": "abc1234",
                "final_status": "failed",
                "started_at": iso_ago(days=3),
            }
        ]
        body = client.get(f"{base(repo_id)}/retro", headers=viewer_auth).json()
        assert body["closed"] == 2
        assert [s["id"] for s in body["stories"]] == [1, 2]
        kinds = {(f["story_id"], f["kind"], f["hub_gate"]) for f in body["failures"]}
        assert kinds == {
            (1, "verification_rejected", "tested"),
            (2, "run_aborted", "in_progress"),
            (2, "deploy_failed", "deployed"),
        }
        # The manifest's own name for the gate.
        gate_names = {f["hub_gate"]: f["gate_name"] for f in body["failures"]}
        assert gate_names["in_progress"] == "Building" and gate_names["tested"] == "Verify"
        assert body["failed_stories"] == 2
        assert body["no_acceptance_criteria"] == [2]
        assert body["no_retrospective_note"] == [2]
        assert body["carried_over"] == [5]
        assert body["dry_runs"] == 1 and body["shipped_runs"] == 0
        assert body["median_cycle_days"] == 3.0
        assert "2 stories closed in the last 14 days." in body["summary"]
        assert "latest verification block" in body["limitation"]

    def test_a_failed_read_marks_the_story_unread_not_clean(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, hub = connect(
            [story(id=1, bucket="done", gate="verified", closed_at=iso_ago(days=1))]
        )
        hub.failing.add("/api/dev/stories/1/notes")
        body = client.get(f"{base(repo_id)}/retro", headers=viewer_auth).json()
        assert body["unread"] == [1]
        assert body["stories"][0]["unread"] == ["notes"]
        assert any("could not be read" in line for line in body["summary"])

    def test_no_hub_says_not_connected_rather_than_zero(
        self, client: TestClient, viewer_auth: dict[str, str], github: Any
    ) -> None:
        repo_id = onboard(client)
        client.app.state.hub = None  # type: ignore[attr-defined]
        body = client.get(f"{base(repo_id)}/retro", headers=viewer_auth).json()
        assert body["hub"] == {"connected": False, "error": "TheHub is not connected."}
        assert body["closed"] is None
