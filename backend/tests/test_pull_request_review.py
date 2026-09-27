"""Pull request review and merge as a governed duty (spec 34 §6.1).

The GitHub account is shared, so these tests are about what the platform does
instead: it reads the diff itself, computes the tier from the files, binds the
approval to one commit, and says who acted in the `independent-review` check.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select

from mykronos.approvals import pull_requests, reviewer
from mykronos.approvals.policy import cached_policy
from mykronos.db.models import ApprovalRequest, ApprovalStamp, Delegation
from mykronos.github.client import PullRequest, PullRequestFile
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_onboarding import onboard

SHA = "a" * 40
NEXT_SHA = "b" * 40


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _agent(client, admin_auth, family: str = "claude-opus-5.5") -> dict[str, str]:
    response = client.post("/api/agents/credentials", json={"family": family}, headers=admin_auth)
    assert response.status_code == 201, response.text
    return _bearer(response.json()["token"])


def _open_pr(github, paths: list[str], *, number: int = 7, sha: str = SHA, **kw: Any) -> None:
    repo = github.repos[REPO]
    repo.pull_requests = [p for p in repo.pull_requests if p.number != number]
    repo.pull_requests.append(
        PullRequest(
            number=number,
            url=f"https://github.test/{REPO}/pull/{number}",
            head_branch="feat/x",
            title="A change",
            head_sha=sha,
            changed_files=kw.pop("changed_files", len(paths)),
        )
    )
    repo.pull_request_files[number] = [
        PullRequestFile(
            filename=p, status="modified", additions=1, deletions=1, patch="@@ +x", **kw
        )
        for p in paths
    ]


def _request(client, auth, number: int = 7, statement: str = ""):
    return client.post(
        "/api/approvals/pull-requests",
        json={"repo": REPO, "number": number, "statement": statement},
        headers=auth,
    )


def _decide(client, auth, body: dict[str, Any], verdict: str = "approve"):
    return client.post(
        f"/api/approvals/{body['id']}/decisions",
        json={
            "verdict": verdict,
            "rationale": "Read the diff: the tests cover the new branch.",
            "evidence_digest": body["evidence_digest"],
        },
        headers=auth,
    )


def _checks(github, sha: str = SHA) -> list[dict[str, Any]]:
    return [
        c
        for c in github.repos[REPO].check_runs
        if c["head_sha"] == sha and c["name"] == pull_requests.CHECK_NAME
    ]


@pytest.fixture
def onboarded(client, admin_auth):
    onboard(client, admin_auth)


class TestTheChangeClassIsComputed:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("approval-policy-v1.yaml", "governance"),
            ("oracle-policy-v1.yaml", "governance"),
            (".github/workflows/ci.yml", "governance"),
            ("deploy/concourse/pipelines/mykronos.yml", "governance"),
            ("backend/mykronos/approvals/engine.py", "governance"),
            ("backend/mykronos/adminauth.py", "governance"),
            ("docs/DECISIONS.md", "routine"),
            ("README.md", "routine"),
            ("backend/tests/test_x.py", "routine"),
            ("frontend/app/page.test.tsx", "routine"),
            ("backend/mykronos/main.py", "production"),
            ("frontend/app/page.tsx", "production"),
            ("a-directory-nobody-named/x.py", "production"),
        ],
    )
    def test_each_path(self, client, path: str, expected: str) -> None:
        duty = cached_policy(client.app.state.settings.approval_policy_path).duty(
            pull_requests.DUTY
        )
        assert pull_requests.classify_path(duty, path) == expected

    def test_moving_a_governance_file_out_is_still_governance(self, client) -> None:
        duty = cached_policy(client.app.state.settings.approval_policy_path).duty(
            pull_requests.DUTY
        )
        assert (
            pull_requests.classify_file(duty, "docs/old-policy.md", "approval-policy-v1.yaml")
            == "governance"
        )

    def test_the_pr_takes_its_strictest_file(
        self, client, admin_auth, github, onboarded
    ) -> None:
        _open_pr(github, ["docs/a.md", "backend/mykronos/main.py"])

        body = _request(client, _agent(client, admin_auth)).json()

        assert body["tier"] == "production"

    def test_a_truncated_listing_is_classed_as_the_strictest(
        self, client, admin_auth, github, onboarded
    ) -> None:
        _open_pr(github, ["docs/a.md"], changed_files=3001)

        body = _request(client, _agent(client, admin_auth)).json()

        assert body["tier"] == "governance"


class TestTheEvidenceIsThePlatforms:
    def test_the_generic_route_refuses_the_duty(self, client, admin_auth, onboarded) -> None:
        response = client.post(
            "/api/approvals",
            json={
                "duty": pull_requests.DUTY,
                "subject_ref": f"{REPO}#7@{SHA}",
                "context": {
                    "snapshot": {"subject_ref": f"{REPO}#7@{SHA}", "change_class": "routine"}
                },
            },
            headers=admin_auth,
        )

        assert response.status_code == 409
        assert pull_requests.ROUTE in response.json()["detail"]

    def test_the_bundle_is_read_from_github(self, client, admin_auth, github, onboarded) -> None:
        _open_pr(github, ["docs/a.md"])

        body = _request(client, _agent(client, admin_auth), statement="Docs only.").json()
        evidence = client.get(f"/api/approvals/{body['id']}/evidence", headers=admin_auth).json()

        assert body["subject_ref"] == f"{REPO}#7@{SHA}"
        assert evidence["evidence"]["files"][0]["path"] == "docs/a.md"
        assert evidence["evidence"]["files"][0]["patch"] == "@@ +x"
        assert evidence["requester_statement"] == "Docs only."

    def test_a_merged_pull_request_is_refused(self, client, admin_auth, github, onboarded):
        _open_pr(github, ["docs/a.md"])
        github.repos[REPO].pull_requests[-1].merged = True

        assert _request(client, _agent(client, admin_auth)).status_code == 409

    def test_one_request_per_commit(self, client, admin_auth, github, onboarded) -> None:
        agent = _agent(client, admin_auth)
        _open_pr(github, ["docs/a.md"])
        assert _request(client, agent).status_code == 201

        again = _request(client, agent)

        assert again.status_code == 409
        assert "already has approval request" in again.json()["detail"]


class TestTheCheckRun:
    def test_a_request_posts_it_in_progress(self, client, admin_auth, github, onboarded):
        _open_pr(github, ["docs/a.md"])

        _request(client, _agent(client, admin_auth))

        [check] = _checks(github)
        assert check["conclusion"] is None
        assert "Waiting for an independent approval" in check["title"]
        assert "agent:claude-opus-5.5:" in check["summary"]

    def test_an_approval_turns_it_green_and_names_both_sides(
        self, client, admin_auth, github, onboarded
    ) -> None:
        _open_pr(github, ["backend/mykronos/approvals/engine.py"])
        body = _request(client, _agent(client, admin_auth)).json()
        assert body["tier"] == "governance"

        response = _decide(client, admin_auth, body)

        assert response.json()["state"] == "approved", response.text
        latest = _checks(github)[-1]
        assert latest["conclusion"] == "success"
        assert "**Requested by** `agent:claude-opus-5.5:" in latest["summary"]
        assert "**approve** by `admin` (human)" in latest["summary"]

    def test_a_rejection_fails_it(self, client, admin_auth, github, onboarded) -> None:
        _open_pr(github, ["docs/a.md"])
        body = _request(client, _agent(client, admin_auth)).json()

        _decide(client, admin_auth, body, verdict="reject")

        assert _checks(github)[-1]["conclusion"] == "failure"

    def test_the_approval_is_of_one_commit(self, client, admin_auth, github, onboarded) -> None:
        agent = _agent(client, admin_auth)
        _open_pr(github, ["docs/a.md"])
        _decide(client, admin_auth, _request(client, agent).json())

        _open_pr(github, ["docs/a.md"], sha=NEXT_SHA)  # a new push
        second = _request(client, agent)

        assert second.status_code == 201, second.text
        assert _checks(github, SHA)[-1]["conclusion"] == "success"
        assert [c["conclusion"] for c in _checks(github, NEXT_SHA)] == [None]

    def test_a_failed_post_keeps_the_decision_and_is_retried(
        self, client, admin_auth, github, onboarded
    ) -> None:
        _open_pr(github, ["docs/a.md"])
        body = _request(client, _agent(client, admin_auth)).json()
        github.permissions["checks"] = "read"

        response = _decide(client, admin_auth, body)

        assert response.json()["state"] == "approved"
        with client.app.state.db.session() as session:
            failed = session.execute(
                select(ApprovalStamp).where(ApprovalStamp.error.is_not(None))
            ).scalar_one()
            assert "checks" in failed.error
        github.permissions["checks"] = "write"
        policy = cached_policy(client.app.state.settings.approval_policy_path)

        posted = asyncio.run(
            pull_requests.publish_due(
                client.app.state.db, policy, client.app.state.github_factory
            )
        )

        assert posted == 1
        assert _checks(github)[-1]["conclusion"] == "success"

    def test_an_expired_request_fails_it(self, client, admin_auth, github, onboarded) -> None:
        _open_pr(github, ["docs/a.md"])
        body = _request(client, _agent(client, admin_auth)).json()
        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, body["id"])
            row.expires_at = row.created_at - timedelta(seconds=1)
        policy = cached_policy(client.app.state.settings.approval_policy_path)

        asyncio.run(
            pull_requests.publish_due(client.app.state.db, policy, client.app.state.github_factory)
        )

        assert _checks(github)[-1]["conclusion"] == "failure"
        chain = client.get(f"/api/approvals/{body['id']}/chain", headers=admin_auth).json()
        assert chain["ok"] and chain["events"][-1]["event"] == "expired"


class TestTheIndependentReviewer:
    def test_a_delegated_reviewer_can_approve_a_routine_change(
        self, client, admin_auth, github, onboarded, monkeypatch
    ) -> None:
        with client.app.state.db.session() as session:
            session.add(
                Delegation(
                    granted_by="operator",
                    grant_request_id="test",
                    duty=pull_requests.DUTY,
                    tiers=["routine"],
                    approver_families=["claude-opus-5"],
                    sampling=0.0,
                    expires_at=utcnow() + timedelta(days=1),
                )
            )
        answer = {
            "verdict": "approve",
            "rationale": "Documentation only; no executable change.",
            "checks": [],
        }
        seen: list[dict[str, Any]] = []

        def create(**kwargs: Any) -> Any:
            seen.append(kwargs)
            response = SimpleNamespace(
                stop_reason="end_turn",
                content=[SimpleNamespace(type="text", text=json.dumps(answer))],
                model=kwargs["model"],
            )
            response._request_id = "req_pr"
            return response

        fake = SimpleNamespace(messages=SimpleNamespace(create=create))
        monkeypatch.setattr(client.app.state.settings, "reviewer_api_key", "test-key")
        monkeypatch.setattr(reviewer.anthropic, "Anthropic", lambda api_key: fake)
        agent = _agent(client, admin_auth)
        _open_pr(github, ["docs/a.md"])
        body = _request(client, agent).json()

        response = client.post(f"/api/approvals/{body['id']}/independent-review", headers=agent)

        assert response.json()["state"] == "approved", response.text
        assert "This is a request to merge a pull request" in seen[0]["system"]
        assert '"path": "docs/a.md"' in seen[0]["messages"][0]["content"]
        latest = _checks(github)[-1]
        assert latest["conclusion"] == "success"
        assert "platform-started" in latest["summary"]
        assert "model `claude-opus-5`" in latest["summary"]


class TestRequestsNobodyMade:
    """The job opens a request for a head nobody asked about, after a grace
    period in which an agent author can ask under its own name."""

    @pytest.fixture
    def required(self, github):
        github.repos[REPO].branch_protection["main"] = {
            "required_status_checks": {"checks": [{"context": pull_requests.CHECK_NAME}]}
        }
        pull_requests._first_seen.clear()

    def _run(self, client, now):
        policy = cached_policy(client.app.state.settings.approval_policy_path)
        return asyncio.run(
            pull_requests.request_missing(
                client.app.state.db, policy, client.app.state.github_factory, now=now
            )
        )

    def test_it_waits_out_the_grace_period_then_asks(
        self, client, admin_auth, github, onboarded, required
    ) -> None:
        _open_pr(github, ["docs/a.md"])
        start = utcnow()

        assert self._run(client, start) == []
        assert self._run(client, start + timedelta(minutes=9)) == []
        [opened] = self._run(client, start + timedelta(minutes=11))

        with client.app.state.db.session() as session:
            row = session.get(ApprovalRequest, opened)
            assert row.requester_kind == "automation"
            assert row.requested_by == "job:pull-request-requests"
            assert row.tier == "routine"
        assert _checks(github)[-1]["conclusion"] is None

    def test_an_agent_that_asked_first_is_the_requester(
        self, client, admin_auth, github, onboarded, required
    ) -> None:
        _open_pr(github, ["docs/a.md"])
        start = utcnow()
        self._run(client, start)
        _request(client, _agent(client, admin_auth))

        assert self._run(client, start + timedelta(minutes=11)) == []

    def test_only_where_the_check_is_required(
        self, client, admin_auth, github, onboarded
    ) -> None:
        pull_requests._first_seen.clear()
        _open_pr(github, ["docs/a.md"])
        start = utcnow()
        self._run(client, start)

        assert self._run(client, start + timedelta(minutes=11)) == []

    def test_drafts_are_left_alone(self, client, admin_auth, github, onboarded, required):
        _open_pr(github, ["docs/a.md"])
        github.repos[REPO].pull_requests[-1].draft = True
        start = utcnow()
        self._run(client, start)

        assert self._run(client, start + timedelta(minutes=11)) == []

    def test_an_agent_author_cannot_approve_what_the_platform_asked(
        self, client, admin_auth, github, onboarded, required
    ) -> None:
        """The reason an automation requester is safe: agent tiers need
        fresh_context, which only a platform-started reviewer has."""
        with client.app.state.db.session() as session:
            session.add(
                Delegation(
                    granted_by="operator",
                    grant_request_id="test",
                    duty=pull_requests.DUTY,
                    tiers=["routine"],
                    approver_families=["claude-opus-5.5"],
                    sampling=0.0,
                    expires_at=utcnow() + timedelta(days=1),
                )
            )
        _open_pr(github, ["docs/a.md"])
        start = utcnow()
        self._run(client, start)
        [opened] = self._run(client, start + timedelta(minutes=11))
        body = client.get(f"/api/approvals/{opened}", headers=admin_auth).json()

        response = _decide(client, _agent(client, admin_auth), body)

        assert response.status_code == 409
        assert "fresh_context" in response.json()["detail"]
