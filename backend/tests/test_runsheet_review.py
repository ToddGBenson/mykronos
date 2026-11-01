"""The run sheet's independent-review findings (TheHub #61141, PR #1068).

Each test here is one finding, read through the code that runs rather than a
hand-built dict:

* the risk gate's blocking floor comes from what the commit introduced, as
  `/decisions/by-commit` computes it, and an override does not clear it
  (Start-Here reads `introduced_blocking` from that route);
* Decide checks each pull-request request against a live read of its pull
  request, never the five-minute listing cache, and never hides a request
  whose pull request it could not read;
* Merge applies Start-Here's per-repository rules: keel and binnacle need
  the self-review record, TheHub merges only at an approved head, drafts are
  named, and the host-only deploy lock is named;
* the approved requests read are bounded to the open pull requests' heads;
* an unread Concourse lane says it was not read, not that it is red.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import delivery_sources
from mykronos import runsheet as rs
from mykronos.db.models import ApprovalRequest, Organization, RepoOnboarding
from mykronos.github.client import (
    ChecksSummary,
    CommitInfo,
    FakeGitHubClient,
    PullRequest,
    PullRequestFile,
)
from mykronos.schemas import utcnow
from tests.conftest import (
    INSTALLATION,
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)

NOON = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
NEW = "e" * 40
HEAD = "a" * 40
OLD = "b" * 40


def onboard(client: TestClient, repo: str = REPO) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        owner = repo.split("/")[0]
        org = session.query(Organization).filter_by(github_org_login=owner).one_or_none()
        if org is None:
            org = Organization(github_org_login=owner)
            session.add(org)
            session.flush()
        session.add(
            RepoOnboarding(
                org_id=org.id,
                github_repo_full_name=repo,
                github_installation_id=INSTALLATION,
                status="active",
                enabled_capabilities=["sast"],
                default_branch="main",
            )
        )
        session.commit()


@pytest.fixture(autouse=True)
def _fresh_caches() -> Any:
    delivery_sources.clear_cache()
    yield
    delivery_sources.clear_cache()


# -- High: the risk gate's floor ------------------------------------------------


def _gate_refuses(client: TestClient, run_compaction: Any) -> str:
    """A commit that introduced a high, judged by the commit gate: the case
    #735 records, where the recommendation is not `no_go` but the floor is."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}
    post_scan(client, auth, scan_run_id="run-new", commit_sha=NEW)
    post_findings(
        client, auth, [finding_payload(rule_id="R1", severity="high")], scan_run_id="run-new"
    )
    run_compaction()
    body = client.post(
        "/api/oracle/evaluate",
        json={"commit_sha": NEW, "decision_type": "commit_gate"},
        headers=auth,
    ).json()
    run_compaction()
    return str(body["decision_id"])


def _facts(client: TestClient, github: FakeGitHubClient, monkeypatch: Any) -> rs.DeployFacts:
    monkeypatch.setattr(rs, "DEPLOY_REPO", REPO)
    onboard(client)
    github.repos[REPO].commits = [CommitInfo(sha=NEW, message="main")]
    github.repos[REPO].commit_runs = {(rs.DELIVERY_WORKFLOW, NEW): ("completed", "success")}
    return asyncio.run(rs._deploy_facts(client.app.state, NOON))  # type: ignore[attr-defined]


def _green(facts: rs.DeployFacts) -> rs.DeployFacts:
    # Concourse is not configured in tests: everything but the gate made green.
    return replace(facts, lanes={n: "succeeded" for n in rs.DEPLOY_LANES}, running_sha="d" * 40)


class TestRiskGateFloor:
    def test_a_commit_that_introduced_a_high_blocks_the_deploy(
        self, client: TestClient, github: FakeGitHubClient, run_compaction: Any, monkeypatch: Any
    ) -> None:
        _gate_refuses(client, run_compaction)
        facts = _facts(client, github, monkeypatch)
        assert facts.decision is not None
        assert facts.decision["introduced_blocking"] is True
        step = rs.deploy_step(_green(facts))
        assert step.state == rs.BLOCKED
        assert "introduced blocking findings" in step.reason

    def test_an_override_does_not_clear_the_floor_start_here_reads(
        self,
        client: TestClient,
        github: FakeGitHubClient,
        run_compaction: Any,
        monkeypatch: Any,
        admin_auth: dict[str, str],
    ) -> None:
        # Start-Here stops on `introduced_blocking` whatever the override says;
        # only its own -Force list (on the host) gets past it.
        decision_id = _gate_refuses(client, run_compaction)
        response = client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "a vendored fixture", "accepted_recommendation": "go"},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()
        facts = _facts(client, github, monkeypatch)
        assert facts.decision is not None
        assert facts.decision["introduced_blocking"] is True
        assert rs.deploy_step(_green(facts)).state == rs.BLOCKED


# -- Medium: Decide reads each request's pull request live ----------------------


def _pending(client: TestClient, ref: str, id: str = "req-1") -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(
            ApprovalRequest(
                id=id, duty="pull_request_merge", tier="T2", subject_ref=ref, state="pending"
            )
        )
        session.commit()


def _stale_listing(client: TestClient, prs: list[delivery_sources.OpenPullRequest]) -> None:
    """The five-minute listing cache, holding an answer from before the push."""
    delivery_sources._pr_cache.put(
        client.app.state.github_factory,  # type: ignore[attr-defined]
        delivery_sources.PullRequestRead(pull_requests=prs, unreachable=[], as_of=utcnow()),
        time.monotonic(),
    )


def _listed(number: int, head: str) -> delivery_sources.OpenPullRequest:
    return delivery_sources.OpenPullRequest(
        repo_full_name=REPO,
        number=number,
        url="",
        title="t",
        draft=False,
        head_branch="b",
        base_branch="main",
        default_branch="main",
        opened_at=None,
        checks=ChecksSummary(total=1, passed=1),
        head_sha=head,
        detail_read=True,
    )


def _decide(client: TestClient) -> rs.Step:
    steps = asyncio.run(rs.gather(client.app.state, NOON))  # type: ignore[attr-defined]
    return next(s for s in steps if s.key == "decide")


class TestDecideReadsLive:
    def test_a_request_made_right_after_a_push_is_not_hidden_by_the_cache(
        self, client: TestClient, github: FakeGitHubClient
    ) -> None:
        onboard(client)
        github.repos[REPO].pull_requests.append(
            PullRequest(number=7, url="", head_branch="b", head_sha=HEAD, base_branch="main")
        )
        _stale_listing(client, [_listed(7, OLD)])
        _pending(client, f"{REPO}#7@{HEAD}")
        step = _decide(client)
        assert [i.ref for i in step.items] == ["req-1"], step.hidden
        assert step.hidden == []

    def test_a_pull_request_newer_than_the_cache_is_checked_not_hidden(
        self, client: TestClient, github: FakeGitHubClient
    ) -> None:
        onboard(client)
        github.repos[REPO].pull_requests.append(
            PullRequest(number=8, url="", head_branch="b", head_sha=HEAD, base_branch="main")
        )
        _stale_listing(client, [])
        _pending(client, f"{REPO}#8@{HEAD}")
        step = _decide(client)
        assert [i.ref for i in step.items] == ["req-1"], step.hidden

    def test_a_live_read_still_hides_a_superseded_or_merged_request(
        self, client: TestClient, github: FakeGitHubClient
    ) -> None:
        onboard(client)
        github.repos[REPO].pull_requests.extend(
            [
                PullRequest(number=7, url="", head_branch="b", head_sha=HEAD, base_branch="main"),
                PullRequest(
                    number=9, url="", head_branch="c", head_sha=OLD, state="closed", merged=True
                ),
            ]
        )
        _pending(client, f"{REPO}#7@{OLD}", id="req-old")
        _pending(client, f"{REPO}#9@{OLD}", id="req-merged")
        step = _decide(client)
        assert step.items == []
        assert sorted(step.hidden) == [
            f"{REPO}#7: its head moved to {HEAD[:7]}, so this request is superseded",
            f"{REPO}#9: no longer open (merged or closed)",
        ]

    def test_a_request_on_a_repository_not_onboarded_stays_and_says_why(
        self, client: TestClient
    ) -> None:
        _pending(client, "other/repo#3@" + HEAD)
        step = _decide(client)
        assert [i.ref for i in step.items] == ["req-1"]
        assert step.hidden == []
        assert step.status == rs.PARTIAL
        assert "other/repo#3" in step.reason


# -- Medium: Merge follows Start-Here's per-repository rules --------------------


def pr(**overrides: Any) -> rs.PullRequestState:
    base: dict[str, Any] = {
        "repo": REPO,
        "number": 7,
        "title": "t",
        "url": "",
        "draft": False,
        "head_sha": HEAD,
        "base_branch": "main",
        "default_branch": "main",
        "mergeable": True,
        "mergeable_state": "clean",
        "checks": ChecksSummary(total=4, passed=4),
    }
    base.update(overrides)
    return rs.PullRequestState(**base)


HUB = "acme/TheHub"
KEEL = "acme/keel"


def merge(prs: list[rs.PullRequestState], **kw: Any) -> rs.Step:
    kw.setdefault("approved_refs", set())
    kw.setdefault("pending_refs", set())
    kw.setdefault("requires_review", {REPO: False, HUB: False, KEEL: False})
    kw.setdefault("required_checks", {REPO: frozenset(), HUB: frozenset(), KEEL: frozenset()})
    kw.setdefault("approval_repos", {HUB})
    kw.setdefault("self_review_repos", {KEEL})
    return rs.merge_step(prs, **kw)


class TestMergeRules:
    def test_keel_needs_the_self_review_record(self) -> None:
        [item] = merge([pr(repo=KEEL, has_self_review=False)]).items
        assert item.state == rs.WAITING
        assert item.reason == "needs your self-review record (self-review.md)"
        assert item.owner == rs.OWNER_YOU
        [ok] = merge([pr(repo=KEEL, has_self_review=True)]).items
        assert ok.state == rs.READY

    def test_an_unread_file_list_is_unknown_on_keel_never_ready(self) -> None:
        [item] = merge([pr(repo=KEEL, has_self_review=None)]).items
        assert item.state == rs.UNKNOWN

    def test_thehub_waits_without_an_approval_at_its_head_however_green(self) -> None:
        [item] = merge([pr(repo=HUB)], approved_refs={f"{HUB}#7@{OLD}"}).items
        assert item.state == rs.WAITING
        assert item.reason == f"not approved at its head {HEAD[:7]}: it waits for the next batch"

    def test_thehub_approved_at_its_head_ignores_advisory_red(self) -> None:
        # develop requires no check; Start-Here merges on the approval alone.
        [item] = merge(
            [pr(repo=HUB, checks=ChecksSummary(total=3, passed=2, failed=1))],
            approved_refs={f"{HUB}#7@{HEAD}"},
        ).items
        assert item.state == rs.READY
        assert "1 advisory check(s) red" in item.reason

    def test_thehub_with_a_required_check_failing_is_blocked(self) -> None:
        [item] = merge(
            [pr(repo=HUB, checks=ChecksSummary(total=3, passed=2, failed=1))],
            approved_refs={f"{HUB}#7@{HEAD}"},
            required_checks={HUB: frozenset({"unit"})},
        ).items
        assert item.state == rs.BLOCKED

    def test_thehub_names_the_batch_list_it_cannot_see(self) -> None:
        step = merge([pr(repo=HUB)], approved_refs={f"{HUB}#7@{HEAD}"})
        assert any("batch" in n for n in step.notes)

    def test_drafts_are_named_so_a_ready_draft_can_be_matched(self) -> None:
        step = merge([pr(draft=True, number=1046)])
        assert step.items == []
        assert step.hidden == [
            f"{REPO}#1046: a draft; Start-Here offers a draft only when its "
            "ready-drafts list names it"
        ]

    def test_the_deploy_lock_is_named_on_merge(self) -> None:
        step = merge([pr()])
        assert any("TheHub deploy" in n and "lock" in n for n in step.notes)


# -- Low: the approvals read is bounded -----------------------------------------


def test_only_approvals_at_an_open_pull_requests_head_are_read(client: TestClient) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        for i in range(5):
            session.add(
                ApprovalRequest(
                    id=f"old-{i}",
                    duty="pull_request_merge",
                    tier="T2",
                    subject_ref=f"{REPO}#{100 + i}@{OLD}",
                    state="approved",
                )
            )
        session.add(
            ApprovalRequest(
                id="now",
                duty="pull_request_merge",
                tier="T2",
                subject_ref=f"{REPO}#7@{HEAD}",
                state="approved",
            )
        )
        session.commit()
    _, approved, _ = rs._approvals(
        client.app.state.db,  # type: ignore[attr-defined]
        "off",
        {f"{REPO}#7@{HEAD}"},
    )
    assert approved == {f"{REPO}#7@{HEAD}"}


# -- Note: an unread lane is not a red lane -------------------------------------


def test_an_unread_lane_says_it_was_not_read() -> None:
    facts = rs.DeployFacts(
        repo=REPO,
        running_sha="d" * 40,
        main_sha="c" * 40,
        delivery=("completed", "success"),
        lanes={"unit": None, "lint-and-types": "succeeded"},
        decision={"found": True, "introduced_blocking": False, "recommendation": "go"},
        now=NOON,
    )
    step = rs.deploy_step(facts)
    # Start-Here counts an unread lane as not green, so it still blocks.
    assert step.state == rs.BLOCKED
    lanes = next(i for i in step.items if i.text.endswith("lanes"))
    assert "unread" not in lanes.reason
    assert "unit could not be read" in lanes.reason
