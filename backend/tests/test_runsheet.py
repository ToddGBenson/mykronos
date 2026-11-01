"""The Today run sheet (TheHub #61141): the server computes what Start-Here
computes, read-only.

Each step's readiness reasons are pure functions of what was read, so they are
tested here against the cases Start-Here's own comments record: a request
pinned to an older head (#1049), a PR that merged while its request waited, a
Delivery that failed building the image (5f5cf6e), the backup window, a red
`unit` lane, and a gate that introduced blocking findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from mykronos import runsheet as rs
from mykronos.github.client import ChecksSummary

HEAD = "a" * 40
OLD = "b" * 40
MAIN = "c" * 40
RUNNING = "d" * 40
REPO = "acme/app"
NOON = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def pending(
    ref: str = f"{REPO}#7@{HEAD}",
    *,
    id: str = "r1",
    duty: str = "pull_request_merge",
    reviewed: bool | None = True,
) -> rs.PendingApproval:
    return rs.PendingApproval(id=id, duty=duty, tier="T2", subject_ref=ref, reviewed=reviewed)


def pr(**overrides: Any) -> rs.PullRequestState:
    base: dict[str, Any] = {
        "repo": REPO,
        "number": 7,
        "title": "Rate-limit the export route",
        "url": f"https://github.com/{REPO}/pull/7",
        "draft": False,
        "head_sha": HEAD,
        "base_branch": "main",
        "default_branch": "main",
        "mergeable": True,
        "mergeable_state": "clean",
        "checks": ChecksSummary(total=4, passed=4),
        "depends_on": [],
        "detail_read": True,
    }
    base.update(overrides)
    return rs.PullRequestState(**base)


# -- Decide ---------------------------------------------------------------------


def live(head: str = HEAD, *, open: bool = True, number: int = 7) -> rs.LiveHeads:
    """What the live single-PR read of the request's pull request found."""
    return {(REPO, number): rs.LiveHead(open=open, head_sha=head)}


class TestDecide:
    def test_a_reviewed_request_at_the_current_head_is_ready_for_you(self) -> None:
        step = rs.decide_step([pending()], live())
        assert step.state == rs.READY
        [item] = step.items
        assert item.state == rs.READY and item.owner == rs.OWNER_YOU
        assert item.ref == "r1"

    def test_a_request_pinned_to_an_older_head_is_hidden_as_superseded(self) -> None:
        step = rs.decide_step([pending(f"{REPO}#7@{OLD}")], live())
        assert step.items == []
        assert step.state == rs.DONE
        assert step.hidden == [
            f"{REPO}#7: its head moved to {HEAD[:7]}, so this request is superseded"
        ]

    def test_a_request_for_a_pull_request_no_longer_open_is_hidden(self) -> None:
        step = rs.decide_step([pending()], live(open=False))
        assert step.items == []
        assert step.hidden == [f"{REPO}#7: no longer open (merged or closed)"]

    def test_a_request_the_reviewer_has_not_posted_on_waits(self) -> None:
        step = rs.decide_step([pending(reviewed=False)], live())
        [item] = step.items
        assert item.state == rs.WAITING
        assert item.owner == rs.OWNER_REVIEWER
        assert "has not posted" in item.reason
        assert step.state == rs.WAITING

    def test_every_request_is_decidable_when_the_reviewer_is_not_in_shadow(self) -> None:
        step = rs.decide_step([pending(reviewed=None)], live())
        assert step.items[0].state == rs.READY

    def test_other_duties_are_never_checked_against_github(self) -> None:
        step = rs.decide_step([pending("acme/app:RA-1", duty="risk_acceptance")], {})
        assert [i.state for i in step.items] == [rs.READY]
        assert step.status == rs.OK

    def test_an_unread_pull_request_keeps_the_request_and_says_so(self) -> None:
        step = rs.decide_step([pending()], {(REPO, 7): "GitHub timed out."})
        assert [i.state for i in step.items] == [rs.READY]
        assert step.status == rs.PARTIAL
        assert f"{REPO}#7: GitHub timed out." in step.reason

    def test_an_abbreviated_sha_matches_the_full_head(self) -> None:
        step = rs.decide_step([pending(f"{REPO}#7@{HEAD[:7]}")], live())
        assert len(step.items) == 1

    def test_nothing_pending_is_done(self) -> None:
        step = rs.decide_step([], live())
        assert step.state == rs.DONE
        assert step.summary == "nothing waiting for your decision"


# -- Merge ----------------------------------------------------------------------


class TestMerge:
    def merge(self, prs: list[rs.PullRequestState] | None, **kw: Any) -> rs.Step:
        kw.setdefault("approved_refs", {f"{REPO}#7@{HEAD}"})
        kw.setdefault("pending_refs", set())
        kw.setdefault("requires_review", {REPO: True})
        return rs.merge_step(prs, **kw)

    def test_approved_at_head_and_green_is_ready(self) -> None:
        [item] = self.merge([pr()]).items
        assert item.state == rs.READY and item.owner == rs.OWNER_YOU
        assert item.reason == "approved at its head, 4/4 checks green"

    def test_not_approved_with_a_request_pending_is_blocked_on_step_one(self) -> None:
        [item] = self.merge(
            [pr()], approved_refs=set(), pending_refs={f"{REPO}#7@{HEAD}"}
        ).items
        assert item.state == rs.BLOCKED
        assert item.reason == "blocked until you decide it in step 1"
        assert item.owner == rs.OWNER_YOU

    def test_not_approved_and_no_request_at_its_head_waits_on_delivery(self) -> None:
        [item] = self.merge([pr()], approved_refs={f"{REPO}#7@{OLD}"}).items
        assert item.state == rs.WAITING
        assert item.reason == f"waiting on independent-review: no request at its head {HEAD[:7]}"
        assert item.owner == rs.OWNER_DELIVERY

    def test_a_repository_that_requires_no_review_needs_no_approval(self) -> None:
        [item] = self.merge([pr()], approved_refs=set(), requires_review={REPO: False}).items
        assert item.state == rs.READY
        assert item.reason == "4/4 checks green"

    def test_unknown_protection_is_read_as_requiring_review(self) -> None:
        [item] = self.merge([pr()], approved_refs=set(), requires_review={}).items
        assert item.state == rs.WAITING

    def test_behind_main_waits_on_an_agent(self) -> None:
        [item] = self.merge([pr(mergeable_state="behind")]).items
        assert item.state == rs.WAITING
        assert item.reason == "branch behind main, an agent must update it"
        assert item.owner == rs.OWNER_AGENT

    def test_a_conflict_or_red_checks_block(self) -> None:
        [conflict] = self.merge([pr(mergeable=False, mergeable_state="dirty")]).items
        assert conflict.state == rs.BLOCKED and conflict.reason == "conflicts with main"
        [red] = self.merge([pr(checks=ChecksSummary(total=4, passed=3, failed=1))]).items
        assert red.state == rs.BLOCKED and red.reason == "1 of 4 check(s) failed"

    def test_running_checks_wait(self) -> None:
        [item] = self.merge([pr(checks=ChecksSummary(total=4, passed=2, pending=2))]).items
        assert item.state == rs.WAITING and item.reason == "2 check(s) still running"

    def test_unread_checks_or_mergeable_are_unknown_never_ready(self) -> None:
        [a] = self.merge([pr(checks=None)]).items
        [b] = self.merge([pr(mergeable=None)]).items
        assert a.state == rs.UNKNOWN and b.state == rs.UNKNOWN

    def test_no_check_reported_yet_waits_on_ci_never_ready(self) -> None:
        # Start-Here skips a PR with no checks at all (`$checks.Count -eq 0`):
        # nothing has judged it yet, so it is not offered.
        [item] = self.merge([pr(checks=ChecksSummary(total=0))]).items
        assert item.state == rs.WAITING
        assert item.reason == "no check has reported on it yet"
        assert item.owner == rs.OWNER_CI

    def test_a_stacked_pull_request_waits(self) -> None:
        [item] = self.merge([pr(base_branch="feature")]).items
        assert item.state == rs.WAITING and item.reason == "stacked on feature; it merges after"

    def test_drafts_are_not_offered(self) -> None:
        step = self.merge([pr(draft=True)])
        assert step.items == []
        assert step.hidden == [
            f"{REPO}#7: a draft; Start-Here offers a draft only when its "
            "ready-drafts list names it"
        ]

    def test_order_is_by_repository_then_number_and_the_summary_counts(self) -> None:
        step = self.merge(
            [pr(number=9, head_sha=OLD), pr(), pr(repo="acme/b", number=1)],
            approved_refs={f"{REPO}#7@{HEAD}", f"{REPO}#9@{OLD}"},
            requires_review={REPO: True, "acme/b": False},
        )
        assert [(i.ref) for i in step.items] == ["acme/app#7", "acme/app#9", "acme/b#1"]
        assert step.state == rs.READY
        assert step.summary == "3 ready, 0 not yet"

    def test_an_unread_list_is_unavailable_not_empty(self) -> None:
        step = self.merge(None, prs_reason="no repository could be listed.")
        assert step.status == rs.UNAVAILABLE and step.state == rs.UNKNOWN
        assert step.reason == "no repository could be listed."


# -- Deploy ---------------------------------------------------------------------


def facts(**overrides: Any) -> rs.DeployFacts:
    base: dict[str, Any] = {
        "repo": "acme/platform",
        "running_sha": RUNNING,
        "main_sha": MAIN,
        "delivery": ("completed", "success"),
        "lanes": {"unit": "succeeded", "lint-and-types": "succeeded"},
        "decision": {"found": True, "introduced_blocking": False, "recommendation": "go"},
        "now": NOON,
    }
    base.update(overrides)
    return rs.DeployFacts(**base)


class TestDeploy:
    def test_everything_green_is_ready(self) -> None:
        step = rs.deploy_step(facts())
        assert step.state == rs.READY
        assert step.summary == f"deploy {MAIN[:7]}: production runs {RUNNING[:7]}"

    def test_production_on_main_is_done(self) -> None:
        assert rs.deploy_step(facts(running_sha=MAIN)).state == rs.DONE

    def test_the_backup_window_waits(self) -> None:
        step = rs.deploy_step(facts(now=datetime(2026, 11, 1, 3, 0, tzinfo=UTC)))
        assert step.state == rs.WAITING
        assert "backup window" in step.reason

    def test_a_failed_delivery_blocks_however_green_the_lanes(self) -> None:
        step = rs.deploy_step(facts(delivery=("completed", "failure")))
        assert step.state == rs.BLOCKED
        assert "Delivery concluded failure" in step.reason

    def test_a_red_or_unreadable_lane_blocks(self) -> None:
        red = rs.deploy_step(facts(lanes={"unit": "failed", "lint-and-types": "succeeded"}))
        assert red.state == rs.BLOCKED and "unit" in red.reason
        unread = rs.deploy_step(facts(lanes={"unit": None, "lint-and-types": "succeeded"}))
        assert unread.state == rs.BLOCKED

    def test_an_unfinished_delivery_waits(self) -> None:
        step = rs.deploy_step(facts(delivery=("in_progress", None)))
        assert step.state == rs.WAITING
        assert step.reason == "Delivery on main has not succeeded yet"

    def test_a_gate_that_introduced_blocking_findings_blocks(self) -> None:
        step = rs.deploy_step(
            facts(decision={"found": True, "introduced_blocking": True, "recommendation": "no_go"})
        )
        assert step.state == rs.BLOCKED and "introduced blocking findings" in step.reason

    def test_every_guard_is_listed_as_an_item(self) -> None:
        names = [i.text for i in rs.deploy_step(facts()).items]
        assert names == [
            "Delivery on main",
            "unit and lint-and-types lanes",
            "risk gate",
            "backup window",
        ]

    def test_unknown_shas_are_unknown(self) -> None:
        assert rs.deploy_step(facts(running_sha="")).state == rs.UNKNOWN
        assert rs.deploy_step(facts(main_sha="")).state == rs.UNKNOWN

    def test_host_only_guards_are_named_not_guessed(self) -> None:
        step = rs.deploy_step(facts())
        assert any("TheHub deploy lock" in n for n in step.notes)


# -- Tasks ----------------------------------------------------------------------


class TestTasks:
    def test_operator_actions_not_observed_done_are_tasks(self) -> None:
        from mykronos import operator_checks as oc

        stories = [
            {"id": 1, "title": "OPERATOR ACTION: protect the tags"},
            {"id": 2, "title": "OPERATOR ACTION: require backend-tests"},
            {"id": 3, "title": "Not an operator ask"},
        ]
        checks = {
            1: oc.Verification(oc.OBSERVED_DONE, evidence="tags are protected"),
            2: oc.Verification(oc.OBSERVED_NOT_DONE, evidence="not required yet"),
        }
        probe = oc.Probe(name="fake", repo="acme/app", check=None)  # type: ignore[arg-type]
        step = rs.tasks_step(stories, checks, registry={1: probe, 2: probe})
        assert [i.ref for i in step.items] == ["#2"]
        assert step.items[0].reason == "checked: not required yet"
        assert step.hidden == ["#1 is done on GitHub: close the story"]
        assert step.state == rs.READY

    def test_no_tasks_is_done(self) -> None:
        step = rs.tasks_step([], {})
        assert step.state == rs.DONE and step.summary == "nothing for you today"

    def test_an_unread_board_is_unavailable(self) -> None:
        step = rs.tasks_step(None, None, board_reason="TheHub is down.")
        assert step.status == rs.UNAVAILABLE and step.state == rs.UNKNOWN


# -- The route ------------------------------------------------------------------


def test_the_route_answers_with_every_step_even_when_nothing_can_be_read(
    client: TestClient, admin_auth: dict[str, str]
) -> None:
    from mykronos.db.models import ApprovalRequest

    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(
            ApprovalRequest(
                id="req-today",
                duty="risk_acceptance",
                tier="T3",
                subject_ref="acme/app:RA-9",
                state="pending",
            )
        )
        session.commit()

    response = client.get("/api/dashboard/today", headers=admin_auth)
    assert response.status_code == 200, response.text
    body = response.json()
    assert [s["key"] for s in body["steps"]] == ["decide", "merge", "deploy", "tasks"]
    decide = body["steps"][0]
    assert [i["ref"] for i in decide["items"]] == ["req-today"]
    for step in body["steps"]:
        assert step["state"] in rs.STATES
        if step["status"] != rs.OK:
            assert step["reason"]
