"""GitHub `workflow_run` chains: a lane skipped behind a red upstream (#504).

`demo-and-dast.yml` runs after `Delivery` and only when Delivery succeeded.
With Delivery red on every commit from 2026-09-18, every Demo and DAST run was
`skipped` -- and the briefing reported `dast` as "2 consecutive failures" from
before the skips began and told somebody to re-scan it. These hold the three
answers apart: blocked behind a named upstream, skipped by its own condition,
and failing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mykronos import briefing
from mykronos.ci import (
    ActionsClient,
    WorkflowRunTrigger,
    reconcile,
    workflow_run_blocks,
    workflow_run_trigger,
)
from mykronos.github.client import FakeGitHubClient, WorkflowRef, WorkflowRun
from mykronos.schemas import utcnow as _utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan

DELIVERY = """\
name: Delivery
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps: [{run: make}]
"""

DEMO_AND_DAST = """\
name: Demo and DAST
on:
  workflow_run:
    workflows: ["Delivery"]
    types: [completed]
    branches: [main]
  workflow_dispatch:
jobs:
  dast:
    if: >-
      github.event_name == 'workflow_dispatch' ||
      github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps: [{run: zap}]
"""

#: The third link: a lane that runs after Demo and DAST.
AFTER_DAST = """\
name: After DAST
on:
  workflow_run:
    workflows: [Demo and DAST]
    types: [completed]
jobs:
  report:
    if: github.event.workflow_run.conclusion == 'success'
    runs-on: ubuntu-latest
    steps: [{run: report}]
"""

WHEN = datetime(2026, 9, 18, 7, 29, tzinfo=UTC)


def _ref(file_name: str, name: str, state: str = "active") -> WorkflowRef:
    return WorkflowRef(
        file_name=file_name,
        name=name,
        state=state,
        url=f"https://github.com/{REPO}/actions/workflows/{file_name}",
    )


def _run(file_name: str, conclusion: str | None, *, branch: str | None = "main") -> WorkflowRun:
    return WorkflowRun(
        workflow_file=file_name,
        conclusion=conclusion,
        run_number=7,
        url=f"https://github.com/{REPO}/actions/runs/{abs(hash(file_name)) % 10_000}",
        finished_at=WHEN,
        head_branch=branch,
    )


WORKFLOWS = [
    _ref("delivery.yml", "Delivery"),
    _ref("demo-and-dast.yml", "Demo and DAST"),
    _ref("after-dast.yml", "After DAST"),
]
TRIGGERS = {
    "demo-and-dast.yml": WorkflowRunTrigger(
        workflows=("Delivery",), types=("completed",), branches=("main",)
    ),
    "after-dast.yml": WorkflowRunTrigger(workflows=("Demo and DAST",), types=("completed",)),
}


class TestParsingTheTrigger:
    def test_the_upstream_types_and_branches_are_read(self) -> None:
        """`on:` is the boolean `True` to PyYAML, which is every real file."""
        assert workflow_run_trigger(DEMO_AND_DAST) == WorkflowRunTrigger(
            workflows=("Delivery",), types=("completed",), branches=("main",)
        )

    def test_a_workflow_with_no_workflow_run_has_no_trigger(self) -> None:
        assert workflow_run_trigger(DELIVERY) is None
        assert workflow_run_trigger("on: [push, workflow_run]\n") is None
        assert workflow_run_trigger("") is None
        assert workflow_run_trigger(None) is None

    def test_a_file_that_does_not_parse_is_not_a_crash(self) -> None:
        assert workflow_run_trigger("on: [unclosed\n") is None

    def test_a_single_upstream_may_be_a_string(self) -> None:
        trigger = workflow_run_trigger(
            "on:\n  workflow_run:\n    workflows: Delivery\n    branches-ignore: ['dep/**']\n"
        )
        assert trigger is not None
        assert trigger.workflows == ("Delivery",)
        assert trigger.accepts_branch("main") is True
        assert trigger.accepts_branch("dep/bump/x") is False
        assert trigger.accepts_branch(None) is None

    def test_branch_globs_follow_github(self) -> None:
        trigger = WorkflowRunTrigger(workflows=("X",), branches=("releases/*", "!releases/old"))
        assert trigger.accepts_branch("releases/v2") is True
        assert trigger.accepts_branch("releases/old") is False
        assert trigger.accepts_branch("releases/v2/hotfix") is False
        assert trigger.accepts_branch("main") is False


class TestClassification:
    def test_upstream_red_blocks_the_downstream_and_names_it(self) -> None:
        runs = {
            "delivery.yml": _run("delivery.yml", "failure"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
        }

        blocks = workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

        block = blocks["demo-and-dast.yml"]
        assert block.blocked_by == block.root == "Delivery"
        assert block.root_state == "failed"
        assert block.root_since == WHEN
        assert block.root_url == runs["delivery.yml"].url

    def test_upstream_green_and_downstream_skipped_is_not_blocked(self) -> None:
        """Its own `if:` declined to run it. Not blocked, and not failing."""
        runs = {
            "delivery.yml": _run("delivery.yml", "success"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
        }

        assert "demo-and-dast.yml" not in workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

    def test_a_downstream_that_ran_is_not_blocked_whatever_its_upstream(self) -> None:
        runs = {
            "delivery.yml": _run("delivery.yml", "failure"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "failure"),
        }

        assert "demo-and-dast.yml" not in workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

    def test_a_chain_of_three_names_the_root(self) -> None:
        runs = {
            "delivery.yml": _run("delivery.yml", "failure"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
            "after-dast.yml": _run("after-dast.yml", "skipped"),
        }

        blocks = workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

        assert blocks["after-dast.yml"].blocked_by == "Demo and DAST"
        assert blocks["after-dast.yml"].root == "Delivery"
        assert blocks["after-dast.yml"].root_state == "failed"
        assert blocks["demo-and-dast.yml"].root == "Delivery"

    def test_a_chain_stops_at_a_link_skipped_by_its_own_condition(self) -> None:
        runs = {
            "delivery.yml": _run("delivery.yml", "success"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
            "after-dast.yml": _run("after-dast.yml", "skipped"),
        }

        blocks = workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

        assert "demo-and-dast.yml" not in blocks
        assert blocks["after-dast.yml"].root == "Demo and DAST"
        assert blocks["after-dast.yml"].root_state == "skipped"

    def test_an_upstream_with_no_run_or_switched_off_blocks(self) -> None:
        runs = {"demo-and-dast.yml": _run("demo-and-dast.yml", "skipped")}
        assert workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)[
            "demo-and-dast.yml"
        ].root_state == "not_run"

        off = [_ref("delivery.yml", "Delivery", state="disabled_manually"), *WORKFLOWS[1:]]
        runs["delivery.yml"] = _run("delivery.yml", "success")
        assert workflow_run_blocks(off, runs, TRIGGERS)[
            "demo-and-dast.yml"
        ].root_state == "disabled"

    def test_an_upstream_run_on_a_filtered_out_branch_explains_nothing(self) -> None:
        runs = {
            "delivery.yml": _run("delivery.yml", "failure", branch="feature/x"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
        }

        assert "demo-and-dast.yml" not in workflow_run_blocks(WORKFLOWS, runs, TRIGGERS)

    def test_an_upstream_name_that_matches_nothing_is_not_guessed_at(self) -> None:
        triggers = {"demo-and-dast.yml": WorkflowRunTrigger(workflows=("Nonesuch",))}
        runs = {"demo-and-dast.yml": _run("demo-and-dast.yml", "skipped")}

        assert workflow_run_blocks(WORKFLOWS, runs, triggers) == {}


#: The fake names a workflow after its file where GitHub uses its `name:`, so
#: the trigger names the upstream by its stem, one of the keys either matches.
FAKE_DEMO_AND_DAST = DEMO_AND_DAST.replace('"Delivery"', "delivery")


def _actions(runs: dict[str, WorkflowRun], *, extra: dict[str, str] | None = None):
    github = FakeGitHubClient()
    repo = github.add_repo(
        REPO,
        files={
            ".github/workflows/delivery.yml": DELIVERY,
            ".github/workflows/demo-and-dast.yml": FAKE_DEMO_AND_DAST,
            **(extra or {}),
        },
    )
    repo.workflow_runs = runs
    return github, ActionsClient(github, capability_by_workflow={})


class TestTheActionsRead:
    @pytest.mark.asyncio
    async def test_a_lane_behind_a_red_upstream_reports_blocked(self) -> None:
        github, client = _actions(
            {
                "delivery.yml": _run("delivery.yml", "failure"),
                "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
            }
        )

        status = await client.status_for(REPO)

        [job] = status.jobs
        assert job.name == "demo-and-dast"
        assert job.status == "skipped"
        assert job.blocked_by == "delivery"
        states = {row.capability: row.state for row in reconcile("github-actions", status.jobs, {})}
        assert states == {"functional": "blocked", "dast": "blocked"}

    @pytest.mark.asyncio
    async def test_skipped_by_its_own_condition_reports_skipped(self) -> None:
        _, client = _actions(
            {
                "delivery.yml": _run("delivery.yml", "success"),
                "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
            }
        )

        status = await client.status_for(REPO)

        states = {row.capability: row.state for row in reconcile("github-actions", status.jobs, {})}
        assert states == {"functional": "skipped", "dast": "skipped"}

    @pytest.mark.asyncio
    async def test_a_healthy_repository_reads_no_workflow_file(self) -> None:
        github, client = _actions(
            {
                "delivery.yml": _run("delivery.yml", "success"),
                "demo-and-dast.yml": _run("demo-and-dast.yml", "success"),
            }
        )

        await client.status_for(REPO)

        assert not [call for call in github.calls if call[0] == "get_file"]

    @pytest.mark.asyncio
    async def test_blocked_lanes_names_the_root_through_a_chain(self) -> None:
        _, client = _actions(
            {
                "delivery.yml": _run("delivery.yml", "failure"),
                "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
                "mykronos-sast.yml": _run("mykronos-sast.yml", "skipped"),
            },
            extra={
                ".github/workflows/mykronos-sast.yml": AFTER_DAST.replace(
                    "Demo and DAST", "demo-and-dast"
                )
            },
        )
        client = ActionsClient(client._github, capability_by_workflow={"mykronos-sast.yml": "sast"})

        held = await client.blocked_lanes(REPO)

        assert held is not None
        by_job = {job.name: block for job, block in held}
        assert by_job["sast"].blocked_by == "demo-and-dast"
        assert by_job["sast"].root == by_job["demo-and-dast"].root == "delivery"
        assert by_job["sast"].root_state == "failed"

    @pytest.mark.asyncio
    async def test_an_unreadable_repository_is_none_not_empty(self) -> None:
        client = ActionsClient(FakeGitHubClient(), capability_by_workflow={})
        assert await client.blocked_lanes(REPO) is None


def _held(root_state: str = "failed") -> briefing.BlockedLane:
    return briefing.BlockedLane(
        pipeline="github-actions",
        job="demo-and-dast",
        blocked_by="Delivery",
        root="Delivery",
        root_state=root_state,
        since=WHEN,
        last_status="skipped",
        build_url=f"https://github.com/{REPO}/actions/runs/35319643422",
        repo_full_name=REPO,
        capabilities=["functional", "dast"],
    )


IDS = {REPO: "repo-1"}


class TestTheBriefing:
    """The acceptance in #504, against the lake the issue describes: `dast`
    failing twice, then nothing -- because every later run was skipped."""

    def _failing_dast(self, client, run_compaction) -> None:
        token = issue_token(client, REPO, "dast")
        headers = {"Authorization": f"Bearer {token}"}
        for n, when in enumerate((_utcnow() - timedelta(days=2), _utcnow() - timedelta(days=1))):
            run_id = f"dast-{n}"
            post_scan(
                client,
                headers,
                scan_run_id=run_id,
                capability="dast",
                scan_status="failure",
                started_at=when.replace(tzinfo=None).isoformat(),
                detail="No *.json files under /home/runner/work/_temp/dast",
            )
            if n == 0:
                post_findings(
                    client, headers, [finding_payload()], scan_run_id=run_id, capability="dast"
                )
        run_compaction()

    def test_with_delivery_red_dast_is_blocked_on_delivery_and_not_rescanned(
        self, client, catalog, run_compaction
    ) -> None:
        self._failing_dast(client, run_compaction)

        report = briefing.build(
            catalog,
            repo_ids=IDS,
            scanned_by={REPO: "github_actions"},
            workflow_blocked_jobs=[_held()],
        )

        [lane] = [lane for lane in report.stalled if lane.capability == "dast"]
        assert lane.reason == "blocked"
        assert lane.blocked_by == "Delivery"
        assert lane.blocked_by_kind == "workflow"
        assert lane.action is not None
        assert lane.action.method == "GET"
        assert "scan?capabilities" not in lane.action.path
        assert "Delivery" in lane.action.label
        assert "one more skipped run" in lane.dispatch_refusal
        # The old run's detail is not this lane's state any more.
        assert lane.detail == ""

        text = briefing.render(report)
        assert "runs after Delivery, which is failing" in text
        assert "POST /api/repos/repo-1/scan?capabilities=dast" not in text
        assert "consecutive failures" not in text
        assert "35319643422" in text
        # And the lane appears in the section that says what is upstream.
        assert f"{REPO} github-actions/demo-and-dast" in text
        assert "behind Delivery (failed)" in text

    def test_with_delivery_green_the_lane_reports_as_it_does_now(
        self, client, catalog, run_compaction
    ) -> None:
        self._failing_dast(client, run_compaction)

        report = briefing.build(
            catalog, repo_ids=IDS, scanned_by={REPO: "github_actions"}, workflow_blocked_jobs=[]
        )

        [lane] = [lane for lane in report.stalled if lane.capability == "dast"]
        assert lane.reason == "failing"
        assert lane.blocked_by_kind == ""
        assert lane.action is not None
        assert lane.action.path == "/api/repos/repo-1/scan?capabilities=dast"

    def test_another_repositorys_block_does_not_touch_this_lane(
        self, client, catalog, run_compaction
    ) -> None:
        self._failing_dast(client, run_compaction)
        elsewhere = _held()
        elsewhere.repo_full_name = "someone/else"

        report = briefing.build(catalog, repo_ids=IDS, workflow_blocked_jobs=[elsewhere])

        [lane] = [lane for lane in report.stalled if lane.capability == "dast"]
        assert lane.reason == "failing"
        # Scoped like every per-repository section.
        assert briefing.build(
            catalog, asset_id=REPO, workflow_blocked_jobs=[elsewhere]
        ).blocked == []

    def test_concourse_unknown_still_says_so_beside_a_github_block(
        self, client, catalog, run_compaction
    ) -> None:
        self._failing_dast(client, run_compaction)

        report = briefing.build(catalog, repo_ids=IDS, workflow_blocked_jobs=[_held()])

        assert report.blocked_unknown is True
        assert [b.job for b in report.blocked] == ["demo-and-dast"]


class TestTheApiCarriesIt:
    def test_the_briefing_endpoint_reads_the_chain_from_github(
        self, client, admin_auth, github, run_compaction
    ) -> None:
        """End to end through `briefing_sources.gather` and the App's client."""
        from tests.test_onboarding import onboard

        assert onboard(client, admin_auth).status_code in (200, 201)
        repo = github.repos[REPO]
        for path, text in {
            ".github/workflows/delivery.yml": DELIVERY,
            ".github/workflows/demo-and-dast.yml": FAKE_DEMO_AND_DAST,
        }.items():
            repo.files[path] = text
            repo.branches[repo.default_branch][path] = text
        repo.workflow_runs = {
            "delivery.yml": _run("delivery.yml", "failure"),
            "demo-and-dast.yml": _run("demo-and-dast.yml", "skipped"),
        }
        dast = {"Authorization": f"Bearer {issue_token(client, REPO, 'dast')}"}
        post_scan(client, dast, scan_run_id="dast-1", capability="dast", scan_status="failure")
        post_findings(client, dast, [finding_payload()], scan_run_id="dast-1", capability="dast")
        run_compaction()

        body = client.get("/api/dashboard/briefing", headers=admin_auth).json()

        [held] = [b for b in body["blocked"] if b["job"] == "demo-and-dast"]
        assert held["repo_full_name"] == REPO
        assert held["root_state"] == "failed"
        [lane] = [lane for lane in body["stalled"] if lane["capability"] == "dast"]
        assert lane["reason"] == "blocked"
        assert lane["blocked_by_kind"] == "workflow"
        assert lane["action"]["method"] == "GET"
