"""Reading GitHub Actions back (spec 32 §7).

The same job `test_ci.py` does for Concourse, for the second reader. What
these guard is narrower and sharper than "the link works": `reconcile()` and
`coverage()` are shared between the two CI systems and were deliberately not
touched by this migration, so every way `ActionsClient` could feed them
something they misread is a way the coverage cross-check silently stops
working — green everywhere, and nothing saying so.

The worst of those is the vocabulary. GitHub says `success`; the platform
says `succeeded`. A client that passed the former through would leave every
green lane reading `not_run`, `coverage()` would report the whole repository
as never having been scanned, and none of it would raise.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mykronos.ci import (
    ActionsClient,
    PipelineStatus,
    Reporting,
    StageCoverage,
    StatusCache,
    capability_by_workflow,
    compare,
    coverage,
    reconcile,
    status_from_conclusion,
)
from mykronos.github.client import FakeGitHubClient, WorkflowRun

REPO = "ToddGBenson/keel"

#: What `capability_by_workflow` would build from the real registry, written
#: out here so a test reads as a statement about behaviour rather than a
#: chain of lookups.
MAP = {
    "mykronos-sast.yml": "sast",
    "mykronos-secrets.yml": "secrets",
    "mykronos-unit.yml": "unit",
}


def _client(*, files: dict[str, str], states=None, runs=None) -> ActionsClient:
    github = FakeGitHubClient()
    repo = github.add_repo(REPO, files=dict(files))
    repo.workflow_states = dict(states or {})
    repo.workflow_runs = dict(runs or {})
    return ActionsClient(github, capability_by_workflow=MAP)


def _run(workflow: str, conclusion: str | None, *, when: datetime | None = None) -> WorkflowRun:
    return WorkflowRun(
        workflow_file=workflow,
        conclusion=conclusion,
        run_number=12,
        url=f"https://github.com/{REPO}/actions/runs/999",
        finished_at=when or datetime(2026, 8, 28, 12, 0, tzinfo=UTC),
    )


class TestVocabulary:
    @pytest.mark.parametrize(
        ("conclusion", "expected"),
        [
            ("success", "succeeded"),
            ("failure", "failed"),
            ("cancelled", "aborted"),
            ("timed_out", "errored"),
            ("startup_failure", "errored"),
        ],
    )
    def test_conclusions_map_to_the_platform_vocabulary(
        self, conclusion: str, expected: str
    ) -> None:
        assert status_from_conclusion(conclusion) == expected

    def test_a_skipped_run_is_not_a_success(self) -> None:
        """A skipped job produced no outcome. Calling it a success would let
        a lane that never executed vouch for a capability."""
        assert status_from_conclusion("skipped") is None

    def test_an_unknown_conclusion_reads_as_not_run(self) -> None:
        """The safe direction: "has not run" invites a look, a wrong
        "succeeded" ends the conversation."""
        assert status_from_conclusion("something_github_added_later") is None
        assert status_from_conclusion(None) is None


class TestStatus:
    @pytest.mark.asyncio
    async def test_a_successful_run_reads_as_succeeded(self) -> None:
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert status.pipeline == "github-actions"
        assert [(j.name, j.status) for j in status.jobs] == [("sast", "succeeded")]
        assert status.failing == []

    @pytest.mark.asyncio
    async def test_a_failed_run_shows_in_failing(self) -> None:
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "failure")},
        )

        status = await client.status_for(REPO)

        assert status.failing == ["sast"]

    @pytest.mark.asyncio
    async def test_a_workflow_that_never_ran_is_not_a_failure(self) -> None:
        client = _client(files={".github/workflows/mykronos-sast.yml": "..."})

        status = await client.status_for(REPO)

        assert status.jobs[0].status is None
        assert status.failing == []

    @pytest.mark.asyncio
    async def test_a_disabled_workflow_does_not_report_its_old_success(self) -> None:
        """The case that would put a green tick on a paused lane.

        Its last run really did succeed; it is switched off now, so that
        result describes a commit nobody is checking any more. Reporting it
        is the "green pipeline, stale data" disagreement spec 15 §4a.1 exists
        to surface rather than hide.
        """
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            states={"mykronos-sast.yml": "disabled_manually"},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert status.jobs[0].status is None
        assert status.jobs[0].finished_at is None

    @pytest.mark.asyncio
    async def test_a_workflow_the_platform_did_not_install_is_ignored(self) -> None:
        """Somebody else's CI. Claiming it produces a capability would
        invent coverage this platform cannot vouch for."""
        client = _client(
            files={
                ".github/workflows/mykronos-sast.yml": "...",
                ".github/workflows/release.yml": "...",
            },
            runs={"release.yml": _run("release.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert [j.name for j in status.jobs] == ["sast"]

    @pytest.mark.asyncio
    async def test_no_installed_workflow_says_so(self) -> None:
        """Distinct from "GitHub did not answer" — the fix is an install
        pull request, not a retry."""
        client = _client(files={"README.md": "..."})

        status = await client.status_for(REPO)

        assert status.pipeline is None
        assert "No Mykronos workflow is installed" in (status.unavailable or "")

    @pytest.mark.asyncio
    async def test_github_being_unreachable_never_raises(self) -> None:
        """A repository page is about findings. GitHub being down must not
        take it down with it (spec 15 §4a, carried forward)."""
        client = ActionsClient(FakeGitHubClient(), capability_by_workflow=MAP)

        status = await client.status_for(REPO)

        assert status.unavailable is not None
        assert "GitHub did not answer" in status.unavailable

    @pytest.mark.asyncio
    async def test_no_app_configured_is_its_own_answer(self) -> None:
        client = ActionsClient(None, capability_by_workflow=MAP)

        status = await client.status_for(REPO)

        assert "No GitHub App is configured" in (status.unavailable or "")


class TestFeedsTheCrossCheck:
    """The point of the whole exercise: what `ActionsClient` produces has to
    be readable by the two functions that were not changed."""

    @pytest.mark.asyncio
    async def test_a_green_lane_that_reported_reads_reporting(self) -> None:
        built = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "success", when=built)},
        )
        status = await client.status_for(REPO)

        reported = reconcile(status.jobs, {"sast": built})
        stages = {c.stage: c.state for c in coverage({"sast"}, reported)}

        assert stages["sast"] == "reporting"

    @pytest.mark.asyncio
    async def test_a_green_lane_that_never_uploaded_reads_never_reported(self) -> None:
        """The failure this cross-check was built to find, now via Actions:
        the workflow succeeds on every run and nothing reaches the lake."""
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "success")},
        )
        status = await client.status_for(REPO)

        reported = reconcile(status.jobs, {})
        stages = {c.stage: c.state for c in coverage({"sast"}, reported)}

        assert stages["sast"] == "never_reported"

    @pytest.mark.asyncio
    async def test_an_enabled_capability_with_no_workflow_reads_no_job(self) -> None:
        client = _client(files={".github/workflows/mykronos-sast.yml": "..."})
        status = await client.status_for(REPO)

        reported = reconcile(status.jobs, {})
        stages = {c.stage: c.state for c in coverage({"sast", "dast"}, reported)}

        assert stages["dast"] == "no_job"

    @pytest.mark.asyncio
    async def test_event_driven_capabilities_are_not_gaps(self) -> None:
        """Aegis is webhook-fed and produces no ScanRun from a lane. It read
        `event_driven` under Concourse and must still, or enabling it would
        light up as a permanent coverage gap."""
        client = _client(files={".github/workflows/mykronos-sast.yml": "..."})
        status = await client.status_for(REPO)

        reported = reconcile(status.jobs, {})
        stages = {c.stage: c.state for c in coverage({"sast", "aegis"}, reported)}

        assert stages["aegis"] == "event_driven"


class TestCapabilityMap:
    def test_it_is_built_from_the_registry_not_restated(self) -> None:
        class Spec:
            def __init__(self, target: str) -> None:
                self.target = target

        class Library:
            specs = {"sast": Spec(".github/workflows/mykronos-sast.yml")}

        assert capability_by_workflow(Library()) == {"mykronos-sast.yml": "sast"}

    def test_no_registry_is_an_empty_map_not_a_crash(self) -> None:
        """This runs inside a status read that must not raise."""
        assert capability_by_workflow(object()) == {}


class TestStatusCache:
    def _status(self, unavailable: str | None = None) -> PipelineStatus:
        return PipelineStatus(
            repo_full_name=REPO, pipeline="github-actions", url="u", unavailable=unavailable
        )

    def test_a_hit_inside_the_ttl_is_reused(self) -> None:
        cache = StatusCache(ttl_seconds=60)
        cache.put(REPO, self._status(), now=100.0)

        assert cache.get(REPO, now=130.0) is not None

    def test_it_expires(self) -> None:
        cache = StatusCache(ttl_seconds=60)
        cache.put(REPO, self._status(), now=100.0)

        assert cache.get(REPO, now=161.0) is None

    def test_a_failure_is_never_cached(self) -> None:
        """Caching an outage would pin it for the whole TTL, and "GitHub did
        not answer" is exactly what somebody reloads the page to change."""
        cache = StatusCache(ttl_seconds=60)
        cache.put(REPO, self._status(unavailable="GitHub did not answer"), now=100.0)

        assert cache.get(REPO, now=101.0) is None

    def test_it_is_bounded(self) -> None:
        cache = StatusCache(ttl_seconds=600, limit=2)
        for index, moment in enumerate((100.0, 101.0, 102.0)):
            cache.put(f"repo-{index}", self._status(), now=moment)

        assert cache.get("repo-0", now=103.0) is None
        assert cache.get("repo-2", now=103.0) is not None


class TestRepoOwnedWorkflows:
    """A workflow the platform did not write, producing capabilities anyway.

    `demo-and-dast.yml` stands up an ephemeral stack, runs the functional suite
    through ZAP's proxy and uploads both `functional` and `dast` (spec 32
    §4.2). No template can express that, so it is hand-written — and before
    `ActionsClient` fell back to `CAPABILITY_BY_JOB`, both capabilities read
    `no_job`: rendered red, as a coverage gap, while the scans were arriving.

    The parity check that authorises retiring the Concourse pipelines reads
    exactly this signal, so a false red here is not cosmetic.
    """

    @pytest.mark.asyncio
    async def test_a_known_job_name_is_credited(self) -> None:
        client = _client(
            files={".github/workflows/demo-and-dast.yml": "..."},
            runs={"demo-and-dast.yml": _run("demo-and-dast.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert [j.name for j in status.jobs] == ["demo-and-dast"]

    @pytest.mark.asyncio
    async def test_one_workflow_answers_for_both_capabilities(self) -> None:
        """The property that made the stem the right thing to return.

        `reconcile()` already splits a tuple — it has to, for Concourse's
        `demo-and-dast` — so the two CIs converge on one table instead of
        growing a second.
        """
        built = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
        client = _client(
            files={".github/workflows/demo-and-dast.yml": "..."},
            runs={"demo-and-dast.yml": _run("demo-and-dast.yml", "success", when=built)},
        )
        status = await client.status_for(REPO)

        reported = reconcile(status.jobs, {"functional": built, "dast": built})
        stages = {c.stage: c.state for c in coverage({"functional", "dast"}, reported)}

        assert stages["functional"] == "reporting"
        assert stages["dast"] == "reporting"

    @pytest.mark.asyncio
    async def test_a_delivery_workflow_is_still_ignored(self) -> None:
        """`delivery.yml` builds and publishes and produces no findings — the
        exact case `ci.py` says "their absence from the lake is not a fault".
        The fallback must not start crediting it with something."""
        client = _client(
            files={".github/workflows/delivery.yml": "..."},
            runs={"delivery.yml": _run("delivery.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert status.pipeline is None
        assert "No Mykronos workflow is installed" in (status.unavailable or "")

    @pytest.mark.asyncio
    async def test_the_template_registry_still_wins(self) -> None:
        """Order matters: the registry is exact and the table is a heuristic,
        so a filename in both resolves by the registry."""
        client = _client(
            files={".github/workflows/mykronos-sast.yml": "..."},
            runs={"mykronos-sast.yml": _run("mykronos-sast.yml", "success")},
        )

        status = await client.status_for(REPO)

        assert [j.name for j in status.jobs] == ["sast"]


class TestParity:
    """The check that authorises retiring a Concourse pipeline (spec 32 §9).

    Retiring a pipeline because its replacement looks green is how a lane goes
    quiet without anybody noticing. Spec 15 §4a.1's first day of existence
    found a lane that had been green on every build and had never reported
    once — this is what stops that happening on purpose, at the moment the old
    system is destroyed and cannot be consulted again.
    """

    def _cov(self, **states: str) -> list[StageCoverage]:
        return [
            StageCoverage(stage=stage, enabled=state != "not_enabled", state=state)
            for stage, state in states.items()
        ]

    def test_identical_coverage_is_safe(self) -> None:
        before = self._cov(sast="reporting", unit="reporting")
        after = self._cov(sast="reporting", unit="reporting")

        rows = compare(before, after)

        assert [r.verdict for r in rows] == ["same", "same"]
        assert not any(r.regressed for r in rows)

    def test_a_lane_that_stopped_reporting_is_a_regression(self) -> None:
        """The whole point. Concourse was reporting; Actions is not."""
        rows = compare(self._cov(sast="reporting"), self._cov(sast="never_reported"))

        assert rows[0].regressed
        assert rows[0].verdict == "REGRESSED"

    def test_a_capability_missing_from_the_new_system_is_a_regression(self) -> None:
        """Treated as `no_job` rather than skipped. A capability the new
        system does not know about is exactly the gap this looks for."""
        rows = compare(self._cov(sast="reporting"), [])

        assert rows[0].after == "no_job"
        assert rows[0].regressed

    def test_going_green_is_an_improvement_not_a_regression(self) -> None:
        rows = compare(self._cov(sast="never_reported"), self._cov(sast="reporting"))

        assert not rows[0].regressed
        assert rows[0].verdict == "improved"

    def test_event_driven_is_not_worse_than_reporting(self) -> None:
        """Aegis, Oracle and Patchwork never produce a ScanRun from a lane.
        Ranking `event_driven` below `reporting` would report a working
        webhook-fed capability as a migration casualty."""
        rows = compare(self._cov(aegis="reporting"), self._cov(aegis="event_driven"))

        assert not rows[0].regressed

    def test_a_capability_nobody_enabled_is_not_a_casualty(self) -> None:
        """`not_enabled` is an absence, not a gap — and a capability that was
        never on cannot have been lost by moving CI."""
        rows = compare(self._cov(cloud="not_enabled"), self._cov(cloud="not_enabled"))

        assert not rows[0].regressed

    def test_silent_is_worse_than_reporting_and_better_than_never(self) -> None:
        """The three states are ordered, and the ordering is what makes
        "no capability got worse" a decidable question rather than a
        judgement call."""
        assert compare(self._cov(x="reporting"), self._cov(x="silent"))[0].regressed
        assert not compare(self._cov(x="never_reported"), self._cov(x="silent"))[0].regressed


class TestParityRefusesAnUnreadableSide:
    """A side that could not be read is not a side with no coverage.

    `status_for` fails soft by design — it returns `unavailable` and no jobs
    rather than raising, because a dashboard must not 500 when a CI server
    restarts. Fed to `coverage()` that is indistinguishable from a system
    running nothing: every capability reads `no_job` on the unreadable side,
    every comparison against it reports "improved", and the check concludes
    "no capability is worse" having compared real coverage against a
    connection error.

    Observed for real on 2026-08-30: Concourse was unresolvable from the
    backend container and `mykronos parity` printed a clean sweep of
    `improved` and exited 0. These pin the shape of that trap so the CLI's
    refusal cannot regress into a flattering verdict.
    """

    def test_an_unreadable_side_looks_like_total_absence(self) -> None:
        """The mechanism, stated as a fact about `coverage()` rather than
        about the CLI: this is why the CLI has to check `unavailable` itself
        instead of trusting the comparison."""
        unreadable = PipelineStatus(
            repo_full_name=REPO,
            pipeline=None,
            url=None,
            unavailable="Concourse did not answer, so its state is unknown.",
        )

        rows = coverage({"sast", "unit"}, reconcile(unreadable.jobs, {}))

        assert {row.state for row in rows if row.stage in {"sast", "unit"}} == {"no_job"}

    def test_and_therefore_compares_as_improved_against_anything(self) -> None:
        """The flattering verdict, demonstrated. Every real capability beats
        `no_job`, so nothing is ever "worse" than a system nobody could
        reach."""
        unreadable = coverage({"sast"}, reconcile([], {}))
        healthy = coverage({"sast"}, [Reporting("sast", "sast", None, None)])
        healthy = [
            StageCoverage(stage=row.stage, enabled=row.enabled, state="reporting")
            if row.stage == "sast"
            else row
            for row in healthy
        ]

        rows = compare(unreadable, healthy)
        sast = next(row for row in rows if row.capability == "sast")

        # The whole estate reads as having gained coverage, because the side
        # that could not be read contributed none.
        assert sast.verdict == "improved"
        assert not any(row.regressed for row in rows)
