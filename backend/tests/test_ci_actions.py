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
    StatusCache,
    capability_by_workflow,
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
