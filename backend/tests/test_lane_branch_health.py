"""Lane health is about one branch, and says so (B-056).

`scan_health` grouped by capability alone, so any branch's run answered for
the lane. Every repository in this estate collects scans from the
`mykronos/enable-workflows-*` branches the installer opens, and TheHub is
scanned on `develop` and `main` at once -- so a pull-request scan could make a
lane look fresh, and its failures counted against a branch nobody deploys.

The expected branch defaults to the repository's own default branch, which is
what makes this useful without anybody configuring anything. A capability may
name another, because "scan `develop`, gate `main`" is a real arrangement the
platform could not previously express.
"""

from __future__ import annotations

from mykronos.capabilities import CapabilityConfigError, validate_config
from mykronos.dashboard import DashboardQueries
from tests.conftest import REPO, issue_token, post_scan

PR_BRANCH = "mykronos/enable-workflows-20260909T000000"


def run(client, token: str, run_id: str, branch: str, status: str = "success") -> None:
    post_scan(
        client,
        {"Authorization": f"Bearer {token}"},
        scan_run_id=run_id,
        capability="sast",
        branch=branch,
        scan_status=status,
    )


def health(catalog, lane_branches=None) -> dict:
    rows = DashboardQueries(catalog).scan_health(REPO, lane_branches=lane_branches)
    return {str(row["capability"]): row for row in rows}


class TestTheLaneIsOneBranch:
    def test_a_pull_request_scan_does_not_answer_for_the_lane(
        self, client, catalog, run_compaction
    ) -> None:
        """The shape every repository here has: real scans of a real tree,
        which are not scans of the branch the lane is about."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "main-1", "main")
        run(client, token, "pr-1", PR_BRANCH)
        run(client, token, "pr-2", PR_BRANCH)
        run_compaction()

        lane = health(catalog, {"sast": "main"})["sast"]

        assert lane["runs"] == 1
        assert lane["off_lane_runs"] == 2
        assert lane["lane_branch"] == "main"

    def test_the_off_lane_runs_are_recorded_not_dropped(
        self, client, catalog, run_compaction
    ) -> None:
        """A run on another branch is a real scan whose findings close on
        their own evidence. It simply does not answer for this lane."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "pr-1", PR_BRANCH)
        run_compaction()

        lane = health(catalog, {"sast": "main"})["sast"]

        assert lane["runs"] == 0
        assert lane["off_lane_runs"] == 1

    def test_failures_elsewhere_do_not_count_against_the_lane(
        self, client, catalog, run_compaction
    ) -> None:
        """A pull-request branch that fails twice used to make the lane look
        broken on a branch that was green."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "main-1", "main")
        run(client, token, "pr-1", PR_BRANCH, status="failure")
        run(client, token, "pr-2", PR_BRANCH, status="failure")
        run_compaction()

        lane = health(catalog, {"sast": "main"})["sast"]

        assert lane["failed"] == 0
        assert lane["failure_rate"] == 0.0

    def test_freshness_comes_from_the_lane_not_the_newest_run(
        self, client, catalog, run_compaction
    ) -> None:
        """The defect stated plainly: a lane looked fresh because something
        else ran."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "main-1", "main")
        run_compaction()
        run(client, token, "pr-1", PR_BRANCH)
        run_compaction()

        with_lane = health(catalog, {"sast": "main"})["sast"]
        without = health(catalog)["sast"]

        assert with_lane["last_run_at"] < without["last_run_at"]

    def test_a_capability_may_name_another_branch(
        self, client, catalog, run_compaction
    ) -> None:
        """"Scan `develop`, gate `main`" is the arrangement the platform could
        not express, and the reason B-045 was forced rather than chosen."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "dev-1", "develop")
        run(client, token, "main-1", "main")
        run_compaction()

        lane = health(catalog, {"sast": "develop"})["sast"]

        assert lane["runs"] == 1
        assert lane["off_lane_runs"] == 1
        assert lane["lane_branch"] == "develop"


class TestWithoutALaneBranch:
    def test_nothing_changes_when_none_is_given(
        self, client, catalog, run_compaction
    ) -> None:
        """Estate-wide callers and repositories with no default branch
        recorded still get what they always got. An unknown expected branch
        must not silently exclude every run."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "main-1", "main")
        run(client, token, "pr-1", PR_BRANCH)
        run_compaction()

        lane = health(catalog)["sast"]

        assert lane["runs"] == 2
        assert lane["off_lane_runs"] == 0
        assert lane["lane_branch"] is None

    def test_a_capability_with_no_declared_branch_keeps_every_run(
        self, client, catalog, run_compaction
    ) -> None:
        """The map is per capability, so one capability declaring a branch
        must not narrow another that did not."""
        token = issue_token(client, REPO, "sast")
        run(client, token, "main-1", "main")
        run(client, token, "pr-1", PR_BRANCH)
        run_compaction()

        lane = health(catalog, {"dast": "main"})["sast"]

        assert lane["runs"] == 2
        assert lane["off_lane_runs"] == 0


class TestDeclaringIt:
    def test_a_branch_name_is_accepted(self) -> None:
        assert validate_config("sast", {"lane_branch": "develop"})["lane_branch"] == "develop"

    def test_a_pattern_is_refused(self) -> None:
        """A lane expected on several branches has no single health, which is
        the thing this field exists to give it."""
        try:
            validate_config("sast", {"lane_branch": "release/*"})
        except CapabilityConfigError as exc:
            assert "not a branch name" in str(exc)
        else:  # pragma: no cover - the assertion above is the test
            raise AssertionError("a glob must be refused")

    def test_unset_means_the_repository_default(self) -> None:
        assert "lane_branch" not in validate_config("sast", {})
