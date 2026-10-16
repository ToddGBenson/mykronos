"""A finding closes on evidence from the tree it was found in (B-056).

`scan_runs` has always carried a branch, and absence reconciliation never read
it, so every branch of a repository wrote to one lane. TheHub is scanned on
`develop` and on `main` at once, and every repository also collects runs from
the install pull requests Mykronos itself opens -- so two consecutive `main`
scans could confirm the absence of a finding that only ever existed on
`develop`, and the next `develop` scan reopened it.

That flapping is the exact outcome the two-scan rule exists to prevent,
arriving through the dimension the rule did not have. It destroys
`resolved_at`, corrupts mean-time-to-fix, and generates a reopened event every
cycle.
"""

from __future__ import annotations

from mykronos.lake import reconcile_absences
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan


def scan(
    client,
    token: str,
    run_id: str,
    branch: str,
    findings: list | None = None,
    *,
    capability: str = "sast",
    status: str = "success",
    pr_number: int | None = 2841,
) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability=capability,
        branch=branch,
        scan_status=status,
        pr_number=pr_number,
        triggered_by="pull_request" if pr_number is not None else "push",
    )
    post_findings(
        client, headers, findings or [], scan_run_id=run_id, capability=capability
    )


def statuses(catalog) -> dict[str, str]:
    return {
        str(row[0]): str(row[1])
        for row in catalog.query("SELECT title, status FROM findings")
    }


class TestOneBranchDoesNotCloseAnother:
    def test_two_scans_of_another_branch_do_not_close_it(
        self, client, catalog, run_compaction
    ) -> None:
        """The live shape: a finding on `develop`, and `main` scanned twice
        while `develop` has not run again. Nothing has looked at the tree the
        finding is in, so nothing can say it is gone."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()
        scan(client, token, "main-1", "main", [])
        scan(client, token, "main-2", "main", [])
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert outcome.fixed == []
        assert statuses(catalog)["on develop"] == "open"

    def test_two_scans_of_its_own_branch_do_close_it(
        self, client, catalog, run_compaction
    ) -> None:
        """The rule still works. Branch-awareness must not become a way of
        never closing anything."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()
        scan(client, token, "dev-2", "develop", [])
        scan(client, token, "dev-3", "develop", [])
        run_compaction()

        assert len(reconcile_absences(catalog).fixed) == 1
        assert statuses(catalog)["on develop"] == "fixed"

    def test_an_install_pull_request_branch_closes_nothing_on_the_default(
        self, client, catalog, run_compaction
    ) -> None:
        """Every repository in this estate collects runs from the
        `mykronos/enable-workflows-*` branches the installer opens. Those are
        real scans of a real tree, and they are not scans of `main`."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "main-1", "main", [finding_payload(title="on main")])
        run_compaction()
        scan(client, token, "pr-1", "mykronos/enable-workflows-20260909T000000", [])
        scan(client, token, "pr-2", "mykronos/enable-workflows-20260909T000000", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert statuses(catalog)["on main"] == "open"

    def test_each_branch_keeps_its_own_two_scan_history(
        self, client, catalog, run_compaction
    ) -> None:
        """Interleaved branches must not consume each other's evidence: the
        two `develop` scans that close a `develop` finding are the two most
        recent `develop` scans, whatever ran between them."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()
        scan(client, token, "main-1", "main", [])
        scan(client, token, "dev-2", "develop", [])
        scan(client, token, "main-2", "main", [])
        scan(client, token, "dev-3", "develop", [])
        run_compaction()

        assert len(reconcile_absences(catalog).fixed) == 1
        assert statuses(catalog)["on develop"] == "fixed"

    def test_a_finding_on_each_branch_is_two_findings(
        self, client, catalog, run_compaction
    ) -> None:
        """Closing one must leave the other alone, which is the whole point:
        the same defect on two branches is fixed on two branches separately."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="both", file_path="a.py")])
        scan(client, token, "main-1", "main", [finding_payload(title="both", file_path="b.py")])
        run_compaction()
        scan(client, token, "dev-2", "develop", [])
        scan(client, token, "dev-3", "develop", [])
        run_compaction()

        reconcile_absences(catalog)
        rows = catalog.query(
            "SELECT file_path, status FROM findings WHERE title = 'both' ORDER BY file_path"
        )

        assert [(str(r[0]), str(r[1])) for r in rows] == [("a.py", "fixed"), ("b.py", "open")]

    def test_a_failed_scan_still_confirms_nothing(
        self, client, catalog, run_compaction
    ) -> None:
        """The status rule and the branch rule are independent, and adding one
        must not have quietly dropped the other."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()
        scan(client, token, "dev-2", "develop", [], status="failure")
        scan(client, token, "dev-3", "develop", [], status="failure")
        run_compaction()

        assert reconcile_absences(catalog).fixed == []

    def test_a_lane_that_has_only_looked_once_anywhere_is_reported_as_waiting(
        self, client, catalog, run_compaction
    ) -> None:
        """"We have not looked enough times" is a different answer from
        "there is nothing to close", and it stays worth saying."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert outcome.fixed == []
        assert (REPO, "sast") in outcome.insufficient_history

    def test_a_working_lane_is_not_reported_as_waiting(
        self, client, catalog, run_compaction
    ) -> None:
        """`develop` has looked twice and is closing findings. Saying the lane
        is short of history because a pull-request branch was scanned once is
        true, useless, and how a report stops being read."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "dev-1", "develop", [finding_payload(title="x")])
        run_compaction()
        scan(client, token, "dev-2", "develop", [])
        scan(client, token, "dev-3", "develop", [])
        scan(client, token, "pr-1", "mykronos/enable-workflows-20260909T000000", [])
        run_compaction()

        outcome = reconcile_absences(catalog)

        assert len(outcome.fixed) == 1
        assert outcome.insufficient_history == []


def push(client, token: str, run_id: str, branch: str, findings: list | None = None) -> None:
    """A push or scheduled run: no pull request, as every main/develop run in
    the estate's lake is."""
    scan(client, token, run_id, branch, findings, pr_number=None)


class TestAPullRequestSightingFallsBackToTheLongLivedBranches:
    """#864: a pull request's branch is scanned for a few days and deleted, so
    a finding whose last sighting was one could never close by absence."""

    def test_the_binnacle_shape_closes_on_two_later_main_runs(
        self, client, catalog, run_compaction
    ) -> None:
        """main sees it, the fix lands, a PR cut before the fix re-sights it,
        and main then runs clean twice. Before #864 this stayed open for good."""
        token = issue_token(client, REPO, "sast")
        push(client, token, "main-1", "main", [finding_payload(title="re-sighted")])
        run_compaction()
        scan(
            client, token, "pr-1", "fix/cut-before-the-fix",
            [finding_payload(title="re-sighted")], pr_number=29,
        )
        run_compaction()
        push(client, token, "main-2", "main", [])
        push(client, token, "main-3", "main", [])
        run_compaction()

        assert len(reconcile_absences(catalog).fixed) == 1
        assert statuses(catalog)["re-sighted"] == "fixed"

    def test_one_later_main_run_is_not_enough(
        self, client, catalog, run_compaction
    ) -> None:
        """The two-scan rule still holds on the fallback lane."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "pr-1", "fix/x", [finding_payload(title="pr")], pr_number=29)
        run_compaction()
        push(client, token, "main-1", "main", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert statuses(catalog)["pr"] == "open"

    def test_runs_from_before_the_sighting_are_not_evidence(
        self, client, catalog, run_compaction
    ) -> None:
        """Two clean main runs that finished before the PR saw it say nothing
        about the tree the PR scanned."""
        token = issue_token(client, REPO, "sast")
        push(client, token, "main-1", "main", [])
        push(client, token, "main-2", "main", [])
        scan(client, token, "pr-1", "fix/x", [finding_payload(title="pr")], pr_number=29)
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert statuses(catalog)["pr"] == "open"

    def test_every_long_lived_branch_that_ran_since_must_have_run_twice(
        self, client, catalog, run_compaction
    ) -> None:
        """TheHub's shape: develop and main both long-lived. develop clean twice
        and main clean once since the sighting is not yet enough -- main has
        looked once and could still be the tree that has it."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "pr-1", "fix/x", [finding_payload(title="pr")], pr_number=29)
        run_compaction()
        push(client, token, "dev-1", "develop", [])
        push(client, token, "dev-2", "develop", [])
        push(client, token, "main-1", "main", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []

        push(client, token, "main-2", "main", [])
        run_compaction()

        assert len(reconcile_absences(catalog).fixed) == 1

    def test_a_branch_that_has_not_run_since_is_not_counted(
        self, client, catalog, run_compaction
    ) -> None:
        """TheHub's main has been quiet since September; a long-lived branch
        that has not looked is not evidence either way, and must not hold a
        finding the default branch has twice confirmed gone."""
        token = issue_token(client, REPO, "sast")
        push(client, token, "main-old", "main", [])
        scan(client, token, "pr-1", "fix/x", [finding_payload(title="pr")], pr_number=29)
        run_compaction()
        push(client, token, "dev-1", "develop", [])
        push(client, token, "dev-2", "develop", [])
        run_compaction()

        assert len(reconcile_absences(catalog).fixed) == 1

    def test_a_long_lived_sighting_still_closes_only_on_its_own_branch(
        self, client, catalog, run_compaction
    ) -> None:
        """B-056 is untouched: a develop push sighting and two clean main
        pushes close nothing."""
        token = issue_token(client, REPO, "sast")
        push(client, token, "dev-1", "develop", [finding_payload(title="on develop")])
        run_compaction()
        push(client, token, "main-1", "main", [])
        push(client, token, "main-2", "main", [])
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
        assert statuses(catalog)["on develop"] == "open"

    def test_another_tool_on_the_branch_is_not_evidence(
        self, client, catalog, run_compaction
    ) -> None:
        """The tool dimension holds on the fallback too: ShellCheck's silence
        says nothing about a CodeQL finding."""
        token = issue_token(client, REPO, "sast")
        scan(client, token, "pr-1", "fix/x", [finding_payload(title="pr")], pr_number=29)
        run_compaction()
        headers = {"Authorization": f"Bearer {token}"}
        for run_id in ("sc-1", "sc-2"):
            post_scan(
                client, headers, scan_run_id=run_id, capability="sast", branch="main",
                tool_name="shellcheck", pr_number=None, triggered_by="push",
            )
        run_compaction()

        assert reconcile_absences(catalog).fixed == []
