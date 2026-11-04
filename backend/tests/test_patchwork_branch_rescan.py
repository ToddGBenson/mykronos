"""A fix's own branch is rescanned, and the pull request records whether the
finding is gone (TheHub #60746).

The clock is pinned: every scan run carries an explicit `started_at`, and the
deadline check takes `now`, so nothing here depends on when it runs.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest

from mykronos.jobs import rescan_fix_branches
from mykronos.patchwork import branch_rescan
from tests.conftest import REPO, post_findings, post_scan
from tests.test_onboarding import onboard
from tests.test_patchwork import patchwork_auth  # noqa: F401 - fixture
from tests.test_patchwork_semgrep_fix import FIXTURE_FILES, _findings, _read

RULE = "mykronos-flask-debug-enabled"
PATH = FIXTURE_FILES[RULE]
OPENED = datetime(2026, 11, 2, 12, 0, 0)
HEAD = "b" * 40


def _iso(moment: datetime) -> str:
    return moment.isoformat()


@pytest.fixture
def opened(client, admin_auth, patchwork_auth, run_compaction, github):  # noqa: F811
    """A draft fix PR opened by Patchwork for one fixture Semgrep finding."""
    onboard(client, admin_auth)
    repo = github.repos[REPO]
    repo.files[PATH] = _read(PATH)
    repo.branches.setdefault("main", {})[PATH] = _read(PATH)
    finding = _findings()[RULE]
    finding["severity"] = "high"
    finding.pop("capability")
    post_scan(
        client,
        patchwork_auth,
        scan_run_id="scan-main-1",
        tool_name="semgrep",
        started_at=_iso(OPENED - timedelta(hours=1)),
    )
    post_findings(client, patchwork_auth, [finding], scan_run_id="scan-main-1")
    run_compaction()
    body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()
    assert body["draft_prs_opened"] == 1, body
    (pr,) = repo.pull_requests
    # The fake does not invent these; GitHub reports both.
    pr.head_sha = HEAD
    pr.created_at = OPENED
    run_compaction()
    return {"pr": pr, "finding": finding, "auth": patchwork_auth}


def _branch_scan(client, opened, *, status="success", report=False, at=None, run_id="scan-pr"):
    post_scan(
        client,
        opened["auth"],
        scan_run_id=run_id,
        tool_name="semgrep",
        commit_sha=HEAD,
        branch=opened["pr"].head_branch,
        scan_status=status,
        finding_count=1 if report else 0,
        started_at=_iso(at or OPENED + timedelta(minutes=5)),
    )
    post_findings(client, opened["auth"], [opened["finding"]] if report else [], scan_run_id=run_id)


def _rescan(client, github, now=OPENED + timedelta(hours=1)):
    return asyncio.run(
        branch_rescan.rescan_open_fixes(client.app.state.catalog, {REPO: github}, now=now)
    )


class TestTheVerdictIsRecordedOnThePullRequest:
    def test_a_fix_that_cleared_the_finding_says_so(
        self, client, github, opened, run_compaction
    ) -> None:
        _branch_scan(client, opened, report=False)
        run_compaction()

        result = _rescan(client, github)

        assert result.verified_fixed == 1, result
        pr = opened["pr"]
        assert branch_rescan.MARKER in pr.body
        assert "no longer reports the finding" in pr.body
        assert github.repos[REPO].pull_request_labels[pr.number] == [
            branch_rescan.LABEL_VERIFIED
        ]
        assert pr.draft is True, "a person still decides; nothing marks it ready"

    def test_a_fix_that_did_not_remove_it_is_labelled_and_not_proposed(
        self, client, github, opened, run_compaction
    ) -> None:
        _branch_scan(client, opened, report=True)
        run_compaction()

        result = _rescan(client, github)

        assert result.still_open == 1, result
        pr = opened["pr"]
        assert "**Do not merge.**" in pr.body
        assert "does not propose it for merge" in pr.body
        assert github.repos[REPO].pull_request_labels[pr.number] == [
            branch_rescan.LABEL_STILL_OPEN
        ]
        assert pr.draft is True

    def test_a_scan_that_did_not_complete_is_inconclusive(
        self, client, github, opened, run_compaction
    ) -> None:
        _branch_scan(client, opened, status="partial_failure")
        run_compaction()

        result = _rescan(client, github)

        assert result.inconclusive == 1, result
        assert github.repos[REPO].pull_request_labels[opened["pr"].number] == [
            branch_rescan.LABEL_UNVERIFIED
        ]
        assert "**Not verified.**" in opened["pr"].body

    def test_a_later_default_branch_scan_makes_absence_unreadable(
        self, client, github, opened, run_compaction
    ) -> None:
        """main still carries the finding, and its scan overwrites the
        last-seen pointer. Reading that as "the branch cleared it" would make
        every fix look like it worked."""
        _branch_scan(client, opened, report=False)
        post_scan(
            client,
            opened["auth"],
            scan_run_id="scan-main-2",
            tool_name="semgrep",
            started_at=_iso(OPENED + timedelta(minutes=30)),
        )
        post_findings(client, opened["auth"], [opened["finding"]], scan_run_id="scan-main-2")
        run_compaction()

        result = _rescan(client, github)

        assert result.inconclusive == 1, result
        assert result.verified_fixed == 0

    def test_a_moved_finding_under_a_new_id_still_counts_as_present(
        self, client, github, opened, run_compaction
    ) -> None:
        """A finding's id includes its line; the verdict matches rule and file."""
        moved = dict(opened["finding"])
        moved["line_start"] = (moved.get("line_start") or 1) + 3
        moved["line_end"] = (moved.get("line_end") or 1) + 3
        moved["code_snippet"] = None
        moved["symbol"] = "elsewhere"
        post_scan(
            client,
            opened["auth"],
            scan_run_id="scan-pr",
            tool_name="semgrep",
            commit_sha=HEAD,
            branch=opened["pr"].head_branch,
            started_at=_iso(OPENED + timedelta(minutes=5)),
        )
        post_findings(client, opened["auth"], [moved], scan_run_id="scan-pr")
        run_compaction()

        assert _rescan(client, github).still_open == 1


class TestWaitingAndTheDeadline:
    def test_no_scan_yet_records_nothing(self, client, github, opened) -> None:
        result = _rescan(client, github, now=OPENED + timedelta(hours=2))

        assert result.waiting == 1 and result.recorded == 0
        assert branch_rescan.MARKER not in opened["pr"].body
        assert opened["pr"].number not in github.repos[REPO].pull_request_labels

    def test_no_scan_by_the_deadline_is_not_scanned_and_not_proposed(
        self, client, github, opened
    ) -> None:
        result = _rescan(
            client, github, now=OPENED + branch_rescan.BRANCH_RESCAN_DEADLINE + timedelta(minutes=1)
        )

        assert result.not_scanned == 1, result
        assert github.repos[REPO].pull_request_labels[opened["pr"].number] == [
            branch_rescan.LABEL_UNVERIFIED
        ]
        assert "No scan of this branch" in opened["pr"].body

    def test_it_is_recorded_once(self, client, github, opened, run_compaction) -> None:
        _branch_scan(client, opened, report=True)
        run_compaction()

        _rescan(client, github)
        body = opened["pr"].body
        second = _rescan(client, github)

        assert second.recorded == 0
        assert opened["pr"].body == body
        assert body.count(branch_rescan.MARKER) == 1


class TestTheJob:
    def test_the_scheduled_job_reads_every_onboarded_repository(
        self, client, github, opened, run_compaction
    ) -> None:
        _branch_scan(client, opened, report=True)
        run_compaction()

        result = asyncio.run(
            rescan_fix_branches(
                client.app.state.db, client.app.state.catalog, client.app.state.github_factory
            )
        )

        assert result.still_open == 1, result


class TestNothingMerges:
    def test_no_rescan_path_merges_marks_ready_or_approves(
        self, client, github, opened, run_compaction
    ) -> None:
        _branch_scan(client, opened, report=False)
        run_compaction()

        _rescan(client, github)

        names = {name for name, _ in github.calls}
        assert not {n for n in names if "merge" in n or "ready" in n or "approv" in n}
        assert names & {"update_pull_request", "add_pull_request_labels"}
        assert opened["pr"].draft is True and opened["pr"].merged is False

    def test_the_rescan_module_names_no_merge_call(self) -> None:
        import inspect

        source = inspect.getsource(branch_rescan)
        for forbidden in (".merge(", "merge_pull_request", "ready_for_review", "approve("):
            assert forbidden not in source
