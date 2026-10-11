"""A pull request's evidence lists what *it* changes, after main is merged in (D-152).

Found by the approval queue's first live run, 2026-10-11: the queue merged main
into #775 (`910629b2` -> `37adbb13`), and the evidence frozen for the new head
listed 42 files, `.gitattributes`, `approval-policy-v1.yaml` and
`approval-queue.ps1` among them, for a change of 9. The operator, rightly,
would not approve main's changes as #775's.

Where it came from: `/pulls/{n}/files` diffs the head against the pull
request's `base.sha`, and GitHub had left that at `75fa5043`, the main #775
was opened against, while main had moved to `49d9a1d2`. GitHub's compare
endpoint, `main...head`, resolves `main` *now* and diffs from the merge-base,
and listed the 9.

The fixture below is real git behind a fake GitHub that answers each endpoint
the way GitHub computes it: the listing from the stale base, the comparison
from the current merge-base. A PR changes A, main changes B, main is merged
into the PR. The evidence must list only A.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mykronos.approvals import pull_requests
from mykronos.approvals.policy import cached_policy
from mykronos.github.client import Comparison, PullRequest, PullRequestFile

ROOT = Path(__file__).resolve().parents[2]
REPO = "acme/app"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")


def git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return out.stdout.strip()


def changed(repo: Path, spec: str) -> list[PullRequestFile]:
    files = []
    for line in git(repo, "diff", "--name-status", spec).splitlines():
        status, path = line.split("\t", 1)
        files.append(
            PullRequestFile(
                filename=path,
                status={"A": "added"}.get(status, "modified"),
                additions=1,
                patch="@@ +x",
            )
        )
    return files


class GitBackedGitHub:
    """Each endpoint the snapshot reads, answered from a real repository the
    way GitHub answers it - including the stale `base.sha`."""

    def __init__(self, repo: Path, stale_base: str) -> None:
        self.repo = repo
        self.stale_base = stale_base
        self.calls: list[str] = []

    async def get_repo(self, full_name: str) -> dict[str, Any]:
        return {"default_branch": "main"}

    async def get_pull_request(self, full_name: str, number: int) -> PullRequest:
        return PullRequest(
            number=number,
            url="https://github.test/pr",
            head_branch="feat",
            title="Change A",
            head_sha=git(self.repo, "rev-parse", "feat"),
            base_branch="main",
            changed_files=len(changed(self.repo, f"{self.stale_base}...feat")),
        )

    async def pull_request_files(self, full_name: str, number: int) -> list[PullRequestFile]:
        # `/pulls/{n}/files`: against `base.sha`, which GitHub left behind.
        self.calls.append("pull_request_files")
        return changed(self.repo, f"{self.stale_base}...feat")

    async def compare(self, full_name: str, base: str, head: str) -> Comparison:
        # `/compare/{base}...{head}`: `base` resolved now, from the merge-base.
        self.calls.append(f"compare {base}...")
        return Comparison(
            files=changed(self.repo, f"{base}...{head}"),
            merge_base_sha=git(self.repo, "merge-base", base, head),
        )


@pytest.fixture
def repo(tmp_path: Path) -> tuple[Path, str]:
    """main -> PR changes A; main changes B; main merged into the PR."""
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "README.md").write_text("base\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    opened_against = git(r, "rev-parse", "main")

    git(r, "checkout", "-qb", "feat")
    (r / "docs").mkdir()
    (r / "docs" / "a.md").write_text("the PR's change\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "A")

    git(r, "checkout", "-q", "main")
    (r / "approval-policy-v1.yaml").write_text("main's change\n", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "B")
    return r, opened_against


def _snapshot(github: GitBackedGitHub) -> dict[str, Any]:
    duty = cached_policy(ROOT / "approval-policy-v1.yaml").duty(pull_requests.DUTY)
    return asyncio.run(pull_requests.snapshot(github, duty, REPO, 775))


@pytest.mark.parametrize("side", ["from_main", "from_branch"])
def test_after_main_is_merged_in_the_evidence_lists_only_the_prs_change(
    repo: tuple[Path, str], side: str
) -> None:
    """Both ways of merging main in: the approval queue's (from main's side,
    so the log keeps main's entries first) and the usual one."""
    r, opened_against = repo
    if side == "from_main":
        git(r, "checkout", "-q", "--detach", "main")
        git(r, "merge", "-q", "--no-ff", "-m", "merge main in", "feat")
        git(r, "branch", "-f", "feat", "HEAD")
        git(r, "checkout", "-q", "main")
    else:
        git(r, "checkout", "-q", "feat")
        git(r, "merge", "-q", "--no-ff", "-m", "merge main in", "main")
        git(r, "checkout", "-q", "main")
    github = GitBackedGitHub(r, stale_base=opened_against)

    # The bug, reproduced: GitHub's listing against the stale base has both.
    stale = asyncio.run(github.pull_request_files(REPO, 775))
    assert sorted(f.filename for f in stale) == ["approval-policy-v1.yaml", "docs/a.md"]
    github.calls.clear()

    evidence = _snapshot(github)

    assert [f["path"] for f in evidence["files"]] == ["docs/a.md"]
    assert evidence["change_class"] == "routine", "main's policy edit is not this PR's"
    assert evidence["base_branch"] == "main"
    assert evidence["merge_base_sha"] == git(r, "rev-parse", "main")
    assert evidence["files_listing_incomplete"] is False
    assert "pull_request_files" not in github.calls


def test_before_main_is_merged_in_nothing_changes(repo: tuple[Path, str]) -> None:
    r, opened_against = repo
    evidence = _snapshot(GitBackedGitHub(r, stale_base=opened_against))

    assert [f["path"] for f in evidence["files"]] == ["docs/a.md"]
    assert evidence["merge_base_sha"] == opened_against
