"""The one merge the platform performs: an approved Dependabot head (TheHub #61615).

spec 08 §3 makes "Patchwork never merges anything" a hard constraint, and it
is held by `GitHubClient` having no merge method (`tests/test_patchwork.py`).
That stays true: nothing here is on the client, its protocol or either
implementation, so Patchwork still has nothing to call.

This module is the deliberate, narrow exception the operator decided on
2026-11-13 for dependency bumps, and it is narrow by construction:

- **Only `dependabot[bot]`.** The pull request is read again here, and one
  opened by anybody else is refused before GitHub is asked.
- **Only the approved head.** The merge sends `sha`, GitHub's
  `--match-head-commit`: a push after the approval makes GitHub refuse it
  with 409 instead of merging a commit nobody approved.
- **Only squash**, the estate's merge method.
- **Only from the autopilot job, and only in `live` mode**
  (`dependabot_autopilot_mode`). `tests/test_dependabot_autopilot.py` fails
  if any other module in the backend sends a merge.

**What is not a control here.** The job's selector reads the pull request's
title, branch and body, and anyone with triage can edit a body. A push to a
`dependabot/*` branch leaves the pull request's `user.login` as
`dependabot[bot]`, so the author check says who *opened* it, not who wrote
the head. Neither is relied on. The controls are: every changed file lies
inside the group's manifests and lockfiles (`AutopilotGroup.owns`); every
required check and `library-allowlist` is green on the current head; and a
person or the platform reviewer approves the real diff of that head through
`pull_request_merge`, whose evidence the platform reads from GitHub itself.

It spends `contents: write`, which the App already holds for the Workflow
Installer (D-008); `REQUIRED_PERMISSIONS` is not widened by it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from mykronos.github.client import GitHubClient, GitHubError, RestGitHubClient

DEPENDABOT_LOGIN = "dependabot[bot]"

#: What the merge spends, declared beside it the way `METHOD_PERMISSIONS`
#: declares the client's: held already, so nothing is widened.
MERGE_PERMISSION = ("contents", "write")


class MergeRefusedError(Exception):
    """The merge was not attempted, or GitHub refused it; the message says which."""


@dataclass(frozen=True)
class MergeResult:
    repo_full_name: str
    number: int
    head_sha: str
    merge_commit_sha: str


class Merger(Protocol):
    async def squash_at_head(
        self, repo_full_name: str, number: int, *, head_sha: str, message: str
    ) -> MergeResult: ...


class AppSquashMerger:
    """Squash-merges through the GitHub App's installation token."""

    def __init__(self, github: RestGitHubClient) -> None:
        self.github = github

    async def squash_at_head(
        self, repo_full_name: str, number: int, *, head_sha: str, message: str
    ) -> MergeResult:
        pr = await self.github.get_pull_request(repo_full_name, number)
        if pr is None or pr.state != "open" or pr.merged:
            raise MergeRefusedError(f"{repo_full_name}#{number} is no longer open.")
        if pr.author != DEPENDABOT_LOGIN:
            raise MergeRefusedError(
                f"{repo_full_name}#{number} was opened by {pr.author or 'an unknown author'}, "
                f"not {DEPENDABOT_LOGIN}; the platform merges nothing else."
            )
        if pr.head_sha != head_sha:
            raise MergeRefusedError(
                f"{repo_full_name}#{number} moved to {pr.head_sha[:12]} after the approval "
                f"of {head_sha[:12]}."
            )
        response = await self.github._request(
            "PUT",
            f"/repos/{repo_full_name}/pulls/{number}/merge",
            json={"merge_method": "squash", "sha": head_sha, "commit_message": message},
        )
        if response.status_code >= 400:
            raise MergeRefusedError(
                f"GitHub refused the merge of {repo_full_name}#{number} at "
                f"{head_sha[:12]}: {response.status_code} {response.text[:300]}"
            )
        payload: dict[str, Any] = response.json() if response.content else {}
        return MergeResult(repo_full_name, number, head_sha, str(payload.get("sha") or ""))


def merger_for(github: GitHubClient) -> Merger:
    """The App's merger for a live client; a refusal for anything else.

    The demo and the tests run on `FakeGitHubClient`, which has no token to
    merge with; the job then records the refusal as the item's reason."""
    if isinstance(github, RestGitHubClient):
        return AppSquashMerger(github)
    raise GitHubError(f"{type(github).__name__} cannot merge; only the App's live client can.")
