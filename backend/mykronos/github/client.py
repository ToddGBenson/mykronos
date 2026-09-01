"""GitHub API surface the platform actually uses (spec 02, spec 03).

Kept deliberately narrow. Only the operations the Workflow Installer and
onboarding need appear here, so the App's permission set stays reviewable
against a short list rather than against "whatever the client library can do".

`FakeGitHubClient` is a real in-memory implementation, not a stub of
convenience: it enforces the same preconditions the API does — a workflow
file write requires `workflows: write`, a secret write requires
`secrets: write`, a branch must exist before you commit to it. Installer
logic tested against it is tested against the rules that actually bite.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

import httpx2

from mykronos.github.auth import AppCredentials, InstallationTokenCache
from mykronos.github.secrets import RepoPublicKey
from mykronos.schemas import utcnow

GITHUB_API = "https://api.github.com"

#: The permission set spec 02 §4 requires, after D-008. `workflows` and
#: `secrets` were both missing from the original spec and are both mandatory:
#: without them the installer cannot commit a workflow file or provision the
#: ingestion secret.
REQUIRED_PERMISSIONS = {
    "contents": "write",
    "workflows": "write",
    "secrets": "write",
    "pull_requests": "write",
    "checks": "write",
    "actions": "write",
    # Spent only by the i2i process opening/updating a groomed story (spec
    # 17 §7.2) — deliberately distinct from `pull_requests`, since an issue
    # is a work item, not a repository content change.
    "issues": "write",
    "metadata": "read",
}

#: Permissions that unlock a capability without being required for one
#: (spec 30 §1.2). Deliberately separate from the set above, and the
#: separation is the decision rather than a filing choice.
#:
#: `administration: read` is what lets the platform read branch protection and
#: rulesets. Putting it in `REQUIRED_PERMISSIONS` would fail the spec 02 §8
#: permission smoke test for **every installation that already exists**,
#: turning an additive new panel into a breaking change for the whole estate —
#: and it would do so to read settings that are useful and are not necessary
#: for anything else the platform does.
#:
#: An App without it reports every governance control as `unknown`, with the
#: reason and the permission named. That is the correct outcome: a permissions
#: gap is not a security failure and must never be scored as one.
OPTIONAL_PERMISSIONS = {
    "administration": "read",
}

WORKFLOW_PATH_PREFIX = ".github/workflows/"


class GitHubError(RuntimeError):
    """A GitHub API call failed in a way the caller must handle."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PermissionDeniedError(GitHubError):
    """The installation lacks a permission the operation requires.

    Raised separately because this is the D-008 failure mode: it means the App
    is registered wrong, and no amount of retrying will help.
    """


@dataclass(frozen=True)
class IssueRef:
    """What `create_issue`/`update_issue` need to hand back (spec 17 §7.2) —
    enough to record on a `TriageStory` and link to from the dashboard,
    nothing more. Not a full issue model: nothing here reads an issue back."""

    number: int
    url: str


@dataclass(frozen=True)
class WorkflowRef:
    """One workflow as GitHub knows it (spec 32 §6).

    `state` is GitHub's own vocabulary and is deliberately passed through
    rather than reduced to a boolean. `disabled_manually` and
    `disabled_inactivity` are both "not running" and they are not the same
    fact: the first is somebody's decision, the second is GitHub switching a
    scheduled workflow off after 60 days without a push. Collapsing them
    hides a real coverage gap behind a deliberate pause.

    Known values: `active`, `disabled_manually`, `disabled_inactivity`,
    `disabled_fork`. Unknown values pass through unaltered — a vocabulary
    GitHub extends must not become an exception here.
    """

    #: The filename, e.g. `mykronos-sast.yml`. The identifier every other
    #: method here takes, and the one the installer chose.
    file_name: str
    name: str
    state: str
    url: str = ""

    @property
    def enabled(self) -> bool:
        return self.state == "active"


@dataclass(frozen=True)
class WorkflowRun:
    """One completed workflow run (spec 32 §7).

    The Actions analogue of Concourse's `finished_build`, and carrying the
    same three things a link needs: what it was, how it ended, and when.
    Deliberately not the run's logs — those hold scanner output, and spec 15
    §4a's rule that the status read never reads logs is not weakened by
    changing which CI it reads.
    """

    workflow_file: str
    #: GitHub's `conclusion`, verbatim. Translated to the platform's status
    #: vocabulary in `ci.py`, where the two systems are already reconciled,
    #: rather than here — this stays a transport.
    conclusion: str | None
    run_number: int | None
    url: str
    finished_at: datetime | None


@dataclass
class FileChange:
    """One staged file addition, update or deletion."""

    path: str
    content: str | None
    """None means delete."""

    @property
    def is_delete(self) -> bool:
        return self.content is None

    @property
    def is_workflow(self) -> bool:
        return self.path.startswith(WORKFLOW_PATH_PREFIX)


@dataclass
class PullRequest:
    number: int
    url: str
    head_branch: str
    state: str = "open"
    merged: bool = False
    #: Patchwork's pull requests are always draft (spec 08 §3). Recorded on
    #: the object so a test can assert it rather than trusting the caller.
    draft: bool = False
    title: str = ""
    created_at: datetime | None = None
    changed_files: int | None = None
    head_sha: str = ""


def _parse_time(value: object) -> datetime | None:
    """GitHub's ISO-8601 with a `Z`, which `fromisoformat` rejects before 3.11
    and which is worth not crashing a whole page over regardless."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class ChecksSummary:
    """How a commit's checks are going, for a human deciding whether to merge.

    Deliberately counts rather than a verdict. "2 failed" and "all green" are
    different questions to a reviewer, and collapsing them into a boolean
    throws away the one that decides whether they look closer.
    """

    total: int = 0
    passed: int = 0
    failed: int = 0
    pending: int = 0


class GitHubClient(Protocol):
    """What the platform needs from GitHub. Nothing more."""

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]: ...

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        """Return file contents, or None if it does not exist."""

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None: ...

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        """Commit staged changes to a branch. Returns the commit SHA."""

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None: ...

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest: ...

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest: ...

    async def get_pull_request(
        self, repo_full_name: str, number: int
    ) -> PullRequest | None:
        """Live state of one pull request, or None if it is gone.

        Read-only, and the dashboard's pull-request view depends on it being
        live rather than on what the platform last recorded: a PR merged or
        closed on GitHub while a webhook was undelivered would otherwise sit
        in the list looking like outstanding work forever.
        """

    async def list_open_pull_requests(
        self, repo_full_name: str, *, limit: int = 100
    ) -> list[PullRequest]:
        """Every open pull request on a repository, whoever opened it.

        The dashboard listed only the ones Mykronos itself opened — installs
        and Patchwork fixes — which made a page named "Pull requests" show
        nothing for a repository with fifteen open. A security platform that
        cannot see the changes people are actually proposing is looking at the
        wrong half of the repository.
        """
        ...

    async def get_checks_summary(
        self, repo_full_name: str, ref: str
    ) -> ChecksSummary: ...

    # NOTE: there is deliberately no `merge_pull_request` here, and there must
    # never be one added casually.
    #
    # spec 08 §3 makes "Patchwork never merges anything" a hard constraint.
    # That cannot be enforced by GitHub permissions — merging needs
    # `contents: write`, which the App already holds so the Workflow Installer
    # can commit workflow files at all (D-008). The constraint is enforced
    # here instead: there is no method to call, in this protocol or in either
    # implementation, and `tests/test_patchwork.py` fails if one appears.
    #
    # Adding merge support is therefore a visible change to a shared interface
    # with a failing test attached, rather than a config flag somebody flips.

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        """Close without merging, explaining why in a comment."""

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey: ...

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None: ...

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None: ...

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        """Publish a Check Run. Returns its id.

        This is the only Mykronos surface most developers ever see, so the
        summary is the product, not a log line.
        """

    async def get_branch_protection(
        self, repo_full_name: str, branch: str
    ) -> dict[str, Any] | None:
        """Branch protection for one branch, or `None` if there is none.

        `None` and `{}` are different answers and both are real (spec 30 §1):
        `None` means the branch is unprotected, which is a finding; a raised
        `GitHubError` means the platform could not look, which is not. The
        caller has to keep them apart, so this never converts one into the
        other.
        """

    async def get_rulesets(self, repo_full_name: str) -> list[dict[str, Any]]:
        """The newer ruleset model, which increasingly supersedes branch
        protection and which a repository may use *instead* (spec 30 §1.2).

        Read as well as branch protection rather than in place of it: a
        repository can have either, both, or neither, and reading only the
        older model would report a modern, well-governed repository as
        unprotected.
        """


    async def get_installation(self, installation_id: int) -> dict[str, Any]: ...

    async def dispatch_workflow(
        self,
        repo_full_name: str,
        workflow_file: str,
        ref: str,
        *,
        inputs: dict[str, str] | None = None,
    ) -> None:
        """Trigger an already-installed `workflow_dispatch`-enabled workflow
        now, rather than waiting for its next scheduled or push-triggered run
        (spec 17 §2.5). Fire-and-forget: GitHub's own dispatch API returns no
        run id synchronously, so there is nothing to hand back — the new run
        shows up wherever scan results already show up, once it completes."""

    async def list_workflows(self, repo_full_name: str) -> list[WorkflowRef]: ...

    async def latest_workflow_runs(self, repo_full_name: str) -> list[WorkflowRun]:
        """The most recent *completed* run of each workflow (spec 32 §7).

        One call for the whole repository, not one per workflow. The
        per-workflow endpoint would be tidier and would spend a request per
        lane on every read, against an installation rate limit shared with
        token rotation, the installer and Patchwork (§7.1) — the status
        panel is the least important consumer of that budget and must not be
        the greediest.

        Completed only, matching Concourse's `finished_build`: a run in
        progress has no outcome, and reporting one as anything would invent
        a result.

        **Known limitation: one page, and the page is repository-wide.** The
        100 newest completed runs across ALL workflows, so an infrequent lane
        in a busy repository falls off the end and comes back with no run at
        all - indistinguishable here from a workflow that has never run.

        Seen on ToddGBenson/keel on 2026-08-29: `pr-governance` and `ci`
        accounted for 66 of the 100, the oldest entry was 2026-08-13, and
        `mykronos-atlas` last ran on 2026-08-12. It had run five times and
        failed five times, and read `not_run`.

        Not fixed by paginating, which spends the request budget this single
        call exists to protect (§7.1). The honest fix is the per-workflow
        `runs` endpoint for lanes missing from the page - one extra request
        each, only for the lanes that need it. Left undone deliberately
        rather than unknowingly: a lane can still read as never-run when it
        has merely been quiet, and this is the reason.
        """

    async def set_workflow_state(
        self, repo_full_name: str, workflow_file: str, *, enabled: bool
    ) -> None:
        """Turn one installed workflow on or off without touching the file
        (spec 32 §6).

        The off switch spec 03 §3 did not have. Its `--soft-disable` sets the
        job to `if: false`, which is a commit, a pull request and a review
        round-trip — and what an operator needs when a lane is misbehaving is
        the `fly pause` equivalent that takes effect now. Installing and
        uninstalling stay pull requests, because those add and remove code;
        this only changes whether existing code runs.

        `workflow_file` is the filename, as with `dispatch_workflow`, so a
        caller never looks up a numeric id first. GitHub returns 204 with no
        body."""

    async def create_issue(
        self, repo_full_name: str, title: str, body: str, *, labels: list[str] | None = None
    ) -> IssueRef:
        """Open an i2i story as a GitHub issue (spec 17 §7.2).

        Issue creation, not pull-request creation, and not a merge — an
        issue is a work item, not a repository content change. Patchwork's
        structural "never merges" guarantee (spec 08 §3, enforced by the
        protocol having no merge method at all) is untouched either
        direction: this method crosses neither line."""

    async def update_issue(
        self,
        repo_full_name: str,
        number: int,
        *,
        title: str | None = None,
        body: str | None = None,
        labels: list[str] | None = None,
    ) -> None:
        """Re-grooming the same finding updates this issue rather than
        opening a second one (spec 17 §7.2) — the caller looks the issue up
        by `TriageStory.id`, this just applies the new content to it."""


# ---------------------------------------------------------------------------
# Fake
# ---------------------------------------------------------------------------


@dataclass
class FakeRepo:
    full_name: str
    default_branch: str = "main"
    files: dict[str, str] = field(default_factory=dict)
    branches: dict[str, dict[str, str]] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    pull_requests: list[PullRequest] = field(default_factory=list)
    check_runs: list[dict[str, Any]] = field(default_factory=list)
    dispatched_workflows: list[dict[str, Any]] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    #: Spec 30 §1. `None` is the default and means *unprotected*, which is the
    #: honest default for a fake repository nobody has configured — and is a
    #: different answer from "could not read", which is a raised error.
    branch_protection: dict[str, dict[str, Any]] = field(default_factory=dict)
    rulesets: list[dict[str, Any]] = field(default_factory=list)
    #: Workflow state by filename (spec 32 §6). Absent means the workflow
    #: exists as a file and GitHub has not been told otherwise, which is
    #: `active` — the same default a freshly merged install PR produces.
    workflow_states: dict[str, str] = field(default_factory=dict)
    #: Latest completed run per workflow filename (spec 32 §7). Absent means
    #: the workflow exists and has never finished a run — which is a real
    #: state (`not_run`) and not an error.
    workflow_runs: dict[str, WorkflowRun] = field(default_factory=dict)


class FakeGitHubClient:
    """In-memory GitHub, enforcing the preconditions that actually bite.

    `permissions` defaults to the correct post-D-008 set, plus the optional
    grants. Narrowing it is how the tests prove the installer fails loudly —
    and says why — when the App is registered without `workflows: write` or
    `secrets: write`, and how they prove the governance panel degrades to
    `unknown` rather than to a row of red crosses without
    `administration: read`.
    """

    def __init__(
        self,
        repos: dict[str, FakeRepo] | None = None,
        permissions: dict[str, str] | None = None,
    ) -> None:
        self.repos = repos or {}
        self.permissions = dict(
            {**REQUIRED_PERMISSIONS, **OPTIONAL_PERMISSIONS}
            if permissions is None
            else permissions
        )
        self.calls: list[tuple[str, str]] = []
        #: Bodies by PR number, so a test can assert what a reviewer would
        #: actually read rather than only that a PR was opened.
        self.pull_request_bodies: dict[int, str] = {}
        self._next_pr_number = 1
        self._next_issue_number = 1
        self.installations: dict[int, dict[str, Any]] = {}

    # -- helpers --------------------------------------------------------

    def add_repo(self, full_name: str, **kwargs: Any) -> FakeRepo:
        repo = FakeRepo(full_name=full_name, **kwargs)
        repo.branches.setdefault(repo.default_branch, dict(repo.files))
        self.repos[full_name] = repo
        return repo

    def _repo(self, full_name: str) -> FakeRepo:
        try:
            return self.repos[full_name]
        except KeyError:
            raise GitHubError(f"Repository {full_name} not found", status=404) from None

    def _require(self, permission: str, level: str, operation: str) -> None:
        held = self.permissions.get(permission)
        if held != level and not (level == "read" and held == "write"):
            raise PermissionDeniedError(
                f"{operation} requires '{permission}: {level}'. The Mykronos GitHub App "
                f"holds '{permission}: {held or 'none'}'. See spec 02 §4 — the App must be "
                "re-registered with the corrected permission set (D-008).",
                status=403,
            )

    # -- protocol -------------------------------------------------------

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]:
        self.calls.append(("get_repo", repo_full_name))
        repo = self._repo(repo_full_name)
        return {"full_name": repo.full_name, "default_branch": repo.default_branch}

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        self.calls.append(("get_file", f"{repo_full_name}:{path}@{ref}"))
        repo = self._repo(repo_full_name)
        return repo.branches.get(ref, repo.files).get(path)

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None:
        self.calls.append(("create_branch", f"{repo_full_name}:{branch}"))
        self._require("contents", "write", "Creating a branch")
        repo = self._repo(repo_full_name)
        if from_ref not in repo.branches:
            raise GitHubError(f"Base ref {from_ref} does not exist", status=422)
        repo.branches[branch] = dict(repo.branches[from_ref])

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        self.calls.append(("commit_files", f"{repo_full_name}:{branch}"))
        self._require("contents", "write", "Committing files")
        if any(change.is_workflow for change in changes):
            # The D-008 failure: GitHub gates .github/workflows/ behind its own
            # permission and refuses a contents-only token for those paths.
            self._require("workflows", "write", "Committing a GitHub Actions workflow file")

        repo = self._repo(repo_full_name)
        if branch not in repo.branches:
            raise GitHubError(f"Branch {branch} does not exist", status=422)

        tree = repo.branches[branch]
        for change in changes:
            if change.is_delete:
                tree.pop(change.path, None)
            else:
                assert change.content is not None
                tree[change.path] = change.content
        return f"sha-{abs(hash((branch, len(tree), message))) % 10**7:07d}"

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None:
        self.calls.append(("find_open_pull_request", repo_full_name))
        repo = self._repo(repo_full_name)
        for pr in repo.pull_requests:
            if pr.state == "open" and pr.head_branch.startswith(head_branch_prefix):
                return pr
        return None

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest:
        self.calls.append(("create_pull_request", repo_full_name))
        self._require("pull_requests", "write", "Opening a pull request")
        repo = self._repo(repo_full_name)
        self.pull_request_bodies[self._next_pr_number] = body
        pr = PullRequest(
            number=self._next_pr_number,
            url=f"https://github.com/{repo_full_name}/pull/{self._next_pr_number}",
            head_branch=head,
            draft=draft,
            # Recorded rather than discarded. The fake took a title and threw
            # it away, so every pull request it produced had an empty one and
            # any test asserting on titles was quietly asserting against "".
            title=title,
        )
        self._next_pr_number += 1
        repo.pull_requests.append(pr)
        return pr

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest:
        self.calls.append(("update_pull_request", f"{repo_full_name}#{number}"))
        self._require("pull_requests", "write", "Updating a pull request")
        repo = self._repo(repo_full_name)
        for pr in repo.pull_requests:
            if pr.number == number:
                return pr
        raise GitHubError(f"Pull request #{number} not found", status=404)

    async def list_open_pull_requests(
        self, repo_full_name: str, *, limit: int = 100
    ) -> list[PullRequest]:
        self.calls.append(("list_open_pull_requests", repo_full_name))
        return [
            pr
            for pr in self._repo(repo_full_name).pull_requests
            if pr.state == "open" and not pr.merged
        ][:limit]

    async def get_pull_request(
        self, repo_full_name: str, number: int
    ) -> PullRequest | None:
        self.calls.append(("get_pull_request", f"{repo_full_name}#{number}"))
        for pr in self._repo(repo_full_name).pull_requests:
            if pr.number == number:
                return pr
        return None

    async def get_checks_summary(
        self, repo_full_name: str, ref: str
    ) -> ChecksSummary:
        self.calls.append(("get_checks_summary", f"{repo_full_name}@{ref}"))
        summary = ChecksSummary()
        for run in self._repo(repo_full_name).check_runs:
            if run.get("head_sha") != ref:
                continue
            summary.total += 1
            conclusion = run.get("conclusion")
            if conclusion in {"success", "neutral", "skipped"}:
                summary.passed += 1
            elif conclusion is None:
                summary.pending += 1
            else:
                summary.failed += 1
        return summary

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        self.calls.append(("close_pull_request", f"{repo_full_name}#{number}"))
        self._require("pull_requests", "write", "Closing a pull request")
        for pr in self._repo(repo_full_name).pull_requests:
            if pr.number == number:
                pr.state = "closed"
                pr.merged = False
                return
        raise GitHubError(f"Pull request #{number} not found", status=404)

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey:
        self.calls.append(("get_actions_public_key", repo_full_name))
        self._require("secrets", "write", "Reading the Actions public key")
        self._repo(repo_full_name)
        # A fixed, published test key. Real sealing is exercised in
        # tests/test_github.py against a generated keypair.
        return RepoPublicKey(
            key_id="568250167242549743",
            key_base64="2Sg8iYjAxxmI2LvUXpJjkYrMxURPc8r+dB7TJyvvcCU=",
        )

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None:
        self.calls.append(("put_actions_secret", f"{repo_full_name}:{name}"))
        self._require("secrets", "write", "Creating an Actions secret")
        self._repo(repo_full_name).secrets[name] = encrypted_value

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None:
        self.calls.append(("delete_actions_secret", f"{repo_full_name}:{name}"))
        self._require("secrets", "write", "Deleting an Actions secret")
        self._repo(repo_full_name).secrets.pop(name, None)

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        self.calls.append(("create_check_run", f"{repo_full_name}@{head_sha}"))
        self._require("checks", "write", "Posting a check run")
        repo = self._repo(repo_full_name)
        check_id = f"check-{len(repo.check_runs) + 1}"
        repo.check_runs.append(
            {
                "id": check_id,
                "name": name,
                "head_sha": head_sha,
                "conclusion": conclusion,
                "title": title,
                "summary": summary,
            }
        )
        return check_id

    async def get_branch_protection(
        self, repo_full_name: str, branch: str
    ) -> dict[str, Any] | None:
        self.calls.append(("get_branch_protection", f"{repo_full_name}:{branch}"))
        self._require("administration", "read", "Reading branch protection")
        return self._repo(repo_full_name).branch_protection.get(branch)

    async def get_rulesets(self, repo_full_name: str) -> list[dict[str, Any]]:
        self.calls.append(("get_rulesets", repo_full_name))
        self._require("administration", "read", "Reading rulesets")
        return list(self._repo(repo_full_name).rulesets)

    async def get_installation(self, installation_id: int) -> dict[str, Any]:
        self.calls.append(("get_installation", str(installation_id)))
        try:
            return self.installations[installation_id]
        except KeyError:
            raise GitHubError(f"Installation {installation_id} not found", status=404) from None

    async def dispatch_workflow(
        self,
        repo_full_name: str,
        workflow_file: str,
        ref: str,
        *,
        inputs: dict[str, str] | None = None,
    ) -> None:
        self.calls.append(("dispatch_workflow", f"{repo_full_name}/{workflow_file}@{ref}"))
        self._require("actions", "write", "Dispatching a workflow run")
        repo = self._repo(repo_full_name)
        repo.dispatched_workflows.append(
            {"workflow_file": workflow_file, "ref": ref, "inputs": inputs or {}}
        )

    async def list_workflows(self, repo_full_name: str) -> list[WorkflowRef]:
        self.calls.append(("list_workflows", repo_full_name))
        self._require("actions", "read", "Listing workflows")
        repo = self._repo(repo_full_name)
        out: list[WorkflowRef] = []
        for path in sorted(repo.files):
            if not path.startswith(WORKFLOW_PATH_PREFIX):
                continue
            file_name = path[len(WORKFLOW_PATH_PREFIX) :]
            out.append(
                WorkflowRef(
                    file_name=file_name,
                    name=file_name,
                    state=repo.workflow_states.get(file_name, "active"),
                    url=f"https://github.com/{repo_full_name}/actions/workflows/{file_name}",
                )
            )
        return out

    async def latest_workflow_runs(self, repo_full_name: str) -> list[WorkflowRun]:
        self.calls.append(("latest_workflow_runs", repo_full_name))
        self._require("actions", "read", "Reading workflow runs")
        repo = self._repo(repo_full_name)
        return [
            run
            for name, run in sorted(repo.workflow_runs.items())
            if f"{WORKFLOW_PATH_PREFIX}{name}" in repo.files
        ]

    async def set_workflow_state(
        self, repo_full_name: str, workflow_file: str, *, enabled: bool
    ) -> None:
        self.calls.append(
            ("set_workflow_state", f"{repo_full_name}/{workflow_file}={enabled}")
        )
        self._require("actions", "write", "Enabling or disabling a workflow")
        repo = self._repo(repo_full_name)
        # 404 on a workflow that is not installed, as GitHub does. Silently
        # recording state for a file that does not exist would let a caller
        # "disable" a capability that was never installed and report success.
        if f"{WORKFLOW_PATH_PREFIX}{workflow_file}" not in repo.files:
            raise GitHubError(
                f"{repo_full_name} has no workflow {workflow_file}", status=404
            )
        repo.workflow_states[workflow_file] = "active" if enabled else "disabled_manually"

    async def create_issue(
        self, repo_full_name: str, title: str, body: str, *, labels: list[str] | None = None
    ) -> IssueRef:
        self.calls.append(("create_issue", f"{repo_full_name}:{title}"))
        self._require("issues", "write", "Opening an issue")
        repo = self._repo(repo_full_name)
        number = self._next_issue_number
        self._next_issue_number += 1
        repo.issues.append(
            {
                "number": number,
                "title": title,
                "body": body,
                "labels": list(labels or []),
                "state": "open",
            }
        )
        return IssueRef(number=number, url=f"https://github.com/{repo_full_name}/issues/{number}")

    async def update_issue(
        self,
        repo_full_name: str,
        number: int,
        *,
        title: str | None = None,
        body: str | None = None,
        labels: list[str] | None = None,
    ) -> None:
        self.calls.append(("update_issue", f"{repo_full_name}#{number}"))
        self._require("issues", "write", "Updating an issue")
        repo = self._repo(repo_full_name)
        issue = next((i for i in repo.issues if i["number"] == number), None)
        if issue is None:
            raise GitHubError(f"Issue #{number} not found on {repo_full_name}", status=404)
        if title is not None:
            issue["title"] = title
        if body is not None:
            issue["body"] = body
        if labels is not None:
            issue["labels"] = list(labels)


# ---------------------------------------------------------------------------
# Real
# ---------------------------------------------------------------------------


class RestGitHubClient:
    """The live client. Mints installation tokens on demand and caches them.

    Not exercised by the test suite — there is nothing meaningful to assert
    about it without a registered App, and asserting against a mocked
    transport would only test the mock. It is covered by the permission smoke
    test in spec 02 §8, which is a Phase 1 entry gate precisely because this
    code cannot be proven correct any other way.
    """

    def __init__(
        self,
        credentials: AppCredentials,
        installation_id: int,
        cache: InstallationTokenCache | None = None,
        base_url: str = GITHUB_API,
    ) -> None:
        self.credentials = credentials
        self.installation_id = installation_id
        self.cache = cache or InstallationTokenCache()
        self.base_url = base_url

    async def _token(self) -> str:
        cached = self.cache.get(self.installation_id)
        if cached is not None:
            return cached

        # Retried, and only here. Minting a token is safe to repeat -- an
        # unused installation token costs nothing -- where the calls in
        # `_request` include PRs and commits, and a POST replayed after a
        # dropped connection can open the same pull request twice.
        #
        # A transport failure is the retryable kind by construction:
        # PermissionDeniedError exists precisely because a misregistered App is
        # the failure no amount of retrying helps, which leaves the dropped
        # connection as the failure it does.
        response: httpx2.Response | None = None
        for attempt in range(3):
            try:
                async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
                    response = await http.post(
                        f"/app/installations/{self.installation_id}/access_tokens",
                        headers={
                            "Authorization": f"Bearer {self.credentials.app_jwt()}",
                            "Accept": "application/vnd.github+json",
                        },
                    )
                break
            except httpx2.HTTPError as exc:
                if attempt == 2:
                    # Raised as GitHubError rather than allowed to escape as an
                    # httpx exception. Callers already handle GitHubError and
                    # degrade one finding to `no_fix_available`; a raw transport
                    # error is not that type, so it sailed past every handler
                    # and failed the whole Patchwork run with a bare 500 that
                    # said only "Internal Server Error".
                    raise GitHubError(
                        f"Could not reach GitHub to mint an installation token: {exc}"
                    ) from exc
        if response is None:  # unreachable: the last attempt raises
            raise GitHubError("Could not reach GitHub to mint an installation token.")
        if response.status_code >= 400:
            raise GitHubError(
                f"Could not mint an installation token: {response.text}",
                status=response.status_code,
            )
        payload = response.json()
        expires = payload.get("expires_at", "")
        expires_at = (
            __import__("datetime").datetime.fromisoformat(expires.replace("Z", "+00:00"))
            .replace(tzinfo=None)
            if expires
            else utcnow()
        )
        self.cache.put(self.installation_id, payload["token"], expires_at)
        return str(payload["token"])

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx2.Response:
        token = await self._token()
        try:
            async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
                response = await http.request(
                    method,
                    path,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    **kwargs,
                )
        except httpx2.HTTPError as exc:
            # Translated, not retried: this carries POSTs that open pull
            # requests and PATCHes that move refs, and a replay after a dropped
            # connection is a duplicate PR rather than a recovery. Callers know
            # how to handle GitHubError; they cannot be expected to know httpx.
            raise GitHubError(f"{method} {path} failed to reach GitHub: {exc}") from exc
        if response.status_code == 401:
            # The cached token was revoked or rotated early; drop it so the
            # next attempt mints a fresh one rather than looping on a dead one.
            self.cache.invalidate(self.installation_id)
        if response.status_code == 403 and "workflow" in response.text.lower():
            raise PermissionDeniedError(
                "GitHub refused a workflow-file write. The App is missing "
                "'workflows: write' (spec 02 §4, D-008).",
                status=403,
            )
        return response

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self._request(method, path, **kwargs)
        if response.status_code >= 400:
            raise GitHubError(
                f"{method} {path} -> {response.status_code}: {response.text[:400]}",
                status=response.status_code,
            )
        return response.json() if response.content else {}

    # -- protocol -------------------------------------------------------

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]:
        return dict(await self._json("GET", f"/repos/{repo_full_name}"))

    async def get_branch_protection(
        self, repo_full_name: str, branch: str
    ) -> dict[str, Any] | None:
        response = await self._request(
            "GET", f"/repos/{repo_full_name}/branches/{branch}/protection"
        )
        if response.status_code == 404:
            # GitHub returns 404 for "this branch is not protected", which is
            # an answer and not a failure. Returned as `None` so the caller can
            # report *unprotected*; a 403 still raises, because "we were not
            # allowed to look" must never render as "there is no protection".
            return None
        if response.status_code >= 400:
            raise GitHubError(
                f"Could not read branch protection for {repo_full_name}: "
                f"{response.text[:400]}",
                status=response.status_code,
            )
        return dict(response.json())

    async def get_rulesets(self, repo_full_name: str) -> list[dict[str, Any]]:
        # `includes_parents` so an organisation-level ruleset counts: a
        # repository governed entirely from the org would otherwise report as
        # having no rules at all.
        rules = await self._json(
            "GET",
            f"/repos/{repo_full_name}/rulesets",
            params={"includes_parents": "true"},
        )
        return list(rules) if isinstance(rules, list) else []

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        response = await self._request(
            "GET", f"/repos/{repo_full_name}/contents/{path}", params={"ref": ref}
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GitHubError(
                f"Reading {path}@{ref} failed: {response.text[:200]}",
                status=response.status_code,
            )
        payload = response.json()
        if payload.get("encoding") != "base64":
            return str(payload.get("content", ""))
        return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None:
        base = await self._json("GET", f"/repos/{repo_full_name}/git/ref/heads/{from_ref}")
        await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base["object"]["sha"]},
        )

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        """One commit for the whole change set, via the Git Data API.

        Deliberately not the Contents API, which commits per file: a
        multi-capability install would land as several commits, and a failure
        halfway would leave the branch in a state that is neither the old
        capability set nor the new one.
        """
        head = await self._json("GET", f"/repos/{repo_full_name}/git/ref/heads/{branch}")
        head_sha = head["object"]["sha"]
        commit = await self._json("GET", f"/repos/{repo_full_name}/git/commits/{head_sha}")

        tree_entries: list[dict[str, Any]] = []
        for change in changes:
            if change.is_delete:
                # A null sha is how the Git Data API expresses a deletion.
                blob_sha = None
            else:
                blob = await self._json(
                    "POST",
                    f"/repos/{repo_full_name}/git/blobs",
                    json={"content": change.content, "encoding": "utf-8"},
                )
                blob_sha = blob["sha"]
            tree_entries.append(
                {"path": change.path, "mode": "100644", "type": "blob", "sha": blob_sha}
            )

        tree = await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/trees",
            json={"base_tree": commit["tree"]["sha"], "tree": tree_entries},
        )
        new_commit = await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/commits",
            json={"message": message, "tree": tree["sha"], "parents": [head_sha]},
        )
        await self._json(
            "PATCH",
            f"/repos/{repo_full_name}/git/refs/heads/{branch}",
            json={"sha": new_commit["sha"], "force": True},
        )
        return str(new_commit["sha"])

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None:
        payload = await self._json(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            params={"state": "open", "per_page": 100},
        )
        for item in payload:
            ref = (item.get("head") or {}).get("ref", "")
            if ref.startswith(head_branch_prefix):
                return PullRequest(
                    number=int(item["number"]),
                    url=str(item["html_url"]),
                    head_branch=ref,
                    state=str(item.get("state", "open")),
                    merged=bool(item.get("merged_at")),
                )
        return None

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest:
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/pulls",
            json={
                "head": head,
                "base": base,
                "title": title,
                "body": body,
                "draft": draft,
            },
        )
        return PullRequest(
            number=int(item["number"]),
            url=str(item["html_url"]),
            head_branch=head,
            draft=bool(item.get("draft", draft)),
        )

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest:
        item = await self._json(
            "PATCH",
            f"/repos/{repo_full_name}/pulls/{number}",
            json={"title": title, "body": body},
        )
        return PullRequest(
            number=int(item["number"]),
            url=str(item["html_url"]),
            head_branch=(item.get("head") or {}).get("ref", ""),
        )

    async def get_pull_request(
        self, repo_full_name: str, number: int
    ) -> PullRequest | None:
        try:
            item = await self._json("GET", f"/repos/{repo_full_name}/pulls/{number}")
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise
        return PullRequest(
            number=int(item["number"]),
            url=str(item["html_url"]),
            head_branch=(item.get("head") or {}).get("ref", ""),
            state=str(item.get("state", "open")),
            merged=bool(item.get("merged_at")),
            draft=bool(item.get("draft", False)),
            title=str(item.get("title", "")),
            created_at=_parse_time(item.get("created_at")),
            changed_files=(
                int(item["changed_files"]) if item.get("changed_files") is not None else None
            ),
            head_sha=str((item.get("head") or {}).get("sha", "")),
        )

    async def list_open_pull_requests(
        self, repo_full_name: str, *, limit: int = 100
    ) -> list[PullRequest]:
        """Open pull requests, newest first.

        One page only. A repository with more than a hundred open pull
        requests has a problem this view cannot help with, and paginating for
        it would slow the common case for every other repository.

        `changed_files` is deliberately absent: the list endpoint does not
        return it, and fetching it would mean a second call per pull request.
        The detail view has it for the one somebody opens.
        """
        # Errors propagate. A repository the App cannot see is a real answer
        # for this view and the caller reports it as unreachable — swallowing
        # it here would render "no open pull requests", which is the one thing
        # it definitely does not mean.
        payload = await self._json(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            params={
                "state": "open",
                "sort": "created",
                "direction": "desc",
                "per_page": min(limit, 100),
            },
        )
        items = payload if isinstance(payload, list) else []
        return [
            PullRequest(
                number=int(item["number"]),
                url=str(item["html_url"]),
                head_branch=(item.get("head") or {}).get("ref", ""),
                state=str(item.get("state", "open")),
                merged=bool(item.get("merged_at")),
                draft=bool(item.get("draft", False)),
                title=str(item.get("title", "")),
                created_at=_parse_time(item.get("created_at")),
                changed_files=None,
                head_sha=str((item.get("head") or {}).get("sha", "")),
            )
            for item in items[:limit]
        ]

    async def get_checks_summary(
        self, repo_full_name: str, ref: str
    ) -> ChecksSummary:
        payload = await self._json(
            "GET",
            f"/repos/{repo_full_name}/commits/{ref}/check-runs",
            params={"per_page": 100},
        )
        summary = ChecksSummary()
        for run in payload.get("check_runs", []):
            summary.total += 1
            if run.get("status") != "completed":
                summary.pending += 1
            elif run.get("conclusion") in {"success", "neutral", "skipped"}:
                summary.passed += 1
            else:
                summary.failed += 1
        return summary

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        if comment:
            # Comment before closing, so the explanation is already there for
            # anyone who reads the close notification.
            await self._json(
                "POST",
                f"/repos/{repo_full_name}/issues/{number}/comments",
                json={"body": comment},
            )
        await self._json(
            "PATCH", f"/repos/{repo_full_name}/pulls/{number}", json={"state": "closed"}
        )

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey:
        payload = await self._json(
            "GET", f"/repos/{repo_full_name}/actions/secrets/public-key"
        )
        return RepoPublicKey(key_id=str(payload["key_id"]), key_base64=str(payload["key"]))

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None:
        await self._json(
            "PUT",
            f"/repos/{repo_full_name}/actions/secrets/{name}",
            json={"encrypted_value": encrypted_value, "key_id": key_id},
        )

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None:
        response = await self._request(
            "DELETE", f"/repos/{repo_full_name}/actions/secrets/{name}"
        )
        # 404 is success for our purposes: the secret is gone either way.
        if response.status_code not in (204, 404):
            raise GitHubError(
                f"Deleting secret {name} failed: {response.text[:200]}",
                status=response.status_code,
            )

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/check-runs",
            json={
                "name": name,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    # GitHub truncates past 65535; do it ourselves so the cut
                    # is at a sensible place rather than mid-sentence.
                    "summary": summary[:60000],
                },
            },
        )
        return str(item["id"])

    async def get_installation(self, installation_id: int) -> dict[str, Any]:
        """Installation metadata, for the daily reconciliation (spec 02 §5.6).

        Authenticates with the App JWT rather than an installation token:
        asking an installation token whether its own installation still exists
        is circular, and it stops working at exactly the moment the answer
        becomes interesting.
        """
        async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
            response = await http.get(
                f"/app/installations/{installation_id}",
                headers={
                    "Authorization": f"Bearer {self.credentials.app_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if response.status_code >= 400:
            raise GitHubError(
                f"Installation {installation_id} lookup failed: {response.text[:200]}",
                status=response.status_code,
            )
        return dict(response.json())

    async def dispatch_workflow(
        self,
        repo_full_name: str,
        workflow_file: str,
        ref: str,
        *,
        inputs: dict[str, str] | None = None,
    ) -> None:
        """`workflow_file` is the filename GitHub already knows the workflow
        by (`sast.yml`, not a numeric workflow id) — the same identifier the
        Workflow Installer wrote it under (spec 03), so a caller never has to
        look up an id first. GitHub returns 204 with no body on success."""
        await self._json(
            "POST",
            f"/repos/{repo_full_name}/actions/workflows/{workflow_file}/dispatches",
            json={"ref": ref, "inputs": inputs or {}},
        )

    async def list_workflows(self, repo_full_name: str) -> list[WorkflowRef]:
        """Every workflow GitHub knows about in this repository, with its
        state (spec 32 §6).

        One page. A repository with more than 100 workflows exists in theory
        and not in this estate, and paginating a status read that §7.1 already
        wants to spend as few calls as possible on would buy nothing.
        """
        payload = await self._json(
            "GET", f"/repos/{repo_full_name}/actions/workflows", params={"per_page": 100}
        )
        out: list[WorkflowRef] = []
        for item in payload.get("workflows", []) or []:
            # `path` is `.github/workflows/<file>`; every other method here
            # takes the bare filename, so this normalises once rather than
            # making each caller strip it.
            path = str(item.get("path", ""))
            file_name = path.rsplit("/", 1)[-1]
            if not file_name:
                continue
            out.append(
                WorkflowRef(
                    file_name=file_name,
                    name=str(item.get("name") or file_name),
                    state=str(item.get("state") or "active"),
                    url=str(item.get("html_url") or ""),
                )
            )
        return out

    async def latest_workflow_runs(self, repo_full_name: str) -> list[WorkflowRun]:
        payload = await self._json(
            "GET",
            f"/repos/{repo_full_name}/actions/runs",
            params={"per_page": 100, "status": "completed"},
        )
        # Newest first, per GitHub. Keeping the first run seen for each
        # workflow is therefore keeping the latest, without sorting.
        latest: dict[str, WorkflowRun] = {}
        for item in payload.get("workflow_runs", []) or []:
            file_name = str(item.get("path", "")).rsplit("/", 1)[-1]
            if not file_name or file_name in latest:
                continue
            latest[file_name] = WorkflowRun(
                workflow_file=file_name,
                conclusion=str(item["conclusion"]) if item.get("conclusion") else None,
                run_number=int(item["run_number"]) if item.get("run_number") else None,
                url=str(item.get("html_url") or ""),
                finished_at=_parse_time(item.get("updated_at")),
            )
        return list(latest.values())

    async def set_workflow_state(
        self, repo_full_name: str, workflow_file: str, *, enabled: bool
    ) -> None:
        verb = "enable" if enabled else "disable"
        await self._json(
            "PUT", f"/repos/{repo_full_name}/actions/workflows/{workflow_file}/{verb}"
        )

    async def create_issue(
        self, repo_full_name: str, title: str, body: str, *, labels: list[str] | None = None
    ) -> IssueRef:
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/issues",
            json={"title": title, "body": body, "labels": list(labels or [])},
        )
        return IssueRef(number=int(item["number"]), url=str(item["html_url"]))

    async def update_issue(
        self,
        repo_full_name: str,
        number: int,
        *,
        title: str | None = None,
        body: str | None = None,
        labels: list[str] | None = None,
    ) -> None:
        payload: dict[str, Any] = {}
        if title is not None:
            payload["title"] = title
        if body is not None:
            payload["body"] = body
        if labels is not None:
            payload["labels"] = list(labels)
        if not payload:
            return
        await self._json("PATCH", f"/repos/{repo_full_name}/issues/{number}", json=payload)
