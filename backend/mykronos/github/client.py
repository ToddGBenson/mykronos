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
from urllib.parse import quote

import httpx2

from mykronos.github.auth import AppCredentials, InstallationTokenCache
from mykronos.github.secrets import RepoPublicKey
from mykronos.schemas import utcnow

GITHUB_API = "https://api.github.com"

#: The permission set spec 02 §4 requires, after D-008. `workflows` and
#: `secrets` were both missing from the original spec and are both mandatory:
#: without them the installer cannot commit a workflow file or provision the
#: ingestion secret.
#:
#: Every entry is earned by a method in `METHOD_PERMISSIONS` below, at exactly
#: this level, and `tests/test_github_permissions.py` holds the two in step
#: (D-161). `issues` is `read`: the platform reads a backlog's issues
#: (`po_issues`) and writes none, since TheHub owns work items (D-133).
REQUIRED_PERMISSIONS = {
    "contents": "write",
    "workflows": "write",
    "secrets": "write",
    "pull_requests": "write",
    "checks": "write",
    "actions": "write",
    "issues": "read",
    "metadata": "read",
}

#: What each `GitHubClient` method spends, as `(permission, level)` pairs.
#:
#: The permission set is reviewable only against its call sites, so they are
#: listed here rather than inferred (D-161). A method missing from this map,
#: a write the REST client sends that is not declared here at `write`, or a
#: `REQUIRED_PERMISSIONS` entry no method earns, each fails a test. Adding a
#: write therefore means declaring its permission here first, and the operator
#: then has to grant it on the App.
#:
#: `get_installation` is empty because it authenticates as the App (a JWT),
#: not as an installation. `project_field_values` needs
#: `organization_projects`, which no installation on a user account can hold;
#: it is declared so the test sees it, and `po_issues` falls back to labels.
METHOD_PERMISSIONS: dict[str, tuple[tuple[str, str], ...]] = {
    "get_repo": (("metadata", "read"),),
    "get_file": (("contents", "read"),),
    # A GraphQL read: POST, and still only `contents: read` (TheHub #60908).
    "get_files": (("contents", "read"),),
    "create_branch": (("contents", "write"),),
    # `workflows: write` only when a change touches `.github/workflows/`.
    "commit_files": (("contents", "write"), ("workflows", "write")),
    "list_tree": (("contents", "read"),),
    "languages": (("metadata", "read"),),
    "installation_repositories": (("metadata", "read"),),
    "find_open_pull_request": (("pull_requests", "read"),),
    "create_pull_request": (("pull_requests", "write"),),
    "update_pull_request": (("pull_requests", "write"),),
    "get_pull_request": (("pull_requests", "read"),),
    "list_open_pull_requests": (("pull_requests", "read"),),
    "pull_request_files": (("pull_requests", "read"),),
    "compare": (("contents", "read"),),
    "list_commits": (("contents", "read"),),
    "get_checks_summary": (("checks", "read"),),
    # The closing comment goes through the issues API, which accepts
    # `pull_requests: write` for a pull request.
    "close_pull_request": (("pull_requests", "write"),),
    "get_actions_public_key": (("secrets", "read"),),
    "put_actions_secret": (("secrets", "write"),),
    "create_check_run": (("checks", "write"),),
    "update_check_run": (("checks", "write"),),
    "get_branch_protection": (("administration", "read"),),
    "get_rulesets": (("administration", "read"),),
    "get_ruleset": (("administration", "read"),),
    "get_installation": (),
    "dispatch_workflow": (("actions", "write"),),
    "list_workflows": (("actions", "read"),),
    "latest_workflow_runs": (("actions", "read"),),
    "set_workflow_state": (("actions", "write"),),
    "issue_state": (("issues", "read"),),
    "list_issues": (("issues", "read"),),
    "project_field_values": (("organization_projects", "read"),),
}

#: Declared in `METHOD_PERMISSIONS` but never required: no App installed on a
#: user account can be granted it (see `po_issues._project_gates`).
UNGRANTABLE_PERMISSIONS = frozenset({"organization_projects"})

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
    #: The branch the run was for. Read only to apply a `workflow_run`
    #: trigger's `branches:` filter to an upstream's run (#504); None where
    #: GitHub did not say, which that filter treats as "cannot tell".
    head_branch: str | None = None


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
    #: The branch it merges into. Read for the comparison the approval
    #: evidence is built from: GitHub's own `base.sha` goes stale (D-152).
    base_branch: str = ""
    #: GitHub's merge verdict, from the single-PR read only (the list
    #: endpoint does not carry it). None when GitHub has not computed it yet
    #: or it was not read -- never guessed as True.
    mergeable: bool | None = None
    #: GitHub's `mergeable_state` (clean, dirty, blocked, behind, unstable,
    #: unknown, ...), passed through. Empty when not read.
    mergeable_state: str = ""
    #: The description, for the story ids and "stacks on #N" it names.
    body: str = ""


@dataclass
class PullRequestFile:
    """One file a pull request changes, as GitHub's `/pulls/{n}/files` lists it.

    `patch` is `None` for binary files and for diffs GitHub declines to
    render inline because they are too large.
    """

    filename: str
    status: str
    additions: int = 0
    deletions: int = 0
    patch: str | None = None
    previous_filename: str | None = None


#: GitHub's compare endpoint lists at most this many files, on its first page.
COMPARE_MAX_FILES = 300
#: ...and at most this many commits, on its first page.
COMPARE_MAX_COMMITS = 250


@dataclass
class Comparison:
    """`base...head` as GitHub's compare endpoint answers it: the files `head`
    changes since its merge-base with `base` as `base` is *now*."""

    files: list[PullRequestFile]
    merge_base_sha: str = ""
    #: Commits on `head` that `base` does not have, and the reverse. `ahead_by`
    #: is "how far behind the branch is the deployment" when `base` is the
    #: deployed revision and `head` the default branch (#452).
    ahead_by: int = 0
    behind_by: int = 0
    #: GitHub's own word: identical | ahead | behind | diverged. Empty when
    #: the comparison was not read from GitHub (a fake built for files only).
    status: str = ""
    #: The commits in `base...head`, oldest first, as GitHub lists them: the
    #: oldest `COMPARE_MAX_COMMITS` on the first page. `ahead_by` is the true
    #: count either way.
    commits: list[CommitInfo] = field(default_factory=list)
    #: What `head` resolved to, and when `base` was committed.
    head_sha: str = ""
    base_committed_at: datetime | None = None

    @property
    def truncated(self) -> bool:
        return len(self.files) >= COMPARE_MAX_FILES

    @property
    def commits_truncated(self) -> bool:
        """True when `commits` lists fewer than `ahead_by` commits."""
        return len(self.commits) < self.ahead_by


def _pull_request_file(item: dict[str, Any]) -> PullRequestFile:
    return PullRequestFile(
        filename=str(item["filename"]),
        status=str(item.get("status", "")),
        additions=int(item.get("additions") or 0),
        deletions=int(item.get("deletions") or 0),
        patch=item.get("patch"),
        previous_filename=item.get("previous_filename"),
    )


@dataclass
class CommitInfo:
    """One commit on a branch, with its full message (spec 35 §8.5).

    The full message, not the subject: a `Stories:` trailer is in the body.
    """

    sha: str
    message: str
    url: str = ""
    committed_at: datetime | None = None


@dataclass(frozen=True)
class IssueInfo:
    """One issue as the Product Owner tab reads it (spec 35 §9, B-072).

    Read only. Pull requests, which GitHub's issues endpoint also returns, are
    never one of these.
    """

    number: int
    title: str
    state: str
    labels: tuple[str, ...] = ()
    body: str = ""
    url: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None


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


#: Paths per GraphQL query in `get_files`. A hundred keeps each response a
#: few hundred KB for migration-sized files and well inside GitHub's node
#: limits; TheHub's migrations are then a handful of requests, not ~420.
FILES_PER_QUERY = 100


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

    async def list_tree(self, repo_full_name: str, ref: str) -> list[str] | None:
        """Every file path on `ref`, or None when the answer is not knowable.

        None means "could not look", and a caller must never read it as
        absence (B-058).
        """
        ...

    async def get_files(
        self, repo_full_name: str, paths: list[str], ref: str
    ) -> dict[str, str | None]:
        """Many files' contents at once, by path; None for a path that does
        not exist. Raises GitHubError when a batch cannot be read
        (TheHub #60908)."""
        ...

    async def languages(self, repo_full_name: str) -> dict[str, int] | None:
        """Bytes per language, or None when it could not be read (B-051)."""
        ...

    async def installation_repositories(self) -> list[str] | None:
        """Every repository this installation can see (B-051). None if unread."""
        ...

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

    async def list_commits(
        self,
        repo_full_name: str,
        ref: str,
        *,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[CommitInfo]:
        """Commits reachable from `ref`, newest first, with full messages.

        Errors propagate: "could not list" must never read as "no commits",
        which for the delivery trace is the claim "nothing delivered this".
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

    async def pull_request_files(
        self, repo_full_name: str, number: int
    ) -> list[PullRequestFile]:
        """Every file the pull request changes, with its patch where GitHub
        renders one. GitHub stops listing at 3,000 files.

        Measured against the pull request's `base.sha`, which GitHub does not
        always move when the base branch does: after main was merged into the
        branch this listed 42 files for a 9-file change (#775, 2026-10-11).
        Approval evidence uses `compare` instead (D-152)."""

    async def compare(self, repo_full_name: str, base: str, head: str) -> Comparison:
        """`base...head`: what `head` changes since its merge-base with `base`
        as it stands now. At most 300 files (`Comparison.truncated`)."""

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str | None,
        title: str,
        summary: str,
    ) -> str:
        """Publish a Check Run. Returns its id.

        `conclusion=None` posts it `in_progress`: a check that has not
        decided yet, which a required status check treats as not passing.

        This is the only Mykronos surface most developers ever see, so the
        summary is the product, not a log line.
        """

    async def update_check_run(
        self,
        repo_full_name: str,
        check_run_id: str,
        *,
        conclusion: str,
        title: str,
        summary: str,
    ) -> None:
        """Complete an existing Check Run with `conclusion` (D-136).

        Updating rather than posting again keeps one check per commit, so a
        lane that fails and then passes on a re-run ends as one green check
        rather than a red and a green under the same name.
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

    async def get_ruleset(self, repo_full_name: str, ruleset_id: int) -> dict[str, Any]:
        """One ruleset in full. The listing leaves out `conditions` and
        `rules`; this read carries them (TheHub #60972)."""

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

    async def issue_state(self, repo_full_name: str, number: int) -> str | None:
        """`open`, `closed`, or `None` if the issue is gone.

        Read, never assumed: whether a recurrence may land on an existing
        issue depends on that issue still being open, and it can have been
        closed by a person this platform never told."""

    async def list_issues(
        self,
        repo_full_name: str,
        *,
        state: str = "open",
        labels: list[str] | None = None,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[IssueInfo]:
        """Issues, never pull requests, carrying every label in `labels`.

        Needs `issues: read` (on a public repository GitHub also answers
        without it). `since` is naive UTC and filters on `updated_at`."""

    async def project_field_values(
        self, owner: str, project_number: int, field_name: str
    ) -> dict[str, dict[int, str]]:
        """A Projects (v2) single-select field for every issue on the board:
        `owner/repo` -> issue number -> option name. Issues with no value are
        absent.

        Raises `PermissionDeniedError` when the App cannot see the project.
        GraphQL answers that as NOT_FOUND, so a missing project and an
        unreadable one are the same answer here."""


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
    #: PR number -> the files it changes.
    pull_request_files: dict[int, list[PullRequestFile]] = field(default_factory=dict)
    #: (base, head) -> what `compare` answers. Unset, `compare` answers with
    #: the listing of the open PR whose head is `head`: the two agree unless a
    #: test says otherwise, and the stale-base test says otherwise.
    comparisons: dict[tuple[str, str], Comparison] = field(default_factory=dict)
    check_runs: list[dict[str, Any]] = field(default_factory=list)
    #: Bytes per language, as GitHub reports them (B-051). Empty by default,
    #: which reads as "nothing measured" rather than as "nothing analysable".
    languages: dict[str, int] = field(default_factory=dict)
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
    #: Commits on the default branch, newest first (spec 35 §8.5).
    commits: list[CommitInfo] = field(default_factory=list)
    #: GitHub's `visibility` (`private`, `internal`, `public`). `None` leaves
    #: both `visibility` and `private` out of `get_repo`, which is how a test
    #: asks for "GitHub did not say".
    visibility: str | None = "private"


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
        self.installations: dict[int, dict[str, Any]] = {}
        #: (owner, project number) -> `owner/repo` -> issue number -> the
        #: gate field's option name. Readable only with
        #: `organization_projects: read`, the one Projects permission a
        #: GitHub App can hold.
        self.projects: dict[tuple[str, int], dict[str, dict[int, str]]] = {}

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
        out: dict[str, Any] = {"full_name": repo.full_name, "default_branch": repo.default_branch}
        if repo.visibility is not None:
            out["visibility"] = repo.visibility
            out["private"] = repo.visibility == "private"
        return out

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        self.calls.append(("get_file", f"{repo_full_name}:{path}@{ref}"))
        repo = self._repo(repo_full_name)
        return repo.branches.get(ref, repo.files).get(path)

    async def get_files(
        self, repo_full_name: str, paths: list[str], ref: str
    ) -> dict[str, str | None]:
        """One recorded call per batch, as the live client makes one GraphQL
        request per `FILES_PER_QUERY` paths."""
        repo = self._repo(repo_full_name)
        tree = repo.branches.get(ref, repo.files)
        out: dict[str, str | None] = {}
        for start in range(0, len(paths), FILES_PER_QUERY):
            batch = paths[start : start + FILES_PER_QUERY]
            self.calls.append(("get_files", f"{repo_full_name}@{ref}:{len(batch)}"))
            out.update({path: tree.get(path) for path in batch})
        return out

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

    async def list_tree(self, repo_full_name: str, ref: str) -> list[str] | None:
        self.calls.append(("list_tree", repo_full_name))
        if repo_full_name not in self.repos:
            # The real client answers None for a repository it cannot read,
            # and a fake that answered [] instead would let a test prove
            # "nothing applies here" from a repository that does not exist.
            return None
        return sorted(self._repo(repo_full_name).files)

    async def installation_repositories(self) -> list[str] | None:
        self.calls.append(("installation_repositories", ""))
        return sorted(self.repos)

    async def languages(self, repo_full_name: str) -> dict[str, int] | None:
        self.calls.append(("languages", repo_full_name))
        if repo_full_name not in self.repos:
            return None
        return dict(self._repo(repo_full_name).languages)

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
            body=body,
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
                pr.title, pr.body = title, body
                self.pull_request_bodies[number] = body
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

    async def pull_request_files(
        self, repo_full_name: str, number: int
    ) -> list[PullRequestFile]:
        self.calls.append(("pull_request_files", f"{repo_full_name}#{number}"))
        return list(self._repo(repo_full_name).pull_request_files.get(number, []))

    async def compare(self, repo_full_name: str, base: str, head: str) -> Comparison:
        self.calls.append(("compare", f"{repo_full_name}@{base}...{head}"))
        repo = self._repo(repo_full_name)
        if (base, head) in repo.comparisons:
            return repo.comparisons[(base, head)]
        for pr in repo.pull_requests:
            if pr.head_sha == head:
                return Comparison(files=list(repo.pull_request_files.get(pr.number, [])))
        raise GitHubError(f"No comparison {base}...{head}", status=404)

    async def list_commits(
        self,
        repo_full_name: str,
        ref: str,
        *,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[CommitInfo]:
        self.calls.append(("list_commits", f"{repo_full_name}@{ref}"))
        commits = self._repo(repo_full_name).commits
        if since is not None:
            commits = [
                c
                for c in commits
                if c.committed_at is None or c.committed_at.replace(tzinfo=None) >= since
            ]
        return list(commits[:limit])

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

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str | None,
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

    async def update_check_run(
        self,
        repo_full_name: str,
        check_run_id: str,
        *,
        conclusion: str,
        title: str,
        summary: str,
    ) -> None:
        self.calls.append(("update_check_run", f"{repo_full_name}#{check_run_id}"))
        self._require("checks", "write", "Updating a check run")
        for run in self._repo(repo_full_name).check_runs:
            if run["id"] == check_run_id:
                run.update(conclusion=conclusion, title=title, summary=summary)
                return
        raise GitHubError(f"Check run {check_run_id} not found", status=404)

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

    async def get_ruleset(self, repo_full_name: str, ruleset_id: int) -> dict[str, Any]:
        self.calls.append(("get_ruleset", f"{repo_full_name}:{ruleset_id}"))
        self._require("administration", "read", "Reading a ruleset")
        for ruleset in self._repo(repo_full_name).rulesets:
            if ruleset.get("id") == ruleset_id:
                return dict(ruleset)
        raise GitHubError(f"Ruleset {ruleset_id} not found", status=404)

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

    async def issue_state(self, repo_full_name: str, number: int) -> str | None:
        self.calls.append(("issue_state", f"{repo_full_name}#{number}"))
        self._require("issues", "read", "Reading an issue")
        repo = self._repo(repo_full_name)
        issue = next((i for i in repo.issues if i["number"] == number), None)
        return None if issue is None else str(issue.get("state") or "open")

    async def list_issues(
        self,
        repo_full_name: str,
        *,
        state: str = "open",
        labels: list[str] | None = None,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[IssueInfo]:
        self.calls.append(("list_issues", f"{repo_full_name}:{state}"))
        self._require("issues", "read", "Listing issues")
        wanted = {label.lower() for label in labels or []}
        out: list[IssueInfo] = []
        for issue in sorted(
            self._repo(repo_full_name).issues, key=lambda i: int(i["number"]), reverse=True
        ):
            issue_state = str(issue.get("state") or "open")
            if state != "all" and issue_state != state:
                continue
            names = tuple(str(label) for label in issue.get("labels") or [])
            if not wanted <= {name.lower() for name in names}:
                continue
            updated = issue.get("updated_at")
            if since is not None and isinstance(updated, datetime) and updated < since:
                continue
            out.append(
                IssueInfo(
                    number=int(issue["number"]),
                    title=str(issue.get("title") or ""),
                    state=issue_state,
                    labels=names,
                    body=str(issue.get("body") or ""),
                    url=f"https://github.com/{repo_full_name}/issues/{issue['number']}",
                    created_at=issue.get("created_at"),
                    updated_at=updated,
                    closed_at=issue.get("closed_at"),
                )
            )
        return out[:limit]

    async def project_field_values(
        self, owner: str, project_number: int, field_name: str
    ) -> dict[str, dict[int, str]]:
        self.calls.append(("project_field_values", f"{owner}#{project_number}:{field_name}"))
        self._require("organization_projects", "read", "Reading a Projects board")
        project = self.projects.get((owner, project_number))
        if project is None:
            raise PermissionDeniedError(
                f"Project {owner}#{project_number} is not visible to the GitHub App.",
                status=404,
            )
        return {repo: dict(values) for repo, values in project.items()}


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

    async def get_ruleset(self, repo_full_name: str, ruleset_id: int) -> dict[str, Any]:
        rule = await self._json(
            "GET",
            f"/repos/{repo_full_name}/rulesets/{int(ruleset_id)}",
            params={"includes_parents": "true"},
        )
        return dict(rule) if isinstance(rule, dict) else {}

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

    async def get_files(
        self, repo_full_name: str, paths: list[str], ref: str
    ) -> dict[str, str | None]:
        """Many files at `ref`, one GraphQL request per `FILES_PER_QUERY`.

        The contents API is one request per file, and TheHub keeps several
        hundred migration files: the D-138 schema split cost ~426 calls per
        `mykronos briefing` (TheHub #60908). GraphQL reads a blob's text by
        `ref:path` expression, so a batch is one round trip.

        A path whose object is missing is None, as `get_file` answers 404. A
        blob GraphQL truncated, or whose text it would not give, is read whole
        through `get_file`, so the answer is never a silent prefix.
        """
        owner, _, name = repo_full_name.partition("/")
        out: dict[str, str | None] = {}
        for start in range(0, len(paths), FILES_PER_QUERY):
            batch = paths[start : start + FILES_PER_QUERY]
            variables: dict[str, str] = {"owner": owner, "name": name}
            fields = []
            for n, path in enumerate(batch):
                variables[f"e{n}"] = f"{ref}:{path}"
                fields.append(
                    f"f{n}: object(expression: $e{n}) {{ ... on Blob {{ text isTruncated }} }}"
                )
            declared = "".join(f", $e{n}: String!" for n in range(len(batch)))
            query = (
                f"query($owner: String!, $name: String!{declared}) "
                "{ repository(owner: $owner, name: $name) { " + " ".join(fields) + " } }"
            )
            payload = await self._json(
                "POST", "/graphql", json={"query": query, "variables": variables}
            )
            repository = (payload.get("data") or {}).get("repository")
            if repository is None:
                raise GitHubError(
                    f"Reading {len(batch)} file(s) of {repo_full_name}@{ref} failed: "
                    f"{str(payload.get('errors'))[:200]}"
                )
            for n, path in enumerate(batch):
                blob = repository.get(f"f{n}")
                if blob is None:
                    out[path] = None
                elif blob.get("isTruncated") or not isinstance(blob.get("text"), str):
                    out[path] = await self.get_file(repo_full_name, path, ref)
                else:
                    out[path] = str(blob["text"])
        return out

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

    async def list_tree(self, repo_full_name: str, ref: str) -> list[str] | None:
        """Every file path on `ref`, or None when the answer is not knowable.

        Used to decide whether an SSDF practice is *inapplicable* to a
        repository rather than merely unevidenced (B-058), which makes the
        failure mode specific and dangerous: a partial listing would say "no
        Dockerfile here" about a repository that has one, and on a compliance
        view that converts "we did not look" into "this does not apply to us".

        So None for anything short of a complete answer, and callers treat
        None as unknown and claim nothing. GitHub truncates this response
        above roughly 100k entries and says so in `truncated`, which is one of
        the cases that must read as unknown rather than as absence.
        """
        try:
            payload = await self._json(
                "GET",
                f"/repos/{repo_full_name}/git/trees/{ref}",
                params={"recursive": "1"},
            )
        except GitHubError:
            return None
        if payload.get("truncated"):
            return None
        return [
            str(entry["path"])
            for entry in payload.get("tree") or []
            if entry.get("type") == "blob" and entry.get("path")
        ]

    async def installation_repositories(self) -> list[str] | None:
        """Every repository this installation can see, or None if it cannot be
        read.

        The platform has always known what it was *told about* and never what
        exists. B-051's headline — four of eleven repositories watched — came
        from a person reading the account, so nothing could notice a
        repository nobody onboarded: `binnacle` sat unscanned with 30 shell
        scripts in it until somebody looked.

        This is the App answering for its own scope. It reports what the
        installation is granted, which is the whole account only if the
        installation is set to all repositories — so a small number here is a
        fact about the grant, not about the account, and the caller has to say
        which it is showing.
        """
        names: list[str] = []
        page = 1
        while True:
            try:
                payload = await self._json(
                    "GET",
                    "/installation/repositories",
                    params={"per_page": 100, "page": page},
                )
            except GitHubError:
                # None, never a partial list. A short answer here would read
                # as "the account has three repositories", which is the exact
                # false statement this exists to replace.
                return None
            batch = (payload or {}).get("repositories") or []
            names.extend(str(repo["full_name"]) for repo in batch if repo.get("full_name"))
            if len(batch) < 100:
                return sorted(names)
            page += 1
            if page > 20:
                # 2000 repositories is not this estate, and an unbounded loop
                # against a paginated API is how a status read becomes an
                # outage.
                return sorted(names)

    async def languages(self, repo_full_name: str) -> dict[str, int] | None:
        """Bytes per language, or None when it could not be read (B-051).

        None rather than an empty dict on failure, and the difference decides
        what a caller may say: an empty result means GitHub had nothing to
        report for a new or empty repository, while None means nobody looked.
        Reporting the second as the first would call every unreadable
        repository fully analysed.
        """
        try:
            payload = await self._json("GET", f"/repos/{repo_full_name}/languages")
        except GitHubError:
            return None
        return {str(name): int(count) for name, count in (payload or {}).items()}

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
            base_branch=str((item.get("base") or {}).get("ref", "")),
            mergeable=(
                bool(item["mergeable"]) if item.get("mergeable") is not None else None
            ),
            mergeable_state=str(item.get("mergeable_state") or ""),
            body=str(item.get("body") or ""),
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
                base_branch=str((item.get("base") or {}).get("ref", "")),
                body=str(item.get("body") or ""),
            )
            for item in items[:limit]
        ]

    async def pull_request_files(
        self, repo_full_name: str, number: int
    ) -> list[PullRequestFile]:
        files: list[PullRequestFile] = []
        # 100 per page, and GitHub lists at most 3,000 files: 30 pages.
        for page in range(1, 31):
            items = await self._json(
                "GET",
                f"/repos/{repo_full_name}/pulls/{number}/files",
                params={"per_page": 100, "page": page},
            )
            for item in items:
                files.append(_pull_request_file(item))
            if len(items) < 100:
                break
        return files

    async def compare(self, repo_full_name: str, base: str, head: str) -> Comparison:
        # Files come on the first page only, up to 300; no paging parameter
        # is sent, so this is that page.
        item = await self._json(
            "GET",
            f"/repos/{repo_full_name}/compare/{quote(base, safe='/')}...{quote(head, safe='/')}",
        )
        commits = [
            CommitInfo(
                sha=str(c.get("sha", "")),
                message=str((c.get("commit") or {}).get("message") or ""),
                url=str(c.get("html_url") or ""),
                committed_at=_parse_time(
                    ((c.get("commit") or {}).get("committer") or {}).get("date")
                ),
            )
            for c in item.get("commits") or []
            if isinstance(c, dict)
        ]
        base_commit = item.get("base_commit") or {}
        return Comparison(
            files=[_pull_request_file(f) for f in item.get("files") or []],
            merge_base_sha=str((item.get("merge_base_commit") or {}).get("sha", "")),
            ahead_by=int(item.get("ahead_by") or 0),
            behind_by=int(item.get("behind_by") or 0),
            status=str(item.get("status") or ""),
            commits=commits,
            # The last listed commit is `head` only when nothing was cut off;
            # the merge base plus `ahead_by` is not a sha, so leave it empty
            # rather than name the wrong commit.
            head_sha=commits[-1].sha if commits and len(commits) >= int(
                item.get("ahead_by") or 0
            ) else "",
            base_committed_at=_parse_time(
                ((base_commit.get("commit") or {}).get("committer") or {}).get("date")
            ),
        )

    async def list_commits(
        self,
        repo_full_name: str,
        ref: str,
        *,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[CommitInfo]:
        """Commits on `ref`, newest first, a hundred to a page, up to `limit`.

        `since` is naive UTC, as every timestamp here is.
        """
        out: list[CommitInfo] = []
        page = 1
        while len(out) < limit:
            params: dict[str, Any] = {"sha": ref, "per_page": 100, "page": page}
            if since is not None:
                params["since"] = since.replace(microsecond=0).isoformat() + "Z"
            payload = await self._json("GET", f"/repos/{repo_full_name}/commits", params=params)
            items = payload if isinstance(payload, list) else []
            for item in items:
                commit = item.get("commit") or {}
                out.append(
                    CommitInfo(
                        sha=str(item.get("sha", "")),
                        message=str(commit.get("message") or ""),
                        url=str(item.get("html_url") or ""),
                        committed_at=_parse_time((commit.get("committer") or {}).get("date")),
                    )
                )
            if len(items) < 100:
                break
            page += 1
        return out[:limit]

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

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str | None,
        title: str,
        summary: str,
    ) -> str:
        state: dict[str, Any] = (
            {"status": "in_progress"}
            if conclusion is None
            else {"status": "completed", "conclusion": conclusion}
        )
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/check-runs",
            json={
                "name": name,
                "head_sha": head_sha,
                **state,
                "output": {
                    "title": title,
                    # GitHub truncates past 65535; do it ourselves so the cut
                    # is at a sensible place rather than mid-sentence.
                    "summary": summary[:60000],
                },
            },
        )
        return str(item["id"])

    async def update_check_run(
        self,
        repo_full_name: str,
        check_run_id: str,
        *,
        conclusion: str,
        title: str,
        summary: str,
    ) -> None:
        await self._json(
            "PATCH",
            f"/repos/{repo_full_name}/check-runs/{check_run_id}",
            json={
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": title, "summary": summary[:60000]},
            },
        )

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
                head_branch=str(item["head_branch"]) if item.get("head_branch") else None,
            )
        return list(latest.values())

    async def set_workflow_state(
        self, repo_full_name: str, workflow_file: str, *, enabled: bool
    ) -> None:
        verb = "enable" if enabled else "disable"
        await self._json(
            "PUT", f"/repos/{repo_full_name}/actions/workflows/{workflow_file}/{verb}"
        )

    async def issue_state(self, repo_full_name: str, number: int) -> str | None:
        response = await self._request("GET", f"/repos/{repo_full_name}/issues/{number}")
        if response.status_code == 404:
            # An issue that was deleted or transferred is an answer, not a
            # failure — same reading as `get_branch_protection`'s 404. A 403
            # still raises: "we were not allowed to look" must never render
            # as "there is no issue".
            return None
        if response.status_code >= 400:
            raise GitHubError(
                f"Could not read {repo_full_name}#{number}: {response.text[:400]}",
                status=response.status_code,
            )
        return str(response.json().get("state") or "open")

    async def list_issues(
        self,
        repo_full_name: str,
        *,
        state: str = "open",
        labels: list[str] | None = None,
        since: datetime | None = None,
        limit: int = 300,
    ) -> list[IssueInfo]:
        out: list[IssueInfo] = []
        page = 1
        while len(out) < limit:
            params: dict[str, Any] = {"state": state, "per_page": 100, "page": page}
            if labels:
                params["labels"] = ",".join(labels)
            if since is not None:
                params["since"] = since.replace(microsecond=0).isoformat() + "Z"
            response = await self._request(
                "GET", f"/repos/{repo_full_name}/issues", params=params
            )
            if response.status_code in (403, 404):
                # A private repository without `issues: read` answers 404, not
                # 403. Either way it is the App's permission, never "no issues".
                raise PermissionDeniedError(
                    f"GitHub refused to list {repo_full_name}'s issues "
                    f"(HTTP {response.status_code}). The App needs 'issues: read'.",
                    status=response.status_code,
                )
            if response.status_code >= 400:
                raise GitHubError(
                    f"Listing {repo_full_name}'s issues failed (HTTP {response.status_code})",
                    status=response.status_code,
                )
            items = response.json() if response.content else []
            items = items if isinstance(items, list) else []
            for item in items:
                if "pull_request" in item:
                    continue
                out.append(
                    IssueInfo(
                        number=int(item["number"]),
                        title=str(item.get("title") or ""),
                        state=str(item.get("state") or "open"),
                        labels=tuple(
                            str(label.get("name") if isinstance(label, dict) else label)
                            for label in item.get("labels") or []
                        ),
                        body=str(item.get("body") or ""),
                        url=str(item.get("html_url") or ""),
                        created_at=_naive(_parse_time(item.get("created_at"))),
                        updated_at=_naive(_parse_time(item.get("updated_at"))),
                        closed_at=_naive(_parse_time(item.get("closed_at"))),
                    )
                )
            if len(items) < 100:
                break
            page += 1
        return out[:limit]

    async def project_field_values(
        self, owner: str, project_number: int, field_name: str
    ) -> dict[str, dict[int, str]]:
        out: dict[str, dict[int, str]] = {}
        cursor: str | None = None
        for _ in range(10):  # 1,000 items; a larger board is not this estate's
            payload = await self._json(
                "POST",
                "/graphql",
                json={
                    "query": _PROJECT_FIELD_QUERY,
                    "variables": {
                        "owner": owner,
                        "number": project_number,
                        "field": field_name,
                        "cursor": cursor,
                    },
                },
            )
            errors = payload.get("errors") or []
            owner_node = (payload.get("data") or {}).get("repositoryOwner") or {}
            project = owner_node.get("projectV2")
            if project is None:
                kinds = sorted({str(e.get("type") or "error") for e in errors}) or ["NOT_FOUND"]
                raise PermissionDeniedError(
                    f"Project {owner}#{project_number} is not visible to the GitHub App "
                    f"({', '.join(kinds)}).",
                    status=403,
                )
            items = project.get("items") or {}
            for node in items.get("nodes") or []:
                content = (node or {}).get("content") or {}
                value = ((node or {}).get("fieldValueByName") or {}).get("name")
                number = content.get("number")
                repo = (content.get("repository") or {}).get("nameWithOwner")
                if value and number is not None and repo:
                    out.setdefault(str(repo), {})[int(number)] = str(value)
            page = items.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                break
            cursor = page.get("endCursor")
        return out


def _naive(value: datetime | None) -> datetime | None:
    """Naive UTC, as every timestamp the platform stores is."""
    return value.replace(tzinfo=None) if value is not None else None


_PROJECT_FIELD_QUERY = """
query($owner: String!, $number: Int!, $field: String!, $cursor: String) {
  repositoryOwner(login: $owner) {
    ... on ProjectV2Owner {
      projectV2(number: $number) {
        items(first: 100, after: $cursor) {
          pageInfo { hasNextPage endCursor }
          nodes {
            content { ... on Issue { number repository { nameWithOwner } } }
            fieldValueByName(name: $field) {
              ... on ProjectV2ItemFieldSingleSelectValue { name }
            }
          }
        }
      }
    }
  }
}
"""
