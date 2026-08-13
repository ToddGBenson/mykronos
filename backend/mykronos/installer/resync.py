"""Bulk template resync (spec 03 §6).

When a template's semver bumps — a pinned action version moves, a step is
added — every repository already carrying that workflow is running the old
one. This sweeps them, re-renders, and opens an update pull request wherever
the file on disk differs from what the current template produces.

Three properties the design turns on:

**Content is compared, never the version string.** Spec 03 §6 is explicit
about this and it is the right call: a repository where somebody hand-edited
the workflow has a header claiming one version and a body that is something
else. Trusting the header would skip exactly the repository most in need of a
resync, and would also silently overwrite a local change without noticing it
was there.

**It opens pull requests, never commits.** Same posture as the installer and
as Patchwork: a bulk job that pushed to two hundred default branches on a
semver bump is a bad afternoon for everybody.

**It is bounded.** A sweep that opened a pull request against every onboarded
repository at once would be indistinguishable from an incident. The limit is a
parameter, defaults low, and what was skipped is reported rather than dropped
— an unreported cap reads as "everything is up to date".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select

from mykronos.db import Database
from mykronos.db.models import RepoOnboarding
from mykronos.github.client import FileChange, GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.installer.installer import BRANCH_PREFIX, capability_configs
from mykronos.installer.templates import TemplateLibrary
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

RESYNC_BRANCH_PREFIX = "mykronos/resync-"


@dataclass
class RepoResync:
    repo_full_name: str
    drifted: list[str] = field(default_factory=list)
    pull_request_number: int | None = None
    pull_request_url: str | None = None
    skipped_reason: str | None = None
    error: str | None = None

    @property
    def opened(self) -> bool:
        return self.pull_request_number is not None


@dataclass
class ResyncResult:
    checked: int = 0
    up_to_date: int = 0
    repos: list[RepoResync] = field(default_factory=list)
    #: Repos that drifted but were past the run's limit. Named rather than
    #: counted, so the next run's operator knows who is still waiting.
    deferred: list[str] = field(default_factory=list)

    @property
    def opened(self) -> list[RepoResync]:
        return [r for r in self.repos if r.opened]

    def summary(self) -> str:
        return (
            f"checked {self.checked}, up to date {self.up_to_date}, "
            f"opened {len(self.opened)}, deferred {len(self.deferred)}, "
            f"errors {sum(1 for r in self.repos if r.error)}"
        )


async def resync_templates(
    db: Database,
    templates: TemplateLibrary,
    github_factory: GitHubClientFactory,
    *,
    ingestion_api_url: str,
    upload_action_ref: str,
    package_spec: str,
    secret_name: str,
    capabilities: set[str] | None = None,
    repos: set[str] | None = None,
    max_pull_requests: int = 10,
    dry_run: bool = False,
    now: datetime | None = None,
) -> ResyncResult:
    """Sweep active repos and open update PRs where the workflows have drifted.

    `dry_run` reports what would change without touching anything, which is
    what you want before a sweep across an estate — the interesting question
    before running this is "how many repositories does this affect", and
    finding out by doing it is the expensive way to ask.

    `repos` narrows the sweep, and exists because of a case the estate-wide
    default gets wrong. A workflow this repository *deliberately deleted*
    reads as drift — `get_file` returns None, and None is not equal to the
    rendered content — so an unfiltered sweep would open a pull request
    restoring it. Spec 16 §4 removed this repository's Actions on purpose;
    the resync has no way to tell that from a file somebody lost, so the
    operator has to.
    """
    stamp = now or utcnow()
    result = ResyncResult()

    with db.session() as session:
        targets = [
            (row.id, row.github_repo_full_name, row.github_installation_id,
             row.default_branch, list(row.enabled_capabilities or []))
            for row in session.execute(
                select(RepoOnboarding)
                .where(RepoOnboarding.status == "active")
                .order_by(RepoOnboarding.github_repo_full_name)
            ).scalars()
            if row.enabled_capabilities
        ]

    for repo_id, repo, installation_id, default_branch, enabled in targets:
        if repos is not None and repo not in repos:
            continue
        result.checked += 1
        wanted = sorted(
            c for c in enabled
            if c in templates.available and (capabilities is None or c in capabilities)
        )
        if not wanted:
            result.up_to_date += 1
            continue

        github = github_factory.for_installation(installation_id)
        entry = RepoResync(repo_full_name=repo)

        try:
            with db.session() as session:
                onboarding = session.get(RepoOnboarding, repo_id)
                configs = (
                    capability_configs(session, onboarding) if onboarding else {}
                )

            changes = await _drifted_files(
                github,
                templates,
                repo,
                default_branch,
                wanted,
                configs,
                ingestion_api_url=ingestion_api_url,
                upload_action_ref=upload_action_ref,
                package_spec=package_spec,
                secret_name=secret_name,
            )
        except GitHubError as exc:
            # One unreachable repo must not stop the sweep. It will be picked
            # up next run, and the failure is reported rather than silently
            # counted as up to date — which is the reading that matters.
            logger.warning("Resync could not read %s: %s", repo, exc)
            entry.error = str(exc)
            result.repos.append(entry)
            continue

        if not changes:
            result.up_to_date += 1
            continue

        entry.drifted = sorted(change.path for change in changes)

        if len(result.opened) >= max_pull_requests:
            entry.skipped_reason = (
                f"deferred: this run's limit of {max_pull_requests} open pull "
                "requests was reached. The drift is unchanged and the next run "
                "will pick it up."
            )
            result.deferred.append(repo)
            result.repos.append(entry)
            continue

        if dry_run:
            entry.skipped_reason = "dry run: nothing was opened"
            result.repos.append(entry)
            continue

        try:
            await _open_resync_pr(
                github, repo, default_branch, changes, entry, templates, stamp
            )
        except GitHubError as exc:
            logger.warning("Resync could not open a PR for %s: %s", repo, exc)
            entry.error = str(exc)

        result.repos.append(entry)

    logger.info("Template resync: %s", result.summary())
    return result


async def _drifted_files(
    github: object,
    templates: TemplateLibrary,
    repo: str,
    default_branch: str,
    wanted: list[str],
    configs: dict[str, dict[str, object]],
    *,
    ingestion_api_url: str,
    upload_action_ref: str,
    package_spec: str,
    secret_name: str,
) -> list[FileChange]:
    """Files whose rendered content differs from what the repository holds.

    Compared byte for byte against the Contents API, not against the stored
    version string (spec 03 §6). A hand-edited workflow advertises a version
    it no longer matches, so trusting the header would skip precisely the
    repository most in need of the sweep.
    """
    from mykronos.installer.installer import _gate_depends_on

    changes: list[FileChange] = []
    for capability in wanted:
        rendered = templates.render(
            capability,
            repo_full_name=repo,
            default_branch=default_branch,
            ingestion_api_url=ingestion_api_url,
            token_secret_name=secret_name,
            upload_action_ref=upload_action_ref,
            mykronos_package_spec=package_spec,
            config=configs.get(capability, {}),
            gate_depends_on=_gate_depends_on(capability, wanted),
        )
        current = await github.get_file(repo, rendered.path, default_branch)  # type: ignore[attr-defined]

        # Newline normalisation only. A repository checked out on Windows can
        # hold CRLF for a file we rendered with LF, and opening a pull request
        # whose entire diff is line endings would train people to ignore these.
        if current is not None and current.replace("\r\n", "\n") == rendered.content:
            continue

        changes.append(FileChange(path=rendered.path, content=rendered.content))
    return changes


async def _open_resync_pr(
    github: object,
    repo: str,
    default_branch: str,
    changes: list[FileChange],
    entry: RepoResync,
    templates: TemplateLibrary,
    stamp: datetime,
) -> None:
    # An installer PR already open means capabilities are mid-change. Landing
    # a resync alongside it would produce two pull requests touching the same
    # files, and whichever merged second would conflict.
    install_pr = await github.find_open_pull_request(repo, BRANCH_PREFIX)  # type: ignore[attr-defined]
    if install_pr is not None:
        entry.skipped_reason = (
            f"deferred: install pull request #{install_pr.number} is still "
            "open and touches the same files. Merge or close it first."
        )
        return

    existing = await github.find_open_pull_request(repo, RESYNC_BRANCH_PREFIX)  # type: ignore[attr-defined]
    branch = existing.head_branch if existing else (
        f"{RESYNC_BRANCH_PREFIX}{stamp:%Y%m%d}"
    )

    if existing is None:
        await github.create_branch(repo, branch, default_branch)  # type: ignore[attr-defined]

    await github.commit_files(  # type: ignore[attr-defined]
        repo,
        branch,
        message=(
            "chore(mykronos): resync workflow templates\n\n"
            + "\n".join(f"- {change.path}" for change in changes)
        ),
        changes=changes,
    )

    if existing is not None:
        # Re-pushing onto the open one rather than opening a second: an
        # operator with two resync PRs cannot tell which is current.
        entry.pull_request_number = existing.number
        entry.pull_request_url = existing.url
        return

    pull_request = await github.create_pull_request(  # type: ignore[attr-defined]
        repo,
        head=branch,
        base=default_branch,
        title="Mykronos: resync workflow templates",
        body=_body(changes, templates),
    )
    entry.pull_request_number = pull_request.number
    entry.pull_request_url = pull_request.url


def _body(changes: list[FileChange], templates: TemplateLibrary) -> str:
    lines = [
        "## Workflow template resync",
        "",
        "These files no longer match what Mykronos renders for this "
        "repository. Merging brings them back in line.",
        "",
        "| File | Template version |",
        "| --- | --- |",
    ]
    for change in changes:
        capability = next(
            (
                name
                for name in templates.available
                if templates.target_path(name) == change.path
            ),
            "?",
        )
        version = templates.spec(capability).version if capability != "?" else "?"
        lines.append(f"| `{change.path}` | {version} |")

    lines += [
        "",
        "### Why you might be seeing this",
        "",
        "- A template version was bumped centrally — a pinned action moved, "
        "or a step changed.",
        "- Or this file was edited by hand. Mykronos compares **content**, "
        "not the version header, so a local change shows up here rather than "
        "being skipped. If the edit was deliberate, say so on this pull "
        "request rather than merging: the next resync will re-open it.",
        "",
        "Nothing has been pushed to your default branch. Mykronos opens pull "
        "requests and never merges them.",
    ]
    return "\n".join(lines)
