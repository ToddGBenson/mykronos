"""Concourse's verdict on a commit, as a GitHub Check Run (D-136, TheHub #60509).

Concourse cannot post to GitHub itself. The only GitHub credential its
pipelines hold is ``((github-token))``, an installation token minted when the
pipeline is applied and dead an hour later. So a job reports its start and end
here, with the repository's ingestion token, and the platform posts the check
run through the GitHub App, minting its own installation token the same way the
risk decision and ``independent-review`` already do.

**One check run per (repository, commit, name).** The first report creates it
and every later one updates it, so a lane that fails, is re-run and passes ends
as one check with the latest answer rather than a red and a green side by side.

**A start never reopens a verdict.** A re-run of the first lane on a commit
that already has an answer leaves that answer where it is. The re-run's own end
replaces it.

**No report means no check run, and that is the safe direction.** A missing
App credential, a repository with no installation, or a pipeline that never
called means GitHub has nothing under this name, and a required check with
nothing under its name blocks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select

from mykronos.db.models import CiCheckRun
from mykronos.github import GitHubClient
from mykronos.github.client import GitHubError
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

CHECK_NAME_PREFIX = "Concourse / "

def check_name_for(repo_full_name: str) -> str:
    """`ToddGBenson/TheHub` -> `Concourse / thehub`, the pipeline's own name."""
    return CHECK_NAME_PREFIX + repo_full_name.partition("/")[2].lower()


class CheckRunNotPostedError(Exception):
    """The check run could not be posted. Carries a message safe to return."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True)
class Posted:
    name: str
    check_run_id: str
    status: str
    conclusion: str | None
    #: created | updated | unchanged
    outcome: str


def _render(job: str, phase: str, conclusion: str | None) -> tuple[str, str]:
    if phase == "start":
        return (
            f"Verifying: {job} started",
            f"Concourse started `{job}` on this commit. The check completes when "
            "the pipeline's gate passes, or when any lane before it fails.",
        )
    if conclusion == "success":
        return (
            f"Verified: {job} passed",
            f"`{job}` passed, and it runs only after every lane before it passed on "
            "this commit.",
        )
    return (
        f"Not verified: {job} did not pass",
        f"`{job}` failed or errored on this commit, so it has not cleared "
        "verification. Its build in Concourse says why.",
    )


async def report(
    db: Any,
    github: GitHubClient | None,
    lock: asyncio.Lock,
    *,
    repo_full_name: str,
    commit_sha: str,
    job: str,
    phase: str,
    conclusion: str | None,
    timeout: float,
) -> Posted:
    """Create or update this commit's check run, and audit what happened.

    `lock` serialises reports, so two lanes failing at once cannot both find no
    row and each create a check run. One lock for the app is enough: the
    platform runs one uvicorn worker, a build sends a handful of these, and the
    table's unique constraint is the backstop.
    """
    name = check_name_for(repo_full_name)
    async with lock:
        return await _report_locked(
            db, github, name, repo_full_name, commit_sha, job, phase, conclusion, timeout
        )


async def _report_locked(
    db: Any,
    github: GitHubClient | None,
    name: str,
    repo: str,
    sha: str,
    job: str,
    phase: str,
    conclusion: str | None,
    timeout: float,
) -> Posted:
    with db.session() as session:
        row = session.execute(
            select(CiCheckRun).where(
                CiCheckRun.repo_full_name == repo,
                CiCheckRun.head_sha == sha,
                CiCheckRun.name == name,
            )
        ).scalar_one_or_none()
        existing_id = (row.external_id or None) if row is not None else None
        existing_status = row.status if row is not None else None
        existing_conclusion = row.conclusion if row is not None else None

    def audit(action: str, **detail: Any) -> None:
        with db.session() as session:
            db.audit(
                session,
                actor=f"ingest:{repo}",
                action=action,
                entity_type="ci_check_run",
                entity_id=f"{repo}@{sha}",
                name=name,
                job=job,
                phase=phase,
                conclusion=conclusion,
                **detail,
            )

    if github is None:
        audit("ci_check_run.post_failed", error="not onboarded")
        raise CheckRunNotPostedError(
            409,
            f"{repo} is not onboarded, so there is no GitHub App installation to post "
            f"'{name}' through. No check run was posted.",
        )

    if phase == "start" and existing_id:
        audit("ci_check_run.unchanged", check_run_id=existing_id)
        return Posted(name, existing_id, existing_status or "", existing_conclusion, "unchanged")

    target = None if phase == "start" else conclusion
    title, summary = _render(job, phase, conclusion)
    try:
        external_id, outcome = await asyncio.wait_for(
            _post(github, repo, sha, name, existing_id, target, title, summary),
            timeout=timeout,
        )
    except (GitHubError, TimeoutError) as exc:
        error = scrub(str(exc) or type(exc).__name__)[:500]
        logger.warning("Could not post %s for %s@%s: %s", name, scrub(repo), sha, error)
        audit("ci_check_run.post_failed", error=error)
        raise CheckRunNotPostedError(
            502,
            f"GitHub did not accept '{name}' for this commit. No check run was "
            "changed; the reason is in the platform log and audit log.",
        ) from None

    status = "in_progress" if target is None else "completed"
    now = utcnow()
    with db.session() as session:
        row = session.execute(
            select(CiCheckRun).where(
                CiCheckRun.repo_full_name == repo,
                CiCheckRun.head_sha == sha,
                CiCheckRun.name == name,
            )
        ).scalar_one_or_none()
        if row is None:
            row = CiCheckRun(repo_full_name=repo, head_sha=sha, name=name, created_at=now)
            session.add(row)
        row.external_id = external_id
        row.status = status
        row.conclusion = target
        row.last_job = job
        row.updated_at = now
        db.audit(
            session,
            actor=f"ingest:{repo}",
            action="ci_check_run.posted",
            entity_type="ci_check_run",
            entity_id=f"{repo}@{sha}",
            name=name,
            job=job,
            phase=phase,
            conclusion=conclusion,
            check_run_id=external_id,
            outcome=outcome,
        )
    return Posted(name, external_id, status, target, outcome)


async def _post(
    github: GitHubClient,
    repo: str,
    sha: str,
    name: str,
    existing_id: str | None,
    conclusion: str | None,
    title: str,
    summary: str,
) -> tuple[str, str]:
    if existing_id and conclusion is not None:
        try:
            await github.update_check_run(
                repo, existing_id, conclusion=conclusion, title=title, summary=summary
            )
            return existing_id, "updated"
        except GitHubError as exc:
            # A check run deleted on GitHub's side. Anything else is a real
            # refusal and is raised.
            if exc.status != 404:
                raise
    created = await github.create_check_run(
        repo, name=name, head_sha=sha, conclusion=conclusion, title=title, summary=summary
    )
    return created, "created"
