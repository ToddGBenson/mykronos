"""Pull request review and merge as a governed duty (spec 34 §6.1).

Every commit, review and merge on GitHub reads as one shared account
(spec 34 §1.2), so a GitHub "approve" cannot tell reviewer from author. The
separation lives here instead:

- **The evidence is the platform's.** `POST /api/approvals/pull-requests`
  names a repository and a number, nothing else. The platform reads the pull
  request from GitHub - head sha, every changed file and its patch - and that
  snapshot is the evidence. The generic approvals route refuses this duty, so
  a requester cannot hand in a diff of their own choosing.
- **The tier is computed.** Each file gets a change class from the globs in
  `approval-policy-v1.yaml`; the pull request takes the most restrictive
  (spec 34 §3.2). A renamed file is classified under both names, so moving a
  governance file out of its directory is still a governance change. A
  listing GitHub truncated is classified as the most restrictive class: files
  nobody saw are not assumed routine.
- **The approval is of one commit.** The subject is `repo#number@sha`, and
  the `independent-review` check run is posted on that sha. A new push has a
  new sha with no green check, which is what makes branch protection hold.

The check run is the stamp: it names the requesting and approving principals
and the record, which is what an audit cites instead of the GitHub account.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

from sqlalchemy import select

from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.approvals.engine import (
    ApprovalError,
    Subject,
    _append_event,
    create_request,
    register_adapter,
    register_dedicated_route,
)
from mykronos.approvals.policy import ApprovalPolicy, Duty
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStamp,
    RepoOnboarding,
)
from mykronos.github import GitHubClient
from mykronos.github.factory import GitHubClientFactory
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

DUTY = "pull_request_merge"
ROUTE = "/api/approvals/pull-requests"
CHECK_NAME = "independent-review"

#: A reviewer reads the evidence; one enormous generated file should not
#: crowd out the rest of the diff.
MAX_PATCH_CHARS = 20_000
MAX_TOTAL_PATCH_CHARS = 200_000

#: request state -> check run conclusion (`None` posts it in progress).
CONCLUSIONS: dict[str, str | None] = {
    "pending": None,
    "approved": "success",
    "rejected": "failure",
    "expired": "failure",
}


# -- Classification ------------------------------------------------------------


@lru_cache(maxsize=256)
def _glob(pattern: str) -> re.Pattern[str]:
    """`**` crosses directories, `*` and `?` do not; anchored at the root."""
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def classify_path(duty: Duty, path: str) -> str:
    for change_class, globs in duty.change_classes:
        if any(_glob(g).match(path) for g in globs):
            return change_class
    return duty.default_class


def _most_restrictive(duty: Duty, classes: list[str]) -> str:
    """The tiers are listed most restrictive first; that order decides."""
    order = list(duty.tiers)
    return min(classes, key=order.index)


def classify_file(duty: Duty, path: str, previous: str | None = None) -> str:
    names = [path] + ([previous] if previous and previous != path else [])
    return _most_restrictive(duty, [classify_path(duty, n) for n in names])


# -- Evidence ------------------------------------------------------------------


def subject_ref(repo: str, number: int, head_sha: str) -> str:
    return f"{repo}#{number}@{head_sha}"


async def snapshot(
    github: GitHubClient, duty: Duty, repo: str, number: int
) -> dict[str, Any]:
    """The evidence bundle, read from GitHub by the platform."""
    pr = await github.get_pull_request(repo, number)
    if pr is None:
        raise ApprovalError(f"No pull request {repo}#{number}.")
    if pr.merged or pr.state != "open":
        raise ApprovalError(f"{repo}#{number} is {'merged' if pr.merged else pr.state}.")
    if not pr.head_sha:
        raise ApprovalError(f"GitHub reported no head commit for {repo}#{number}.")
    listed = await github.pull_request_files(repo, number)

    files: list[dict[str, Any]] = []
    budget = MAX_TOTAL_PATCH_CHARS
    for f in listed:
        patch = f.patch or ""
        room = max(0, min(MAX_PATCH_CHARS, budget))
        truncated = len(patch) > room
        shown = patch[:room]
        budget -= len(shown)
        files.append(
            {
                "path": f.filename,
                "previous_path": f.previous_filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "class": classify_file(duty, f.filename, f.previous_filename),
                "patch": shown,
                "patch_truncated": truncated,
                "binary_or_unrendered": f.patch is None,
            }
        )

    incomplete = pr.changed_files is not None and pr.changed_files > len(listed)
    classes = [f["class"] for f in files]
    if incomplete or not classes:
        # Files nobody saw are not assumed routine, and an empty listing is
        # not a change with nothing in it.
        classes.append(next(iter(duty.tiers)))
    return {
        "subject_ref": subject_ref(repo, number, pr.head_sha),
        "repo": repo,
        "number": number,
        "title": pr.title,
        "head_sha": pr.head_sha,
        "head_branch": pr.head_branch,
        "change_class": _most_restrictive(duty, classes),
        "changed_files": pr.changed_files,
        "files_listed": len(listed),
        "files_listing_incomplete": incomplete,
        "files": files,
    }


def _adapter(subject: str, context: dict[str, Any]) -> Subject:
    snap = context.get("snapshot")
    if not snap or snap.get("subject_ref") != subject:
        raise ApprovalError(
            f"Pull request approvals are created through {ROUTE}, which reads the "
            "pull request from GitHub and computes the tier from its files."
        )
    return Subject(tier=snap["change_class"], evidence=snap)


def client_for(db: Any, github_factory: GitHubClientFactory, repo: str) -> GitHubClient | None:
    with db.session() as session:
        onboarding = (
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo)
            )
            .scalars()
            .first()
        )
        installation = onboarding.github_installation_id if onboarding else None
    if installation is None:
        return None
    return github_factory.for_installation(installation)


async def propose(
    db: Any,
    policy: ApprovalPolicy,
    github: GitHubClient,
    *,
    requested_by: Principal,
    repo: str,
    number: int,
    statement: str = "",
) -> ApprovalRequest:
    duty = policy.duty(DUTY)
    snap = await snapshot(github, duty, repo, number)
    ref = snap["subject_ref"]
    with db.session() as session:
        existing = (
            session.execute(
                select(ApprovalRequest).where(
                    ApprovalRequest.duty == DUTY,
                    ApprovalRequest.subject_ref == ref,
                    ApprovalRequest.state.in_(("pending", "approved")),
                )
            )
            .scalars()
            .first()
        )
        if existing is not None:
            raise ApprovalError(
                f"{ref} already has approval request {existing.id} ({existing.state})."
            )
    return create_request(
        db,
        policy,
        duty=DUTY,
        subject_ref=ref,
        requested_by=requested_by,
        statement=statement,
        context={"snapshot": snap},
    )


register_adapter(DUTY, _adapter)
register_dedicated_route(DUTY, ROUTE)


# -- The stamp: the independent-review check run --------------------------------


def _summary(session: Any, policy: ApprovalPolicy, request: ApprovalRequest) -> tuple[str, str]:
    ev = request.evidence
    tier = policy.duty(DUTY).tiers.get(request.tier)
    rules = sorted(r.value for r in tier.independence) if tier else []
    decisions = list(
        session.execute(
            select(ApprovalDecision)
            .where(ApprovalDecision.request_id == request.id)
            .order_by(ApprovalDecision.created_at)
        ).scalars()
    )
    titles = {
        "pending": f"Waiting for an independent approval ({request.tier})",
        "approved": f"Approved by {decisions[-1].approver if decisions else 'unknown'}",
        "rejected": "Rejected",
        "expired": "Expired without a decision",
    }
    lines = [
        f"**Approval record** `{request.id}` - duty `{DUTY}`, tier **{request.tier}**, "
        f"policy `{request.policy_version}`.",
        "",
        f"**Requested by** `{request.requested_by}` ({request.requester_kind}).",
        f"**Commit** `{ev.get('head_sha', '')}`. An approval covers this commit only; "
        "a new push needs a new one.",
        f"**Independence required**: {', '.join(rules) or 'none'}.",
        "",
        "GitHub shows one shared account for every action on this repository. The "
        "principals above and below are who acted (spec 34 §1.2).",
    ]
    if decisions:
        lines += ["", "**Decisions**"]
        for d in decisions:
            prov = d.approver_provenance or {}
            who = f"`{d.approver}` ({d.approver_kind}"
            if prov.get("model"):
                who += f", model `{prov['model']}`"
            if prov.get("platform_started"):
                who += ", platform-started"
            who += ")"
            rationale = d.rationale.strip().replace("\n", " ")
            if len(rationale) > 600:
                rationale = rationale[:600] + "…"
            lines.append(f"- **{d.verdict}** by {who}: {rationale}")
    counts: dict[str, int] = {}
    for f in ev.get("files", []):
        counts[f["class"]] = counts.get(f["class"], 0) + 1
    lines += [
        "",
        "**Files by class**: "
        + ", ".join(f"{c} {n}" for c, n in sorted(counts.items()))
        + (" - listing incomplete, classed as the strictest" if ev.get("files_listing_incomplete")
           else ""),
    ]
    return titles.get(request.state, request.state), "\n".join(lines)


def _expire_overdue(db: Any) -> None:
    """A pending request past its TTL is expired, on its own chain; otherwise
    its check would sit `in_progress` for ever."""
    now = utcnow()
    with db.session() as session:
        for request in session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.duty == DUTY,
                ApprovalRequest.state == "pending",
                ApprovalRequest.expires_at <= now,
            )
        ).scalars():
            request.state = "expired"
            _append_event(session, request.id, "expired", "job:pull-request-stamps", {})


async def publish(
    db: Any, policy: ApprovalPolicy, github_factory: GitHubClientFactory, request_id: str
) -> ApprovalStamp | None:
    """Post the check run for a request's current state, if it is not posted yet.

    A failed post is recorded with its error and retried by the job: the
    decision stands whether or not GitHub heard about it.
    """
    with db.session() as session:
        request = session.get(ApprovalRequest, request_id)
        if request is None or request.duty != DUTY or request.state not in CONCLUSIONS:
            return None
        last = (
            session.execute(
                select(ApprovalStamp)
                .where(ApprovalStamp.request_id == request_id, ApprovalStamp.error.is_(None))
                .order_by(ApprovalStamp.created_at.desc())
            )
            .scalars()
            .first()
        )
        if last is not None and last.state == request.state:
            return None
        state = request.state
        repo = str(request.evidence.get("repo", ""))
        sha = str(request.evidence.get("head_sha", ""))
        title, summary = _summary(session, policy, request)

    stamp = ApprovalStamp(
        request_id=request_id,
        target=f"github_check:{repo}@{sha}",
        state=state,
        conclusion=CONCLUSIONS[state] or "in_progress",
        created_at=utcnow(),
    )
    github = client_for(db, github_factory, repo)
    if github is None:
        stamp.error = f"{repo} is not onboarded; no installation to post through."
    else:
        try:
            stamp.external_id = await github.create_check_run(
                repo,
                name=CHECK_NAME,
                head_sha=sha,
                conclusion=CONCLUSIONS[state],
                title=title,
                summary=summary,
            )
        except Exception as exc:  # noqa: BLE001 - recorded and retried, never raised
            stamp.error = f"{type(exc).__name__}: {exc}"[:2000]
            logger.warning("Could not post %s for %s: %s", CHECK_NAME, request_id, exc)
    with db.session() as session:
        session.add(stamp)
        db.audit(
            session,
            actor="platform",
            action="approval.stamped" if stamp.error is None else "approval.stamp_failed",
            entity_type="approval_request",
            entity_id=request_id,
            target=stamp.target,
            conclusion=stamp.conclusion,
            error=stamp.error,
        )
        session.flush()
        session.expunge(stamp)
    return stamp


async def publish_due(
    db: Any, policy: ApprovalPolicy, github_factory: GitHubClientFactory
) -> int:
    """The job: every recent request whose check does not show its state yet."""
    _expire_overdue(db)
    since = utcnow() - timedelta(hours=policy.request_ttl_hours + 24)
    with db.session() as session:
        ids = list(
            session.execute(
                select(ApprovalRequest.id).where(
                    ApprovalRequest.duty == DUTY, ApprovalRequest.created_at >= since
                )
            ).scalars()
        )
    posted = 0
    for request_id in ids:
        stamp = await publish(db, policy, github_factory, request_id)
        if stamp is not None and stamp.error is None:
            posted += 1
    return posted


# -- Requests nobody made -------------------------------------------------------

#: How long a new head commit waits for someone to ask before the platform
#: does. An agent that opened the PR asks under its own name within this
#: window, and the record then says who; after it, the platform asks, so a
#: required check never leaves a PR waiting on a request nobody remembered.
REQUEST_GRACE = timedelta(minutes=10)

AUTO_REQUESTER = Principal(
    actor="job:pull-request-requests", role=Role.VIEWER, kind=ActorKind.AUTOMATION
)

#: subject_ref -> when the job first saw that head. In memory on purpose: a
#: restart only restarts the grace period, which errs towards waiting.
_first_seen: dict[str, datetime] = {}


def _requires_check(protection: dict[str, Any] | None) -> bool:
    checks = ((protection or {}).get("required_status_checks") or {})
    names = {c.get("context") for c in checks.get("checks") or []}
    names |= set(checks.get("contexts") or [])
    return CHECK_NAME in names


async def request_missing(
    db: Any,
    policy: ApprovalPolicy,
    github_factory: GitHubClientFactory,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Open an approval request for every open PR head nobody asked about.

    Only on repositories whose default branch requires `independent-review`:
    elsewhere a request would be paperwork nothing reads. The requester is an
    automation principal, which is safe because every tier an agent may
    approve demands `fresh_context` - so a request the platform opened can be
    approved by a person or a platform-started reviewer, never by the agent
    that wrote the change.
    """
    now = now or utcnow()
    with db.session() as session:
        repos = [
            (r.github_repo_full_name, r.github_installation_id)
            for r in session.execute(
                # Whether the branch requires the check is the real test,
                # asked of GitHub below; this only skips what was removed.
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
        ]
        asked = {
            ref
            for ref in session.execute(
                select(ApprovalRequest.subject_ref).where(
                    ApprovalRequest.duty == DUTY,
                    ApprovalRequest.state.in_(("pending", "approved")),
                )
            ).scalars()
        }
    opened: list[str] = []
    for repo, installation in repos:
        if installation is None:
            continue
        github = github_factory.for_installation(installation)
        try:
            branch = str((await github.get_repo(repo)).get("default_branch") or "main")
            if not _requires_check(await github.get_branch_protection(repo, branch)):
                continue
            pulls = await github.list_open_pull_requests(repo)
        except Exception as exc:  # noqa: BLE001 - one repository never stops the rest
            logger.warning("Could not list pull requests for %s: %s", repo, exc)
            continue
        for pr in pulls:
            if not pr.head_sha or pr.draft:
                continue
            ref = subject_ref(repo, pr.number, pr.head_sha)
            if ref in asked:
                continue
            first = _first_seen.setdefault(ref, now)
            if now - first < REQUEST_GRACE:
                continue
            try:
                request = await propose(
                    db,
                    policy,
                    github,
                    requested_by=AUTO_REQUESTER,
                    repo=repo,
                    number=pr.number,
                    statement=(
                        "Opened by the platform: nobody asked for an approval of this "
                        f"commit within {int(REQUEST_GRACE.total_seconds() // 60)} minutes "
                        "of it being seen. The author is not known to the platform."
                    ),
                )
            except ApprovalError as exc:
                logger.info("Not requesting %s: %s", ref, exc)
                continue
            _first_seen.pop(ref, None)
            await publish(db, policy, github_factory, request.id)
            opened.append(request.id)
    return opened
