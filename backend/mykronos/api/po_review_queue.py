"""The operator's review queue (D-163): what is waiting on a person, estate-wide.

Two reads and no writes. The per-repository approvals inbox (spec 35 §8.2)
answers "what is waiting in this repository"; this answers the operator's
question, "what do I need to do", across all of them:

- **Pending decisions.** Every pending approval request, soonest to expire
  first, each with the platform's one-line summary of its frozen evidence,
  the requester's claim labelled as a claim, the evidence digest a decision
  binds to, and the platform reviewer's latest shadow verdict beside it.
- **Ready to merge.** Every approved `pull_request_merge` request whose pull
  request is still open, with what GitHub says now: still at the approved
  head (ready), moved past it (the approval no longer covers it), or not
  readable. Merged and closed pull requests drop out.

The **review packet** is one request in full: the frozen evidence, whether it
still hashes to its digest, the duty's review instructions from the policy -
the platform's question for that duty, never the requester's - and the
reviewer's per-claim checks.

Two things Review-PendingApprovals.ps1 did that only the terminal could
(TheHub #61136):

- **The verification check.** The packet carries the platform's own check,
  run when it is read: the evidence still hashes to its digest, the request
  has not expired, and for a pull request what GitHub says now. A question
  nobody could answer is `None`, never a pass.
- **Superseded requests.** A pending pull-request request names one head.
  Once the pull request moves on, is merged or is closed, approving it covers
  nothing, so the queue lists it under `superseded` rather than `pending`.
  GitHub not answering is not superseded: those stay pending.

Deciding is not here. Repository requests are decided in place on the
repository's tab (D-144), and any request from the packet through
`/api/dashboard/product-owner/approvals/{id}/decision` (`api/po_console.py`);
both run `approvals.engine.decide`. Nothing here records a decision, starts a
reviewer or posts to GitHub.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from mykronos import po_console as pc
from mykronos.adminauth import PrincipalDep
from mykronos.approvals import pull_requests, reviewer
from mykronos.approvals.engine import canonical_digest
from mykronos.approvals.policy import cached_policy
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStamp,
    AuditLogEntry,
    RepoOnboarding,
)
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["product-owner"])

#: Pull requests asked about at once, and how long one answer may take.
GITHUB_CONCURRENCY = 4
GITHUB_TIMEOUT_SECONDS = 10.0
MAX_PENDING = 500

#: What GitHub says about an approved pull request now.
READY = "ready"
NEW_COMMITS = "new_commits"
UNKNOWN = "unknown"


class PoQueueReviewOut(BaseModel):
    """The platform reviewer's latest verdict on a request (spec 34 §4.3)."""

    verdict: str
    rationale: str
    model: str | None
    reviewed_at: str | None
    #: A shadow verdict is recorded beside the request and counts for
    #: nothing. A live reviewer's verdict is a decision, listed in `decisions`.
    counts: bool
    #: False on a tier only a person may approve. There the reviewer is told
    #: to reject so that a person decides, so its reject is advice, not a
    #: finding: the shadow report's `delegable` and scripts/review_inbox.py's
    #: governance rule, applied the same way.
    delegable: bool
    #: Its per-claim checks: what it tested, whether it held, and why.
    checks: list[dict[str, Any]] = Field(default_factory=list)


class PoQueueDecisionOut(BaseModel):
    approver: str
    approver_kind: str
    verdict: str
    rationale: str
    created_at: str | None


class PoQueueItemOut(BaseModel):
    id: str
    duty: str
    tier: str
    subject_ref: str
    #: The platform's one line about its own evidence, not the requester's.
    summary: str
    repo_full_name: str | None
    #: The onboarded repository it belongs to, when there is one: the packet
    #: offers the in-place decision (D-144) only then.
    repo_id: str | None
    #: The repository tab where it is decided in place, or None when it is
    #: decided through the approvals API (estate-wide, or not onboarded).
    decide_link: str | None
    requested_by: str
    requester_kind: str
    #: The requester's claim. A claim to test against the evidence, never
    #: evidence (spec 34 §4.2).
    requester_claim: str
    evidence_digest: str
    created_at: str | None
    expires_at: str | None
    overdue: bool
    reviewer: PoQueueReviewOut | None
    decisions: list[PoQueueDecisionOut]


class PoMergeRowOut(BaseModel):
    request_id: str
    repo_full_name: str
    number: int | None
    title: str
    approved_head_sha: str
    approved_at: str | None
    approvers: list[str]
    #: The `independent-review` check for the approval reached GitHub.
    check_posted: bool
    #: ready | new_commits | unknown
    github_state: str
    github_error: str | None
    #: At the approved head and the check posted: merge it.
    ready: bool


class PoReviewerStateOut(BaseModel):
    mode: str
    #: Agreement with people's decisions on delegable tiers, or None with no
    #: decided history.
    agreement: float | None
    #: When the hourly probe of the reviewer's model key last turned refused
    #: or unreachable (TheHub #61614); None while it is ok or never probed.
    unavailable_since: str | None = None


class PoQueueCountsOut(BaseModel):
    pending: int
    unreviewed: int
    overdue: int
    ready_to_merge: int
    #: Pending requests left out of `pending` because their pull request
    #: moved on, merged or closed.
    superseded: int = 0


class PoSupersededOut(BaseModel):
    """A pending request whose pull request has left the head it names."""

    id: str
    duty: str
    subject_ref: str
    summary: str
    repo_full_name: str | None
    requested_head_sha: str
    #: The head GitHub reports now; None when the pull request is closed.
    current_head_sha: str | None
    #: new_commits | merged | closed
    reason: str


class PoReviewQueueOut(BaseModel):
    reviewer: PoReviewerStateOut
    counts: PoQueueCountsOut
    pending: list[PoQueueItemOut]
    superseded: list[PoSupersededOut] = Field(default_factory=list)
    ready_to_merge: list[PoMergeRowOut]
    policy_version: str | None


class PoVerificationLineOut(BaseModel):
    #: True holds, False fails, None could not be checked.
    ok: bool | None
    text: str


class PoVerificationOut(BaseModel):
    """The platform's check of a request, run when it was read."""

    ran_at: str | None
    #: True when every line holds, False when any fails, else None.
    holds: bool | None
    lines: list[PoVerificationLineOut]


class PoReviewPacketOut(PoQueueItemOut):
    evidence: dict[str, Any]
    #: The stored evidence still hashes to the digest decisions bind to.
    digest_verified: bool
    #: What the policy asks an approver of this duty to check.
    review_instructions: str | None
    needs: dict[str, Any] | None
    #: The pull request has left the head this request names.
    superseded: bool = False
    verification: PoVerificationOut | None = None


def _policy(request: Request) -> Any:
    try:
        return cached_policy(request.app.state.settings.approval_policy_path)
    except Exception:  # noqa: BLE001 - the views still render without it
        logger.warning("The approval policy could not be loaded")
        return None


def _latest_reviews(session: Any, ids: list[str], policy: Any) -> dict[str, PoQueueReviewOut]:
    if not ids:
        return {}
    out: dict[str, PoQueueReviewOut] = {}
    entries = session.execute(
        select(AuditLogEntry)
        .where(AuditLogEntry.action == reviewer.SHADOW_ACTION)
        .where(AuditLogEntry.entity_id.in_(ids))
        .order_by(AuditLogEntry.created_at.desc())
    ).scalars()
    for entry in entries:
        if entry.entity_id in out:
            continue
        detail = dict(entry.detail or {})
        out[entry.entity_id] = PoQueueReviewOut(
            verdict=str(detail.get("verdict") or ""),
            rationale=str(detail.get("rationale") or ""),
            model=detail.get("model"),
            reviewed_at=pc.iso(entry.created_at),
            counts=False,
            delegable=reviewer._delegable(policy, detail.get("duty"), detail.get("tier")),
            checks=[c for c in detail.get("checks") or [] if isinstance(c, dict)],
        )
    return out


def _decisions(session: Any, ids: list[str]) -> dict[str, list[ApprovalDecision]]:
    out: dict[str, list[ApprovalDecision]] = {}
    if ids:
        for d in session.execute(
            select(ApprovalDecision)
            .where(ApprovalDecision.request_id.in_(ids))
            .order_by(ApprovalDecision.created_at)
        ).scalars():
            out.setdefault(d.request_id, []).append(d)
    return out


def _repo_ids(session: Any) -> dict[str, str]:
    return {
        row.github_repo_full_name.lower(): row.id
        for row in session.execute(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).scalars()
    }


def _item(
    row: ApprovalRequest,
    review: PoQueueReviewOut | None,
    decisions: list[ApprovalDecision],
    repo_ids: dict[str, str],
    now: Any,
) -> dict[str, Any]:
    repo = pc.request_repo(row.duty, row.subject_ref, row.evidence)
    repo_id = repo_ids.get(repo.lower()) if repo else None
    return {
        "id": row.id,
        "duty": row.duty,
        "tier": row.tier,
        "subject_ref": row.subject_ref,
        "summary": pc.evidence_summary(row.duty, row.evidence),
        "repo_full_name": repo,
        "repo_id": repo_id,
        "decide_link": (
            f"/repos/{repo_id}?tab=product-owner&view=approvals" if repo_id else None
        ),
        "requested_by": row.requested_by,
        "requester_kind": row.requester_kind,
        "requester_claim": row.requester_statement or "",
        "evidence_digest": row.evidence_digest,
        "created_at": pc.iso(row.created_at),
        "expires_at": pc.iso(row.expires_at),
        "overdue": row.expires_at <= now,
        "reviewer": review,
        "decisions": [
            PoQueueDecisionOut(
                approver=d.approver,
                approver_kind=d.approver_kind,
                verdict=d.verdict,
                rationale=d.rationale,
                created_at=pc.iso(d.created_at),
            )
            for d in decisions
        ],
    }


async def _github_state(
    request: Request, repo: str, number: Any, approved_head: str
) -> tuple[str | None, str | None]:
    """(state, error). state None means merged, closed or gone: not listed."""
    if not isinstance(number, int):
        return UNKNOWN, "The evidence names no pull request number."
    github = pull_requests.client_for(
        request.app.state.db, request.app.state.github_factory, repo
    )
    if github is None:
        return UNKNOWN, f"{repo} is not onboarded, so GitHub was not asked."
    try:
        pr = await asyncio.wait_for(
            github.get_pull_request(repo, number), timeout=GITHUB_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 - one pull request never stops the page
        return UNKNOWN, f"GitHub did not answer: {type(exc).__name__}"
    if pr is None or pr.merged or pr.state != "open":
        return None, None
    return (READY if pr.head_sha == approved_head else NEW_COMMITS), None


#: Where a pending pull request stands against the head its request names.
AT_HEAD = "at_head"
MERGED = "merged"
CLOSED = "closed"
SUPERSEDED = (NEW_COMMITS, MERGED, CLOSED)


def _pr_ref(duty: str, subject_ref: str, evidence: Any) -> tuple[str | None, Any, str]:
    """(repo, number, head) of the pull request a request names, if it names one."""
    if duty != pull_requests.DUTY:
        return None, None, ""
    data = evidence if isinstance(evidence, dict) else {}
    return (
        pc.request_repo(duty, subject_ref, data),
        data.get("number"),
        str(data.get("head_sha") or ""),
    )


async def _pr_standing(
    request: Request, repo: str | None, number: Any, head: str
) -> tuple[str, str | None, str | None]:
    """(standing, current head, error) of the pull request a request names.

    UNKNOWN whenever GitHub was not asked or did not answer: a question nobody
    could answer is never read as superseded, or as current.
    """
    if not repo or not isinstance(number, int) or not head:
        return UNKNOWN, None, "the evidence names no pull request and head"
    github = pull_requests.client_for(
        request.app.state.db, request.app.state.github_factory, repo
    )
    if github is None:
        return UNKNOWN, None, f"{repo} is not onboarded, so GitHub was not asked"
    try:
        pr = await asyncio.wait_for(
            github.get_pull_request(repo, number), timeout=GITHUB_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 - one pull request never stops the page
        return UNKNOWN, None, f"GitHub did not answer: {type(exc).__name__}"
    if pr is None:
        return UNKNOWN, None, f"GitHub has no pull request #{number} in {repo}"
    if pr.merged:
        return MERGED, pr.head_sha, None
    if pr.state != "open":
        return CLOSED, pr.head_sha, None
    return (AT_HEAD if pr.head_sha == head else NEW_COMMITS), pr.head_sha, None


def _line(ok: bool | None, text: str) -> PoVerificationLineOut:
    return PoVerificationLineOut(ok=ok, text=text)


async def verify(
    request: Request,
    *,
    duty: str,
    subject_ref: str,
    evidence: Any,
    evidence_digest: str,
    expires_at: Any,
    now: Any,
) -> tuple[PoVerificationOut, str | None]:
    """The platform's verification check of one request, and the pull
    request's standing when it names one (TheHub #61136).

    The same lines whether the packet is being read or a decision recorded,
    so what is stored with a decision is what the page showed, re-run.
    """
    data = evidence if isinstance(evidence, dict) else {}
    digest_ok = canonical_digest(data) == evidence_digest
    lines = [
        _line(
            digest_ok,
            "the stored evidence hashes to its digest"
            if digest_ok
            else "the stored evidence no longer hashes to its digest: do not decide on it",
        ),
        _line(
            expires_at > now,
            f"the request is open until {pc.iso(expires_at)}"
            if expires_at > now
            else f"the request expired at {pc.iso(expires_at)}: the engine will refuse a decision",
        ),
    ]
    standing: str | None = None
    if duty == pull_requests.DUTY:
        repo, number, head = _pr_ref(duty, subject_ref, data)
        standing, current, error = await _pr_standing(request, repo, number, head)
        pr = f"#{number}" if isinstance(number, int) else "the pull request"
        if standing == AT_HEAD:
            lines.append(_line(True, f"{pr} is open at {head[:12]}, the head this request names"))
        elif standing == NEW_COMMITS:
            lines.append(
                _line(
                    False,
                    f"superseded: {pr} has moved on to {(current or '')[:12]}; "
                    f"this request names {head[:12]}, so approving it covers nothing",
                )
            )
        elif standing in (MERGED, CLOSED):
            lines.append(_line(False, f"superseded: {pr} is already {standing}"))
        else:
            lines.append(_line(None, f"{pr} could not be checked: {error}"))
    oks = [line.ok for line in lines]
    holds = False if False in oks else (None if None in oks else True)
    return PoVerificationOut(ran_at=pc.iso(now), holds=holds, lines=lines), standing


async def _ready_to_merge(request: Request, policy: Any) -> list[PoMergeRowOut]:
    ttl = getattr(policy, "request_ttl_hours", 168)
    since = utcnow() - timedelta(hours=ttl + 24)
    with request.app.state.db.session() as session:
        rows = list(
            session.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.duty == pull_requests.DUTY)
                .where(ApprovalRequest.state == "approved")
                .where(ApprovalRequest.created_at >= since)
                .order_by(ApprovalRequest.decided_at)
            ).scalars()
        )
        ids = [r.id for r in rows]
        decisions = _decisions(session, ids)
        posted = (
            {
                s.request_id
                for s in session.execute(
                    select(ApprovalStamp)
                    .where(ApprovalStamp.request_id.in_(ids))
                    .where(ApprovalStamp.state == "approved")
                    .where(ApprovalStamp.error.is_(None))
                ).scalars()
            }
            if ids
            else set()
        )
        candidates = [
            {
                "request_id": r.id,
                "repo": pc.request_repo(r.duty, r.subject_ref, r.evidence) or "",
                "number": (r.evidence or {}).get("number"),
                "title": str((r.evidence or {}).get("title") or ""),
                "head": str((r.evidence or {}).get("head_sha") or ""),
                "approved_at": pc.iso(r.decided_at),
                "approvers": [
                    d.approver for d in decisions.get(r.id, []) if d.verdict == "approve"
                ],
            }
            for r in rows
        ]

    semaphore = asyncio.Semaphore(GITHUB_CONCURRENCY)

    async def one(c: dict[str, Any]) -> PoMergeRowOut | None:
        async with semaphore:
            state, error = await _github_state(request, c["repo"], c["number"], c["head"])
        if state is None:
            return None
        check = c["request_id"] in posted
        return PoMergeRowOut(
            request_id=c["request_id"],
            repo_full_name=c["repo"],
            number=c["number"] if isinstance(c["number"], int) else None,
            title=c["title"],
            approved_head_sha=c["head"],
            approved_at=c["approved_at"],
            approvers=c["approvers"],
            check_posted=check,
            github_state=state,
            github_error=error,
            ready=state == READY and check,
        )

    found = await asyncio.gather(*(one(c) for c in candidates))
    return [row for row in found if row is not None]


def _unavailable_since(db: Any) -> str | None:
    from mykronos import reviewer_key

    since = reviewer_key.unavailable_since(db)
    return since.strftime("%Y-%m-%d %H:%MZ") if since else None


@router.get("/product-owner/review-queue", response_model=PoReviewQueueOut)
async def review_queue(request: Request, principal: PrincipalDep) -> PoReviewQueueOut:
    """What is waiting on a person: pending decisions and approved pull requests."""
    policy = _policy(request)
    now = utcnow()
    with request.app.state.db.session() as session:
        rows = list(
            session.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.state == "pending")
                .order_by(ApprovalRequest.expires_at)
                .limit(MAX_PENDING)
            ).scalars()
        )
        ids = [r.id for r in rows]
        reviews = _latest_reviews(session, ids, policy)
        decisions = _decisions(session, ids)
        repo_ids = _repo_ids(session)
        listed = [
            PoQueueItemOut(
                **_item(r, reviews.get(r.id), decisions.get(r.id, []), repo_ids, now)
            )
            for r in rows
        ]
        refs = {r.id: _pr_ref(r.duty, r.subject_ref, r.evidence) for r in rows}

    # Which pending pull-request requests still name the pull request's head
    # (TheHub #61136). Only these are asked about; nothing else is superseded.
    semaphore = asyncio.Semaphore(GITHUB_CONCURRENCY)

    async def standing_of(item: PoQueueItemOut) -> tuple[str, str | None]:
        repo, number, head = refs[item.id]
        if repo is None:
            return UNKNOWN, None
        async with semaphore:
            standing, current, _ = await _pr_standing(request, repo, number, head)
        return standing, current

    standings = await asyncio.gather(*(standing_of(item) for item in listed))
    pending: list[PoQueueItemOut] = []
    superseded: list[PoSupersededOut] = []
    for item, (standing, current) in zip(listed, standings, strict=True):
        if standing in SUPERSEDED:
            superseded.append(
                PoSupersededOut(
                    id=item.id,
                    duty=item.duty,
                    subject_ref=item.subject_ref,
                    summary=item.summary,
                    repo_full_name=item.repo_full_name,
                    requested_head_sha=refs[item.id][2],
                    current_head_sha=current if standing != CLOSED else None,
                    reason=standing,
                )
            )
        else:
            pending.append(item)

    report = await asyncio.to_thread(reviewer.shadow_report, request.app.state.db, policy)
    merge = await _ready_to_merge(request, policy)
    return PoReviewQueueOut(
        reviewer=PoReviewerStateOut(
            mode=reviewer.mode(request.app.state.settings),
            agreement=report.get("agreement"),
            unavailable_since=_unavailable_since(request.app.state.db),
        ),
        counts=PoQueueCountsOut(
            pending=len(pending),
            unreviewed=sum(1 for p in pending if p.reviewer is None),
            overdue=sum(1 for p in pending if p.overdue),
            ready_to_merge=sum(1 for m in merge if m.ready),
            superseded=len(superseded),
        ),
        pending=pending,
        superseded=superseded,
        ready_to_merge=merge,
        policy_version=getattr(policy, "version", None),
    )


@router.get("/product-owner/review-queue/{request_id}", response_model=PoReviewPacketOut)
async def review_packet(
    request: Request, request_id: str, principal: PrincipalDep
) -> PoReviewPacketOut:
    """One request in full: claim, frozen evidence and the reviewer's verdict, apart."""
    policy = _policy(request)
    with request.app.state.db.session() as session:
        row = session.get(ApprovalRequest, request_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No approval request {request_id}.",
            )
        reviews = _latest_reviews(session, [row.id], policy)
        decisions = _decisions(session, [row.id])
        item = _item(
            row, reviews.get(row.id), decisions.get(row.id, []), _repo_ids(session), utcnow()
        )
        evidence = dict(row.evidence or {})
        verified = canonical_digest(evidence) == row.evidence_digest
        duty, tier = row.duty, row.tier
        subject_ref, digest, expires_at = row.subject_ref, row.evidence_digest, row.expires_at
    verification, standing = await verify(
        request,
        duty=duty,
        subject_ref=subject_ref,
        evidence=evidence,
        evidence_digest=digest,
        expires_at=expires_at,
        now=utcnow(),
    )
    instructions = None
    needs = None
    if policy is not None:
        try:
            instructions = policy.duty(duty).reviewer_instructions or None
        except (KeyError, ValueError):
            instructions = None
        needs = pc.tier_needs(policy, duty, tier)
    return PoReviewPacketOut(
        **item,
        evidence=evidence,
        digest_verified=verified,
        review_instructions=instructions,
        needs=needs,
        superseded=standing in SUPERSEDED,
        verification=verification,
    )
