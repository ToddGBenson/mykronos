"""The Today run sheet: what Start-Here computes, computed by the server (TheHub #61141).

The operator's day runs in a fixed order, which is the order of the
terminal script it replaces: **decide**, **merge**, **deploy**, **tasks**.
(**Watch**, the red and silent lanes, is the briefing's own data and is read
from `GET /api/dashboard/briefing` beside this.) Every line names its state,
its reason and its owner, because "not yet" is useless without "why" and
"whose move".

The rules are Start-Here's, line for line, so the two can be compared for a
week before the page is trusted (the story's acceptance):

* **Decide.** Pending approval requests. A `pull_request_merge` request is
  hidden when its pull request is no longer open, or when the pull request's
  head has moved past the sha it names (#1049 had both: approving the old one
  does nothing). Each is checked against a live read of its own pull request,
  as Start-Here's `gh pr view` does, never the cached listing: a request made
  right after a push names a head the cache has not seen. A request whose
  pull request could not be read stays, and the step says why. While the
  independent reviewer runs in `shadow`, a request it has not posted on waits
  for it.
* **Merge.** Every open, non-draft pull request on an onboarded repository,
  oldest number first per repository, under Start-Here's rule for its
  repository: TheHub merges only at a head an approved request names (develop
  requires no check, so a red advisory check does not stop it); keel and
  binnacle need the operator's `self-review.md` in the pull request; any
  repository whose branch requires `independent-review` needs the approval at
  its head. Then conflicts, red checks, behind, running checks; never guessed
  ready when a read is missing. Drafts are named, since Start-Here offers the
  drafts its own list names, and the host-only guards (the TheHub deploy
  lock, TheHub's batch list) are named in `notes`.
* **Deploy.** The platform's own production: running sha against main, the
  backup window, main's Delivery run, the `unit` and `lint-and-types` lanes,
  and the risk gate on main, read as `/decisions/by-commit` answers it (the
  floor is what the commit introduced, which an override does not clear).
  Two guards live only on the host (the TheHub deploy lock and Delivery's
  hold flag); they are named in `notes`, never guessed.
* **Tasks.** The board's `OPERATOR ACTION:` stories that GitHub does not show
  as done (`operator_checks`). Start-Here's one-offs are scripts on the host
  and are not visible here.

Read-only by construction: nothing in this module writes anywhere. The pure
builders take what was read and return steps; `gather` does the reading.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any

from sqlalchemy import select

from mykronos import operator_checks
from mykronos.github.client import ChecksSummary

logger = logging.getLogger(__name__)

#: A step's or a line's state, the run sheet's five words.
READY = "ready"
WAITING = "waiting"
BLOCKED = "blocked"
DONE = "done"
UNKNOWN = "unknown"
STATES = (READY, WAITING, BLOCKED, DONE, UNKNOWN)

#: Whether a step's sources were read (the daily briefing's vocabulary).
OK = "ok"
PARTIAL = "partial"
UNAVAILABLE = "unavailable"

#: Whose move it is.
OWNER_YOU = "you"
OWNER_REVIEWER = "independent reviewer"
OWNER_AGENT = "an agent"
OWNER_DELIVERY = "Delivery"
OWNER_CI = "CI"

#: The platform's own deploy, as Start-Here section 3 checks it.
DEPLOY_REPO = "ToddGBenson/mykronos"
DEPLOY_PIPELINE = "mykronos"
DEPLOY_LANES = ("unit", "lint-and-types")
DELIVERY_WORKFLOW = "delivery.yml"
#: 02:40-04:15Z, the nightly backup (7:40-9:15 pm Arizona).
BACKUP_WINDOW = (time(2, 40), time(4, 15))
#: The check `main` requires on mykronos (spec 34 §6.1).
REVIEW_CHECK = "independent-review"
PR_DUTY = "pull_request_merge"

#: Start-Here's per-repository merge rules (section 2).
#: TheHub requires no check on develop: the approval at the head is the gate.
APPROVAL_REPOS: frozenset[str] = frozenset({"ToddGBenson/TheHub"})
#: keel and binnacle need the operator's own self-review record in the PR.
SELF_REVIEW_REPOS: frozenset[str] = frozenset({"ToddGBenson/keel", "ToddGBenson/binnacle"})
SELF_REVIEW_FILE = "self-review.md"
#: Live single-PR reads for Decide, at a time and each under this many seconds.
LIVE_READ_CONCURRENCY = 6
LIVE_READ_TIMEOUT_SECONDS = 15.0

MERGE_HOST_NOTES = (
    "Start-Here holds every merge while a TheHub deploy runs (the deploy lock, on the "
    "host); this server cannot see the lock.",
    "Start-Here merges TheHub pull requests only from its batch list, which lives on the "
    "host: an approved one outside the batch waits for the next batch.",
)

HOST_ONLY_GUARDS = (
    "Start-Here also checks the TheHub deploy lock, which this server cannot see: "
    "one deploy runs on the host at a time.",
    "When Delivery holds the deploy itself (its flag file on the host), Start-Here "
    "offers nothing here; this server cannot see that flag either.",
)


@dataclass
class Item:
    text: str
    state: str
    reason: str
    owner: str
    #: A request id, `repo#number` or a story `#id`: what to open.
    ref: str = ""
    url: str = ""


@dataclass
class Step:
    key: str
    title: str
    state: str
    summary: str
    items: list[Item] = field(default_factory=list)
    #: What was left out and why: superseded requests, drafts, done tasks.
    hidden: list[str] = field(default_factory=list)
    #: Whether the step's sources were read: ok | partial | unavailable.
    status: str = OK
    #: Why a source could not be read, or why the step stands as it does.
    reason: str = ""
    #: Facts the server cannot check, named rather than guessed.
    notes: list[str] = field(default_factory=list)


def _roll_up(items: list[Item]) -> str:
    for state in (READY, BLOCKED, WAITING, UNKNOWN):
        if any(i.state == state for i in items):
            return state
    return DONE


# -- Decide ---------------------------------------------------------------------

_PR_REF = re.compile(r"^(?P<repo>[^#\s]+)#(?P<n>\d+)@(?P<sha>[0-9a-f]{7,40})$")


def parse_pr_ref(ref: str) -> tuple[str, int, str] | None:
    """`owner/repo#12@<sha>`, the subject of a pull-request approval."""
    m = _PR_REF.match(ref)
    return (m["repo"], int(m["n"]), m["sha"]) if m else None


def same_sha(a: str, b: str) -> bool:
    return bool(a) and bool(b) and (a.startswith(b) or b.startswith(a))


@dataclass
class PendingApproval:
    id: str
    duty: str
    tier: str
    subject_ref: str
    #: Whether the independent reviewer has posted on it. None when the
    #: reviewer is not in `shadow`, so every request is decidable now.
    reviewed: bool | None


@dataclass
class PullRequestState:
    repo: str
    number: int
    title: str
    url: str
    draft: bool
    #: Empty when the single-PR read did not run.
    head_sha: str
    base_branch: str
    default_branch: str
    mergeable: bool | None
    mergeable_state: str
    checks: ChecksSummary | None
    depends_on: list[int] = field(default_factory=list)
    detail_read: bool = False
    #: Whether the PR changes a `self-review.md` (keel, binnacle). None when
    #: its files were not read.
    has_self_review: bool | None = None


@dataclass
class LiveHead:
    """One pull request as a live single-PR read found it."""

    open: bool
    head_sha: str


#: (repo, number) -> what the live read found, or why it could not be read.
LiveHeads = dict[tuple[str, int], LiveHead | str]


def decide_step(pending: list[PendingApproval], heads: LiveHeads) -> Step:
    items: list[Item] = []
    hidden: list[str] = []
    unchecked: list[str] = []
    for request in pending:
        parsed = parse_pr_ref(request.subject_ref) if request.duty == PR_DUTY else None
        if parsed is not None:
            repo, number, sha = parsed
            live = heads.get((repo, number), "its pull request was not read")
            if isinstance(live, str):
                # Never hidden on a read that did not happen: only you can tell.
                unchecked.append(f"{repo}#{number}: {live}")
            elif not live.open:
                hidden.append(f"{repo}#{number}: no longer open (merged or closed)")
                continue
            elif live.head_sha and not same_sha(live.head_sha, sha):
                hidden.append(
                    f"{repo}#{number}: its head moved to {live.head_sha[:7]}, "
                    "so this request is superseded"
                )
                continue
        text = f"{request.duty.replace('_', ' ')} · {request.tier} · {request.subject_ref}"
        if request.reviewed is False:
            items.append(
                Item(
                    text=text,
                    state=WAITING,
                    reason="the independent reviewer has not posted on it yet",
                    owner=OWNER_REVIEWER,
                    ref=request.id,
                )
            )
        else:
            items.append(
                Item(
                    text=text, state=READY, reason="ready for you", owner=OWNER_YOU, ref=request.id
                )
            )
    ready = sum(1 for i in items if i.state == READY)
    waiting = len(items) - ready
    if not items:
        summary = "nothing waiting for your decision"
    else:
        summary = f"{ready} ready for you"
        if waiting:
            summary += f", {waiting} waiting on the reviewer"
    status, reason = OK, ""
    if unchecked:
        status = PARTIAL
        reason = (
            f"{len(unchecked)} pull-request request(s) not checked against their pull "
            "request's head, so none is hidden: " + "; ".join(unchecked)
        )
    return Step(
        key="decide",
        title="Decide",
        state=_roll_up(items),
        summary=summary,
        items=items,
        hidden=hidden,
        status=status,
        reason=reason,
    )


# -- Merge ----------------------------------------------------------------------


def _pr_item(
    p: PullRequestState,
    *,
    approved_refs: set[str],
    pending_refs: set[str],
    requires_review: bool,
    required_checks: frozenset[str] | None = None,
    approval_gated: bool = False,
    needs_self_review: bool = False,
) -> Item:
    def item(state: str, reason: str, owner: str) -> Item:
        return Item(
            text=f"{p.repo}#{p.number}: {p.title}",
            state=state,
            reason=reason,
            owner=owner,
            ref=f"{p.repo}#{p.number}",
            url=p.url,
        )

    stacked = bool(p.base_branch) and bool(p.default_branch) and p.base_branch != p.default_branch
    if stacked or p.depends_on:
        on = ", ".join(f"#{n}" for n in p.depends_on) or p.base_branch
        return item(WAITING, f"stacked on {on}; it merges after", OWNER_AGENT)

    def names(refs: Iterable[str]) -> bool:
        for ref in refs:
            parsed = parse_pr_ref(ref)
            if parsed and parsed[0] == p.repo and parsed[1] == p.number and same_sha(
                parsed[2], p.head_sha
            ):
                return True
        return False

    approved = names(approved_refs) if p.head_sha else False
    checks = p.checks
    if approval_gated:
        return _approval_gated_item(p, item, approved, names(pending_refs), required_checks)
    if requires_review and not approved:
        if not p.head_sha:
            return item(
                UNKNOWN, "its head was not read, so its approval cannot be checked", OWNER_CI
            )
        if names(pending_refs):
            return item(BLOCKED, "blocked until you decide it in step 1", OWNER_YOU)
        return item(
            WAITING,
            f"waiting on {REVIEW_CHECK}: no request at its head {p.head_sha[:7]}",
            OWNER_DELIVERY,
        )
    if needs_self_review and not p.has_self_review:
        if p.has_self_review is None:
            return item(
                UNKNOWN, "its files were not read, so its self-review record cannot be checked",
                OWNER_CI,
            )
        return item(WAITING, f"needs your self-review record ({SELF_REVIEW_FILE})", OWNER_YOU)
    if p.mergeable is False or p.mergeable_state == "dirty":
        return item(BLOCKED, f"conflicts with {p.base_branch or 'its base'}", OWNER_AGENT)
    if checks is not None and checks.failed:
        return item(BLOCKED, f"{checks.failed} of {checks.total} check(s) failed", OWNER_AGENT)
    if p.mergeable_state == "behind":
        return item(
            WAITING,
            f"branch behind {p.base_branch or 'main'}, an agent must update it",
            OWNER_AGENT,
        )
    if checks is None:
        return item(UNKNOWN, "its checks could not be read", OWNER_CI)
    if checks.pending:
        return item(WAITING, f"{checks.pending} check(s) still running", OWNER_CI)
    if not checks.total:
        # Start-Here skips a PR no check has reported on: nothing judged it yet.
        return item(WAITING, "no check has reported on it yet", OWNER_CI)
    if p.mergeable is None:
        return item(UNKNOWN, "GitHub has not said whether it can merge", OWNER_CI)
    green = f"{checks.passed}/{checks.total} checks green"
    return item(READY, f"approved at its head, {green}" if requires_review else green, OWNER_YOU)


def _approval_gated_item(
    p: PullRequestState,
    item: Callable[[str, str, str], Item],
    approved: bool,
    pending: bool,
    required: frozenset[str] | None,
) -> Item:
    """TheHub's rule: a PR merges only at the exact head an approved request
    names, and only a *required* check that is not green stops it. A conflict
    is still named: the merge would refuse it."""
    if not p.head_sha:
        return item(UNKNOWN, "its head was not read, so its approval cannot be checked", OWNER_CI)
    if not approved:
        if pending:
            return item(BLOCKED, "blocked until you decide it in step 1", OWNER_YOU)
        return item(
            WAITING,
            f"not approved at its head {p.head_sha[:7]}: it waits for the next batch",
            OWNER_DELIVERY,
        )
    if p.mergeable is False or p.mergeable_state == "dirty":
        return item(BLOCKED, f"conflicts with {p.base_branch or 'its base'}", OWNER_AGENT)
    checks = p.checks
    # Unknown protection is read as requiring checks: never guess ready.
    enforced = required is None or bool(required)
    if enforced:
        if checks is None:
            return item(UNKNOWN, "its checks could not be read", OWNER_CI)
        if checks.failed:
            return item(
                BLOCKED,
                f"{checks.failed} of {checks.total} check(s) failed, and "
                f"{p.base_branch or 'its base'} requires checks",
                OWNER_AGENT,
            )
        if checks.pending:
            return item(WAITING, f"{checks.pending} check(s) still running", OWNER_CI)
    advisory = (
        f"; {checks.failed} advisory check(s) red, none required"
        if not enforced and checks is not None and checks.failed
        else ""
    )
    return item(READY, f"approved at its head{advisory}", OWNER_YOU)


def merge_step(
    prs: list[PullRequestState] | None,
    *,
    approved_refs: set[str],
    pending_refs: set[str],
    requires_review: dict[str, bool | None],
    required_checks: dict[str, frozenset[str] | None] | None = None,
    approval_repos: frozenset[str] | set[str] = APPROVAL_REPOS,
    self_review_repos: frozenset[str] | set[str] = SELF_REVIEW_REPOS,
    prs_reason: str = "",
) -> Step:
    if prs is None:
        return Step(
            key="merge",
            title="Merge",
            state=UNKNOWN,
            summary="pull requests could not be read",
            status=UNAVAILABLE,
            reason=prs_reason or "GitHub's pull requests were not read.",
            notes=list(MERGE_HOST_NOTES),
        )
    required = required_checks or {}
    drafts = sorted((p for p in prs if p.draft), key=lambda p: (p.repo, p.number))
    offered = sorted((p for p in prs if not p.draft), key=lambda p: (p.repo, p.number))
    items = [
        _pr_item(
            p,
            approved_refs=approved_refs,
            pending_refs=pending_refs,
            # Unknown protection is read as requiring review: never guess ready.
            requires_review=requires_review.get(p.repo) is not False,
            required_checks=required.get(p.repo),
            approval_gated=p.repo in approval_repos,
            needs_self_review=p.repo in self_review_repos,
        )
        for p in offered
    ]
    ready = sum(1 for i in items if i.state == READY)
    return Step(
        key="merge",
        title="Merge",
        state=_roll_up(items),
        summary=(
            "nothing open to merge" if not items else f"{ready} ready, {len(items) - ready} not yet"
        ),
        items=items,
        hidden=[
            f"{p.repo}#{p.number}: a draft; Start-Here offers a draft only when its "
            "ready-drafts list names it"
            for p in drafts
        ],
        status=PARTIAL if prs_reason else OK,
        reason=prs_reason,
        notes=list(MERGE_HOST_NOTES),
    )


# -- Deploy ---------------------------------------------------------------------


@dataclass
class DeployFacts:
    repo: str
    #: `MYKRONOS_BUILD_SHA` of this process. Empty when the image lacks it.
    running_sha: str
    #: The default branch's head. Empty when GitHub could not be read.
    main_sha: str
    #: (status, conclusion) of main's Delivery run, or None when none was found.
    delivery: tuple[str, str | None] | None
    #: Concourse job -> its latest finished build's status, None if unread.
    lanes: dict[str, str | None]
    #: `GET /api/oracle/decisions/by-commit` for main, as that route answers
    #: it (`api.oracle.commit_decision`), or None when unread.
    decision: dict[str, Any] | None
    now: datetime
    reason: str = ""


def in_backup_window(now: datetime) -> bool:
    # The platform's timestamps are naive UTC (spec 01 §6).
    aware = now if now.tzinfo else now.replace(tzinfo=UTC)
    clock = aware.astimezone(UTC).time()
    return BACKUP_WINDOW[0] <= clock < BACKUP_WINDOW[1]


def deploy_step(f: DeployFacts) -> Step:
    def short(sha: str) -> str:
        return sha[:7] if sha else "unknown"

    delivery_word = " ".join(x for x in (f.delivery or ("not found", None)) if x)
    red_lanes = [name for name, status in f.lanes.items() if status != "succeeded"]
    unread_lanes = [name for name in red_lanes if not f.lanes[name]]
    lanes_word = (
        "green"
        if not red_lanes
        else ", ".join(
            f"{n} {f.lanes[n]}" if f.lanes[n] else f"{n} could not be read" for n in red_lanes
        )
    )
    window = in_backup_window(f.now)
    if f.decision is None:
        gate_word, gate_state = "not read", UNKNOWN
    elif not f.decision.get("found"):
        gate_word, gate_state = "no decision for main yet", WAITING
    elif f.decision.get("introduced_blocking"):
        gate_word, gate_state = "introduced blocking findings", BLOCKED
    else:
        word = f.decision.get("effective_recommendation") or f.decision.get("recommendation")
        gate_word, gate_state = str(word or "decided"), READY
    items = [
        Item(
            "Delivery on main",
            READY
            if f.delivery == ("completed", "success")
            else BLOCKED
            if f.delivery and f.delivery[0] == "completed"
            else WAITING,
            delivery_word,
            OWNER_DELIVERY,
        ),
        Item(
            " and ".join(DEPLOY_LANES) + " lanes",
            READY if not red_lanes else BLOCKED,
            lanes_word,
            OWNER_AGENT,
        ),
        Item("risk gate", gate_state, gate_word, OWNER_CI),
        Item(
            "backup window",
            WAITING if window else READY,
            "02:40-04:15Z, now inside it" if window else "outside 02:40-04:15Z",
            OWNER_YOU,
        ),
    ]
    base = Step(
        key="deploy",
        title="Deploy",
        state=UNKNOWN,
        summary=f"deploy {short(f.main_sha)}: production runs {short(f.running_sha)}",
        items=items,
        notes=list(HOST_ONLY_GUARDS),
        status=OK if not f.reason else PARTIAL,
        reason=f.reason,
    )
    # Start-Here's order, so the first reason it would print is the one given.
    if not f.running_sha or not f.main_sha:
        base.state = UNKNOWN
        base.reason = f.reason or (
            "The running sha is unknown (the image was built without MYKRONOS_BUILD_SHA)."
            if not f.running_sha
            else "main's head could not be read."
        )
        base.status = PARTIAL
    elif same_sha(f.running_sha, f.main_sha):
        base.state, base.summary, base.items = DONE, "production is on main", []
    elif window:
        base.state = WAITING
        base.reason = "main is ahead, but 02:40-04:15Z is the backup window. Deploy after it."
    elif f.delivery and f.delivery[0] == "completed" and f.delivery[1] != "success":
        base.state = BLOCKED
        base.reason = f"main's Delivery concluded {f.delivery[1]}: no image to deploy."
    elif red_lanes:
        base.state = BLOCKED
        base.reason = (
            f"not deploying a broken main: {lanes_word}."
            if len(unread_lanes) < len(red_lanes)
            else f"Start-Here counts a lane it cannot read as not green: {lanes_word}."
        )
    elif f.delivery != ("completed", "success"):
        base.state = WAITING
        base.reason = "Delivery on main has not succeeded yet"
    elif gate_state == BLOCKED:
        base.state = BLOCKED
        base.reason = f"the gate refused {short(f.main_sha)}: it introduced blocking findings."
    else:
        base.state = READY
        base.reason = (
            "deploy.ps1 waits for the risk gate's verdict"
            if gate_state != READY
            else "every guard the server can see is green"
        )
    return base


# -- Tasks ----------------------------------------------------------------------

OPERATOR_ACTION_PREFIX = "operator action:"


def tasks_step(
    stories: list[dict[str, Any]] | None,
    checks: dict[int, operator_checks.Verification] | None,
    *,
    board_reason: str = "",
    checks_reason: str = "Operator actions were not checked against GitHub.",
    registry: dict[int, operator_checks.Probe] | None = None,
) -> Step:
    if stories is None:
        return Step(
            key="tasks",
            title="Tasks",
            state=UNKNOWN,
            summary="the board could not be read",
            status=UNAVAILABLE,
            reason=board_reason or "TheHub's board was not read.",
        )
    actions = [
        s for s in stories if str(s.get("title") or "").lower().startswith(OPERATOR_ACTION_PREFIX)
    ]
    items: list[Item] = []
    hidden: list[str] = []
    for story in actions:
        ref = f"#{story.get('id')}"
        v = operator_checks.for_story(story.get("id"), checks, checks_reason, registry)
        if v.verification == operator_checks.OBSERVED_DONE:
            hidden.append(f"{ref} is done on GitHub: close the story")
            continue
        reason = {
            operator_checks.OBSERVED_NOT_DONE: f"checked: {v.evidence}",
            operator_checks.PROBE_ERROR: f"could not check: {v.evidence}",
        }.get(v.verification, "nothing checks this one; only you know")
        title = str(story.get("title") or "")
        items.append(Item(text=title[len(OPERATOR_ACTION_PREFIX):].strip() or title, state=READY,
                          reason=reason, owner=OWNER_YOU, ref=ref))
    return Step(
        key="tasks",
        title="Tasks",
        state=_roll_up(items),
        summary="nothing for you today" if not items else f"{len(items)} for you",
        items=items,
        hidden=hidden,
        notes=["Start-Here's one-off scripts run on the host and are not listed here."],
        status=PARTIAL if checks is None and actions else OK,
        reason=checks_reason if checks is None and actions else "",
    )


# -- Reading --------------------------------------------------------------------


def _error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


def _approvals(
    db: Any, reviewer_mode: str, head_refs: set[str]
) -> tuple[list[PendingApproval], set[str], set[str]]:
    """Pending requests, and the approved ones among `head_refs` (each open
    pull request's `repo#n@head`): only an approval at a head counts, so the
    approvals ever made are never all read."""
    from mykronos.approvals.reviewer import SHADOW_ACTION
    from mykronos.db.models import ApprovalRequest, AuditLogEntry

    with db.session() as session:
        pending_rows = list(
            session.execute(
                select(ApprovalRequest)
                .where(ApprovalRequest.state == "pending")
                .order_by(ApprovalRequest.created_at)
            ).scalars()
        )
        approved: set[str] = set()
        if head_refs:
            approved = {
                str(ref)
                for ref in session.execute(
                    select(ApprovalRequest.subject_ref)
                    .where(ApprovalRequest.state == "approved")
                    .where(ApprovalRequest.duty == PR_DUTY)
                    .where(ApprovalRequest.subject_ref.in_(sorted(head_refs)))
                ).scalars()
            }
        reviewed: set[str] | None = None
        if reviewer_mode == "shadow" and pending_rows:
            reviewed = {
                str(e)
                for e in session.execute(
                    select(AuditLogEntry.entity_id)
                    .where(AuditLogEntry.action == SHADOW_ACTION)
                    .where(AuditLogEntry.entity_id.in_([r.id for r in pending_rows]))
                ).scalars()
            }
        pending = [
            PendingApproval(
                id=r.id,
                duty=r.duty,
                tier=r.tier,
                subject_ref=r.subject_ref,
                reviewed=None if reviewer_mode != "shadow" else r.id in (reviewed or set()),
            )
            for r in pending_rows
        ]
        pending_refs = {r.subject_ref for r in pending_rows if r.duty == PR_DUTY}
    return pending, approved, pending_refs


async def _protections(
    db: Any, factory: Any, branches: dict[str, str]
) -> tuple[dict[str, bool | None], dict[str, frozenset[str] | None]]:
    """Per repository: whether its branch requires `independent-review`, and
    the checks it requires. None for either when protection was not read."""
    from mykronos.approvals.pull_requests import client_for

    async def one(repo: str, branch: str) -> tuple[str, frozenset[str] | None]:
        client = client_for(db, factory, repo) if factory is not None else None
        if client is None:
            return repo, None
        try:
            protection = await client.get_branch_protection(repo, branch)
        except Exception:  # noqa: BLE001 - an unread protection is "unknown", never "none"
            return repo, None
        if protection is None:
            return repo, frozenset()
        required = protection.get("required_status_checks") or {}
        contexts = {str(c) for c in required.get("contexts") or []}
        contexts |= {
            str(c.get("context")) for c in required.get("checks") or [] if isinstance(c, dict)
        }
        return repo, frozenset(contexts)

    pairs = await asyncio.gather(*(one(r, b) for r, b in branches.items()))
    checks = dict(pairs)
    review = {r: (None if c is None else REVIEW_CHECK in c) for r, c in checks.items()}
    return review, checks


async def _live_heads(db: Any, factory: Any, pending: list[PendingApproval]) -> LiveHeads:
    """Each pending pull-request request's pull request, read live (Start-Here's
    `gh pr view` per request). Bounded by the pending requests, a few at a time."""
    from mykronos.approvals.pull_requests import client_for

    wanted = sorted(
        {
            (parsed[0], parsed[1])
            for r in pending
            if r.duty == PR_DUTY and (parsed := parse_pr_ref(r.subject_ref)) is not None
        }
    )
    gate = asyncio.Semaphore(LIVE_READ_CONCURRENCY)

    async def one(repo: str, number: int) -> LiveHead | str:
        if factory is None:
            return "no GitHub client is configured"
        client = client_for(db, factory, repo)
        if client is None:
            return f"{repo} is not onboarded, so its pull request was not read"
        async with gate:
            try:
                live = await asyncio.wait_for(
                    client.get_pull_request(repo, number), LIVE_READ_TIMEOUT_SECONDS
                )
            except Exception as exc:  # noqa: BLE001 - kept visible, with why
                return f"its pull request could not be read ({type(exc).__name__})"
        if live is None:
            return LiveHead(open=False, head_sha="")
        return LiveHead(open=live.state == "open" and not live.merged, head_sha=live.head_sha)

    answers = await asyncio.gather(*(one(repo, n) for repo, n in wanted))
    return dict(zip(wanted, answers, strict=True))


async def _self_reviews(db: Any, factory: Any, prs: list[PullRequestState]) -> None:
    """Whether each open keel or binnacle PR carries the self-review record,
    as Start-Here reads it from the PR's files. Left None when unread."""
    from mykronos.approvals.pull_requests import client_for

    gate = asyncio.Semaphore(LIVE_READ_CONCURRENCY)

    async def one(p: PullRequestState) -> None:
        client = client_for(db, factory, p.repo) if factory is not None else None
        if client is None:
            return
        async with gate:
            try:
                files = await asyncio.wait_for(
                    client.pull_request_files(p.repo, p.number), LIVE_READ_TIMEOUT_SECONDS
                )
            except Exception:  # noqa: BLE001 - None: the line says it was not read
                return
        p.has_self_review = any(SELF_REVIEW_FILE in f.filename for f in files)

    await asyncio.gather(
        *(one(p) for p in prs if p.repo in SELF_REVIEW_REPOS and not p.draft)
    )


async def _deploy_facts(state: Any, now: datetime) -> DeployFacts:
    from mykronos.approvals.pull_requests import client_for
    from mykronos.ci import ConcourseClient

    settings = state.settings
    reasons: list[str] = []
    main_sha = ""
    delivery: tuple[str, str | None] | None = None
    client = client_for(state.db, state.github_factory, DEPLOY_REPO)
    if client is None:
        reasons.append(f"{DEPLOY_REPO} is not onboarded, so main and Delivery were not read.")
    else:
        try:
            commits = await client.list_commits(DEPLOY_REPO, "main", limit=1)
            main_sha = commits[0].sha if commits else ""
            if main_sha:
                delivery = await client.workflow_run_for_commit(
                    DEPLOY_REPO, DELIVERY_WORKFLOW, main_sha
                )
        except Exception as exc:  # noqa: BLE001 - the step says what it could not read
            reasons.append(f"GitHub: {_error(exc)}")
    lanes: dict[str, str | None] = {name: None for name in DEPLOY_LANES}
    if settings.concourse_url:
        concourse = ConcourseClient(
            settings.concourse_url,
            team=settings.concourse_team,
            external_url=settings.concourse_external_url,
        )
        jobs = await asyncio.to_thread(concourse.jobs, DEPLOY_PIPELINE)
        if jobs is None:
            reasons.append("Concourse could not be read.")
        for job in jobs or []:
            name = str(job.get("name") or "")
            build = job.get("finished_build")
            if name in lanes and isinstance(build, dict):
                lanes[name] = str(build.get("status") or "") or None
    else:
        reasons.append("No Concourse is configured, so the lanes were not read.")
    decision: dict[str, Any] | None = None
    if main_sha:
        try:
            decision = await asyncio.to_thread(_risk_gate, state, main_sha)
        except Exception as exc:  # noqa: BLE001
            reasons.append(f"The risk gate could not be read: {_error(exc)}")
    return DeployFacts(
        repo=DEPLOY_REPO,
        running_sha=str(getattr(settings, "build_sha", "") or "").strip(),
        main_sha=main_sha,
        delivery=delivery,
        lanes=lanes,
        decision=decision,
        now=now,
        reason=" ".join(reasons),
    )


def _risk_gate(state: Any, sha: str) -> dict[str, Any]:
    """`/decisions/by-commit/{sha}`'s body, computed by the route's own code:
    the floor (`introduced_blocking`) is what the commit introduced, judged
    now, which is what Start-Here and deploy.ps1 read."""
    from mykronos.api.oracle import commit_decision
    from mykronos.oracle.service import OracleService

    service = OracleService(
        state.catalog, state.buffer, state.oracle_policy, state.knowledge, db=state.db
    )
    return commit_decision(service, state.catalog, sha).model_dump()


async def gather(state: Any, now: datetime) -> list[Step]:
    """Read every source and build the four steps. Each read fails alone."""
    from mykronos import delivery_sources
    from mykronos.approvals import reviewer

    inputs = await delivery_sources.gather(state)
    read = inputs.pull_requests
    prs: list[PullRequestState] | None = None
    prs_reason = "" if read is not None else inputs.pull_requests_error
    if read is not None:
        prs = [
            PullRequestState(
                repo=p.repo_full_name,
                number=p.number,
                title=p.title,
                url=p.url,
                draft=p.draft,
                head_sha=p.head_sha,
                base_branch=p.base_branch,
                default_branch=p.default_branch,
                mergeable=p.mergeable,
                mergeable_state=p.mergeable_state,
                checks=p.checks,
                depends_on=list(p.depends_on),
                detail_read=p.detail_read,
            )
            for p in read.pull_requests
        ]
        notes = [f"{repo}: {why}" for repo, why in read.unreachable]
        if read.stale:
            notes.append(read.reason)
        if read.details_unread:
            notes.append(f"{read.details_unread} pull request(s) not read in detail")
        prs_reason = "; ".join(notes)
    factory = getattr(state, "github_factory", None)
    head_refs = {f"{p.repo}#{p.number}@{p.head_sha}" for p in prs or [] if p.head_sha}
    pending, approved, pending_refs = await asyncio.to_thread(
        _approvals, state.db, reviewer.mode(state.settings), head_refs
    )
    branches = {p.repo: p.default_branch or "main" for p in prs or []}
    (requires, required), heads, _ = await asyncio.gather(
        _protections(state.db, factory, branches),
        _live_heads(state.db, factory, pending),
        _self_reviews(state.db, factory, prs or []),
    )
    facts = await _deploy_facts(state, now)
    board = inputs.board
    stories = board.open_stories() if board is not None else None
    return [
        decide_step(pending, heads),
        merge_step(
            prs,
            approved_refs=approved,
            pending_refs=pending_refs,
            requires_review=requires,
            required_checks=required,
            prs_reason=prs_reason,
        ),
        deploy_step(facts),
        tasks_step(
            stories,
            inputs.operator_checks,
            board_reason=inputs.board_error,
            checks_reason=inputs.operator_checks_error,
        ),
    ]
