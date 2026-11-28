"""What only the operator can decide: the exceptions digest (TheHub #62419).

Step 7 of epic #62412. The 07:00 briefing DM (`briefing_dm`, TheHub #60864)
leads with this section and reduces the rest of the page to counts. Five
classes are items, each carrying the one command that decides it:

- **risk_acceptance** - a pending `risk_acceptance` approval, any tier;
- **disposition** - a pending `finding_disposition` approval, critical or high
  (medium and low are delegable to the security agent, so they are counts);
- **credential** - a credential expired or due within `CREDENTIAL_DUE_HOURS`
  that nothing renews by itself (`credential_expiry`; sub-agent credentials,
  renewed roles and self-rotating ingestion tokens are counts, by the same
  rule that keeps them from paging, `credential_expiry_incidents.quiet_actors`);
- **policy_change** - a pending governance-class `pull_request_merge` (a PR
  that edits approval, Oracle or pipeline policy) or a `delegation_grant`;
- **gate_refusal** - a risk-gate scope recorded `refused`
  (`risk_gate_notice_states`, TheHub #61197), any repository including TheHub,
  re-evaluated within `STALE_REFUSAL_DAYS`. An older one is a count: nothing
  is asking that gate any more.

Everything else (other pending approvals, approvals decided in the last 24 h,
including routine ones decided by standing rule, TheHub #62346) is a count in
`data.counts`.

**What has no record is named, never read as "none".** The deploy ratchet
(`oracle.deploy_gate`) answers and forgets: no refusal is stored. Credentials
waiting to be minted exist only in the operator's queue, outside MyKronos.
Both are in `data.not_read` and keep the section `partial` until a record
exists.

**Urgent questions.** An item that cannot wait for 07:00 - a non-PR gate
refused for over `RELEASE_BLOCKED_HOURS`, a critical-tier approval, or a
credential inside its last `CREDENTIAL_URGENT_HOURS` - carries a `question`:
one question, three options, the recommended one first. `send_urgent_questions`
DMs each one by itself and audits it (`briefing.urgent`), and an item asked
within `ASK_AGAIN_HOURS` is not asked again. It builds the same section the
page does, so the two cannot disagree.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from mykronos.daily_briefing import DECISION, OK, PARTIAL, Line, Section, _error, unavailable
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    AuditLogEntry,
    RiskAcceptance,
    RiskGateNoticeState,
)
from mykronos.jobs import BRIEFING_URGENT_JOB, JobSkipped

if TYPE_CHECKING:  # pragma: no cover
    from mykronos.config import Settings
    from mykronos.notify import Notification, Notifier

logger = logging.getLogger(__name__)

KEY, TITLE = "exceptions", "Decide"
SOURCE = (
    "approval_requests, approval_decisions, risk_acceptances; credential calendar "
    "(agent credentials, read and ingestion tokens, declared file); risk_gate_notice_states"
)
CLASSES = ("risk_acceptance", "disposition", "credential", "policy_change", "gate_refusal")

CREDENTIAL_DUE_HOURS = 48
CREDENTIAL_URGENT_HOURS = 24
RELEASE_BLOCKED_HOURS = 2
STALE_REFUSAL_DAYS = 7
ASK_AGAIN_HOURS = 12
TICK_SECONDS = 900

ACTION = "briefing.urgent"

NOT_READ = (
    {
        "class": "deploy_ratchet_refusals",
        "label": "deploy ratchet refusals",
        "why": "GET /api/oracle/deploy-gate keeps no record of a refusal.",
    },
    {
        "class": "credential_mints_waiting",
        "label": "credential mints waiting",
        "why": "A mint waiting for the operator is not recorded in MyKronos.",
    },
)


def _naive(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(tzinfo=None) if moment.tzinfo else moment


def _hours(since: datetime, now: datetime) -> int:
    return max(0, int((now - since).total_seconds() // 3600))


def _item(cls: str, key: str, what: str, so_what: str, decide: str, *,
          repo: str = "", urgent: str = "", ask: str = "",
          options: tuple[str, str, str] | None = None) -> dict[str, Any]:
    question = (
        {"ask": ask, "options": list(options), "recommended": 0}
        if urgent and options else None
    )
    return {"class": cls, "key": key, "what": what, "so_what": so_what, "decide": decide,
            "repo_full_name": repo, "urgent": urgent if question else "",
            "question": question}


# -- approvals ---------------------------------------------------------------

_LABELS = {
    "risk_acceptance": "risk acceptance",
    "finding_disposition": "disposition request",
    "pull_request_merge": "policy-change merge",
    "delegation_grant": "delegation grant",
}


def _class_of(duty: str, tier: str) -> str:
    if duty == "risk_acceptance":
        return "risk_acceptance"
    if duty == "finding_disposition" and tier in ("critical", "high"):
        return "disposition"
    if (duty, tier) == ("pull_request_merge", "governance") or duty == "delegation_grant":
        return "policy_change"
    return ""


def _approvals(session: Any, now: datetime) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pending = session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.state == "pending", ApprovalRequest.expires_at > now
        ).order_by(ApprovalRequest.created_at)
    ).scalars().all()
    acceptances = {
        r.id: r
        for r in session.execute(
            select(RiskAcceptance).where(
                RiskAcceptance.id.in_([p.subject_ref for p in pending
                                       if p.duty == "risk_acceptance"])
            )
        ).scalars()
    }
    items: list[dict[str, Any]] = []
    other: Counter[str] = Counter()
    for req in pending:
        cls = _class_of(req.duty, req.tier)
        if not cls:
            other[req.duty] += 1
            continue
        decide = f"POST /api/approvals/{req.id}/decisions"
        waited = _hours(req.created_at, now)
        record = acceptances.get(req.subject_ref)
        repo = str(record.repo_full_name) if record is not None else ""
        about = (
            f"{repo}, {len(record.covered_finding_ids or [])} finding(s)"
            if record is not None else req.subject_ref
        )
        what = (f"A {req.tier} {_LABELS[req.duty]} for {about} has waited {waited} h "
                f"(requested by {req.requested_by}).")
        critical = req.tier == "critical"
        items.append(_item(
            cls, f"approval:{req.id}", what,
            "Only a person may decide it; it lapses unanswered on "
            f"{req.expires_at:%Y-%m-%d %H:%MZ}.",
            decide, repo=repo,
            urgent="a critical waits on you" if critical else "",
            ask=f"A critical {_LABELS[req.duty]} for {about} has waited {waited} h. "
                "Will you decide it now?",
            options=(
                f"Read its evidence (GET /api/approvals/{req.id}/evidence) and decide "
                "it now: nothing else can.",
                "Reject it, and fix what it covers instead of accepting or closing it.",
                f"Leave it pending: it lapses on {req.expires_at:%Y-%m-%d} and the "
                "finding(s) stay open meanwhile.",
            ),
        ))
    since = now - timedelta(hours=24)
    kinds = [str(k) for k in session.execute(
        select(ApprovalDecision.approver_kind).where(ApprovalDecision.created_at >= since)
    ).scalars()]
    decided = {"total": len(kinds), "by_agent": kinds.count("agent"),
               "by_human": kinds.count("human")}
    return items, {"other_pending_approvals": dict(sorted(other.items())),
                   "decided_last_24h": decided}


# -- credentials -------------------------------------------------------------


def _credentials(session: Any, db: Any, settings: Any,
                 now: datetime) -> tuple[list[dict[str, Any]], int, str]:
    from mykronos import credential_expiry
    from mykronos.credential_expiry_incidents import AUTOMATIC_KINDS, quiet_actors

    why = ""
    try:
        declared = credential_expiry.load_all(
            getattr(settings, "credential_expiry_path", None),
            getattr(settings, "credential_expiry_private_path", None),
        )
    except credential_expiry.CredentialFileError as exc:
        declared, why = [], f"The declared credential file could not be read: {exc}."
    rows = credential_expiry.expiring(
        credential_expiry.collect(session, declared, now), now, CREDENTIAL_DUE_HOURS
    )
    quiet = quiet_actors(db, now)
    items, not_yours = [], 0
    for row in rows:
        actor = str(row["name"]).split(" (", 1)[0]
        if row["kind"] in AUTOMATIC_KINDS or (
            row["kind"] == "agent-credential" and actor in quiet
        ):
            not_yours += 1
            continue
        left = float(row["hours_left"])
        when = f"lapsed {-left:.0f} h ago" if left <= 0 else f"expires in {left:.0f} h"
        name = f"{row['name']} ({row['kind']})"
        items.append(_item(
            "credential", f"credential:{row['kind']}:{actor}",
            f"{name} {when} ({row['expires_at']:%Y-%m-%d %H:%MZ}, {row['source']}).",
            "Whatever uses it stops working when it lapses.",
            str(row["renewal_step"]),
            urgent=f"under {CREDENTIAL_URGENT_HOURS} h" if left < CREDENTIAL_URGENT_HOURS else "",
            ask=f"{name} {when}. Will you renew it now?",
            options=(f"Renew it now: {row['renewal_step']}",
                     "Revoke it, if nothing uses it any more.",
                     "Let it lapse and renew it later: what uses it fails until then."),
        ))
    return items, not_yours, why


# -- gate refusals -----------------------------------------------------------


def _refusals(session: Any, now: datetime) -> tuple[list[dict[str, Any]], int]:
    rows = session.execute(
        select(RiskGateNoticeState).where(RiskGateNoticeState.state == "refused")
        .order_by(RiskGateNoticeState.since)
    ).scalars().all()
    fresh_after = now - timedelta(days=STALE_REFUSAL_DAYS)
    items, stale = [], 0
    for r in rows:
        if r.updated_at < fresh_after:
            stale += 1
            continue
        held = _hours(r.since, now)
        release = not r.subject.startswith("pr_gate")
        sha = r.since_sha[:12]
        items.append(_item(
            "gate_refusal", f"gate:{r.repo_full_name}|{r.subject}|{r.since_sha}",
            f"The risk gate refuses {r.repo_full_name} {r.subject} since commit {sha}, "
            f"{held} h (score {r.last_score}, {r.held} later refusal(s) held).",
            "Fixing or accepting the blocking findings unblocks it; only a person may "
            "override the decision (deploy_override).",
            f"GET /api/oracle/decisions/by-commit/{r.since_sha}",
            repo=r.repo_full_name,
            urgent=(f"release blocked over {RELEASE_BLOCKED_HOURS} h"
                    if release and held >= RELEASE_BLOCKED_HOURS else ""),
            ask=f"{r.repo_full_name}'s {r.subject} has been refused by the risk gate for "
                f"{held} h (since {sha}). How should it be unblocked?",
            options=("Fix the blocking findings: an agent takes them as a story.",
                     "Accept the residual risk on them through a risk acceptance.",
                     "Override this decision (deploy_override, a person only) and fix "
                     "afterwards."),
        ))
    return items, stale


# -- the section -------------------------------------------------------------


def exceptions_section(db: Any, settings: Any, *, now: datetime) -> Section:
    """Every pending exception with its deciding command, the rest as counts."""
    moment = _naive(now)
    reasons = [f"Not recorded yet: {g['label']} ({g['why']})" for g in NOT_READ]
    try:
        with db.session() as session:
            approvals, counts = _approvals(session, moment)
            credentials, not_yours, why = _credentials(session, db, settings, moment)
            refusals, stale = _refusals(session, moment)
    except Exception as exc:  # noqa: BLE001 - reported, never shown as none
        logger.debug("Could not read the exceptions")
        return unavailable(KEY, TITLE, SOURCE, _error(exc))
    if why:
        reasons.append(why)
    items = [*approvals, *credentials, *refusals]
    by_class = Counter(i["class"] for i in items)
    counts.update(credentials_not_yours=not_yours, stale_gate_refusals=stale)
    return Section(
        key=KEY, title=TITLE, status=PARTIAL if reasons else OK, source=SOURCE,
        as_of=moment, reason=" ".join(reasons),
        lines=[Line(what=i["what"], so_what=i["so_what"], work=DECISION,
                    repo_full_name=i["repo_full_name"], ref=i["decide"]) for i in items],
        data={"items": items, "by_class": {c: by_class[c] for c in CLASSES},
              "counts": counts, "not_read": [dict(g) for g in NOT_READ]},
    )


# -- urgent questions --------------------------------------------------------


class UrgentUndeliveredError(RuntimeError):
    """Slack did not accept a question; it is not audited, so the next tick asks."""


def question_note(item: dict[str, Any], *, url: str) -> Notification:
    """One urgent question: the ask, three options with the recommendation
    first, and the deciding command."""
    from mykronos.briefing_dm import WHAT_CHARS, _cut
    from mykronos.notify import Notification

    question = item["question"]
    options = [_cut(o, 300) for o in question["options"]]
    lines = [
        f"*{_cut(question['ask'], 300)}*",
        f"1. (recommended) {options[0]}",
        f"2. {options[1]}",
        f"3. {options[2]}",
        f"Decide: {_cut(item['decide'], WHAT_CHARS)}",
        f"Asked because {_cut(item['urgent'], 80)}; not asked again for "
        f"{ASK_AGAIN_HOURS} h. <{url}|The briefing>",
    ]
    return Notification(title="One decision cannot wait for 07:00", detail="",
                        repo_full_name="", level="critical", lines=tuple(lines))


def _asked_since(db: Any, since: datetime) -> set[str]:
    with db.session() as session:
        rows = session.execute(
            select(AuditLogEntry.entity_id, AuditLogEntry.detail)
            .where(AuditLogEntry.action == ACTION)
        ).all()
    asked = set()
    for entity, detail in rows:
        stamp = (detail or {}).get("asked_at", "")
        try:
            at = _naive(datetime.fromisoformat(str(stamp)))
        except ValueError:
            continue
        if at > since:
            asked.add(str(entity))
    return asked


async def send_urgent_questions(
    settings: Settings, *, db: Any, notifier: Notifier | None = None,
    now: datetime | None = None,
) -> list[Notification]:
    """DM each urgent item not asked in the last `ASK_AGAIN_HOURS`, one per
    message. Nothing urgent is a quiet success; something to ask with Slack
    unconfigured raises `JobSkipped`."""
    from mykronos.briefing_dm import page_url, unconfigured
    from mykronos.notify import SlackNotifier

    moment = _naive(now or datetime.now(UTC))
    section = exceptions_section(db, settings, now=moment)
    asked = _asked_since(db, moment - timedelta(hours=ASK_AGAIN_HOURS))
    due = [i for i in section.data.get("items", [])
           if i["question"] and i["key"][:255] not in asked]
    if not due:
        return []
    reason = unconfigured(settings)
    if reason:
        raise JobSkipped(reason.replace("briefing DM", "urgent question"))
    sender = notifier or SlackNotifier(
        bot_token=settings.slack_bot_token, channel=settings.briefing_dm_channel
    )
    sent = []
    for item in due:
        note = question_note(item, url=page_url(settings))
        if not await sender.send(note):
            raise UrgentUndeliveredError(
                "Slack did not accept an urgent question; the backend log has its reason."
            )
        with db.session() as session:
            db.audit(session, actor=f"job:{BRIEFING_URGENT_JOB}", action=ACTION,
                     entity_type="briefing_exception", entity_id=item["key"][:255],
                     urgent=item["urgent"], asked_at=moment.isoformat())
        sent.append(note)
    logger.info("Urgent questions sent: %s.", len(sent))
    return sent
