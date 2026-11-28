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
credential inside its last `CREDENTIAL_URGENT_HOURS` or lapsed within them (the
incident job's window) - carries a `question`: one question, three options, the
recommended one first. `send_urgent_questions` DMs each one by itself. It builds
the same section the page does, so the two cannot disagree. After review of
PR #1238:

- a source the job cannot read is itself an urgent question ("cannot read
  X"), and an unreadable section also fails the run: never a quiet success;
- at most `URGENT_PER_TICK` questions a tick, the last naming how many more
  wait, and at most `URGENT_PER_DAY` in any 24 h; the rest are on the page
  and in the 07:00 digest;
- an item is asked again after `ASK_AGAIN_HOURS`, except a gate refusal,
  which is asked once per refused commit (`since_sha`) and then left to the
  digest, as `risk_gate_notice` does for the alerts channel (#61197);
- the ask is audited (`briefing.urgent`, outcome `asked`) BEFORE it is sent,
  so an audit write that fails sends nothing and cannot resend every tick;
  Slack refusing it writes outcome `undelivered`, and the next tick asks;
- the history read is bounded by the rows' own `created_at`.

**Who sees credentials.** The calendar names credentials, so
`GET /api/credentials/expiring` refuses a principal that may not write. The
briefing route applies the same rule through `withhold_credentials`: such a
principal gets the count, not the rows.
"""

from __future__ import annotations

import dataclasses
import logging
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import or_, select

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
URGENT_PER_TICK = 3
URGENT_PER_DAY = 6

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
        # The incident job's window: inside the last day, or lapsed within one.
        # A credential lapsed longer ago stays in the digest, never asked.
        urgent = ""
        if -CREDENTIAL_URGENT_HOURS < left <= 0:
            urgent = f"it lapsed within the last {CREDENTIAL_URGENT_HOURS} h"
        elif 0 < left <= CREDENTIAL_URGENT_HOURS:
            urgent = f"under {CREDENTIAL_URGENT_HOURS} h left"
        items.append(_item(
            "credential", f"credential:{row['kind']}:{actor}",
            f"{name} {when} ({row['expires_at']:%Y-%m-%d %H:%MZ}, {row['source']}).",
            "Whatever uses it stops working when it lapses.",
            str(row["renewal_step"]),
            urgent=urgent,
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
    unreadable = (
        [{"key": "unreadable:credential-file", "what": "the declared credential file",
          "why": why}] if why else []
    )
    return Section(
        key=KEY, title=TITLE, status=PARTIAL if reasons else OK, source=SOURCE,
        as_of=moment, reason=" ".join(reasons),
        lines=[Line(what=i["what"], so_what=i["so_what"], work=DECISION,
                    repo_full_name=i["repo_full_name"], ref=i["decide"]) for i in items],
        data={"items": items, "by_class": {c: by_class[c] for c in CLASSES},
              "counts": counts, "not_read": [dict(g) for g in NOT_READ],
              "unreadable": unreadable},
    )


def withhold_credentials(section: Section) -> Section:
    """The section for a principal that may not list credentials: the same
    rule as `GET /api/credentials/expiring` (TheHub #61104). The credential
    items and their lines go; `by_class` keeps their count, and
    `counts.credentials_withheld` says how many were left out."""
    items = section.data.get("items", [])
    kept = [i for i in items if i["class"] != "credential"]
    if len(kept) == len(items):
        return section
    refs = {(i["what"], i["decide"]) for i in items if i["class"] == "credential"}
    counts = {**section.data.get("counts", {}), "credentials_withheld": len(items) - len(kept)}
    return dataclasses.replace(
        section,
        lines=[ln for ln in section.lines if (ln.what, ln.ref) not in refs],
        data={**section.data, "items": kept, "counts": counts},
    )


# -- urgent questions --------------------------------------------------------


class UrgentUndeliveredError(RuntimeError):
    """Slack did not accept a question; it is audited `undelivered`, so the
    next tick asks again."""


class ExceptionsUnreadableError(RuntimeError):
    """The exceptions could not be read. Raised after the "cannot read"
    question, so the run is recorded as failed and platform health shows it."""


def _unreadable(key: str, what: str, why: str) -> dict[str, Any]:
    """A source the digest cannot read, as an urgent question of its own."""
    return _item(
        "unreadable", key, f"MyKronos cannot read {what}: {why}",
        "Until it is read, the digest cannot list what waits on you there.",
        "GET /api/dashboard/platform-health",
        urgent=f"MyKronos cannot read {what}",
        ask=f"MyKronos cannot read {what} ({why}). How should it be handled?",
        options=(
            "Have an agent fix the read today, from the backend log and platform health.",
            "Check those sources yourself on the briefing page until it is fixed.",
            f"Wait: a passing failure clears by itself; asked again in {ASK_AGAIN_HOURS} h "
            "if not.",
        ),
    )


def question_note(item: dict[str, Any], *, url: str, more: int = 0) -> Notification:
    """One urgent question: the ask, three options with the recommendation
    first, and the deciding command. `more` (the last question of a tick)
    names how many others wait on the page."""
    from mykronos.briefing_dm import WHAT_CHARS, _cut
    from mykronos.notify import Notification

    question = item["question"]
    options = [_cut(o, 300) for o in question["options"]]
    again = (
        "not asked again for this commit; the 07:00 digest lists it"
        if str(item["key"]).startswith("gate:") else
        f"not asked again for {ASK_AGAIN_HOURS} h"
    )
    lines = [
        f"*{_cut(question['ask'], 300)}*",
        f"1. (recommended) {options[0]}",
        f"2. {options[1]}",
        f"3. {options[2]}",
        f"Decide: {_cut(item['decide'], WHAT_CHARS)}",
        f"Asked because {_cut(item['urgent'], 80)}; {again}. <{url}|The briefing>",
    ]
    if more:
        lines.append(
            f"{more} more cannot wait either: they are on the briefing page and in the "
            "07:00 digest, and are asked as the limits allow."
        )
    return Notification(title="One decision cannot wait for 07:00", detail="",
                        repo_full_name="", level="critical", lines=tuple(lines))


@dataclasses.dataclass(frozen=True)
class _History:
    #: Keys whose latest outcome is `asked`, and when.
    asked: dict[str, datetime]
    #: Questions that reached Slack in the last 24 h.
    in_last_day: int


def _history(db: Any, moment: datetime, gate_keys: list[str]) -> _History:
    """What was asked. Bounded by `created_at`: the last 24 h, plus every row
    for the gate refusals being considered (asked once per commit)."""
    since = moment - timedelta(hours=24)
    where = AuditLogEntry.created_at > since
    if gate_keys:
        where = or_(where, AuditLogEntry.entity_id.in_(gate_keys))
    with db.session() as session:
        rows = session.execute(
            select(AuditLogEntry.entity_id, AuditLogEntry.detail, AuditLogEntry.created_at)
            .where(AuditLogEntry.action == ACTION, where)
        ).all()
    events = sorted(
        ((created, (detail or {}).get("outcome", "asked") == "undelivered", str(entity))
         for entity, detail, created in rows),
    )
    asked: dict[str, datetime] = {}
    in_last_day = 0
    for created, undelivered, entity in events:
        recent = created > since
        if undelivered:
            asked.pop(entity, None)
            in_last_day -= recent
        else:
            asked[entity] = created
            in_last_day += recent
    return _History(asked=asked, in_last_day=max(0, in_last_day))


def _record(db: Any, key: str, outcome: str, urgent: str, moment: datetime) -> None:
    with db.session() as session:
        entry = db.audit(session, actor=f"job:{BRIEFING_URGENT_JOB}", action=ACTION,
                         entity_type="briefing_exception", entity_id=key,
                         urgent=urgent, outcome=outcome, asked_at=moment.isoformat())
        # The job's own clock, so the window and the record agree.
        entry.created_at = moment


async def send_urgent_questions(
    settings: Settings, *, db: Any, notifier: Notifier | None = None,
    now: datetime | None = None,
) -> list[Notification]:
    """DM the urgent items that are due, one per message, within the caps.
    Nothing urgent is a quiet success; something to ask with Slack
    unconfigured raises `JobSkipped`; an unreadable section is asked and then
    raises `ExceptionsUnreadableError`."""
    from mykronos.briefing_dm import page_url, unconfigured
    from mykronos.notify import SlackNotifier

    moment = _naive(now or datetime.now(UTC))
    section = exceptions_section(db, settings, now=moment)
    readable = section.status in (OK, PARTIAL)
    if readable:
        candidates = [
            _unreadable(u["key"], u["what"], u["why"])
            for u in section.data.get("unreadable", [])
        ] + [i for i in section.data.get("items", []) if i["question"]]
    else:
        candidates = [_unreadable("unreadable:exceptions", "the exceptions", section.reason)]
    for item in candidates:
        item["key"] = str(item["key"])[:255]
    history = _history(db, moment, [i["key"] for i in candidates
                                    if i["key"].startswith("gate:")])
    again_after = moment - timedelta(hours=ASK_AGAIN_HOURS)

    def asked(key: str) -> bool:
        at = history.asked.get(key)
        return at is not None and (key.startswith("gate:") or at > again_after)

    due = [i for i in candidates if not asked(i["key"])]
    sent: list[Notification] = []
    if due:
        reason = unconfigured(settings)
        if reason and not readable:
            raise ExceptionsUnreadableError(
                f"The exceptions could not be read, and {reason[0].lower()}{reason[1:]}"
            )
        if reason:
            raise JobSkipped(reason.replace("briefing DM", "urgent question"))
        sender = notifier or SlackNotifier(
            bot_token=settings.slack_bot_token, channel=settings.briefing_dm_channel
        )
        budget = max(0, min(URGENT_PER_TICK, URGENT_PER_DAY - history.in_last_day))
        batch = due[:budget]
        for index, item in enumerate(batch):
            more = len(due) - len(batch) if index == len(batch) - 1 else 0
            note = question_note(item, url=page_url(settings), more=more)
            # Recorded first: if this write fails nothing is sent, so a broken
            # audit log cannot turn into the same DM every tick.
            _record(db, item["key"], "asked", item["urgent"], moment)
            if not await sender.send(note):
                _record(db, item["key"], "undelivered", item["urgent"], moment)
                raise UrgentUndeliveredError(
                    "Slack did not accept an urgent question; the backend log has its "
                    "reason."
                )
            sent.append(note)
        if len(due) > len(batch):
            logger.info("Urgent questions held by the caps: %s.", len(due) - len(batch))
    logger.info("Urgent questions sent: %s.", len(sent))
    if not readable:
        raise ExceptionsUnreadableError(f"The exceptions could not be read: {section.reason}")
    return sent
