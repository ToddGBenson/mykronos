"""The 07:00 briefing DM (TheHub #60864, epic #60858).

`GET /api/briefing/daily` is the page Todd reads first thing. This is what
puts it in front of him without his asking: once a local day, at
`briefing_dm_time` in `briefing_dm_timezone`, a short Slack DM that lists
exceptions only (TheHub #62419) and counts the rest:

- every item only he can decide (`briefing_exceptions`: pending risk
  acceptances, high/critical disposition requests, credentials due,
  policy-change approvals, risk-gate refusals), each with its deciding
  command, and the classes MyKronos has no record of yet, by name;
- how much else on the page is work, split merge / decision / story, and
  the rest as counts (other approvals pending, approvals decided in 24 h,
  suggested-focus lines);
- the open critical/high backlog, by severity: the scan post names only
  new findings (TheHub #61195), so this is where the totals are;
- every section that could not be read, by name - a briefing that leaves out
  what it could not see reads as "all clear", which is the failure the page
  itself was built against (#401);
- the products as one count, naming any that could not be read;

and a link to `/briefing` on the dashboard, where the rest is. Before #62419
the DM also listed the top three focus lines and one line per product; both
are on the page.

**The DM is the page, not a second opinion.** Both are read through the one
route, `api.briefing_daily.daily_briefing_route`, so when B3 (TheHub #60861)
fills "Needs you today" and "Sprint health", the DM gains them the same day
with no change here.

**Scheduled like every other job, and judged like one.** It runs under
`main._every` on a short tick. A tick before the send time, or after today's
DM has gone, raises `JobNotDue` and leaves `job_runs` alone; so the row's
`last_succeeded_at` is the last DM actually delivered, `interval_seconds` is a
day (`jobs.RECORDED_INTERVAL_SECONDS`), and platform health reads a missed
morning as `late` and an undelivered one as `failing` - the same states it
reads for every other job. "Already sent today" is that row, so a restart does
not send twice.

**Not configured is said, never silent.** No bot token, no DM target or no
dashboard URL raises `JobSkipped` with the setting's name: the row reads
`skipped` with the reason, and the next tick tries again, so the DM goes out
the same day the setting arrives.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, time, tzinfo
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select

from mykronos.db.models import JobRun, RepoOnboarding
from mykronos.jobs import BRIEFING_DM_JOB, JobNotDue, JobSkipped
from mykronos.logsafe import scrub
from mykronos.notify import Notification, Notifier, SlackNotifier

if TYPE_CHECKING:  # pragma: no cover - import-cycle guard
    from fastapi import FastAPI

    from mykronos.api.briefing_daily import DailyBriefingOut
    from mykronos.config import Settings

logger = logging.getLogger(__name__)

# The `job_runs` row, and the name platform health shows, is
# `jobs.BRIEFING_DM_JOB` ("briefing-dm"), imported above.

#: How often the scheduler asks whether the DM is due. Five minutes late is
#: still 07:05; a restart is caught within the same window.
TICK_SECONDS = 300

#: How many exceptions the DM lists (TheHub #62419). The page has the rest.
EXCEPTIONS_IN_DM = 10

#: The operator's exceptions (`briefing_exceptions`): listed, not counted.
EXCEPTIONS_KEY = "exceptions"

#: A line in a DM is read on a phone. Long finding titles are cut, and the
#: page carries them whole.
WHAT_CHARS = 140
REASON_CHARS = 100

#: The overall section the counts must not double: it re-ranks lines from the
#: others.
FOCUS_KEY = "suggested_focus"

WORK_ORDER = ("merge", "decision", "story")

#: How one product's briefing is read: an onboarding id, or None for overall.
BriefingReader = Callable[[str | None], Awaitable["DailyBriefingOut"]]


class BriefingDmUndeliveredError(RuntimeError):
    """Slack did not accept the DM. Raised so the run reads `failing` and the
    next tick retries the same day; `SlackNotifier` has logged Slack's own
    reason (`channel_not_found`, `not_in_channel`, ...)."""


# ---------------------------------------------------------------------------
# When
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Schedule:
    at: time
    zone: tzinfo

    def due(self, now: datetime, last_sent: datetime | None) -> bool:
        """Whether today's DM is owed: past the send time, local, and not yet
        delivered on this local date."""
        local = now.astimezone(self.zone)
        if local.time() < self.at:
            return False
        if last_sent is None:
            return True
        return last_sent.astimezone(self.zone).date() != local.date()


def schedule_from(settings: Settings) -> Schedule:
    """The configured send time. An unknown zone raises, which `_every`
    records as a failure naming it: silently falling back to UTC would send
    at midnight in Phoenix and look like it worked."""
    hours, minutes = settings.briefing_dm_time.split(":")
    try:
        zone = ZoneInfo(settings.briefing_dm_timezone)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(
            f"MYKRONOS_BRIEFING_DM_TIMEZONE {settings.briefing_dm_timezone!r} is not "
            "a known IANA zone"
        ) from exc
    return Schedule(at=time(int(hours), int(minutes)), zone=zone)


def last_sent(db: Any, name: str = BRIEFING_DM_JOB) -> datetime | None:
    """The last delivered DM: the job's `last_succeeded_at`, aware UTC.

    Only a delivered DM moves it. Ticks that are not due leave the row alone,
    and a skipped or failed run does not touch the success stamp.
    """
    with db.session() as session:
        row = session.get(JobRun, name)
        last: datetime | None = row.last_succeeded_at if row is not None else None
    if last is None:
        return None
    # Stored naive UTC by `main._record_run`.
    return last.replace(tzinfo=UTC) if last.tzinfo is None else last.astimezone(UTC)


def unconfigured(settings: Settings) -> str:
    """Why the DM cannot be sent, naming the setting; empty when it can."""
    missing = []
    if not settings.slack_bot_token.strip():
        missing.append("MYKRONOS_SLACK_BOT_TOKEN")
    if not settings.briefing_dm_channel.strip():
        missing.append("MYKRONOS_BRIEFING_DM_CHANNEL")
    if not settings.dashboard_url.strip():
        missing.append("MYKRONOS_DASHBOARD_URL")
    if not missing:
        return ""
    reason = f"Slack is not configured for the briefing DM: {', '.join(missing)} not set"
    if "MYKRONOS_SLACK_BOT_TOKEN" in missing and settings.slack_webhook_url.strip():
        reason += " (an incoming webhook cannot DM a person)"
    return reason + "."


def page_url(settings: Settings) -> str:
    return settings.dashboard_url.strip().rstrip("/") + "/briefing"


# ---------------------------------------------------------------------------
# What
# ---------------------------------------------------------------------------


def _esc(text: str) -> str:
    """Slack's own escaping for text it should not read as markup.

    Lines carry finding titles and remote error text, which come from
    repository content. Unescaped, `<https://elsewhere|Open the full
    briefing>` in one would render as a second, different link in the DM.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cut(text: str, limit: int) -> str:
    """One untrusted value, on one line, cut for a phone, and escaped."""
    text = " ".join(text.split())
    text = text if len(text) <= limit else text[: limit - 1] + "…"
    return _esc(text)


def _plural(count: int, word: str) -> str:
    if count == 1:
        return f"{count} {word}"
    return f"{count} {word[:-1]}ies" if word.endswith("y") else f"{count} {word}s"


def work_counts(sections: Iterable[Any]) -> Counter[str]:
    """Merges, decisions and stories on the page, each line once.

    Suggested focus re-ranks lines from the other sections and is left out,
    the exceptions are listed by name rather than counted, and a line that two
    sections both carry is counted once.
    """
    seen: set[tuple[str, str, str]] = set()
    counts: Counter[str] = Counter()
    for section in sections:
        if section.key in (FOCUS_KEY, EXCEPTIONS_KEY):
            continue
        for line in section.lines:
            identity = (line.what, line.ref, line.repo_full_name)
            if identity in seen:
                continue
            seen.add(identity)
            counts[line.work] += 1
    return counts


def _counts_text(counts: Counter[str]) -> str:
    parts = [_plural(counts[kind], kind) for kind in WORK_ORDER if counts[kind]]
    return ", ".join(parts) if parts else "nothing"


def unread(sections: Iterable[Any]) -> list[str]:
    """Every section that is not fully read, by name and with its reason."""
    out = []
    for section in sections:
        if section.status == "ok":
            continue
        word = {
            "unavailable": "unavailable",
            "not_available": "not built yet",
            "partial": "partial",
        }.get(section.status, section.status)
        out.append(f"{_esc(section.title)} ({word}: {_cut(section.reason, REASON_CHARS)})")
    return out


@dataclass(frozen=True)
class ProductRead:
    """One product's briefing, or why it could not be read."""

    repo_full_name: str
    briefing: DailyBriefingOut | None = None
    error: str = ""


def backlog_text(delta: Any) -> str:
    """"16 critical, 2 high" from a risk-delta section, or "" when it was not
    read or holds none. The scan post names only new findings (TheHub
    #61195); the standing backlog is reported here, once a day."""
    if delta is None or delta.status not in ("ok", "partial"):
        return ""
    by_severity = delta.data.get("open_backlog", {}).get("by_severity", {}) or {}
    return ", ".join(
        f"{int(by_severity[name])} {name}"
        for name in ("critical", "high")
        if by_severity.get(name)
    )


def product_line(product: ProductRead) -> str:
    """One line: what changed in the window, what is work, what is unread."""
    name = _esc(product.repo_full_name)
    if product.briefing is None:
        return f"• *{name}*: could not be read ({_cut(product.error, REASON_CHARS)})."
    sections = {s.key: s for s in product.briefing.sections}
    parts: list[str] = []

    delta = sections.get("findings_delta")
    if delta is not None and delta.status in ("ok", "partial"):
        introduced = int(delta.data.get("introduced", {}).get("total", 0) or 0)
        closed = int(delta.data.get("closed", {}).get("total", 0) or 0)
        window = int(delta.data.get("window_hours", 24) or 24)
        parts.append(f"{introduced} introduced, {closed} closed in {window}h")
        backlog = int(delta.data.get("open_backlog", {}).get("total", 0) or 0)
        if backlog:
            parts.append(f"{backlog} open critical/high")

    deploy = sections.get("deploy_and_health")
    if deploy is not None and deploy.status in ("ok", "partial") and deploy.lines:
        parts.append(_cut(deploy.lines[0].what, WHAT_CHARS))
    elif deploy is not None and deploy.status == "ok":
        parts.append("production current")

    counts = work_counts(product.briefing.sections)
    parts.append(
        f"work: {_counts_text(counts)}" if sum(counts.values()) else "nothing needs you"
    )

    gaps = [
        _esc(s.title)
        for s in product.briefing.sections
        if s.status in ("unavailable", "not_available")
    ]
    if gaps:
        parts.append(f"unread: {', '.join(gaps)}")
    return f"• *{name}*: " + "; ".join(parts) + "."


def exception_lines(section: Any, *, limit: int = EXCEPTIONS_IN_DM) -> list[str]:
    """The operator's exceptions, each with the command that decides it
    (TheHub #62419), at most `limit` of them, then what has no record to read
    them from. A missing or unreadable section says so: it is never an
    all-clear."""
    if section is None or section.status not in ("ok", "partial"):
        return ["*Decide:* the exceptions could not be read today."]
    items = section.data.get("items", [])
    out = [f"*Decide ({len(items)}):*" if items else "*Decide:* nothing is waiting on you."]
    for item in items[:limit]:
        out.append(
            f"• {_cut(item['what'], 2 * WHAT_CHARS)} Decide: "
            f"{_cut(item['decide'], 2 * WHAT_CHARS)}"
        )
    if len(items) > limit:
        out.append(f"…and {len(items) - limit} more on the page.")
    gaps = [_esc(str(g.get("label", ""))) for g in section.data.get("not_read", [])]
    if gaps:
        out.append(f"*Not readable yet:* {'; '.join(gaps)}.")
    return out


def also_counted(exceptions: Any, focus: Any) -> str:
    """Everything outside the exceptions, as counts only."""
    counts = exceptions.data.get("counts", {}) if exceptions is not None else {}
    parts = []
    other = sum((counts.get("other_pending_approvals") or {}).values())
    if other:
        parts.append(f"{_plural(other, 'other approval')} pending")
    decided = counts.get("decided_last_24h") or {}
    if decided.get("total"):
        parts.append(
            f"{decided['total']} decided by rule or a person in 24h "
            f"({decided.get('by_agent', 0)} by an agent)"
        )
    if counts.get("credentials_not_yours"):
        parts.append(
            f"{_plural(counts['credentials_not_yours'], 'credential')} due that a parent "
            "agent or MyKronos renews"
        )
    if counts.get("stale_gate_refusals"):
        parts.append(
            f"{_plural(counts['stale_gate_refusals'], 'gate refusal')} not re-evaluated "
            "for a week"
        )
    if focus is not None and focus.lines:
        parts.append(f"{_plural(len(focus.lines), 'suggested focus line')} on the page")
    return "; ".join(parts)


def products_text(products: list[ProductRead]) -> str:
    """The products as one count, naming only the ones that could not be read."""
    read = [p.briefing for p in products if p.briefing is not None]
    gaps = sum(
        1 for b in read
        if any(s.status in ("unavailable", "not_available") for s in b.sections)
    )
    text = f"*Products:* {len(read)} read" + (
        f" ({gaps} with a section unread)" if gaps else ""
    )
    failed = [p for p in products if p.briefing is None]
    if failed:
        names = ", ".join(
            f"{_esc(p.repo_full_name)} ({_cut(p.error, REASON_CHARS)})" for p in failed
        )
        text += f", {len(failed)} could not be read: {names}"
    return text + "."


def compose(
    overall: DailyBriefingOut,
    products: list[ProductRead],
    *,
    url: str,
    local_now: datetime,
) -> Notification:
    """The DM, as a `Notification` whose lines are each scrubbed on the way
    out (`Notification.render`).

    The link comes first: `notify.MAX_TEXT` truncates the tail of a long
    message, and the page is the point of the DM.

    **Never cut silently (TheHub #62419).** A message over `MAX_TEXT` would
    lose its tail - the "Not read" list and the products - with no sign.
    Instead the lower sections are left out whole, backlog first, then the
    other counts, then "Needs you", and a line names what was left out;
    after that the exceptions list shortens, saying how many more are on
    the page. "Not read" and the products always stay.
    """
    counts = work_counts(overall.sections)
    sections = {s.key: s for s in overall.sections}
    exceptions = sections.get(EXCEPTIONS_KEY)
    also = also_counted(exceptions, sections.get(FOCUS_KEY))
    backlog = backlog_text(sections.get("risk_delta"))
    # Highest first; dropped from the end.
    optional = [
        ("Needs you", [f"*Needs you:* {_counts_text(counts)}."]),
        ("Also counted", [f"*Also counted:* {also}."] if also else []),
        ("Open critical/high backlog",
         [f"*Open critical/high backlog:* {backlog}."] if backlog else []),
    ]
    optional = [(name, block) for name, block in optional if block]

    tail = []
    gaps = unread(s for s in overall.sections if s.status in ("unavailable", "not_available"))
    if gaps:
        # One per line: each is cut to fit, and a joined line would be cut
        # by `notify.LINE_MAX` after the second or third.
        tail.append("*Not read:*")
        tail.extend(f"- {gap}" for gap in gaps)
    if products:
        tail.append(products_text(products))

    def build(kept: int, limit: int) -> Notification:
        lines = [f"<{url}|Open the full briefing>", *exception_lines(exceptions, limit=limit)]
        for _name, block in optional[:kept]:
            lines.extend(block)
        left_out = [name for name, _block in optional[kept:]]
        if left_out:
            lines.append(f"*Left out to fit:* {', '.join(left_out)}; on the page.")
        lines.extend(tail)
        return Notification(
            title=f"Morning briefing, {local_now:%a %d %b}",
            detail="",
            repo_full_name="",
            level="info",
            lines=tuple(lines),
        )

    kept, limit = len(optional), EXCEPTIONS_IN_DM
    note = build(kept, limit)
    while not note.fits and kept > 0:
        kept -= 1
        note = build(kept, limit)
    while not note.fits and limit > 0:
        limit -= 1
        note = build(kept, limit)
    return note



# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


def products(db: Any) -> list[tuple[str, str]]:
    """(onboarding id, repo) for every product the portfolio shows: not
    removed, and not the synthetic benchmark corpus."""
    with db.session() as session:
        rows = session.execute(
            select(RepoOnboarding.id, RepoOnboarding.github_repo_full_name)
            .where(RepoOnboarding.status != "removed")
            .where(RepoOnboarding.synthetic.is_(False))
            .order_by(RepoOnboarding.github_repo_full_name)
        ).all()
    return [(str(repo_id), str(name)) for repo_id, name in rows]


def route_reader(
    app: FastAPI, *, actor: str = f"job:{BRIEFING_DM_JOB}", lists_credentials: bool = False
) -> BriefingReader:
    """Read the briefing through its own route, so the DM and the page cannot
    disagree. The request is synthetic: the route reads only `app.state`.
    The briefing-signal filing job reads through it too, as itself.

    The route lists credentials due only to a principal that may write (the
    rule of `GET /api/credentials/expiring`, TheHub #62419). The DM lists
    them, so it passes `lists_credentials` and reads as an in-process
    automation principal with that role, as the credential-incident job
    reads the calendar; every other reader stays a viewer."""
    from fastapi import Request

    from mykronos.adminauth import ActorKind, Principal, Role
    from mykronos.api.briefing_daily import daily_briefing_route

    role = Role.ADMIN if lists_credentials else Role.VIEWER
    principal = Principal(actor=actor, role=role, kind=ActorKind.AUTOMATION)


    async def read(repo_id: str | None) -> DailyBriefingOut:
        request = Request(
            {
                "type": "http",
                "app": app,
                "method": "GET",
                "path": "/api/briefing/daily",
                "headers": [],
                "query_string": b"",
            }
        )
        return await daily_briefing_route(request, principal, repo_id=repo_id)

    return read


async def send_briefing_dm(
    settings: Settings,
    *,
    db: Any,
    read: BriefingReader,
    notifier: Notifier | None = None,
    now: datetime | None = None,
    job_name: str = BRIEFING_DM_JOB,
) -> Notification:
    """Send today's DM if it is due. Returns what was sent.

    Raises `JobNotDue` before the send time and once today's has gone,
    `JobSkipped` when Slack is not configured for it, and
    `BriefingDmUndeliveredError` when Slack refused it.
    """
    moment = now or datetime.now(UTC)
    schedule = schedule_from(settings)
    if not schedule.due(moment, last_sent(db, job_name)):
        raise JobNotDue
    reason = unconfigured(settings)
    if reason:
        raise JobSkipped(reason)

    overall = await read(None)
    reads: list[ProductRead] = []
    for repo_id, name in products(db):
        try:
            reads.append(ProductRead(repo_full_name=name, briefing=await read(repo_id)))
        except Exception as exc:  # noqa: BLE001 - one product must not lose the DM
            logger.warning("Briefing DM: could not read %s: %s", scrub(name), scrub(str(exc)))
            reads.append(ProductRead(repo_full_name=name, error=str(exc) or type(exc).__name__))

    note = compose(
        overall, reads, url=page_url(settings), local_now=moment.astimezone(schedule.zone)
    )
    sender = notifier or SlackNotifier(
        bot_token=settings.slack_bot_token, channel=settings.briefing_dm_channel
    )
    if not await sender.send(note):
        raise BriefingDmUndeliveredError(
            "Slack did not accept the briefing DM; the backend log has Slack's reason."
        )
    logger.info("Briefing DM sent (%s product line(s)).", len(reads))
    return note
