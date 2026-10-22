"""The 07:00 briefing DM (TheHub #60864, epic #60858).

`GET /api/briefing/daily` is the page Todd reads first thing. This is what
puts it in front of him without his asking: once a local day, at
`briefing_dm_time` in `briefing_dm_timezone`, a short Slack DM with

- how much on the page is work for him, split merge / decision / story;
- the top three suggested-focus lines;
- every section that could not be read, by name - a briefing that leaves out
  what it could not see reads as "all clear", which is the failure the page
  itself was built against (#401);
- one line per product;

and a link to `/briefing` on the dashboard, where the rest is.

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

#: How many suggested-focus lines the DM carries. The page has the rest.
FOCUS_IN_DM = 3

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
    and a line that two sections both carry is counted once.
    """
    seen: set[tuple[str, str, str]] = set()
    counts: Counter[str] = Counter()
    for section in sections:
        if section.key == FOCUS_KEY:
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
    """
    counts = work_counts(overall.sections)
    sections = {s.key: s for s in overall.sections}
    lines = [
        f"<{url}|Open the full briefing>",
        f"*Needs you:* {_counts_text(counts)}.",
    ]

    focus = sections.get(FOCUS_KEY)
    if focus is not None and focus.lines:
        lines.append("*Suggested focus:*")
        for index, line in enumerate(focus.lines[:FOCUS_IN_DM], start=1):
            lines.append(
                f"{index}. [{line.work}] {_cut(line.what, WHAT_CHARS)} - "
                f"{_cut(line.so_what, WHAT_CHARS)}"
            )
    elif focus is not None and focus.status not in ("ok", "partial"):
        lines.append("*Suggested focus:* could not be ranked today.")
    else:
        lines.append("*Suggested focus:* nothing to start with.")

    gaps = unread(s for s in overall.sections if s.status in ("unavailable", "not_available"))
    if gaps:
        # One per line: each is cut to fit, and a joined line would be cut
        # by `notify.LINE_MAX` after the second or third.
        lines.append("*Not read:*")
        lines.extend(f"- {gap}" for gap in gaps)

    if products:
        lines.append("*Products:*")
        lines.extend(product_line(product) for product in products)

    return Notification(
        title=f"Morning briefing, {local_now:%a %d %b}",
        detail="",
        repo_full_name="",
        level="info",
        lines=tuple(lines),
    )


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


def route_reader(app: FastAPI) -> BriefingReader:
    """Read the briefing through its own route, so the DM and the page cannot
    disagree. The request is synthetic: the route reads only `app.state`."""
    from fastapi import Request

    from mykronos.adminauth import ActorKind, Principal, Role
    from mykronos.api.briefing_daily import daily_briefing_route

    principal = Principal(
        actor=f"job:{BRIEFING_DM_JOB}", role=Role.VIEWER, kind=ActorKind.AUTOMATION
    )

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
