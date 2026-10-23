"""The same-day flash DM (TheHub #60865, B7 of epic #60858).

The weekly page waits for Monday. A flash does not: when an item on any
application's page is **known exploited (CISA KEV) or critical, and matches
something shipped** (`weekly_briefing._flash`), it is DMed the same day.
Nothing else fires one - a high that is not exploited, or a critical seen only
on a pull-request branch, waits for the page.

**Once per item.** Each sent item is audited as `briefing.flash` with its
application and key, and an item already audited is never sent again, so a
tick every half hour does not repeat itself and a restart does not either.

**Not configured is said, never silent.** It reuses the briefing DM's Slack
settings, and with them missing raises `JobSkipped` naming them - but only
when there is something to send: a quiet week is a successful run, not a
skipped one.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from mykronos.briefing_dm import _cut, _esc, unconfigured
from mykronos.db.models import AuditLogEntry
from mykronos.jobs import BRIEFING_FLASH_JOB, JobSkipped
from mykronos.logsafe import scrub
from mykronos.notify import Notification, Notifier, SlackNotifier

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

    from mykronos.api.briefing_weekly import WeeklyBriefingOut
    from mykronos.config import Settings

logger = logging.getLogger(__name__)

#: How often the scheduler looks. Same-day, not same-minute.
TICK_SECONDS = 1_800

ACTION = "briefing.flash"

#: Items per DM; the page has the rest.
MAX_IN_DM = 10

WeeklyReader = Callable[[], Awaitable["WeeklyBriefingOut"]]


class FlashUndeliveredError(RuntimeError):
    """Slack did not accept the flash. Nothing is audited, so the next tick
    retries."""


@dataclass(frozen=True)
class Flash:
    repo_full_name: str
    repo_id: str
    key: str
    what: str
    reason: str
    action: str
    source: str


def candidates(briefing: WeeklyBriefingOut) -> list[Flash]:
    out = []
    for page in briefing.pages:
        for section in page.sections:
            for item in section.items:
                if item.flash:
                    out.append(
                        Flash(
                            repo_full_name=page.repo_full_name,
                            repo_id=page.repo_id,
                            key=item.key,
                            what=item.what,
                            reason=item.flash_reason,
                            action=item.action,
                            source=item.source,
                        )
                    )
    # One item can appear in two sections (an advisory fitted to the threat
    # model is also an advisory); one DM line per advisory and application.
    seen: set[tuple[str, str]] = set()
    unique = []
    for flash in out:
        identity = (flash.repo_full_name, flash.what.split(" ", 1)[0])
        if identity in seen:
            continue
        seen.add(identity)
        unique.append(flash)
    return unique


def _entity(flash: Flash) -> str:
    return f"{flash.repo_full_name}|{flash.key}"[:255]


def already_sent(db: Any) -> set[str]:
    with db.session() as session:
        return set(
            session.scalars(
                select(AuditLogEntry.entity_id).where(AuditLogEntry.action == ACTION)
            )
        )


def compose(flashes: list[Flash], *, dashboard_url: str) -> Notification:
    base = dashboard_url.strip().rstrip("/")
    lines = [f"<{base}/briefing/weekly|Open the weekly briefing>"]
    for flash in flashes[:MAX_IN_DM]:
        source = flash.source if flash.source.startswith("https://") else base + flash.source
        lines.append(
            f"• *{_esc(flash.repo_full_name)}*: {_cut(flash.what, 140)} - "
            f"{_cut(flash.reason, 80)}. {_cut(flash.action, 140)} <{_esc(source)}|source>"
        )
    more = len(flashes) - MAX_IN_DM
    if more > 0:
        lines.append(f"and {more} more on the page.")
    return Notification(
        title=f"Flash: {len(flashes)} exploited or critical match(es) in what we ship",
        detail="",
        repo_full_name="",
        level="warning",
        lines=tuple(lines),
    )


async def send_flashes(
    settings: Settings,
    *,
    db: Any,
    read: WeeklyReader,
    notifier: Notifier | None = None,
    now: datetime | None = None,
) -> list[Flash]:
    """DM every flash not sent before. Returns what was sent (possibly none)."""
    moment = now or datetime.now(UTC)
    briefing = await read()
    sent = already_sent(db)
    fresh = [f for f in candidates(briefing) if _entity(f) not in sent]
    if not fresh:
        return []
    reason = unconfigured(settings)
    if reason:
        raise JobSkipped(reason.replace("briefing DM", "flash DM"))
    note = compose(fresh, dashboard_url=settings.dashboard_url)
    sender = notifier or SlackNotifier(
        bot_token=settings.slack_bot_token, channel=settings.briefing_dm_channel
    )
    if not await sender.send(note):
        raise FlashUndeliveredError(
            "Slack did not accept the flash DM; the backend log has Slack's reason."
        )
    with db.session() as session:
        for flash in fresh:
            db.audit(
                session,
                actor=f"job:{BRIEFING_FLASH_JOB}",
                action=ACTION,
                entity_type="briefing_item",
                entity_id=_entity(flash),
                repo_full_name=flash.repo_full_name,
                what=flash.what,
                reason=flash.reason,
                source=flash.source,
                sent_at=moment.isoformat(),
            )
    logger.info("Flash DM sent: %s item(s).", len(fresh))
    return fresh


def route_reader(app: FastAPI) -> WeeklyReader:
    """Read the weekly page through its own route, as the job."""
    from fastapi import Request

    from mykronos.adminauth import ActorKind, Principal, Role
    from mykronos.api.briefing_weekly import weekly_briefing_route

    principal = Principal(
        actor=f"job:{BRIEFING_FLASH_JOB}", role=Role.VIEWER, kind=ActorKind.AUTOMATION
    )

    async def read() -> WeeklyBriefingOut:
        request = Request(
            {
                "type": "http",
                "app": app,
                "method": "GET",
                "path": "/api/briefing/weekly",
                "headers": [],
                "query_string": b"",
            }
        )
        try:
            return await weekly_briefing_route(request, principal, repo_id=None)
        except Exception as exc:
            logger.warning("Flash: weekly briefing unreadable: %s", scrub(str(exc)))
            raise

    return read
