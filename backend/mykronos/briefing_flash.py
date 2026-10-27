"""The same-day flash DM (TheHub #60865, B7 of epic #60858).

The weekly page waits for Monday. A flash does not: when an item on any
application's page is **known exploited (CISA KEV) or critical, and matches
something shipped** (`weekly_briefing._flash`), it is DMed the same day.
Nothing else fires one - a high that is not exploited, or a critical seen only
on a pull-request branch, waits for the page.

**Once per item, until it is fixed.** Each sent item is audited as
`briefing.flash` with its application and key, and an item already audited is
not sent again, so a tick every half hour does not repeat itself and a restart
does not either. When an item leaves a section that read everything it lists
(`_read_in_full`), it is audited as `briefing.flash_cleared`; if it comes back
- a fixed finding that regresses - it flashes again (review of #1009).

**The first run is a baseline, not news.** The first time the job runs it
records every item already flashing as sent (`seeded`) and DMs nothing, so
deploying it does not DM every existing KEV or critical match at once. A job
that has already sent flashes is past its first run and is not re-seeded.

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
from mykronos.weekly_briefing import MAX_ITEMS

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import FastAPI

    from mykronos.api.briefing_weekly import WeeklyBriefingOut
    from mykronos.config import Settings

logger = logging.getLogger(__name__)

#: How often the scheduler looks. Same-day, not same-minute.
TICK_SECONDS = 1_800

ACTION = "briefing.flash"

#: An item that left a section which read everything: it may flash again.
CLEARED = "briefing.flash_cleared"

#: Written once, by the first run, whether or not it found anything.
SEEDED = "briefing.flash_seeded"
SEED_ENTITY = "first-run"

#: The section each flashing key prefix comes from, and the statuses in which
#: that section has read everything it could list. `malicious_packages` is
#: always `partial` - its takeover feed is not connected - while the findings
#: it lists are read in full; `advisories` is `partial` when KEV could not be
#: read, which turns flashes off without anything being fixed.
_SECTIONS: dict[str, tuple[str, frozenset[str]]] = {
    "advisory": ("advisories", frozenset({"ok"})),
    "fit": ("threat_model", frozenset({"ok"})),
    "malicious": ("malicious_packages", frozenset({"ok", "partial"})),
}

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
    """Entities sent (or seeded) more often than cleared.

    Counted, not ordered by time: a clear is only written for a sent entity
    and a send only for an unsent one, so the two alternate, and two events
    in the same clock tick cannot be misread."""
    with db.session() as session:
        rows = session.execute(
            select(AuditLogEntry.entity_id, AuditLogEntry.action).where(
                AuditLogEntry.action.in_((ACTION, CLEARED))
            )
        ).all()
    balance: dict[str, int] = {}
    for entity, action in rows:
        balance[str(entity)] = balance.get(str(entity), 0) + (1 if action == ACTION else -1)
    return {e for e, n in balance.items() if n > 0}


def _first_run(db: Any) -> bool:
    """No seed marker and nothing ever sent."""
    with db.session() as session:
        found = session.scalars(
            select(AuditLogEntry.id)
            .where(AuditLogEntry.action.in_((SEEDED, ACTION)))
            .limit(1)
        ).first()
    return found is None


def _seed(db: Any, flashes: list[Flash], moment: datetime) -> None:
    with db.session() as session:
        for flash in flashes:
            db.audit(
                session,
                actor=f"job:{BRIEFING_FLASH_JOB}",
                action=ACTION,
                entity_type="briefing_item",
                entity_id=_entity(flash),
                repo_full_name=flash.repo_full_name,
                what=flash.what,
                reason=flash.reason,
                seeded=True,
                sent_at=None,
            )
        db.audit(
            session,
            actor=f"job:{BRIEFING_FLASH_JOB}",
            action=SEEDED,
            entity_type="briefing_flash",
            entity_id=SEED_ENTITY,
            items=len(flashes),
            seeded_at=moment.isoformat(),
        )


def _read_in_full(briefing: WeeklyBriefingOut) -> dict[tuple[str, str], set[str]]:
    """(repository, key prefix) -> the keys flashing there now, for every
    section that read everything it could list and listed all of it. An item
    is fixed only when it is missing from one of these; a page or section
    that could not be read, or a list cut at `MAX_ITEMS`, says nothing."""
    out: dict[tuple[str, str], set[str]] = {}
    for page in briefing.pages:
        by_key = {section.key: section for section in page.sections}
        for prefix, (section_key, statuses) in _SECTIONS.items():
            section = by_key.get(section_key)
            if section is None or section.status not in statuses:
                continue
            if len(section.items) >= MAX_ITEMS:
                continue
            out[(page.repo_full_name, prefix)] = {i.key for i in section.items if i.flash}
    return out


def _gone(sent: set[str], briefing: WeeklyBriefingOut) -> list[str]:
    complete = _read_in_full(briefing)
    gone = []
    for entity in sorted(sent):
        repo, _, key = entity.partition("|")
        flashing = complete.get((repo, key.split(":", 1)[0]))
        if flashing is not None and key not in flashing:
            gone.append(entity)
    return gone


def _clear(db: Any, entities: list[str], moment: datetime) -> None:
    with db.session() as session:
        for entity in entities:
            db.audit(
                session,
                actor=f"job:{BRIEFING_FLASH_JOB}",
                action=CLEARED,
                entity_type="briefing_item",
                entity_id=entity,
                cleared_at=moment.isoformat(),
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
    """DM every flash not sent before. Returns what was sent (possibly none).

    The first run seeds instead of sending; every run first clears the items
    that are no longer there, so one that returns flashes again."""
    moment = now or datetime.now(UTC)
    briefing = await read()
    now_flashing = candidates(briefing)
    if _first_run(db):
        _seed(db, now_flashing, moment)
        logger.info("Flash: first run, %s existing item(s) recorded, none sent.", len(now_flashing))
        return []
    sent = already_sent(db)
    gone = _gone(sent, briefing)
    if gone:
        _clear(db, gone, moment)
        sent -= set(gone)
    fresh = [f for f in now_flashing if _entity(f) not in sent]
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
