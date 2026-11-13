"""Does the platform reviewer's model key still work? (TheHub #61614)

Every independent review rests on one API key, and nothing asked whether it
answered until a person started a review and read the 503. On the night of
2026-11-13 every start was refused with a 401 for over an hour and five
approvals sat pending with nothing alerting.

The probe is one list-models call an hour: it bills no tokens, a bad key is a
401, and it needs no request body. It records three states, kept apart because
they need different things done: `refused` (401/403) is a key to replace,
`unreachable` (timeout, connection error, 5xx, rate limit) is the API or the
network, `ok` needs nothing.

What is stored is the state, a time, the model name and the HTTP status. Never
the key, a prefix of it, or a response header: the page that shows this is
served on an internet-exposed dashboard.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import anthropic

from mykronos.db import Database
from mykronos.db.models import ReviewerKeyProbe
from mykronos.notify import Notification, Notifier

logger = logging.getLogger(__name__)

ReviewerKeyState = Literal["ok", "refused", "unreachable", "off"]

#: The scheduled job's name and its `job_runs` row.
REVIEWER_KEY_JOB = "reviewer-key-probe"

#: The name of the platform health row.
ROW_NAME = "platform reviewer key"

PROBE_TIMEOUT_SECONDS = 10.0


#: A row older than this many probe intervals is stale and no reader trusts it.
STALE_AFTER_INTERVALS = 2

DEFAULT_INTERVAL_SECONDS = 3600


@dataclass(frozen=True)
class ProbeResult:
    state: ReviewerKeyState
    http_status: int | None


class ReviewerKeyProbeIncompleteError(RuntimeError):
    """The state changed and the alert was not delivered; the next tick retries."""


def probe_key(key: str, *, client: Any | None = None) -> ProbeResult:
    """Ask the model API's list-models endpoint whether `key` is accepted.

    Retries are off: the job is the retry, once an hour, and a probe that
    quietly retried would hide a flapping key. Nothing from the exception is
    kept but its status code, so a header cannot leak into a row or a log.
    """
    api = client or anthropic.Anthropic(
        api_key=key, timeout=PROBE_TIMEOUT_SECONDS, max_retries=0
    )
    try:
        api.models.list(limit=1)
    except anthropic.APIStatusError as exc:
        status = int(exc.status_code)
        if status in (401, 403):
            return ProbeResult("refused", status)
        return ProbeResult("unreachable", status)
    except anthropic.APIConnectionError:  # includes APITimeoutError
        return ProbeResult("unreachable", None)
    return ProbeResult("ok", 200)


def current(db: Database) -> ReviewerKeyProbe | None:
    """The recorded probe, detached from its session, or None before the first."""
    with db.session() as session:
        row = session.get(ReviewerKeyProbe, 1)
        if row is None:
            return None
        session.expunge(row)
        return row


def _interval(settings: Any) -> int:
    configured = getattr(settings, "reviewer_key_probe_interval_seconds", 0)
    return int(configured or DEFAULT_INTERVAL_SECONDS)


def fresh(
    db: Database, settings: Any, *, now: datetime | None = None
) -> ReviewerKeyProbe | None:
    """The recorded probe, or None before the first or when it is stale.

    A row not refreshed within two probe intervals says nothing about the key
    now (the job stopped, or was never rescheduled), so readers ignore it.
    """
    row = current(db)
    if row is None:
        return None
    moment = now or datetime.now(UTC)
    age = (moment - _utc(row.as_of)).total_seconds()
    if age > STALE_AFTER_INTERVALS * _interval(settings):
        return None
    return row


def unavailable_since(
    db: Database, settings: Any, *, now: datetime | None = None
) -> datetime | None:
    """When the reviewer became unavailable, or None when the last probe was ok,
    off or stale (or none has run: an unprobed reviewer is not reported
    unavailable)."""
    row = fresh(db, settings, now=now)
    if row is None or row.state in ("ok", "off"):
        return None
    return _utc(row.since)


def probing_disabled(db: Database, settings: Any, *, now: datetime | None = None) -> bool:
    """True when the freshest probe row says probing is switched off."""
    row = fresh(db, settings, now=now)
    return row is not None and row.state == "off"


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _stamp(value: datetime) -> str:
    return _utc(value).strftime("%Y-%m-%d %H:%MZ")


def _record(db: Database, result: ProbeResult, model: str, now: datetime) -> ReviewerKeyProbe:
    """Store the result and return the row, detached."""
    with db.session() as session:
        row = session.get(ReviewerKeyProbe, 1)
        if row is None:
            row = ReviewerKeyProbe(id=1, since=now, alerted=False)
            session.add(row)
            row.state = result.state
        elif row.state != result.state:
            row.since = now
            # A new bad state is announced afresh; a return to ok (or a pause
            # to off) keeps the
            # flag, which is what tells the recovery note it is owed.
            if result.state in ("refused", "unreachable"):
                row.alerted = False
        row.state = result.state
        row.as_of = now
        row.model = model
        row.http_status = result.http_status
        session.flush()
        session.expunge(row)
        return row


def _mark_alerted(db: Database, alerted: bool) -> None:
    with db.session() as session:
        row = session.get(ReviewerKeyProbe, 1)
        if row is not None:
            row.alerted = alerted


async def probe_reviewer_key(
    db: Database,
    settings: Any,
    *,
    notifier: Notifier | None,
    client: Any | None = None,
    now: datetime | None = None,
) -> ProbeResult:
    """Probe, record, and say so once when the key stops working or recovers.

    The alert is de-duplicated on the stored state: a refusal is announced the
    first time it is seen and not again while it lasts, and a recovery note
    follows only a refusal that was announced. The flag is set only when the
    notifier reports delivery, so an undelivered alert is retried next tick.
    """
    from mykronos.approvals import reviewer
    from mykronos.jobs import JobSkipped

    moment = now or datetime.now(UTC)
    model = str(getattr(settings, "reviewer_model", "") or "claude-opus-5-5")
    if reviewer.mode(settings) == "off":
        # Write the skip down, so a refusal recorded before it is not read as
        # current (TheHub #61628).
        await asyncio.to_thread(_record, db, ProbeResult("off", None), model, moment)
        raise JobSkipped("the independent reviewer is switched off (reviewer_mode: off)")
    key = reviewer.api_key(settings)
    if key is None and client is None:
        await asyncio.to_thread(_record, db, ProbeResult("off", None), model, moment)
        raise JobSkipped("the reviewer has no API key configured, so there is nothing to probe")
    result = await asyncio.to_thread(probe_key, key or "", client=client)
    row = await asyncio.to_thread(_record, db, result, model, moment)

    if result.state != "ok":
        logger.warning("Reviewer key probe: %s (HTTP %s)", result.state, result.http_status)
        if row.alerted:
            return result
        await _deliver(
            notifier,
            Notification(
                title="The platform reviewer's model key is not working",
                detail="",
                repo_full_name="",
                level="critical",
                lines=_alert_lines(row),
            ),
            f"the platform reviewer key is {result.state} and nobody has been told",
        )
        await asyncio.to_thread(_mark_alerted, db, True)
        return result

    if row.alerted:
        await _deliver(
            notifier,
            Notification(
                title="The platform reviewer's model key works again",
                detail="",
                repo_full_name="",
                level="info",
                lines=(f"The hourly probe answered ok at {_stamp(row.as_of)}.",),
            ),
            "the reviewer key recovered and nobody has been told",
        )
        await asyncio.to_thread(_mark_alerted, db, False)
    return result


def _alert_lines(row: ReviewerKeyProbe) -> tuple[str, ...]:
    status = f" (HTTP {row.http_status})" if row.http_status else ""
    what = (
        "the model API refused the key"
        if row.state == "refused"
        else "the model API did not answer"
    )
    return (
        f"The hourly probe reports {row.state}{status} since {_stamp(row.since)}: {what}.",
        "Production-tier approvals cannot get an independent review until this clears.",
        "Pending requests stay pending for a person.",
    )


async def _deliver(notifier: Notifier | None, note: Notification, why: str) -> None:
    from mykronos.jobs import JobSkipped

    if notifier is None or not notifier.enabled:
        raise JobSkipped(f"{why}: no Slack transport is configured; MyKronos Health shows it")
    if not await notifier.send(note):
        raise ReviewerKeyProbeIncompleteError(f"{why}: the notice was not delivered")
