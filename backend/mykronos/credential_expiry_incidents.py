"""An incident a day before a credential lapses unrenewed (TheHub #61104).

The calendar (`GET /api/credentials/expiring`, `mykronos.credential_expiry`)
says what lapses soon, and Start-Here shows it 48 hours ahead. This is the
backstop for when nobody acted on that: an hourly job that opens one Hub
incident for each credential that is inside its last `LEAD_HOURS`, or lapsed
within the last `LEAD_HOURS`, and is still on the calendar.

**"Nobody renewed it" is the calendar's own answer.** A renewed credential
leaves the list: an agent credential with a live replacement is hidden, a
re-dated declared entry moves out of the window, a revoked one is never
listed. So the job reads the list *through the route*, with the same rules,
the same declared file(s) and the same clock as the page and the CLI. It
never re-implements them, and a later rule (a private overlay, a renewal by
role) reaches the incidents without a change here.

**What never pages.**

* A sub-agent's credential (non-empty lineage). It is short-lived by design
  and its parent agent's to replace; paging for each one would page all day.
* An agent credential whose role is already renewed: the renewal rule mints
  the next one 48 hours ahead, and the old one stays listed until it lapses
  (`quiet_actors`).
* Ingestion tokens. MyKronos's own `rotation` job renews them, and a failing
  rotation already shows in platform health. An overlap's end is the tail of a
  renewal that has happened, not an expiry nobody renewed.
* A lapse more than `LEAD_HOURS` old. It stays on the calendar; paging for it
  a day late would only page, on the first deploy, for every old lapse.

**Once per expiry.** Each opened incident is audited
(`credential_expiry.incident_opened`) under a key of the credential's name and
expiry date, so the next tick opens nothing new, and a re-dated credential is a
new expiry. TheHub also keeps one open incident per `source_ref`. When an
audited credential leaves the list, the job comments on its incident once
(`credential_expiry.incident_cleared`); a person resolves it. Nothing here
closes an incident.

**Metadata only.** The incident carries the name, kind, owner, date, source
and renewal step the route already returns. No token, hash or key is ever
read into it.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from mykronos.db.models import AgentCredential, AuditLogEntry
from mykronos.jobs import CREDENTIAL_EXPIRY_INCIDENTS_JOB, JobSkipped

if TYPE_CHECKING:  # pragma: no cover - import-cycle guard
    from fastapi import FastAPI

    from mykronos.api.credentials import ExpiringCredentialOut, ExpiringOut

logger = logging.getLogger(__name__)

#: How long before a lapse the incident opens, and how long after one an
#: unnoticed lapse still opens one.
LEAD_HOURS = 24

#: How often the scheduler runs the job. Hourly: an incident opens at most an
#: hour after a credential enters its last day.
TICK_SECONDS = 3600

SOURCE_CAPABILITY = "mykronos_credential_expiry"
ROOM = "devops"
SEVERITY = "error"
ACTION = "credential_expiry.incident_opened"
CLEARED = "credential_expiry.incident_cleared"
ENTITY_TYPE = "credential_expiry"
ACTOR = f"job:{CREDENTIAL_EXPIRY_INCIDENTS_JOB}"

#: Renewed by MyKronos itself (the `rotation` job), so never an expiry
#: nobody renewed.
AUTOMATIC_KINDS = frozenset({"ingestion-token", "ingestion-token-overlap"})

ExpiringReader = Callable[[float], Awaitable["ExpiringOut"]]


class CredentialIncidentError(RuntimeError):
    """TheHub refused an incident. Nothing was audited for it, so the next
    tick tries again."""


@dataclass
class IncidentResult:
    #: Names of the credentials an incident was opened for.
    opened: list[str] = field(default_factory=list)
    #: `source_ref`s of incidents commented on because the credential left
    #: the list.
    cleared: list[str] = field(default_factory=list)


def route_reader(app: FastAPI) -> ExpiringReader:
    """Read the calendar through its own route, so an incident and the page
    cannot disagree. The request is synthetic and in-process: the route reads
    only `app.state`. The principal is this job, as automation; the route asks
    for a role that may write because the list names credentials."""
    from fastapi import Request

    from mykronos.adminauth import ActorKind, Principal, Role
    from mykronos.api.credentials import expiring as expiring_route

    principal = Principal(actor=ACTOR, role=Role.ADMIN, kind=ActorKind.AUTOMATION)

    async def read(within_hours: float) -> ExpiringOut:
        request = Request(
            {
                "type": "http",
                "app": app,
                "method": "GET",
                "path": "/api/credentials/expiring",
                "headers": [],
                "query_string": b"",
            }
        )
        return await expiring_route(request, principal, within_hours=within_hours)

    return read


def _naive(moment: datetime) -> datetime:
    if moment.tzinfo is not None:
        return moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def source_ref(row: ExpiringCredentialOut) -> str:
    """The key of one expiry: the credential and its date, so a re-dated or
    renewed credential is a new expiry."""
    return f"credential-expiry:{row.name}@{_naive(row.expires_at).isoformat(timespec='minutes')}"


def _entity(ref: str) -> str:
    # Names come from a free-text file and a free-text purpose, so the audit
    # key is a digest; the readable ref rides in the entry's detail.
    return hashlib.sha256(ref.encode("utf-8")).hexdigest()


def _role(purpose: str) -> str:
    return " ".join(str(purpose or "").split()).casefold()


def quiet_actors(db: Any, now: datetime) -> set[str]:
    """Agent actors whose credential never pages.

    * A sub-agent's (non-empty lineage): its parent agent's to replace.
    * A root credential already renewed: another live root credential lasts
      past the incident window and is the same actor, or the same role
      (purpose, compared casefolded) for the same person. The renewal rule
      mints the next credential 48 hours ahead and every mint is a new actor,
      so the old one is still listed in its last day; that is not "nobody
      renewed it". Only a root counts as a renewal, because a sub-agent may
      label itself with any purpose. A credential with no purpose is renewed
      only by its own actor.
    """
    horizon = now + timedelta(hours=LEAD_HOURS)
    with db.session() as session:
        rows = session.execute(
            select(
                AgentCredential.actor,
                AgentCredential.lineage,
                AgentCredential.purpose,
                AgentCredential.on_behalf_of,
                AgentCredential.expires_at,
            ).where(AgentCredential.revoked_at.is_(None))
        ).all()
    quiet = {str(r.actor) for r in rows if r.lineage}
    roots = [r for r in rows if not r.lineage]
    for r in roots:
        for other in roots:
            if other.expires_at <= horizon or other.expires_at <= r.expires_at:
                continue
            same_role = bool(_role(r.purpose)) and (
                _role(other.purpose) == _role(r.purpose)
                and other.on_behalf_of == r.on_behalf_of
            )
            if other.actor == r.actor or same_role:
                quiet.add(str(r.actor))
                break
    return quiet


def _actor_of(row: ExpiringCredentialOut) -> str:
    # The calendar names an agent credential `<actor> (<instance>...)`.
    return row.name.split(" (", 1)[0]


def due(
    rows: list[ExpiringCredentialOut], *, quiet: set[str]
) -> list[ExpiringCredentialOut]:
    """The rows that page: inside their last day, or lapsed within one, and
    not renewed by MyKronos itself, a parent agent or an earlier mint."""
    out = []
    for row in rows:
        if row.kind in AUTOMATIC_KINDS:
            continue
        if row.kind == "agent-credential" and _actor_of(row) in quiet:
            continue
        if -LEAD_HOURS < row.hours_left <= LEAD_HOURS:
            out.append(row)
    return out


def opened_incidents(db: Any) -> dict[str, dict[str, Any]]:
    """Open entries, by entity: opened more often than cleared, with the
    detail of the latest opening (its ref and the Hub incident id)."""
    with db.session() as session:
        rows = session.execute(
            select(AuditLogEntry.entity_id, AuditLogEntry.action, AuditLogEntry.detail)
            .where(AuditLogEntry.action.in_((ACTION, CLEARED)))
            .order_by(AuditLogEntry.created_at)
        ).all()
    balance: dict[str, int] = {}
    detail: dict[str, dict[str, Any]] = {}
    for entity, action, info in rows:
        key = str(entity)
        if action == ACTION:
            balance[key] = balance.get(key, 0) + 1
            detail[key] = dict(info or {})
        else:
            balance[key] = balance.get(key, 0) - 1
    return {key: detail[key] for key, n in balance.items() if n > 0}


def _hours(value: float) -> str:
    return f"{abs(round(value)):.0f}h"


def payload(row: ExpiringCredentialOut) -> dict[str, Any]:
    if row.expired:
        title = f"Credential lapsed {_hours(row.hours_left)} ago, not renewed: {row.name}"
    else:
        title = f"Credential expires in {_hours(row.hours_left)}, not renewed: {row.name}"
    when = _naive(row.expires_at).isoformat(timespec="minutes")
    detail = (
        f"{row.name} ({row.kind}) expires at {when}Z and nobody has renewed it.\n\n"
        f"Owner: {row.owner}\n"
        f"Source: {row.source} "
        + (
            "(read from MyKronos's own records)"
            if row.source == "observed"
            else "(a date a person wrote in the credential calendar)"
        )
        + f"\nRenewal step: {row.renewal_step}\n\n"
        f"Opened by MyKronos's {CREDENTIAL_EXPIRY_INCIDENTS_JOB} job {LEAD_HOURS} hours "
        "ahead (TheHub #61104). Renewing it takes it off GET /api/credentials/expiring, "
        "and the job then comments here; resolve this incident once the renewal is "
        "confirmed."
    )
    return {
        "room": ROOM,
        "severity": SEVERITY,
        "title": title[:255],
        "detail": detail,
        "source_capability": SOURCE_CAPABILITY,
        "source_ref": source_ref(row),
        "tags": ["credential-expiry", f"owner:{row.owner}"[:64]],
        "context": {
            "name": row.name,
            "kind": row.kind,
            "owner": row.owner,
            "expires_at": when,
            "source": row.source,
        },
    }


async def raise_incidents(
    *,
    db: Any,
    hub: Any,
    read: ExpiringReader,
    now: datetime | None = None,
) -> IncidentResult:
    """Open an incident for each credential due one, and comment on those
    whose credential has left the list.

    Raises `JobSkipped` when TheHub is not connected and
    `CredentialIncidentError` when TheHub refused an incident or a comment.
    """
    from mykronos.delivery_sources import HUB_NOT_CONNECTED

    if hub is None:
        raise JobSkipped(HUB_NOT_CONNECTED)
    moment = _naive(now or datetime.now(UTC))
    # The window reaches back as far as the calendar lists lapses, so an
    # incident is cleared only once its credential has really left the list.
    view = await read(LEAD_HOURS)
    listed = {source_ref(row) for row in view.credentials}
    already = opened_incidents(db)
    result = IncidentResult()
    refused: list[str] = []

    for row in due(view.credentials, quiet=quiet_actors(db, moment)):
        ref = source_ref(row)
        if _entity(ref) in already:
            continue
        outcome = await hub.open_incident(payload(row))
        if not outcome.ok:
            refused.append(f"{row.name}: {outcome.detail}")
            continue
        incident_id = outcome.body.get("id") if isinstance(outcome.body, dict) else None
        with db.session() as session:
            db.audit(
                session,
                actor=ACTOR,
                action=ACTION,
                entity_type=ENTITY_TYPE,
                entity_id=_entity(ref),
                source_ref=ref,
                incident_id=incident_id,
                expires_at=_naive(row.expires_at).isoformat(),
                opened_at=moment.isoformat(),
            )
        result.opened.append(row.name)
        logger.info("Opened TheHub incident %s for an unrenewed credential", incident_id)

    for entity, info in already.items():
        ref = str(info.get("source_ref") or "")
        if ref in listed:
            continue
        incident_id = info.get("incident_id")
        if incident_id is not None:
            outcome = await hub.comment_incident(
                int(incident_id),
                f"At {moment.isoformat(timespec='minutes')}Z this credential is no longer on "
                "the expiry list: renewed, revoked, re-dated or past the calendar's look-back. "
                "Resolve this incident once the renewal is confirmed.",
            )
            if not outcome.ok:
                refused.append(f"comment on incident {incident_id}: {outcome.detail}")
                continue
        with db.session() as session:
            db.audit(
                session,
                actor=ACTOR,
                action=CLEARED,
                entity_type=ENTITY_TYPE,
                entity_id=entity,
                source_ref=ref,
                incident_id=incident_id,
                cleared_at=moment.isoformat(),
            )
        result.cleared.append(ref)

    if refused:
        raise CredentialIncidentError("TheHub refused: " + "; ".join(refused))
    return result

