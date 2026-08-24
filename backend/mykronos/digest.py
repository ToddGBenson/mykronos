"""The weekly per-owner digest (spec 27 §4).

Everything this platform knows lives behind a URL somebody has to remember to
visit. A digest is the one thing that goes the other way, which is why it is
worth getting the contents right rather than shipping a link.

**The last section is not filler.** A weekly message that only ever lists new
obligations trains people to stop opening it — and a platform whose messages
go unread is a platform that has quietly switched itself off. This one also
says what closed and, since spec 25 §2, whether the closure was *verified*.
That is the only line here that says risk was removed rather than that a row
changed, and it is the reason anybody reads the rest.

**Addressed, not broadcast.** Every item is scoped to one owner (spec 24 §1) —
a digest that mails the whole estate to everyone is a digest people filter into
a folder. An owner with nothing outstanding is not sent one at all: an empty
weekly message is a training exercise in ignoring weekly messages.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from mykronos.dashboard import due_state
from mykronos.lake.catalog import Catalog
from mykronos.notify import Notification
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How many rows of each kind a digest names before it summarises. A digest
#: that lists everything is a report, and a report is what the queue already
#: is.
MAX_ROWS = 5


@dataclass
class OwnerDigest:
    owner: str
    newly_overdue: list[dict[str, Any]] = field(default_factory=list)
    claimed_and_ageing: list[dict[str, Any]] = field(default_factory=list)
    top_unclaimed: list[dict[str, Any]] = field(default_factory=list)
    closed_last_week: int = 0
    verified_last_week: int = 0

    @property
    def worth_sending(self) -> bool:
        """Whether there is anything to say.

        Closures alone count: "the four things you fixed last week are
        verified gone" is worth a message on its own, and it is the message
        that makes the others get read.
        """
        return bool(
            self.newly_overdue
            or self.claimed_and_ageing
            or self.top_unclaimed
            or self.closed_last_week
        )


def _rows(catalog: Catalog, since: datetime) -> list[dict[str, Any]]:
    columns = (
        "finding_id",
        "repo_full_name",
        "rule_id",
        "title",
        "severity",
        "owner",
        "due_at",
        "first_seen_at",
    )
    raw = catalog.query(
        f"SELECT {', '.join(columns)} FROM findings "
        "WHERE status = 'open' AND owner IS NOT NULL AND owner <> ''"
    )
    return [dict(zip(columns, row, strict=True)) for row in raw]


def build(
    catalog: Catalog,
    *,
    states: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> list[OwnerDigest]:
    """One digest per owner with something outstanding.

    `states` is the claim/snooze map (spec 27 §3); without it every row counts
    as unclaimed, which is the right degradation — a digest that silently
    dropped claimed work would under-report somebody's week.
    """
    moment = now or utcnow()
    week_ago = moment - timedelta(days=7)
    states = states or {}

    by_owner: dict[str, OwnerDigest] = defaultdict(lambda: OwnerDigest(owner=""))
    for row in _rows(catalog, week_ago):
        owner = str(row["owner"])
        digest = by_owner[owner]
        digest.owner = owner

        state = states.get(str(row["finding_id"]))
        claimed_by = getattr(state, "claimed_by", None)
        if getattr(state, "snoozed_until", None):
            # Deliberately deferred, with a reason and a date. Chasing it in a
            # weekly message is how a snooze stops meaning anything.
            continue

        if due_state(row.get("due_at"), now=moment) == "overdue":
            digest.newly_overdue.append(row)
        elif claimed_by:
            first_seen = row.get("first_seen_at")
            if isinstance(first_seen, datetime) and first_seen < week_ago:
                digest.claimed_and_ageing.append(row)
        else:
            digest.top_unclaimed.append(row)

    closed = catalog.query(
        "SELECT owner, count(*) FROM findings WHERE status = 'fixed' "
        "AND resolved_at >= ? AND owner IS NOT NULL GROUP BY 1",
        [week_ago],
    )
    for owner, count in closed:
        digest = by_owner[str(owner)]
        digest.owner = str(owner)
        digest.closed_last_week = int(count)

    if catalog.all_files("remediation_events"):
        verified = catalog.query(
            "SELECT f.owner, count(*) FROM remediation_events e "
            "JOIN findings f ON f.finding_id = e.finding_id "
            "WHERE e.verification_outcome = 'verified_fixed' AND e.verified_at >= ? "
            "AND f.owner IS NOT NULL GROUP BY 1",
            [week_ago],
        )
        for owner, count in verified:
            digest = by_owner[str(owner)]
            digest.owner = str(owner)
            digest.verified_last_week = int(count)

    return [d for d in by_owner.values() if d.owner and d.worth_sending]


def render(digest: OwnerDigest) -> Notification:
    """One owner's week, as a message.

    Opens with what is late, because that is what a deadline is for, and
    closes with what was fixed, because that is what makes it read next week.
    """
    lines: list[str] = []

    def section(title: str, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        lines.append(f"*{title}* ({len(rows)})")
        for row in rows[:MAX_ROWS]:
            lines.append(
                f"- {row['severity']} `{row['rule_id']}` in {row['repo_full_name']}"
            )
        if len(rows) > MAX_ROWS:
            lines.append(f"- ...and {len(rows) - MAX_ROWS} more")
        lines.append("")

    section("Overdue", digest.newly_overdue)
    section("Claimed and ageing", digest.claimed_and_ageing)
    section("Unclaimed, worth a look", digest.top_unclaimed)

    if digest.closed_last_week:
        verified = digest.verified_last_week
        lines.append(
            f"*Closed last week:* {digest.closed_last_week}"
            + (
                f", {verified} verified gone by a re-scan."
                if verified
                else " — none re-scanned yet, so none confirmed removed."
            )
        )

    level = "critical" if digest.newly_overdue else "info"
    return Notification(
        title=f"Weekly security worklist — {digest.owner}",
        detail="\n".join(lines).strip(),
        repo_full_name="",
        level=level,
    )


def send_all(catalog: Catalog, notifier: Any, *, now: datetime | None = None) -> int:
    """Send every owner's digest. Returns how many went out.

    A delivery failure is surfaced by the notifier itself (PS-10: a notifier
    that cannot deliver is worse than none) rather than swallowed here.
    """
    digests = build(catalog, now=now)
    for digest in digests:
        notifier.send(render(digest))
    if digests:
        logger.info("Weekly digest sent to %d owner(s).", len(digests))
    return len(digests)
