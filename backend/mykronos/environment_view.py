"""Stored environmental scores, read for lists and counts (TheHub #60828).

`environment.rescore` keeps one `EnvironmentalScore` per open finding. The
finding page reads one; the Findings list and its summary read every one for
a repository, and must agree with each other: a count of "rescored down" is
only useful if filtering to it lists exactly those findings. So both read the
stored row through this module, and neither recomputes anything on read — a
list of four hundred findings would otherwise resolve four hundred sets of
facts to draw one column.

**Direction is the word, not the number.** A finding is rescored down when its
effective severity is a lower word than the scanner's, which is what the list
shows beside it. A score that moved inside one band (9.8 to 9.1) leaves the
word unchanged, and the list does not claim a rescore it does not show.

**Down is verified by construction.** The resolver applies a lowering fact
only when it was observed, or declared and confirmed within the window, and
never lowers exploitability on a declaration (environment.py rule 3). So every
stored "down" rests on evidence; the summary says "(verified)" because it is
true of the rule, not because this module checks again.

**Absent is "not rescorable".** A rescore stores a row for every open finding
it could score and deletes the rest, so no row means no vector (no CVE, or no
published v3 vector for it) — or that no rescore has reached the repository
yet, which the daily `environment` job bounds to a day.

**The triage rank reads it too** (TheHub #60829). `rank_reading` turns one
stored row into what the queue's `environmental` term needs: how many CVSS
bands the environment moved the score, whether the row is in force, and one
line naming the facts that moved it. A row resting on an expired lowering fact
is set aside by `environment._lapsed` - the same rule the rescore uses to
recompute it - so the rank never leans on evidence the rescore would discard.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import environment
from mykronos.db.models import EnvironmentalScore

#: The four states every finding of a status is in, exactly one each, so the
#: counts sum to the list's `total`.
RESCORE_STATES: tuple[str, ...] = ("down", "up", "unchanged", "not_rescorable")

_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class StoredScore:
    """What the list needs from one `EnvironmentalScore` row."""

    effective_severity: str
    scanner_severity: str
    base: float
    environmental: float

    @property
    def state(self) -> str:
        return direction(self.scanner_severity, self.effective_severity)


def direction(scanner_severity: str, effective_severity: str) -> str:
    """`down`, `up` or `unchanged`: the effective word against the scanner's."""
    scanner = _RANK.get((scanner_severity or "").lower())
    effective = _RANK.get((effective_severity or "").lower())
    if scanner is None or effective is None or scanner == effective:
        return "unchanged"
    return "down" if effective < scanner else "up"


def stored_scores(session: Session, repo_full_name: str) -> dict[str, StoredScore]:
    """Every stored score for one repository, by finding id."""
    rows = session.execute(
        select(
            EnvironmentalScore.finding_id,
            EnvironmentalScore.effective_severity,
            EnvironmentalScore.scanner_severity,
            EnvironmentalScore.base,
            EnvironmentalScore.environmental,
        ).where(EnvironmentalScore.repo_full_name == repo_full_name)
    )
    return {
        str(finding_id): StoredScore(
            effective_severity=str(effective or ""),
            scanner_severity=str(scanner or ""),
            base=float(base or 0.0),
            environmental=float(env or 0.0),
        )
        for finding_id, effective, scanner, base, env in rows
        if effective
    }


def state_of(finding_id: str, stored: Mapping[str, StoredScore]) -> str:
    score = stored.get(finding_id)
    return "not_rescorable" if score is None else score.state


def count_states(
    finding_ids: Iterable[str], stored: Mapping[str, StoredScore]
) -> dict[str, int]:
    """How many of these findings are in each state; sums to their number."""
    counts = dict.fromkeys(RESCORE_STATES, 0)
    for finding_id in finding_ids:
        counts[state_of(finding_id, stored)] += 1
    return counts


def count_effective(
    finding_ids: Iterable[str], stored: Mapping[str, StoredScore]
) -> dict[str, int]:
    """How many of these findings have each effective severity. Findings
    without a stored score are in no bucket: they have no effective severity,
    and counting them under the scanner's word would claim a re-reading."""
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for finding_id in finding_ids:
        score = stored.get(finding_id)
        if score is not None and score.effective_severity in counts:
            counts[score.effective_severity] += 1
    return counts


# -- The triage rank's reading (TheHub #60829) -----------------------------

#: How many applied facts the rank line names before "and N more". A rank
#: term is one line beside a queue row; the finding page lists every fact.
_SUMMARY_FACTS = 2


@dataclass(frozen=True)
class RankReading:
    """What the queue's `environmental` term reads from one stored score.

    `state` is `scored` (in force) or `lapsed` (rests on an expired lowering
    fact). A finding with no stored row has no reading at all, and the rank
    says so itself. `shift` is env_band - base_band, and only counts when
    scored.
    """

    state: str
    shift: int
    summary: str


def _age(when: Any, now: datetime) -> str | None:
    if not isinstance(when, str) or not when:
        return None
    try:
        moment = datetime.fromisoformat(when)
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.replace(tzinfo=None)
    days = (now.replace(tzinfo=None) - moment).days
    if days < 1:
        return "today"
    return f"{days}d ago"


def _fact_phrase(raw: Mapping[str, Any], now: datetime) -> str:
    """`MAV:L from observed 'api' is bound to loopback, 3d ago`."""
    phrase = f"{raw.get('metric')}:{raw.get('value')}"
    tier = str(raw.get("tier") or "")
    because = str(raw.get("because") or "").strip()
    source = " ".join(part for part in (tier, because) if part)
    if source:
        phrase += f" from {source}"
    age = _age(raw.get("verified_at"), now)
    if age:
        phrase += f", {age}"
    return phrase


def _bands(count: int) -> str:
    return f"{count} band{'' if count == 1 else 's'}"


def rank_reading(row: EnvironmentalScore | None, now: datetime) -> RankReading | None:
    """The rank's view of one stored score, or None when there is none."""
    if row is None or not row.effective_severity:
        return None
    if environment._lapsed(row, now):
        expired = sorted(
            str(raw.get("expires_at"))
            for raw in row.facts_json or []
            if raw.get("applied") and raw.get("direction") == "lower" and raw.get("expires_at")
        )
        when = expired[0][:10] if expired else "earlier"
        return RankReading(
            state="lapsed",
            shift=0,
            summary=(
                f"environmental score set aside: a lowering fact it rests on expired "
                f"{when}; not counted until the next rescore"
            ),
        )
    bands = environment.BANDS
    try:
        shift = bands.index(row.env_band) - bands.index(row.base_band)
    except ValueError:
        shift = 0
    if shift == 0:
        if round(row.environmental, 1) == round(row.base, 1):
            summary = f"rescored, unchanged at {row.base:.1f}: no rank change"
        else:
            summary = (
                f"rescored within its band ({row.base_band} {row.base:.1f} to "
                f"{row.environmental:.1f}): no rank change"
            )
        return RankReading(state="scored", shift=0, summary=summary)

    wanted = "lower" if shift < 0 else "raise"
    moved = [
        raw
        for raw in row.facts_json or []
        if raw.get("applied") and raw.get("direction") == wanted
    ]
    head = f"rescored {'down' if shift < 0 else 'up'} {_bands(abs(shift))}"
    if not moved:
        return RankReading(state="scored", shift=shift, summary=head)
    phrases = [_fact_phrase(raw, now) for raw in moved[:_SUMMARY_FACTS]]
    more = len(moved) - _SUMMARY_FACTS
    if more > 0:
        phrases.append(f"and {more} more")
    return RankReading(state="scored", shift=shift, summary=f"{head}: {'; '.join(phrases)}")


def rank_readings(
    session: Session, finding_ids: Iterable[str], now: datetime
) -> dict[str, RankReading]:
    """Readings for every finding id that has a stored score.

    Chunked so a five-thousand-row queue is a handful of queries, not one per
    row and not one statement with five thousand parameters.
    """
    ids = list(dict.fromkeys(str(i) for i in finding_ids))
    readings: dict[str, RankReading] = {}
    for start in range(0, len(ids), 500):
        chunk = ids[start : start + 500]
        for row in session.scalars(
            select(EnvironmentalScore).where(EnvironmentalScore.finding_id.in_(chunk))
        ):
            reading = rank_reading(row, now)
            if reading is not None:
                readings[str(row.finding_id)] = reading
    return readings


@dataclass(frozen=True)
class RankCoverage:
    """How many open findings the environmental term can read, of how many."""

    scored: int
    lapsed: int
    unscored: int

    @property
    def total(self) -> int:
        return self.scored + self.lapsed + self.unscored


def rank_coverage(
    session: Session, open_finding_ids: Iterable[str], now: datetime
) -> RankCoverage:
    """Count open findings by whether a stored score is in force for them."""
    open_ids = {str(i) for i in open_finding_ids}
    scored = lapsed = 0
    for row in session.scalars(select(EnvironmentalScore)):
        if str(row.finding_id) not in open_ids:
            continue
        reading = rank_reading(row, now)
        if reading is None:
            continue
        if reading.state == "lapsed":
            lapsed += 1
        else:
            scored += 1
    return RankCoverage(scored=scored, lapsed=lapsed, unscored=len(open_ids) - scored - lapsed)
