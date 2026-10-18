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
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

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
