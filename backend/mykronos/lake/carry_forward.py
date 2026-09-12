"""Carrying a finding forward when its content changes (spec 05 §5b).

`finding_id` is a hash of the code the tool matched (§5). That is what makes
a finding survive reindentation and code motion, and it has an edge: when the
matched code *itself* changes, the hash changes, the old row is orphaned and
the same defect arrives as a new finding with a new `first_seen_at` — and,
if somebody had dispositioned it, without their decision.

**Observed 2026-09-09.** TheHub's Oracle gate blocked with "Introduced by
bd9e3c6b: 0 critical, 3 high". Two of the three were new code. The third was
a `text()` call in `backend/services/devops/lifecycle.py` that had been
dismissed as a false positive four days earlier; an unrelated change added two
lines *inside* its SQL string, the snippet hash moved, and the call came back
as a new open high. The gate named a line the commit had not written, and an
operator decision was discarded without anybody being told.

**Why the fix is not a coarser hash.** The obvious repair is to hash less —
the first line of the match, or only the enclosing symbol. Every version of
that trades this failure for a worse one: two distinct findings in one
function collapse into one row, and the platform stops reporting a real
defect. Under-reporting is the direction this codebase refuses (spec 04 §6),
so identity stays exact and the *link between two identities* becomes an
explicit, recorded fact instead.

**What this does.** After each compaction, for every finding whose own lane —
`(repo, capability, branch, tool)`, the same lane `reconcile.py` closes on —
has run again without reporting it, look for a finding that appeared in that
same run, under the same rule, in the same file, whose snippet is
substantially the one that went missing. Where exactly one such pair exists
and it is unambiguous, the old row is withdrawn as `superseded` naming its
replacement, and the replacement inherits what belonged to the finding rather
than to the sighting: when it was first seen, and any disposition a person had
recorded.

**What it refuses.** No match above the floor, or two candidates too close to
separate, and nothing happens — the decision is reported as stranded, with the
reason, rather than applied to a finding that did not earn it. A finding
carrying no stored snippet cannot be matched at all and is named as such.
Absence of evidence is not a reason to guess.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mykronos.fingerprint import snippet_similarity
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.lake.reconcile import CONFIRMING_STATUSES
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Statuses a person set, which must never be lost. `open` is here too: a
#: finding that only moved was not introduced by the commit that moved it, and
#: carrying `first_seen_*` across is what stops a gate saying otherwise.
CARRIED_STATUSES = ("open", "false_positive", "accepted_risk", "suppressed")

#: Decisions, as opposed to observations. Only these are copied onto the
#: successor as a status; an `open` predecessor carries its dates and nothing
#: else.
HUMAN_DISPOSITIONS = ("false_positive", "accepted_risk", "suppressed")

#: The share of normalized lines two snippets must have in common before one
#: is treated as the other having changed rather than as a different finding.
#:
#: Measured, not chosen. The dismissed `lifecycle.py` snippet scores 0.75
#: against the edited version of itself and 0.35 and 0.26 against the two
#: genuinely new calls beside it. 0.6 sits in that gap with room on both
#: sides.
MIN_SIMILARITY = 0.6

#: How far ahead of the runner-up the best match must be. Without it, a call
#: copied into two places would hand its dismissal to whichever copy sorted
#: first. 0.75 against 0.35 clears this comfortably; two near-identical copies
#: do not, and are refused.
MIN_MARGIN = 0.2


@dataclass(frozen=True)
class _Finding:
    finding_id: str
    dt: str
    asset_id: str
    capability: str
    rule_id: str
    file_path: str
    branch: str
    tool_name: str
    status: str
    code_snippet: str
    first_seen_at: datetime | None
    first_seen_scan_run_id: str
    last_seen_at: datetime | None
    resolved_at: datetime | None
    accepted_until: Any
    accepted_reason_code: str | None

    @property
    def group(self) -> tuple[str, ...]:
        return (
            self.asset_id,
            self.capability,
            self.rule_id,
            self.file_path,
            self.branch,
            self.tool_name,
        )


@dataclass(frozen=True)
class Carried:
    """One finding withdrawn in favour of another, and why."""

    from_finding_id: str
    to_finding_id: str
    similarity: float
    runner_up: float
    asset_id: str
    capability: str
    rule_id: str
    file_path: str
    #: The disposition that moved, or None when the predecessor was merely
    #: `open` and only its dates travelled.
    disposition: str | None

    def describe(self) -> str:
        moved = self.disposition or "first seen"
        return (
            f"{self.file_path} [{self.rule_id}]: {moved} carried "
            f"{self.from_finding_id[:12]} -> {self.to_finding_id[:12]} "
            f"(similarity {self.similarity:.2f}, next best {self.runner_up:.2f})"
        )


@dataclass(frozen=True)
class Stranded:
    """A disposition that could not be carried, named rather than dropped."""

    finding_id: str
    asset_id: str
    capability: str
    rule_id: str
    file_path: str
    status: str
    reason: str

    def describe(self) -> str:
        return (
            f"{self.file_path} [{self.rule_id}]: {self.status} on "
            f"{self.finding_id[:12]} — {self.reason}"
        )


@dataclass
class CarryForwardResult:
    carried: list[Carried] = field(default_factory=list)
    stranded: list[Stranded] = field(default_factory=list)
    partitions_written: int = 0

    def summary(self) -> str:
        return (
            f"{len(self.carried)} finding(s) carried forward, "
            f"{len(self.stranded)} decision(s) stranded"
        )


def _rows(catalog: Catalog) -> list[Any]:
    """Every finding in a lane that has scanned again, with its lane attached.

    The lane is `(repo, capability, branch, tool)` — the same four columns
    `reconcile.py` partitions on, and for the same reason: a scanner that
    cannot read a language has said nothing about findings written in it, and
    a branch's silence is not evidence about another branch.

    Deliberately *not* "findings whose `last_seen_at` is older than the newest
    row in the estate". That test was tried on 2026-09-09 and reported 161
    stale dispositions, essentially all of them false: no capability rescans
    every file on every run, so an ordinary row that was simply not matched
    again looks orphaned. Only the scan run that a lane actually completed can
    say whether a finding was reported.
    """
    statuses = ", ".join(f"'{s}'" for s in CONFIRMING_STATUSES)
    carried = ", ".join(f"'{s}'" for s in CARRIED_STATUSES)
    return catalog.query(
        f"""
        WITH newest AS (
            SELECT repo_full_name, capability, branch, tool_name, scan_run_id
            FROM (
                SELECT repo_full_name, capability,
                       coalesce(branch, '') AS branch,
                       coalesce(tool_name, '') AS tool_name,
                       scan_run_id,
                       row_number() OVER (
                           PARTITION BY repo_full_name, capability,
                                        coalesce(branch, ''),
                                        coalesce(tool_name, '')
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs
                WHERE scan_status IN ({statuses})
            ) WHERE rn = 1
        )
        SELECT f.finding_id, f.dt, f.asset_id, f.capability, f.rule_id,
               f.file_path, n.branch, n.tool_name, f.status,
               coalesce(f.code_snippet, '') AS code_snippet,
               f.first_seen_at, f.first_seen_scan_run_id, f.last_seen_at,
               f.resolved_at, f.accepted_until, f.accepted_reason_code,
               f.last_seen_scan_run_id = n.scan_run_id AS reported_now
        FROM findings f
        JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id
        JOIN newest n
          ON n.repo_full_name = f.asset_id
         AND n.capability = f.capability
         AND n.branch = coalesce(s.branch, '')
         AND n.tool_name = coalesce(s.tool_name, '')
        WHERE f.file_path IS NOT NULL
          AND f.status IN ({carried})
          -- Code findings only. A dependency finding is keyed on the package
          -- and a network finding on address and port (§5), so neither can
          -- churn when a file is edited — there is no snippet in either
          -- identity to move. Including them was tried and produced 133 rows
          -- about container CVEs that had simply been patched, which is the
          -- noise this mechanism exists to avoid generating.
          AND f.package_name IS NULL
          AND f.address IS NULL
          AND coalesce(f.fingerprint_version, '') IN ('v2-snippet', 'v1-line')
        """
    )


def _split(rows: list[Any]) -> tuple[list[_Finding], list[_Finding]]:
    """(gone, present) — findings the lane stopped reporting, and the rest."""
    gone: list[_Finding] = []
    present: list[_Finding] = []
    for row in rows:
        reported_now = bool(row[16])
        finding = _Finding(
            finding_id=str(row[0]),
            dt=str(row[1]),
            asset_id=str(row[2]),
            capability=str(row[3]),
            rule_id=str(row[4]),
            file_path=str(row[5]),
            branch=str(row[6]),
            tool_name=str(row[7]),
            status=str(row[8]),
            code_snippet=str(row[9] or ""),
            first_seen_at=row[10],
            first_seen_scan_run_id=str(row[11] or ""),
            last_seen_at=row[12],
            resolved_at=row[13],
            accepted_until=row[14],
            accepted_reason_code=None if row[15] is None else str(row[15]),
        )
        (present if reported_now else gone).append(finding)
    return gone, present


def _eligible(predecessor: _Finding, successor: _Finding) -> bool:
    """A successor must have appeared no earlier than its predecessor's last
    sighting. Without this a pre-existing finding in the same file could be
    handed the history of one that has only just gone."""
    if predecessor.last_seen_at and successor.first_seen_at:
        return successor.first_seen_at >= predecessor.last_seen_at
    return True


def match(
    gone: list[_Finding], present: list[_Finding]
) -> tuple[list[tuple[_Finding, _Finding, float, float]], list[tuple[_Finding, str]]]:
    """Pair each vanished finding with its replacement, or say why not.

    A pair is taken only when it is the best available match for *both* sides
    and clears both the floor and the margin. Everything is evaluated against
    the partners still free, so the result does not depend on the order rows
    came out of DuckDB.
    """
    pairs: list[tuple[_Finding, _Finding, float, float]] = []
    refusals: list[tuple[_Finding, str]] = []

    by_group: dict[tuple[str, ...], list[_Finding]] = {}
    for finding in present:
        by_group.setdefault(finding.group, []).append(finding)

    grouped_gone: dict[tuple[str, ...], list[_Finding]] = {}
    for finding in gone:
        grouped_gone.setdefault(finding.group, []).append(finding)

    for group, missing in sorted(grouped_gone.items()):
        free = sorted(by_group.get(group, []), key=lambda f: f.finding_id)
        outstanding = sorted(missing, key=lambda f: f.finding_id)

        scores: dict[tuple[str, str], float] = {}
        for predecessor in outstanding:
            for successor in free:
                if not _eligible(predecessor, successor):
                    continue
                scores[(predecessor.finding_id, successor.finding_id)] = (
                    snippet_similarity(predecessor.code_snippet, successor.code_snippet)
                )

        taken_from: set[str] = set()
        taken_to: set[str] = set()

        # Highest first, ties broken on the ids so two identical scores
        # resolve the same way on every run.
        ordered = sorted(
            scores.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )
        for (from_id, to_id), score in ordered:
            if from_id in taken_from or to_id in taken_to:
                continue
            if score < MIN_SIMILARITY:
                continue

            row = [
                value
                for (f, t), value in scores.items()
                if f == from_id and t != to_id and t not in taken_to
            ]
            column = [
                value
                for (f, t), value in scores.items()
                if t == to_id and f != from_id and f not in taken_from
            ]
            runner_up = max([*row, *column, 0.0])
            if score - runner_up < MIN_MARGIN:
                continue

            predecessor = next(f for f in outstanding if f.finding_id == from_id)
            successor = next(f for f in free if f.finding_id == to_id)
            pairs.append((predecessor, successor, score, runner_up))
            taken_from.add(from_id)
            taken_to.add(to_id)

        for predecessor in outstanding:
            if predecessor.finding_id in taken_from:
                continue
            if predecessor.status not in HUMAN_DISPOSITIONS:
                # An `open` finding that simply went away is the absence
                # reconciler's business, not this one's. Reporting it here
                # would bury the decisions this result exists to surface.
                continue
            if not free:
                # Nothing appeared under this rule in this file. The dismissed
                # code was deleted, or the rule stopped firing — either way
                # there was no decision to make and no decision was lost.
                # Reporting it would say "178 stranded decisions" about an
                # estate holding one, which is the shape of the wrong number
                # this defect was first measured with.
                continue
            refusals.append((predecessor, _refusal(predecessor, scores)))

    return pairs, refusals


def _refusal(predecessor: _Finding, scores: dict[tuple[str, str], float]) -> str:
    """Why this decision was not carried, for a person to act on.

    Only ever reached when something *did* appear under the same rule in the
    same file: this is a refusal to choose, not a report that a finding went
    away.
    """
    if not predecessor.code_snippet.strip():
        return "no code snippet was stored, so there is nothing to match it against"

    mine = sorted(
        (
            (value, to_id)
            for (from_id, to_id), value in scores.items()
            if from_id == predecessor.finding_id
        ),
        reverse=True,
    )
    if not mine:
        return "everything under this rule in this file predates it"

    best, best_id = mine[0]
    if best < MIN_SIMILARITY:
        return (
            f"the closest thing in the file scored {best:.2f}, below the "
            f"{MIN_SIMILARITY:.2f} floor — it is a different finding"
        )
    second = mine[1][0] if len(mine) > 1 else 0.0
    return (
        f"{best_id[:12]} scored {best:.2f} and the next scored {second:.2f}, "
        f"closer than the {MIN_MARGIN:.2f} margin — refusing to guess"
    )


def carry_forward(catalog: Catalog, *, dry_run: bool = False) -> CarryForwardResult:
    """Link findings across a change of content. Safe to run repeatedly.

    Idempotent by construction: a predecessor becomes `superseded`, which is
    not in `CARRIED_STATUSES`, so a second pass sees nothing left to do.
    """
    result = CarryForwardResult()
    if not catalog.all_files("findings"):
        return result

    gone, present = _split(_rows(catalog))
    if not gone:
        return result

    pairs, refusals = match(gone, present)

    for predecessor, reason in refusals:
        result.stranded.append(
            Stranded(
                finding_id=predecessor.finding_id,
                asset_id=predecessor.asset_id,
                capability=predecessor.capability,
                rule_id=predecessor.rule_id,
                file_path=predecessor.file_path,
                status=predecessor.status,
                reason=reason,
            )
        )

    for predecessor, successor, score, runner_up in pairs:
        disposition = (
            predecessor.status if predecessor.status in HUMAN_DISPOSITIONS else None
        )
        result.carried.append(
            Carried(
                from_finding_id=predecessor.finding_id,
                to_finding_id=successor.finding_id,
                similarity=score,
                runner_up=runner_up,
                asset_id=predecessor.asset_id,
                capability=predecessor.capability,
                rule_id=predecessor.rule_id,
                file_path=predecessor.file_path,
                disposition=disposition,
            )
        )

    if dry_run or not pairs:
        return result

    result.partitions_written = _apply(catalog, pairs)
    for carried in result.carried:
        logger.info("Carried forward: %s", carried.describe())
    for stranded in result.stranded:
        logger.warning("Decision stranded: %s", stranded.describe())
    return result


def _apply(
    catalog: Catalog, pairs: list[tuple[_Finding, _Finding, float, float]]
) -> int:
    """Write both halves of each link.

    The successor is updated before the predecessor is withdrawn. If the
    process dies between the two, the worst outcome is a decision recorded
    twice, which a person can see and resolve; the other order would lose it.
    """
    written = 0
    now = utcnow()

    for predecessor, successor, _score, _runner_up in pairs:
        # What belongs to the finding rather than to the sighting. A
        # disposition only moves if there was one: an `open` predecessor
        # carries its dates and stays open, because nobody decided anything
        # about it.
        sets = [
            "first_seen_at = ?",
            "first_seen_scan_run_id = ?",
        ]
        params: list[Any] = [predecessor.first_seen_at, predecessor.first_seen_scan_run_id]
        if predecessor.status in HUMAN_DISPOSITIONS:
            sets += [
                "status = ?",
                "resolved_at = ?",
                "accepted_until = ?",
                "accepted_reason_code = ?",
            ]
            params += [
                predecessor.status,
                predecessor.resolved_at,
                predecessor.accepted_until,
                predecessor.accepted_reason_code,
            ]

        outcome = update_findings(
            catalog,
            locate_findings(catalog, [successor.finding_id]),
            ", ".join(sets),
            params,
            # A person who dispositioned the successor in the meantime has
            # said something more recent than this; leave it alone.
            only_if_status=successor.status,
        )
        written += outcome.partitions_written
        if not outcome.count:
            continue

        # `superseded`, not `fixed` (spec 05 §5a). The defect is very likely
        # still there under the new id, and `fixed` is the sole input to mean
        # time to fix — retiring these as fixed would report a remediation
        # that never happened, which is the exact lie that status exists to
        # prevent, arriving from one more direction.
        outcome = update_findings(
            catalog,
            locate_findings(catalog, [predecessor.finding_id]),
            "status = 'superseded', superseded_by = ?, resolved_at = ?",
            [successor.finding_id, now],
            only_if_status=predecessor.status,
        )
        written += outcome.partitions_written

    return written
