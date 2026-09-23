"""Attribute the withdrawals that predate `superseded_source` (spec 05 §5a).

`superseded` has two machine setters. Reprocessing sets it when the adapter
that produced the record was wrong; `carry_forward` sets it when the code the
record described changed. Both setters write `superseded_source` now — but 460
rows were withdrawn before the column existed, and they hold null.

**The information is perishing, which is why this runs now rather than later.**
The only thing separating the two setters on those rows today is an accident:
every reprocess withdrawal so far happens to have left `superseded_by` null,
and all three carry-forwards set it. §5a explicitly permits reprocessing to
name a replacement "where there is one", so the first reprocess that
re-derives an equivalent finding writes a row that is, on that evidence,
indistinguishable from a carry-forward. After that the backfill is guesswork.

**So it does not read `superseded_by` as if it meant the setter.** It reads
scan-run provenance, which says the same thing for a reason rather than by
coincidence:

`carry_forward` writes *both halves* of a link. It copies the predecessor's
`first_seen_at` and `first_seen_scan_run_id` onto the successor — that is what
stops a gate blaming the commit that moved a line — and the successor is by
construction a finding that a **later scan of the same lane** reported. So a
carry-forward predecessor points at a successor that carries its own
first-seen run and belongs to a different scan run.

Reprocessing re-reads one archived scan and re-ingests it under **that same
`scan_run_id`**. The replacement it names therefore comes from the very run
the withdrawn record was last seen in. And `carry_forward` never withdraws a
predecessor it has not matched, so it cannot be the origin of a `superseded`
row with no replacement at all.

Three rules, in order, and a row that matches none of them is reported rather
than guessed at. An invented setter is worse than an absent one: it is the
guesswork this whole change exists to avoid, wearing the answer's clothes.

**How it decided is written down.** The lake records *what* a finding is;
spec 12 §7's audit log records who set it and why — the division `groom.py`
already relies on to say who dispositioned a finding. One audit entry per
attributed row names the rule that decided it and the provenance it read, so
a later reader can check the attribution instead of taking it on trust.

**Not written through the buffer**, for the reason `migrate_assets` is not:
compaction's findings upsert reopens a row whose stored status is `fixed`, and
a backfill is not a rescan. `update_findings` rewrites the named column in
place and leaves status, dispositions and `first_seen_at` alone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text

from mykronos.db import Database
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings

logger = logging.getLogger(__name__)

#: The value written by `carry_forward._apply`.
CARRY_FORWARD = "carry_forward"
#: The value written by `reprocess._mark_superseded`.
REPROCESS = "reprocess"

AUDIT_ACTION = "finding.superseded_source_backfilled"


@dataclass(frozen=True)
class Attribution:
    """One withdrawal, the setter derived for it, and the evidence."""

    finding_id: str
    superseded_source: str
    #: Which of the three rules below decided it. Stored in the audit entry so
    #: the attribution can be re-checked against this module rather than
    #: believed.
    rule: str
    evidence: dict[str, Any]


@dataclass
class BackfillResult:
    examined: int = 0
    already_sourced: int = 0
    attributed: list[Attribution] = field(default_factory=list)
    #: Withdrawals matching none of the three rules. Left null and named.
    undetermined: list[str] = field(default_factory=list)
    partitions_written: int = 0
    #: [#60485] Entries actually written this run. Lower than `attributed` on a
    #: re-run that is repairing a half-applied backfill, which is the case the
    #: count exists to make visible rather than leave to inference.
    audit_entries_written: int = 0

    @property
    def by_setter(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for row in self.attributed:
            counts[row.superseded_source] = counts.get(row.superseded_source, 0) + 1
        return counts

    def summary(self) -> str:
        split = ", ".join(f"{n} {setter}" for setter, n in sorted(self.by_setter.items()))
        return (
            f"{self.examined} withdrawal(s) examined, "
            f"{len(self.attributed)} attributed ({split or 'none'}), "
            f"{self.already_sourced} already named their setter, "
            f"{len(self.undetermined)} undetermined, "
            f"{self.audit_entries_written} audit entr"
            f"{'y' if self.audit_entries_written == 1 else 'ies'} written"
        )


def _derive(row: dict[str, Any], *, successor_exists: bool) -> tuple[str, str] | None:
    """The setter and the rule that decided it, or None if neither fits."""
    # 1. `carry_forward` wrote both halves: it moved the predecessor's
    #    first-seen run onto a successor that a *different* scan reported.
    if (
        successor_exists
        and row["successor_first_seen_scan_run_id"] == row["first_seen_scan_run_id"]
        and row["successor_scan_run_id"] != row["last_seen_scan_run_id"]
    ):
        return CARRY_FORWARD, "successor_carries_the_predecessors_first_seen_run"

    # 2. Nothing replaced it. `carry_forward` only withdraws a predecessor it
    #    has matched, so it is never the origin of a null replacement.
    if row["superseded_by"] is None:
        return REPROCESS, "no_replacement_and_carry_forward_always_names_one"

    # 3. The replacement came out of the run this record was last seen in,
    #    which is reprocessing re-ingesting that run's archived output.
    if successor_exists and row["successor_scan_run_id"] == row["last_seen_scan_run_id"]:
        return REPROCESS, "replacement_from_the_run_it_was_last_seen_in"

    return None


def backfill_superseded_source(
    catalog: Catalog,
    db: Database,
    *,
    actor: str = "cli",
    dry_run: bool = False,
) -> BackfillResult:
    """Name the setter on every withdrawal written before the column existed."""
    result = BackfillResult()
    if not catalog.all_files("findings"):
        return result

    rows = catalog.query(
        "SELECT p.finding_id, p.superseded_source, p.superseded_by, "
        "       p.first_seen_scan_run_id, p.last_seen_scan_run_id, p.resolved_at, "
        "       s.finding_id, s.scan_run_id, s.first_seen_scan_run_id "
        "FROM findings p LEFT JOIN findings s ON s.finding_id = p.superseded_by "
        "WHERE p.status = 'superseded' "
        "ORDER BY p.finding_id"
    )

    for (
        finding_id,
        superseded_source,
        superseded_by,
        first_seen_scan_run_id,
        last_seen_scan_run_id,
        resolved_at,
        successor_id,
        successor_scan_run_id,
        successor_first_seen_scan_run_id,
    ) in rows:
        result.examined += 1
        if superseded_source:
            result.already_sourced += 1
            continue

        evidence = {
            "superseded_by": _text(superseded_by),
            "first_seen_scan_run_id": _text(first_seen_scan_run_id),
            "last_seen_scan_run_id": _text(last_seen_scan_run_id),
            "successor_scan_run_id": _text(successor_scan_run_id),
            "successor_first_seen_scan_run_id": _text(successor_first_seen_scan_run_id),
            "resolved_at": None if resolved_at is None else str(resolved_at),
        }
        derived = _derive(evidence, successor_exists=successor_id is not None)
        if derived is None:
            result.undetermined.append(str(finding_id))
            logger.warning(
                "backfill_superseded_source: %s matches neither setter's "
                "signature and was left null — superseded_by=%s, "
                "last_seen_scan_run_id=%s",
                finding_id,
                evidence["superseded_by"],
                evidence["last_seen_scan_run_id"],
            )
            continue

        setter, rule = derived
        result.attributed.append(
            Attribution(
                finding_id=str(finding_id),
                superseded_source=setter,
                rule=rule,
                evidence=evidence,
            )
        )

    if dry_run or not result.attributed:
        return result

    # [#60485] THE AUDIT IS WRITTEN FIRST, AND THE ORDER IS THE WHOLE POINT.
    #
    # It used to run after the lake update, in a different store with no
    # compensation between them. On 2026-09-23 the lake write committed, the
    # audit INSERT died on "database is locked", and the result was 460
    # findings naming a setter with nothing anywhere saying how it was decided
    # -- unrecoverable through this function, because the `already_sourced`
    # guard then skips every one of them.
    #
    # Inverted, the surviving failure is the detectable one. An audit entry for
    # a finding whose `superseded_source` is still null CONTRADICTS ITSELF and
    # is visible to anyone who looks; the old order produced a lake that looked
    # settled and a silence nobody could distinguish from "nothing happened".
    #
    # `Database.audit` says it takes the caller's session "so the log entry
    # commits in the same transaction as the change it describes -- an audit
    # log that can be missing entries for changes that succeeded is worse than
    # none". That holds inside SQLite and cannot span the lake, so ordering is
    # the only instrument left.
    already_logged = _already_logged(db)
    pending = [a for a in result.attributed if a.finding_id not in already_logged]
    if pending:
        with db.session() as session:
            for attribution in pending:
                db.audit(
                    session,
                    actor=actor,
                    action=AUDIT_ACTION,
                    entity_type="finding",
                    entity_id=attribution.finding_id,
                    superseded_source=attribution.superseded_source,
                    rule=attribution.rule,
                    **attribution.evidence,
                )
    result.audit_entries_written = len(pending)

    # One update per setter, so the value is a single bound parameter rather
    # than one per row.
    for setter in sorted(result.by_setter):
        ids = [a.finding_id for a in result.attributed if a.superseded_source == setter]
        outcome = update_findings(
            catalog,
            locate_findings(catalog, ids),
            "superseded_source = ?",
            [setter],
            # A withdrawal is terminal, but the guard costs nothing and is the
            # difference between this and a sweep that could overwrite a
            # status something changed between the read and the write.
            only_if_status="superseded",
        )
        result.partitions_written += outcome.partitions_written
        logger.info(
            "backfill_superseded_source: %d withdrawal(s) attributed to %s",
            len(ids),
            setter,
        )

    return result


def _already_logged(db: Database) -> set[str]:
    """Finding ids this backfill has already logged an entry for.

    [#60485] What makes a re-run REPAIR rather than duplicate. If the lake
    write failed after the audit succeeded, the findings are still unsourced,
    so they are re-derived and re-attempted -- and skipping the entries that
    already exist is what stops the second pass writing 460 duplicates.
    """
    with db.session() as session:
        rows = session.execute(
            text("SELECT entity_id FROM audit_log WHERE action = :a"),
            {"a": AUDIT_ACTION},
        ).fetchall()
    return {str(r[0]) for r in rows}


def _text(value: Any) -> str | None:
    return None if value is None else str(value)
