"""Absence reconciliation — closing findings that stopped being reported.

spec 05 §5: a finding absent from the latest scan is marked `fixed`, but only
after **two consecutive scans** confirm its absence, so a flaky scanner that
misses something once does not close it and then reopen it next run. That
flapping would be worse than leaving it open: it destroys `resolved_at`,
corrupts mean-time-to-fix, and generates a reopened event every cycle.

Rather than tracking an absence counter on each finding, absence is derived:
if a finding's `last_seen_scan_run_id` is not among the two most recent
qualifying scans for its (repo, capability), it has missed both.

**On spec 05 §9's "no component other than the Ingestion API writes to the
Parquet partitions".** This job does write. The rule exists so that all
*ingestion* goes through one validating, deduplicating path — and this is not
ingestion. It is a derived state transition that belongs to the lake itself,
which is why it lives here beside compaction rather than in a service that
merely reads. Routing it through the findings endpoint would be actively
wrong: that path means "I observed this again", and its upsert would flip a
`fixed` finding straight back to `open`. See docs/DECISIONS.md D-014.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

import duckdb

from mykronos.lake.catalog import Catalog, sql_path
from mykronos.lake.tables import column_names
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Scan outcomes that count as a real observation. A failed or partially
#: failed scan reporting nothing is not evidence a finding is gone — treating
#: it as such would close findings every time CI had a bad day.
CONFIRMING_STATUSES = ("success", "no_applicable_targets")

#: spec 05 §5. Two consecutive absences, not one.
REQUIRED_ABSENCES = 2


@dataclass
class ReconcileResult:
    fixed: list[str] = field(default_factory=list)
    partitions_written: int = 0
    #: (repo, capability) pairs skipped for lack of enough qualifying scans.
    insufficient_history: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed)


def reconcile_absences(catalog: Catalog, required: int = REQUIRED_ABSENCES) -> ReconcileResult:
    """Close findings that have been absent from `required` consecutive scans."""
    result = ReconcileResult()
    names = column_names("findings")
    projection = ", ".join(names)

    if not catalog.all_files("findings"):
        return result

    with catalog.connect() as con:
        statuses = ", ".join(f"'{s}'" for s in CONFIRMING_STATUSES)

        # The most recent qualifying scan runs per (repo, capability).
        con.execute("DROP TABLE IF EXISTS recent_runs")
        con.execute(
            f"""
            CREATE TEMP TABLE recent_runs AS
            SELECT repo_full_name, capability, scan_run_id, rn
            FROM (
                SELECT repo_full_name, capability, scan_run_id,
                       row_number() OVER (
                           PARTITION BY repo_full_name, capability
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs
                WHERE scan_status IN ({statuses})
            ) WHERE rn <= {required}
            """
        )

        # A pair with fewer than `required` qualifying scans cannot yet confirm
        # anything. Recorded rather than silently skipped: "we have not looked
        # enough times" is different from "nothing to close".
        for repo, capability, count in con.execute(
            "SELECT repo_full_name, capability, count(*) FROM recent_runs "
            "GROUP BY 1, 2 HAVING count(*) < ?",
            [required],
        ).fetchall():
            result.insufficient_history.append((str(repo), str(capability)))
            logger.debug(
                "Skipping %s/%s: only %s qualifying scan(s)", repo, capability, count
            )

        # Open findings whose last sighting predates all of those runs.
        candidates = con.execute(
            f"""
            SELECT f.finding_id, f.dt
            FROM findings f
            WHERE f.status = 'open'
              AND EXISTS (
                  SELECT 1 FROM recent_runs r
                  WHERE r.repo_full_name = f.repo_full_name
                    AND r.capability = f.capability
                  GROUP BY r.repo_full_name, r.capability
                  HAVING count(*) >= {required}
              )
              AND f.last_seen_scan_run_id NOT IN (
                  SELECT r.scan_run_id FROM recent_runs r
                  WHERE r.repo_full_name = f.repo_full_name
                    AND r.capability = f.capability
              )
            """
        ).fetchall()

        if not candidates:
            con.execute("DROP TABLE IF EXISTS recent_runs")
            return result

        by_partition: dict[str, list[str]] = {}
        for finding_id, dt in candidates:
            by_partition.setdefault(str(dt), []).append(str(finding_id))

        resolved_at = utcnow()
        for dt, finding_ids in by_partition.items():
            files = catalog.partition_files("findings", dt)
            if not files:
                continue
            pattern = sql_path(catalog.partition_dir("findings", dt) / "*.parquet")

            con.execute("DROP TABLE IF EXISTS part")
            con.execute(
                f"CREATE TEMP TABLE part AS "
                f"SELECT {projection} FROM read_parquet('{pattern}', union_by_name = 1)"
            )
            placeholders = ", ".join(["?"] * len(finding_ids))
            con.execute(
                f"UPDATE part SET status = 'fixed', resolved_at = ? "
                f"WHERE finding_id IN ({placeholders}) AND status = 'open'",
                [resolved_at, *finding_ids],
            )

            target = catalog.partition_dir("findings", dt) / "part-0000.parquet"
            _write_parquet(con, f"SELECT {projection} FROM part", target)
            for stale in files:
                if stale != target:
                    stale.unlink(missing_ok=True)
            con.execute("DROP TABLE part")

            result.fixed.extend(finding_ids)
            result.partitions_written += 1

        con.execute("DROP TABLE IF EXISTS recent_runs")
        catalog.refresh_views(con)

    if result.fixed:
        logger.info("Reconciliation closed %s absent finding(s)", result.total_fixed)
    return result


def _write_parquet(
    con: duckdb.DuckDBPyConnection, select_sql: str, destination: Path
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(".parquet.tmp")
    con.execute(f"COPY ({select_sql}) TO '{sql_path(pending)}' (FORMAT PARQUET)")
    os.replace(pending, destination)


__all__ = ["REQUIRED_ABSENCES", "ReconcileResult", "reconcile_absences"]
