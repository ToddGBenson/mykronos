"""In-place updates to finding rows.

Two callers need to change a finding after it has been written: absence
reconciliation closes findings that stopped being reported (spec 05 §5), and
the dashboard records a human disposition — false positive, accepted risk
(spec 10 §2.2). Both rewrite Parquet partitions, and doing that dance twice in
two modules is how the second copy quietly diverges.

Why this is not a spec 05 §9 violation is argued in docs/DECISIONS.md D-014:
the rule exists so all *ingestion* passes one validating path, and neither of
these is ingestion. Routing a status change through the findings endpoint
would be actively wrong — that path means "I observed this again", and its
upsert flips a closed finding straight back to open.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb

from mykronos.lake.catalog import Catalog, sql_path
from mykronos.lake.tables import column_names

logger = logging.getLogger(__name__)


@dataclass
class UpdateResult:
    updated: list[str] = field(default_factory=list)
    partitions_written: int = 0

    @property
    def count(self) -> int:
        return len(self.updated)


def write_parquet_atomically(
    con: duckdb.DuckDBPyConnection, select_sql: str, destination: Path
) -> None:
    """Write a relation to Parquet via a temp file and an atomic rename.

    A partition half-written by a crash would be a partition of findings that
    silently vanished.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix(".parquet.tmp")
    con.execute(f"COPY ({select_sql}) TO '{sql_path(pending)}' (FORMAT PARQUET)")
    os.replace(pending, destination)


def update_findings(
    catalog: Catalog,
    finding_ids_by_partition: dict[str, list[str]],
    set_clause: str,
    params: list[Any],
    *,
    only_if_status: str | None = None,
) -> UpdateResult:
    """Apply `set_clause` to the named findings, partition by partition.

    `only_if_status` guards against overwriting a state that changed between
    the read and the write — a finding a human marked `false_positive` while
    a reconciliation sweep was deciding to close it, for instance.

    Each rewritten partition is consolidated to a single part file, so
    repeated updates cannot fragment the lake.
    """
    result = UpdateResult()
    projection = ", ".join(column_names("findings"))

    if not finding_ids_by_partition:
        return result

    with catalog.connect() as con:
        for dt, finding_ids in finding_ids_by_partition.items():
            files = catalog.partition_files("findings", dt)
            if not files or not finding_ids:
                continue

            pattern = sql_path(catalog.partition_dir("findings", dt) / "*.parquet")
            con.execute("DROP TABLE IF EXISTS part")
            con.execute(
                f"CREATE TEMP TABLE part AS "
                f"SELECT {projection} FROM read_parquet('{pattern}', union_by_name = 1)"
            )

            placeholders = ", ".join(["?"] * len(finding_ids))
            guard = " AND status = ?" if only_if_status else ""
            con.execute(
                f"UPDATE part SET {set_clause} "
                f"WHERE finding_id IN ({placeholders}){guard}",
                [*params, *finding_ids, *([only_if_status] if only_if_status else [])],
            )

            target = catalog.partition_dir("findings", dt) / "part-0000.parquet"
            write_parquet_atomically(con, f"SELECT {projection} FROM part", target)
            for stale in files:
                if stale != target:
                    stale.unlink(missing_ok=True)
            con.execute("DROP TABLE part")

            result.updated.extend(finding_ids)
            result.partitions_written += 1

        catalog.refresh_views(con)

    return result


def locate_findings(catalog: Catalog, finding_ids: list[str]) -> dict[str, list[str]]:
    """Group finding ids by the partition they live in."""
    if not finding_ids or not catalog.all_files("findings"):
        return {}

    placeholders = ", ".join(["?"] * len(finding_ids))
    rows = catalog.query(
        f"SELECT finding_id, dt FROM findings WHERE finding_id IN ({placeholders})",
        finding_ids,
    )
    grouped: dict[str, list[str]] = {}
    for finding_id, dt in rows:
        grouped.setdefault(str(dt), []).append(str(finding_id))
    return grouped
