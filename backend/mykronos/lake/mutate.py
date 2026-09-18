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
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import duckdb

from mykronos.lake.catalog import Catalog, sql_path
from mykronos.lake.tables import TABLES, add_missing_columns, column_names

logger = logging.getLogger(__name__)


@dataclass
class UpdateResult:
    updated: list[str] = field(default_factory=list)
    partitions_written: int = 0

    @property
    def count(self) -> int:
        return len(self.updated)


class PartitionChangedError(RuntimeError):
    """Another writer rewrote this partition while we were computing ours.

    Raised instead of completing a write that would discard the other
    writer's rows. Retrying the whole read-modify-write is the correct
    response: the second attempt reads what the first writer left.
    """


def partition_token(directory: Path) -> tuple[tuple[str, int, int, int], ...]:
    """Cheap identity of a partition's contents, for compare-and-swap.

    `(name, inode, mtime_ns, size)` per part file. The inode is the load-
    bearing one: `os.replace` renames a new file over the destination, so the
    destination's inode changes even when a rewrite happens inside one
    filesystem timestamp tick and produces a byte-identical size.

    A partition that does not exist yet is the empty tuple, which compares
    equal to itself — a first write is not a conflict.
    """
    entries = []
    for f in sorted(directory.glob("*.parquet")):
        try:
            st = f.stat()
        except FileNotFoundError:
            # Vanished between the glob and the stat, which is itself a
            # concurrent writer. Leaving it out makes the token differ from
            # whatever was captured before, which is the answer we want.
            continue
        entries.append((f.name, st.st_ino, st.st_mtime_ns, st.st_size))
    return tuple(entries)


def write_parquet_atomically(
    con: duckdb.DuckDBPyConnection,
    select_sql: str,
    destination: Path,
    *,
    expect: tuple[tuple[str, int, int, int], ...] | None = None,
) -> None:
    """Write a relation to Parquet via a temp file and an atomic rename.

    A partition half-written by a crash would be a partition of findings that
    silently vanished.

    **`os.replace` is atomic against a crash and not against another writer**
    (#443). It is a rename, not a compare-and-swap. Two processes that each
    read partition P, each compute a new version from what they read, and each
    rename their result produce last-writer-wins: the first writer's rows are
    gone, no error is raised, and the outcome is indistinguishable from a scan
    that found nothing. DuckDB's transaction covers the view definition
    refreshed afterwards, not the Parquet file swapped underneath it.

    `expect` closes that. Pass `partition_token(dir)` captured BEFORE the read,
    and the rename is refused if the partition moved in between.

    What this is honestly worth: the window shrinks from the whole
    read-modify-write — a DuckDB scan plus an UPDATE, easily seconds — to the
    microseconds between the final stat and the rename. It is not a lock and
    does not claim to be. #443 asks first for detection, and a conflict that
    raises is a conflict somebody can retry; a lost update is not.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Unique per process and per call. The old name was
    # `destination.with_suffix('.parquet.tmp')`, one fixed path per partition,
    # so two concurrent writers did not merely race at the rename -- they wrote
    # the same temp file at the same time. Found while fixing the rename.
    pending = destination.with_name(
        f"{destination.stem}.{os.getpid()}.{uuid4().hex}.parquet.tmp"
    )
    try:
        con.execute(f"COPY ({select_sql}) TO '{sql_path(pending)}' (FORMAT PARQUET)")

        if expect is not None:
            current = partition_token(destination.parent)
            if current != expect:
                raise PartitionChangedError(
                    f"{destination.parent.name} changed while it was being "
                    f"rewritten; refusing to overwrite another writer's rows. "
                    f"Retry the read-modify-write."
                )

        os.replace(pending, destination)
    except BaseException:
        with suppress(OSError):
            pending.unlink()
        raise


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

            # Captured BEFORE the read, so it describes the partition this
            # update is computed from. See write_parquet_atomically (#443).
            before = partition_token(catalog.partition_dir("findings", dt))

            pattern = sql_path(catalog.partition_dir("findings", dt) / "*.parquet")
            con.execute("DROP TABLE IF EXISTS part")
            con.execute(
                f"CREATE TEMP TABLE part AS "
                f"SELECT * FROM read_parquet('{pattern}', union_by_name = 1)"
            )
            # A column added to the schema after this partition was written is
            # absent from every file in it, and `union_by_name` cannot invent
            # one no file has. Fill it with NULL, which is what a row written
            # before the column existed truthfully holds.
            add_missing_columns(con, "part", "findings")

            placeholders = ", ".join(["?"] * len(finding_ids))
            guard = " AND status = ?" if only_if_status else ""
            con.execute(
                f"UPDATE part SET {set_clause} "
                f"WHERE finding_id IN ({placeholders}){guard}",
                [*params, *finding_ids, *([only_if_status] if only_if_status else [])],
            )

            target = catalog.partition_dir("findings", dt) / "part-0000.parquet"
            write_parquet_atomically(
                con, f"SELECT {projection} FROM part", target, expect=before
            )
            for stale in files:
                if stale != target:
                    stale.unlink(missing_ok=True)
            con.execute("DROP TABLE part")

            result.updated.extend(finding_ids)
            result.partitions_written += 1

        catalog.refresh_views(con)

    return result


def purge_rows(
    catalog: Catalog, table: str, where: str, params: list[Any]
) -> tuple[int, int]:
    """Delete rows matching `where`, rewriting each affected partition.

    Real deletion, not a tombstone column. This exists for spec 06 §9's
    retention rule, and a "deleted" flag on a row that is still in the file
    would not honour a deletion request — it would just stop the dashboard
    from showing what the system still holds.

    A partition emptied entirely has its directory removed, so an expired day
    leaves nothing behind rather than an empty Parquet file that still
    announces the date somebody was assessed.

    Returns (rows_deleted, partitions_rewritten).
    """
    if table not in TABLES:
        raise ValueError(f"Unknown table {table!r}.")

    projection = ", ".join(column_names(table))
    deleted = 0
    rewritten = 0

    with catalog.connect() as con:
        for directory in sorted(catalog.table_dir(table).glob("dt=*")):
            files = sorted(directory.glob("*.parquet"))
            if not files:
                continue
            # Captured BEFORE the read. `before` is already a row count in this
            # function, hence the longer name. See write_parquet_atomically.
            token_before = partition_token(directory)
            pattern = sql_path(directory / "*.parquet")

            con.execute("DROP TABLE IF EXISTS part")
            con.execute(
                f"CREATE TEMP TABLE part AS "
                f"SELECT * FROM read_parquet('{pattern}', union_by_name = 1)"
            )
            # A column added to the schema after this partition was written is
            # absent from every file in it, and `union_by_name` cannot invent
            # one no file has. Fill it with NULL, which is what a row written
            # before the column existed truthfully holds.
            add_missing_columns(con, "part", table)
            before = con.execute("SELECT count(*) FROM part").fetchone()
            con.execute(f"DELETE FROM part WHERE {where}", params)
            after = con.execute("SELECT count(*) FROM part").fetchone()

            removed = int(before[0]) - int(after[0]) if before and after else 0
            if removed == 0:
                con.execute("DROP TABLE part")
                continue

            deleted += removed
            rewritten += 1
            remaining = int(after[0]) if after else 0

            if remaining == 0:
                for stale in files:
                    stale.unlink(missing_ok=True)
                with suppress(OSError):
                    directory.rmdir()
            else:
                target = directory / "part-0000.parquet"
                write_parquet_atomically(
                    con, f"SELECT {projection} FROM part", target, expect=token_before
                )
                for stale in files:
                    if stale != target:
                        stale.unlink(missing_ok=True)
            con.execute("DROP TABLE part")

        catalog.refresh_views(con)

    return deleted, rewritten


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
