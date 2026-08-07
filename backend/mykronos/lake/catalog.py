"""DuckDB catalog over the Parquet partitions (spec 05 §8).

Exposes one view per table, always defined even when the lake is empty, so
callers never have to special-case a fresh install.

Read/write asymmetry is deliberate: `connect_readonly()` is what the dashboard
and Oracle use, and it physically cannot write to the partitions (spec 05 §9).
Compaction takes the writable connection.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import duckdb

from mykronos.lake.tables import TABLES, empty_select


def sql_path(path: Path) -> str:
    """Render a path as a DuckDB string literal.

    Forward slashes work on every platform DuckDB supports, including Windows;
    single quotes are doubled so a path can never terminate the literal early.
    """
    return path.as_posix().replace("'", "''")


class Catalog:
    """Owns the lake directory layout and the DuckDB views over it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.catalog_path = root / "_manifest.duckdb"

    # -- layout ---------------------------------------------------------

    def table_dir(self, table: str) -> Path:
        return self.root / table

    def partition_dir(self, table: str, dt: str) -> Path:
        return self.table_dir(table) / f"dt={dt}"

    def partition_files(self, table: str, dt: str) -> list[Path]:
        directory = self.partition_dir(table, dt)
        if not directory.is_dir():
            return []
        return sorted(directory.glob("*.parquet"))

    def all_files(self, table: str) -> list[Path]:
        directory = self.table_dir(table)
        if not directory.is_dir():
            return []
        return sorted(directory.glob("dt=*/*.parquet"))

    def next_part_index(self, table: str, dt: str) -> int:
        existing = self.partition_files(table, dt)
        return len(existing)

    def initialise(self) -> None:
        """Create the directory skeleton. Safe to call repeatedly."""
        for table in TABLES:
            self.table_dir(table).mkdir(parents=True, exist_ok=True)
        (self.root / "_buffer").mkdir(parents=True, exist_ok=True)
        (self.root / "raw").mkdir(parents=True, exist_ok=True)
        with self.connect() as con:
            self.refresh_views(con)

    # -- connections ----------------------------------------------------

    @contextmanager
    def connect(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """Writable connection. Compaction only."""
        self.root.mkdir(parents=True, exist_ok=True)
        con = duckdb.connect(str(self.catalog_path))
        try:
            self.refresh_views(con)
            yield con
        finally:
            con.close()

    @contextmanager
    def connect_readonly(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """Read-only connection for the dashboard and Oracle.

        Uses an in-memory database with views pointed at the Parquet files
        rather than opening `_manifest.duckdb` read-only, so a reader never
        blocks or is blocked by a concurrent compaction holding the catalog.
        """
        con = duckdb.connect(":memory:")
        try:
            self.refresh_views(con)
            yield con
        finally:
            con.close()

    # -- views ----------------------------------------------------------

    def refresh_views(self, con: duckdb.DuckDBPyConnection) -> None:
        """(Re)define one view per table against whatever Parquet exists now."""
        for table in TABLES:
            files = self.all_files(table)
            if files:
                pattern = sql_path(self.table_dir(table) / "dt=*" / "*.parquet")
                body = (
                    f"SELECT * FROM read_parquet('{pattern}', "
                    "hive_partitioning = 1, union_by_name = 1)"
                )
            else:
                body = empty_select(table)
            con.execute(f"CREATE OR REPLACE VIEW {table} AS {body}")

    # -- convenience ----------------------------------------------------

    def query(self, sql: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        with self.connect_readonly() as con:
            return con.execute(sql, params or []).fetchall()

    def count(self, table: str) -> int:
        with self.connect_readonly() as con:
            row = con.execute(f"SELECT count(*) FROM {table}").fetchone()
        return int(row[0]) if row else 0
