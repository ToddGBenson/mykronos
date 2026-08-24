"""A column added to the schema is queryable before any partition is rewritten.

`add_missing_columns` has always fixed this for the temp table compaction
builds. The *read* path had no equivalent, so a partition written before a
column existed made every query naming that column fail with

    Binder Error: Referenced column "due_at" not found in FROM clause!

which points at the column rather than at the cause. It took the portfolio
endpoint — the dashboard's landing page — to a 500 in production on
2026-08-23, the first deploy after spec 24 added `due_at`.

The lazy-upgrade design is right and unchanged: partitions are still rewritten
as compaction touches them. What changed is that reads no longer wait for it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb
import pytest

from mykronos.lake.catalog import Catalog
from mykronos.lake.tables import TABLES


def write_legacy_partition(catalog: Catalog, table: str, omit: tuple[str, ...]) -> None:
    """Write a partition whose schema predates `omit` — a real old file."""
    columns = [(name, kind) for name, kind in TABLES[table] if name not in omit]
    projection = ", ".join(f"CAST(NULL AS {kind}) AS {name}" for name, kind in columns)
    directory = catalog.table_dir(table) / "dt=2026-01-01"
    directory.mkdir(parents=True, exist_ok=True)
    target = (directory / "legacy.parquet").as_posix()
    con = duckdb.connect()
    try:
        con.execute(f"COPY (SELECT {projection}) TO '{target}' (FORMAT PARQUET)")
    finally:
        con.close()


@pytest.fixture
def catalog(tmp_path: Path) -> Catalog:
    return Catalog(tmp_path / "lake")


class TestAColumnTheFilesDoNotHave:
    def test_it_is_queryable(self, catalog: Catalog) -> None:
        write_legacy_partition(catalog, "findings", omit=("due_at", "due_source"))

        rows = catalog.query("SELECT due_at, due_source FROM findings")

        assert rows == [(None, None)]

    def test_a_filter_on_it_does_not_raise(self, catalog: Catalog) -> None:
        """The portfolio's own shape: count(*) FILTER (WHERE due_at <= ?)."""
        write_legacy_partition(catalog, "findings", omit=("due_at",))

        rows = catalog.query(
            "SELECT count(*) FILTER (WHERE due_at IS NOT NULL) FROM findings"
        )

        assert rows == [(0,)]

    def test_the_rows_that_exist_are_still_returned(self, catalog: Catalog) -> None:
        """The union must not swallow real data — the zero-row side is
        `WHERE 1=0` and contributes nothing."""
        write_legacy_partition(catalog, "findings", omit=("due_at",))

        assert catalog.count("findings") == 1

    def test_every_declared_column_is_present(self, catalog: Catalog) -> None:
        """Not just the one that broke: any column added from here on."""
        write_legacy_partition(
            catalog, "findings", omit=("due_at", "due_source", "owner", "owner_source")
        )
        declared = [name for name, _ in TABLES["findings"]]

        rows = catalog.query(f"SELECT {', '.join(declared)} FROM findings")

        assert len(rows[0]) == len(declared)

    @pytest.mark.parametrize("table", sorted(TABLES))
    def test_it_holds_for_every_table(self, catalog: Catalog, table: str) -> None:
        """The next column will not be on `findings`."""
        last = TABLES[table][-1][0]
        write_legacy_partition(catalog, table, omit=(last,))

        assert catalog.query(f"SELECT {last} FROM {table}") == [(None,)]


class TestAnEmptyLake:
    def test_still_reports_the_declared_shape(self, catalog: Catalog) -> None:
        rows: list[Any] = catalog.query("SELECT due_at FROM findings")
        assert rows == []
