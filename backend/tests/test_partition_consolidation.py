"""Appends do not fragment a partition without bound.

Compaction wrote a new part file per partition on every run that appended, and
only an update consolidated. `scan_runs` is nearly all appends, so the live
lake held 1,648 files for 8.3MB on 2026-10-08, and every query that touched
it opened all of them - about 200ms of each dashboard aggregate before any work.
"""

from __future__ import annotations

import pytest

from mykronos.lake.compaction import MAX_PARTITION_FILES, consolidate_fragmented
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan


@pytest.fixture
def auth(client) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}


def _partitions(catalog, table: str) -> dict[str, int]:
    return {
        d.name: len(list(d.glob("*.parquet")))
        for d in sorted(catalog.table_dir(table).glob("dt=*"))
    }


def test_repeated_appends_stay_under_the_limit_and_lose_nothing(
    client, auth, run_compaction, catalog
) -> None:
    runs = MAX_PARTITION_FILES * 3
    for i in range(runs):
        post_scan(client, auth, scan_run_id=f"scan-{i}", started_at="2026-10-08T09:00:00")
        post_findings(
            client, auth, [finding_payload(rule_id=f"R{i}", symbol=f"s{i}")],
            scan_run_id=f"scan-{i}",
        )
        run_compaction()

    assert all(n <= MAX_PARTITION_FILES for n in _partitions(catalog, "scan_runs").values())
    assert catalog.query("SELECT count(*), count(DISTINCT scan_run_id) FROM scan_runs")[0] == (
        runs,
        runs,
    )
    assert catalog.query("SELECT count(*) FROM findings")[0][0] == runs


def test_an_already_fragmented_partition_is_consolidated_without_changing_a_row(
    client, auth, run_compaction, catalog
) -> None:
    runs = MAX_PARTITION_FILES * 3
    for i in range(runs):
        post_scan(client, auth, scan_run_id=f"scan-{i}", started_at="2026-10-08T09:00:00")
        run_compaction()
    # Fragment it the way the old compaction did: one file per row.
    part_dir = next(catalog.table_dir("scan_runs").glob("dt=*"))
    with catalog.connect() as con:
        con.execute(
            f"CREATE TEMP TABLE all_rows AS SELECT * FROM read_parquet('{part_dir.as_posix()}/*.parquet')"
        )
        before = sorted(con.execute("SELECT * FROM all_rows ORDER BY scan_run_id").fetchall())
        for f in part_dir.glob("*.parquet"):
            f.unlink()
        for i, (sid,) in enumerate(con.execute("SELECT scan_run_id FROM all_rows").fetchall()):
            con.execute(
                f"COPY (SELECT * FROM all_rows WHERE scan_run_id = '{sid}') "
                f"TO '{(part_dir / f'part-{i:04d}.parquet').as_posix()}' (FORMAT PARQUET)"
            )
        assert len(list(part_dir.glob("*.parquet"))) == runs

        assert consolidate_fragmented(con, catalog, ["scan_runs"]) == 1
        assert [p.name for p in part_dir.glob("*.parquet")] == ["part-0000.parquet"]
        after = sorted(
            con.execute(
                f"SELECT * FROM read_parquet('{part_dir.as_posix()}/*.parquet') ORDER BY scan_run_id"
            ).fetchall()
        )
    assert after == before


def test_nothing_to_do_rewrites_nothing(client, auth, run_compaction, catalog) -> None:
    post_scan(client, auth, scan_run_id="only")
    run_compaction()
    part = next(catalog.table_dir("scan_runs").glob("dt=*/*.parquet"))
    mtime = part.stat().st_mtime_ns
    with catalog.connect() as con:
        assert consolidate_fragmented(con, catalog) == 0
    assert part.stat().st_mtime_ns == mtime
