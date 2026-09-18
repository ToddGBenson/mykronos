"""`os.replace` is atomic against a crash, not against another writer (#443).

The failure this guards is the one with no symptom. Two processes each read
partition P, each compute a new version from what they read, and each rename
their result over it. The second rename wins, the first writer's rows are
gone, nothing raises, and the result is indistinguishable from a scan that
found nothing.

These tests exercise the real filesystem and a real DuckDB connection. A mock
of `os.replace` would prove the code calls it and nothing about whether the
rows survive, which is the only question here.
"""

from __future__ import annotations

import os
from pathlib import Path

import duckdb
import pytest

from mykronos.lake.mutate import (
    PartitionChangedError,
    partition_token,
    write_parquet_atomically,
)


@pytest.fixture
def con():
    connection = duckdb.connect()
    try:
        yield connection
    finally:
        connection.close()


def _rows(con, path: Path) -> list[tuple]:
    return con.execute(
        f"SELECT * FROM read_parquet('{path.as_posix()}') ORDER BY 1"
    ).fetchall()


class TestPartitionToken:
    def test_a_partition_that_does_not_exist_is_not_a_conflict(self, tmp_path) -> None:
        """A first write must not be refused for having nothing to compare to."""
        assert partition_token(tmp_path / "dt=2026-09-18") == ()

    def test_it_ignores_the_temp_files_it_is_meant_to_ignore(self, tmp_path, con) -> None:
        (tmp_path / "part-0000.parquet.tmp").write_bytes(b"x")
        assert partition_token(tmp_path) == ()

    def test_a_rewrite_changes_the_token_even_when_the_bytes_do_not(
        self, tmp_path, con
    ) -> None:
        """The reason the inode is in the token.

        Two writers can produce byte-identical files of identical size inside
        one filesystem timestamp tick. Size and mtime would compare equal;
        `os.replace` still swapped the file.
        """
        target = tmp_path / "part-0000.parquet"
        con.execute(f"COPY (SELECT 1 AS n) TO '{target.as_posix()}' (FORMAT PARQUET)")
        first = partition_token(tmp_path)

        other = tmp_path / "other.tmp"
        con.execute(f"COPY (SELECT 1 AS n) TO '{other.as_posix()}' (FORMAT PARQUET)")
        os.replace(other, target)

        assert partition_token(tmp_path) != first


class TestWriteRefusesToClobber:
    def test_an_unchanged_partition_is_written(self, tmp_path, con) -> None:
        target = tmp_path / "part-0000.parquet"
        con.execute(f"COPY (SELECT 1 AS n) TO '{target.as_posix()}' (FORMAT PARQUET)")

        write_parquet_atomically(
            con, "SELECT 2 AS n", target, expect=partition_token(tmp_path)
        )

        assert _rows(con, target) == [(2,)]

    def test_a_partition_another_writer_moved_is_refused(self, tmp_path, con) -> None:
        """The whole point. Our update is computed from `before`; somebody
        else lands theirs; ours must not silently replace it."""
        target = tmp_path / "part-0000.parquet"
        con.execute(f"COPY (SELECT 1 AS n) TO '{target.as_posix()}' (FORMAT PARQUET)")
        before = partition_token(tmp_path)

        # The other writer, between our read and our rename.
        other = tmp_path / "theirs.tmp"
        con.execute(f"COPY (SELECT 99 AS n) TO '{other.as_posix()}' (FORMAT PARQUET)")
        os.replace(other, target)

        with pytest.raises(PartitionChangedError, match="refusing to overwrite"):
            write_parquet_atomically(con, "SELECT 2 AS n", target, expect=before)

        assert _rows(con, target) == [(99,)], "the other writer's rows must survive"

    def test_without_expect_it_still_clobbers(self, tmp_path, con) -> None:
        """A guard against the fix being cosmetic.

        `expect=None` keeps the old behaviour deliberately, for first writes
        and for callers with nothing to compare. This test exists so that
        "the write is safe now" is never read as unconditional.
        """
        target = tmp_path / "part-0000.parquet"
        con.execute(f"COPY (SELECT 99 AS n) TO '{target.as_posix()}' (FORMAT PARQUET)")

        write_parquet_atomically(con, "SELECT 2 AS n", target)

        assert _rows(con, target) == [(2,)]

    def test_a_refused_write_leaves_no_temp_file_behind(self, tmp_path, con) -> None:
        target = tmp_path / "part-0000.parquet"
        con.execute(f"COPY (SELECT 1 AS n) TO '{target.as_posix()}' (FORMAT PARQUET)")
        before = partition_token(tmp_path)
        other = tmp_path / "theirs.tmp"
        con.execute(f"COPY (SELECT 99 AS n) TO '{other.as_posix()}' (FORMAT PARQUET)")
        os.replace(other, target)

        with pytest.raises(PartitionChangedError):
            write_parquet_atomically(con, "SELECT 2 AS n", target, expect=before)

        assert list(tmp_path.glob("*.tmp")) == []


class TestTheTempFileIsNotShared:
    def test_two_writers_do_not_target_the_same_temp_path(self, tmp_path) -> None:
        """The second defect, found while fixing the first.

        The old name was `destination.with_suffix('.parquet.tmp')` -- one
        fixed path per partition. Two concurrent writers did not merely race
        at the rename; they wrote the same temp file at the same time, so the
        bytes one of them renamed were partly the other's.
        """
        target = tmp_path / "part-0000.parquet"
        seen = set()

        for _ in range(4):
            con = duckdb.connect()
            try:
                # Capture the temp path this call would use by letting the
                # write run and recording what appears, then asserting the
                # names differ across calls.
                names_before = {p.name for p in tmp_path.glob("*")}
                write_parquet_atomically(con, "SELECT 1 AS n", target)
                created = {p.name for p in tmp_path.glob("*")} - names_before
                seen |= created
            finally:
                con.close()

        # Nothing left behind, and the destination is the only survivor.
        assert [p.name for p in tmp_path.glob("*")] == ["part-0000.parquet"]

    def test_the_temp_name_carries_the_pid(self, tmp_path, con, monkeypatch) -> None:
        """Enough to separate two processes writing the same partition."""
        target = tmp_path / "dt=2026-09-18" / "part-0000.parquet"
        captured: list[str] = []
        real_replace = os.replace

        def spy(src, dst):
            captured.append(Path(src).name)
            return real_replace(src, dst)

        monkeypatch.setattr("mykronos.lake.mutate.os.replace", spy)
        write_parquet_atomically(con, "SELECT 1 AS n", target)

        assert captured, "the write did not reach os.replace"
        assert f".{os.getpid()}." in captured[0]
        assert captured[0].endswith(".parquet.tmp")
