"""Write-ahead buffer (spec 05 §2).

A 200 from the Ingestion API is a durability guarantee, not an in-memory ack
(spec 05 §4), but writing one Parquet file per request would shred the lake
into thousands of tiny files. So each request lands as a fsync'd JSONL
segment and a periodic compaction job folds segments into Parquet.

Concurrency approach: **one segment file per request**, written to a `.tmp`
name and then atomically renamed into place. Readers only ever see complete
segments, writers never contend on a shared handle, and a crash mid-write
leaves an orphan `.tmp` that is ignored and swept later. No locking.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SEGMENT_SUFFIX = ".jsonl"
PENDING_SUFFIX = ".tmp"


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Not JSON-serialisable: {type(value).__name__}")


class WriteAheadBuffer:
    """Durable append-only staging area between the API and Parquet."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def table_dir(self, table: str) -> Path:
        return self.root / table

    def append(self, table: str, rows: Sequence[dict[str, Any]]) -> Path | None:
        """Persist `rows` as one sealed segment. Returns its path.

        Returns None for an empty batch — a scan that found nothing still
        registers its ScanRun (spec 04 §6), but there is no findings segment
        to write, and an empty file would only cost a compaction read.

        The fsync before rename is what makes the caller's subsequent 200
        honest: the bytes are on the platter, not in the page cache.
        """
        if not rows:
            return None

        directory = self.table_dir(table)
        directory.mkdir(parents=True, exist_ok=True)

        # Lexically sortable name: compaction consumes segments in write order,
        # which keeps last-write-wins deterministic for same-key rows.
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
        base = f"{stamp}-{uuid.uuid4().hex[:12]}"
        pending = directory / f"{base}{PENDING_SUFFIX}"
        sealed = directory / f"{base}{SEGMENT_SUFFIX}"

        with pending.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, default=_json_default, ensure_ascii=False))
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(pending, sealed)
        _fsync_dir(directory)
        return sealed

    def sealed_segments(self, table: str) -> list[Path]:
        directory = self.table_dir(table)
        if not directory.is_dir():
            return []
        return sorted(directory.glob(f"*{SEGMENT_SUFFIX}"))

    def count_sealed(self) -> int:
        if not self.root.is_dir():
            return 0
        return sum(1 for _ in self.root.glob(f"*/*{SEGMENT_SUFFIX}"))

    @staticmethod
    def read_segment(path: Path) -> list[dict[str, Any]]:
        """Read one segment, skipping unparseable lines.

        A truncated trailing line means the process died mid-write on a
        filesystem that reordered the fsync; the rest of the segment is still
        good data and dropping it would violate "no component silently drops
        data" far more seriously than dropping one torn record.
        """
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows

    @staticmethod
    def consume(paths: Iterable[Path]) -> None:
        """Delete segments *after* their Parquet write is confirmed.

        Ordering matters (spec 05 §10): the buffer is the source of truth until
        compaction succeeds. A crash between the Parquet write and this call
        replays those rows, which the upsert makes idempotent.
        """
        for path in paths:
            path.unlink(missing_ok=True)


def _fsync_dir(directory: Path) -> None:
    """Durably record the rename. No-op on Windows, which cannot fsync a
    directory handle and does not require it for rename durability."""
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
