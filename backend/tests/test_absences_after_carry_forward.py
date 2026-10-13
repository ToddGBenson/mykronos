"""Absence never closes what carry-forward would link (TheHub #60734).

The production shape on 2026-10-13: #795 re-keyed every PowerShell finding,
ingestion gave each new row its predecessor's first sighting, and the old
prefixed rows stayed `open` because the hourly carry-forward had last run
before any new-uploader scan. Two such scans later they were two scans absent,
and the absence job -- on its own timer, three seconds behind carry-forward's
-- would have closed 38 of them as `fixed`.
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

import mykronos.main as app_main
from mykronos.lake import Catalog, reconcile_absences
from mykronos.lake.maintenance import (
    LANE_CLOSURE_LOCK,
    carry_forward_exclusively,
    reconcile_after_linking,
)
from tests.conftest import REPO, issue_token
from tests.test_concourse_build_paths import (
    SCRIPT,
    STORED_PATH,
    _as_stored,
    _checkout,
    _from_adapter,
    _rows,
    _scan,
)


def _production_shape(
    client: TestClient, catalog: Catalog, run_compaction: Callable[[], Any], tmp_path: Path
) -> None:
    """An old prefixed row, then two new-uploader scans, and no carry-forward."""
    token = issue_token(client, REPO, "sast")
    _scan(client, token, _as_stored())
    run_compaction()
    for _ in range(2):
        _scan(client, token, _from_adapter(_checkout(tmp_path)))
        run_compaction()

    rows = _rows(catalog)
    assert rows[STORED_PATH]["status"] == "open", "the old row is still open, as in production"
    assert rows[SCRIPT]["first_seen_at"] == rows[STORED_PATH]["first_seen_at"]


def test_absence_alone_closes_the_old_row_as_fixed(
    client: TestClient, catalog: Catalog, run_compaction: Callable[[], Any], tmp_path: Path
) -> None:
    """The defect: what the absence job did before this change."""
    _production_shape(client, catalog, run_compaction, tmp_path)

    assert reconcile_absences(catalog).total_fixed == 1
    assert _rows(catalog)[STORED_PATH]["status"] == "fixed"


def test_the_absence_job_links_first_and_closes_nothing(
    client: TestClient, catalog: Catalog, run_compaction: Callable[[], Any], tmp_path: Path
) -> None:
    _production_shape(client, catalog, run_compaction, tmp_path)

    result = reconcile_after_linking(catalog)

    assert result.closed.total_fixed == 0
    assert [c.exact for c in result.carried.carried] == [True]
    rows = _rows(catalog)
    assert rows[STORED_PATH]["status"] == "superseded"
    assert rows[STORED_PATH]["superseded_by"] == rows[SCRIPT]["finding_id"]
    assert not [r for r in rows.values() if r["status"] == "fixed"]


def test_the_scheduled_jobs_are_the_locked_ones() -> None:
    """Both timers in `main.py` go through `lake/maintenance.py`. A job wired
    straight to `reconcile_absences` again would restore the race."""
    source = inspect.getsource(app_main)
    absences = source[
        source.index("async def _absences") : source.index("async def _carry_forward")
    ]
    carry = source[source.index("async def _carry_forward") : source.index("async def _portfolio")]
    assert "reconcile_after_linking" in absences
    assert "reconcile_absences" not in absences
    assert "carry_forward_exclusively" in carry


def test_the_two_never_overlap(catalog: Catalog) -> None:
    """While one holds the lock the other waits, whichever starts first."""
    finished = threading.Event()

    def run() -> None:
        carry_forward_exclusively(catalog)
        reconcile_after_linking(catalog)
        finished.set()

    with LANE_CLOSURE_LOCK:
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        assert not finished.wait(0.3), "a pass ran while the lock was held"
    worker.join(timeout=10)
    assert finished.is_set()
