"""The time-travel canary (TheHub #61109): proof that the clock moved.

The nightly `time-travel` job runs the unit suite under libfaketime. If the
preload has no effect -- a new Debian package moves the library, a wheel reads
the time without libc, an edit drops the wrapper -- the suite runs on the real
clock, goes green, and the job reports "no time bombs" every night. These
tests are the job's first step, under the same `under_faketime` wrapper as the
suite, and the job stops with a CANARY error when any of them fails.

They run only when the job sets TIME_TRAVEL_REAL_NOW, the epoch read on the
real clock just before. They then assert that the time is at least that plus
the offset (less an hour), as read by:

- Python's time.time() and datetime.now(), in the main pytest process (the
  job runs this file with `-n 0`) and in an xdist worker (`-n 2`), so LD_PRELOAD
  is proven to reach execnet's workers;
- DuckDB's now(), which reads the clock in C++ and not through Python.

TIME_TRAVEL_CANARY_IN_WORKER=1 or 0 says which of the two runs this is, and a
test asserts it, so a run in the wrong place cannot pass for the other.
"""

from __future__ import annotations

import os
import re
import time
from datetime import UTC, datetime

import pytest

REAL_NOW = os.environ.get("TIME_TRAVEL_REAL_NOW", "")
OFFSET = os.environ.get("TIME_TRAVEL_OFFSET", "")
# Set only by the job's two canary runs. When it is set, the canary must run:
# a skip is pytest exit 0, so an edit that dropped or moved the REAL_NOW
# export would otherwise make the canary pass on nothing.
ASKED = os.environ.get("TIME_TRAVEL_CANARY_IN_WORKER", "")

pytestmark = pytest.mark.skipif(
    not REAL_NOW and not ASKED,
    reason="the time-travel canary runs only inside the time-travel job",
)


@pytest.fixture(autouse=True)
def _the_real_epoch_was_given() -> None:
    assert REAL_NOW, (
        "TIME_TRAVEL_REAL_NOW is empty but the job asked for the canary "
        "(TIME_TRAVEL_CANARY_IN_WORKER is set): with no real epoch there is "
        "nothing to compare the clock against"
    )

# An hour short of the full offset still proves the move: an unshifted clock
# is days short, and the hour absorbs any rounding in how the offset is applied.
_SLACK_SECONDS = 3600


def _floor() -> float:
    match = re.fullmatch(r"\+(\d+)d", OFFSET)
    assert match, f"TIME_TRAVEL_OFFSET should read +<days>d, not {OFFSET!r}"
    return int(REAL_NOW) + int(match.group(1)) * 86400 - _SLACK_SECONDS


def _unshifted(what: str, seen: float) -> str:
    return (
        f"{what} reads {datetime.fromtimestamp(seen, UTC):%Y-%m-%dT%H:%MZ}, "
        f"not now{OFFSET}: the clock did not move, so the suite would run on the real clock"
    )


def test_python_reads_the_moved_clock() -> None:
    floor = _floor()
    assert time.time() >= floor, _unshifted("time.time()", time.time())
    stamp = datetime.now(UTC).timestamp()
    assert stamp >= floor, _unshifted("datetime.now()", stamp)


def test_duckdb_reads_the_moved_clock() -> None:
    import duckdb

    seen = duckdb.connect().execute("SELECT epoch(now())").fetchone()[0]
    assert seen >= _floor(), _unshifted("DuckDB now()", seen)


def test_it_ran_where_the_job_said() -> None:
    expected = os.environ.get("TIME_TRAVEL_CANARY_IN_WORKER")
    worker = os.environ.get("PYTEST_XDIST_WORKER")
    if expected == "1":
        assert worker, "asked for an xdist worker, ran in the main process"
    elif expected == "0":
        assert not worker, f"asked for the main process, ran in worker {worker}"
