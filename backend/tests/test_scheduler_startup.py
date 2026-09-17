"""Does a scheduled job ever actually run, and does a retried one say so? (#409)

THE DEFECT THIS PINS. `_every` slept for a whole interval before its first
call, so a job did nothing for the first `interval` of a container's life. For
an hourly job that is a detail. For a daily one on a container redeployed
several times a day it is fatal: every restart resets the clock, so a job whose
interval exceeds the mean uptime converges on never running at all.

Measured 2026-09-16 on the running platform: fifteen hours of uptime, and the
`last_run_at` of every daily job was from the *previous* container. Six jobs
are on 86400s and one of them is `rotation`, the ingestion-token sweep.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from mykronos.main import (
    _STARTUP_SPREAD_SECONDS,
    _every,
    run_acceptance_sweep,
)


async def _no_sleep(seconds: float) -> None:
    """The backoff, without the wall clock."""
    return None


@pytest.mark.asyncio
class TestTheFirstRun:
    async def test_a_daily_job_runs_without_waiting_a_day(self, monkeypatch) -> None:
        """The whole issue. A job on a 24-hour interval must not need the
        container to survive 24 hours before it does anything."""
        slept: list[float] = []
        calls = 0

        async def fake_sleep(seconds: float) -> None:
            slept.append(seconds)
            # Let the first interval-length sleep end the test rather than
            # actually waiting a day.
            if seconds >= 86_400:
                raise asyncio.CancelledError

        async def run() -> None:
            nonlocal calls
            calls += 1

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        with pytest.raises(asyncio.CancelledError):
            await _every("acceptances", 86_400, run)

        assert calls == 1, "the job must run before its first full interval"
        assert slept[0] < _STARTUP_SPREAD_SECONDS + 1
        assert slept[-1] == 86_400, "and then settle onto its interval"

    async def test_the_first_run_is_jittered(self, monkeypatch) -> None:
        """Twelve jobs firing in the same second on boot is its own outage —
        several rewrite the same `findings` partitions, and that collision is
        what took the acceptance sweep down for three days."""
        offsets: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            offsets.append(seconds)
            raise asyncio.CancelledError

        async def run() -> None:  # pragma: no cover - never reached
            raise AssertionError("should not run before the startup delay")

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        for _ in range(12):
            with pytest.raises(asyncio.CancelledError):
                await _every("job", 3_600, run)

        assert all(0 <= o <= _STARTUP_SPREAD_SECONDS for o in offsets)
        assert len(set(offsets)) > 1, "a fixed delay is not jitter"

    async def test_a_failing_job_still_reaches_its_next_tick(self, monkeypatch) -> None:
        """Unchanged behaviour, asserted because the loop was restructured: a
        job that dies on its first bad day and never runs again is a worse
        failure than the one that killed it."""
        calls = 0

        async def fake_sleep(seconds: float) -> None:
            if seconds >= 3_600 and calls >= 2:
                raise asyncio.CancelledError

        async def run() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("bad day")

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)

        with pytest.raises(asyncio.CancelledError):
            await _every("job", 3_600, run)

        assert calls >= 2, "a failure must not end the loop"


#: The exact text DuckDB produced on the failing run, from `job_runs.last_error`
#: on the operational database.
CONFLICT = (
    'TransactionContext Error: Catalog write-write conflict on alter with '
    '"Schema\\0main\\0main\\0View\\0main\\0findings"'
)


@pytest.mark.asyncio
class TestTheAcceptanceRetry:
    """The other half of #409: the sweep collides with the jobs that share its
    partitions, and one collision costs a daily job a whole day."""

    async def test_a_retry_is_visible_to_whoever_reads_the_logs(
        self, monkeypatch, caplog
    ) -> None:
        """THE DEFECT THIS PINS. A conflict that is retried away leaves no
        trace anywhere else: `_record_run` clears `last_error` and returns
        `consecutive_failures` to 0 on the eventual success, so `job_runs` says
        the sweep was fine. This line is the only evidence it happened, and at
        INFO it was not evidence either — the deployed logger sits at WARNING
        (measured on the running container, effective level 30).

        #409 is three days of the platform not saying a control had stopped. A
        sweep silently retrying twice every day is the same fact arriving the
        same way.
        """
        attempts = 0

        def sweep(catalog):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError(CONFLICT)
            return "swept"

        monkeypatch.setattr("mykronos.main.sweep_acceptances", sweep)
        monkeypatch.setattr(asyncio, "sleep", _no_sleep)

        with caplog.at_level(logging.DEBUG, logger="mykronos.main"):
            assert await run_acceptance_sweep(object()) == "swept"

        retries = [r for r in caplog.records if "write conflict" in r.getMessage()]
        assert retries, "a retried conflict must be logged at all"
        assert retries[0].levelno >= logging.WARNING, (
            "below WARNING the deployed platform does not print it, so a "
            "collision that is retried away is invisible everywhere"
        )

    async def test_a_conflict_is_retried_rather_than_costing_a_day(
        self, monkeypatch
    ) -> None:
        """Regression guard. The sweep is daily, so one lost attempt is one
        lost day — which is what left two acceptances live whose premise a scan
        had already contradicted."""
        attempts = 0

        def sweep(catalog):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise RuntimeError(CONFLICT)
            return "swept"

        monkeypatch.setattr("mykronos.main.sweep_acceptances", sweep)
        monkeypatch.setattr(asyncio, "sleep", _no_sleep)

        assert await run_acceptance_sweep(object()) == "swept"
        assert attempts == 3

    async def test_something_that_is_not_a_conflict_raises_at_once(
        self, monkeypatch
    ) -> None:
        """Regression guard. A retry loop wide enough to swallow a real bug
        would be worse than the bug: it would turn a broken sweep into three
        broken sweeps and one log line."""
        attempts = 0

        def sweep(catalog):
            nonlocal attempts
            attempts += 1
            raise ValueError("findings partition is unreadable")

        monkeypatch.setattr("mykronos.main.sweep_acceptances", sweep)
        monkeypatch.setattr(asyncio, "sleep", _no_sleep)

        with pytest.raises(ValueError):
            await run_acceptance_sweep(object())
        assert attempts == 1, "only a conflict is retryable"

    async def test_a_conflict_every_time_still_reaches_job_runs(
        self, monkeypatch
    ) -> None:
        """Regression guard. Giving up has to raise, because `_every` is what
        writes the failure to `job_runs` — swallowing it would restore exactly
        the silence #409 is about."""
        attempts = 0

        def sweep(catalog):
            nonlocal attempts
            attempts += 1
            raise RuntimeError(CONFLICT)

        monkeypatch.setattr("mykronos.main.sweep_acceptances", sweep)
        monkeypatch.setattr(asyncio, "sleep", _no_sleep)

        with pytest.raises(RuntimeError):
            await run_acceptance_sweep(object())
        assert attempts == 3
