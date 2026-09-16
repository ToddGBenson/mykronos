"""Does a scheduled job ever actually run? (#409)

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

import pytest

from mykronos.main import _STARTUP_SPREAD_SECONDS, _every


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
