"""Is the platform itself working — and can it tell the three ways it is not?"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from mykronos import platform_health

NOW = datetime(2026, 9, 3, 12, 0, 0)
HOURLY = 3_600


@dataclass
class Row:
    """Stands in for a `JobRun`, so these assertions need no database."""

    name: str = "absences"
    last_run_at: datetime | None = None
    last_succeeded_at: datetime | None = None
    consecutive_failures: int = 0
    last_error: str = ""
    interval_seconds: int = HOURLY


class TestTheQuietFailure:
    def test_a_job_that_keeps_failing_is_failing_not_ok(self) -> None:
        """The whole reason this exists.

        The runner catches every exception, logs it and retries — which is
        right, and means a job that has thrown on every run for a fortnight
        looks from outside exactly like one that has never had a problem.
        """
        health = platform_health.assess_job(
            Row(
                last_run_at=NOW,
                last_succeeded_at=NOW - timedelta(days=14),
                consecutive_failures=336,
                last_error="DuckDB: database is locked",
            ),
            now=NOW,
        )

        assert health.status == "failing"
        assert "336 consecutive failures" in health.detail
        assert "database is locked" in health.detail

    def test_a_fresh_last_run_does_not_rescue_a_failing_job(self) -> None:
        """`last_run_at` is fresh for ever on a job whose failures are caught.
        Reading only that would report a dead job as healthy, which is how
        this was invisible in the first place."""
        health = platform_health.assess_job(
            Row(last_run_at=NOW, last_succeeded_at=None, consecutive_failures=1),
            now=NOW,
        )

        assert health.status == "failing"


class TestThreeStatesKeptApart:
    def test_a_job_that_is_late_is_not_a_job_that_is_failing(self) -> None:
        """Different things to do about them: a failing job has an error to
        read, a late one has a scheduler to check."""
        health = platform_health.assess_job(
            Row(last_succeeded_at=NOW - timedelta(hours=9)), now=NOW
        )

        assert health.status == "late"
        assert "runs every 1 hour" in health.detail

    def test_a_job_that_never_ran_is_its_own_state(self) -> None:
        health = platform_health.assess_job(Row(), now=NOW)

        assert health.status == "never_ran"

    def test_a_recent_success_is_ok(self) -> None:
        health = platform_health.assess_job(
            Row(last_succeeded_at=NOW - timedelta(minutes=10)), now=NOW
        )

        assert health.status == "ok"


class TestNotCryingWolf:
    def test_ordinary_jitter_is_not_lateness(self) -> None:
        """A timer inside a process that also serves requests drifts. A health
        page that goes red on that is one people stop reading."""
        health = platform_health.assess_job(
            Row(last_succeeded_at=NOW - timedelta(seconds=HOURLY + 120)), now=NOW
        )

        assert health.status == "ok"

    def test_a_long_interval_job_is_not_late_right_after_a_deploy(self) -> None:
        """Without the start-up time a daily job reads as late for a day after
        every deploy — wrong exactly when somebody is most likely to look."""
        daily = Row(interval_seconds=86_400)
        health = platform_health.assess_job(
            daily, now=NOW, started_at=NOW - timedelta(minutes=5)
        )

        assert health.status == "ok"
        assert "not been due" in health.detail

    def test_but_it_is_late_once_the_interval_really_has_passed(self) -> None:
        daily = Row(interval_seconds=86_400)
        health = platform_health.assess_job(
            daily, now=NOW, started_at=NOW - timedelta(days=5)
        )

        assert health.status == "never_ran"


class TestDegraded:
    def test_failing_or_late_jobs_are_degraded(self) -> None:
        for status in ("failing", "late"):
            health = platform_health.PlatformHealth(
                jobs=[platform_health.JobHealth(name="x", status=status, detail="")]
            )
            assert health.degraded, status

    def test_an_unreachable_dependency_is_degraded(self) -> None:
        health = platform_health.PlatformHealth(
            dependencies=[
                platform_health.DependencyHealth(
                    name="vault", reachable=False, detail="sealed"
                )
            ]
        )

        assert health.degraded

    def test_a_job_that_has_not_been_due_yet_is_not_degraded(self) -> None:
        """Otherwise the first minutes after every deploy are red, which
        teaches people the red means nothing."""
        health = platform_health.PlatformHealth(
            jobs=[
                platform_health.JobHealth(name="x", status="never_ran", detail=""),
                platform_health.JobHealth(name="y", status="ok", detail=""),
            ]
        )

        assert not health.degraded

    def test_everything_healthy_is_not_degraded(self) -> None:
        health = platform_health.PlatformHealth(
            jobs=[platform_health.JobHealth(name="x", status="ok", detail="")],
            dependencies=[
                platform_health.DependencyHealth(name="vault", reachable=True, detail="")
            ],
        )

        assert not health.degraded
