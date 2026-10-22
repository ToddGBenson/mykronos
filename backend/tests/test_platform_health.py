"""Is the platform itself working — and can it tell the three ways it is not?"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest

from mykronos import jobs, platform_health

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
    scheduled: bool = True


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


class TestASwitchedOffJobIsNotLate:
    """`routing` was switched off on purpose on 2026-09-18, and its row kept
    reading "late, last succeeded 9 days ago" in every briefing after."""

    def test_an_unscheduled_job_is_disabled_not_late(self) -> None:
        health = platform_health.assess_job(
            Row(name="routing", last_succeeded_at=NOW - timedelta(days=9), scheduled=False),
            now=NOW,
        )

        assert health.status == "disabled"
        assert not platform_health.PlatformHealth(jobs=[health]).degraded

    def test_a_scheduled_job_that_old_is_still_late(self) -> None:
        health = platform_health.assess_job(
            Row(name="routing", last_succeeded_at=NOW - timedelta(days=9)), now=NOW
        )

        assert health.status == "late"

    def test_start_up_marks_what_this_deployment_runs(self, tmp_path) -> None:
        from sqlalchemy import select

        from mykronos.db import Database
        from mykronos.db.models import JobRun

        db = Database(f"sqlite:///{(tmp_path / 'm.db').as_posix()}")
        db.create_all()
        with db.session() as session:
            session.add_all([JobRun(name="routing"), JobRun(name="absences")])

        platform_health.mark_scheduled(db, ["absences", "not-run-yet"])

        with db.session() as session:
            rows = {r.name: r.scheduled for r in session.execute(select(JobRun)).scalars()}
        db.engine.dispose()
        assert rows == {"routing": False, "absences": True}


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


class TestSkipped:
    """Due, and nothing done: neither of the other outcomes (TheHub #60864)."""

    def test_a_skipped_job_reads_skipped_with_its_reason(self) -> None:
        row = Row(name="briefing-dm", interval_seconds=86_400, last_run_at=NOW)
        row.skipped_reason = "MYKRONOS_BRIEFING_DM_CHANNEL not set."  # type: ignore[attr-defined]

        health = platform_health.assess_job(row, now=NOW)

        assert health.status == "skipped"
        assert "MYKRONOS_BRIEFING_DM_CHANNEL" in health.detail

    def test_a_failure_still_outranks_a_stale_skip(self) -> None:
        row = Row(consecutive_failures=2, last_error="boom")
        row.skipped_reason = "old"  # type: ignore[attr-defined]

        assert platform_health.assess_job(row, now=NOW).status == "failing"


class TestIngestionIsJudgedByWhatItServes:
    """MyKronos Health read "Needs attention" on every load (TheHub #60905).

    The ingestion row asked the public URL from inside the backend container,
    and a host inside this network cannot reach its own public hostname
    (hairpin NAT, measured 2026-09-12). The probe failed on every load while
    GitHub-hosted runners - which can only reach this platform through that
    URL - kept uploading. A permanent red is a page nobody reads.

    What ingestion serves is uploads. A run carrying a workflow run id came
    from a GitHub runner, through the public URL, so one inside the grace
    window is the evidence the in-network probe cannot give.
    """

    def _unreachable(self) -> jobs.ReachabilityResult:
        return jobs.ReachabilityResult(
            url="https://mykronos.example/healthz",
            detail="https://mykronos.example/healthz could not be reached: timed out",
        )

    def test_a_reachable_probe_is_reachable(self) -> None:
        result = jobs.ReachabilityResult(url="https://x/healthz", reachable=True)

        dep = platform_health.assess_ingestion(result, hours_since_actions_upload=None)

        assert dep.reachable
        assert dep.name == "ingestion"

    def test_a_recent_upload_outweighs_the_in_network_probe(self) -> None:
        dep = platform_health.assess_ingestion(
            self._unreachable(), hours_since_actions_upload=1.5
        )

        assert dep.reachable, "uploads are landing through the public URL"
        assert "hairpin" in dep.detail
        assert "1.5h" in dep.detail
        assert not platform_health.PlatformHealth(dependencies=[dep]).degraded

    def test_no_recent_upload_is_a_real_failure(self) -> None:
        dep = platform_health.assess_ingestion(
            self._unreachable(),
            hours_since_actions_upload=jobs.ACTIONS_UPLOAD_GRACE_HOURS + 1,
        )

        assert not dep.reachable
        assert "No GitHub Actions upload for" in dep.detail
        assert platform_health.PlatformHealth(dependencies=[dep]).degraded

    def test_no_evidence_is_not_reassurance(self) -> None:
        dep = platform_health.assess_ingestion(
            self._unreachable(), hours_since_actions_upload=None
        )

        assert not dep.reachable
        assert "nothing corroborates" in dep.detail


class TestAnUnconfiguredDependencyIsNotAFailure:
    """B-014's rule, which `self-check` follows and this page did not: a
    dependency the deployment does not have is not one that failed."""

    def test_it_does_not_degrade(self) -> None:
        health = platform_health.PlatformHealth(
            dependencies=[
                platform_health.DependencyHealth(
                    name="vault", reachable=False, detail="not set", configured=False
                )
            ]
        )

        assert not health.degraded

    @pytest.mark.asyncio
    async def test_concourse_with_no_url_is_not_configured(self) -> None:
        result = await jobs.check_concourse("")

        assert not result.configured
        assert not result.reachable


class TestThePage:
    def test_a_blind_probe_with_uploads_landing_is_healthy(
        self, client, admin_auth, monkeypatch
    ) -> None:
        from mykronos.api import dashboard

        async def checks(_settings: object) -> list[tuple[str, jobs.ReachabilityResult]]:
            return [
                (
                    "ingestion",
                    jobs.ReachabilityResult(url="https://x/healthz", detail="timed out"),
                ),
                (
                    "vault",
                    jobs.ReachabilityResult(detail="no vault", configured=False),
                ),
                ("concourse", jobs.ReachabilityResult(url="c", reachable=True)),
            ]

        monkeypatch.setattr(dashboard, "jobs_self_check", checks)
        monkeypatch.setattr(jobs, "hours_since_an_actions_upload", lambda _dir: 0.5)

        body = client.get("/api/dashboard/platform-health", headers=admin_auth).json()

        deps = {d["name"]: d for d in body["dependencies"]}
        assert deps["ingestion"]["reachable"] is True
        assert deps["vault"]["configured"] is False
        assert not any(j["status"] in ("failing", "late") for j in body["jobs"])
        assert body["degraded"] is False
