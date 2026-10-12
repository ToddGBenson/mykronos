"""The timeout audit runs on a schedule against live Concourse (TheHub #60729).

`test_timeout_audit.py` was the only automatic run of the audit against live
history until PR #789 made it hermetic, rightly: a unit test grading live data
turned `main` red the day one job had a slow run. That left the live verdict
with no caller. The backend's `timeout-audit` job is the caller now, and these
tests pin the three things it must say and the one it must never say:

* a tight cap raises a notification naming the job and the suggested cap;
* an unreachable Concourse is `could not audit`, recorded as a FAILED run;
* a clean estate is quiet;
* and an unreadable estate is never reported as clean.

The fetch is injected, so nothing here reads a real Concourse. One test drives
the real HTTP fetch at a closed port, because "unreachable" through a fake is
only a claim about the fake.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos import jobs, main, timeout_audit
from mykronos.config import Settings
from mykronos.notify import Notification

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE_DIR = REPO_ROOT / "deploy" / "concourse" / "pipelines"


class Recorder:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


def _builds(*runs: tuple[str, int]) -> list[dict[str, Any]]:
    return [
        {"name": str(i), "status": status, "start_time": 1_000_000, "end_time": 1_000_000 + secs}
        for i, (status, secs) in enumerate(runs, start=1)
    ]


def _job_names() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for path in sorted(PIPELINE_DIR.glob("*.yml")):
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        out[path.stem] = [job["name"] for job in config.get("jobs") or []]
    return out


def _cap(pipeline: str, job_name: str) -> int:
    config = yaml.safe_load((PIPELINE_DIR / f"{pipeline}.yml").read_text(encoding="utf-8"))
    job = next(j for j in config["jobs"] if j["name"] == job_name)
    caps: list[int] = []

    def visit(node: dict[str, Any]) -> None:
        task = node.get("task")
        if isinstance(task, str) and task not in timeout_audit.HOOKS and node.get("timeout"):
            minutes = timeout_audit.to_minutes(node["timeout"])
            if minutes is not None:
                caps.append(minutes)

    timeout_audit.walk(job["plan"], visit)
    assert caps, f"{pipeline}/{job_name} has no capped task to test against"
    return sum(caps)


def fake_concourse(
    history: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
    *,
    unreadable: set[str] | None = None,
) -> timeout_audit.Fetch:
    """Every committed job, one quick success each unless `history` says otherwise."""
    history = history or {}
    unreadable = unreadable or set()
    routes: dict[str, Any] = {}
    for pipeline, names in _job_names().items():
        base = f"/api/v1/teams/main/pipelines/{pipeline}/jobs"
        routes[base] = [{"name": name} for name in names]
        for name in names:
            routes[f"{base}/{name}/builds?limit=100"] = history.get(
                (pipeline, name), _builds(("succeeded", 30))
            )

    def fetch(path: str) -> Any:
        if any(f"/pipelines/{p}/" in path for p in unreadable):
            raise ConnectionError("connection refused")
        return routes[path]

    return fetch


def unreachable(path: str) -> Any:
    raise ConnectionError("[Errno 111] Connection refused")


async def run(fetch: timeout_audit.Fetch, notifier: Recorder | None = None,
              pipeline_dir: Path = PIPELINE_DIR) -> timeout_audit.TimeoutAuditReport:
    return await jobs.audit_pipeline_timeouts(
        "http://concourse.invalid:8080", pipeline_dir, notifier=notifier, fetch=fetch
    )


class TestAFindingIsRaised:
    async def test_a_tight_cap_notifies_naming_the_job_and_the_suggested_cap(self) -> None:
        cap = _cap("personal-soc", "secrets")
        worst = cap * 60 * 9 // 10  # 1.1x headroom: under HEADROOM_FLOOR
        notifier = Recorder()

        report = await run(
            fake_concourse({("personal-soc", "secrets"): _builds(("succeeded", 60),
                                                                 ("succeeded", worst))}),
            notifier,
        )

        assert report.verdict == "caps to raise"
        [problem] = report.unwaived
        assert (problem.pipeline, problem.job, problem.cap) == ("personal-soc", "secrets", cap)
        assert problem.suggested_cap > cap
        [note] = notifier.sent
        assert note.level == "warning"
        assert (
            f"personal-soc/secrets: cap {cap}m vs worst successful {round(worst / 60)}m, "
            f"suggest {problem.suggested_cap}m"
        ) in note.detail

    async def test_a_clock_killed_build_is_a_finding_even_with_no_success(self) -> None:
        cap = _cap("personal-soc", "secrets")
        notifier = Recorder()

        report = await run(
            fake_concourse({("personal-soc", "secrets"): _builds(("failed", cap * 60 + 5))}),
            notifier,
        )

        [problem] = report.unwaived
        assert problem.kind == "timeout"
        assert "personal-soc/secrets: cap " in notifier.sent[0].detail
        assert "a failed build ran" in notifier.sent[0].detail

    async def test_a_clean_estate_is_quiet(self) -> None:
        notifier = Recorder()

        report = await run(fake_concourse(), notifier)

        assert report.verdict == "clean"
        assert report.capped_jobs >= 40, "a clean run that graded nothing is not clean"
        assert notifier.sent == []


class TestUnreachableIsNeverClean:
    async def test_an_unreachable_concourse_is_could_not_audit(self) -> None:
        notifier = Recorder()

        with pytest.raises(jobs.TimeoutAuditIncompleteError, match="could not audit"):
            await run(unreachable, notifier)

        assert notifier.sent == [], "nothing was read, so nothing can be a finding"

    async def test_the_real_fetch_against_a_closed_port_is_could_not_audit(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            closed = probe.getsockname()[1]

        with pytest.raises(jobs.TimeoutAuditIncompleteError, match="could not audit"):
            await jobs.audit_pipeline_timeouts(f"http://127.0.0.1:{closed}", PIPELINE_DIR)

    async def test_findings_from_the_readable_part_still_send_and_the_run_still_fails(
        self,
    ) -> None:
        cap = _cap("personal-soc", "secrets")
        notifier = Recorder()

        with pytest.raises(jobs.TimeoutAuditIncompleteError, match="thehub"):
            await run(
                fake_concourse(
                    {("personal-soc", "secrets"): _builds(("failed", cap * 60 + 5))},
                    unreadable={"thehub"},
                ),
                notifier,
            )

        [note] = notifier.sent
        assert "personal-soc/secrets" in note.detail

    async def test_no_pipeline_files_is_could_not_audit_not_an_empty_clean_estate(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(jobs.TimeoutAuditIncompleteError, match="no pipeline definitions"):
            await run(fake_concourse(), pipeline_dir=tmp_path)

    async def test_the_failure_is_what_job_runs_records(self, settings: Settings) -> None:
        """`_every` turns the raise into a failed row platform health reads."""
        from mykronos.db import Database
        from mykronos.db.models import JobRun

        db = Database(settings.database_url)
        db.create_all()
        try:
            await run(unreachable)
        except jobs.TimeoutAuditIncompleteError as exc:
            main._record_run(db, "timeout-audit", 86_400, str(exc))

        try:
            with db.session() as session:
                row = session.get(JobRun, "timeout-audit")
                assert row is not None
                assert row.last_succeeded_at is None
                assert row.consecutive_failures == 1
                assert row.last_error.startswith("could not audit")
        finally:
            db.close()


class TestTheSuggestion:
    def test_it_clears_the_floor_the_audit_grades_against(self) -> None:
        """A suggestion the audit would flag again tomorrow is not one."""
        for worst in (60, 517, 3_599, 7_260):
            suggestion = timeout_audit.suggested_cap(worst, [worst])
            assert suggestion >= worst / 60 * timeout_audit.HEADROOM_FLOOR
            assert suggestion % timeout_audit.SUGGESTION_STEP_MINUTES == 0

    def test_the_outlier_ratio_applies_only_where_it_was_measured(self) -> None:
        routine = [600] * 9 + [700]  # ten samples, p90 = 600s = 10m
        assert timeout_audit.suggested_cap(700, routine) == 55  # 10m x 5.10 -> 51 -> 55
        assert timeout_audit.suggested_cap(700, routine[:9]) == 20  # 11.7m x 1.3 -> 15.2 -> 20


class TestItIsScheduled:
    def _scheduled(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        monkeypatch.setattr(main, "_every", record)
        app = main.create_app(settings)
        with TestClient(app):
            pass
        return captured

    def test_it_runs_daily_against_the_configured_concourse(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True,
            "concourse_url": "http://concourse:8080",
            "concourse_team": "main",
        })
        calls: list[tuple[Any, ...]] = []

        async def fake_audit(url: str, pipeline_dir: Path, **kwargs: Any) -> None:
            calls.append((url, pipeline_dir, kwargs["team"]))

        monkeypatch.setattr(main, "audit_pipeline_timeouts", fake_audit)
        scheduled = self._scheduled(settings, monkeypatch)

        assert "timeout-audit" in scheduled
        interval, job = scheduled["timeout-audit"]
        assert interval == 86_400

        import asyncio

        asyncio.run(job())
        assert calls == [("http://concourse:8080", settings.pipeline_definitions_dir, "main")]

    def test_without_a_concourse_it_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "",
        })
        assert "timeout-audit" not in self._scheduled(settings, monkeypatch)

    def test_the_image_carries_the_pipeline_files_it_grades(self) -> None:
        """The default path resolves in a checkout; the image needs the copy."""
        dockerfile = (REPO_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
        assert "deploy/concourse/pipelines /app/deploy/concourse/pipelines" in dockerfile
        assert "MYKRONOS_PIPELINE_DEFINITIONS_DIR=/app/deploy/concourse/pipelines" in dockerfile
        default = Settings.model_fields["pipeline_definitions_dir"].default_factory
        assert default is not None
        assert Path(default()).resolve() == PIPELINE_DIR.resolve()  # type: ignore[call-arg]
