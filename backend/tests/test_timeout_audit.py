"""The timeout audit is run here, because nothing else ran it (#60002).

`scripts/audit_pipeline_timeouts.py` exits 1 when a task cap sits below the
job's own observed worst run, and it had no caller: no workflow, no pipeline,
no hook, and this repository has no Makefile, justfile, tox or nox. A repo-wide
search for its name returned its own docstring and one prose mention. It
reported seven bad caps for as long as nobody looked.

Two of those caps had ALREADY FIRED. `mykronos/publish-frontend` builds #78,
#88 and #89 died with `timeout exceeded` inside kaniko, and `mykronos/iac` #74
died inside its upload task. A build killed by the clock reports as a FAILURE,
and in the UI that is indistinguishable from a failure caused by the thing the
job was checking -- so the cost of not running this was not a tidy number, it
was three builds whose red was misattributed.

WHAT IS AND IS NOT ASSERTED HERE. Whether the audit WORKS is graded, not
what it finds about the live estate. The script is run end to end against a
fake Concourse API serving injected build history, so a clean history must
pass, a tight cap must be named and fail the run, and a job killed by the clock
must be reported rather than crash the report. These tests used to read LIVE
Concourse and assert the estate had no finding, which turned `main` red the
day `personal-soc/secrets` had one slow run: a unit test grading live data.
The live verdict still needs a caller, and a scheduled lane is the place for
it, not the unit tier: until one exists, run the script by hand.
The waivers, the constants, and the fact that the script parses every pipeline
file and finds real caps in them are checked offline, from the committed files.

Every layer asserts a floor before it asserts a conclusion. A discovery step
that finds no pipelines, or a pipeline with no capped tasks, is a failure and
not a clean run.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "audit_pipeline_timeouts.py"
PIPELINE_DIR = REPO_ROOT / "deploy" / "concourse" / "pipelines"

#: Floors. Named rather than derived from the directory, so deleting a pipeline
#: file fails this instead of silently shrinking what the audit covers.
EXPECTED_PIPELINES = {"mykronos", "personal-soc", "thehub"}
#: The estate had 57 capped, non-hook tasks when this was written. A parser
#: change that started finding a handful would otherwise pass everything.
MINIMUM_CAPPED_TASKS = 40


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("audit_pipeline_timeouts", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


audit = _load()


def pipeline_jobs() -> dict[str, set[str]]:
    """`pipeline -> job names`, read from the committed files."""
    found: dict[str, set[str]] = {}
    for path in sorted(PIPELINE_DIR.glob("*.yml")):
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        found[path.stem] = {job["name"] for job in config.get("jobs") or []}
    return found


def capped_tasks() -> list[tuple[str, str, str, int]]:
    """`(pipeline, job, task, minutes)` for every non-hook task with a cap.

    Walks the parsed document with the audit's OWN `walk`, so this measures the
    thing the audit measures rather than a second opinion about it.
    """
    out: list[tuple[str, str, str, int]] = []
    for path in sorted(PIPELINE_DIR.glob("*.yml")):
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in config.get("jobs") or []:
            def visit(node: dict, job_name: str = job["name"], stem: str = path.stem) -> None:
                task = node.get("task")
                if isinstance(task, str) and task not in audit.HOOKS and node.get("timeout"):
                    minutes = audit.to_minutes(node["timeout"])
                    if minutes is not None:
                        out.append((stem, job_name, task, minutes))

            audit.walk(job.get("plan") or [], visit)
    return out


class TestTheAuditCanSeeSomething:
    """A check that inspects nothing passes everything."""

    def test_every_pipeline_it_audits_is_a_file_we_have(self) -> None:
        found = pipeline_jobs()
        assert set(found) == EXPECTED_PIPELINES, (
            f"the pipelines on disk are {sorted(found)}, expected "
            f"{sorted(EXPECTED_PIPELINES)}. Add or remove one here in the same "
            "change, so a deleted pipeline is a decision and not a silent "
            "narrowing of what this audit covers."
        )
        for pipeline, jobs in found.items():
            assert jobs, f"{pipeline}.yml declares no jobs"

    def test_it_finds_real_caps_to_audit(self) -> None:
        caps = capped_tasks()
        assert len(caps) >= MINIMUM_CAPPED_TASKS, (
            f"only {len(caps)} capped tasks found across the estate; expected at "
            f"least {MINIMUM_CAPPED_TASKS}. The audit reports 'every cap clears "
            "its observed worst run' when it finds no caps at all, which is the "
            "same sentence it prints when everything is genuinely fine."
        )
        assert all(minutes > 0 for *_, minutes in caps), "a cap parsed as zero minutes"

    def test_the_thresholds_are_the_measured_ones(self) -> None:
        """The caps raised by #60002 were derived from these two numbers.

        Changing either silently re-scales every future cap decision, so they
        are pinned with the measurement beside them rather than left as loose
        module constants.
        """
        assert audit.HEADROOM_FLOOR == 1.3
        assert audit.OUTLIER_RATIO == 5.10, (
            "OUTLIER_RATIO is the 90th percentile of worst/p90 across the 53 "
            "estate jobs with 10+ successful builds, measured 2026-09-18. "
            "Re-measure before changing it; do not adjust it to make a cap fit."
        )


class TestTheWaiversAreHonest:
    """The same rule `ACKNOWLEDGED_UNMAPPED_JOBS` is held to (#59989, #59990)."""

    def test_every_waiver_names_a_job_that_exists(self) -> None:
        found = pipeline_jobs()
        for pipeline, job in audit.TIMEOUT_WAIVERS:
            assert pipeline in found, (
                f"waiver names pipeline `{pipeline}`, which has no file here"
            )
            assert job in found[pipeline], (
                f"waiver names `{pipeline}/{job}`, which is not a job in "
                f"{pipeline}.yml. A waiver that outlives its job starts excusing "
                "a future job that reuses the name."
            )

    def test_every_waiver_gives_a_reason_and_a_way_out(self) -> None:
        for (pipeline, job), reason in audit.TIMEOUT_WAIVERS.items():
            assert reason and reason.strip(), f"`{pipeline}/{job}` is waived with no reason"
            assert len(reason) > 80, (
                f"`{pipeline}/{job}`'s reason is too short to be one. A waiver "
                "has to say why raising the cap would be the WRONG fix, not "
                "that raising it is inconvenient."
            )
            assert "Remove this when" in reason or "expires" in reason, (
                f"`{pipeline}/{job}`'s waiver names no condition for removing "
                "it, so nothing will ever remove it. An allowlist nobody prunes "
                "becomes the hole it was meant to document."
            )


def _builds(*runs: tuple[str, int]) -> list[dict[str, Any]]:
    """Concourse build records: `(status, duration in seconds)` each."""
    return [
        {"name": str(i), "status": status, "start_time": 1_000_000, "end_time": 1_000_000 + secs}
        for i, (status, secs) in enumerate(runs, start=1)
    ]


class _FakeConcourse:
    """Serves the two Concourse API routes the audit reads, from a dict.

    `history[(pipeline, job)]` is that job's build list. Every job declared in
    a committed pipeline file is listed, so the audit walks the real estate;
    a job with no entry in `history` has a single quick successful run.
    """

    def __init__(self, history: dict[tuple[str, str], list[dict[str, Any]]]) -> None:
        jobs = pipeline_jobs()
        routes: dict[str, Any] = {}
        for pipeline, names in jobs.items():
            base = f"/api/v1/teams/main/pipelines/{pipeline}/jobs"
            routes[base] = [{"name": name} for name in sorted(names)]
            for name in names:
                routes[f"{base}/{name}/builds"] = history.get(
                    (pipeline, name), _builds(("succeeded", 30))
                )

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
                body = routes.get(urlsplit(self.path).path)
                if body is None:
                    self.send_error(404)
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> _FakeConcourse:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


def run_audit(concourse_url: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True, text=True, timeout=600, check=False, cwd=REPO_ROOT,
        env={**os.environ, "CONCOURSE_URL": concourse_url, "CONCOURSE_TEAM": "main"},
    )


def assert_it_reported(result: subprocess.CompletedProcess[str]) -> None:
    assert "Traceback" not in result.stderr, (
        f"the audit crashed rather than reporting.\n{result.stderr[-2000:]}"
    )
    assert result.returncode in (0, 1), (
        f"the audit exited {result.returncode} rather than reporting.\n"
        f"{result.stderr[-2000:]}"
    )
    for pipeline in EXPECTED_PIPELINES:
        assert f"{pipeline}   (" in result.stdout, (
            f"the audit produced no section for `{pipeline}`"
        )
    assert "could not read" not in result.stdout, (
        "the audit failed to read the fixture history\n" + result.stdout[-2000:]
    )


class TestTheAuditActuallyRuns:
    """The audit runs end to end and says what it found.

    These used to read LIVE Concourse history and assert the live estate had
    no finding, so `main` went red the day `personal-soc/secrets` had one slow
    run -- a test named "runs and reports" failing because the audit reported.
    The verdict about the live estate belongs to the audit; whether the audit
    WORKS is graded here, against history injected through a fake API, so the
    result is the same on every machine and every day.
    """

    def test_it_runs_and_reports_rather_than_crashing(self) -> None:
        """It used to crash before reaching any pipeline.

        Its FLY path pointed into a different project's checkout, so it died
        with FileNotFoundError -- and a detector that crashes reports no
        problems, which is indistinguishable from finding none.
        """
        with _FakeConcourse({}) as concourse:
            result = run_audit(concourse.url)
        assert_it_reported(result)
        assert result.returncode == 0, result.stdout[-4000:]
        assert "every cap clears its observed worst run with margin" in result.stdout

    def test_a_tight_cap_is_reported_and_fails_the_run(self) -> None:
        """The shape the live estate had on 2026-10-11: 8.6m against a 10m cap.

        Derived from the committed cap rather than copied from that day, so
        raising the cap does not quietly turn this into a clean run.
        """
        cap = next(m for p, j, _, m in capped_tasks() if (p, j) == ("personal-soc", "secrets"))
        worst = cap * 60 * 9 // 10  # 1.1x headroom: under HEADROOM_FLOOR, above the cap
        history = {("personal-soc", "secrets"): _builds(("succeeded", 60), ("succeeded", worst))}
        with _FakeConcourse(history) as concourse:
            result = run_audit(concourse.url)
        assert_it_reported(result)
        assert result.returncode == 1, result.stdout[-4000:]
        assert "Caps to raise:" in result.stdout
        assert f"personal-soc/secrets: cap {cap}m vs worst successful {round(worst / 60)}m" in (
            result.stdout
        )

    def test_a_job_that_never_succeeded_but_hit_its_cap_is_reported(self) -> None:
        """The "never ok" branch recorded a 4-field problem the report unpacked as 5.

        So the one job shape the timeout-signature check exists for --
        failed builds only, killed by the clock -- crashed the report with a
        ValueError instead of naming the job.
        """
        cap = next(m for p, j, _, m in capped_tasks() if (p, j) == ("personal-soc", "secrets"))
        history = {("personal-soc", "secrets"): _builds(("failed", cap * 60 + 5))}
        with _FakeConcourse(history) as concourse:
            result = run_audit(concourse.url)
        assert_it_reported(result)
        assert result.returncode == 1, result.stdout[-4000:]
        assert "personal-soc/secrets: cap " in result.stdout
        assert "a failed build ran" in result.stdout
