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

WHAT IS AND IS NOT ASSERTED HERE. The live run needs Concourse, so it is
skipped without one, the same fail-soft the drift detectors use: "not running
here" is not drift. Everything that can be checked offline is checked offline
and unconditionally -- the waivers, the constants, and the fact that the script
parses every pipeline file and finds real caps in them. That offline layer is
what makes the skip acceptable, because the failure mode being guarded against
is somebody editing a cap or adding a waiver, and both are readable anywhere.

Every layer asserts a floor before it asserts a conclusion. A discovery step
that finds no pipelines, or a pipeline with no capped tasks, is a failure and
not a clean run.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
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


class TestTheAuditActuallyRuns:
    def test_it_runs_and_reports_rather_than_crashing(self) -> None:
        """It used to crash before reaching any pipeline.

        Its FLY path pointed into a different project's checkout, so it died
        with FileNotFoundError -- and a detector that crashes reports no
        problems, which is indistinguishable from finding none.
        """
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True, text=True, timeout=600, check=False, cwd=REPO_ROOT,
        )
        assert result.returncode in (0, 1), (
            f"the audit exited {result.returncode} rather than reporting.\n"
            f"{result.stderr[-2000:]}"
        )
        if "could not read" in result.stdout:
            pytest.skip("Concourse is not reachable; the offline layers still ran")

        # It reached the server, so the verdict is real and is asserted.
        assert "mykronos" in result.stdout and "thehub" in result.stdout, (
            "the audit produced no per-pipeline section"
        )
        assert result.returncode == 0, (
            "a task timeout cap sits below its job's observed worst run. A build "
            "killed by the clock reports as a failure, and in the UI that is "
            "indistinguishable from a failure caused by whatever the job was "
            "checking.\n\n" + result.stdout[-4000:]
        )
