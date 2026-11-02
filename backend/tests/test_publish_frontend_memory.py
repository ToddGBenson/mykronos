"""mykronos/publish-frontend killed for memory: an outage, not a red build (TheHub #61246).

2026-11-02 13:47Z: publish-frontend #276 ran `npm ci` in the frontend image's
`deps` stage, then kaniko took a snapshot of the filesystem and saved
`app/node_modules` for the later stages, and the log ends `Killed` with the
task exiting 137. Nothing in the build failed: the worker it ran on, which
D-174 caps at 3 GiB, was also holding TheHub's post-merge pytest run (#1711,
peak ~1.3 GiB) and `sast` #282. #270 on 2026-10-31 died the same way, at the
same snapshot. Both went red as FAILED, which the CI watch files as a story and
Start-Here and the overnight loop stop on; they re-trigger an ERRORED build
once.

Serial groups are per pipeline, so no group can keep this job off a worker that
thehub.yml is using. So:

- kaniko runs with `--compressed-caching=false`, which its own documentation
  gives as the setting for a build that fails out of memory: it stops each
  layer being held compressed in memory, and node_modules is the big layer;
- a kaniko SIGKILL (137) builds no image and says so, pushes nothing, and the
  build ERRORS on the step after the task instead of failing. Any other kaniko
  failure is still a failed build.

The task's script is executed as it stands in the pipeline, with a stub in
place of the kaniko executor.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"

JOB = "publish-frontend"
TASK = "kaniko"
EXECUTOR = "/kaniko/executor"
OUTPUT = "built"
VERDICT = f"{OUTPUT}/verdict"
# The errored step's name is what the build page shows, so it says what to do.
ERRORED_STEP = "killed-for-memory-not-a-build-failure-re-run"


def _job() -> dict[str, Any]:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _plan_index() -> tuple[list[dict[str, Any]], int]:
    plan: list[dict[str, Any]] = _job()["plan"]
    return plan, next(n for n, s in enumerate(plan) if s.get("task") == TASK)


def _script() -> str:
    plan, i = _plan_index()
    return str(plan[i]["config"]["run"]["args"][-1])


def _run(tmp_path: Path, executor_rc: int) -> tuple[int, str, bool]:
    sh = shutil.which("bash")
    if sh is None:
        pytest.skip("no bash on this host")
    stub = tmp_path / "executor"
    stub.write_text(
        f'#!/bin/sh\necho "kaniko stub $*"\nexit {executor_rc}\n', encoding="utf-8"
    )
    stub.chmod(0o755)
    (tmp_path / "meta").mkdir()
    (tmp_path / "meta" / "sha").write_text("a" * 40, encoding="utf-8")
    (tmp_path / OUTPUT).mkdir()
    script = _script()
    assert EXECUTOR in script, f"{JOB}/{TASK} no longer calls {EXECUTOR}"
    body = script.replace(EXECUTOR, f"sh '{stub.as_posix()}'")
    out = subprocess.run(
        [sh, "-ec", body],
        cwd=tmp_path,
        env={"REGISTRY": "registry.invalid", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return out.returncode, out.stdout + out.stderr, (tmp_path / VERDICT).exists()


class TestKanikoHoldsLessInMemory:
    def test_compressed_caching_is_off(self) -> None:
        assert "--compressed-caching=false" in _script(), (
            f"{JOB}/{TASK} holds every layer compressed in memory; #270 and #276 "
            "were SIGKILLed snapshotting node_modules on a 3 GiB worker"
        )

    def test_the_reason_is_stated_beside_it(self) -> None:
        assert "#61246" in PIPELINE.read_text(encoding="utf-8")


class TestTheBuildErrorsInsteadOfFailing:
    def test_the_task_records_a_verdict_and_the_next_step_reads_it(self) -> None:
        plan, i = _plan_index()
        outputs = {o["name"] for o in plan[i]["config"].get("outputs") or []}
        assert OUTPUT in outputs, f"{JOB}/{TASK} has no `{OUTPUT}` output for its verdict"
        after = plan[i + 1] if i + 1 < len(plan) else {}
        assert after.get("load_var") == ERRORED_STEP and after.get("file") == VERDICT, (
            f"the step after {TASK} must be `load_var: {ERRORED_STEP}` reading {VERDICT}, "
            "so a kaniko killed for memory ERRORS the build instead of failing it"
        )

    def test_a_sigkill_records_no_verdict_and_says_why(self, tmp_path: Path) -> None:
        rc, out, judged = _run(tmp_path, 137)
        assert rc == 0, out
        assert not judged, "kaniko was killed for memory, yet a verdict was recorded"
        assert "::error::" in out and "not a build failure" in out and "re-run" in out, out

    def test_a_real_kaniko_failure_still_fails(self, tmp_path: Path) -> None:
        rc, out, judged = _run(tmp_path, 1)
        assert rc == 1, out
        assert not judged, out

    def test_a_built_image_records_its_verdict(self, tmp_path: Path) -> None:
        rc, out, judged = _run(tmp_path, 0)
        assert rc == 0 and judged, out
        assert "--destination registry.invalid/mykronos-frontend:" + "a" * 40 in out, out
