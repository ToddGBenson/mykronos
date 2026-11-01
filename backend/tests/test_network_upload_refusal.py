"""A refused network upload turns the lane red (TheHub #61121).

personal-soc's three network lanes (external-exposure, netassess-ingest,
netassess-freshness) file their results from an `ensure:` hook. Each hook ended

    ... python -m mykronos.upload ... \\
      || echo "upload did not complete cleanly - the verdict above still stands."
    exit 0

so when the backend answered 403 ("'network' is not enabled for
ToddGBenson/personal-soc") the build stayed green, and for a week no network
finding reached the lake with nothing anywhere going red.

The rule these tests hold:

* the uploader is refused, or never reaches the backend, so NOTHING was filed
  -> the hook exits non-zero, the job goes red, and Slack is told why;
* the run WAS filed, but as a degraded scan (the uploader also exits 1 then)
  -> the hook exits 0: the verdict task above already judged that run, and the
  lake has the record, so there is nothing for this hook to add;
* the run was filed cleanly -> exit 0, nothing written for Slack.

The hooks are EXECUTED under bash, with the uploader stubbed, rather than
grepped for words.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

PIPELINE = (
    Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "personal-soc.yml"
)
HOOK_TASK = "upload-network-findings"
NETWORK_JOBS = ("external-exposure", "netassess-ingest", "netassess-freshness")
APT_CONF = "/etc/apt/apt.conf.d/99force-ipv4"

REFUSED = (
    "ERROR POST /api/ingest/scan-run -> HTTP 403 "
    "{\"detail\":\"'network' is not enabled for ToddGBenson/personal-soc. "
    'Currently granted: functional, iac, oracle, sast, secrets."}'
)

#: The uploader, stubbed. `python -m mykronos.upload` is the only `python` call
#: in the hook; it prints what the real one logs in each case and exits with the
#: real one's code (backend/mykronos/upload.py `main`).
STUBS = r"""
apt-get() { :; }
python() {
  case "$FAKE_UPLOAD" in
    refused)
      echo "$FAKE_REFUSAL" >&2
      return 1 ;;
    degraded)
      echo "INFO Uploaded 3 finding(s) for scan run 0000 (partial)" >&2
      echo "ERROR Scan status is partial — failing the step so this run is visibly broken." >&2
      return 1 ;;
    ok)
      echo "INFO Uploaded 3 finding(s) for scan run 0000 (success)" >&2
      return 0 ;;
  esac
  echo "unexpected FAKE_UPLOAD=$FAKE_UPLOAD" >&2
  return 99
}
"""


def _jobs() -> dict[str, dict[str, Any]]:
    document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return {job["name"]: job for job in document["jobs"]}


def _hook(job: str) -> dict[str, Any]:
    for step in _jobs()[job]["plan"]:
        ensure = step.get("ensure") if isinstance(step, dict) else None
        if isinstance(ensure, dict) and ensure.get("task") == HOOK_TASK:
            return ensure
    pytest.fail(f"{job} has no `{HOOK_TASK}` ensure hook")


def _run(tmp_path: Path, job: str, mode: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute the upload hook")
    hook = _hook(job)
    script = str(hook["config"]["run"]["args"][-1])
    assert APT_CONF in script
    script = script.replace(APT_CONF, (tmp_path / "apt.conf").as_posix())
    (tmp_path / "results").mkdir(exist_ok=True)
    env = {
        **os.environ,
        **{k: str(v) for k, v in (hook.get("params") or {}).items()},
        "MYKRONOS_INSTALL_UPLOADER": ":",
        "MYKRONOS_URL": "http://mykronos.test",
        "MYKRONOS_TOKEN": "t",
        "FAKE_UPLOAD": mode,
        "FAKE_REFUSAL": REFUSED,
    }
    return subprocess.run(
        [bash, "-s"],
        input=STUBS + script,
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


@pytest.mark.parametrize("job", NETWORK_JOBS)
def test_a_refused_upload_turns_the_lane_red(tmp_path: Path, job: str) -> None:
    r = _run(tmp_path, job, "refused")
    out = r.stdout + r.stderr
    assert r.returncode != 0, (
        f"{job}: the backend refused the upload and nothing was filed, but the hook "
        f"exited 0, so the lane stays green:\n{out}"
    )
    assert "HTTP 403" in out, "the refusal itself must be in the build log"


@pytest.mark.parametrize("job", NETWORK_JOBS)
def test_a_refusal_tells_slack_why_the_lane_is_red(tmp_path: Path, job: str) -> None:
    """The job's `on_failure:` alert reads the first line of notify/message.txt.
    Without one written here it would repeat the verdict task's message (or a
    bare "failed"), which says nothing about the upload."""
    hook = _hook(job)
    inputs = {i["name"] for i in hook["config"].get("inputs", [])}
    outputs = {o["name"] for o in hook["config"].get("outputs", [])}
    assert "notify" in inputs and "notify" in outputs, (
        f"{job}: the hook must read and write `notify` to reach the Slack alert"
    )
    _run(tmp_path, job, "refused")
    message = tmp_path / "notify" / "message.txt"
    assert message.exists(), f"{job}: nothing was written for the Slack alert"
    first = message.read_text(encoding="utf-8").splitlines()[0]
    assert f"personal-soc / {job}" in first
    assert "nothing was filed" in first


@pytest.mark.parametrize("job", NETWORK_JOBS)
def test_the_refusal_line_goes_above_the_verdicts_message(tmp_path: Path, job: str) -> None:
    (tmp_path / "notify").mkdir()
    (tmp_path / "notify" / "message.txt").write_text("the verdict's own line\n", encoding="utf-8")
    _run(tmp_path, job, "refused")
    lines = (tmp_path / "notify" / "message.txt").read_text(encoding="utf-8").splitlines()
    assert "nothing was filed" in lines[0]
    assert "the verdict's own line" in lines, "the verdict's message must not be lost"


@pytest.mark.parametrize("job", NETWORK_JOBS)
def test_a_filed_but_degraded_run_leaves_the_verdict_to_the_task(tmp_path: Path, job: str) -> None:
    """Guard. The uploader exits 1 for a degraded scan too, but that run IS in the
    lake, and the verdict task above already judged it."""
    r = _run(tmp_path, job, "degraded")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "notify" / "message.txt").exists()


@pytest.mark.parametrize("job", NETWORK_JOBS)
def test_a_clean_upload_is_quiet(tmp_path: Path, job: str) -> None:
    """Guard."""
    r = _run(tmp_path, job, "ok")
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "notify" / "message.txt").exists()
