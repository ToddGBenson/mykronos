"""`pr-gates` never posts a red verdict for a run that judged nothing.

On 2026-11-15 the worker's disk was starved and every step slowed 2-13x.
`integration` ran into its Concourse timeout while still installing Postgres
(builds 1333-1341). A Concourse timeout kills the task with no outputs, so the
infra/reason marker could never be written and the failure hook posted
`failure` on four heads whose code was never run. Two more were left
`in_progress` because `report-to-hub` ran first in the hook and timed out.

Since TheHub #62416 the integration task is gone from the pull request (dev
process v2 step 4: integration tiers run after the merge only, in
container-tiers), and with it the tests that executed its budget. What #1175
fixed in the reporter stays and is still EXECUTED here, with curl stubbed: an
infra marker turns `failure` into `cancelled`, an error is never a verdict,
and the check is posted before the Hub report.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "pr-gates"
HEAD = "a" * 40
CHECK = "report-check-run"
HUB = "report-to-hub"


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _hook_steps(hook: str) -> list[dict[str, Any]]:
    """A hook's steps, with a `try:` unwrapped to the step it guards."""
    return [s.get("try", s) for s in _job().get(hook, {}).get("do", [])]


def _step(task: str) -> dict[str, Any]:
    """A plan step by task name, inside a `do:` wrapper too."""
    for s in _job()["plan"]:
        if s.get("task") == task:
            return s
        for inner in s.get("do") or []:
            if inner.get("task") == task:
                return inner
    raise AssertionError(f"no {task!r} step in {JOB}")


# -- the reporter, executed ----------------------------------------------------


_CURL_STUB = """curl() {
  while [ $# -gt 0 ]; do
    case "$1" in -d|--data) printf '%s' "$2" > "$CAPTURE" ;; esac
    shift
  done
  return 0
}
"""


def _report(tmp_path: Path, hook: str) -> dict[str, Any]:
    """Run the pr-gates `hook`'s check-run step against `tmp_path`'s outputs."""
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("sh is required")
    step = next(s for s in _hook_steps(hook) if s.get("task") == CHECK)
    (tmp_path / "source" / ".git").mkdir(parents=True, exist_ok=True)
    (tmp_path / "source" / ".git" / "HEAD").write_text(HEAD + "\n")
    if (tmp_path / "memory-infra").exists():
        shutil.copytree(tmp_path / "memory-infra", tmp_path / "infra")
    env = {**os.environ, "CAPTURE": str(tmp_path / "body.json"),
           "MYKRONOS_URL": "http://mykronos.test", "MYKRONOS_TOKEN": "tok",
           "REPO_FULL_NAME": "ToddGBenson/TheHub",
           **{k: str(v) for k, v in step["params"].items()
              if k not in ("MYKRONOS_URL", "MYKRONOS_TOKEN", "REPO_FULL_NAME")}}
    r = subprocess.run([sh, "-s"], input=_CURL_STUB + step["config"]["run"]["args"][-1],
                       env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stdout + r.stderr
    body: dict[str, Any] = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    return body


def _infra_marker(tmp_path: Path, reason: str) -> None:
    """What `linux-verdict` leaves when the gates' remote result failed this
    host's check: infra/reason, so nothing was judged."""
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "reason").write_text(reason + "\n")


def test_a_failure_with_an_infra_marker_reaches_github_as_cancelled(tmp_path: Path) -> None:
    """The job fails, so on_failure reports; the marker turns its `failure`
    into `cancelled`: nothing was judged."""
    _infra_marker(tmp_path, "INFRASTRUCTURE, NOT A VERDICT: gates' result failed this host's check")
    body = _report(tmp_path, "on_failure")
    assert (body["commit_sha"], body["phase"], body["conclusion"]) == (HEAD, "end", "cancelled")


def test_a_real_failure_still_reaches_github_as_failure(tmp_path: Path) -> None:
    assert _report(tmp_path, "on_failure")["conclusion"] == "failure"


# -- A2: a Concourse error is never a verdict -------------------------------


def test_an_error_posts_cancelled(tmp_path: Path) -> None:
    """A lost worker, an image check that failed, no worker satisfying a step:
    there is no infra marker (nothing ran to write one), and still no verdict."""
    assert _report(tmp_path, "on_error")["conclusion"] == "cancelled"


def test_only_on_failure_can_post_failure() -> None:
    for hook in ("on_error", "on_abort", "on_success"):
        for step in _hook_steps(hook):
            if step.get("task") == CHECK:
                assert step["params"]["CONCLUSION"] != "failure", hook


# -- A3: the check is posted before the Hub report --------------------------


@pytest.mark.parametrize("hook", ["on_failure", "on_error"])
def test_the_check_run_is_posted_before_the_hub_report(hook: str) -> None:
    """A timed-out or unschedulable `report-to-hub` must not stop the check:
    the check gates the merge, the Hub report is telemetry."""
    tasks = [s.get("task") for s in _hook_steps(hook)]
    assert tasks == [CHECK, HUB], tasks


@pytest.mark.parametrize("hook", ["on_failure", "on_error"])
def test_a_refused_check_post_cannot_skip_the_hub_report(hook: str) -> None:
    """Review of #1175, N4: the check step is first, so it is wrapped in
    `try:`; a refused or unreachable post still lets the Hub hear the result."""
    first = _job()[hook]["do"][0]
    assert set(first) == {"try"} and first["try"]["task"] == CHECK


# -- C: the caps (PS-7) -------------------------------------------------------


def test_the_pick_keeps_its_cap() -> None:
    assert _step("pick")["timeout"] == "15m"
