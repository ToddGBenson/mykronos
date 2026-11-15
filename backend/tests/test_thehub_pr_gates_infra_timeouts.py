"""`pr-gates` never posts a red verdict for a run that judged nothing.

On 2026-11-15 the worker's disk was starved and every step slowed 2-13x.
`integration` ran into its Concourse timeout while still installing Postgres
(builds 1333-1341). A Concourse timeout kills the task with no outputs, so the
infra/reason marker could never be written and the failure hook posted
`failure` on four heads whose code was never run. Two more were left
`in_progress` because `report-to-hub` ran first in the hook and timed out.

These tests EXECUTE the integration script and the check-run reporter as they
stand in the pipeline, with TheHub's script and curl stubbed.
"""

from __future__ import annotations

import json
import os
import re
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
MARGIN_S = 90


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _step(task: str) -> dict[str, Any]:
    return next(s for s in _job()["plan"] if s.get("task") == task)


def _seconds(duration: str) -> int:
    m = re.fullmatch(r"(\d+)m", duration)
    assert m, f"expected whole minutes, got {duration!r}"
    return int(m.group(1)) * 60


# -- A1: container-tiers is ended inside the task, where it can say why ------


def test_container_tiers_runs_under_a_budget_90s_inside_the_hard_timeout() -> None:
    task = _step("integration")
    budget = int(task["params"]["TIER_HARD_BUDGET_S"])
    assert budget == _seconds(task["timeout"]) - MARGIN_S
    script = task["config"]["run"]["args"][-1]
    assert '-s TERM -k 30 "$BUDGET" bash pr/scripts/ci/container-tiers.sh pr subset' in script
    # The KILL after TERM still lands inside the hard timeout.
    assert budget + 30 < _seconds(task["timeout"])


def _integration(tmp_path: Path, tiers_body: str, budget: str) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash or not shutil.which("timeout"):
        pytest.skip("bash and timeout(1) are required")
    pr = tmp_path / "pr"
    (pr / ".git").mkdir(parents=True)
    (pr / ".git" / "HEAD").write_text(HEAD + "\n")
    (pr / ".git" / "pr-number").write_text("713\n")
    (pr / "config" / "ci").mkdir(parents=True)
    (pr / "config" / "ci" / "pr-integration-subset.txt").write_text("x  # y\n")
    (pr / "scripts" / "ci").mkdir(parents=True)
    (pr / "scripts" / "ci" / "container-tiers.sh").write_text(tiers_body)
    script = _step("integration")["config"]["run"]["args"][-1].replace(
        "/tmp/container-tiers", (tmp_path / "tiers-out").as_posix())
    env = {**os.environ, "TIER_HARD_BUDGET_S": budget}
    return subprocess.run([bash, "-c", script], cwd=tmp_path, capture_output=True, text=True,
                          timeout=90, env=env)


SLOW_ENVIRONMENT = (
    "echo '[container-tiers] installing PostgreSQL 16 + pgvector and Redis'\n"
    "sleep 6\n"
    "exit 0\n"
)
SLOW_SUBSET = (
    "echo '[container-tiers] running the subset tier: pytest x'\n"
    "sleep 6\n"
    "exit 0\n"
)


def test_an_environment_build_that_overruns_is_no_verdict(tmp_path: Path) -> None:
    r = _integration(tmp_path, SLOW_ENVIRONMENT, budget="2")
    assert r.returncode == 2, r.stdout + r.stderr
    reason = (tmp_path / "memory-infra" / "reason").read_text()
    assert reason.startswith("NO VERDICT")
    assert "overran its 2s budget" in reason
    assert "the subset never started" in reason
    assert "not a test failure" in reason
    assert (tmp_path / "memory-infra" / "exit_code").read_text().strip() == "2"
    assert "reported unjudged, not failed" in r.stdout


def test_a_subset_cut_off_by_the_budget_is_no_verdict_either(tmp_path: Path) -> None:
    """The subset's own 300s soft cap never fired, so the environment ate the
    time: nothing about the pull request's code was concluded."""
    r = _integration(tmp_path, SLOW_SUBSET, budget="2")
    assert r.returncode == 2, r.stdout + r.stderr
    reason = (tmp_path / "memory-infra" / "reason").read_text()
    assert "the subset had started but had not finished" in reason


def test_the_subsets_own_soft_timeout_is_still_partial_not_an_outage(tmp_path: Path) -> None:
    """container-tiers' 124 returns well inside the budget: the existing
    partial path, which is a verdict, applies."""
    r = _integration(tmp_path, "echo '[container-tiers] running the subset tier: x'\nexit 124\n",
                     budget="60")
    assert r.returncode == 124, r.stdout + r.stderr
    assert not (tmp_path / "memory-infra").exists()
    assert "results are partial" in r.stdout


def test_a_run_inside_the_budget_is_untouched(tmp_path: Path) -> None:
    r = _integration(tmp_path, "exit 1\n", budget="60")
    assert r.returncode == 1, r.stdout + r.stderr
    assert not (tmp_path / "memory-infra").exists()


# -- the reporter, executed on what A1 leaves behind --------------------------


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
    step = next(s for s in _job()[hook]["do"] if s.get("task") == CHECK)
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


def test_an_overrun_reaches_github_as_cancelled_not_failure(tmp_path: Path) -> None:
    """The job fails (exit 2), so on_failure reports; the marker turns its
    `failure` into `cancelled`."""
    _integration(tmp_path, SLOW_ENVIRONMENT, budget="2")
    body = _report(tmp_path, "on_failure")
    assert (body["commit_sha"], body["phase"], body["conclusion"]) == (HEAD, "end", "cancelled")


def test_a_real_failure_still_reaches_github_as_failure(tmp_path: Path) -> None:
    _integration(tmp_path, "exit 1\n", budget="60")
    assert _report(tmp_path, "on_failure")["conclusion"] == "failure"


# -- A2: a Concourse error is never a verdict -------------------------------


def test_an_error_posts_cancelled(tmp_path: Path) -> None:
    """A lost worker, an image check that failed, no worker satisfying a step:
    there is no infra marker (nothing ran to write one), and still no verdict."""
    assert _report(tmp_path, "on_error")["conclusion"] == "cancelled"


def test_only_on_failure_can_post_failure() -> None:
    job = _job()
    for hook in ("on_error", "on_abort", "on_success"):
        for step in job.get(hook, {}).get("do", []):
            if step.get("task") == CHECK:
                assert step["params"]["CONCLUSION"] != "failure", hook


# -- A3: the check is posted before the Hub report --------------------------


@pytest.mark.parametrize("hook", ["on_failure", "on_error"])
def test_the_check_run_is_posted_before_the_hub_report(hook: str) -> None:
    """A timed-out or unschedulable `report-to-hub` must not stop the check:
    the check gates the merge, the Hub report is telemetry."""
    tasks = [s.get("task") for s in _job()[hook]["do"]]
    assert tasks == [CHECK, HUB], tasks


# -- C: the caps (PS-7) -------------------------------------------------------


def test_the_caps_sit_above_the_starved_runs_and_the_soft_cap_holds() -> None:
    integration = _step("integration")
    assert integration["timeout"] == "14m"
    assert integration["params"]["TIER_SOFT_TIMEOUT_S"] == "300"
    assert _step("pick")["timeout"] == "15m"
