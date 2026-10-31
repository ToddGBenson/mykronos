"""TheHub's pipeline reports `Concourse / thehub` on every commit it verifies (D-136).

`unit` reports the start. `oracle-gate`, which waits on every lane through
`passed:`, reports success as its last step. Every job upstream of it reports
failure when it fails or errors, so a red lane is a red check and never silence.

The reporter script is EXECUTED as it stands in the pipeline, with curl stubbed
to capture what it would send, rather than grepped for words.
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
TASK = "report-check-run"
GATE = "oracle-gate"
PR_GATES = "pr-gates"
SHA = "0123456789abcdef0123456789abcdef01234567"


def _doc() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _jobs() -> dict[str, dict[str, Any]]:
    return {job["name"]: job for job in _doc()["jobs"]}


def _upstream_of(target: str) -> set[str]:
    """Every job `target` waits on, transitively, read from `passed:`."""
    jobs = _jobs()
    seen: set[str] = set()
    pending = [target]
    while pending:
        name = pending.pop()
        for step in jobs[name]["plan"]:
            for upstream in step.get("passed") or []:
                if upstream not in seen:
                    seen.add(upstream)
                    pending.append(upstream)
    return seen


def _reporters(node: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []

    def walk(n: Any) -> None:
        if isinstance(n, dict):
            if n.get("task") == TASK:
                found.append(n)
            for v in n.values():
                walk(v)
        elif isinstance(n, list):
            for v in n:
                walk(v)

    walk(node)
    return found


def test_the_gate_waits_on_every_verifying_lane() -> None:
    """The premise of choosing `oracle-gate`: it sits downstream of the lanes.

    Not `deploy-demo` since TheHub#349: the gate sits beside the demo deploy,
    not behind it.
    """
    upstream = _upstream_of(GATE)
    assert {"unit", "build", "secrets", "sast", "dependencies", "containers",
            "prompt-evals", "iac"} <= upstream
    assert "deploy-demo" not in upstream


def test_only_the_gate_and_its_upstream_write_the_check() -> None:
    """TheHub#349. The platform keeps the LATEST report per commit, so a job
    beside the gate that reported too would race it: a demo failure landing
    before the gate's success would be overwritten green, one landing after
    would turn a passed gate red. Only the gate's own chain may report.

    `pr-gates` is the one other reporter, and it races nothing: it reports
    only on a pull request's head, which no develop lane ever checks out
    (test_pr_gates_never_judges_a_develop_commit)."""
    allowed = _upstream_of(GATE) | {GATE, PR_GATES}
    for job in _doc()["jobs"]:
        if _reporters(job):
            assert job["name"] in allowed, (
                f"{job['name']} reports `Concourse / thehub` but is not upstream of {GATE}"
            )


def test_the_first_lane_reports_the_start_before_it_tests() -> None:
    plan = _jobs()["unit"]["plan"]
    names = [step.get("task") for step in plan]
    start = plan[names.index(TASK)]

    assert names.index(TASK) < names.index("pytest")
    assert start["params"]["PHASE"] == "start"
    assert "CONCLUSION" not in start["params"]
    assert start["params"]["JOB"] == "unit"


def test_the_gate_reports_success_as_its_last_step() -> None:
    last = _jobs()[GATE]["plan"][-1]

    assert last.get("task") == TASK
    assert last["params"]["PHASE"] == "end"
    assert last["params"]["CONCLUSION"] == "success"
    assert last["params"]["JOB"] == GATE


@pytest.mark.parametrize("hook", ["on_failure", "on_error"])
def test_every_lane_up_to_the_gate_reports_failure(hook: str) -> None:
    jobs = _jobs()
    for name in sorted(_upstream_of(GATE) | {GATE}):
        steps = jobs[name].get(hook, {}).get("do", [])
        assert steps, f"{name} has no {hook} hook"
        # Last, so a failed report cannot stop the Slack alert or Hub report
        # that run before it in the same `do:`.
        last = steps[-1]
        assert last.get("task") == TASK, f"{name}.{hook} does not end with {TASK}"
        params = last["params"]
        assert (params["JOB"], params["PHASE"], params["CONCLUSION"]) == (
            name, "end", "failure",
        ), f"{name}.{hook}"


def test_the_report_is_never_retried_and_always_bounded() -> None:
    """PS-12 and PS-7: it can fail, so no `attempts:`; it holds the worker, so a timeout."""
    reporters = _reporters(_doc()["jobs"])
    # 20 since TheHub#349 took `deploy-demo`'s two failure reports out; 23
    # since `pr-gates` (TheHub #61102): its failure, error and success reports.
    assert len(reporters) == 23
    for step in reporters:
        assert "attempts" not in step
        assert step.get("timeout")
        assert step["params"]["MYKRONOS_TOKEN"] == "((thehub-ingestion-token))"
        assert step["params"]["REPO_FULL_NAME"] == "ToddGBenson/TheHub"


def test_the_pipeline_never_calls_github_for_the_check() -> None:
    script = _script()
    assert "api.github.com" not in script
    assert "github-token" not in json.dumps(_reporters(_doc()["jobs"])[0])


# -- the script itself ------------------------------------------------------


def _script() -> str:
    return _reporters(_doc()["jobs"])[0]["config"]["run"]["args"][-1]


_CURL_STUB = """curl() {
  printf '%s\\n' "$@" > "$CAPTURE_ARGS"
  while [ $# -gt 0 ]; do
    case "$1" in -d|--data) printf '%s' "$2" > "$CAPTURE" ;; esac
    shift
  done
  return "${CURL_RC:-0}"
}
"""


def _run(tmp_path: Path, head: str | None, **params: str) -> subprocess.CompletedProcess[str]:
    sh = shutil.which("sh")
    assert sh, "sh is required to execute the reporter script"
    if head is not None:
        (tmp_path / "source" / ".git").mkdir(parents=True)
        (tmp_path / "source" / ".git" / "HEAD").write_text(head + "\n", encoding="utf-8")
    env = {
        **os.environ,
        "CAPTURE": str(tmp_path / "body.json"),
        "CAPTURE_ARGS": str(tmp_path / "args.txt"),
        "MYKRONOS_URL": "http://mykronos.test",
        "MYKRONOS_TOKEN": "tok",
        "REPO_FULL_NAME": "ToddGBenson/TheHub",
        **params,
    }
    return subprocess.run(
        [sh, "-s"], input=_CURL_STUB + _script(), env=env, cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )


def test_a_start_sends_the_commit_and_no_conclusion(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="unit", PHASE="start")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert body == {
        "repo_full_name": "ToddGBenson/TheHub",
        "commit_sha": SHA,
        "job": "unit",
        "phase": "start",
        "conclusion": None,
    }
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").split("\n")
    assert "--fail-with-body" in args
    assert "http://mykronos.test/api/ingest/check-runs" in args


def test_a_failure_sends_the_conclusion(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="sast", PHASE="end", CONCLUSION="failure")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert (body["job"], body["phase"], body["conclusion"]) == ("sast", "end", "failure")


def test_a_refused_report_fails_the_step(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="unit", PHASE="start", CURL_RC="22")

    assert r.returncode != 0


@pytest.mark.parametrize("head", [None, "ref: refs/heads/develop", "abc1234"])
def test_no_commit_to_name_fails_rather_than_guessing(tmp_path: Path, head: str | None) -> None:
    r = _run(tmp_path, head, JOB="unit", PHASE="end", CONCLUSION="failure")

    assert r.returncode != 0
    assert not (tmp_path / "body.json").exists()
