"""personal-soc's pipeline reports `Concourse / personal-soc` on every commit it verifies (D-151).

The D-136 pattern, reused for a second repository (TheHub #60580). `guard`
reports the start. `all-lanes`, which waits on every verifying lane through
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

PIPELINE = (
    Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "personal-soc.yml"
)
TASK = "report-check-run"
GATE = "all-lanes"
FIRST = "guard"
SHA = "0123456789abcdef0123456789abcdef01234567"

#: Every job whose pass or fail is a verdict on the commit.
VERIFYING = {"guard", "secrets", "iac", "oracle", "lint", "functional", "skill-integrity"}
#: Commit- or clock-triggered jobs that are deliberately not part of the verdict.
NOT_WIRED = {
    "set-pipeline",
    "package",
    "doc-drift",
    "external-exposure",
    "netassess-ingest",
    "netassess-freshness",
}


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
    """The premise of `all-lanes`: it sits downstream of every verifying lane."""
    assert _upstream_of(GATE) == VERIFYING


def test_package_publishes_only_what_every_verifying_lane_and_the_oracle_passed() -> None:
    """`package` puts a bundle on the host that Scheduled Tasks then run
    unattended. It used to wait on `[guard, secrets, lint, functional,
    skill-integrity]`, so it published past `iac` and the oracle gate. It now
    sits behind `all-lanes`, which carries every verifying lane with it."""
    upstream = _upstream_of("package")
    assert "oracle" in upstream, "package publishes without the oracle gate"
    assert VERIFYING | {GATE} <= upstream


def test_the_gate_is_in_a_group() -> None:
    """Concourse hides a job that is in no group."""
    grouped = {job for group in _doc()["groups"] for job in group["jobs"]}
    assert GATE in grouped


def test_the_first_lane_reports_the_start_after_its_probe_and_before_it_checks() -> None:
    plan = _jobs()[FIRST]["plan"]
    names = [step.get("task") for step in plan]
    start = plan[names.index(TASK)]

    assert names.index("preflight") < names.index(TASK) < names.index("no-personal-data")
    assert start["params"]["PHASE"] == "start"
    assert "CONCLUSION" not in start["params"]
    assert start["params"]["JOB"] == FIRST


def test_the_gate_reports_success_as_its_last_step() -> None:
    last = _jobs()[GATE]["plan"][-1]

    assert last.get("task") == TASK
    assert last["params"]["PHASE"] == "end"
    assert last["params"]["CONCLUSION"] == "success"
    assert last["params"]["JOB"] == GATE


@pytest.mark.parametrize("hook", ["on_failure", "on_error"])
def test_every_lane_up_to_the_gate_reports_failure(hook: str) -> None:
    jobs = _jobs()
    for name in sorted(VERIFYING | {GATE}):
        steps = jobs[name].get(hook, {}).get("do", [])
        assert steps, f"{name} has no {hook} hook"
        # Last, so a failed report cannot stop the Slack alert that runs
        # before it in the same `do:`.
        assert steps[0].get("task") == "notify-slack", f"{name}.{hook} lost its Slack alert"
        last = steps[-1]
        assert last.get("task") == TASK, f"{name}.{hook} does not end with {TASK}"
        params = last["params"]
        assert (params["JOB"], params["PHASE"], params["CONCLUSION"]) == (
            name,
            "end",
            "failure",
        ), f"{name}.{hook}"


def test_jobs_outside_the_verdict_never_report() -> None:
    jobs = _jobs()
    assert NOT_WIRED | VERIFYING | {GATE} == set(jobs)
    for name in NOT_WIRED:
        assert not _reporters(jobs[name]), f"{name} reports a check run but is not a verdict"


def test_every_reporting_job_probes_mykronos_first() -> None:
    """PS-2: a job that talks to Mykronos probes it before anything else does."""
    jobs = _jobs()
    for name in VERIFYING | {GATE}:
        names = [step.get("task") for step in jobs[name]["plan"]]
        assert "preflight" in names, f"{name} reports without a preflight"


def test_the_report_is_never_retried_and_always_bounded() -> None:
    """PS-12 and PS-7: it can fail, so no `attempts:`; it holds the worker, so a timeout."""
    reporters = _reporters(_doc()["jobs"])
    # 8 jobs x 2 hooks, one start, one success.
    assert len(reporters) == 18
    for step in reporters:
        assert "attempts" not in step
        assert step.get("timeout")
        assert step["params"]["MYKRONOS_TOKEN"] == "((personal-soc-ingestion-token))"
        assert step["params"]["REPO_FULL_NAME"] == "ToddGBenson/personal-soc"


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
        "REPO_FULL_NAME": "ToddGBenson/personal-soc",
        **params,
    }
    return subprocess.run(
        [sh, "-s"],
        input=_CURL_STUB + _script(),
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_a_start_sends_the_commit_and_no_conclusion(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="guard", PHASE="start")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert body == {
        "repo_full_name": "ToddGBenson/personal-soc",
        "commit_sha": SHA,
        "job": "guard",
        "phase": "start",
        "conclusion": None,
    }
    args = (tmp_path / "args.txt").read_text(encoding="utf-8").split("\n")
    assert "--fail-with-body" in args
    assert "http://mykronos.test/api/ingest/check-runs" in args


def test_a_success_sends_the_conclusion(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="all-lanes", PHASE="end", CONCLUSION="success")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert (body["job"], body["phase"], body["conclusion"]) == ("all-lanes", "end", "success")


def test_a_failure_sends_the_conclusion(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="oracle", PHASE="end", CONCLUSION="failure")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert (body["job"], body["phase"], body["conclusion"]) == ("oracle", "end", "failure")


def test_a_refused_report_fails_the_step(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="guard", PHASE="start", CURL_RC="22")

    assert r.returncode != 0


@pytest.mark.parametrize("head", [None, "ref: refs/heads/main", "abc1234"])
def test_no_commit_to_name_fails_rather_than_guessing(tmp_path: Path, head: str | None) -> None:
    r = _run(tmp_path, head, JOB="guard", PHASE="end", CONCLUSION="failure")

    assert r.returncode != 0
    assert not (tmp_path / "body.json").exists()
