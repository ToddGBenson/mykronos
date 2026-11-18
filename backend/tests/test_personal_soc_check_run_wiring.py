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

CHECKOV_DIGEST = "sha256:888060aaaa6f4499fd3b00a1a03185ed760937b049d438fa6e00b3203a5d613e"

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


#: What each hook tells the check (TheHub #61769). A failed build is a task
#: that exited non-zero, a verdict. An errored build is Concourse unable to run
#: a step at all, so nothing was judged: Mykronos's `CheckRunReport` takes only
#: success, failure and cancelled, and cancelled is the one that says so.
HOOK_CONCLUSION = {"on_failure": "failure", "on_error": "cancelled"}


@pytest.mark.parametrize("hook", sorted(HOOK_CONCLUSION))
def test_every_lane_up_to_the_gate_reports_its_end(hook: str) -> None:
    jobs = _jobs()
    for name in sorted(VERIFYING | {GATE}):
        steps = jobs[name].get(hook, {}).get("do", [])
        assert steps, f"{name} has no {hook} hook"
        # No Slack hook since TheHub #61194: the red-main poll is the one
        # sender, and test_one_message_per_build fails on a hook that posts.
        assert all(step.get("task") != "notify-slack" for step in steps), f"{name}.{hook}"
        last = steps[-1]
        assert last.get("task") == TASK, f"{name}.{hook} does not end with {TASK}"
        params = last["params"]
        assert (params["JOB"], params["PHASE"], params["CONCLUSION"]) == (
            name,
            "end",
            HOOK_CONCLUSION[hook],
        ), f"{name}.{hook}"


def test_every_hook_conclusion_is_one_mykronos_accepts() -> None:
    """A value the schema refuses is a 422, and the check is left in progress."""
    from typing import get_args

    from mykronos.schemas import CheckRunReport

    # Literal["success", "failure", "cancelled"] | None
    accepted = {
        value
        for member in get_args(CheckRunReport.model_fields["conclusion"].annotation)
        for value in get_args(member)
        if isinstance(value, str)
    }
    sent = {
        step["params"]["CONCLUSION"]
        for step in _reporters(_doc()["jobs"])
        if "CONCLUSION" in step["params"]
    }
    assert sent == {"success", "failure", "cancelled"}
    assert sent <= accepted


def test_the_report_outlasts_a_slow_container_start() -> None:
    """personal-soc/iac #21: five minutes went to starting the hook's container,
    and the 5m cap killed it six seconds into its script, before it posted."""
    for step in _reporters(_doc()["jobs"]):
        value = str(step["timeout"])
        assert value.endswith("m") and int(value[:-1]) >= 10, step["timeout"]


def test_the_reporter_can_read_the_infra_marker() -> None:
    for step in _reporters(_doc()["jobs"]):
        inputs = {i["name"]: i for i in step["config"]["inputs"]}
        assert inputs.get("infra", {}).get("optional") is True


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
  printf '%s' "${CURL_BODY:-}"
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


def test_a_kept_failure_is_reported_as_kept_not_as_cancelled(tmp_path: Path) -> None:
    """TheHub #61842. Mykronos answers a cancelled against a stored failure
    with `unchanged`; the log must not say the check is now cancelled."""
    body = '{"name": "Concourse / personal-soc", "check_run_id": "1", "status": "completed",'
    body += ' "conclusion": "failure", "outcome": "unchanged"}'
    r = _run(tmp_path, SHA, JOB="iac", PHASE="end", CONCLUSION="cancelled", CURL_BODY=body)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "Mykronos left the check at 'failure'" in r.stdout
    assert "Reported end cancelled" not in r.stdout


def test_a_posted_end_is_reported_as_sent(tmp_path: Path) -> None:
    body = '{"conclusion": "cancelled", "outcome": "updated"}'
    r = _run(tmp_path, SHA, JOB="iac", PHASE="end", CONCLUSION="cancelled", CURL_BODY=body)

    assert r.returncode == 0, r.stdout + r.stderr
    assert f"Reported end cancelled for iac on {SHA}." in r.stdout


def test_a_refused_report_fails_the_step(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="guard", PHASE="start", CURL_RC="22")

    assert r.returncode != 0


@pytest.mark.parametrize("head", [None, "ref: refs/heads/main", "abc1234"])
def test_a_start_with_no_commit_to_name_fails_rather_than_guessing(
    tmp_path: Path, head: str | None
) -> None:
    r = _run(tmp_path, head, JOB="guard", PHASE="start")

    assert r.returncode != 0
    assert not (tmp_path / "body.json").exists()


@pytest.mark.parametrize("head", [None, "ref: refs/heads/main", "abc1234"])
def test_an_end_with_no_commit_says_so_and_never_guesses(tmp_path: Path, head: str | None) -> None:
    """TheHub #61769. A hook ends a lane that is already red; failing it too
    added a second red step that read as a second fault. It still posts
    nothing it cannot pin to a commit, and says exactly that."""
    r = _run(tmp_path, head, JOB="iac", PHASE="end", CONCLUSION="failure")

    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "body.json").exists()
    assert "no checked-out commit" in r.stdout
    assert "iac could not post 'failure'" in r.stdout
    assert "Nothing was posted" in r.stdout


def test_the_fetched_version_names_the_commit_when_head_does_not(tmp_path: Path) -> None:
    """The git resource writes the version it fetched to .git/ref."""
    git = tmp_path / "source" / ".git"
    git.mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git / "ref").write_text(SHA + "\n", encoding="utf-8")

    r = _run(tmp_path, None, JOB="iac", PHASE="end", CONCLUSION="failure")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert (body["commit_sha"], body["conclusion"]) == (SHA, "failure")


def _infra(tmp_path: Path) -> None:
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "reason").write_text(
        "INFRASTRUCTURE, NOT A VERDICT: checkov did not finish inside its 8m budget.\n",
        encoding="utf-8",
    )


def test_an_infrastructure_failure_is_a_cancelled_check(tmp_path: Path) -> None:
    _infra(tmp_path)
    r = _run(tmp_path, SHA, JOB="iac", PHASE="end", CONCLUSION="failure")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert body["conclusion"] == "cancelled"
    assert "8m budget" in r.stdout


def test_an_errored_build_is_a_cancelled_check(tmp_path: Path) -> None:
    r = _run(tmp_path, SHA, JOB="iac", PHASE="end", CONCLUSION="cancelled")

    assert r.returncode == 0, r.stdout + r.stderr
    body = json.loads((tmp_path / "body.json").read_text(encoding="utf-8"))
    assert body["conclusion"] == "cancelled"


_CURL_SEQ = """curl() {
  n=$(( $(cat "$CURL_COUNT" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$CURL_COUNT"
  while [ $# -gt 0 ]; do
    case "$1" in -d) printf '%s\\n' "$2" >> "$CAPTURE" ;; esac
    shift
  done
  eval "rc=\\${CURL_RC_$n:-0}"
  return "$rc"
}
"""


def _run_seq(tmp_path: Path, **params: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    sh = shutil.which("sh")
    assert sh, "sh is required to execute the reporter script"
    (tmp_path / "source" / ".git").mkdir(parents=True)
    (tmp_path / "source" / ".git" / "HEAD").write_text(SHA + "\n", encoding="utf-8")
    capture = tmp_path / "bodies.jsonl"
    r = subprocess.run(
        [sh, "-s"],
        input=_CURL_SEQ + _script(),
        env={
            **os.environ,
            "CAPTURE": str(capture),
            "CURL_COUNT": str(tmp_path / "curls"),
            "MYKRONOS_URL": "http://mykronos.test",
            "MYKRONOS_TOKEN": "tok",
            "REPO_FULL_NAME": "ToddGBenson/personal-soc",
            "JOB": "iac",
            "PHASE": "end",
            **params,
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    sent = (
        [json.loads(x)["conclusion"] for x in capture.read_text(encoding="utf-8").splitlines() if x]
        if capture.exists()
        else []
    )
    return r, sent


def test_a_mykronos_that_refuses_cancelled_gets_failure_not_silence(tmp_path: Path) -> None:
    """A 422 must not leave the check in progress."""
    r, sent = _run_seq(tmp_path, CONCLUSION="cancelled", CURL_RC_1="22")

    assert r.returncode == 0, r.stdout + r.stderr
    assert sent == ["cancelled", "failure"]


def test_an_unreachable_mykronos_still_fails_the_step(tmp_path: Path) -> None:
    r, sent = _run_seq(tmp_path, CONCLUSION="cancelled", CURL_RC_1="7")

    assert r.returncode == 7
    assert sent == ["cancelled"]


def test_a_refused_failure_is_never_retried(tmp_path: Path) -> None:
    r, sent = _run_seq(tmp_path, CONCLUSION="failure", CURL_RC_1="22")

    assert r.returncode == 22
    assert sent == ["failure"]


# -- the iac lane (TheHub #61769) ---------------------------------------------
#
# personal-soc/iac #21 and #23 spent their whole 15m installing git and an
# unpinned checkov on python:slim and were killed with no scan; #22 died in apt.
# Each then told the commit's check `failure`, though nothing was judged.


def _resources() -> dict[str, dict[str, Any]]:
    return {r["name"]: r for r in _doc()["resources"]}


def _iac_task() -> dict[str, Any]:
    (task,) = [s for s in _jobs()["iac"]["plan"] if s.get("task") == "checkov"]
    return task


def test_checkov_runs_on_a_digest_pinned_image() -> None:
    resource = _resources()["checkov"]
    assert resource["type"] == "registry-image"
    assert resource["source"]["repository"] == "bridgecrew/checkov"
    assert resource["version"] == {"digest": CHECKOV_DIGEST}
    assert _iac_task()["image"] == "checkov"
    gets = [s["get"] for s in _jobs()["iac"]["plan"] if "get" in s]
    assert "checkov" in gets


def test_checkov_is_the_version_the_other_iac_lanes_run() -> None:
    """One checkov version across the estate's iac lanes."""
    for name in ("mykronos.yml", "thehub.yml"):
        doc = yaml.safe_load((PIPELINE.parent / name).read_text(encoding="utf-8"))
        (other,) = [r for r in doc["resources"] if r["name"] == "checkov"]
        assert other["source"] == _resources()["checkov"]["source"], name


def test_the_iac_task_installs_neither_apt_packages_nor_the_scanner() -> None:
    script = _iac_task()["config"]["run"]["args"][-1]
    assert "apt-get" not in script
    assert "pip install" not in script


def test_checkov_has_a_budget_inside_the_task_cap() -> None:
    task = _iac_task()
    script = task["config"]["run"]["args"][-1]
    assert "timeout --kill-after=30s 8m" in script
    assert int(str(task["timeout"]).rstrip("m")) > 8
    assert "infra" in {o["name"] for o in task["config"]["outputs"]}


# Stubs for every tool the task (old or new) reaches for, so the script never
# touches the machine running the test: no `git config --global`, and no real
# apt or pip install. Run with `-e`, as Concourse runs it (`bash -ec`).
_IAC_STUBS = """checkov() { echo "checkov stub $*"; }
git() { :; }
python3() { echo 0; }
python() { :; }
pip() { :; }
apt-get() { :; }
timeout() { return "${TIMEOUT_RC:-0}"; }
"""


def _run_iac(tmp_path: Path, timeout_rc: int) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute the iac task")
    for d in ("source", "infra", "notify"):
        (tmp_path / d).mkdir()
    return subprocess.run(
        [bash, "-e", "-s"],
        input=_IAC_STUBS + _iac_task()["config"]["run"]["args"][-1],
        env={**os.environ, "TIMEOUT_RC": str(timeout_rc), "MYKRONOS_TOKEN": ""},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize("rc", [124, 137])
def test_a_scan_that_runs_out_of_time_is_an_infrastructure_fault(tmp_path: Path, rc: int) -> None:
    r = _run_iac(tmp_path, rc)

    assert r.returncode == 75, r.stdout + r.stderr
    reason = (tmp_path / "infra" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: checkov did not finish")
    assert "nothing on this commit was scanned or judged" in reason


def test_a_scan_that_finishes_leaves_no_marker(tmp_path: Path) -> None:
    """Whatever it found, or whether it wrote a report, is not an outage."""
    _run_iac(tmp_path, 0)

    assert not (tmp_path / "infra" / "reason").exists()
