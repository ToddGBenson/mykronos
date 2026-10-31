"""A GitHub outage during the uploader install is not a failed security gate (TheHub #61007).

thehub/containers #209 (TheHub 188c48ee) died in `pip install` of the mykronos
uploader: its `git clone` got "Failed to connect to github.com port 443 after
21067 ms". No scan ran, yet the job reported `trivy=failed`, TheHub opened
"Deploy stage 'trivy' failed", the GitHub check went red and the risk gate
stopped for that commit.

Two halves, both pinned here:

1. Every uploader install in every pipeline goes through ONE script, the
   `install_uploader` anchor: three attempts, 10s then 30s apart. Structural
   checks find any install that bypasses it; the script itself is EXECUTED with
   pip and sleep stubbed.
2. When the install still fails in a task that runs before its job judges
   anything, the job's hooks report `errored` (not `failed`) to TheHub and
   `cancelled` (not `failure`) to the check, saying no scan ran. The hooks are
   executed as they stand in thehub.yml.
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

from tests.test_hub_failure_reports_carry_reason import _hook
from tests.test_hub_failure_reports_carry_reason import _run as _run_hub_report

PIPELINES = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines"
FILES = ("mykronos.yml", "thehub.yml", "personal-soc.yml")
SPEC = "git+https://github.com/ToddGBenson/mykronos@"
CALL = 'bash -c "$MYKRONOS_INSTALL_UPLOADER"'
PARAM = "MYKRONOS_INSTALL_UPLOADER"

#: Textual call sites per file, not YAML task instances: an aliased `upload`
#: task is one site that several jobs run. Pinned so a site that quietly goes
#: back to its own pip line, or a new lane added without the call, is noticed.
CALL_SITES = {"mykronos.yml": 16, "thehub.yml": 17, "personal-soc.yml": 7}

#: The only tasks that may declare `infra`, and why each is safe: each runs
#: before anything in its job reaches a verdict, so a failed install there means
#: nothing was judged. A marker from an `upload` that follows a real failing
#: scan would launder that failure into an outage, so no upload is listed.
INFRA_TASKS = {
    ("thehub.yml", "containers", "derive-estate-images"),
    ("thehub.yml", "image-refresh", "plan"),
    # Since #1045 this job reports to TheHub; the install precedes pytest.
    ("thehub.yml", "functional-demo", "run-functional"),
}

#: TheHub #61106. These declare `infra` for a different fault, a pytest tier
#: killed for memory, and they may follow a verdict (unit uploads after its
#: tiers). So the output is mounted at a path the installer never writes - it
#: looks only for ./infra and ../infra - and only the task's own OOM block
#: fills it. Held by test_an_oom_task_hides_infra_from_the_installer and,
#: executed, by backend/tests/test_thehub_memory_guard.py.
OOM_TASKS = {
    ("thehub.yml", "unit", "pytest"),
    ("thehub.yml", "post-merge", "grade"),
}


def _text(name: str) -> str:
    return (PIPELINES / name).read_text(encoding="utf-8")


def _doc(name: str) -> dict[str, Any]:
    return yaml.safe_load(_text(name))


def _tasks(name: str) -> list[tuple[str, dict[str, Any]]]:
    found: list[tuple[str, dict[str, Any]]] = []

    def walk(node: Any, job: str) -> None:
        if isinstance(node, dict):
            if "task" in node and isinstance(node.get("config"), dict):
                found.append((job, node))
            for v in node.values():
                walk(v, job)
        elif isinstance(node, list):
            for v in node:
                walk(v, job)

    for job in _doc(name)["jobs"]:
        walk(job, job["name"])
    return found


def _script(task: dict[str, Any]) -> str:
    return str((task["config"].get("run") or {}).get("args", [""])[-1])


def _anchor(name: str) -> str:
    return str(_doc(name)["anchors"]["install_uploader"])


# -- every install goes through the one script --------------------------------


@pytest.mark.parametrize("name", FILES)
def test_no_task_installs_the_uploader_with_its_own_pip_line(name: str) -> None:
    """The anchor is the only place the git spec may be installed from."""
    for job, task in _tasks(name):
        script = _script(task)
        for line in script.splitlines():
            if "pip install" in line and SPEC in line:
                pytest.fail(
                    f"{name} {job}/{task['task']} installs the uploader directly, "
                    f"with no retry: {line.strip()!r}. Use {CALL}."
                )


@pytest.mark.parametrize("name", FILES)
def test_every_call_site_is_counted(name: str) -> None:
    calls = [
        line for line in _text(name).splitlines()
        if CALL in line and not line.lstrip().startswith("#")
    ]
    assert len(calls) == CALL_SITES[name]
    assert all(line.strip() == CALL for line in calls), "a call site is wrapped or chained"


@pytest.mark.parametrize("name", FILES)
def test_every_task_that_calls_the_installer_is_given_it(name: str) -> None:
    """A call with the param unset would run `bash -c ""`, install nothing and exit 0."""
    calls = [(j, t) for j, t in _tasks(name) if CALL in _script(t)]
    assert calls
    anchor = _anchor(name)
    for job, task in calls:
        params = task.get("params") or {}
        where = f"{name} {job}/{task['task']}"
        assert params.get(PARAM) == anchor, f"{where} does not pass {PARAM}"
        assert params.get("MYKRONOS_REF") == "((mykronos-ref))", where


def test_the_installer_is_one_text_in_every_pipeline() -> None:
    texts = {name: _anchor(name) for name in FILES}
    assert len(set(texts.values())) == 1, "install_uploader differs between pipeline files"


def test_the_installer_installs_the_pinned_ref_and_nothing_else() -> None:
    """The pin is not this story's to move (a stale mykronos-ref stops delivery)."""
    anchor = _anchor("thehub.yml")
    assert (
        '"mykronos @ git+https://github.com/ToddGBenson/mykronos@${MYKRONOS_REF}'
        '#subdirectory=backend"' in anchor
    )


# -- the script, executed ----------------------------------------------------

_STUBS = """pip() {
  n=$(( $(cat "$PIP_COUNT" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$PIP_COUNT"
  printf '%s\\n' "$*" >> "$PIP_ARGS"
  [ "$n" -ge "${PIP_OK_ON:-999}" ]
}
sleep() { printf '%s\\n' "$1" >> "$SLEEPS"; }
"""


def _install(tmp_path: Path, ok_on: int | None, *, infra: bool) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute the installer")
    if infra:
        (tmp_path / "infra").mkdir()
    env = {
        **os.environ,
        "MYKRONOS_REF": "v99",
        "PIP_COUNT": str(tmp_path / "count"),
        "PIP_ARGS": str(tmp_path / "args"),
        "SLEEPS": str(tmp_path / "sleeps"),
    }
    if ok_on is not None:
        env["PIP_OK_ON"] = str(ok_on)
    return subprocess.run(
        [bash, "-s"], input=_STUBS + _anchor("thehub.yml"), env=env, cwd=tmp_path,
        capture_output=True, text=True, timeout=30,
    )


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").split() if path.exists() else []


def test_a_first_attempt_that_works_does_not_wait(tmp_path: Path) -> None:
    r = _install(tmp_path, ok_on=1, infra=True)

    assert r.returncode == 0, r.stderr
    assert _lines(tmp_path / "count") == ["1"]
    assert _lines(tmp_path / "sleeps") == []
    assert not (tmp_path / "infra" / "reason").exists()
    (args,) = (tmp_path / "args").read_text(encoding="utf-8").splitlines()
    assert args == (
        "install --quiet mykronos @ git+https://github.com/ToddGBenson/mykronos@v99"
        "#subdirectory=backend"
    )


def test_a_21_second_outage_is_ridden_out_by_the_retry(tmp_path: Path) -> None:
    """containers #209's outage: the third attempt, 40s later, gets through."""
    r = _install(tmp_path, ok_on=3, infra=True)

    assert r.returncode == 0, r.stderr
    assert _lines(tmp_path / "count") == ["3"]
    assert _lines(tmp_path / "sleeps") == ["10", "30"]
    assert not (tmp_path / "infra" / "reason").exists()


def test_an_install_that_never_works_is_an_infrastructure_fault(tmp_path: Path) -> None:
    r = _install(tmp_path, ok_on=None, infra=True)

    assert r.returncode == 75, r.stderr  # EX_TEMPFAIL, not a scanner's exit
    assert _lines(tmp_path / "count") == ["3"]
    assert _lines(tmp_path / "sleeps") == ["10", "30"]
    reason = (tmp_path / "infra" / "reason").read_text(encoding="utf-8")
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT")
    assert "no scan ran" in reason and "v99" in reason
    assert "no scan ran" in r.stderr


def test_a_task_without_the_infra_output_writes_no_marker(tmp_path: Path) -> None:
    """Undeclared means not safe to downgrade: the step fails, the report says failed."""
    r = _install(tmp_path, ok_on=None, infra=False)

    assert r.returncode == 75
    assert not (tmp_path / "infra").exists()


# -- who may say "infrastructure" ---------------------------------------------


def test_only_tasks_before_any_verdict_declare_infra() -> None:
    declared = {
        (name, job, task["task"])
        for name in FILES
        for job, task in _tasks(name)
        if any(o.get("name") == "infra" for o in task["config"].get("outputs") or [])
    }
    assert declared == INFRA_TASKS | OOM_TASKS


@pytest.mark.parametrize("name,job,task_name", sorted(OOM_TASKS))
def test_an_oom_task_hides_infra_from_the_installer(name: str, job: str, task_name: str) -> None:
    task = next(t for j, t in _tasks(name) if j == job and t["task"] == task_name)
    (out,) = [o for o in task["config"]["outputs"] if o.get("name") == "infra"]
    path = str(out.get("path") or "infra").strip("./")
    assert path not in ("infra", ""), f"{job}/{task_name} mounts infra where the installer writes"
    assert "/" not in path


@pytest.mark.parametrize("name,job,task_name", sorted(INFRA_TASKS))
def test_an_infra_task_installs_before_its_job_has_scanned(
    name: str, job: str, task_name: str
) -> None:
    """Nothing before it in the plan is a scan, and the install is how it starts."""
    plan = next(j for j in _doc(name)["jobs"] if j["name"] == job)["plan"]
    index = next(i for i, s in enumerate(plan) if s.get("task") == task_name)
    for step in plan[:index]:
        assert "ensure" not in step, f"{job}: a step before {task_name} has an ensure"
        if "task" in step:
            assert SPEC not in _script(step) and CALL not in _script(step), step["task"]
            assert "upload" not in _script(step), f"{job}: {step['task']} uploads a verdict"
    assert CALL in _script(plan[index])


def test_every_thehub_reporter_can_read_the_marker() -> None:
    for job, task in _tasks("thehub.yml"):
        if task["task"] in ("report-to-hub", "report-check-run"):
            inputs = {i["name"]: i for i in task["config"]["inputs"]}
            assert inputs.get("infra", {}).get("optional") is True, (
                f"{job}/{task['task']} does not mount the optional infra input"
            )


# -- TheHub hears `errored`, with the reason ---------------------------------


def _marker(tmp_path: Path) -> str:
    reason = (
        "INFRASTRUCTURE, NOT A VERDICT: the mykronos uploader could not be installed "
        "from GitHub at v99 after 3 attempts, so no scan ran to a verdict."
    )
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "reason").write_text(reason + "\n", encoding="utf-8")
    return reason


@pytest.mark.parametrize("job", sorted({j for _f, j, _t in INFRA_TASKS}))
def test_an_install_outage_reports_errored_to_thehub_not_failed(tmp_path: Path, job: str) -> None:
    reason = _marker(tmp_path)

    (body,) = _run_hub_report(tmp_path, _hook(job, "failed"))

    assert body["status"] == "errored", body
    assert body["exit_code"] == 75
    assert body["log_tail"].startswith(reason)
    assert f"/teams/main/pipelines/thehub/jobs/{job}" in body["log_tail"]
    if "meta" in body:  # the real jq; the fallback stub builds no meta
        assert body["meta"]["infrastructure"] is True


def test_a_real_trivy_failure_still_reports_failed(tmp_path: Path) -> None:
    (body,) = _run_hub_report(tmp_path, _hook("containers", "failed"))

    assert body["status"] == "failed"
    assert body["exit_code"] == 1
    if "meta" in body:
        assert "infrastructure" not in body["meta"]


def test_an_empty_marker_downgrades_nothing(tmp_path: Path) -> None:
    """Concourse makes the output volume before the task runs; empty is the success case."""
    (tmp_path / "infra").mkdir()

    (body,) = _run_hub_report(tmp_path, _hook("containers", "failed"))

    assert body["status"] == "failed"


@pytest.mark.parametrize("status", ["success", "aborted"])
def test_only_a_failure_is_ever_downgraded(tmp_path: Path, status: str) -> None:
    _marker(tmp_path)

    (body,) = _run_hub_report(tmp_path, _hook("containers", status))

    assert body["status"] == status
    assert "log_tail" not in body


# -- the GitHub check says `cancelled`, not `failure` -------------------------

SHA = "0123456789abcdef0123456789abcdef01234567"

_CURL = """curl() {
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


def _check_script() -> str:
    for _job, task in _tasks("thehub.yml"):
        if task["task"] == "report-check-run":
            return _script(task)
    pytest.fail("no report-check-run task in thehub.yml")


def _run_check(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("sh is required to execute the check reporter")
    (tmp_path / "source" / ".git").mkdir(parents=True)
    (tmp_path / "source" / ".git" / "HEAD").write_text(SHA + "\n", encoding="utf-8")
    capture = tmp_path / "bodies.jsonl"
    r = subprocess.run(
        [sh, "-s"], input=_CURL + _check_script(), cwd=tmp_path,
        env={
            **os.environ,
            "CAPTURE": str(capture),
            "CURL_COUNT": str(tmp_path / "curls"),
            "MYKRONOS_URL": "http://mykronos.test",
            "MYKRONOS_TOKEN": "tok",
            "REPO_FULL_NAME": "ToddGBenson/TheHub",
            "JOB": "containers",
            "PHASE": "end",
            "CONCLUSION": "failure",
            **env,
        },
        capture_output=True, text=True, timeout=30,
    )
    bodies = (
        [json.loads(x) for x in capture.read_text(encoding="utf-8").splitlines() if x]
        if capture.exists()
        else []
    )
    return r, bodies


def test_an_install_outage_is_a_cancelled_check(tmp_path: Path) -> None:
    _marker(tmp_path)

    r, bodies = _run_check(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    assert [b["conclusion"] for b in bodies] == ["cancelled"]
    assert "no scan ran" in r.stdout


def test_a_real_failure_is_still_a_failure_check(tmp_path: Path) -> None:
    r, bodies = _run_check(tmp_path)

    assert r.returncode == 0, r.stdout + r.stderr
    assert [b["conclusion"] for b in bodies] == ["failure"]


def test_a_mykronos_that_refuses_cancelled_gets_failure_not_silence(tmp_path: Path) -> None:
    """Until the backend half deploys, a 422 must not leave the check in progress."""
    _marker(tmp_path)

    r, bodies = _run_check(tmp_path, CURL_RC_1="22")

    assert r.returncode == 0, r.stdout + r.stderr
    assert [b["conclusion"] for b in bodies] == ["cancelled", "failure"]


def test_an_unreachable_mykronos_still_fails_the_step(tmp_path: Path) -> None:
    """Only an HTTP refusal earns the fallback; no answer at all is red, as before."""
    _marker(tmp_path)

    r, bodies = _run_check(tmp_path, CURL_RC_1="7")

    assert r.returncode == 7
    assert [b["conclusion"] for b in bodies] == ["cancelled"]
