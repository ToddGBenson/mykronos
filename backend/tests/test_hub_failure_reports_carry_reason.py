"""Every failure report TheHub's pipeline sends carries `exit_code` and `log_tail` (#336).

The `report-to-hub` hook never populated either for any stage: TheHub measured
1 of 886 Concourse events carrying output, and thirty consecutive deploy-demo
failures (`curl: (22) ... 410`) left their reason only in a build log nothing
else reads.

These EXECUTE the hook script as it stands in thehub.yml -- with the params a
real call site resolves to, and apt-get/git/curl stubbed (jq too, when the host
has none) -- rather than asserting that words are present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

FAILURE = ("failed", "errored")


def _pipeline() -> Path:
    for parent in Path(__file__).resolve().parents:
        p = parent / "deploy" / "concourse" / "pipelines" / "thehub.yml"
        if p.is_file():
            return p
    pytest.fail("deploy/concourse/pipelines/thehub.yml not found above this test")


def _doc() -> dict:
    return yaml.safe_load(_pipeline().read_text(encoding="utf-8"))


def _walk(node, job, found, pred):
    if isinstance(node, dict):
        if pred(node):
            found.append((job, node))
        for v in node.values():
            _walk(v, job, found, pred)
    elif isinstance(node, list):
        for v in node:
            _walk(v, job, found, pred)


def _hub_reports() -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    for job in _doc()["jobs"]:
        _walk(job, job["name"], found, lambda n: n.get("task") == "report-to-hub")
    assert len(found) > 80, f"expected the ~88 report-to-hub hooks, found {len(found)}"
    return found


def _failure_reports() -> list[tuple[str, dict]]:
    out = [(j, h) for j, h in _hub_reports() if (h.get("params") or {}).get("STATUS") in FAILURE]
    assert out, "no failure reports found"
    return out


# -- structure ---------------------------------------------------------------


def test_every_failure_report_names_its_own_job_and_the_link_metadata():
    for job, hook in _failure_reports():
        p = hook["params"]
        assert p.get("JOB") == job, f"{job}: failure report passes JOB={p.get('JOB')!r}"
        assert p.get("PIPELINE") == "thehub" and p.get("TEAM") == "main"
        assert str(p.get("CONCOURSE_URL", "")).startswith("http")
        assert "HUB_URL" in p and "HUB_DEPLOY_TOKEN" in p, (
            f"{job}: step params replaced the credentials instead of merging"
        )


def test_every_report_hook_can_read_a_task_written_log():
    for job, hook in _hub_reports():
        inputs = {i["name"]: i for i in hook["config"]["inputs"]}
        assert inputs.get("hub_log", {}).get("optional") is True, (
            f"{job}: report-to-hub does not mount the optional hub_log input"
        )


def test_every_other_inline_report_sends_exit_code_and_log_tail_on_failure():
    """Scripts that POST to /api/ops/deploys themselves, outside the anchor."""
    found: list[tuple[str, dict]] = []
    for job in _doc()["jobs"]:
        _walk(
            job,
            job["name"],
            found,
            lambda n: n.get("task") not in (None, "report-to-hub") and "config" in n,
        )
    inline = [
        (j, t)
        for j, t in found
        if "/api/ops/deploys" in str(t["config"].get("run", {}).get("args", ""))
    ]
    assert inline, "expected at least the post-merge verdict reporter"
    for job, task in inline:
        script = task["config"]["run"]["args"][-1]
        assert "exit_code" in script and "log_tail" in script, (
            f"{job}/{task['task']} reports to TheHub without exit_code and log_tail"
        )


# -- behaviour: run the hook --------------------------------------------------

_FAKE_JQ = r"""
import json, sys
args = sys.argv[1:]
null_input = False
vars_ = {}
filt = None
i = 0
while i < len(args):
    a = args[i]
    if a.startswith("-") and a not in ("--arg", "--argjson") and not a.startswith("--"):
        null_input = null_input or "n" in a
        i += 1
    elif a in ("--arg", "--argjson"):
        vars_[args[i + 1]] = args[i + 2] if a == "--arg" else json.loads(args[i + 2])
        i += 3
    else:
        filt = a
        i += 1
if null_input:
    # Only the anchor's object constructors use -n; their shape is not under
    # test here, so a faithful-enough object is built from the named vars.
    print(json.dumps({"stage": vars_.get("s"), "status": vars_.get("st"),
                      "deploy_id": vars_.get("d")}))
else:
    assert filt.strip() == ". + {exit_code: $ec, log_tail: $lt}", filt
    doc = json.loads(sys.stdin.read())
    doc.update(exit_code=vars_["ec"], log_tail=vars_["lt"])
    print(json.dumps(doc))
"""


def _stubs(tmp_path: Path) -> str:
    s = """apt-get() { :; }
git() {
  case "$*" in
    *rev-parse*) echo 0123456789abcdef0123456789abcdef01234567 ;;
    *log*) echo "feat: a thing (#1)" ;;
  esac
}
curl() {
  while [ $# -gt 0 ]; do
    case "$1" in -d) printf '%s\\n' "$2" >> "$CAPTURE"; shift ;; esac
    shift
  done
}
"""
    if not shutil.which("jq"):
        fake = tmp_path / "fakejq.py"
        fake.write_text(_FAKE_JQ, encoding="utf-8")
        s += f'jq() {{ "{Path(sys.executable).as_posix()}" "{fake.as_posix()}" "$@"; }}\n'
    return s


def _run(tmp_path: Path, hook: dict) -> list[dict]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute the report hook")
    script = hook["config"]["run"]["args"][-1]
    apt_conf = "/etc/apt/apt.conf.d/99force-ipv4"
    assert apt_conf in script
    script = script.replace(apt_conf, (tmp_path / "apt.conf").as_posix())
    capture = tmp_path / "posted.jsonl"
    params = {k: str(v) for k, v in (hook.get("params") or {}).items()}
    params.update(HUB_URL="http://hub.test", HUB_DEPLOY_TOKEN="t")
    env = {**os.environ, **params, "CAPTURE": str(capture)}
    r = subprocess.run(
        [bash, "-s"],
        input=_stubs(tmp_path) + script,
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert capture.exists(), f"nothing was posted: {r.stdout}{r.stderr}"
    return [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines() if line]


def _hook(job: str, status: str) -> dict:
    for j, h in _hub_reports():
        if j == job and h["params"].get("STATUS") == status:
            return h
    pytest.fail(f"no {status} report in {job}")


def test_a_failed_deploy_reports_the_tasks_real_exit_code_and_its_last_60_lines(tmp_path):
    log = tmp_path / "hub_log"
    log.mkdir()
    (log / "output.log").write_bytes(
        (
            "".join(f"line {n}\n" for n in range(1, 101))
            + "curl: (22) The requested URL returned error: 410\n"
        ).encode()
    )
    (log / "exit_code").write_text("22\n", encoding="utf-8")
    (body,) = _run(tmp_path, _hook("deploy-demo", "failed"))
    assert body["exit_code"] == 22
    tail = body["log_tail"]
    assert "http://localhost:8080/teams/main/pipelines/thehub/jobs/deploy-demo" in tail
    assert "410" in tail and "line 100" in tail
    assert "line 41\n" not in tail, "more than the last 60 lines were sent"
    assert "line 42\n" in tail


@pytest.mark.parametrize("job,status", [(j, h["params"]["STATUS"]) for j, h in _failure_reports()])
def test_every_failure_report_carries_exit_code_and_log_tail(tmp_path, job, status):
    """No hub_log at all -- the common case: exit_code 1 and the job link."""
    bodies = _run(tmp_path, _hook(job, status))
    for body in bodies:  # set-pipeline also posts its own `finish`
        assert body["exit_code"] == 1, body
        assert f"/teams/main/pipelines/thehub/jobs/{job}" in body["log_tail"], body


def test_a_zero_exit_code_on_disk_is_not_reported_for_a_failure(tmp_path):
    """The instrumented task succeeded and a later step failed the job."""
    log = tmp_path / "hub_log"
    log.mkdir()
    (log / "exit_code").write_text("0\n", encoding="utf-8")
    (body,) = _run(tmp_path, _hook("deploy-demo", "failed"))
    assert body["exit_code"] == 1


@pytest.mark.parametrize("status", ["success", "aborted"])
def test_non_failure_reports_are_unchanged(tmp_path, status):
    log = tmp_path / "hub_log"
    log.mkdir()
    (log / "exit_code").write_text("3\n", encoding="utf-8")
    (body,) = _run(tmp_path, _hook("deploy-demo", status))
    assert "exit_code" not in body and "log_tail" not in body


# -- the deploy task writes what the hook reads -------------------------------


def test_request_deploy_tees_its_output_and_records_its_exit_code(tmp_path):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required")
    job = next(j for j in _doc()["jobs"] if j["name"] == "deploy-demo")
    task = next(s for s in job["plan"] if s.get("task") == "request-deploy")
    assert {"name": "hub_log"} in task["config"]["outputs"]
    script = task["config"]["run"]["args"][-1]
    # The prologue only: everything up to and including the trap.
    head = script[: script.index("\n", script.index("trap '")) + 1]
    (tmp_path / "hub_log").mkdir()
    r = subprocess.run(
        [bash, "-s"],
        input=head + "echo before\necho 'mc: 410 Gone' >&2\nexit 22\n",
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 22
    assert (tmp_path / "hub_log" / "exit_code").read_text().strip() == "22"
    out = (tmp_path / "hub_log" / "output.log").read_text()
    assert "before" in out and "410 Gone" in out
    assert "before" in r.stdout, "the build log itself must still show the output"
