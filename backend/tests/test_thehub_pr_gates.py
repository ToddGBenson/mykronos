"""`pr-gates`: the deploy's own gates on every TheHub pull request (TheHub #61102).

Deploy 6722 failed at harden_pip_audit after merge and 6719 rolled back on the
pipeline-mirror tests. This job finds open pull request heads, runs TheHub's
scripts/pr_deploy_gates.sh on one per tick, and reports `Concourse / thehub` on
that head.

The pick script and the two report anchors are EXECUTED as they stand in the
pipeline, with the network stubbed, rather than grepped for words.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
import yaml

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "pr-gates"
DEVELOP_TIP = "d" * 40
OPEN_HEAD = "a" * 40
OLDER_HEAD = "b" * 40
FORK_HEAD = "f" * 40
CLOSED_HEAD = "c" * 40


def _doc() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _job() -> dict[str, Any]:
    return next(j for j in _doc()["jobs"] if j["name"] == JOB)


def _step(task: str) -> dict[str, Any]:
    return next(s for s in _job()["plan"] if s.get("task") == task)


def _hooks() -> list[dict[str, Any]]:
    job = _job()
    return [s for hook in ("on_success", "on_failure", "on_error", "on_abort")
            for s in job.get(hook, {}).get("do", [])]


# -- shape ------------------------------------------------------------------


def test_it_runs_on_a_clock_because_no_resource_sees_a_pull_request() -> None:
    plan = _job()["plan"]
    assert plan[0] == {"get": "ten-minutes", "trigger": True, "attempts": 3}
    timer = next(r for r in _doc()["resources"] if r["name"] == "ten-minutes")
    assert timer["type"] == "time" and timer["source"]["interval"] == "10m"


def test_the_code_under_review_gets_no_credential() -> None:
    """The gates task runs the pull request's own code. It is handed a pip
    cache path and nothing else: no deploy key, no ingestion or Hub token."""
    gates = _step("gates")
    assert gates["params"] == {"PIP_CACHE_DIR": "/pipcache"}
    assert "((" not in json.dumps(gates["config"])


def test_the_gates_are_thehubs_script_not_a_copy_here() -> None:
    """The policy lives beside the deploy that enforces it. This file only
    finds the head and reports, so it cannot drift from deploy.sh."""
    script = _step("gates")["config"]["run"]["args"][-1]
    assert 'bash pr/scripts/pr_deploy_gates.sh --mykronos "$PWD/live-pipeline"' in script
    assert "pip-audit" not in script


def test_the_live_definition_is_not_named_pipelines() -> None:
    """hub_report reads an input called `pipelines` as "this job applied a
    pipeline" and files a self-contained run with a `finish` stage."""
    gets = [s for s in _job()["plan"] if "get" in s]
    assert {"get": "live-pipeline", "resource": "pipelines", "attempts": 3} in gets
    assert not any(s["get"] == "pipelines" for s in gets)


def test_every_report_is_about_the_pull_request_head() -> None:
    reports = [s for s in _hooks() if s.get("task") in ("report-to-hub", "report-check-run")]
    assert len(reports) == 6
    for step in reports + [_job()["plan"][-1]]:
        assert step.get("input_mapping") == {"source": "pr"}, step.get("task")


def test_hub_reports_say_pull_request_and_need_a_judged_commit() -> None:
    """Not `develop`/`prod`: a red PR must not read as a red develop lane."""
    hub = [s for s in _hooks() if s.get("task") == "report-to-hub"]
    assert {s["params"]["STATUS"] for s in hub} == {"success", "failed", "errored", "aborted"}
    for step in hub:
        assert step["params"]["STAGE"] == "pr_gates"
        assert step["params"]["TARGET_ENV"] == "pull-request"
        assert step["params"]["SCANNED_BRANCH"] == "pull-request"
        assert step["params"]["REQUIRE_SOURCE"] == "1"


def test_success_is_reported_last_and_only_for_a_judged_head() -> None:
    last = _job()["plan"][-1]
    assert last["task"] == "report-check-run"
    assert last["params"]["PHASE"] == "end"
    assert last["params"]["CONCLUSION"] == "success"
    assert last["params"]["NO_COMMIT_OK"] == "1"
    for step in _hooks():
        assert "NO_COMMIT_OK" not in (step.get("params") or {}), "a failure must not be swallowed"


# -- the pick, executed ----------------------------------------------------


def _pick_script() -> str:
    script = _step("pick")["config"]["run"]["args"][-1]
    body = re.search(r"python3 - <<'PICK'\n(.*?)\nPICK\n", script, re.S)
    assert body, "the pick's python heredoc moved"
    return textwrap.dedent(body.group(1))


class _Mykronos(BaseHTTPRequestHandler):
    answers: dict[str, dict[str, Any]] = {}
    posted: list[dict[str, Any]] = []

    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).posted.append({"path": self.path, "auth": self.headers["Authorization"], **body})
        created = {"outcome": "created", "status": "in_progress", "conclusion": None}
        answer = type(self).answers.get(body["commit_sha"], created)
        data = json.dumps({"name": "Concourse / thehub", "check_run_id": "1", **answer}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def mykronos():
    _Mykronos.answers, _Mykronos.posted = {}, []
    server = HTTPServer(("127.0.0.1", 0), _Mykronos)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", _Mykronos
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


REFS = "\n".join([
    f"{DEVELOP_TIP}\trefs/heads/develop",
    f"{OPEN_HEAD}\trefs/heads/feat/newer",
    f"{OLDER_HEAD}\trefs/heads/feat/older",
    f"{CLOSED_HEAD}\trefs/heads/feat/closed",
    f"{OLDER_HEAD}\trefs/pull/10/head", f"{'1' * 40}\trefs/pull/10/merge",
    f"{OPEN_HEAD}\trefs/pull/12/head", f"{'2' * 40}\trefs/pull/12/merge",
    f"{CLOSED_HEAD}\trefs/pull/13/head",
    f"{FORK_HEAD}\trefs/pull/14/head", f"{'4' * 40}\trefs/pull/14/merge",
    f"{DEVELOP_TIP}\trefs/pull/15/head", f"{'5' * 40}\trefs/pull/15/merge",
]) + "\n"


def _unchanged(status: str, conclusion: str | None) -> dict[str, Any]:
    """Mykronos's answer to a start on a head that already has a check run."""
    return {"outcome": "unchanged", "status": status, "conclusion": conclusion}


def _pick(tmp_path: Path, url: str) -> tuple[str, str]:
    (tmp_path / "memo").mkdir(exist_ok=True)
    (tmp_path / "refs").write_text(REFS, encoding="utf-8")
    env = {**os.environ, "PR_REFS": str(tmp_path / "refs"), "PR_PICK": str(tmp_path / "pick"),
           "THEHUB_BRANCH": "develop", "MYKRONOS_URL": url, "MYKRONOS_TOKEN": "tok",
           "REPO_FULL_NAME": "ToddGBenson/TheHub"}
    r = subprocess.run([sys.executable, "-I", "-c", _pick_script()], env=env, cwd=tmp_path,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
    return (tmp_path / "pick").read_text(encoding="utf-8"), r.stdout


def test_the_newest_open_same_repo_head_is_judged_first(tmp_path, mykronos) -> None:
    url, server = mykronos
    pick, out = _pick(tmp_path, url)

    assert pick == f"12 {OPEN_HEAD}\n"
    assert [p["commit_sha"] for p in server.posted] == [OPEN_HEAD]
    assert server.posted[0] == {
        "path": "/api/ingest/check-runs", "auth": "Bearer tok",
        "repo_full_name": "ToddGBenson/TheHub", "commit_sha": OPEN_HEAD,
        "job": "pr-gates", "phase": "start", "conclusion": None,
    }
    assert "#14" in out and "fork" in out


def test_a_fork_a_closed_pr_and_a_develop_commit_are_never_judged(tmp_path, mykronos) -> None:
    url, server = mykronos
    server.answers = {s: _unchanged("completed", "success") for s in (OPEN_HEAD, OLDER_HEAD)}
    pick, _ = _pick(tmp_path, url)

    assert pick == ""
    asked = {p["commit_sha"] for p in server.posted}
    assert asked == {OPEN_HEAD, OLDER_HEAD}
    assert not asked & {FORK_HEAD, CLOSED_HEAD, DEVELOP_TIP}


def test_a_judged_head_is_remembered_and_not_asked_again(tmp_path, mykronos) -> None:
    url, server = mykronos
    server.answers = {OPEN_HEAD: _unchanged("completed", "failure")}
    pick, _ = _pick(tmp_path, url)
    assert pick == f"10 {OLDER_HEAD}\n"

    server.posted.clear()
    pick, _ = _pick(tmp_path, url)
    assert pick == f"10 {OLDER_HEAD}\n"
    assert [p["commit_sha"] for p in server.posted] == [OLDER_HEAD]


def test_a_head_that_could_not_be_judged_is_judged_again(tmp_path, mykronos) -> None:
    """`cancelled` means the run never reached a verdict (#61007)."""
    url, server = mykronos
    server.answers = {OPEN_HEAD: _unchanged("completed", "cancelled")}
    pick, _ = _pick(tmp_path, url)
    assert pick == f"12 {OPEN_HEAD}\n"


def test_a_run_that_died_mid_judgement_is_resumed(tmp_path, mykronos) -> None:
    url, server = mykronos
    server.answers = {OPEN_HEAD: _unchanged("in_progress", None)}
    pick, _ = _pick(tmp_path, url)
    assert pick == f"12 {OPEN_HEAD}\n"


def test_the_fetch_is_by_the_sha_the_check_was_started_on() -> None:
    script = _step("pick")["config"]["run"]["args"][-1]
    assert 'git -C pr fetch -q --depth 1 "$REPO_URI" "$SHA"' in script
    assert 'test "$(git -C pr rev-parse HEAD)" = "$SHA"' in script


# -- the two anchor guards, executed --------------------------------------


def _anchor_script(task: str) -> str:
    step = next(s for s in _hooks() if s.get("task") == task)
    return step["config"]["run"]["args"][-1]


def test_a_tick_that_judged_nothing_reports_nothing_to_github(tmp_path) -> None:
    sh = shutil.which("sh")
    if not sh:
        pytest.skip("sh is required")
    stub = 'curl() { echo CURL >> "$CAPTURE"; }\n'
    env = {**os.environ, "CAPTURE": str(tmp_path / "c"), "MYKRONOS_URL": "http://x",
           "MYKRONOS_TOKEN": "t", "REPO_FULL_NAME": "ToddGBenson/TheHub",
           "JOB": JOB, "PHASE": "end", "CONCLUSION": "success"}
    script = stub + _anchor_script("report-check-run")

    quiet = subprocess.run([sh, "-s"], input=script, env={**env, "NO_COMMIT_OK": "1"},
                           cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert quiet.returncode == 0, quiet.stdout + quiet.stderr
    assert not (tmp_path / "c").exists()

    loud = subprocess.run([sh, "-s"], input=script, env=env,
                          cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert loud.returncode != 0, "without the flag, no commit is still a failure"


def test_a_tick_that_judged_nothing_files_nothing_in_thehub(tmp_path) -> None:
    """Without REQUIRE_SOURCE the anchor's no-`source` branch would file a
    pipeline-apply run with a `finish` stage, every ten minutes."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required")
    stubs = ('apt-get() { :; }\ngit() { return 1; }\n'
             'curl() { echo CURL >> "$CAPTURE"; }\njq() { echo "{}"; }\n')
    script = _anchor_script("report-to-hub").replace(
        "/etc/apt/apt.conf.d/99force-ipv4", (tmp_path / "apt.conf").as_posix())
    env = {**os.environ, "CAPTURE": str(tmp_path / "c"), "HUB_URL": "http://hub.test",
           "HUB_DEPLOY_TOKEN": "t", "STAGE": "pr_gates", "STATUS": "success",
           "SCANNED_BRANCH": "pull-request"}

    quiet = subprocess.run([bash, "-s"], input=stubs + script, env={**env, "REQUIRE_SOURCE": "1"},
                           cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert quiet.returncode == 0, quiet.stdout + quiet.stderr
    assert not (tmp_path / "c").exists(), quiet.stdout

    loud = subprocess.run([bash, "-s"], input=stubs + script, env=env,
                          cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert (tmp_path / "c").exists(), "the control: without the flag the anchor posts"
    assert loud.returncode == 0
