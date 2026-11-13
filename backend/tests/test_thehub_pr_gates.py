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
    """The gates task runs the pull request's own code. It is handed nothing:
    no deploy key, no ingestion or Hub token, and since TheHub #61113 no pip
    cache either."""
    gates = _step("gates")
    assert not gates.get("params")
    assert "((" not in json.dumps(gates["config"])


def test_the_gates_are_thehubs_script_not_a_copy_here() -> None:
    """The policy lives beside the deploy that enforces it. This file only
    finds the head and reports, so it cannot drift from deploy.sh."""
    script = _step("gates")["config"]["run"]["args"][-1]
    # [TheHub #61113] The base branch's copy of it, not the head's.
    assert 'bash "$JUDGE/scripts/pr_deploy_gates.sh" --mykronos "$PWD/live-pipeline"' in script
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


# -- the cheap integration tier (TheHub #61110) ------------------------------
#
# #61102 deferred its AC3: the deploy's integration tier needs Postgres with
# pgvector and the entrypoint's schema build, and a cold install alone overran
# a pull request check's 10 minutes. So the job runs TheHub's
# `scripts/ci/container-tiers.sh <pr> subset` inside a CACHED image -- the
# newest develop commit `build` pushed an image for, dependencies preinstalled
# -- and TheHub's script lays the pull request's backend/ over it and runs only
# config/ci/pr-integration-subset.txt.

INTEGRATION_PARAMS = {"CONTAINER_TIERS_DISPOSABLE", "TIER_SOFT_TIMEOUT_S", "MEMORY_GUARD",
                      "MEMORY_BUDGET_MB"}


def _memory_guard_anchor() -> str:
    """The `memory_guard` anchor's text, as `unit` and `container-tiers` are given it."""
    tiers = next(j for j in _doc()["jobs"] if j["name"] == "container-tiers")
    task = next(s for s in tiers["plan"] if s.get("task") == "tiers")
    guard: str = task["params"]["MEMORY_GUARD"]
    return guard


def test_the_cached_image_is_the_newest_develop_commit_build_pushed() -> None:
    """Not the pull request's image (it has none) and not a moving tag: the
    develop commit that most recently passed `build`, which pushed
    registry/thehub:<sha>. Not a trigger: a develop commit is not a pull
    request, and the clock already decides when this runs."""
    plan = _job()["plan"]
    built = next(s for s in plan if s.get("get") == "built")
    assert built["resource"] == "source"
    assert built["passed"] == ["build"]
    assert not built.get("trigger")
    pick = _step("pick")
    assert {"name": "built"} in pick["config"]["inputs"]
    assert {"name": "image"} in pick["config"]["outputs"]
    assert "git -C built rev-parse HEAD" in pick["config"]["run"]["args"][-1]
    load = next(s for s in plan if s.get("load_var") == "image_sha")
    assert load["file"] == "image/sha" and load["format"] == "raw"
    assert plan.index(load) > plan.index(pick)


def test_the_integration_subset_runs_in_that_image() -> None:
    task = _step("integration")
    image = task["config"]["image_resource"]
    assert image["type"] == "registry-image"
    assert image["source"] == {"repository": "((registry))/thehub", "tag": "((.:image_sha))",
                               "insecure": True}
    plan = _job()["plan"]
    load = next(s for s in plan if s.get("load_var") == "image_sha")
    assert plan.index(load) < plan.index(task) < len(plan) - 1, (
        "after the image is resolved, and before the success report"
    )


def test_the_subset_is_thehubs_tier_not_a_list_here() -> None:
    script = _step("integration")["config"]["run"]["args"][-1]
    assert "bash pr/scripts/ci/container-tiers.sh pr subset" in script
    assert "tests/integration/" not in script, "the list lives in TheHub, beside the deploy"


def test_the_integration_task_gets_no_credential() -> None:
    """It runs the pull request's code, as `gates` does."""
    task = _step("integration")
    assert set(task["params"]) == INTEGRATION_PARAMS
    config = {k: v for k, v in task["config"].items() if k != "image_resource"}
    assert "((" not in json.dumps(config)
    assert "((" not in json.dumps({k: v for k, v in task["params"].items() if k != "MEMORY_GUARD"})
    assert [i["name"] for i in task["config"]["inputs"]] == ["pr"]


def test_it_runs_in_the_memory_group_under_the_guard() -> None:
    """#61106: never beside `unit`, `post-merge` or `container-tiers`, and a
    memory kill says errored rather than failed."""
    assert set(_job()["serial_groups"]) == {"dast", "pytest-memory"}
    task = _step("integration")
    assert task["params"]["MEMORY_GUARD"] == _memory_guard_anchor()
    budget = int(task["params"]["MEMORY_BUDGET_MB"])
    assert budget == 2304, "container-tiers' budget: Postgres shares it"
    assert {"name": "infra", "path": "memory-infra"} in task["config"]["outputs"]


def test_it_fits_the_ten_minute_budget() -> None:
    """The tier's soft cap leaves room for the services and the bootstrap
    (~3m measured in container-tiers) inside 10 minutes, and the task's hard
    timeout is above the soft one so pytest can still write its summary."""
    task = _step("integration")
    soft = int(task["params"]["TIER_SOFT_TIMEOUT_S"])
    assert soft <= 300
    hard = task["timeout"]
    assert re.fullmatch(r"\d+m", hard) and int(hard[:-1]) * 60 > soft + 180


def _integration(tmp_path: Path, tiers_rc: int | None, *, head: bool = True,
                 subset: bool = True, oom: bool = False) -> subprocess.CompletedProcess[str]:
    """The integration task's script, executed, with TheHub's script stubbed."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required")
    pr = tmp_path / "pr"
    pr.mkdir()
    if head:
        (pr / ".git").mkdir()
        (pr / ".git" / "HEAD").write_text(OPEN_HEAD + "\n")
        (pr / ".git" / "pr-number").write_text("12\n")
        (pr / "scripts" / "ci").mkdir(parents=True)
        lines = [f'echo "$@" > "{(tmp_path / "args").as_posix()}"']
        if oom:
            lines.append('mkdir -p "$CONTAINER_TIERS_OUT"')
            lines.append('echo oom > "$CONTAINER_TIERS_OUT/oom-reason"')
        lines.append(f"exit {tiers_rc}")
        (pr / "scripts" / "ci" / "container-tiers.sh").write_text("\n".join(lines) + "\n")
        if subset:
            (pr / "config" / "ci").mkdir(parents=True)
            (pr / "config" / "ci" / "pr-integration-subset.txt").write_text("x  # y\n")
    script = _step("integration")["config"]["run"]["args"][-1].replace(
        "/tmp/container-tiers", (tmp_path / "tiers-out").as_posix())
    return subprocess.run([bash, "-c", script], cwd=tmp_path, capture_output=True, text=True,
                          timeout=60)


def test_a_tick_with_no_head_runs_nothing(tmp_path) -> None:
    r = _integration(tmp_path, None, head=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert not (tmp_path / "args").exists()


def test_a_green_subset_passes_and_ran_the_subset_tier(tmp_path) -> None:
    r = _integration(tmp_path, 0)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (tmp_path / "args").read_text().split() == ["pr", "subset"]


def test_a_red_subset_fails_the_job(tmp_path) -> None:
    """Red reaches `Concourse / thehub` through the job's on_failure hooks."""
    r = _integration(tmp_path, 1)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "::error::" in r.stdout
    assert not (tmp_path / "memory-infra").exists(), "a real failure is a verdict, not an outage"
    fail = [s for s in _job()["on_failure"]["do"] if s.get("task") == "report-check-run"]
    assert fail and fail[0]["params"]["CONCLUSION"] == "failure"


def test_a_memory_kill_is_an_outage_not_a_verdict(tmp_path) -> None:
    r = _integration(tmp_path, 137, oom=True)
    assert r.returncode == 137, r.stdout + r.stderr
    assert (tmp_path / "memory-infra" / "reason").read_text().strip() == "oom"
    assert (tmp_path / "memory-infra" / "exit_code").read_text().strip() == "137"


def test_a_branch_without_the_subset_says_so_and_fails(tmp_path) -> None:
    """A head from before TheHub's half of #61110 cannot be judged: rebase it."""
    r = _integration(tmp_path, 0, subset=False)
    assert r.returncode != 0
    assert "pr-integration-subset.txt" in r.stdout
    assert not (tmp_path / "args").exists()


# -- a requirements.txt pull request gets a verdict (TheHub #61636) ----------
#
# TheHub #692 (a dependency floor) changed requirements.txt, so container-tiers
# tried `pip install -r` inside the cached develop image, which has python and
# no pip. That printed NO VERDICT, exited 2, and the job reported failed. It
# also merged without the regenerated committed SBOM, because nothing had judged
# it. These tests execute the integration task's script with python3 stubbed.

SBOM_TEST = "backend/tests/unit/scripts/test_the_committed_sbom_satisfies_requirements.py"


def _requirements_pr(tmp_path: Path, tiers_rc: int, *, pip: bool, sbom_rc: int = 0,
                     changed: str = "backend/requirements.txt\n",
                     req_differs: bool = True,
                     ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """The integration script with a stub python3 that logs every call."""
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required")
    pr = tmp_path / "pr"
    (pr / ".git" / "process-gates").mkdir(parents=True)
    (pr / ".git" / "HEAD").write_text(OPEN_HEAD + "\n")
    (pr / ".git" / "pr-number").write_text("12\n")
    (pr / ".git" / "process-gates" / "changed").write_text(changed)
    (pr / "scripts" / "ci").mkdir(parents=True)
    (pr / "config" / "ci").mkdir(parents=True)
    (pr / "config" / "ci" / "pr-integration-subset.txt").write_text("x  # y\n")
    (pr / "backend" / "tests" / "unit" / "scripts").mkdir(parents=True)
    (pr / SBOM_TEST).write_text("# stub\n")
    (pr / "backend" / "requirements.txt").write_text("soupsieve>=2.8\n")
    app = tmp_path / "app"
    app.mkdir()
    (app / "requirements.txt").write_text("soupsieve>=2.7\n" if req_differs else "soupsieve>=2.8\n")
    log = tmp_path / "calls"
    (pr / "scripts" / "ci" / "container-tiers.sh").write_text(
        f'echo "container-tiers $*" >> "{log.as_posix()}"\nexit {tiers_rc}\n')
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    py = stubs / "python3"
    py.write_text(
        "#!/bin/bash\n"
        f'echo "python3 $*" >> "{log.as_posix()}"\n'
        'case "$*" in\n'
        f'  "-m pip --version") exit {0 if pip else 1} ;;\n'
        f'  *pytest*) exit {sbom_rc} ;;\n'
        "esac\nexit 0\n")
    py.chmod(0o755)
    script = _step("integration")["config"]["run"]["args"][-1].replace(
        "/tmp/container-tiers", (tmp_path / "tiers-out").as_posix())
    env = {**os.environ, "PATH": f"{stubs.as_posix()}:{os.environ['PATH']}",
           "APP_DIR": app.as_posix()}
    r = subprocess.run([bash, "-c", script], cwd=tmp_path, capture_output=True, text=True,
                       timeout=60, env=env)
    calls = log.read_text().splitlines() if log.exists() else []
    return r, calls


def test_pip_is_bootstrapped_before_the_requirements_install(tmp_path) -> None:
    """(a) The cached image has no pip: ensurepip must run before container-tiers
    (whose `pip install -r` is what died in #692)."""
    r, calls = _requirements_pr(tmp_path, 0, pip=False)
    assert r.returncode == 0, r.stdout + r.stderr
    ensure = [i for i, c in enumerate(calls) if "-m ensurepip" in c]
    tiers = [i for i, c in enumerate(calls) if c.startswith("container-tiers")]
    assert ensure and tiers and ensure[0] < tiers[0], calls


def test_pip_is_left_alone_when_requirements_match(tmp_path) -> None:
    _, calls = _requirements_pr(tmp_path, 0, pip=False, req_differs=False)
    assert not any("ensurepip" in c for c in calls), calls


def test_pip_is_left_alone_when_it_exists(tmp_path) -> None:
    _, calls = _requirements_pr(tmp_path, 0, pip=True)
    assert not any("ensurepip" in c for c in calls), calls


def test_no_verdict_reports_unjudged_not_failed(tmp_path) -> None:
    """(b) container-tiers exit 2 leaves the infra marker the hooks read, so the
    Hub stage is errored and the check run cancelled -- never failed."""
    r, _ = _requirements_pr(tmp_path, 2, pip=True, changed="README.md\n", req_differs=False)
    assert r.returncode == 2, r.stdout + r.stderr
    reason = (tmp_path / "memory-infra" / "reason").read_text()
    assert "NO VERDICT" in reason and "not a test failure" in reason.lower()
    assert (tmp_path / "memory-infra" / "exit_code").read_text().strip() == "2"


def test_a_real_failure_still_leaves_no_infra_marker(tmp_path) -> None:
    r, _ = _requirements_pr(tmp_path, 1, pip=True, changed="README.md\n", req_differs=False)
    assert r.returncode == 1, r.stdout + r.stderr
    assert not (tmp_path / "memory-infra").exists()


def test_the_report_hooks_downgrade_an_infra_marker() -> None:
    """The mapping the marker relies on: hub_report turns failed into errored,
    and the check run turns failure into cancelled, whenever infra/reason exists."""
    text = PIPELINE.read_text(encoding="utf-8")
    assert 'if [ "$STATUS" = "failed" ] && [ -s infra/reason ]' in text
    assert '[ "${CONCLUSION:-}" = "failure" ] && [ -s infra/reason ]' in text


def test_a_requirements_change_runs_the_committed_sbom_test(tmp_path) -> None:
    """(c) requirements.txt among the changed paths selects the SBOM test."""
    r, calls = _requirements_pr(tmp_path, 0, pip=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert any("pytest" in c and "test_the_committed_sbom_satisfies_requirements.py" in c
               for c in calls), calls


def test_a_stale_sbom_fails_the_pull_request(tmp_path) -> None:
    r, _ = _requirements_pr(tmp_path, 0, pip=True, sbom_rc=1)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "latest-python.cdx.json" in r.stdout
    assert not (tmp_path / "memory-infra").exists(), "a stale SBOM is a verdict"


def test_a_pull_request_without_requirements_skips_the_sbom_test(tmp_path) -> None:
    _, calls = _requirements_pr(tmp_path, 0, pip=True, changed="README.md\n", req_differs=False)
    assert not any("pytest" in c for c in calls), calls
