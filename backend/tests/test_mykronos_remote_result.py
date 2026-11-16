"""This host decides what a remote `linux` worker's result is worth (review of #1178).

The laptops are inside the CI trust boundary for mykronos.yml's moved lanes
(operator decision 2026-11-16, ~03:20Z), WITH host-side checks. These tests
hold those checks:

* every moved job asks for a remote worker first (`linux_probe`), so an
  offline laptop ERRORS the build in 5 minutes instead of failing a scan;
* every remote task sits in a timed `try:` and writes `ran/rc` from an EXIT
  trap, and `remote-result` runs next, on this host;
* `remote-result` takes this host's HEAD as the commit, refuses a result
  naming another, and refuses a SARIF that is not a run of the expected tool
  or holds no results: an empty upload counts toward absence-closing every
  open finding of that tool;
* every upload names this host's commit, never the file the remote wrote.

The script is executed here, against fixtures, not just read.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
HOST = "0123456789abcdef0123456789abcdef01234567"

# job -> (remote task, the upload or filing step that sends its result)
MOVED = {
    "sast": ("semgrep", "upload-semgrep"),
    "dependencies": ("osv-scanner", "upload-osv"),
    "coverage": ("pytest-cov", "upload-coverage"),
    "time-travel": ("pytest-time-travel", "file-hub-story"),
}


def _doc() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _job(name: str) -> dict[str, Any]:
    return next(j for j in _doc()["jobs"] if j["name"] == name)


def _contains_task(step: Any, task: str) -> bool:
    if isinstance(step, dict):
        if step.get("task") == task:
            return True
        return any(_contains_task(v, task) for v in step.values())
    if isinstance(step, list):
        return any(_contains_task(v, task) for v in step)
    return False


def _find_task(step: Any, task: str) -> dict[str, Any] | None:
    if isinstance(step, dict):
        if step.get("task") == task:
            return step
        for value in step.values():
            found = _find_task(value, task)
            if found:
                return found
    if isinstance(step, list):
        for value in step:
            found = _find_task(value, task)
            if found:
                return found
    return None


# -- the plan shape ---------------------------------------------------------


@pytest.mark.parametrize("job", sorted(MOVED))
def test_each_moved_job_probes_then_tries_then_lets_this_host_decide(job: str) -> None:
    task, _ = MOVED[job]
    plan = _job(job)["plan"]
    holder = next(i for i, s in enumerate(plan) if _contains_task(s, task))
    wrapper = plan[holder]
    assert "try" in wrapper, f"{job}: {task} is not in a `try:`, so a timeout fails the build"
    assert wrapper["try"].get("timeout"), f"{job}: the `try:` body carries no timeout"
    after = plan[holder + 1]
    assert after.get("task") == "remote-result", f"{job}: {after.get('task')!r} follows {task}"
    assert "linux" not in (after.get("tags") or [])
    checked = plan[holder + 2]
    assert checked.get("file") == "checked/ok" and "load_var" in checked
    # The probe and its load_var come first, before the remote task.
    probe = next(i for i, s in enumerate(plan) if _contains_task(s, "linux-worker-probe"))
    assert probe < holder and plan[probe + 1].get("file") == "probed/rc"


@pytest.mark.parametrize("job", sorted(MOVED))
def test_the_remote_task_writes_ran_rc_on_exit(job: str) -> None:
    task = _find_task(_job(job)["plan"], MOVED[job][0])
    assert task is not None
    outputs = {o["name"] for o in task["config"]["outputs"]}
    assert "ran" in outputs
    script = task["config"]["run"]["args"][-1]
    assert "trap 'printf \"%s\\n\" \"$?\" > \"$RAN_DIR/rc\"' EXIT" in script


def test_the_probe_writes_probed_not_ran() -> None:
    """A probe's `ran` would outlive a remote task that timed out."""
    probe = _find_task(_doc()["anchors"]["linux_probe"], "linux-worker-probe")
    assert probe is not None
    assert [o["name"] for o in probe["config"]["outputs"]] == ["probed"]


@pytest.mark.parametrize("job", sorted(MOVED))
def test_the_upload_names_this_hosts_commit(job: str) -> None:
    step = _find_task(_job(job)["plan"], MOVED[job][1])
    assert step is not None
    script = step["config"]["run"]["args"][-1]
    assert "/commit)" not in script, f"{job}: the upload reads a commit the remote wrote"
    assert "rev-parse HEAD)" in script or "checked/short" in script


def test_reachability_is_posted_only_when_checked() -> None:
    script = _find_task(_job("sast")["plan"], "upload-semgrep")["config"]["run"]["args"][-1]
    assert "[ -f ../checked/reachability-ok ] || exit 0" in script


# -- the script, executed ------------------------------------------------


def _sarif(tool: str, results: int) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool}}, "results": [{"ruleId": "r"}] * results}],
    }


def _run(
    tmp_path: Path,
    *,
    rc: str | None = "0",
    commit: str | None = HOST,
    sarif: Any = None,
    reach: Any = None,
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    script = _doc()["anchors"]["remote_result"]["config"]["run"]["args"][-1]
    (tmp_path / "source" / ".git").mkdir(parents=True)
    (tmp_path / "source" / ".git" / "HEAD").write_text(HOST + "\n", encoding="ascii")
    for name in ("ran", "result", "reach", "checked"):
        (tmp_path / name).mkdir()
    if rc is not None:
        (tmp_path / "ran" / "rc").write_text(rc + "\n", encoding="ascii")
    if commit is not None:
        (tmp_path / "result" / "commit").write_text(commit + "\n", encoding="ascii")
    params = {"LINUX_STEP": "sast/semgrep", "COMMIT_FILE": "commit"}
    if sarif is not None:
        text = sarif if isinstance(sarif, str) else json.dumps(sarif)
        (tmp_path / "result" / "out.sarif").write_text(text, encoding="utf-8")
        params |= {"SARIF_FILE": "out.sarif", "EXPECT_TOOL": "semgrep"}
    if reach is not None:
        (tmp_path / "reach" / "reachability.json").write_text(json.dumps(reach), encoding="utf-8")
    params |= env or {}
    proc = subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=tmp_path,
        env={"PATH": "", **params},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return proc, tmp_path / "checked"


def test_a_good_result_is_checked_with_this_hosts_commit(tmp_path: Path) -> None:
    proc, checked = _run(tmp_path, sarif=_sarif("Semgrep OSS", 3))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (checked / "ok").read_text().strip() == HOST
    assert (checked / "short").read_text().strip() == HOST[:12]


@pytest.mark.parametrize(
    "case",
    [
        {"rc": None},  # timed out or never ran: no ran/rc
        {"rc": "zero"},
        {"commit": "f" * 40},  # another commit
        {"commit": None},
        {"sarif": _sarif("Semgrep OSS", 0)},  # empty: would absence-close
        {"sarif": {"version": "2.1.0", "runs": []}},
        {"sarif": _sarif("osv-scanner", 2)},  # another tool
        {"sarif": "not json"},
        {"sarif": {"version": "2.1.0", "runs": [{"tool": "x", "results": [1]}]}},
        {"sarif": {"runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [{}]}]}},
    ],
    ids=lambda c: next(iter(c)) + ":" + str(next(iter(c.values())))[:24],
)
def test_a_missing_or_forged_result_is_refused_and_errors_the_build(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    """Exit 0 with no checked/ok: the `load_var` after it errors the build,
    so nothing is uploaded and the lane reads as errored, not failed."""
    kwargs: dict[str, Any] = {"sarif": _sarif("semgrep", 1)} | case
    proc, checked = _run(tmp_path, **kwargs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (checked / "ok").exists(), proc.stdout
    assert "NOT A VERDICT, NOT UPLOADED" in proc.stdout


def test_a_remote_task_that_ran_and_failed_keeps_its_verdict(tmp_path: Path) -> None:
    proc, checked = _run(tmp_path, rc="2")
    assert proc.returncode == 2
    assert not (checked / "ok").exists()


def test_a_short_commit_is_compared_as_short(tmp_path: Path) -> None:
    proc, checked = _run(tmp_path, commit=HOST[:12], env={"SHORT_COMMIT": "1"})
    assert proc.returncode == 0 and (checked / "ok").exists(), proc.stdout
    other = tmp_path / "other"
    other.mkdir()
    proc, checked = _run(other, commit="f" * 12, env={"SHORT_COMMIT": "1"})
    assert not (checked / "ok").exists()


def _reach(**over: Any) -> dict[str, Any]:
    body = {
        "language": "python",
        "commit_sha": HOST,
        "orphaned_paths": ["a.py"],
        "files_analysed": 10,
        "files_unparseable": 0,
    }
    return body | over


@pytest.mark.parametrize(
    "body, ok",
    [
        (_reach(), True),
        (_reach(taint={"status": "ran", "matches": []}), True),
        (_reach(commit_sha="f" * 40), False),
        (_reach(files_analysed="10"), False),
        (_reach(orphaned_paths=[1]), False),
        (_reach(extra=1), False),
        ([], False),
    ],
)
def test_reachability_is_marked_only_when_well_formed_for_this_commit(
    tmp_path: Path, body: Any, ok: bool
) -> None:
    proc, checked = _run(tmp_path, sarif=_sarif("semgrep", 1), reach=body)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # A bad report never costs the scan: the result is still checked.
    assert (checked / "ok").exists()
    assert (checked / "reachability-ok").exists() is ok
