"""Follow-ups to mykronos #1179 in personal-soc.yml (TheHub #61842).

F2  the reporter's "end with no commit, exit 0" is for a hook on a red lane,
    never for the gate's in-plan success.
F3  an iac upload that fails fails the task, and a scan that wrote no report
    still uploads (PS-3), so Mykronos hears that it broke.
F4  a digest-pinned task image records the date it was pinned, for the
    hand-bump rule in docs/pipeline-standard.md PS-8.
And the netassess-freshness #19 timeout: the network installs in the upload
hooks, and the downloads and bucket listing in the tasks, have deadlines of
their own inside the step's `timeout:`.

The scripts are EXECUTED as they stand in the pipeline, with every tool
stubbed, as in test_personal_soc_check_run_wiring.py.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.test_personal_soc_check_run_wiring import (
    PIPELINE,
    _doc,
    _iac_task,
    _jobs,
    _run,
)

PIPELINES = PIPELINE.parent

# -- F2 -----------------------------------------------------------------------


@pytest.mark.parametrize("head", [None, "ref: refs/heads/main", "abc1234"])
def test_a_gate_success_with_no_commit_fails_the_step(tmp_path: Path, head: str | None) -> None:
    """The gate's success is the one report that turns the check green. A gate
    that cannot name its commit has verified nothing, so it must not finish
    green with nothing posted."""
    r = _run(tmp_path, head, JOB="all-lanes", PHASE="end", CONCLUSION="success")

    assert r.returncode != 0, r.stdout + r.stderr
    assert not (tmp_path / "body.json").exists()


@pytest.mark.parametrize("conclusion", ["failure", "cancelled"])
def test_a_red_end_with_no_commit_still_finishes(tmp_path: Path, conclusion: str) -> None:
    r = _run(tmp_path, None, JOB="iac", PHASE="end", CONCLUSION=conclusion)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "Nothing was posted" in r.stdout


# -- F3 / PS-3 ----------------------------------------------------------------

_STUBS = """checkov() { :; }
git() { :; }
pip() { :; }
apt-get() { :; }
python3() { echo 0; }
python() {
  case "$*" in
    *mykronos.upload*)
      echo called > "$UPLOAD_MARK"
      [ "${UPLOAD_ACCEPTED:-1}" = 1 ] && echo "Uploaded 0 finding(s) for scan run r1 (failure)"
      return "${UPLOAD_RC:-0}" ;;
  esac
}
timeout() {
  if [ "${WRITE_SARIF:-0}" = 1 ]; then
    echo '{"runs": []}' > "$RESULTS/results_sarif.sarif"
  fi
  return 0
}
"""


def _run_iac(
    tmp_path: Path, *, sarif: bool, upload_rc: int, accepted: bool = True
) -> subprocess.CompletedProcess[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is required to execute the iac task")
    for d in ("source", "infra", "notify"):
        (tmp_path / d).mkdir()
    results = tmp_path / "results"
    # The task writes to an absolute /tmp/results; give each test its own.
    script = _iac_task()["config"]["run"]["args"][-1].replace("/tmp/results", str(results))
    return subprocess.run(
        [bash, "-e", "-s"],
        input=_STUBS + script,
        env={
            **os.environ,
            "MYKRONOS_TOKEN": "tok",
            "MYKRONOS_URL": "http://mykronos.test",
            "MYKRONOS_INSTALL_UPLOADER": ":",
            "UPLOAD_MARK": str(tmp_path / "uploaded"),
            "UPLOAD_RC": str(upload_rc),
            "UPLOAD_ACCEPTED": "1" if accepted else "0",
            "WRITE_SARIF": "1" if sarif else "0",
            "RESULTS": str(results),
        },
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_an_iac_upload_never_accepted_is_an_infrastructure_fault(tmp_path: Path) -> None:
    """Nothing was ingested, so nothing was judged: infra/reason and 75, and
    the check hook says `cancelled` (Fable nit 5 on #1191)."""
    r = _run_iac(tmp_path, sarif=True, upload_rc=1, accepted=False)

    assert (tmp_path / "uploaded").exists()
    assert r.returncode == 75, r.stdout + r.stderr
    reason = (tmp_path / "infra" / "reason").read_text()
    assert reason.startswith("INFRASTRUCTURE, NOT A VERDICT: Mykronos did not accept")
    message = (tmp_path / "notify" / "message.txt").read_text()
    assert "never accepted its upload" in message


def test_an_iac_upload_filed_as_degraded_is_a_failure_and_says_it_was_filed(
    tmp_path: Path,
) -> None:
    """The uploader exits 1 on a degraded scan it DID file. The message must
    not say nothing was ingested (Fable nit 3 on #1191), and it is a verdict."""
    r = _run_iac(tmp_path, sarif=True, upload_rc=1, accepted=True)

    assert r.returncode == 1, r.stdout + r.stderr
    assert "accepted the IaC upload but filed it as a failed or degraded scan" in r.stdout
    assert "nothing from this scan was ingested" not in r.stdout
    assert not (tmp_path / "infra" / "reason").exists()


def test_an_iac_scan_with_no_report_still_uploads_and_still_fails(tmp_path: Path) -> None:
    """PS-3: the uploader files a missing report as a failed scan, so the
    upload has to run for Mykronos to hear that the scan broke."""
    r = _run_iac(tmp_path, sarif=False, upload_rc=1, accepted=True)

    assert (tmp_path / "uploaded").exists(), r.stdout + r.stderr
    assert r.returncode == 1
    assert "checkov wrote no SARIF report" in r.stdout
    assert not (tmp_path / "infra" / "reason").exists()


def test_an_iac_scan_that_uploads_passes(tmp_path: Path) -> None:
    r = _run_iac(tmp_path, sarif=True, upload_rc=0)

    assert r.returncode == 0, r.stdout + r.stderr
    assert "IaC scan complete." in r.stdout


def test_the_iac_gap_is_no_longer_recorded() -> None:
    from tests.test_pipeline_conformance import checker

    assert "personal-soc.yml:iac PS-3" not in checker.KNOWN_GAPS


# -- netassess-freshness #19: deadlines inside the step's timeout ------------


def _tasks(node: Any, found: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    found = [] if found is None else found
    if isinstance(node, dict):
        if "task" in node and isinstance(node.get("config"), dict):
            found.append(node)
        for value in node.values():
            _tasks(value, found)
    elif isinstance(node, list):
        for value in node:
            _tasks(value, found)
    return found


def _script(task: dict[str, Any]) -> str:
    return str((task["config"].get("run") or {}).get("args", [""])[-1])


def _all_tasks() -> list[tuple[str, dict[str, Any]]]:
    return [(job["name"], t) for job in _doc()["jobs"] for t in _tasks(job)]


def test_every_uploader_install_has_network_deadlines() -> None:
    """netassess-freshness #19 spent its whole 10m `upload-network-findings`
    budget in this install and was killed before the uploader sent a byte.
    Every task in the file, so the next lane cannot leave it out."""
    call = 'bash -c "$MYKRONOS_INSTALL_UPLOADER"'
    sites = [(j, t) for j, t in _all_tasks() if call in _script(t)]
    assert sites
    for job, task in sites:
        script = _script(task)
        where = f"{job}/{task['task']}"
        before = script.split(call)[0]
        for setting in (
            "PIP_DEFAULT_TIMEOUT=",
            "PIP_RETRIES=",
            "GIT_HTTP_LOW_SPEED_LIMIT=",
            "GIT_HTTP_LOW_SPEED_TIME=",
        ):
            assert setting in before, f"{where} installs the uploader without {setting}"


def test_every_apt_task_has_acquire_deadlines() -> None:
    for job, task in _all_tasks():
        script = _script(task)
        if "apt-get update" not in script:
            continue
        where = f"{job}/{task['task']}"
        before = script.split("apt-get update")[0]
        for setting in ("Acquire::http::Timeout", "Acquire::https::Timeout", "Acquire::Retries"):
            assert setting in before, f"{where} runs apt with no {setting}"


_CURL_START = re.compile(r"(?:^|[;&|(]\s*|\$\(\s*|\bif\s+|\bthen\s+)curl\s")


def test_every_curl_and_mc_call_is_bounded() -> None:
    """Fable nit 1 on #1191: every curl a task starts carries --max-time, and
    every mc call runs under `timeout`, not only the ones on the #19 path."""
    curls = mcs = 0
    for job, task in _all_tasks():
        for line in _script(task).splitlines():
            if line.lstrip().startswith("#"):
                continue
            where = f"{job}/{task['task']}: {line.strip()}"
            if _CURL_START.search(line.strip()):
                curls += 1
                assert "--max-time" in line, where
            if re.search(r"\bmc --quiet (ls|cp|mb)\b", line):
                mcs += 1
                assert "timeout --kill-after=10s" in line, where
    assert curls and mcs


_APT_DEADLINE = re.compile(r"timeout --kill-after=10s \d+s sh -c 'apt-get update")
_INSTALL_DEADLINE = re.compile(r"if timeout --kill-after=10s \d+s bash -ec '$")


def test_every_apt_and_uploader_install_has_a_hard_deadline() -> None:
    """Fable nit 2 on #1191. The stall deadlines alone measured 354s for apt
    against a live WAN blackhole (2026-11-18), so each install also runs
    under `timeout`."""
    call = 'bash -c "$MYKRONOS_INSTALL_UPLOADER"'
    apts = installs = 0
    for job, task in _all_tasks():
        lines = _script(task).splitlines()
        for i, line in enumerate(lines):
            where = f"{job}/{task['task']}: {line.strip()}"
            if "apt-get update" in line and not line.lstrip().startswith("#"):
                apts += 1
                assert _APT_DEADLINE.search(line), where
            if line.strip() == call:
                installs += 1
                assert _INSTALL_DEADLINE.match(lines[i - 1].strip()), where
    assert apts == 15 and installs == 7, (apts, installs)


def _deadline(script: str, pattern: str) -> int:
    m = re.search(pattern, script)
    assert m, pattern
    return int(m.group(1))


#: The slowest container creation measured on this worker (builds 1333-1341),
#: which a task's clock includes.
WORST_CREATION_S = 130
KILL_GRACE_S = 10


@pytest.mark.parametrize("job", ["external-exposure", "netassess-ingest", "netassess-freshness"])
def test_the_network_hooks_worst_case_fits_its_cap(job: str) -> None:
    """Fable nit 2 on #1191: the sum, as a fact. With the network black-holed,
    the slowest container creation plus every install deadline and its KILL
    grace ends inside the hook's cap, so the hook fails and names itself
    rather than being killed by Concourse. The upload is not reached then."""
    (hook,) = [
        t["ensure"] for t in _tasks(_jobs()[job]) if isinstance(t.get("ensure"), dict)
    ]
    script = _script(hook)
    apt = _deadline(script, r"timeout --kill-after=10s (\d+)s sh -c 'apt-get")
    install = _deadline(script, r"if timeout --kill-after=10s (\d+)s bash -ec '")
    worst = WORST_CREATION_S + apt + install + 2 * KILL_GRACE_S
    cap = int(str(hook["timeout"]).rstrip("m")) * 60
    assert worst <= cap, (worst, cap)
    assert (apt, install, worst, cap) == (150, 240, 540, 600)


def test_the_freshness_task_deadlines_fit_inside_its_cap() -> None:
    (task,) = [t for t in _tasks(_jobs()["netassess-freshness"]) if t["task"] == "check-age"]
    assert int(str(task["timeout"]).rstrip("m")) == 15
    script = _script(task)
    assert "--max-time 180" in script  # 3m download
    assert "timeout --kill-after=10s 120s mc --quiet ls" in script  # 2m listing


# -- F4 -----------------------------------------------------------------------

_PINNED = re.compile(r"^\s*# pinned: (\d{4}-\d{2}-\d{2})\s*$")


def test_every_digest_pin_records_its_date() -> None:
    """The record the PS-8 hand-bump rule reads. Checked for presence and a
    real date only: a unit test that turned red with the calendar alone would
    block every unrelated change on the day it fired.

    personal-soc.yml only, for now. thehub.yml's ZAP pin (D-128) is the one
    other digest pin, and that file is TheHub's mirror; it is listed as open
    in the standard rather than edited here."""
    path = PIPELINE
    lines = path.read_text(encoding="utf-8").splitlines()
    pinned = [r for r in yaml.safe_load("\n".join(lines))["resources"] if "version" in r]
    for i, line in enumerate(lines):
        if not re.match(r"^\s*version: \{ digest: ", line):
            continue
        match = _PINNED.match(lines[i - 1])
        assert match, f"{path.name}:{i + 1} pins a digest with no '# pinned: YYYY-MM-DD' line"
        day = dt.date.fromisoformat(match.group(1))
        assert day <= dt.date.today(), f"{path.name}:{i} is pinned in the future"
    assert len(pinned) == sum(
        1 for line in lines if re.match(r"^\s*version: \{ digest: ", line)
    ), f"{path.name} has a version pin this test cannot see"


def test_the_hand_bump_rule_is_recorded() -> None:
    standard = (PIPELINES.parents[2] / "docs" / "pipeline-standard.md").read_text(encoding="utf-8")
    assert "bumped by hand (TheHub #61842)" in standard
    assert "test_every_digest_pin_records_its_date" in standard
