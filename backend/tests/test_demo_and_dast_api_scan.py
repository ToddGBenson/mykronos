"""ZAP scans MyKronos's backend API, not only the dashboard in front of it.

The DAST lane spidered the frontend and, with the weekly run, actively scanned
it. The backend was in the same ephemeral stack and only ever reached through
what the functional suite happened to call: no OpenAPI import, so most of the
API's routes were never requested by ZAP at all. These hold the API scan to
the lane's existing rules -- same ZAP pin, same passive/active switch, same
upload, and a failure that turns the job red instead of a silent empty scan.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"
DEMO = ROOT / "deploy" / "demo" / "docker-compose.yml"


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job: dict[str, Any] = doc["jobs"]["demo-and-dast"]
    return job


def _steps() -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = _job()["steps"]
    return steps


def _step(step_id: str) -> dict[str, Any]:
    found = [s for s in _steps() if s.get("id") == step_id]
    assert found, f"no step with id {step_id!r}"
    return found[0]


def _api_run() -> str:
    run: str = _step("zap_api")["run"]
    return run


def _index(predicate: object) -> int:
    for i, step in enumerate(_steps()):
        if callable(predicate) and predicate(step):
            return i
    raise AssertionError("step not found")


def test_the_api_is_scanned_from_its_openapi_document() -> None:
    run = _api_run()
    assert "zap-api-scan.py" in run
    assert re.search(r"-f\s+openapi\b", run), "the API scan does not import the OpenAPI document"
    assert "/openapi.json" in run


def test_the_api_scan_targets_the_ephemeral_backend_only() -> None:
    """An active scan with an admin token writes; it must hit only the stack
    this job stood up, whose database is tmpfs and dies with the run."""
    run = _api_run()
    assert "${PROXIED_BACKEND}" in run or "$PROXIED_BACKEND" in run
    assert _job()["env"]["PROXIED_BACKEND"] == "http://backend:8100"
    # On the compose network, where `backend` resolves to this run's container.
    assert "--network" in run and "mykronos-demo_default" in run
    for elsewhere in ("toddbenson", "8002", "8100:", "3100:", "host.docker.internal"):
        assert elsewhere not in run, f"the API scan step mentions {elsewhere!r}"


def test_the_api_scan_uses_the_zap_the_compose_file_pins() -> None:
    """One pin (D-128). The step reads the image from the compose file's
    `zap` service, rather than naming a second tag that can drift."""
    run = _api_run()
    assert '"$COMPOSE" config' in run and '["services"]["zap"]["image"]' in run
    assert "zaproxy/zaproxy:" not in run, "a second ZAP pin, which will drift from compose's"
    assert "@sha256:" in run, "the step does not refuse an image that is not digest-pinned"


def test_the_api_scan_follows_the_lanes_active_switch() -> None:
    assert _step("zap_api")["env"]["ACTIVE"] == _step("zap")["env"]["ACTIVE"]
    run = _api_run()
    # zap-api-scan.py runs an active scan unless told `-S` (safe mode).
    assert '"$ACTIVE"' in run and "-S" in run


def test_the_active_api_scan_is_bounded() -> None:
    assert "scanner.maxScanDurationInMins" in _api_run()
    # Spider (10) + frontend active (40) + API active (20) + setup no longer
    # fits the 60 minutes the job had.
    assert int(_job()["timeout-minutes"]) >= 90


def test_the_api_scan_is_authenticated_as_admin_through_the_gate() -> None:
    run = _api_run()
    env = _step("zap_api").get("env", {})
    assert "ZAP_AUTH_HEADER_VALUE" in env or "ZAP_AUTH_HEADER_VALUE" in run
    assert "Bearer" in str(env) + run
    assert "X-Hub-Token" in run
    # From the job's environment, never written into the script, and never a
    # repository secret: this repository is public and its logs are too.
    assert "not-a-secret" not in run
    assert "secrets." not in str(_step("zap_api"))


def test_the_workflow_admin_token_is_the_demo_admin_token() -> None:
    env = _job()["env"]
    backend = yaml.safe_load(DEMO.read_text(encoding="utf-8"))["services"]["backend"]["environment"]
    assert env["DEMO_ADMIN_TOKEN"] == backend["MYKRONOS_ADMIN_TOKEN"]
    assert env["DEMO_GATE_TOKEN"] == backend["MYKRONOS_GATE_TOKEN"]


def test_the_api_report_is_uploaded_with_the_frontend_report() -> None:
    """One ScanRun, not two. Absence reconciliation partitions on the tool, so
    a second `zap` upload holding only API findings would close every
    frontend finding after two runs, and the reverse."""
    assert "$RUNNER_TEMP/dast/" in _api_run()
    assert re.search(r"-J\s+\S*zap-api\.json", _api_run())
    dast_uploads = [
        s for s in _steps()
        if s.get("uses") == "./actions/upload-results" and s["with"]["capability"] == "dast"
    ]
    assert len(dast_uploads) == 1
    assert dast_uploads[0]["with"]["results-path"] == "${{ runner.temp }}/dast"


def test_the_api_scan_runs_before_the_upload_whatever_came_before() -> None:
    step = _step("zap_api")
    assert step.get("if") == "always()"
    assert step.get("continue-on-error") is True
    api = _index(lambda s: s.get("id") == "zap_api")
    upload = _index(lambda s: s.get("name") == "Upload the DAST result")
    frontend = _index(lambda s: s.get("id") == "zap")
    assert frontend < api < upload


def test_an_unreachable_api_fails_loudly() -> None:
    run = _api_run()
    # The document is fetched and checked before ZAP sees it: no paths is a
    # broken target, not a clean one.
    assert "curl -fsS" in run and "paths" in run
    assert "::error::" in run and "exit 1" in run
    # zap-api-scan.py exits 3 on any error, including importing no URLs.
    assert re.search(r"-ge\s+3", run)


def test_a_failed_api_scan_cannot_close_api_findings() -> None:
    """A scan that produced nothing for the API must be recorded as partial,
    or the frontend report alone would read as the API being clean."""
    run = _api_run()
    assert "zap-api.json" in run
    assert "PARTIAL" in run.upper()


def test_a_failed_api_scan_turns_the_job_red_last() -> None:
    steps = _steps()
    fail = [i for i, s in enumerate(steps) if s.get("if") == "steps.zap_api.outcome == 'failure'"]
    assert len(fail) == 1
    assert "exit 1" in steps[fail[0]]["run"]
    teardown = _index(lambda s: s.get("name") == "Tear down")
    assert fail[0] > teardown


def test_a_missing_dashboard_report_still_cannot_read_as_a_whole_run() -> None:
    """`Spider, and scan` writes no report when it reached only the gate, so
    the upload records a failed run. The API report beside it must not turn
    that into a successful run holding only API findings."""
    run = _api_run()
    guard = run.index('if [ ! -s "$RUNNER_TEMP/dast/zap.json" ]; then')
    assert '> "$RUNNER_TEMP/dast/zap.json"' in run[guard : run.index("fi", guard)]
    assert guard < run.index("docker run")


# --- What ZAP actually sent: the backend's own access log -----------------
#
# A scan whose every request the perimeter gate or the admin check refused is
# a scan of the gate, and its report looks exactly like a clean API. The
# signal is the demo backend's uvicorn access log, read for the window of the
# scan -- not a request the step makes itself, which would only prove that the
# step's own headers work, not ZAP's.

BACKEND_DOCKERFILE = ROOT / "backend" / "Dockerfile"


def _access_log_counter() -> str:
    """The Python the step pipes the backend's log through, verbatim."""
    run = _api_run()
    start = run.index("<<'PY'\n", run.index("docker logs")) + len("<<'PY'\n")
    end = run.index("\nPY\n", start)
    return run[start:end]


def _uvicorn_lines(requests: list[tuple[str, str, int]], *, colours: bool) -> str:
    """Lines formatted by uvicorn's own access formatter, as the demo logs them."""
    from uvicorn.logging import AccessFormatter

    formatter = AccessFormatter(
        fmt='%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        use_colors=colours,
    )
    lines = []
    for method, path, status in requests:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            0,
            '%s - "%s %s HTTP/%s" %d',
            ("172.18.0.5:41234", method, path, "1.1", status),
            None,
        )
        lines.append(formatter.format(record))
    # The rest of a real log, which must not count.
    lines.append("INFO:     Application startup complete.")
    return "\n".join(lines) + "\n"


def _count(log: str, tmp_path: Path) -> tuple[int, ...]:
    path = tmp_path / "backend.log"
    path.write_text(log, encoding="utf-8")
    out = subprocess.run(
        [sys.executable, "-", str(path)],
        input=_access_log_counter(),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return tuple(int(x) for x in out)


def test_the_demo_backend_writes_an_access_log() -> None:
    """The signal exists: the image runs uvicorn at info with the access log
    on, and the demo compose file does not override the command."""
    dockerfile = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    cmd = dockerfile[dockerfile.index('CMD ["python", "-m", "uvicorn"') :]
    cmd = cmd[: cmd.index("]") + 1]
    assert '"--log-level", "info"' in cmd
    assert "access-log" not in cmd
    backend = yaml.safe_load(DEMO.read_text(encoding="utf-8"))["services"]["backend"]
    assert "command" not in backend and "entrypoint" not in backend


def test_the_step_reads_the_backends_log_for_the_scans_window() -> None:
    run = _api_run()
    started = run.index("STARTED=")
    scan = run.index("docker run")
    logs = run.index("docker logs")
    assert started < scan < logs < run.index('cp "$WRK/zap-api.json"')
    log_call = run[logs : run.index("\n", logs)]
    assert '--since "$STARTED"' in log_call
    assert "mykronos-demo-backend-1" in log_call


@pytest.mark.parametrize("colours", [False, True], ids=["plain", "coloured"])
def test_the_counter_reads_uvicorns_own_format(colours: bool, tmp_path: Path) -> None:
    log = _uvicorn_lines(
        [
            ("GET", "/api/repos", 200),
            ("POST", "/api/risk-acceptances?x=%27", 201),
            ("GET", "/api/dashboard/summary", 401),
            ("DELETE", "/api/agents/abc", 403),
            ("PUT", "/api/triage/1", 422),
            # Not the API: the healthcheck and the step's own document fetch.
            ("GET", "/healthz", 200),
            ("GET", "/openapi.json", 200),
        ],
        colours=colours,
    )
    # total /api/ responses, 2xx, 401+403
    assert _count(log, tmp_path) == (5, 2, 2)


def test_a_scan_that_only_met_the_gate_counts_no_success(tmp_path: Path) -> None:
    log = _uvicorn_lines([("GET", f"/api/r{i}", 401) for i in range(40)], colours=False)
    assert _count(log, tmp_path) == (40, 0, 40)


def test_an_empty_log_counts_nothing(tmp_path: Path) -> None:
    assert _count("", tmp_path) == (0, 0, 0)


def test_no_success_or_a_refused_majority_fails_the_step() -> None:
    run = _api_run()
    guard = run.index('if [ "$API_2XX" -eq 0 ]')
    condition = run[guard : run.index("\n", guard)]
    assert "API_DENIED * 2" in condition and '-gt "$API_TOTAL"' in condition
    assert "broken " in run[guard : run.index("fi", guard)]
    # Counts that could not be read are no success, not a pass.
    assert '|| SENT="0 0 0"' in run
    assert guard < run.index('cp "$WRK/zap-api.json"')


# -- The step, run --------------------------------------------------------------
#
# The tests above read the step. These run it, under the shell GitHub gives a
# `run:` with no `shell:` (`bash -eo pipefail`), with `docker` and `curl`
# stubbed on PATH. Reading it missed that `-e` killed the step on ZAP's exit
# 3 before `RC=$?`, so the failure marker was never written and a failed API
# scan uploaded as a clean one.

_DOCKER_STUB = r"""#!/usr/bin/env bash
case "$1" in
  compose)
    echo '{"services": {"zap": {"image": "ghcr.io/zaproxy/zaproxy:weekly@sha256:abc"}}}' ;;
  run)
    # What the upload would find if the job died here.
    if [ -f "$RUNNER_TEMP/dast/zap-api.json" ]; then
      cp "$RUNNER_TEMP/dast/zap-api.json" "$RUNNER_TEMP/during-scan.json"
    fi
    wrk=""
    while [ $# -gt 0 ]; do
      if [ "$1" = "-v" ]; then wrk="${2%%:/zap/wrk*}"; fi
      shift
    done
    if [ "$STUB_ZAP_RC" -lt 3 ]; then echo '{"site": []}' > "$wrk/zap-api.json"; fi
    exit "$STUB_ZAP_RC" ;;
  logs)
    printf 'INFO:     172.18.0.5:1 - "GET /api/repos HTTP/1.1" 200 OK\n' ;;
esac
"""

_CURL_STUB = r"""#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; fi
  shift
done
echo '{"paths": {"/api/repos": {}}}' > "$out"
"""


def _run_step(tmp_path: Path, zap_rc: int) -> tuple[int, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # The step calls `python`; point it at this interpreter. (A Windows
    # interpreter directory cannot go on a POSIX PATH: its drive colon splits.)
    python_shim = f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n'
    for name, body in (("docker", _DOCKER_STUB), ("curl", _CURL_STUB), ("python", python_shim)):
        stub = bin_dir / name
        stub.write_text(body, encoding="utf-8", newline="\n")
        stub.chmod(0o755)
    runner_temp = tmp_path / "runner"
    (runner_temp / "dast").mkdir(parents=True)
    (runner_temp / "dast" / "zap.json").write_text('{"site": []}', encoding="utf-8")
    script = tmp_path / "step.sh"
    script.write_text(_api_run(), encoding="utf-8", newline="\n")
    env = {
        "PATH": f"{bin_dir.as_posix()}:/usr/bin:/bin",
        "RUNNER_TEMP": runner_temp.as_posix(),
        "COMPOSE": "compose.yml",
        "DEMO_GATE_TOKEN": "gate",
        "DEMO_ADMIN_TOKEN": "admin",
        "PROXIED_BACKEND": "http://backend:8100",
        "PUBLISHED_BACKEND": "http://127.0.0.1:8201",
        "ACTIVE": "false",
        "STUB_ZAP_RC": str(zap_rc),
    }
    # GitHub's default for `run:` on Linux: bash --noprofile --norc -eo pipefail {0}
    done = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", script.as_posix()],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return done.returncode, runner_temp / "dast"


@pytest.mark.parametrize("zap_rc", [3, 125])
def test_a_zap_error_leaves_the_failure_marker(tmp_path: Path, zap_rc: int) -> None:
    rc, dast = _run_step(tmp_path, zap_rc)
    assert rc != 0
    report = dast / "zap-api.json"
    assert report.is_file(), "a failed API scan left no marker: the upload reads the run as complete"
    assert "did not complete" in report.read_text(encoding="utf-8")


def test_a_job_killed_mid_scan_leaves_the_failure_marker(tmp_path: Path) -> None:
    # A timeout or cancel-in-progress runs no script logic, so the marker
    # has to be on disk before ZAP starts and replaced only on success.
    _run_step(tmp_path, 0)
    during = tmp_path / "runner" / "during-scan.json"
    assert during.is_file(), "nothing marked the run partial while ZAP was running"
    assert "did not complete" in during.read_text(encoding="utf-8")


def test_a_completed_scan_replaces_the_marker_with_zaps_report(tmp_path: Path) -> None:
    rc, dast = _run_step(tmp_path, 2)
    assert rc == 0
    assert (dast / "zap-api.json").read_text(encoding="utf-8").strip() == '{"site": []}'
