"""ZAP scans MyKronos's backend API, not only the dashboard in front of it.

The DAST lane spidered the frontend and, with the weekly run, actively scanned
it. The backend was in the same ephemeral stack and only ever reached through
what the functional suite happened to call: no OpenAPI import, so most of the
API's routes were never requested by ZAP at all. These hold the API scan to
the lane's existing rules -- same ZAP pin, same passive/active switch, same
upload, and a failure that turns the job red instead of a silent empty scan.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"
DEMO = ROOT / "deploy" / "demo" / "docker-compose.yml"


def _job() -> dict:
    job: dict = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["demo-and-dast"]
    return job


def _steps() -> list[dict]:
    steps: list[dict] = _job()["steps"]
    return steps


def _step(step_id: str) -> dict:
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
