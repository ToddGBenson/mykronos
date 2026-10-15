"""A real browser drives the dashboard in Demo and DAST, not only httpx.

The functional suite speaks HTTP and ZAP reads responses; neither runs the
page's JavaScript. So the static CSP that blocked hydration and left every
control on the site inert (`frontend/proxy.ts`) was invisible to both: every
page answered 200 with the right HTML and did nothing when clicked. The
Playwright suite in `frontend/e2e/` opens the console; these hold the lane to
running it, and to reporting it without disturbing the lanes beside it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos.adapters.base import ScanContext
from mykronos.adapters.registry import normalize_results
from mykronos.schemas import ScanStatus

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"
DEMO = ROOT / "deploy" / "demo" / "docker-compose.yml"
FRONTEND = ROOT / "frontend"


def _steps() -> list[dict[str, Any]]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps: list[dict[str, Any]] = doc["jobs"]["demo-and-dast"]["steps"]
    return steps


def _index(predicate: Any) -> int:
    for i, step in enumerate(_steps()):
        if predicate(step):
            return i
    raise AssertionError("step not found")


def _e2e() -> dict[str, Any]:
    found = [s for s in _steps() if s.get("id") == "e2e"]
    assert found, "Demo and DAST has no browser suite step (id: e2e)"
    return found[0]


def _e2e_run() -> str:
    run: str = _e2e()["run"]
    return run


# -- The suite itself -------------------------------------------------------------


def test_playwright_is_pinned_exactly() -> None:
    """A floating range would let a Playwright release change what the lane
    does between two runs of the same commit."""
    package = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    version = package["devDependencies"].get("@playwright/test", "")
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"@playwright/test is {version!r}"
    lock = json.loads((FRONTEND / "package-lock.json").read_text(encoding="utf-8"))
    assert lock["packages"]["node_modules/@playwright/test"]["version"] == version


def test_the_config_is_chromium_with_traces_and_junit() -> None:
    config = (FRONTEND / "playwright.config.ts").read_text(encoding="utf-8")
    assert re.findall(r'name:\s*"(\w+)"', config) == ["chromium"]
    assert 'trace: "retain-on-failure"' in config
    assert '"junit"' in config and "process.env.E2E_JUNIT" in config
    assert "process.env.E2E_BASE_URL" in config


def test_the_specs_cover_the_gate_hydration_and_the_core_pages() -> None:
    specs = {p.name for p in (FRONTEND / "e2e").glob("*.spec.ts")}
    assert {"gate.spec.ts", "hydration.spec.ts", "pages.spec.ts"} <= specs
    fixtures = (FRONTEND / "e2e" / "fixtures.ts").read_text(encoding="utf-8")
    # The property the suite exists for: a CSP violation fails a test.
    assert "securitypolicyviolation" in fixtures


def test_vitest_does_not_collect_the_browser_specs() -> None:
    """`npm test` runs in the frontend PR check with no browser and no stack."""
    config = (FRONTEND / "vitest.config.mts").read_text(encoding="utf-8")
    assert 'include: ["__tests__/**/*.test.ts"]' in config


# -- Its place in the lane --------------------------------------------------------


def test_it_runs_after_the_functional_suite_and_before_zap() -> None:
    """Before the spider, so a broken UI is reported even when ZAP is slow or
    times out the job."""
    functional = _index(lambda s: s.get("id") == "functional")
    e2e = _index(lambda s: s.get("id") == "e2e")
    spider = _index(lambda s: s.get("id") == "zap")
    api = _index(lambda s: s.get("id") == "zap_api")
    assert functional < e2e < spider < api


def test_it_is_gated_like_the_functional_suite_and_never_stops_the_scan() -> None:
    step = _e2e()
    functional = next(s for s in _steps() if s.get("id") == "functional")
    assert step.get("if") == functional.get("if")
    assert step.get("continue-on-error") is True
    # The scans still run whatever the browser suite did.
    for step_id in ("zap", "zap_api"):
        assert next(s for s in _steps() if s.get("id") == step_id).get("if") == "always()"


def test_it_installs_chromium_with_its_system_dependencies() -> None:
    run = _e2e_run()
    assert "npm ci" in run
    assert "npx playwright install --with-deps chromium" in run
    assert "npx playwright test" in run
    setup_node = [s for s in _steps() if str(s.get("uses", "")).startswith("actions/setup-node@")]
    assert setup_node, "no Node on the runner for the browser suite"
    assert re.fullmatch(r"actions/setup-node@[0-9a-f]{40}", setup_node[0]["uses"])
    assert _index(lambda s: s is setup_node[0] or s == setup_node[0]) < _index(
        lambda s: s.get("id") == "e2e"
    )


def test_it_drives_the_published_dashboard_directly_not_through_zap() -> None:
    """Direct to the port compose publishes. Through ZAP's proxy the suite
    would be one more traffic source shaping the site tree, which is the
    functional suite's job; this one is about what the browser does."""
    env = _e2e()["env"]
    frontend_ports = yaml.safe_load(DEMO.read_text(encoding="utf-8"))["services"]["frontend"][
        "ports"
    ]
    published = str(frontend_ports[0]).split(":")[0]
    assert env["E2E_BASE_URL"] == f"http://127.0.0.1:{published}"
    assert "ZAP_PROXY" not in _e2e_run() and "HTTP_PROXY" not in _e2e_run()


def test_the_gate_token_comes_from_the_environment() -> None:
    assert "demo-gate-token-not-a-secret" not in _e2e_run()
    assert "DEMO_GATE_TOKEN" not in _e2e().get("env", {}), "the job-level value is the one place"


def test_the_seeded_findings_are_compacted_before_the_browser_reads_them() -> None:
    """The seed lands in the write-ahead buffer, and the dashboard reads the
    compacted lake: without this every findings page is empty until the
    five-minute compaction loop happens to run."""
    run = _e2e_run()
    assert "python -m mykronos.cli compact" in run
    assert run.index("mykronos.cli compact") < run.index("npx playwright test")


# -- How it reports ---------------------------------------------------------------


def test_the_junit_joins_the_functional_upload_rather_than_making_a_second() -> None:
    """One `functional`/`junit` ScanRun per build. A second uploader for the
    same capability and tool would be a second run in the same partition, and
    each would answer for the other's absence."""
    env = _e2e()["env"]
    assert env["E2E_JUNIT"] == "${{ runner.temp }}/functional/e2e.xml"
    uploads = [s for s in _steps() if s.get("uses") == "./actions/upload-results"]
    assert sorted((s["with"]["capability"], s["with"]["tool"]) for s in uploads) == [
        ("dast", "zap"),
        ("functional", "junit"),
    ]
    functional = next(s for s in uploads if s["with"]["capability"] == "functional")
    assert functional["with"]["results-path"] == "${{ runner.temp }}/functional"
    assert functional.get("if") == "always()"


def test_traces_stay_out_of_the_uploaded_directories() -> None:
    out = _e2e()["env"]["E2E_OUTPUT_DIR"]
    assert out.startswith("${{ runner.temp }}/")
    assert not out.startswith("${{ runner.temp }}/functional")
    assert not out.startswith("${{ runner.temp }}/dast")


def test_a_failed_run_keeps_its_trace_as_an_artifact() -> None:
    keep = [
        s for s in _steps()
        if str(s.get("uses", "")).startswith("actions/upload-artifact@")
        and s.get("if") == "steps.e2e.outcome == 'failure'"
    ]
    assert len(keep) == 1, "a failed browser run's trace is not kept"
    assert re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", keep[0]["uses"])
    assert keep[0]["with"]["path"] == _e2e()["env"]["E2E_OUTPUT_DIR"]
    # Reporting after the work, as every upload here is.
    assert _index(lambda s: s is keep[0] or s == keep[0]) > _index(
        lambda s: s.get("name") == "Upload the DAST result"
    )


def test_a_failed_browser_suite_turns_the_job_red_last() -> None:
    steps = _steps()
    fail = [i for i, s in enumerate(steps) if s.get("if") == "steps.e2e.outcome == 'failure'"
            and "run" in s]
    assert len(fail) == 1
    assert "exit 1" in steps[fail[0]]["run"]
    assert fail[0] > _index(lambda s: s.get("name") == "Tear down")


# -- The step, run ----------------------------------------------------------------
#
# Run under the shell GitHub gives a `run:` with no `shell:`, with `docker`,
# `npm` and `npx` stubbed on PATH, and its JUnit read back by the adapter the
# functional upload uses.

_DOCKER_STUB = r"""#!/usr/bin/env bash
case "$1" in
  compose) echo "backend-container-id" ;;
  exec) exit "${STUB_COMPACT_RC:-0}" ;;
esac
"""

_NPM_STUB = "#!/usr/bin/env bash\nexit 0\n"

# Playwright's own reporter output, trimmed: one file suite per spec.
_PLAYWRIGHT_XML = """<testsuites id="" name="" tests="2" failures="{failures}" skipped="0" \
errors="0" time="3.1">
<testsuite name="hydration.spec.ts" timestamp="2026-10-15T03:10:47.505Z" hostname="chromium" \
tests="2" failures="{failures}" skipped="0" time="3.1" errors="0">
<testcase name="the theme toggle responds to a click" classname="hydration.spec.ts" time="1.2">
</testcase>
</testsuite>
</testsuites>
"""

_NPX_STUB = r"""#!/usr/bin/env bash
if [ "$1 $2" = "playwright install" ]; then exit "${STUB_INSTALL_RC:-0}"; fi
if [ "$1 $2" = "playwright test" ]; then
  # What the upload would find if the job died while the browser ran.
  cp "$E2E_JUNIT" "$RUNNER_TEMP/during-e2e.xml" 2>/dev/null || true
  if [ -n "${STUB_XML:-}" ]; then printf '%s' "$STUB_XML" > "$E2E_JUNIT"; fi
  exit "${STUB_TEST_RC:-0}"
fi
"""


def _run_step(
    tmp_path: Path,
    *,
    test_rc: int = 0,
    failures: int | None = 0,
    install_rc: int = 0,
    compact_rc: int = 0,
) -> tuple[int, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    python_shim = f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n'
    for name, body in (
        ("docker", _DOCKER_STUB),
        ("npm", _NPM_STUB),
        ("npx", _NPX_STUB),
        ("python", python_shim),
        # The retry waits between attempts; not in a test.
        ("sleep", "#!/usr/bin/env bash\nexit 0\n"),
    ):
        stub = bin_dir / name
        stub.write_text(body, encoding="utf-8", newline="\n")
        stub.chmod(0o755)
    (tmp_path / "frontend").mkdir()
    runner_temp = tmp_path / "runner"
    functional = runner_temp / "functional"
    functional.mkdir(parents=True)
    # The functional suite has already written its report by now.
    (functional / "functional.xml").write_text(
        '<testsuites><testsuite name="pytest" tests="26" failures="0" errors="0"/></testsuites>',
        encoding="utf-8",
    )
    script = tmp_path / "step.sh"
    script.write_text(_e2e_run(), encoding="utf-8", newline="\n")
    env = {
        "PATH": f"{bin_dir.as_posix()}:/usr/bin:/bin",
        "RUNNER_TEMP": runner_temp.as_posix(),
        "COMPOSE": "compose.yml",
        "DEMO_GATE_TOKEN": "gate",
        "E2E_BASE_URL": "http://127.0.0.1:3200",
        "E2E_JUNIT": (functional / "e2e.xml").as_posix(),
        "E2E_OUTPUT_DIR": (runner_temp / "e2e").as_posix(),
        "STUB_TEST_RC": str(test_rc),
        "STUB_INSTALL_RC": str(install_rc),
        "STUB_COMPACT_RC": str(compact_rc),
        "STUB_XML": "" if failures is None else _PLAYWRIGHT_XML.format(failures=failures),
    }
    done = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", script.as_posix()],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return done.returncode, functional


def _status(functional: Path) -> tuple[ScanStatus, list[str]]:
    context = ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability="functional",
        tool_name="junit",
        tool_version="",
        commit_sha="0" * 40,
        branch="main",
    )
    result = normalize_results("functional", "junit", functional, context)
    return result.scan_status, result.warnings


def test_a_passing_browser_suite_reads_as_a_passing_functional_run(tmp_path: Path) -> None:
    rc, functional = _run_step(tmp_path)
    assert rc == 0
    status, _ = _status(functional)
    assert status is ScanStatus.SUCCESS


def test_a_failing_browser_test_fails_the_functional_run_by_name(tmp_path: Path) -> None:
    rc, functional = _run_step(tmp_path, test_rc=1, failures=1)
    assert rc != 0
    status, warnings = _status(functional)
    assert status is not ScanStatus.SUCCESS
    assert any(w.startswith("hydration.spec.ts: ") for w in warnings), warnings


@pytest.mark.parametrize(
    "kwargs",
    [
        {"install_rc": 1},
        {"compact_rc": 1},
        {"test_rc": 1, "failures": None},
    ],
    ids=["browser-install-failed", "compaction-failed", "playwright-wrote-nothing"],
)
def test_a_suite_that_never_reported_cannot_read_as_a_pass(
    tmp_path: Path, kwargs: dict[str, Any]
) -> None:
    """Without a marker the upload would find only `functional.xml`, and a
    browser suite that never ran would read as a functional run that passed."""
    rc, functional = _run_step(tmp_path, **kwargs)
    assert rc != 0
    status, _ = _status(functional)
    assert status is not ScanStatus.SUCCESS


def test_a_job_killed_mid_suite_leaves_the_marker(tmp_path: Path) -> None:
    """A timeout or cancel runs no script logic, so the marker is on disk
    before the browser starts and replaced only by Playwright's report."""
    _run_step(tmp_path)
    during = tmp_path / "runner" / "during-e2e.xml"
    assert during.is_file(), "nothing marked the browser suite unfinished while it ran"
    assert 'errors="1"' in during.read_text(encoding="utf-8")
