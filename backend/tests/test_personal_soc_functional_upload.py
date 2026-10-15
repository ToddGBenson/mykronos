"""personal-soc's `functional` lane reports what it ran (PS-1, D-046).

The job executed real assertions against Compare-Assessment and Find-DocDrift
on every commit and uploaded nothing, so `functional` for personal-soc read in
the lake exactly like a capability nobody runs: green in Concourse, blind in
Mykronos. These pin the reporting half.

Three properties, each a way the report could lie:

* the result is uploaded as `--capability functional --tool junit`, from an
  `ensure:` hook, so a failing suite still reports (PS-3);
* the hook's `results` input is optional, so a task that never started still
  reaches the uploader, which reports a missing path as a failed scan;
* a FAILING report is on disk before anything runs, so a task that dies part
  way can never leave behind something that reads as a pass.

The PowerShell harness is EXECUTED where `pwsh` is available, against stub
scripts, rather than grepped for words: the report it writes is parsed by the
adapter the platform uses.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos.adapters.base import ScanContext
from mykronos.adapters.tests_junit import normalize
from mykronos.schemas import ScanStatus

PIPELINE = (
    Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "personal-soc.yml"
)
JOB = "functional"
TASK = "run-tests"
REPORT = "results/functional.xml"


def _job() -> dict[str, Any]:
    document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(job for job in document["jobs"] if job["name"] == JOB)


def _task() -> dict[str, Any]:
    return next(step for step in _job()["plan"] if step.get("task") == TASK)


def _script(step: dict[str, Any]) -> str:
    return str(step["config"]["run"]["args"][-1])


def _hook() -> dict[str, Any]:
    hook = _task().get("ensure")
    assert isinstance(hook, dict), f"`{TASK}` has no `ensure:` hook, so nothing uploads its result"
    return hook


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/personal-soc",
        capability="functional",
        tool_name="junit",
        tool_version="",
        commit_sha="0" * 40,
        branch="main",
    )


def _marker() -> str:
    match = re.search(
        r"cat > results/functional\.xml <<'XML'\n(.*?)\nXML\n", _script(_task()), re.DOTALL
    )
    assert match, f"`{TASK}` writes no placeholder report before it runs"
    return match.group(1)


def _harness() -> str:
    match = re.search(r"cat > tests\.ps1 <<'PS'\n(.*?)\nPS\n", _script(_task()), re.DOTALL)
    assert match, "the PowerShell harness is no longer a `tests.ps1` heredoc"
    return match.group(1)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_the_result_is_uploaded_as_functional_junit() -> None:
    hook = _hook()
    assert hook["task"] == "upload"
    assert hook.get("timeout"), "a hook with no timeout can hold the single worker (PS-7)"
    body = " ".join(_script(hook).split())
    assert "python -m mykronos.upload" in body
    assert "--capability functional --tool junit" in body
    assert "--repo ToddGBenson/personal-soc" in body
    assert "--results-path ../results" in body
    assert "((personal-soc-ingestion-token))" in str(hook["params"]["MYKRONOS_TOKEN"])


def test_the_uploader_has_its_image_and_the_job_probes_mykronos_first() -> None:
    plan = _job()["plan"]
    assert any(step.get("get") == "python" for step in plan), "the upload runs in `python`"
    assert _hook()["image"] == "python"
    assert any(step.get("task") == "preflight" for step in plan), "PS-2"


def test_an_upload_survives_a_suite_that_never_started() -> None:
    """The task's `results` volume exists only once it runs; the hook must not
    require it, or a task that dies at start errors instead of reporting."""
    outputs = {o["name"] for o in _task()["config"]["outputs"]}
    assert "results" in outputs
    inputs = {i["name"]: i for i in _hook()["config"]["inputs"]}
    assert "source" in inputs
    assert inputs["results"].get("optional") is True


def test_a_missing_report_is_not_skipped_as_if_nothing_happened() -> None:
    """The uploader reports a missing or empty results path as a failed scan.
    A hook that checks for the file and quietly exits 0 throws that away."""
    body = _script(_hook())
    assert "-s results" not in body and "-f results" not in body


def test_a_failing_report_is_written_before_anything_runs() -> None:
    script = _script(_task())
    marker_at = script.index("cat > results/functional.xml")
    for later in ("apt-get", "pwsh -NonInteractive"):
        assert marker_at < script.index(later), f"the placeholder is written after `{later}`"

    result = normalize(_marker().encode(), _context())
    assert result.scan_status is ScanStatus.FAILURE, result.warnings


def test_the_conformance_checker_passes_the_job() -> None:
    import importlib.util

    path = Path(__file__).resolve().parents[2] / "scripts" / "check_pipeline_conformance.py"
    spec = importlib.util.spec_from_file_location("check_pipeline_conformance", path)
    assert spec and spec.loader
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    problems, _ = checker.check_pipeline(PIPELINE)
    assert not [p for p in problems if f":{JOB} " in p], problems


# ---------------------------------------------------------------------------
# The harness, executed
# ---------------------------------------------------------------------------

PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed here")

#: Stands in for Compare-Assessment.ps1: writes the numbers the harness expects
#: for each fixture directory, keyed by the directory's name.
COMPARE_STUB = r"""
param([string]$Baseline, [string]$Current)
$name = Split-Path $Current -Leaf
$s = @{ score_baseline=100; score_current=100; score_delta=0; resolved=0; new=0;
         band_current='Excellent'; severity_changed=0 }
if ($name -like 'cur*') {
  $s.score_baseline = 93; $s.score_current = 84; $s.score_delta = -9; $s.band_current = 'Good'
}
if ($name -eq 'cur')  { $s.resolved = 1; $s.new = 1 }
if ($name -eq 'cur2') { $s.severity_changed = 1 }
$s | ConvertTo-Json | Set-Content (Join-Path $Current 'change-summary.json')
"""

#: Stands in for Find-DocDrift.ps1, through Write-Host as the real one reports.
DRIFT_STUB = r"""
param([string]$Doc, [string[]]$Paths)
if ((git log -1 --format=%s) -eq 'initial') { Write-Host 'README.md is likely current' }
else { Write-Host 'drift: src/a.ps1' }
"""


def _run(tmp_path: Path, *, stubs: bool) -> tuple[int, str, ET.Element]:
    (tmp_path / "results").mkdir()
    (tmp_path / REPORT).write_text(_marker(), encoding="utf-8")
    if stubs:
        compare = tmp_path / "source/skills/network-assessment/scripts/Compare-Assessment.ps1"
        drift = tmp_path / "source/skills/update-docs/scripts/Find-DocDrift.ps1"
        for path, body in ((compare, COMPARE_STUB), (drift, DRIFT_STUB)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
    (tmp_path / "tests.ps1").write_text(_harness(), encoding="utf-8")
    proc = subprocess.run(
        [str(PWSH), "-NonInteractive", "-NoProfile", "-File", "tests.ps1"],
        cwd=tmp_path, capture_output=True, text=True, timeout=300, check=False,
    )
    raw = (tmp_path / REPORT).read_bytes()
    return proc.returncode, raw.decode("utf-8", errors="replace"), ET.fromstring(raw)


@needs_pwsh
def test_a_passing_suite_reports_every_assertion(tmp_path: Path) -> None:
    rc, raw, root = _run(tmp_path, stubs=True)
    assert rc == 0, raw
    result = normalize(raw.encode(), _context())
    assert result.scan_status is ScanStatus.SUCCESS, result.warnings

    cases = list(root.iter("testcase"))
    ran = [c for c in cases if c.find("skipped") is None]
    # 7 Compare-Assessment + 2 severity-changed + 3 Find-DocDrift assertions.
    assert len(ran) == 12, [c.get("name") for c in cases]
    assert all(c.find("failure") is None for c in cases)
    # What is not covered is named in the report, not only in the log.
    skipped = [c for c in cases if c.find("skipped") is not None]
    assert any("Invoke-BreachCheck" in (c.get("name") or "") for c in skipped)


@needs_pwsh
def test_a_suite_that_dies_reports_failure_not_silence(tmp_path: Path) -> None:
    """No scripts to test: the first call throws. The report must say the suite
    aborted, and must not be the bare placeholder either."""
    rc, raw, root = _run(tmp_path, stubs=False)
    assert rc != 0
    result = normalize(raw.encode(), _context())
    assert result.scan_status is ScanStatus.FAILURE, result.warnings
    failed = [c.get("name") or "" for c in root.iter("testcase") if c.find("failure") is not None]
    assert any("aborted" in name for name in failed), failed
