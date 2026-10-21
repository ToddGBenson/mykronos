"""CI jobs that said one thing and did another (audit of 2026-10-20).

Each class pins one lane to what its name claims:

* `dependencies` scans the backend, and a manifest that yields no packages
  fails the job instead of reading as a clean supply chain;
* `insider` fails when GitHub did not answer the pull-request lookup, instead
  of reading the refusal as "no pull request";
* the quality lanes' uploads are checked rather than swallowed with `|| true`;
* a DAST scan that ran out of budget uploads as PARTIAL, not as a full pass.

The `ai` and `oracle-gate` items live beside their existing tests
(`test_ai_checks.py`, `test_deploy_follows_d048.py`), and keel's lane mapping
in `test_ci_job_audit.py`.
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

from mykronos.adapters import ScanContext
from mykronos.adapters.dast_zap import INCOMPLETE_MARKER
from mykronos.adapters.dast_zap import normalize as zap_normalize
from mykronos.adapters.registry import normalize_results
from mykronos.schemas import ScanStatus

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"


def _pipeline() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return document


def _script(job_name: str, task_name: str) -> str:
    job = next(j for j in _pipeline()["jobs"] if j["name"] == job_name)
    task = next(step for step in job["plan"] if step.get("task") == task_name)
    script: str = task["config"]["run"]["args"][-1]
    return script


def _zap_context() -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability="dast",
        tool_name="zap",
        tool_version="1",
        commit_sha="abc123",
        branch="main",
    )


def _zap_report() -> bytes:
    """A minimal ZAP JSON report with one medium alert."""
    return json.dumps(
        {
            "@version": "2.16.0",
            "site": [
                {
                    "@name": "http://frontend:3000",
                    "alerts": [
                        {
                            "pluginid": "10038",
                            "alertRef": "10038",
                            "alert": "Content Security Policy (CSP) Header Not Set",
                            "name": "Content Security Policy (CSP) Header Not Set",
                            "riskcode": "2",
                            "confidence": "3",
                            "riskdesc": "Medium (High)",
                            "desc": "<p>CSP is not set.</p>",
                            "instances": [
                                {"uri": "http://frontend:3000/", "method": "GET"}
                            ],
                            "count": "1",
                            "solution": "<p>Set it.</p>",
                            "cweid": "693",
                            "wascid": "15",
                        }
                    ],
                }
            ],
        }
    ).encode()


# -- 1. dependencies: the backend is scanned, and zero packages is not a pass --


def _manifest_guard() -> str:
    """The package-count check, verbatim from the osv-scanner task."""
    script = _script("dependencies", "osv-scanner")
    start = script.index("<<'PY' || manifests_rc=$?\n") + len("<<'PY' || manifests_rc=$?\n")
    end = script.index("\nPY\n", start)
    return script[start:end]


def _run_guard(tmp_path: Path, results: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "osv.json"
    report.write_text(json.dumps({"results": results}), encoding="utf-8")
    return subprocess.run(
        [
            sys.executable,
            "-",
            str(report),
            "backend/requirements.txt",
            "backend/requirements-dev.txt",
            "frontend/package-lock.json",
            "deploy/zap/requirements.txt",
        ],
        input=_manifest_guard(),
        capture_output=True,
        text=True,
        check=False,
    )


def _result(path: str, packages: int) -> dict[str, Any]:
    return {
        "source": {"path": f"/tmp/build/abc/source/{path}", "type": "lockfile"},
        "packages": [{"package": {"name": f"p{i}"}} for i in range(packages)],
    }


class TestDependenciesRefusesAnUnscannedManifest:
    def test_the_backend_lock_is_one_of_the_claimed_manifests(self) -> None:
        """The backend's lock (#961) is what the scan reads for the backend,
        so it is a manifest the guard insists on - a missing lock is red."""
        script = _script("dependencies", "osv-scanner")
        guard = script[script.index("python - /tmp/osv.json") : script.index("<<'PY'")]
        for manifest in (
            "backend/requirements.txt",
            "backend/requirements-dev.txt",
            "frontend/package-lock.json",
            "deploy/zap/requirements.txt",
        ):
            assert manifest in guard

    def test_every_claimed_manifest_with_packages_passes(self, tmp_path: Path) -> None:
        out = _run_guard(
            tmp_path,
            [
                _result("backend/requirements.txt", 89),
                _result("backend/requirements-dev.txt", 120),
                _result("frontend/package-lock.json", 517),
                _result("deploy/zap/requirements.txt", 8),
            ],
        )
        assert out.returncode == 0, out.stdout + out.stderr
        assert "backend/requirements.txt: 89 package(s)" in out.stdout

    def test_build_265_the_backend_never_scanned_fails(self, tmp_path: Path) -> None:
        """Exactly what build #265 scanned: 8 + 517 packages, no backend."""
        out = _run_guard(
            tmp_path,
            [
                _result("deploy/zap/requirements.txt", 8),
                _result("frontend/package-lock.json", 517),
            ],
        )
        assert out.returncode == 1
        assert "backend/requirements.txt: not scanned" in out.stdout
        assert "::error::" in out.stdout

    def test_a_manifest_with_zero_packages_fails(self, tmp_path: Path) -> None:
        out = _run_guard(
            tmp_path,
            [
                _result("backend/requirements.txt", 0),
                _result("backend/requirements-dev.txt", 120),
                _result("frontend/package-lock.json", 517),
                _result("deploy/zap/requirements.txt", 8),
            ],
        )
        assert out.returncode == 1
        assert "backend/requirements.txt: 0 package(s)" in out.stdout

    def test_an_unexpected_empty_manifest_fails_too(self, tmp_path: Path) -> None:
        out = _run_guard(
            tmp_path,
            [
                _result("backend/requirements.txt", 89),
                _result("backend/requirements-dev.txt", 120),
                _result("frontend/package-lock.json", 517),
                _result("deploy/zap/requirements.txt", 8),
                _result("functional/package-lock.json", 0),
            ],
        )
        assert out.returncode == 1
        assert "functional/package-lock.json" in out.stdout

    def test_the_verdict_is_decided_after_the_upload(self) -> None:
        """PS-3: a failed check must not cost the findings that were found."""
        script = _script("dependencies", "osv-scanner")
        upload = script.index("python -m mykronos.upload")
        assert script.index("manifests_rc=0") < upload
        assert script.index('if [ "$manifests_rc" -ne 0 ]; then') > upload


# -- 3. insider: a refused lookup is not "no pull request" ----------------------


class TestInsiderFailsWhenGitHubDidNotAnswer:
    def test_the_pull_request_lookup_must_be_a_200(self) -> None:
        script = _script("insider", "aegis")
        assert "|| echo '[]' > pulls.json" not in script
        assert "-w '%{http_code}'" in script
        check = script.index('if [ "$PULLS_CODE" != "200" ]; then')
        no_pr = script.index("NO PULL REQUEST FOR $SHA.")
        assert check < no_pr
        assert "exit 1" in script[check:no_pr]

    def test_a_200_that_is_not_a_list_fails_too(self) -> None:
        script = _script("insider", "aegis")
        assert "jq -r 'type' pulls.json" in script

    def test_every_github_call_carries_the_token_when_there_is_one(self) -> None:
        script = _script("insider", "aegis")
        calls = [m.start() for m in re.finditer(r'"\$API/', script)]
        assert len(calls) == 4, "expected pulls lookup, pr, reviews and permission calls"
        for start in calls:
            preceding = script[script.rindex("curl", 0, start) : start]
            assert '"${GH_AUTH[@]}"' in preceding, script[start : start + 60]
        # Built from the env var, never echoed.
        assert 'GH_AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")' in script
        assert not re.search(r"^\s*set -[a-z]*x", script, re.MULTILINE)
        assert not re.search(r"echo[^\n]*GITHUB_TOKEN", script)

    def test_a_failed_reviews_fetch_is_not_zero_reviews(self) -> None:
        script = _script("insider", "aegis")
        assert "|| echo '[]' > reviews.json" not in script
        assert '"$API/pulls/$PR/reviews" > reviews.json\n' in script


# -- 7. uploads are checked, not swallowed --------------------------------------


@pytest.mark.parametrize(
    ("job", "task"),
    [
        ("unit", "pytest"),
        ("coverage", "pytest-cov"),
        ("lint-and-types", "ruff-and-mypy"),
        ("qa-spec-links", "check-links"),
    ],
)
def test_a_failed_upload_fails_the_job(job: str, task: str) -> None:
    script = _script(job, task)
    upload = script.index("python -m mykronos.upload")
    tail = script[upload:]
    assert "|| true" not in tail.split("\n\n")[0], f"{job}'s upload is swallowed again"
    assert "|| upload_rc=$?" in tail
    check = tail.index('if [ "$upload_rc" -ne 0 ]; then')
    assert 'exit "$upload_rc"' in tail[check:]
    assert "did not reach Mykronos" in tail[check:]


def test_no_upload_in_the_pipeline_ends_in_or_true() -> None:
    text = PIPELINE.read_text(encoding="utf-8")
    assert "--blocking false || true" not in text


def test_the_unit_comment_no_longer_points_at_a_retired_lane() -> None:
    """D-118 retired the Actions unit lane; coverage is the weekly job (D-121)."""
    script = _script("unit", "pytest")
    assert "Coverage is collected on\n# the Actions unit lane" not in script
    assert "the Actions unit lane instead" not in script
    assert "`coverage` job below instead (D-121)" in script


# -- 5. a DAST scan that ran out of budget is partial, not a full pass ---------


class TestAnIncompleteDastScanIsPartial:
    def test_the_marker_alone_is_a_partial_failure_with_its_reason(self) -> None:
        marker = f"{INCOMPLETE_MARKER} the active scan did not reach 100% within 2400s\n"

        result = zap_normalize(marker.encode(), _zap_context())

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE
        assert result.findings == []
        assert "did not complete" in result.warnings[0]
        assert "2400s" in result.warnings[0]

    def test_the_report_beside_it_still_ingests_but_the_run_is_partial(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "zap.json").write_bytes(_zap_report())
        (tmp_path / "zap-incomplete.json").write_text(
            f"{INCOMPLETE_MARKER} the active scan did not reach 100% within 2400s\n",
            encoding="utf-8",
        )

        result = normalize_results("dast", "zap", tmp_path, _zap_context())

        assert result.findings, "the findings the scan did produce were lost"
        assert result.scan_status is ScanStatus.PARTIAL_FAILURE

    def test_without_the_marker_the_same_report_is_a_success(self, tmp_path: Path) -> None:
        (tmp_path / "zap.json").write_bytes(_zap_report())

        result = normalize_results("dast", "zap", tmp_path, _zap_context())

        assert result.scan_status is ScanStatus.SUCCESS

    def test_the_actions_lane_writes_the_marker_on_a_budget_overrun(self) -> None:
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        step = next(s for s in doc["jobs"]["demo-and-dast"]["steps"] if s.get("id") == "zap")
        run: str = step["run"]
        report = run.index('/OTHER/core/other/jsonreport/" > "$RUNNER_TEMP/dast/zap.json"')
        marker = run.index('> "$RUNNER_TEMP/dast/zap-incomplete.json"')
        assert report < marker, "the marker must sit beside a report that exists"
        assert INCOMPLETE_MARKER in run[report:marker + 60]
        assert '[ "$SPIDER_OK" -eq 0 ]' in run and '[ "$ACTIVE_OK" -eq 0 ]' in run
        # The budgets themselves are unchanged: the fix is the status.
        assert 'poll "/JSON/ascan/view/status/" 2400' in run
        assert 'poll "/JSON/spider/view/status/" 600' in run

    def test_the_actions_dast_upload_can_go_red(self) -> None:
        """A partial run fails the uploader (spec 04 §8); that must reach the job."""
        doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        step = next(
            s for s in doc["jobs"]["demo-and-dast"]["steps"]
            if s.get("name") == "Upload the DAST result"
        )
        assert not step.get("continue-on-error")

    def test_the_concourse_lane_writes_the_marker_too(self) -> None:
        script = _script("demo-and-dast", "functional-and-dast")
        assert '[ "$st" = "100" ] || INCOMPLETE=' in script
        assert 'if [ "$st" != "100" ]; then' in script
        marker = f'echo "{INCOMPLETE_MARKER} ${{INCOMPLETE}}."'
        assert f"{marker} > ../results/zap-incomplete.json" in script
