"""The upload step — spec 04 §2, spec 05 §6, spec 01 §6.

The governing rule is that findings are never silently dropped. Most of these
tests are about what happens when something goes wrong, because that is where
that rule is either honoured or quietly broken.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from mykronos.adapters.base import AdapterResult
from mykronos.schemas import FindingSubmission, ScanStatus, Severity
from mykronos.upload import (
    MAX_ATTEMPTS,
    IngestionClient,
    UploadError,
    UploadOutcome,
    count_blocking,
    upload,
    write_step_summary,
)
from tests.test_adapters import sarif

REPO = "example-org/payments-api"


class StubResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {"accepted": 0}
        self.headers: dict[str, str] = {}
        self.content = b"x"
        self.text = json.dumps(self._payload)

    def json(self) -> dict[str, Any]:
        return self._payload


class RecordingClient(IngestionClient):
    """An IngestionClient that records calls instead of making them."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        super().__init__("https://mykronos.test", "token")
        self.calls: list[tuple[str, dict[str, Any] | None, dict[str, Any] | None]] = []
        self.responses = responses or {}
        self.fail_on: set[str] = set()

    def post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        content: bytes | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append((path, json_body, params))
        if path in self.fail_on:
            raise UploadError(f"stubbed failure for {path}")
        default: dict[str, Any] = {"accepted": len((json_body or {}).get("findings", []))}
        if path == "/api/ingest/raw":
            default = {"raw_output_ref": "raw/example-org/payments-api/run/x.sarif"}
        return self.responses.get(path, default)

    def paths(self) -> list[str]:
        return [c[0] for c in self.calls]

    def bodies_for(self, path: str) -> list[dict[str, Any]]:
        return [c[1] for c in self.calls if c[0] == path and c[1] is not None]


def make_args(results_path: Path, workspace: Path, **overrides: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "capability": "sast",
        "tool": "codeql",
        "tool_version": "2.19.0",
        "results_path": str(results_path),
        "ingestion_url": "https://mykronos.test",
        "token": "tok",
        "repo": REPO,
        "commit_sha": "a91f2c7",
        "branch": "main",
        "workflow_run_id": "9900123",
        "triggered_by": "pull_request",
        "pr_number": 2841,
        "workspace": str(workspace),
        "scan_run_id": "run-1",
        "severity_threshold": "low",
        "blocking": "false",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


@pytest.fixture
def results(tmp_path: Path) -> Path:
    directory = tmp_path / "codeql-results"
    directory.mkdir()
    (directory / "python.sarif").write_bytes(sarif())
    return directory


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "orders").mkdir(parents=True, exist_ok=True)
    (tmp_path / "orders" / "query.py").write_text(
        "def get_order(order_id):\n"
        "    cursor = conn.cursor()\n"
        '    cursor.execute("SELECT * FROM orders WHERE id = " + order_id)\n'
        "    return cursor.fetchone()\n" * 5,
        encoding="utf-8",
    )
    return tmp_path


class TestRetries:
    def test_retries_then_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """spec 05 §6: back off on 429/503 rather than dropping findings."""
        attempts = {"n": 0}

        class Client:
            def __init__(self, **_: Any) -> None: ...
            def __enter__(self) -> Client:
                return self
            def __exit__(self, *_: Any) -> None: ...
            def post(self, *_: Any, **__: Any) -> StubResponse:
                attempts["n"] += 1
                return StubResponse(200 if attempts["n"] == 3 else 429)

        monkeypatch.setattr("mykronos.upload.httpx2.Client", Client)
        monkeypatch.setattr("mykronos.upload.time.sleep", lambda _: None)

        assert IngestionClient("https://x", "t").post("/api/ingest/findings") is not None
        assert attempts["n"] == 3

    def test_gives_up_loudly_rather_than_silently(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scan that could not record its findings must fail the step, not
        pass with nothing stored."""
        class Client:
            def __init__(self, **_: Any) -> None: ...
            def __enter__(self) -> Client:
                return self
            def __exit__(self, *_: Any) -> None: ...
            def post(self, *_: Any, **__: Any) -> StubResponse:
                return StubResponse(503)

        monkeypatch.setattr("mykronos.upload.httpx2.Client", Client)
        monkeypatch.setattr("mykronos.upload.time.sleep", lambda _: None)

        with pytest.raises(UploadError) as excinfo:
            IngestionClient("https://x", "t").post("/api/ingest/findings")

        assert f"{MAX_ATTEMPTS} attempts" in str(excinfo.value)
        assert "NOT recorded" in str(excinfo.value)

    def test_a_4xx_is_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 403 will be just as forbidden next time. Retrying it burns CI
        minutes and buries the real error."""
        attempts = {"n": 0}

        class Client:
            def __init__(self, **_: Any) -> None: ...
            def __enter__(self) -> Client:
                return self
            def __exit__(self, *_: Any) -> None: ...
            def post(self, *_: Any, **__: Any) -> StubResponse:
                attempts["n"] += 1
                return StubResponse(403)

        monkeypatch.setattr("mykronos.upload.httpx2.Client", Client)
        monkeypatch.setattr("mykronos.upload.time.sleep", lambda _: None)

        with pytest.raises(UploadError, match="will not be retried"):
            IngestionClient("https://x", "t").post("/api/ingest/findings")
        assert attempts["n"] == 1

    def test_retry_after_header_is_honoured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        slept: list[float] = []

        class Client:
            def __init__(self, **_: Any) -> None: ...
            def __enter__(self) -> Client:
                return self
            def __exit__(self, *_: Any) -> None: ...
            def post(self, *_: Any, **__: Any) -> StubResponse:
                response = StubResponse(429 if not slept else 200)
                response.headers["Retry-After"] = "7"
                return response

        monkeypatch.setattr("mykronos.upload.httpx2.Client", Client)
        monkeypatch.setattr("mykronos.upload.time.sleep", slept.append)

        IngestionClient("https://x", "t").post("/api/ingest/findings")
        assert slept == [7.0]


class TestOrchestration:
    def test_registers_the_run_before_and_after(
        self, results: Path, workspace: Path
    ) -> None:
        """spec 04 §7: exactly one ScanRun per run, upserted on the same id."""
        client = RecordingClient()
        upload(make_args(results, workspace), client=client)

        scan_runs = client.bodies_for("/api/ingest/scan-run")
        assert len(scan_runs) == 2
        assert scan_runs[0]["scan_run_id"] == scan_runs[1]["scan_run_id"] == "run-1"
        assert scan_runs[0].get("completed_at") is None
        assert scan_runs[1]["completed_at"] is not None

    def test_findings_are_posted_with_their_capability(
        self, results: Path, workspace: Path
    ) -> None:
        client = RecordingClient()
        outcome = upload(make_args(results, workspace), client=client)

        body = client.bodies_for("/api/ingest/findings")[0]
        assert body["capability"] == "sast"
        assert body["scan_run_id"] == "run-1"
        assert outcome.findings_accepted == 1

    def test_the_finalised_run_records_the_finding_count(
        self, results: Path, workspace: Path
    ) -> None:
        client = RecordingClient()
        upload(make_args(results, workspace), client=client)
        assert client.bodies_for("/api/ingest/scan-run")[1]["finding_count"] == 1

    def test_the_raw_output_is_archived_and_referenced(
        self, results: Path, workspace: Path
    ) -> None:
        """spec 05 §7: a disputed finding must be traceable back to exactly
        what the tool said."""
        client = RecordingClient()
        outcome = upload(make_args(results, workspace), client=client)

        assert "/api/ingest/raw" in client.paths()
        assert outcome.raw_output_ref
        assert client.bodies_for("/api/ingest/scan-run")[1]["raw_output_ref"]

    def test_losing_the_archive_does_not_lose_the_findings(
        self, results: Path, workspace: Path
    ) -> None:
        """The archive is for dispute resolution; the findings are what the
        platform runs on. Failing the former must not discard the latter."""
        client = RecordingClient()
        client.fail_on = {"/api/ingest/raw"}

        outcome = upload(make_args(results, workspace), client=client)

        assert outcome.findings_accepted == 1
        assert outcome.raw_output_ref is None

    def test_pr_number_zero_becomes_null(self, results: Path, workspace: Path) -> None:
        """GitHub expression fallbacks yield 0 for "not a pull request"; a run
        claiming to belong to PR #0 would be a lie in the audit trail."""
        client = RecordingClient()
        upload(make_args(results, workspace, pr_number=0), client=client)
        assert client.bodies_for("/api/ingest/scan-run")[0]["pr_number"] is None

    def test_a_failed_scan_is_still_registered(
        self, tmp_path: Path, workspace: Path
    ) -> None:
        """The worst outcome would be a gap: the lake must show the run
        happened and failed (spec 04 §7)."""
        client = RecordingClient()
        outcome = upload(make_args(tmp_path / "missing", workspace), client=client)

        finalised = client.bodies_for("/api/ingest/scan-run")[1]
        assert finalised["scan_status"] == ScanStatus.FAILURE.value
        assert outcome.scan_status is ScanStatus.FAILURE

    def test_an_empty_scan_still_posts_a_findings_call(
        self, tmp_path: Path, workspace: Path
    ) -> None:
        """"Scanned and found nothing" has to be distinguishable from "never
        ran" (spec 04 §6), which means saying so explicitly."""
        results = tmp_path / "empty-results"
        results.mkdir()
        (results / "python.sarif").write_bytes(
            json.dumps({"version": "2.1.0", "runs": []}).encode()
        )
        client = RecordingClient()

        outcome = upload(make_args(results, workspace), client=client)

        assert client.bodies_for("/api/ingest/findings")[0]["findings"] == []
        assert outcome.scan_status is ScanStatus.SUCCESS


class TestBlocking:
    def _findings(self, *severities: Severity) -> list[FindingSubmission]:
        return [
            FindingSubmission(rule_id=f"R{i}", title="t", severity=s)
            for i, s in enumerate(severities)
        ]

    def test_counts_at_or_above_the_threshold(self) -> None:
        findings = self._findings(
            Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL
        )
        assert count_blocking(findings, Severity.HIGH) == 2
        assert count_blocking(findings, Severity.LOW) == 3
        assert count_blocking(findings, Severity.CRITICAL) == 1

    def test_below_threshold_findings_are_still_ingested(
        self, results: Path, workspace: Path
    ) -> None:
        """spec 04 §5: below-threshold findings are kept for trend data, they
        just do not block."""
        client = RecordingClient()
        outcome = upload(
            make_args(results, workspace, severity_threshold="critical"), client=client
        )
        assert outcome.findings_accepted == 1


class TestStepSummary:
    def test_writes_a_severity_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """spec 04 §2. For most developers this is the only Mykronos surface
        they will ever see."""
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))

        result = AdapterResult(
            findings=[
                FindingSubmission(rule_id="a", title="t", severity=Severity.CRITICAL),
                FindingSubmission(rule_id="b", title="t", severity=Severity.LOW),
            ],
            warnings=["1 finding had no code snippet"],
        )
        write_step_summary(UploadOutcome(scan_run_id="run-1"), result, "sast", "codeql")

        text = summary.read_text(encoding="utf-8")
        assert "| critical | 1 |" in text
        assert "| low | 1 |" in text
        assert "no code snippet" in text
        assert "run-1" in text

    def test_says_so_when_there_is_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        summary = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
        write_step_summary(UploadOutcome(scan_run_id="r"), AdapterResult(), "sast", "codeql")
        assert "_none_" in summary.read_text(encoding="utf-8")

    def test_absent_outside_actions_is_not_an_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
        write_step_summary(UploadOutcome(scan_run_id="r"), AdapterResult(), "sast", "codeql")


class TestAdapterDispatch:
    def test_unknown_pairing_is_refused_clearly(
        self, results: Path, workspace: Path
    ) -> None:
        client = RecordingClient()
        with pytest.raises(UploadError, match="No adapter"):
            upload(make_args(results, workspace, tool="not-a-real-tool"), client=client)

    def test_the_error_names_what_is_supported(
        self, results: Path, workspace: Path
    ) -> None:
        """An operator who typo'd a tool name should be told the options,
        not just that they were wrong."""
        client = RecordingClient()
        with pytest.raises(UploadError) as excinfo:
            upload(make_args(results, workspace, tool="codeqll"), client=client)

        message = str(excinfo.value)
        assert "codeqll" in message
        assert "codeql" in message and "semgrep" in message

    def test_a_registered_alternative_tool_works(
        self, results: Path, workspace: Path
    ) -> None:
        """Semgrep is SARIF-native, so spec 04 §3's secondary SAST tool needs
        no adapter code of its own."""
        client = RecordingClient()
        outcome = upload(make_args(results, workspace, tool="semgrep"), client=client)
        assert outcome.findings_accepted == 1
