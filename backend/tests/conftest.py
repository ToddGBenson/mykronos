from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.config import Settings
from mykronos.lake import Catalog, WriteAheadBuffer, compact
from mykronos.main import create_app

REPO = "example-org/payments-api"
CAPABILITY = "sast"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        datalake_dir=tmp_path / "datalake",
        token_registry_path=tmp_path / "tokens.json",
        # Compaction is driven explicitly in tests so assertions never race a timer.
        run_compaction_in_background=False,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def catalog(settings: Settings) -> Catalog:
    return Catalog(settings.datalake_dir)


@pytest.fixture
def buffer(settings: Settings) -> WriteAheadBuffer:
    return WriteAheadBuffer(settings.buffer_dir)


@pytest.fixture
def run_compaction(catalog: Catalog, buffer: WriteAheadBuffer) -> Callable[[], Any]:
    def _run() -> Any:
        return compact(catalog, buffer)

    return _run


@pytest.fixture
def token(client: TestClient) -> str:
    return str(client.app.state.tokens.issue(REPO, CAPABILITY))  # type: ignore[attr-defined]


@pytest.fixture
def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# Payload builders
# --------------------------------------------------------------------------


def scan_run_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scan_run_id": "11111111-1111-1111-1111-111111111111",
        "repo_full_name": REPO,
        "capability": CAPABILITY,
        "tool_name": "codeql",
        "tool_version": "2.19.0",
        "commit_sha": "a91f2c7",
        "branch": "main",
        "pr_number": 2841,
        "triggered_by": "pull_request",
        "github_workflow_run_id": "9900123",
        "started_at": datetime.now(UTC).replace(tzinfo=None).isoformat(),
        "scan_status": "success",
        "finding_count": 1,
    }
    payload.update(overrides)
    return payload


SNIPPET = """
    def get_order(order_id):
        cursor.execute("SELECT * FROM orders WHERE id = " + order_id)
        return cursor.fetchone()
"""


def finding_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": "CWE-89",
        "title": "SQL injection via string concatenation",
        "description": "User input is concatenated into a SQL statement.",
        "severity": "critical",
        "cvss_score": 9.1,
        "file_path": "orders/query.py",
        "line_start": 214,
        "line_end": 216,
        "symbol": "get_order",
        "code_snippet": SNIPPET,
        "raw_finding_json": {"ruleId": "CWE-89", "level": "error"},
    }
    payload.update(overrides)
    return payload


def dependency_finding(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": "CVE-2024-4812",
        "title": "urllib3 redirect handling flaw",
        "severity": "high",
        "package_name": "urllib3",
        "package_version": "2.0.4",
    }
    payload.update(overrides)
    return payload


def post_scan(client: TestClient, auth: dict[str, str], **overrides: Any) -> Any:
    return client.post("/api/ingest/scan-run", json=scan_run_payload(**overrides), headers=auth)


def post_findings(
    client: TestClient,
    auth: dict[str, str],
    findings: list[dict[str, Any]],
    scan_run_id: str = "11111111-1111-1111-1111-111111111111",
) -> Any:
    return client.post(
        "/api/ingest/findings",
        json={"scan_run_id": scan_run_id, "findings": findings},
        headers=auth,
    )


def later(minutes: int) -> str:
    return (
        (datetime.now(UTC) + timedelta(minutes=minutes))
        .replace(tzinfo=None)
        .isoformat()
    )
