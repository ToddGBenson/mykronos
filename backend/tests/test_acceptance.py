"""Spec 05 §9 acceptance criteria that are measured rather than asserted.

Marked `slow` so the fast suite stays fast:

    pytest -m "not slow"     # inner loop
    pytest                   # everything, as CI runs it
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from mykronos.lake import Catalog
from tests.conftest import finding_payload, issue_token, post_findings, post_scan

BATCH = 10_000
BUDGET_SECONDS = 30.0


@pytest.mark.slow
def test_ten_thousand_findings_within_thirty_seconds(
    client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
) -> None:
    """"A scanner workflow can register a ScanRun and submit 10,000 findings
    in under 30 seconds against a locally running instance."

    Measures the whole path a workflow actually pays for: register, submit,
    and compact to queryable Parquet.
    """
    findings = [
        finding_payload(
            rule_id=f"CWE-{i % 90}",
            file_path=f"src/module_{i % 500}.py",
            symbol=f"handler_{i}",
            code_snippet=f"unsafe_call(user_input_{i})",
            line_start=i,
            line_end=i + 2,
        )
        for i in range(BATCH)
    ]

    started = time.perf_counter()
    assert post_scan(client, auth, finding_count=BATCH).status_code == 200
    response = post_findings(client, auth, findings)
    assert response.status_code == 200
    assert response.json()["accepted"] == BATCH
    run_compaction()
    elapsed = time.perf_counter() - started

    assert catalog.count("findings") == BATCH
    assert elapsed < BUDGET_SECONDS, (
        f"ingest + compact of {BATCH} findings took {elapsed:.1f}s, "
        f"budget is {BUDGET_SECONDS:.0f}s (spec 05 §9)"
    )


@pytest.mark.slow
def test_rescanning_ten_thousand_findings_updates_rather_than_grows(
    client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
) -> None:
    """The steady state a real repo lives in: the same findings, every run.

    This is the expensive path — every row is an update, so the whole
    partition is rewritten. If dedup at scale were going to be a problem, it
    would show here rather than on the first ingest.
    """
    findings = [
        finding_payload(
            rule_id=f"CWE-{i % 90}",
            file_path=f"src/module_{i % 500}.py",
            symbol=f"handler_{i}",
            code_snippet=f"unsafe_call(user_input_{i})",
            line_start=i,
        )
        for i in range(BATCH)
    ]

    post_findings(client, auth, findings)
    run_compaction()
    assert catalog.count("findings") == BATCH

    # Same findings, every line shifted by a header comment added to each file.
    shifted = [dict(f, line_start=f["line_start"] + 5) for f in findings]

    started = time.perf_counter()
    post_findings(client, auth, shifted, scan_run_id="rescan")
    run_compaction()
    elapsed = time.perf_counter() - started

    assert catalog.count("findings") == BATCH, "a rescan must not grow the table"
    assert elapsed < BUDGET_SECONDS, (
        f"rescan of {BATCH} findings took {elapsed:.1f}s, budget {BUDGET_SECONDS:.0f}s"
    )


@pytest.mark.slow
def test_portfolio_scale_query_stays_interactive(
    client: TestClient, catalog: Catalog, run_compaction
) -> None:
    """Spec 10 §6 wants a 200-repo portfolio view in under 2 seconds.

    Phase 0 cannot test the dashboard, but it can check that the underlying
    aggregate over a portfolio-shaped lake is not itself the bottleneck —
    before anyone builds materialized views to paper over a slow base query.
    """
    repos = 40
    per_repo = 250

    for r in range(repos):
        repo = f"example-org/service-{r:03d}"
        headers = {"Authorization": f"Bearer {issue_token(client, repo, 'sast')}"}
        post_findings(
            client,
            headers,
            [
                finding_payload(
                    rule_id=f"CWE-{i % 40}",
                    file_path=f"src/m{i}.py",
                    symbol=f"fn_{i}",
                    code_snippet=f"call_{i}()",
                    severity=["critical", "high", "medium", "low"][i % 4],
                )
                for i in range(per_repo)
            ],
            scan_run_id=f"run-{r}",
        )
    run_compaction()

    assert catalog.count("findings") == repos * per_repo

    started = time.perf_counter()
    rows = catalog.query(
        """
        SELECT repo_full_name,
               count(*) FILTER (WHERE severity = 'critical') AS critical,
               count(*) FILTER (WHERE severity = 'high')     AS high,
               max(last_seen_at)                             AS last_seen
        FROM findings
        WHERE status = 'open'
        GROUP BY repo_full_name
        ORDER BY critical DESC
        """
    )
    elapsed = time.perf_counter() - started

    assert len(rows) == repos
    assert elapsed < 2.0, f"portfolio aggregate took {elapsed:.2f}s (spec 10 §6 budget: 2s)"
