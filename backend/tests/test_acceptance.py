"""Spec 05 §9 acceptance criteria that are measured rather than asserted.

Marked `slow` so the fast suite stays fast:

    pytest -m "not slow"     # inner loop
    pytest                   # everything, as CI runs it

**Why these budgets scale, and why the spec numbers are still written here
literally.**

Spec 05 §9 asks for 10,000 findings ingested and compacted "in under 30
seconds *against a locally running instance*", and spec 10 §6 for a 200-repo
portfolio view under 2 seconds. Both are claims about what the platform can do
on a developer's machine, which is the machine the person waiting on it is
using.

The Concourse worker is not that machine. It is a container inside Docker
Desktop on a host that is also running the Mykronos stack, a registry, MinIO,
TheHub's twelve services, and up to four pipeline jobs at once — including
another job doing a cold `pip install` of a large dependency set. Measuring
wall-clock there measures the contention, not the code: the same commit came in
at 61.3s on one run and passed comfortably on the next two.

So `MYKRONOS_PERF_MULTIPLIER` scales every budget in this file by one declared
factor, defaulting to 1.0. The spec's numbers stay in the source unedited and
are what a developer's run enforces; CI states its multiplier in the build log
so a relaxed budget is never a silent one.

What this deliberately does *not* do is stop measuring. Every assertion still
runs and still fails past the scaled budget, so a genuine regression — an
accidental O(n²), a lost vectorised path — still turns the lane red. A 2x
tolerance absorbs a busy worker; it does not absorb 21 seconds of row-by-row
inserts (D-003).
"""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

from mykronos.lake import Catalog
from tests.conftest import finding_payload, issue_token, post_findings, post_scan


def _multiplier() -> float:
    """Budget scaling for the machine the tests are running on.

    Invalid or non-positive values fall back to 1.0 rather than raising: a
    typo in a pipeline variable must not turn every performance test into an
    error whose message is about parsing.
    """
    try:
        value = float(os.environ.get("MYKRONOS_PERF_MULTIPLIER", "1"))
    except ValueError:
        return 1.0
    return value if value > 0 else 1.0


PERF_MULTIPLIER = _multiplier()

BATCH = 10_000
#: spec 05 §9. Scaled — see the module docstring.
BUDGET_SECONDS = 30.0 * PERF_MULTIPLIER
#: spec 10 §6.
PORTFOLIO_BUDGET_SECONDS = 2.0 * PERF_MULTIPLIER


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
def test_portfolio_endpoint_stays_within_budget(
    client: TestClient, admin_auth: dict[str, str], catalog: Catalog, run_compaction
) -> None:
    """spec 10 §6: the portfolio view loads in under 2 seconds for 200 repos.

    This test is why the materialized views spec 10 §3 describes are deferred
    rather than skipped (docs/DECISIONS.md D-016). It measures the *endpoint*,
    not just the SQL — onboarding rows, the DuckDB aggregate, the Python join
    and serialisation — against the real budget. If the live query ever
    outgrows it, this fails and the cache stops being premature.
    """
    from tests.test_onboarding import onboard

    repos = 200
    per_repo = 25

    for index in range(repos):
        repo = f"example-org/service-{index:03d}"
        onboard(client, admin_auth, repo=repo)
        headers = {"Authorization": f"Bearer {issue_token(client, repo, 'sast')}"}
        post_scan(client, headers, repo_full_name=repo, scan_run_id=f"run-{index}")
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
            scan_run_id=f"run-{index}",
        )
    run_compaction()

    assert catalog.count("findings") == repos * per_repo

    started = time.perf_counter()
    response = client.get("/api/dashboard/portfolio", headers=admin_auth)
    elapsed = time.perf_counter() - started

    assert response.status_code == 200
    body = response.json()
    # Printed so the headroom is visible in CI output, not just the pass/fail.
    print(
        f"\nportfolio endpoint: {elapsed:.3f}s for {repos} repos / "
        f"{repos * per_repo} findings (budget {PORTFOLIO_BUDGET_SECONDS:.3f}s)"
    )
    assert len(body["repos"]) == repos
    assert body["summary"]["open_critical"] > 0
    assert elapsed < PORTFOLIO_BUDGET_SECONDS, (
        f"portfolio endpoint took {elapsed:.2f}s for {repos} repos and "
        f"{repos * per_repo} findings; spec 10 §6 budget is 2s. Materialized "
        "views (spec 10 §3) are deferred on the strength of this measurement — "
        "if it no longer holds, build them."
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
    assert elapsed < PORTFOLIO_BUDGET_SECONDS, (
        f"portfolio aggregate took {elapsed:.2f}s "
        f"(spec 10 §6 budget: {PORTFOLIO_BUDGET_SECONDS:.2f}s)"
    )
