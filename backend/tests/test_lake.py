"""Data lake storage semantics — specs/05-datalake.md §2, §5, §9, §10."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import duckdb
import pytest
from fastapi.testclient import TestClient

from mykronos.lake import Catalog
from mykronos.lake.catalog import sql_path
from mykronos.lake.tables import column_names
from tests.conftest import (
    REPO,
    SNIPPET,
    dependency_finding,
    finding_payload,
    later,
    post_findings,
    post_scan,
)


def one(catalog: Catalog, sql: str) -> Any:
    rows = catalog.query(sql)
    assert len(rows) == 1, f"expected exactly one row, got {len(rows)}"
    return rows[0]


def set_status(catalog: Catalog, finding_id: str, status: str) -> None:
    """Force a finding's status, standing in for the dashboard's write-back
    (spec 10 §2.2), which does not exist until Phase 2."""
    with catalog.connect() as con:
        pattern = sql_path(catalog.table_dir("findings") / "dt=*" / "*.parquet")
        target = catalog.all_files("findings")[0]
        con.execute(
            f"CREATE TEMP TABLE fix AS SELECT * EXCLUDE (dt) FROM read_parquet('{pattern}', "
            "hive_partitioning = 1, union_by_name = 1)"
        )
        con.execute("UPDATE fix SET status = ?, resolved_at = now() WHERE finding_id = ?",
                    [status, finding_id])
        con.execute(f"COPY (SELECT * FROM fix) TO '{sql_path(target)}' (FORMAT PARQUET)")


class TestRoundTrip:
    def test_finding_is_queryable_after_compaction(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """The Phase 0 demo (spec 13 §3): a finding goes in over HTTP and comes
        back out of the lake in SQL."""
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])

        assert catalog.count("findings") == 0, "not visible before compaction"
        run_compaction()

        title, severity, path = one(
            catalog, "SELECT title, severity, file_path FROM findings"
        )
        assert severity == "critical"
        assert path == "orders/query.py"
        assert "SQL injection" in title

    def test_scan_run_recorded_for_every_run(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 04 §7: success, no-op or failure — one ScanRun each, so scan
        coverage is auditable from the lake alone."""
        post_scan(client, auth, scan_run_id="run-success")
        post_scan(
            client, auth, scan_run_id="run-noop",
            scan_status="no_applicable_targets", finding_count=0,
        )
        post_scan(client, auth, scan_run_id="run-failed", scan_status="failure")
        run_compaction()

        statuses = dict(
            catalog.query("SELECT scan_run_id, scan_status FROM scan_runs ORDER BY 1")
        )
        assert statuses == {
            "run-success": "success",
            "run-noop": "no_applicable_targets",
            "run-failed": "failure",
        }

    def test_no_op_scan_is_distinguishable_from_never_ran(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_scan(client, auth, scan_status="no_applicable_targets", finding_count=0)
        post_findings(client, auth, [])
        run_compaction()

        assert catalog.count("scan_runs") == 1
        assert catalog.count("findings") == 0

    def test_raw_tool_record_is_preserved_verbatim(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_findings(
            client, auth,
            [finding_payload(raw_finding_json={"ruleId": "CWE-89", "nested": {"a": [1, 2]}})],
        )
        run_compaction()
        (raw,) = one(catalog, "SELECT raw_finding_json FROM findings")
        assert '"nested"' in raw and '"a"' in raw


class TestDeduplication:
    def test_reingesting_the_same_finding_does_not_duplicate_it(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 05 §9: a re-run of the same commit updates last_seen_at and
        nothing else."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        first_id, first_seen, last_seen = one(
            catalog, "SELECT finding_id, first_seen_at, last_seen_at FROM findings"
        )

        post_findings(client, auth, [finding_payload()], scan_run_id="second-run")
        run_compaction()

        same_id, same_first, later_last = one(
            catalog, "SELECT finding_id, first_seen_at, last_seen_at FROM findings"
        )
        assert catalog.count("findings") == 1
        assert same_id == first_id
        assert same_first == first_seen, "first_seen_at is immutable"
        assert later_last >= last_seen

    def test_line_shift_preserves_the_finding(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 05 §9 fingerprint-stability criterion — the required
        regression, not an aspiration.

        Unrelated lines are inserted above the finding. The line number moves;
        the identity, the first_seen_at, and the row itself must not.
        """
        post_findings(client, auth, [finding_payload(line_start=214, line_end=216)])
        run_compaction()
        original_id, original_first_seen = one(
            catalog, "SELECT finding_id, first_seen_at FROM findings"
        )

        # Same code, seventeen lines further down the file.
        post_findings(
            client, auth,
            [finding_payload(line_start=231, line_end=233)],
            scan_run_id="after-refactor",
        )
        run_compaction()

        assert catalog.count("findings") == 1, "a shifted finding is not a new finding"
        finding_id, first_seen, line_start, status = one(
            catalog, "SELECT finding_id, first_seen_at, line_start, status FROM findings"
        )
        assert finding_id == original_id
        assert first_seen == original_first_seen, "age and MTTF survive the refactor"
        assert line_start == 231, "but the location is refreshed for deep-linking"
        assert status == "open"

    def test_fixing_the_code_retires_the_finding_and_opens_a_new_one(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """The counterweight: identity must not be so sticky that a real change
        goes unnoticed."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        post_findings(
            client, auth,
            [finding_payload(code_snippet="cursor.execute(SAFE_QUERY, [order_id])")],
            scan_run_id="after-fix",
        )
        run_compaction()

        assert catalog.count("findings") == 2

    def test_duplicates_within_a_single_batch_collapse(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_findings(client, auth, [finding_payload(), finding_payload(), finding_payload()])
        run_compaction()
        assert catalog.count("findings") == 1

    def test_dependency_finding_survives_a_version_bump(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_findings(client, auth, [dependency_finding(package_version="2.0.4")])
        run_compaction()
        post_findings(
            client, auth, [dependency_finding(package_version="2.0.5")], scan_run_id="r2"
        )
        run_compaction()

        assert catalog.count("findings") == 1
        (version,) = one(catalog, "SELECT package_version FROM findings")
        assert version == "2.0.5", "the observed version is refreshed"

    def test_concurrent_runs_on_one_commit_keep_both_scan_runs(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 05 §10: both ScanRun rows are kept for an accurate audit trail,
        while finding dedup still collapses to one row."""
        post_scan(client, auth, scan_run_id="run-a")
        post_scan(client, auth, scan_run_id="run-b")
        post_findings(client, auth, [finding_payload()], scan_run_id="run-a")
        post_findings(client, auth, [finding_payload()], scan_run_id="run-b")
        run_compaction()

        assert catalog.count("scan_runs") == 2
        assert catalog.count("findings") == 1


class TestStatusTransitions:
    def test_a_fixed_finding_that_returns_reopens(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 05 §5 — and a reopened finding is a high-value retro signal for
        the Knowledge Store in Phase 5."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = one(catalog, "SELECT finding_id FROM findings")
        set_status(catalog, finding_id, "fixed")

        post_findings(client, auth, [finding_payload()], scan_run_id="regression")
        result = run_compaction()

        (status, resolved_at) = one(catalog, "SELECT status, resolved_at FROM findings")
        assert status == "open"
        assert resolved_at is None
        assert finding_id in result.reopened

    @pytest.mark.parametrize("disposition", ["false_positive", "accepted_risk", "suppressed"])
    def test_human_dispositions_survive_a_rescan(
        self, client, auth, catalog: Catalog, run_compaction, disposition: str
    ) -> None:
        """A human decision is not overturned by the scanner simply reporting
        the finding again — only 'fixed' reopens."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = one(catalog, "SELECT finding_id FROM findings")
        set_status(catalog, finding_id, disposition)

        post_findings(client, auth, [finding_payload()], scan_run_id="rescan")
        run_compaction()

        (status,) = one(catalog, "SELECT status FROM findings")
        assert status == disposition


class TestDurabilityAndLayout:
    def test_buffer_is_drained_only_after_parquet_is_written(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, buffer, run_compaction
    ) -> None:
        post_findings(client, auth, [finding_payload()])
        assert buffer.count_sealed() == 1
        assert not catalog.all_files("findings")

        run_compaction()

        assert buffer.count_sealed() == 0
        assert catalog.all_files("findings")

    def test_partitions_are_hive_layout(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        parquet = catalog.all_files("findings")[0]
        assert parquet.parent.name.startswith("dt=")
        assert parquet.name.endswith(".parquet")

    def test_partition_is_consolidated_not_fragmented_on_update(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """Repeated rescans of the same finding must not grow the file count."""
        for run in range(4):
            post_findings(client, auth, [finding_payload()], scan_run_id=f"run-{run}")
            run_compaction()

        assert catalog.count("findings") == 1
        assert len(catalog.all_files("findings")) == 1

    def test_empty_lake_is_queryable(self, catalog: Catalog) -> None:
        """A fresh install answers queries with zero rows rather than failing
        on a missing relation."""
        catalog.initialise()
        assert catalog.count("findings") == 0
        assert catalog.query("SELECT * FROM findings WHERE severity = 'critical'") == []

    def test_compaction_is_idempotent_when_replayed(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """A crash between the Parquet write and the buffer delete replays
        those rows; the upsert must absorb it (spec 05 §10)."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        run_compaction()
        run_compaction()
        assert catalog.count("findings") == 1

    def test_readonly_connection_cannot_write(self, catalog: Catalog) -> None:
        """spec 05 §9: nothing but the Ingestion API writes to the lake."""
        catalog.initialise()
        with catalog.connect_readonly() as con, pytest.raises(duckdb.Error):
            con.execute("INSERT INTO findings VALUES (NULL)")


class TestScanRunUpsert:
    def test_finalising_a_run_updates_it_in_place(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """A run is posted at workflow start and again at completion; the
        second post upserts (docs/DECISIONS.md D-002)."""
        post_scan(client, auth, scan_status="success", finding_count=0)
        run_compaction()

        post_scan(
            client, auth,
            completed_at=later(3), scan_status="partial_failure", finding_count=7,
        )
        run_compaction()

        assert catalog.count("scan_runs") == 1
        status, count, completed = one(
            catalog, "SELECT scan_status, finding_count, completed_at FROM scan_runs"
        )
        assert (status, count) == ("partial_failure", 7)
        assert completed is not None


class TestPartialUpdatesWithinOneBatch:
    """Two sparse patches to the same row before compaction runs.

    Compaction collapses duplicate keys last-write-wins before it upserts,
    which is right for tables whose upsert overwrites — and wrong for the
    columns that arrive alone and mean "set this, leave the rest". Overriding a
    risk decision and then merging its pull request inside one five-minute
    window is an ordinary sequence, so this is not a hypothetical.
    """

    def _decision(self, buffer, decision_id: str, **patch: Any) -> None:
        row = {name: None for name in column_names("risk_decisions")}
        row.update(
            decision_id=decision_id,
            repo_full_name=REPO,
            decision_type="pr_gate",
            pr_number=1,
            commit_sha="abc",
            overall_risk_score=80,
            recommendation="no_go",
            inputs_snapshot="{}",
            reasoning="",
            policy_version="1.0",
            evaluated_at=datetime.now(UTC).replace(tzinfo=None).isoformat(),
        )
        row.update(patch)
        buffer.append("risk_decisions", [row])

    def test_both_patches_survive(self, buffer, catalog: Catalog, run_compaction) -> None:
        self._decision(buffer, "d-1")
        run_compaction()

        self._decision(buffer, "d-1", human_override='{"reason": "vendored"}')
        self._decision(buffer, "d-1", gate_outcome="merged")
        run_compaction()

        assert catalog.count("risk_decisions") == 1
        override, outcome, recommendation = one(
            catalog,
            "SELECT human_override, gate_outcome, recommendation FROM risk_decisions",
        )
        assert outcome == "merged"
        assert override is not None, "the earlier patch was collapsed away"
        # And neither patch overwrote the decision itself.
        assert recommendation == "no_go"

    def test_the_newest_non_null_wins_for_the_same_column(
        self, buffer, catalog: Catalog, run_compaction
    ) -> None:
        self._decision(buffer, "d-2")
        run_compaction()

        self._decision(buffer, "d-2", gate_outcome="closed_unmerged")
        self._decision(buffer, "d-2", gate_outcome="merged")
        run_compaction()

        assert one(catalog, "SELECT gate_outcome FROM risk_decisions") == ("merged",)


class TestSnippetHandling:
    def test_snippet_is_retained_for_future_refingerprinting(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """spec 05 §5: a future fingerprint change migrates by re-deriving from
        the stored snippet, carrying first_seen_at across."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (snippet, version) = one(
            catalog, "SELECT code_snippet, fingerprint_version FROM findings"
        )
        assert "cursor.execute" in snippet
        assert version == "v2-snippet"

    def test_degraded_fingerprints_are_reportable(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """An adapter that supplies no snippet produces churn-prone rows. They
        are labelled so the data-quality cost is measurable, not invisible."""
        post_findings(
            client, auth,
            [
                finding_payload(),
                finding_payload(
                    rule_id="CWE-79", file_path="views.py",
                    symbol=None, code_snippet=None, line_start=12,
                ),
            ],
        )
        run_compaction()

        counts = dict(
            catalog.query(
                "SELECT fingerprint_version, count(*) FROM findings GROUP BY 1 ORDER BY 1"
            )
        )
        assert counts == {"v1-line": 1, "v2-snippet": 1}


def test_snippet_constant_is_realistic() -> None:
    assert "cursor.execute" in SNIPPET
