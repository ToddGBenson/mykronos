"""Re-deriving findings from archived output (spec 05 §5a).

Three adapters were wrong in one day, and each correction changed the identity
of every finding that adapter had produced. This is how those records are
repaired without re-running a scan.

Most of these tests are about what reprocessing must *not* do. It can retire
hundreds of records in one call, and the two ways to get that wrong — marking
them fixed, or retiring findings another scan still reports — are both silent
and both corrupt numbers people make decisions from.
"""

from __future__ import annotations

import json

import pytest

from mykronos.lake.catalog import Catalog
from mykronos.reprocess import reprocess
from mykronos.schemas import FindingStatus
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard

SARIF_ABSOLUTE = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner"}},
            "results": [
                {
                    "ruleId": "GHSA-xxxx",
                    "level": "error",
                    "message": {"text": "Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-xxxx'."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": (
                                        "file:///home/runner/work/payments-api/"
                                        "payments-api/frontend/package-lock.json"
                                    )
                                }
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


@pytest.fixture
def archived(client, admin_auth, run_compaction, tmp_path):
    """A scan run whose raw output is on disk, ingested by an old adapter."""
    onboard(client, admin_auth)
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
    settings = client.app.state.settings

    client.post(
        "/api/ingest/scan-run",
        json={
            "scan_run_id": "reproc-1",
            "repo_full_name": REPO,
            "capability": "atlas",
            "tool_name": "osv-scanner",
            "tool_version": "2.5.0",
            "commit_sha": "a91f2c7",
            "branch": "main",
            "triggered_by": "push",
            "started_at": "2026-08-12T09:00:00",
            "scan_status": "success",
            "finding_count": 1,
        },
        headers=auth,
    )

    # A finding as the *old* adapter recorded it: absolute path, no package.
    client.post(
        "/api/ingest/findings",
        json={
            "scan_run_id": "reproc-1",
            "capability": "atlas",
            "findings": [
                {
                    "rule_id": "GHSA-xxxx",
                    "title": "js-yaml",
                    "description": "old shape",
                    "severity": "high",
                    "file_path": (
                        "home/runner/work/payments-api/payments-api/"
                        "frontend/package-lock.json"
                    ),
                }
            ],
        },
        headers=auth,
    )

    archive = settings.raw_dir / "example-org" / "payments-api" / "reproc-1" / "osv.sarif"
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_text(json.dumps(SARIF_ABSOLUTE), encoding="utf-8")

    catalog = client.app.state.catalog
    run_compaction()

    # Stamp the archive onto the scan run the way /api/ingest/raw would.
    assert catalog.query("SELECT scan_run_id FROM scan_runs"), "scan run not compacted"
    _set_raw_ref(catalog, "reproc-1", "raw/example-org/payments-api/reproc-1/osv.sarif")
    return catalog


def _set_raw_ref(catalog: Catalog, scan_run_id: str, ref: str) -> None:
    """Stamp raw_output_ref onto a compacted scan run, as the raw endpoint does."""
    for path in catalog.all_files("scan_runs"):
        with catalog.connect() as con:
            con.execute(
                "CREATE OR REPLACE TABLE _sr AS SELECT * FROM read_parquet(?)", [str(path)]
            )
            con.execute(
                "UPDATE _sr SET raw_output_ref = ? WHERE scan_run_id = ?",
                [ref, scan_run_id],
            )
            con.execute("COPY _sr TO ? (FORMAT PARQUET)", [str(path)])


class TestItRepairsTheFinding:
    def test_the_re_derived_finding_has_the_corrected_shape(
        self, client, archived, run_compaction
    ) -> None:
        settings = client.app.state.settings

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        rows = archived.query(
            "SELECT file_path, package_name, package_version FROM findings "
            "WHERE status = 'open'"
        )
        assert rows == [("frontend/package-lock.json", "js-yaml", "4.3.0")]

    def test_the_old_record_is_superseded_not_fixed(
        self, client, archived, run_compaction
    ) -> None:
        """The whole reason for a sixth status. `fixed` is the only input to
        mean-time-to-fix, so retiring mis-identified findings as fixed reports
        a mass remediation that never happened."""
        settings = client.app.state.settings

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        statuses = dict(
            archived.query("SELECT status, count(*) FROM findings GROUP BY 1")
        )
        assert statuses.get(FindingStatus.SUPERSEDED.value) == 1
        assert statuses.get(FindingStatus.FIXED.value) is None

    def test_the_superseded_record_names_its_replacement(
        self, client, archived, run_compaction
    ) -> None:
        """So a disappearance can be followed rather than just noticed."""
        settings = client.app.state.settings

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        rows = archived.query(
            "SELECT superseded_by FROM findings WHERE status = 'superseded'"
        )
        replacement = rows[0][0]
        assert replacement
        assert archived.query(
            "SELECT count(*) FROM findings WHERE finding_id = ? AND status = 'open'",
            [replacement],
        ) == [(1,)]


class TestItDoesNotCorruptTheNumbers:
    def test_superseded_is_absent_from_mean_time_to_fix(
        self, client, archived, run_compaction
    ) -> None:
        from mykronos.maturity import mean_time_to_fix

        settings = client.app.state.settings
        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert mean_time_to_fix(archived, REPO) is None

    def test_superseded_is_absent_from_the_open_count(
        self, client, archived, run_compaction
    ) -> None:
        """One vulnerability, one open row — not two, and not zero."""
        settings = client.app.state.settings
        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert archived.query(
            "SELECT count(*) FROM findings WHERE status = 'open'"
        ) == [(1,)]


class TestSafety:
    def test_a_dry_run_writes_nothing(
        self, client, archived, run_compaction
    ) -> None:
        settings = client.app.state.settings
        before = archived.query("SELECT status, finding_id FROM findings")

        result = reprocess(
            archived, client.app.state.buffer, settings.raw_dir, dry_run=True
        )
        run_compaction()

        assert result.produced == 1
        assert archived.query("SELECT status, finding_id FROM findings") == before

    def test_it_never_retires_a_finding_another_scan_still_reports(
        self, client, archived, run_compaction
    ) -> None:
        """The safety property. Retirement is scoped to the scan run being
        reprocessed; a finding whose latest sighting is a different run is
        somebody else's business."""
        settings = client.app.state.settings
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        client.post(
            "/api/ingest/scan-run",
            json={
                "scan_run_id": "other-scan",
                "repo_full_name": REPO,
                "capability": "sast",
                "tool_name": "codeql",
                "tool_version": "1",
                "commit_sha": "b" * 7,
                "branch": "main",
                "triggered_by": "push",
                "started_at": "2026-08-12T10:00:00",
                "scan_status": "success",
                "finding_count": 1,
            },
            headers=auth,
        )
        client.post(
            "/api/ingest/findings",
            json={
                "scan_run_id": "other-scan",
                "capability": "sast",
                "findings": [
                    {
                        "rule_id": "py/other",
                        "title": "unrelated",
                        "severity": "medium",
                        "file_path": "app.py",
                    }
                ],
            },
            headers=auth,
        )
        run_compaction()

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert archived.query(
            "SELECT status FROM findings WHERE rule_id = 'py/other'"
        ) == [("open",)]

    def test_a_scan_with_no_archive_is_skipped_not_emptied(
        self, client, admin_auth, run_compaction
    ) -> None:
        """A scan whose archive has aged out must not have its findings
        retired — that would read as remediation."""
        onboard(client, admin_auth)
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        client.post(
            "/api/ingest/scan-run",
            json={
                "scan_run_id": "no-archive",
                "repo_full_name": REPO,
                "capability": "sast",
                "tool_name": "codeql",
                "tool_version": "1",
                "commit_sha": "c" * 7,
                "branch": "main",
                "triggered_by": "push",
                "started_at": "2026-08-12T11:00:00",
                "scan_status": "success",
                "finding_count": 1,
            },
            headers=auth,
        )
        client.post(
            "/api/ingest/findings",
            json={
                "scan_run_id": "no-archive",
                "capability": "sast",
                "findings": [
                    {
                        "rule_id": "py/keeps",
                        "title": "still here",
                        "severity": "medium",
                        "file_path": "app.py",
                    }
                ],
            },
            headers=auth,
        )
        run_compaction()
        catalog = client.app.state.catalog

        result = reprocess(
            catalog, client.app.state.buffer, client.app.state.settings.raw_dir
        )
        run_compaction()

        assert catalog.query(
            "SELECT status FROM findings WHERE rule_id = 'py/keeps'"
        ) == [("open",)]
        assert result.superseded == 0

    def test_an_unparseable_archive_is_reported_not_destructive(
        self, client, archived, run_compaction
    ) -> None:
        settings = client.app.state.settings
        archive = (
            settings.raw_dir / "example-org" / "payments-api" / "reproc-1" / "osv.sarif"
        )
        archive.write_text("{not json", encoding="utf-8")

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        # Nothing was produced, so nothing may be retired.
        assert archived.query(
            "SELECT count(*) FROM findings WHERE status = 'superseded'"
        ) == [(0,)]


class TestItDoesNotRewriteHistory:
    def test_the_re_derived_finding_keeps_the_scans_date(
        self, client, archived, run_compaction
    ) -> None:
        """Re-derivation produces new ids by design, so every row is an
        insert. Stamping them with the reprocess time would record the whole
        estate as first seen today: the triage queue orders by age, so an old
        critical somebody has ignored for a month would drop to the bottom of
        the list looking new, and every age-based measure would reset.
        """
        settings = client.app.state.settings

        reprocess(archived, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        rows = archived.query(
            "SELECT first_seen_at FROM findings WHERE status = 'open' "
            "AND rule_id = 'GHSA-xxxx'"
        )
        assert rows, "expected the re-derived finding"
        first_seen = rows[0][0]
        scan_started = archived.query(
            "SELECT coalesce(completed_at, started_at) FROM scan_runs "
            "WHERE scan_run_id = 'reproc-1'"
        )[0][0]

        assert first_seen == scan_started


class TestIdentityMatchesIngestion:
    def test_reprocess_computes_ids_the_same_way_the_api_does(self) -> None:
        """Two code paths, one identity rule.

        `compute_finding_id` keys dependency findings on the package rather
        than the path, and reprocess originally omitted `package_name`. A
        re-derived finding therefore got a different id from the one a real
        scan produces for the same vulnerability, so the next scan would have
        inserted a third record instead of updating.

        Compared as argument names rather than by running both, because the
        failure is an argument quietly missing from one call.
        """
        import inspect

        from mykronos import reprocess as reprocess_module
        from mykronos.api import ingest as ingest_module

        def call_args(source: str) -> set[str]:
            start = source.index("compute_finding_id(")
            depth = 0
            for offset, char in enumerate(source[start:], start):
                depth += char == "("
                depth -= char == ")"
                if depth == 0:
                    body = source[start + len("compute_finding_id(") : offset]
                    break
            return {
                line.split("=", 1)[0].strip()
                for line in body.split(",")
                if "=" in line
            }

        api = call_args(inspect.getsource(ingest_module))
        derived = call_args(inspect.getsource(reprocess_module))

        missing = api - derived
        assert not missing, (
            f"reprocess omits {sorted(missing)} when computing finding_id; "
            "re-derived findings would not match what a scan produces"
        )


class TestItDoesNotResurrectTheDead:
    def test_a_fixed_finding_is_not_reopened(
        self, client, archived, admin_auth, run_compaction
    ) -> None:
        """Re-derivation is not a new observation.

        Re-ingesting a historical scan re-reports findings a later scan found
        gone, and compaction's reopen rule (spec 05 §5) treats a re-reported
        `fixed` finding as having come back. The first real run reopened 263
        records that way, inflating the open count with work already done.
        """
        settings = client.app.state.settings
        catalog = archived

        # Reprocess once so the corrected finding exists, then resolve it the
        # way a later scan would.
        reprocess(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()
        from mykronos.lake.mutate import locate_findings, update_findings

        open_ids = [
            r[0]
            for r in catalog.query(
                "SELECT finding_id FROM findings WHERE status = 'open'"
            )
        ]
        update_findings(
            catalog,
            locate_findings(catalog, open_ids),
            "status = 'fixed', resolved_at = ?",
            [__import__("mykronos.schemas", fromlist=["utcnow"]).utcnow()],
        )

        reprocess(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert catalog.query(
            "SELECT count(*) FROM findings WHERE status = 'open'"
        ) == [(0,)], "a re-derivation must not reopen a finding already fixed"

    def test_a_dismissed_finding_keeps_its_dismissal(
        self, client, archived, admin_auth, run_compaction
    ) -> None:
        """A false positive somebody reasoned about is a decision, and a
        re-run of the adapter does not overturn it."""
        settings = client.app.state.settings
        catalog = archived

        reprocess(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()
        finding_id = catalog.query(
            "SELECT finding_id FROM findings WHERE status = 'open'"
        )[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "vendored copy"},
            headers=admin_auth,
        )
        run_compaction()

        reprocess(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert catalog.query(
            "SELECT status FROM findings WHERE finding_id = ?", [finding_id]
        ) == [("false_positive",)]


class TestScope:
    def test_only_the_latest_scan_per_capability_is_re_derived(
        self, client, archived, run_compaction
    ) -> None:
        """Older scans are history, not current state.

        Re-materialising them resurrects findings later scans had resolved,
        and the absence reconciler then closes each one again with
        `resolved_at = now`. The first real run put 282 findings' worth of
        imaginary remediation into mean-time-to-fix that way — the number the
        `superseded` status exists to keep honest, corrupted from a direction
        that status cannot defend.
        """
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
        settings = client.app.state.settings

        client.post(
            "/api/ingest/scan-run",
            json={
                "scan_run_id": "reproc-2",
                "repo_full_name": REPO,
                "capability": "atlas",
                "tool_name": "osv-scanner",
                "tool_version": "2.5.0",
                "commit_sha": "b91f2c7",
                "branch": "main",
                "triggered_by": "push",
                "started_at": "2026-08-12T18:00:00",
                "scan_status": "success",
                "finding_count": 0,
            },
            headers=auth,
        )
        run_compaction()
        _set_raw_ref(
            archived, "reproc-2", "raw/example-org/payments-api/reproc-1/osv.sarif"
        )

        result = reprocess(
            archived, client.app.state.buffer, settings.raw_dir, dry_run=True
        )

        assert [s.scan_run_id for s in result.scans] == ["reproc-2"], (
            "expected only the most recent atlas scan"
        )

    def test_all_history_is_available_when_asked_for(
        self, client, archived, run_compaction
    ) -> None:
        settings = client.app.state.settings

        result = reprocess(
            archived,
            client.app.state.buffer,
            settings.raw_dir,
            dry_run=True,
            all_history=True,
        )

        assert result.scans, "expected at least the one archived scan"
