"""Findings gain an asset (spec 14 §5).

The danger in this migration is not getting the values wrong — a repository's
`asset_id` is the string `repo_full_name` already holds. It is what a careless
rewrite does to everything *else* on the row: status, dispositions, and
`first_seen_at`, which is the only input to mean time to fix.
"""

from __future__ import annotations

import pytest

from mykronos.migrate_assets import migrate_assets
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def _seed(client, auth, run_compaction, findings=None):
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        findings or [finding_payload(rule_id="R1"), finding_payload(rule_id="R2")],
        scan_run_id="run-1",
    )
    run_compaction()


def _clear_assets(catalog):
    """Put the lake back into its pre-migration shape.

    Ingestion writes the asset fields now, so there is nothing to migrate
    unless they are removed first — and a test that migrates nothing would
    pass while proving nothing.
    """
    from mykronos.lake.mutate import locate_findings, update_findings

    ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
    update_findings(
        catalog, locate_findings(catalog, ids), "asset_type = NULL, asset_id = NULL", []
    )
    return ids


class TestMigration:
    def test_a_repository_finding_becomes_a_repo_asset(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _seed(client, auth, run_compaction)
        _clear_assets(catalog)

        result = migrate_assets(catalog)

        assert result.migrated == 2
        rows = catalog.query("SELECT DISTINCT asset_type, asset_id FROM findings")
        assert rows == [("repo", REPO)]

    def test_the_asset_id_is_the_repo_name_unchanged(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The property that makes this safe to run on a live lake: finding_id
        is derived from the subject (spec 05 §5) and the subject's value does
        not change, so nothing re-identifies and nothing reopens as new work."""
        _seed(client, auth, run_compaction)
        before = sorted(
            str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")
        )
        _clear_assets(catalog)

        migrate_assets(catalog)

        after = sorted(
            str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")
        )
        assert before == after

    def test_it_does_not_reopen_a_fixed_finding(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The hazard that changed how this is written. Compaction's findings
        upsert reopens any row whose stored status is `fixed`, so routing the
        backfill through the write-ahead buffer would have reported every
        previously-fixed finding as freshly reopened."""
        from mykronos.lake.mutate import locate_findings, update_findings

        _seed(client, auth, run_compaction)
        ids = _clear_assets(catalog)
        update_findings(
            catalog,
            locate_findings(catalog, ids[:1]),
            "status = 'fixed', resolved_at = now()",
            [],
        )

        migrate_assets(catalog)

        statuses = dict(
            (str(a), str(b))
            for a, b in catalog.query("SELECT finding_id, status FROM findings")
        )
        assert statuses[ids[0]] == "fixed"

    def test_it_preserves_a_human_disposition(
        self, client, auth, run_compaction, catalog
    ) -> None:
        from mykronos.lake.mutate import locate_findings, update_findings

        _seed(client, auth, run_compaction)
        ids = _clear_assets(catalog)
        update_findings(
            catalog,
            locate_findings(catalog, ids[:1]),
            "status = 'false_positive'",
            [],
        )

        migrate_assets(catalog)

        statuses = dict(
            (str(a), str(b))
            for a, b in catalog.query("SELECT finding_id, status FROM findings")
        )
        assert statuses[ids[0]] == "false_positive"

    def test_it_preserves_first_seen_at(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The only input to mean time to fix. A migration that reset it would
        report the whole backlog as discovered today."""
        _seed(client, auth, run_compaction)
        before = sorted(
            str(r[0]) for r in catalog.query("SELECT first_seen_at FROM findings")
        )
        _clear_assets(catalog)

        migrate_assets(catalog)

        after = sorted(
            str(r[0]) for r in catalog.query("SELECT first_seen_at FROM findings")
        )
        assert before == after

    def test_running_it_twice_changes_nothing(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _seed(client, auth, run_compaction)
        _clear_assets(catalog)
        migrate_assets(catalog)

        second = migrate_assets(catalog)

        assert second.migrated == 0
        assert second.already_done == 2

    def test_a_dry_run_writes_nothing(
        self, client, auth, run_compaction, catalog
    ) -> None:
        _seed(client, auth, run_compaction)
        _clear_assets(catalog)

        result = migrate_assets(catalog, dry_run=True)

        assert result.migrated == 2
        assert catalog.query("SELECT count(*) FROM findings WHERE asset_id IS NULL")[0][
            0
        ] == 2


class TestIngestion:
    @pytest.mark.parametrize("field", ["asset_type", "asset_id"])
    def test_new_findings_arrive_with_an_asset(
        self, client, auth, run_compaction, catalog, field
    ) -> None:
        """So the migration is a one-off rather than a recurring sweep."""
        _seed(client, auth, run_compaction)

        rows = catalog.query(f"SELECT DISTINCT {field} FROM findings")

        assert rows == [("repo",)] if field == "asset_type" else rows == [(REPO,)]
