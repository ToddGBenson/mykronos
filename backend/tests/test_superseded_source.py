"""Which machine withdrew a finding, recorded on the row (spec 05 §5a).

`superseded` has two machine setters and they make different claims.
Reprocessing says *the adapter that produced this record was wrong*;
`carry_forward` says *the code this record described changed*. The first means
the finding should never have existed in that shape, the second means it is
still live under a new identity — opposite implications for whether anybody
should go and look.

Until now the only thing separating them was an accident. `superseded_by` was
null on every one of the 457 reprocess withdrawals in the lake and set on all
three carry-forwards, so a reader could tell them apart by a field that does
not mean that. §5a explicitly permits reprocessing to set `superseded_by`
"where there is one", and `test_a_reprocess_that_named_a_replacement_...`
below is that exact row: a reprocess withdrawal with a replacement named,
indistinguishable from a carry-forward on the old evidence.

So the setter is written down, and the rows that predate the column are
attributed from scan-run provenance while that is still decidable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.backfill_superseded_source import backfill_superseded_source
from mykronos.dashboard import DashboardQueries
from mykronos.db import Database
from mykronos.db.models import AuditLogEntry
from mykronos.lake import Catalog, carry_forward
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.reprocess import reprocess
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_finding_identity_carry_forward import (
    AFTER_INSERT,
    BEFORE_INSERT,
    SCAN_ONE,
    SCAN_TWO,
    _adapter_finding,
    _scan,
)
from tests.test_onboarding import onboard

# ---------------------------------------------------------------------------
# The two setters, each driven through its real code path
# ---------------------------------------------------------------------------

OSV_SARIF: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner"}},
            "results": [
                {
                    "ruleId": "GHSA-xxxx",
                    "level": "error",
                    "message": {
                        "text": "Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-xxxx'."
                    },
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

#: The same archive with nothing in it — the re-derivation that produces no
#: equivalent finding, which is how 457 rows in the lake came to hold a null
#: `superseded_by`.
OSV_SARIF_EMPTY: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}],
}

REPROCESSED_RUN = "reproc-1"


def _set_raw_ref(catalog: Catalog, scan_run_id: str, ref: str) -> None:
    """Stamp raw_output_ref onto a compacted scan run, as the raw endpoint does."""
    for path in catalog.all_files("scan_runs"):
        with catalog.connect() as con:
            con.execute(
                "CREATE OR REPLACE TABLE _sr AS SELECT * FROM read_parquet(?)",
                [str(path)],
            )
            con.execute(
                "UPDATE _sr SET raw_output_ref = ? WHERE scan_run_id = ?",
                [ref, scan_run_id],
            )
            con.execute("COPY _sr TO ? (FORMAT PARQUET)", [str(path)])


def _archive(
    client: TestClient,
    admin_auth: dict[str, str],
    run_compaction: Any,
    sarif: Any,
) -> Catalog:
    """A scan run whose raw output is on disk, ingested by an old adapter."""
    onboard(client, admin_auth)
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
    settings = client.app.state.settings

    client.post(
        "/api/ingest/scan-run",
        json={
            "scan_run_id": REPROCESSED_RUN,
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
    client.post(
        "/api/ingest/findings",
        json={
            "scan_run_id": REPROCESSED_RUN,
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

    archive = (
        settings.raw_dir / "example-org" / "payments-api" / REPROCESSED_RUN / "osv.sarif"
    )
    archive.parent.mkdir(parents=True, exist_ok=True)
    archive.write_text(json.dumps(sarif), encoding="utf-8")

    catalog = client.app.state.catalog
    run_compaction()
    assert catalog.query("SELECT scan_run_id FROM scan_runs"), "scan run not compacted"
    _set_raw_ref(
        catalog, REPROCESSED_RUN, f"raw/example-org/payments-api/{REPROCESSED_RUN}/osv.sarif"
    )
    return catalog


def _reprocess_withdrawal(
    client: TestClient,
    admin_auth: dict[str, str],
    run_compaction: Any,
    *,
    replacement: bool = True,
) -> Catalog:
    """One finding retired by a corrected adapter."""
    catalog = _archive(
        client, admin_auth, run_compaction, OSV_SARIF if replacement else OSV_SARIF_EMPTY
    )
    settings = client.app.state.settings
    reprocess(catalog, client.app.state.buffer, settings.raw_dir)
    run_compaction()
    return catalog


def _carry_forward_withdrawal(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Any,
    tmp_path: Path,
) -> None:
    """One finding retired because the code it matched was edited."""
    workspace = tmp_path / "checkout"
    workspace.mkdir()

    _scan(client, auth, SCAN_ONE, "aaaaaaa", minute=0)
    post_findings(
        client, auth, [_adapter_finding(workspace, BEFORE_INSERT, 10)], scan_run_id=SCAN_ONE
    )
    run_compaction()

    _scan(client, auth, SCAN_TWO, "bbbbbbb", minute=30)
    post_findings(
        client, auth, [_adapter_finding(workspace, AFTER_INSERT, 18)], scan_run_id=SCAN_TWO
    )
    run_compaction()

    result = carry_forward(catalog)
    assert result.carried, "the scenario did not produce a carry-forward"


def _withdrawn(catalog: Catalog) -> list[tuple[str, Any]]:
    return [
        (str(a), b)
        for a, b in catalog.query(
            "SELECT finding_id, superseded_source FROM findings "
            "WHERE status = 'superseded' ORDER BY finding_id"
        )
    ]


def _forget_the_setter(catalog: Catalog) -> list[str]:
    """Put the lake back into its pre-column shape.

    Both setters record themselves now, so there is nothing to backfill unless
    the column is cleared first — and a backfill that attributes nothing would
    pass while proving nothing.
    """
    ids = [fid for fid, _ in _withdrawn(catalog)]
    update_findings(catalog, locate_findings(catalog, ids), "superseded_source = NULL", [])
    return ids


@pytest.fixture
def db(client: TestClient) -> Database:
    """The app's own operational database — where the audit log lives."""
    database: Database = client.app.state.db
    return database


# ---------------------------------------------------------------------------
# The setter writes itself down
# ---------------------------------------------------------------------------


class TestTheSetterRecordsItself:
    def test_reprocess_names_itself(self, client, admin_auth, run_compaction) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)

        assert [source for _, source in _withdrawn(catalog)] == ["reprocess"]

    def test_carry_forward_names_itself(
        self, client, auth, catalog, run_compaction, tmp_path
    ) -> None:
        _carry_forward_withdrawal(client, auth, catalog, run_compaction, tmp_path)

        assert [source for _, source in _withdrawn(catalog)] == ["carry_forward"]

    def test_a_finding_nobody_withdrew_has_no_setter(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """The column is about withdrawal. A row nothing withdrew holds null,
        which is the honest value rather than a default."""
        post_scan(client, auth, scan_run_id=SCAN_ONE)
        post_findings(client, auth, [finding_payload()], scan_run_id=SCAN_ONE)
        run_compaction()

        rows = catalog.query("SELECT status, superseded_source FROM findings")

        assert rows == [("open", None)]


# ---------------------------------------------------------------------------
# The rows that predate the column
# ---------------------------------------------------------------------------


class TestTheBackfillAttributesTheOlderRows:
    def test_a_withdrawal_with_no_replacement_is_attributed_to_reprocess(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        """The shape 457 of the lake's 460 rows are in. `carry_forward` only
        ever withdraws a predecessor it has matched, so it never leaves
        `superseded_by` null — a null replacement cannot have come from it."""
        catalog = _reprocess_withdrawal(
            client, admin_auth, run_compaction, replacement=False
        )
        assert catalog.query(
            "SELECT count(*) FROM findings "
            "WHERE status = 'superseded' AND superseded_by IS NULL"
        ) == [(1,)]
        _forget_the_setter(catalog)

        result = backfill_superseded_source(catalog, db)

        assert [source for _, source in _withdrawn(catalog)] == ["reprocess"]
        assert result.by_setter == {"reprocess": 1}

    def test_a_carry_forward_withdrawal_is_attributed_to_carry_forward(
        self, client, auth, catalog, run_compaction, tmp_path, db
    ) -> None:
        _carry_forward_withdrawal(client, auth, catalog, run_compaction, tmp_path)
        _forget_the_setter(catalog)

        result = backfill_superseded_source(catalog, db)

        assert [source for _, source in _withdrawn(catalog)] == ["carry_forward"]
        assert result.by_setter == {"carry_forward": 1}

    def test_a_reprocess_that_named_a_replacement_is_not_read_as_a_carry_forward(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        """The row the whole story is about.

        §5a permits reprocessing to name a replacement, and the moment one
        does, `superseded_by IS NOT NULL` stops meaning carry-forward. The
        provenance still separates them: a reprocess replacement is ingested
        under the *same* scan run the withdrawn record was last seen in,
        because that is the archived output being re-read. A carry-forward
        successor comes from a later scan of the lane.
        """
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        assert catalog.query(
            "SELECT count(*) FROM findings "
            "WHERE status = 'superseded' AND superseded_by IS NOT NULL"
        ) == [(1,)]
        _forget_the_setter(catalog)

        backfill_superseded_source(catalog, db)

        assert [source for _, source in _withdrawn(catalog)] == ["reprocess"]

    def test_it_records_how_it_decided(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        """A value nobody can audit is a value nobody can challenge. The lake
        records *what* the setter was; spec 12 §7's audit log records how that
        answer was arrived at — the same division `groom.py` already relies on
        for who set a finding's status."""
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        ids = _forget_the_setter(catalog)

        backfill_superseded_source(catalog, db)

        with db.session() as session:
            entries = list(
                session.scalars(
                    select(AuditLogEntry).where(
                        AuditLogEntry.action == "finding.superseded_source_backfilled"
                    )
                )
            )
            assert [e.entity_id for e in entries] == ids
            detail = entries[0].detail
        assert detail["superseded_source"] == "reprocess"
        assert detail["rule"] == "replacement_from_the_run_it_was_last_seen_in"
        assert detail["last_seen_scan_run_id"] == REPROCESSED_RUN
        assert detail["successor_scan_run_id"] == REPROCESSED_RUN

    def test_a_dry_run_writes_nothing(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        _forget_the_setter(catalog)

        result = backfill_superseded_source(catalog, db, dry_run=True)

        assert result.by_setter == {"reprocess": 1}
        assert [source for _, source in _withdrawn(catalog)] == [None]
        with db.session() as session:
            assert (
                session.scalars(
                    select(AuditLogEntry).where(
                        AuditLogEntry.action == "finding.superseded_source_backfilled"
                    )
                ).all()
                == []
            )

    def test_running_it_twice_changes_nothing(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        _forget_the_setter(catalog)
        backfill_superseded_source(catalog, db)

        second = backfill_superseded_source(catalog, db)

        assert second.by_setter == {}
        assert second.already_sourced == 1

    def test_a_row_it_cannot_attribute_is_reported_rather_than_guessed(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        """Neither signature fits, so the column stays null and the finding is
        named. An invented setter is worse than an absent one: it is the
        guesswork this change exists to avoid, wearing the answer's clothes."""
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        ids = _forget_the_setter(catalog)
        update_findings(
            catalog,
            locate_findings(catalog, ids),
            "superseded_by = 'a-finding-that-is-not-in-this-lake'",
            [],
        )

        result = backfill_superseded_source(catalog, db)

        assert result.undetermined == ids
        assert [source for _, source in _withdrawn(catalog)] == [None]

    def test_it_leaves_the_rest_of_the_row_alone(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        """A backfill is not a rescan. Status, the replacement pointer and
        `first_seen_at` — the only input to mean time to fix — are read, never
        rewritten."""
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        _forget_the_setter(catalog)
        before = catalog.query(
            "SELECT finding_id, status, superseded_by, first_seen_at, resolved_at "
            "FROM findings ORDER BY finding_id"
        )

        backfill_superseded_source(catalog, db)

        after = catalog.query(
            "SELECT finding_id, status, superseded_by, first_seen_at, resolved_at "
            "FROM findings ORDER BY finding_id"
        )
        assert after == before

    def test_it_does_not_touch_a_finding_that_was_never_withdrawn(
        self, client, admin_auth, run_compaction, db
    ) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        _forget_the_setter(catalog)

        backfill_superseded_source(catalog, db)

        rows = catalog.query(
            "SELECT superseded_source FROM findings WHERE status <> 'superseded'"
        )
        assert rows == [(None,)]


# ---------------------------------------------------------------------------
# Something reads it
# ---------------------------------------------------------------------------


class TestTheSurfacesServeIt:
    """A column nobody selects is a column nobody can see.

    `superseded_by` was in the lake for months before either of these two
    surfaces selected it, so a superseded row could not be followed to its
    replacement anywhere a person actually looks (spec 17 §5.1). The same
    mistake is available here and is cheaper to not make.
    """

    def test_the_findings_list_carries_the_setter(
        self, client, admin_auth, run_compaction
    ) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)

        rows, _total = DashboardQueries(catalog).findings(
            REPO, finding_status="superseded"
        )

        assert [row["superseded_source"] for row in rows] == ["reprocess"]

    def test_the_finding_detail_carries_the_setter(
        self, client, admin_auth, run_compaction
    ) -> None:
        catalog = _reprocess_withdrawal(client, admin_auth, run_compaction)
        withdrawn_id = _withdrawn(catalog)[0][0]

        record = DashboardQueries(catalog).finding(withdrawn_id)

        assert record is not None
        assert record["superseded_source"] == "reprocess"
