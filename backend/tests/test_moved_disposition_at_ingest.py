"""A dismissed finding whose code moved lands dismissed, not new (TheHub #61129).

**Observed 2026-11-01.** A commit-gate refused a commit with "introduced
0 critical, 7 high". The commit had inserted 165 lines near the top of one
file and, below the insert, added one more interpolated predicate to five
`text()` calls that had each been dismissed as a false positive weeks
earlier. Their snippets changed, so their ids changed, and all five arrived
`open` and first seen by that commit. `carry_forward` paired every one of
them correctly 37 minutes later -- after the gate had already asked and
refused, and seven disposition requests had been filed for decisions already
made.

The snippets below reproduce that shape: five dismissed calls, each edited
by one interpolated line and moved down the file, two of them close enough
to each other that the margin matters, one only just above the floor, one
reindented; and two calls the change made flaggable for the first time.
Matching them is `carry_forward`'s existing rule (floor and margin); what is
under test is that the rule is applied at ingestion, before the rows are
written, so the gate's first question already gets the right answer.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.config import Settings
from mykronos.dashboard import DashboardQueries
from mykronos.db.models import AuditLogEntry
from mykronos.lake import Catalog, carry_forward
from tests.conftest import ADMIN_TOKEN, REPO, finding_payload, post_findings, post_scan

RULE = "python.sqlalchemy.security.audit.avoid-sqlalchemy-text"
FILE = "payments/ledger.py"

SCAN_BEFORE = "bbbbbbbb-0000-0000-0000-000000000001"
SCAN_BEFORE_AGAIN = "bbbbbbbb-0000-0000-0000-000000000003"
SCAN_AFTER = "bbbbbbbb-0000-0000-0000-000000000002"
COMMIT_BEFORE = "aaaa1111"
COMMIT_AFTER = "bbbb2222"

# ---------------------------------------------------------------------------
# `_BEFORE` is the call as dismissed; `_AFTER` is the same call once the
# change added its predicate.
# ---------------------------------------------------------------------------

LEDGER_TOTAL_BEFORE = '''        text(
            "SELECT sum(l.amount) FROM ledger l "
            "WHERE l.account_id = :account "
            "  AND l.posted_at >= :since "
            "  AND NOT l.reversed "
            f"  AND l.kind IN {_SETTLED_KINDS_SQL} "
            "GROUP BY l.account_id"
        ),'''

REFUND_LOOKUP_BEFORE = '''        text(
            "SELECT r.id FROM refunds r "
            "JOIN payments p ON p.id = r.payment_id "
            "WHERE p.order_id = :order "
            "  AND r.state <> 'void' "
            f"  AND r.reason IN {_REFUND_REASONS_SQL} "
            "  AND p.captured_at IS NOT NULL "
            "LIMIT 1"
        ),'''

REFUND_TOTAL_BEFORE = '''        text(
            "SELECT sum(r.amount) FROM refunds r "
            "JOIN payments p ON p.id = r.payment_id "
            "WHERE p.order_id = :order "
            "  AND r.state <> 'void' "
            f"  AND r.reason IN {_REFUND_REASONS_SQL} "
            "  AND r.settled_at IS NOT NULL "
            "  AND p.captured_at IS NOT NULL "
            "ORDER BY r.settled_at DESC LIMIT 1"
        ),'''

PAYOUT_SIGNAL_BEFORE = '''        text(
            "SELECT payout_ref, batch_id FROM payouts "
            "WHERE status = 'paid' "
            f"  AND memo ~* :pat AND {_NOT_A_TEST_PAYOUT} "
            "LIMIT 200"
        ),'''

DISPUTE_SIGNAL_BEFORE = '''        text(
            "SELECT max(ts) FROM ("
            "  SELECT d.opened_at AS ts FROM disputes d "
            "  WHERE d.state = 'won' "
            f"    AND d.network IN {_CARD_NETWORKS_SQL} "
            "  UNION ALL "
            "  SELECT c.created_at AS ts FROM chargebacks c "
            "  WHERE c.reversed "
            ") s"
        ),'''

LEDGER_TOTAL_AFTER = '''        text(
            "SELECT sum(l.amount) FROM ledger l "
            "WHERE l.account_id = :account "
            "  AND l.posted_at >= :since "
            "  AND NOT l.reversed "
            f"  AND l.kind IN {_SETTLED_KINDS_SQL} "
            # ...and only entries whose batch was not rolled back.
            f"  AND {_batch_kept_sql('l')} "
            "GROUP BY l.account_id"
        ),'''

REFUND_LOOKUP_AFTER = '''        text(
            "SELECT r.id FROM refunds r "
            "JOIN payments p ON p.id = r.payment_id "
            "WHERE p.order_id = :order "
            "  AND r.state <> 'void' "
            f"  AND r.reason IN {_REFUND_REASONS_SQL} "
            "  AND p.captured_at IS NOT NULL "
            f"  AND {_batch_kept_sql('p')} "
            "LIMIT 1"
        ),'''

REFUND_TOTAL_AFTER = '''        text(
            "SELECT sum(r.amount) FROM refunds r "
            "JOIN payments p ON p.id = r.payment_id "
            "WHERE p.order_id = :order "
            "  AND r.state <> 'void' "
            f"  AND r.reason IN {_REFUND_REASONS_SQL} "
            "  AND r.settled_at IS NOT NULL "
            "  AND p.captured_at IS NOT NULL "
            f"  AND {_batch_kept_sql('p')} "
            "ORDER BY r.settled_at DESC LIMIT 1"
        ),'''

PAYOUT_SIGNAL_AFTER = '''        text(
            "SELECT payout_ref, batch_id FROM payouts o "
            "WHERE status = 'paid' "
            f"  AND memo ~* :pat AND {_NOT_A_TEST_PAYOUT} "
            f"  AND {_batch_kept_sql('o')} "
            "LIMIT 200"
        ),'''

DISPUTE_SIGNAL_AFTER = '''            text(
                "SELECT max(ts) FROM ("
                "  SELECT d.opened_at AS ts FROM disputes d "
                "  WHERE d.state = 'won' "
                f"    AND d.network IN {_CARD_NETWORKS_SQL} "
                f"    AND {_batch_kept_sql('d')} "
                "  UNION ALL "
                "  SELECT c.created_at AS ts FROM chargebacks c "
                "  WHERE c.reversed "
                ") s"
            ),'''

#: Two statements the change made flaggable for the first time: each had no
#: interpolation before, so the rule had nothing to report.
ROLLED_BACK_BATCHES_AFTER = '''        text(
            "WITH rolled_back AS ( "
            "  SELECT b.id FROM batches b "
            f"  WHERE b.state IN {_ROLLBACK_STATES_SQL} "
            ") "
            "SELECT count(*) FROM rolled_back"
        ),'''

PAYOUT_KEPT_AFTER = '''        text("SELECT 1 FROM payout_history h "
             "WHERE state = 'paid' "
             f"AND {_history_batch_kept_sql('h')}")'''

#: (name, line before the change, line after, symbol, before, after) for the five
#: dismissed calls.
MOVED = [
    ("ledger_total", 937, 1104, "_ledger_total", LEDGER_TOTAL_BEFORE, LEDGER_TOTAL_AFTER),
    (
        "refund_lookup", 968, 1137, "_refund_for_order",
        REFUND_LOOKUP_BEFORE, REFUND_LOOKUP_AFTER,
    ),
    (
        "refund_total", 1011, 1183, "_refund_total_for_order",
        REFUND_TOTAL_BEFORE, REFUND_TOTAL_AFTER,
    ),
    (
        "payout_signal", 1129, 1320, "_payout_signal",
        PAYOUT_SIGNAL_BEFORE, PAYOUT_SIGNAL_AFTER,
    ),
    (
        "dispute_signal", 1201, 1514, "_dispute_signal",
        DISPUTE_SIGNAL_BEFORE, DISPUTE_SIGNAL_AFTER,
    ),
]

#: The two calls the change made flaggable for the first time.
GENUINELY_NEW = [
    (937, "_rolled_back_batches", ROLLED_BACK_BATCHES_AFTER),
    (1311, "_payout_signal", PAYOUT_KEPT_AFTER),
]


def _scan(
    client: TestClient,
    auth: dict[str, str],
    scan_run_id: str,
    commit_sha: str,
    minute: int,
    branch: str = "develop",
) -> None:
    started = datetime(2026, 11, 1, 0, minute, tzinfo=UTC).replace(tzinfo=None)
    for completed in (None, started.isoformat()):
        body: dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "commit_sha": commit_sha,
            "branch": branch,
            "tool_name": "semgrep",
            "started_at": started.isoformat(),
            "scan_status": "success",
            "pr_number": None,
            "triggered_by": "push",
        }
        if completed:
            body["completed_at"] = completed
        response = post_scan(client, auth, **body)
        assert response.status_code == 200, response.text


def _finding(snippet: str, line: int, symbol: str) -> dict[str, Any]:
    return finding_payload(
        rule_id=RULE,
        title="Avoid SQLAlchemy text()",
        severity="high",
        file_path=FILE,
        line_start=line,
        line_end=line + snippet.count("\n"),
        symbol=symbol,
        code_snippet=snippet,
        raw_finding_json={"check_id": RULE},
    )


def _ids_by_line(catalog: Catalog, scan_run_id: str) -> dict[int, str]:
    rows = catalog.query(
        "SELECT line_start, finding_id FROM findings "
        "WHERE file_path = ? AND last_seen_scan_run_id = ?",
        [FILE, scan_run_id],
    )
    return {int(line): str(fid) for line, fid in rows}


def _dispose(client: TestClient, finding_id: str) -> None:
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": "false_positive", "reason": "every value reaching text() is bound"},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert response.status_code == 200, response.text


def _dismissed_before_the_change(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> dict[str, str]:
    """Scan the commit before the change twice and dismiss all five calls. Returns name -> id.

    Twice, because in the lake the dismissed rows had been re-reported for
    weeks: last seen long after first seen, which is what makes an inherited
    first sighting predate the row it came from.
    """
    for scan_run_id, minute in ((SCAN_BEFORE, 0), (SCAN_BEFORE_AGAIN, 10)):
        _scan(client, auth, scan_run_id, COMMIT_BEFORE, minute=minute)
        response = post_findings(
            client,
            auth,
            [_finding(before, line, symbol) for _, line, _, symbol, before, _ in MOVED],
            scan_run_id=scan_run_id,
        )
        assert response.status_code == 200, response.text
        run_compaction()
        if scan_run_id == SCAN_BEFORE:
            by_line = _ids_by_line(catalog, SCAN_BEFORE)
            dismissed = {name: by_line[line] for name, line, *_ in MOVED}
            for finding_id in dismissed.values():
                _dispose(client, finding_id)
            run_compaction()
    assert _ids_by_line(catalog, SCAN_BEFORE_AGAIN) == {
        line: dismissed[name] for name, line, *_ in MOVED
    }
    return dismissed


def _scan_the_change(
    client: TestClient,
    auth: dict[str, str],
    run_compaction: Callable[[], Any],
    *,
    with_new: bool,
    branch: str = "develop",
) -> None:
    """Scan the change: the five calls, moved and edited; optionally the two new."""
    _scan(client, auth, SCAN_AFTER, COMMIT_AFTER, minute=30, branch=branch)
    findings = [_finding(after, line, symbol) for _, _, line, symbol, _, after in MOVED]
    if with_new:
        findings += [_finding(snippet, line, symbol) for line, symbol, snippet in GENUINELY_NEW]
    response = post_findings(client, auth, findings, scan_run_id=SCAN_AFTER)
    assert response.status_code == 200, response.text
    run_compaction()


# ---------------------------------------------------------------------------
# AC1 and AC2 -- the observed shape
# ---------------------------------------------------------------------------


def test_a_165_line_insert_above_five_false_positives_introduces_nothing(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """The gate asks straight after ingestion, before any carry-forward pass.

    Before this change the answer here was {"high": 5}: the observed
    refusal, less the two calls the change genuinely made flaggable.
    """
    dismissed = _dismissed_before_the_change(client, auth, catalog, run_compaction)
    _scan_the_change(client, auth, run_compaction, with_new=False)

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {}

    after = _ids_by_line(catalog, SCAN_AFTER)
    for name, _, line, *_ in MOVED:
        assert after[line] != dismissed[name], "the mechanism under test: it re-keyed"
        row = DashboardQueries(catalog).finding(after[line])
        assert row is not None
        assert row["status"] == "false_positive", name
        first = catalog.query(
            "SELECT first_seen_scan_run_id FROM findings WHERE finding_id = ?",
            [after[line]],
        )
        assert first == [(SCAN_BEFORE,)], name


def test_each_inherited_decision_is_audited_naming_both_ids(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    dismissed = _dismissed_before_the_change(client, auth, catalog, run_compaction)
    _scan_the_change(client, auth, run_compaction, with_new=True)
    after = _ids_by_line(catalog, SCAN_AFTER)

    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        entries = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "finding.disposition_inherited"
            )
        ).all()

    pairs = sorted(
        (e.detail["predecessor_finding_id"], e.detail["successor_finding_id"])
        for e in entries
    )
    assert pairs == sorted((dismissed[name], after[line]) for name, _, line, *_ in MOVED)
    for entry in entries:
        assert entry.entity_id == entry.detail["successor_finding_id"]
        assert entry.detail["disposition"] == "false_positive"
        assert entry.detail["scan_run_id"] == SCAN_AFTER
        assert entry.detail["similarity"] >= 0.6


def test_carry_forward_then_withdraws_each_predecessor_as_superseded(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """AC1's link. Ingestion moved the decision; the next pass names the
    replacement on the old row, and strands nothing."""
    dismissed = _dismissed_before_the_change(client, auth, catalog, run_compaction)
    _scan_the_change(client, auth, run_compaction, with_new=True)
    after = _ids_by_line(catalog, SCAN_AFTER)

    result = carry_forward(catalog)

    assert result.stranded == []
    assert sorted((c.from_finding_id, c.to_finding_id) for c in result.carried) == sorted(
        (dismissed[name], after[line]) for name, _, line, *_ in MOVED
    )
    for name, _, line, *_ in MOVED:
        assert catalog.query(
            "SELECT status, superseded_by FROM findings WHERE finding_id = ?",
            [dismissed[name]],
        ) == [("superseded", after[line])]
        row = DashboardQueries(catalog).finding(after[line])
        assert row is not None
        assert row["status"] == "false_positive"

    # And a second pass has nothing left to do.
    again = carry_forward(catalog)
    assert again.carried == []
    assert again.stranded == []


# ---------------------------------------------------------------------------
# AC3 -- a real change still counts
# ---------------------------------------------------------------------------


def test_the_two_calls_the_change_made_flaggable_still_count_as_introduced(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """Newly interpolated, so newly flagged, and nothing to inherit from."""
    _dismissed_before_the_change(client, auth, catalog, run_compaction)
    _scan_the_change(client, auth, run_compaction, with_new=True)

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {"high": 2}
    rows = DashboardQueries(catalog).introduced_rows(REPO, COMMIT_AFTER)
    assert sorted(r["line_start"] for r in rows) == [937, 1311]


def test_a_snippet_below_the_floor_opens_as_new(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """One dismissed call disappears and an unrelated one appears in its
    place. The unrelated one scores under the floor and is the commit's."""
    _scan(client, auth, SCAN_BEFORE, COMMIT_BEFORE, minute=0)
    post_findings(
        client,
        auth,
        [_finding(LEDGER_TOTAL_BEFORE, 937, "_ledger_total")],
        scan_run_id=SCAN_BEFORE,
    )
    run_compaction()
    _dispose(client, _ids_by_line(catalog, SCAN_BEFORE)[937])

    _scan(client, auth, SCAN_AFTER, COMMIT_AFTER, minute=30)
    post_findings(
        client,
        auth,
        [_finding(ROLLED_BACK_BATCHES_AFTER, 937, "_rolled_back_batches")],
        scan_run_id=SCAN_AFTER,
    )
    run_compaction()

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {"high": 1}


def test_a_dismissed_call_still_reported_hands_nothing_to_its_neighbour(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """The original is still reported, so the similar new call is a copy, not
    a move, and nothing is inherited."""
    _scan(client, auth, SCAN_BEFORE, COMMIT_BEFORE, minute=0)
    post_findings(
        client,
        auth,
        [_finding(LEDGER_TOTAL_BEFORE, 937, "_ledger_total")],
        scan_run_id=SCAN_BEFORE,
    )
    run_compaction()
    _dispose(client, _ids_by_line(catalog, SCAN_BEFORE)[937])

    _scan(client, auth, SCAN_AFTER, COMMIT_AFTER, minute=30)
    post_findings(
        client,
        auth,
        [
            _finding(LEDGER_TOTAL_BEFORE, 937, "_ledger_total"),
            _finding(LEDGER_TOTAL_AFTER, 1104, "_ledger_total"),
        ],
        scan_run_id=SCAN_AFTER,
    )
    run_compaction()

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {"high": 1}


def test_a_decision_on_another_branch_does_not_move(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """The lane is the branch too: develop's silence says nothing about main."""
    _dismissed_before_the_change(client, auth, catalog, run_compaction)
    _scan_the_change(client, auth, run_compaction, with_new=False, branch="main")

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {"high": 5}


def test_a_full_batch_is_left_for_carry_forward(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    settings: Settings,
    run_compaction: Callable[[], Any],
) -> None:
    """A batch at the request ceiling may be followed by another from the same
    run, which could still report the predecessor; nothing is inferred."""
    _dismissed_before_the_change(client, auth, catalog, run_compaction)
    settings.max_findings_per_request = len(MOVED)
    _scan_the_change(client, auth, run_compaction, with_new=False)

    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {"high": 5}

    # The hourly pass still gets there, once the run is whole.
    carry_forward(catalog)
    assert DashboardQueries(catalog).introduced_by(REPO, COMMIT_AFTER) == {}
