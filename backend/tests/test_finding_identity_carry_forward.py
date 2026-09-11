"""A decision survives the code moving underneath it (spec 05 §5b).

The defect these tests pin was observed on 2026-09-09, when TheHub's pipeline
scanned `develop` for the first time and the Oracle gate blocked with
"Introduced by bd9e3c6b: 0 critical, 3 high". Two of the three were new code.
The third was `_deploy_run_sha_for_story` in
`backend/services/devops/lifecycle.py` — a `text()` call the commit did not
write, which had been dismissed as a false positive four days earlier. Two
lines were added *inside* the SQL string it contains, its `finding_id` changed
because identity is a hash of the matched snippet, and the same call came back
as a new open high with the operator's decision gone.

`test_the_lifecycle_case_from_2026_09_09` is that scan, with the four real
snippets out of the lake.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.adapters.snippet import best_snippet
from mykronos.dashboard import DashboardQueries
from mykronos.fingerprint import snippet_similarity
from mykronos.lake import Catalog, carry_forward
from mykronos.lake.carry_forward import MIN_MARGIN, MIN_SIMILARITY
from tests.conftest import (
    ADMIN_TOKEN,
    REPO,
    finding_payload,
    post_findings,
    post_scan,
)

RULE = "python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text"
FILE = "backend/services/devops/lifecycle.py"

SCAN_ONE = "aaaaaaaa-0000-0000-0000-000000000001"
SCAN_TWO = "aaaaaaaa-0000-0000-0000-000000000002"

# ---------------------------------------------------------------------------
# The four snippets the lake actually held, verbatim. 821 is the dismissed
# one; 917 is the same call after `#58851` added two lines to its SQL; 948 and
# 991 are the two functions the commit genuinely introduced.
# ---------------------------------------------------------------------------

DISMISSED_821 = '''        text(
            "SELECT r.sha FROM deploy_runs r "
            "WHERE r.meta -> 'stories' @> CAST(:sid AS jsonb) "
            "  AND (r.final_status = 'success' "
            "       OR EXISTS (SELECT 1 FROM deploy_stage_events e "
            "                  WHERE e.deploy_run_id = r.id "
            f"                    AND e.stage_name IN {_POST_SWAP_STAGES_SQL})) "
            "LIMIT 1"
        ),'''

EDITED_917 = '''        text(
            "SELECT r.sha FROM deploy_runs r "
            "WHERE r.meta -> 'stories' @> CAST(:sid AS jsonb) "
            # [#58851] A run may have RETRACTED a story it never delivered.
            "  AND NOT COALESCE(r.meta -> 'stories_retracted', '[]'::jsonb) "
            "      @> CAST(:sid AS jsonb) "
            "  AND (r.final_status = 'success' "
            "       OR EXISTS (SELECT 1 FROM deploy_stage_events e "
            "                  WHERE e.deploy_run_id = r.id "
            f"                    AND e.stage_name IN {_POST_SWAP_STAGES_SQL})) "
            "LIMIT 1"
        ),'''

NEW_948 = '''        text(
            "SELECT g.sha FROM deploy_runs r "
            "JOIN deploy_runs g "
            "  ON g.id = CAST(r.meta -> 'covered_by' ->> 'run_id' AS INTEGER) "
            "WHERE r.meta -> 'stories' @> CAST(:sid AS jsonb) "
            "  AND NOT COALESCE(r.meta -> 'stories_retracted', '[]'::jsonb) "
            "      @> CAST(:sid AS jsonb) "
            "  AND r.meta -> 'covered_by' ->> 'sha' IS NOT NULL "
            "  AND (g.final_status = 'success' "
            "       OR EXISTS (SELECT 1 FROM deploy_stage_events e "
            "                  WHERE e.deploy_run_id = g.id "
            f"                    AND e.stage_name IN {_POST_SWAP_STAGES_SQL})) "
            "LIMIT 1"
        ),'''

NEW_991 = '''        text(
            "SELECT g.finished_at FROM deploy_runs r "
            "JOIN deploy_runs g "
            "  ON g.id = CAST(r.meta -> 'covered_by' ->> 'run_id' AS INTEGER) "
            "WHERE r.meta -> 'stories' @> CAST(:sid AS jsonb) "
            "  AND NOT COALESCE(r.meta -> 'stories_retracted', '[]'::jsonb) "
            "      @> CAST(:sid AS jsonb) "
            "  AND r.meta -> 'covered_by' ->> 'sha' IS NOT NULL "
            "  AND g.finished_at IS NOT NULL "
            "  AND (g.final_status = 'success' "
            "       OR EXISTS (SELECT 1 FROM deploy_stage_events e "
            "                  WHERE e.deploy_run_id = g.id "
            f"                    AND e.stage_name IN {_POST_SWAP_STAGES_SQL})) "
            "ORDER BY g.finished_at DESC LIMIT 1"
        ),'''


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scan(
    client: TestClient,
    auth: dict[str, str],
    scan_run_id: str,
    commit_sha: str,
    minute: int,
) -> None:
    """Open and finalise one successful scan of the `sast` lane on `main`."""
    started = datetime(2026, 9, 9, 12, minute, tzinfo=UTC).replace(tzinfo=None)
    for completed in (None, started.isoformat()):
        body: dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "commit_sha": commit_sha,
            "branch": "main",
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


def _sast_finding(snippet: str, line: int, **overrides: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "rule_id": RULE,
        "title": "Avoid SQLAlchemy text()",
        "severity": "high",
        "file_path": FILE,
        "line_start": line,
        "line_end": line + snippet.count("\n"),
        "symbol": "stories",
        "code_snippet": snippet,
    }
    fields.update(overrides)
    return finding_payload(**fields)


def _row(catalog: Catalog, finding_id: str) -> dict[str, Any] | None:
    return DashboardQueries(catalog).finding(finding_id)


def _ids_by_line(catalog: Catalog) -> dict[int, str]:
    rows = catalog.query(
        "SELECT line_start, finding_id FROM findings WHERE file_path = ?", [FILE]
    )
    return {int(line): str(fid) for line, fid in rows}


def _dispose(
    client: TestClient, finding_id: str, status: str = "false_positive"
) -> None:
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": status, "reason": "every value reaching text() is bound"},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert response.status_code == 200, response.text


# ---------------------------------------------------------------------------
# AC5 / AC1 — the finding moves down its file and the decision survives
# ---------------------------------------------------------------------------

BEFORE_INSERT = '''import os

from db import cursor


class Config:
    dsn = os.environ["DSN"]


QUERY = "SELECT * FROM orders WHERE id = " + os.environ["ORDER"]
'''

AFTER_INSERT = '''import os

from db import cursor


class Config:
    dsn = os.environ["DSN"]


def _verified_since(story_id):
    return cursor.execute("SELECT 1")


def _covered_success_ts_for_story(story_id):
    return cursor.execute("SELECT 2")


QUERY = "SELECT * FROM orders WHERE id = " + os.environ["ORDER"]
'''


def _adapter_finding(workspace: Path, source: str, line: int) -> dict[str, Any]:
    """What the SARIF adapter would submit for `line` of `source`.

    Goes through `best_snippet` rather than hand-writing a snippet, because
    the mechanism under test is exactly what that function returns: the
    snippet it slices from disk and the symbol it infers are both read
    relative to the finding's position in the file.
    """
    (workspace / "orders.py").write_text(source, encoding="utf-8")
    snippet, symbol, _ = best_snippet(
        context_region_snippet=None,
        region_snippet=None,
        workspace=workspace,
        file_path="orders.py",
        start_line=line,
        end_line=line,
    )
    return finding_payload(
        rule_id="py/sql-injection",
        title="SQL query built from user input",
        severity="high",
        file_path="orders.py",
        line_start=line,
        line_end=line,
        symbol=symbol,
        code_snippet=snippet,
    )


def test_inserting_code_above_a_dismissed_finding_does_not_resurrect_it(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    tmp_path: Path,
) -> None:
    """AC5. Two functions are inserted above a dismissed finding.

    Nothing about the flagged line changes; it is simply further down the
    file. Before this change the adapter's `symbol` and its disk-sliced
    snippet both moved with it, the `finding_id` changed, and the dismissal
    was left behind on a row nothing reports any more.
    """
    workspace = tmp_path / "checkout"
    workspace.mkdir()

    _scan(client, auth, SCAN_ONE, "aaaaaaa", minute=0)
    first = _adapter_finding(workspace, BEFORE_INSERT, line=10)
    assert post_findings(client, auth, [first], scan_run_id=SCAN_ONE).status_code == 200
    run_compaction()

    original = catalog.query(
        "SELECT finding_id FROM findings WHERE file_path = 'orders.py'"
    )
    assert len(original) == 1
    original_id = str(original[0][0])
    _dispose(client, original_id)

    # The same line, pushed down by two inserted functions.
    _scan(client, auth, SCAN_TWO, "bbbbbbb", minute=30)
    moved = _adapter_finding(workspace, AFTER_INSERT, line=18)
    assert post_findings(client, auth, [moved], scan_run_id=SCAN_TWO).status_code == 200
    run_compaction()

    result = carry_forward(catalog)

    ids = {
        str(r[0])
        for r in catalog.query(
            "SELECT finding_id FROM findings WHERE file_path = 'orders.py'"
        )
    }
    assert len(ids) == 2, "the mechanism under test: motion minted a second identity"

    moved_id = next(i for i in ids if i != original_id)
    assert [(c.from_finding_id, c.to_finding_id) for c in result.carried] == [
        (original_id, moved_id)
    ]

    survivor = _row(catalog, moved_id)
    assert survivor is not None
    assert survivor["status"] == "false_positive"

    withdrawn = catalog.query(
        "SELECT status, superseded_by FROM findings WHERE finding_id = ?", [original_id]
    )
    assert withdrawn == [("superseded", moved_id)]


def test_the_moved_finding_keeps_the_date_it_was_first_seen(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    tmp_path: Path,
) -> None:
    """AC3, at the root. `introduced_by` keys on `first_seen_scan_run_id`.

    A finding that only moved was not introduced by the commit that moved it,
    so the scan that first saw it is carried across with the disposition.
    """
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

    carry_forward(catalog)

    rows = catalog.query(
        "SELECT first_seen_scan_run_id, status FROM findings "
        "WHERE file_path = 'orders.py' AND status <> 'superseded'"
    )
    assert len(rows) == 1
    assert str(rows[0][0]) == SCAN_ONE

    introduced = DashboardQueries(catalog).introduced_by(REPO, "bbbbbbb")
    assert introduced == {}, "the commit moved the line; it did not write it"


# ---------------------------------------------------------------------------
# The observed case
# ---------------------------------------------------------------------------


def test_the_lifecycle_case_from_2026_09_09(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """AC1 and AC3 against the scan that filed the story.

    One dismissed `text()` call is edited; two genuinely new ones appear in
    the same file under the same rule. The dismissal must land on the edited
    one and on neither of the others, and the gate must report two highs
    rather than three.
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    assert (
        post_findings(
            client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE
        ).status_code
        == 200
    )
    run_compaction()

    dismissed_id = _ids_by_line(catalog)[821]
    _dispose(client, dismissed_id)

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    assert (
        post_findings(
            client,
            auth,
            [
                _sast_finding(EDITED_917, 917),
                _sast_finding(NEW_948, 948),
                _sast_finding(NEW_991, 991),
            ],
            scan_run_id=SCAN_TWO,
        ).status_code
        == 200
    )
    run_compaction()

    # Before: three open highs, all attributed to bd9e3c6b.
    assert DashboardQueries(catalog).introduced_by(REPO, "bd9e3c6b") == {"high": 3}

    result = carry_forward(catalog)

    by_line = _ids_by_line(catalog)
    assert [(c.from_finding_id, c.to_finding_id) for c in result.carried] == [
        (dismissed_id, by_line[917])
    ]

    assert _row(catalog, by_line[917])["status"] == "false_positive"
    assert _row(catalog, by_line[948])["status"] == "open"
    assert _row(catalog, by_line[991])["status"] == "open"
    assert _row(catalog, dismissed_id)["status"] == "superseded"

    # After: the two the commit actually wrote.
    assert DashboardQueries(catalog).introduced_by(REPO, "bd9e3c6b") == {"high": 2}

    rows = DashboardQueries(catalog).introduced_rows(REPO, "bd9e3c6b")
    assert sorted(r["line_start"] for r in rows) == [948, 991]


# ---------------------------------------------------------------------------
# Refusals — the direction that hides a real finding
# ---------------------------------------------------------------------------


def test_a_dissimilar_successor_is_not_given_someone_elses_dismissal(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """The flagged code was deleted and an unrelated one added in its place.

    Nothing is carried. Handing a real finding a dismissal it never earned is
    the failure this mechanism must not have, so the floor is refused rather
    than stretched.
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE)
    run_compaction()
    _dispose(client, _ids_by_line(catalog)[821])

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(client, auth, [_sast_finding(NEW_991, 991)], scan_run_id=SCAN_TWO)
    run_compaction()

    result = carry_forward(catalog)

    assert result.carried == []
    assert len(result.stranded) == 1
    assert "below the" in result.stranded[0].reason
    assert _row(catalog, _ids_by_line(catalog)[991])["status"] == "open"


def test_two_equally_similar_successors_are_refused_rather_than_guessed(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """One call is copied into two places and the original disappears.

    Either could be the survivor and the platform cannot tell which, so it
    says so instead of choosing.
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE)
    run_compaction()
    _dispose(client, _ids_by_line(catalog)[821])

    twin_a = DISMISSED_821.replace('"LIMIT 1"', '"LIMIT 1"  # first copy')
    twin_b = DISMISSED_821.replace('"LIMIT 1"', '"LIMIT 1"  # second copy')

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(
        client,
        auth,
        [_sast_finding(twin_a, 900), _sast_finding(twin_b, 950)],
        scan_run_id=SCAN_TWO,
    )
    run_compaction()

    result = carry_forward(catalog)

    assert result.carried == []
    assert len(result.stranded) == 1
    assert "refusing to guess" in result.stranded[0].reason


def test_a_dismissal_with_no_stored_snippet_is_reported_not_dropped(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """AC4's honest half.

    A finding ingested before snippets were captured has nothing to match on.
    It is named in the result rather than quietly left behind, because the
    whole point of this mechanism is that a decision is never discarded in
    silence.
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(
        client,
        auth,
        [_sast_finding(DISMISSED_821, 821, code_snippet=None, symbol=None)],
        scan_run_id=SCAN_ONE,
    )
    run_compaction()
    _dispose(client, _ids_by_line(catalog)[821])

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(client, auth, [_sast_finding(EDITED_917, 917)], scan_run_id=SCAN_TWO)
    run_compaction()

    result = carry_forward(catalog)

    assert result.carried == []
    assert [s.reason for s in result.stranded] == [
        "no code snippet was stored, so there is nothing to match it against"
    ]


def test_dry_run_reports_without_writing(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE)
    run_compaction()
    dismissed_id = _ids_by_line(catalog)[821]
    _dispose(client, dismissed_id)

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(client, auth, [_sast_finding(EDITED_917, 917)], scan_run_id=SCAN_TWO)
    run_compaction()

    result = carry_forward(catalog, dry_run=True)

    assert len(result.carried) == 1
    assert result.partitions_written == 0
    assert _row(catalog, dismissed_id)["status"] == "false_positive"
    assert _row(catalog, _ids_by_line(catalog)[917])["status"] == "open"


def test_a_finding_still_being_reported_is_never_a_candidate(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """The dismissed call is untouched and a new one appears beside it.

    Nothing has gone missing, so nothing is carried and the new finding is
    correctly attributed to the commit that wrote it.
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE)
    run_compaction()
    _dispose(client, _ids_by_line(catalog)[821])

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(
        client,
        auth,
        [_sast_finding(DISMISSED_821, 821), _sast_finding(NEW_991, 991)],
        scan_run_id=SCAN_TWO,
    )
    run_compaction()

    result = carry_forward(catalog)

    assert result.carried == []
    assert result.stranded == []
    assert DashboardQueries(catalog).introduced_by(REPO, "bd9e3c6b") == {"high": 1}


# ---------------------------------------------------------------------------
# The matcher itself
# ---------------------------------------------------------------------------


class TestSimilarity:
    """The two constants, measured against the snippets in the lake."""

    def test_the_edited_call_clears_the_floor(self) -> None:
        assert snippet_similarity(DISMISSED_821, EDITED_917) >= MIN_SIMILARITY

    def test_the_two_new_calls_do_not(self) -> None:
        assert snippet_similarity(DISMISSED_821, NEW_948) < MIN_SIMILARITY
        assert snippet_similarity(DISMISSED_821, NEW_991) < MIN_SIMILARITY

    def test_the_margin_separates_them(self) -> None:
        best = snippet_similarity(DISMISSED_821, EDITED_917)
        runner_up = max(
            snippet_similarity(DISMISSED_821, NEW_948),
            snippet_similarity(DISMISSED_821, NEW_991),
        )
        assert best - runner_up >= MIN_MARGIN

    def test_reindentation_alone_is_identical(self) -> None:
        assert snippet_similarity(
            DISMISSED_821, "\n".join("    " + x for x in DISMISSED_821.splitlines())
        ) == pytest.approx(1.0)

    def test_nothing_in_common_is_zero(self) -> None:
        assert snippet_similarity("a\nb", "c\nd") == 0.0

    def test_two_empty_snippets_are_not_a_match(self) -> None:
        assert snippet_similarity("", "") == 0.0


def test_an_empty_lake_is_a_no_op(catalog: Catalog) -> None:
    result = carry_forward(catalog)
    assert result.carried == []
    assert result.stranded == []
