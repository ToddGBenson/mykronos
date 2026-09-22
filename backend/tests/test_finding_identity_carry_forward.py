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

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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


# ---------------------------------------------------------------------------
# #60273 — the refusals reach a person, in the configuration production is in
# ---------------------------------------------------------------------------
#
# Measured against the production lake on 2026-09-18 (8,424 findings / 4,897
# scan runs): `carry_forward` returns **0 carried and 4 stranded**, and will
# return exactly that every hour until one of the four inputs changes. The
# refusals are all computed correctly and all four land in
# `CarryForwardResult` — the defect was that the two `logger.warning` lines
# naming them sat *below* `if dry_run or not pairs: return result`, so with no
# carries the function returned first and threw them away. The scheduled job in
# `main.py` reads the log, not the object, so none of those four names has ever
# reached a log line.
#
# The four, and what each one exercises here:
#
#   mykronos backend/mykronos/jobs.py                false_positive  0.538
#   mykronos backend/mykronos/db/session.py          false_positive  0.333
#   TheHub   .../incident_response/ir_service.py     false_positive  0.000
#   keel     .github/workflows/release.yml           accepted_risk   no snippet
#
# The three scores are reproduced exactly by `TestTheLiveRefusalScores` below
# (7/13, 1/3 and 0). The fourth is production's "nothing comparable" case,
# modelled as the stored-no-snippet refusal — the one reason `_refusal` gives
# that carries no score at all.
#
# These tests deliberately run with *zero* carries. A test that also carried
# something would keep the function past the early return and would pass
# against the defect.

STRANDED_LOGGER = "mykronos.lake.carry_forward"

FILE_JOBS = "backend/mykronos/jobs.py"
FILE_SESSION = "backend/mykronos/db/session.py"
FILE_IR = "backend/services/incident_response/ir_service.py"
FILE_RELEASE = ".github/workflows/release.yml"

RULE_ACTION_PIN = "yaml.github-actions.security.third-party-action-not-pinned"

# --- 0.538: seven normalized lines in common out of thirteen ---------------

JOBS_DISMISSED = '''    def _sweep_stale_scan_runs(session: Session) -> int:
        cutoff = utcnow() - timedelta(hours=6)
        rows = session.execute(
            text("SELECT scan_run_id FROM scan_runs WHERE started_at < :cutoff"),
            {"cutoff": cutoff},
        )
        swept = [r[0] for r in rows]
        logger.info("swept %d stale scan runs", len(swept))
        session.commit()
        return len(swept)'''

JOBS_SUCCESSOR = '''    def _sweep_stale_scan_runs(session: Session) -> int:
        cutoff = utcnow() - timedelta(hours=6)
        rows = session.execute(
            text("SELECT scan_run_id, finished FROM scan_runs WHERE started_at < :c"),
            {"cutoff": cutoff},
        )
        swept = [r[0] for r in rows if r[1] is None]
        logger.warning("swept %d running scan runs", len(swept))
        session.commit()
        return len(swept)'''

# --- 0.333: four in common out of twelve, the `_identifier(...)` rewrite ----

SESSION_DISMISSED = '''    def _configure(engine: Engine) -> None:
        engine.execute(text("SET search_path TO mykronos"))
        engine.execute(text("SET statement_timeout TO 30000"))
        engine.execute(text("SET lock_timeout TO 5000"))
        engine.execute(text("SET timezone TO 'UTC'"))
        register_vector(engine)
        engine.dispose()
        return None'''

SESSION_SUCCESSOR = '''    def _configure(engine: Engine) -> None:
        engine.execute(_identifier(text("SET search_path TO :schema"), schema))
        engine.execute(_identifier(text("SET statement_timeout TO :ms"), timeout))
        engine.execute(_identifier(text("SET lock_timeout TO :ms"), lock_ms))
        engine.execute(_identifier(text("SET timezone TO :tz"), tz))
        register_vector(engine)
        engine.dispose()
        return None'''

# --- 0.000: nothing in common at all ---------------------------------------

IR_DISMISSED = '''    severity_counts = collections.Counter(a.severity for a in alerts)
    if severity_counts["critical"]:
        page_oncall(incident, reason="critical alert present")'''

IR_SUCCESSOR = '''    window = timedelta(minutes=settings.correlation_window_minutes)
    grouped = itertools.groupby(sorted(events, key=_by_host), _by_host)
    return [Correlation(host=h, events=list(g)) for h, g in grouped]'''

# --- the fourth: an unpinned action, accepted, with no snippet ever stored --

RELEASE_SUCCESSOR = '''      - uses: actions/checkout@v7.0.1
        with:
          fetch-depth: 0'''


class TestTheLiveRefusalScores:
    """The three scored refusals production is sitting on, reproduced exactly.

    Not decoration: these are what make the configuration below the real one.
    Each is a Jaccard over normalized snippet lines with an exact rational
    value, so the numbers in the log assertions are measured rather than
    guessed at.
    """

    def test_jobs_scores_the_measured_0_538(self) -> None:
        score = snippet_similarity(JOBS_DISMISSED, JOBS_SUCCESSOR)
        assert score == pytest.approx(7 / 13)
        assert score == pytest.approx(0.538, abs=5e-4)
        assert score < MIN_SIMILARITY

    def test_session_scores_the_measured_0_333(self) -> None:
        score = snippet_similarity(SESSION_DISMISSED, SESSION_SUCCESSOR)
        assert score == pytest.approx(1 / 3)
        assert score == pytest.approx(0.333, abs=5e-4)
        assert score < MIN_SIMILARITY

    def test_ir_service_scores_the_measured_0_000(self) -> None:
        assert snippet_similarity(IR_DISMISSED, IR_SUCCESSOR) == 0.0

    def test_all_three_sit_below_the_floor_by_a_clear_margin(self) -> None:
        """The floor is 0.60 and the nearest refusal is 0.538, so none of
        these is a borderline call that a small retune would flip."""
        assert MIN_SIMILARITY - snippet_similarity(
            JOBS_DISMISSED, JOBS_SUCCESSOR
        ) == pytest.approx(0.0615, abs=5e-4)


def _accept_risk(client: TestClient, finding_id: str) -> None:
    """Production's fourth stranded decision is an accepted risk, not a false
    positive, and accepting one takes more than a status (spec 24 §3.2): a
    machine-revisitable code and an end date."""
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={
            "status": "accepted_risk",
            "reason": "the release workflow runs only on a protected tag ref",
            "accepted_reason_code": "compensating_control",
            "accepted_until": (
                datetime.now(UTC).date() + timedelta(days=30)
            ).isoformat(),
        },
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert response.status_code == 200, response.text


def _ids_by_file_and_line(catalog: Catalog) -> dict[tuple[str, int], str]:
    rows = catalog.query("SELECT file_path, line_start, finding_id FROM findings")
    return {(str(f), int(line)): str(fid) for f, line, fid in rows}


def _the_production_four(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> dict[str, str]:
    """Put the lake in the state production is in: four decisions, no carry.

    The four live in one repository here rather than three, because the lane
    and the group are what the matcher keys on and the log line is what is
    under test; the file, rule, status and score of each are production's.

    In every one of them something *did* appear under the same rule in the
    same file afterwards — so each is a refusal to choose, not a report that
    the code was deleted (spec 05 §5b, "Absence is not a refusal").
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    assert (
        post_findings(
            client,
            auth,
            [
                _sast_finding(JOBS_DISMISSED, 140, file_path=FILE_JOBS),
                _sast_finding(SESSION_DISMISSED, 61, file_path=FILE_SESSION),
                _sast_finding(IR_DISMISSED, 388, file_path=FILE_IR),
                # Ingested before snippets were captured: nothing to match on.
                _sast_finding(
                    RELEASE_SUCCESSOR,
                    22,
                    file_path=FILE_RELEASE,
                    rule_id=RULE_ACTION_PIN,
                    code_snippet=None,
                    symbol=None,
                ),
            ],
            scan_run_id=SCAN_ONE,
        ).status_code
        == 200
    )
    run_compaction()

    ids = _ids_by_file_and_line(catalog)
    dismissed = {
        "jobs_0_538": ids[(FILE_JOBS, 140)],
        "session_0_333": ids[(FILE_SESSION, 61)],
        "ir_0_000": ids[(FILE_IR, 388)],
        "release_no_snippet": ids[(FILE_RELEASE, 22)],
    }
    for key, finding_id in dismissed.items():
        # Production's fourth is an accepted risk, not a false positive. Both
        # are in HUMAN_DISPOSITIONS and both must be reported when stranded.
        if key == "release_no_snippet":
            _accept_risk(client, finding_id)
        else:
            _dispose(client, finding_id)

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    assert (
        post_findings(
            client,
            auth,
            [
                _sast_finding(JOBS_SUCCESSOR, 140, file_path=FILE_JOBS),
                _sast_finding(SESSION_SUCCESSOR, 61, file_path=FILE_SESSION),
                _sast_finding(IR_SUCCESSOR, 402, file_path=FILE_IR),
                _sast_finding(
                    RELEASE_SUCCESSOR,
                    24,
                    file_path=FILE_RELEASE,
                    rule_id=RULE_ACTION_PIN,
                ),
            ],
            scan_run_id=SCAN_TWO,
        ).status_code
        == 200
    )
    run_compaction()
    return dismissed


def test_the_stranded_decisions_are_logged_when_nothing_was_carried(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """#60273. Nothing is carried, four decisions are refused, and a person can
    read all four out of the log.

    This is production's hourly state. Before this change it computed four
    refusals and emitted none of them, because the two `logger.warning` lines
    sat below `if dry_run or not pairs: return result`.
    """
    dismissed = _the_production_four(client, auth, catalog, run_compaction)

    with caplog.at_level(logging.DEBUG, logger=STRANDED_LOGGER):
        result = carry_forward(catalog)

    # The configuration under test, asserted rather than assumed.
    assert result.carried == [], "this must be the zero-carry path or it proves nothing"
    assert len(result.stranded) == 4
    assert result.summary() == "0 finding(s) carried forward, 4 decision(s) stranded"

    stranded_records = [
        record
        for record in caplog.records
        if record.name == STRANDED_LOGGER and "Decision stranded" in record.getMessage()
    ]
    assert len(stranded_records) == 4

    # At WARNING. A refusal somebody has to act on must not arrive at a level
    # the scheduled process filters out.
    assert {record.levelno for record in stranded_records} == {logging.WARNING}

    logged = "\n".join(record.getMessage() for record in stranded_records)

    # Each names its own finding, its file, and the disposition at stake.
    for finding_id in dismissed.values():
        assert finding_id[:12] in logged
    for file_path in (FILE_JOBS, FILE_SESSION, FILE_IR, FILE_RELEASE):
        assert file_path in logged
    assert "accepted_risk" in logged
    assert "false_positive" in logged

    # And the reason, with the measured number in it — not just the fact.
    assert f"scored 0.54, below the {MIN_SIMILARITY:.2f} floor" in logged
    assert f"scored 0.33, below the {MIN_SIMILARITY:.2f} floor" in logged
    assert f"scored 0.00, below the {MIN_SIMILARITY:.2f} floor" in logged
    assert "no code snippet was stored" in logged

    # Nothing was carried, so nothing may claim to have been.
    assert [
        record for record in caplog.records if "Carried forward" in record.getMessage()
    ] == []


def test_a_carry_forward_with_nothing_to_do_is_distinguishable_from_one_that_refused(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The house rule, stated as a test: a control that reported nothing must
    not look like a control that reported fine.

    A lane where the dismissed call is still being reported genuinely has
    nothing to say, and says nothing. The four-refusal run above says four
    things. If those two produced the same log, the log would be worthless —
    and until this change they did.
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

    with caplog.at_level(logging.DEBUG, logger=STRANDED_LOGGER):
        result = carry_forward(catalog)

    assert result.carried == []
    assert result.stranded == []
    assert [r for r in caplog.records if r.name == STRANDED_LOGGER] == []


def test_a_dry_run_still_reports_the_decisions_it_refused(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`dry_run` withholds the writes, not the refusals.

    A refusal is finished the moment `match` returns it — no row has to be
    written for a decision to have been stranded — so a preview that hid them
    would be a preview of the wrong thing.
    """
    _the_production_four(client, auth, catalog, run_compaction)

    with caplog.at_level(logging.DEBUG, logger=STRANDED_LOGGER):
        result = carry_forward(catalog, dry_run=True)

    assert result.partitions_written == 0
    assert len(result.stranded) == 4
    assert len([r for r in caplog.records if "Decision stranded" in r.getMessage()]) == 4
    # Nothing was written, so nothing may be logged as though it had been.
    assert [r for r in caplog.records if "Carried forward" in r.getMessage()] == []


def test_a_dry_run_does_not_announce_carries_it_did_not_write(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The other half of the same rule, from the other direction: when there
    *is* a carry to make, a dry run must not log it as made.

    This is what keeps the fix from being "log everything unconditionally",
    and it pins that `_apply` and the `Carried forward` line stay gated on
    there being pairs (#60273 AC3).
    """
    _scan(client, auth, SCAN_ONE, "7197a02", minute=0)
    post_findings(client, auth, [_sast_finding(DISMISSED_821, 821)], scan_run_id=SCAN_ONE)
    run_compaction()
    _dispose(client, _ids_by_line(catalog)[821])

    _scan(client, auth, SCAN_TWO, "bd9e3c6b", minute=30)
    post_findings(client, auth, [_sast_finding(EDITED_917, 917)], scan_run_id=SCAN_TWO)
    run_compaction()

    with caplog.at_level(logging.DEBUG, logger=STRANDED_LOGGER):
        dry = carry_forward(catalog, dry_run=True)
    assert len(dry.carried) == 1
    assert dry.partitions_written == 0
    assert [r for r in caplog.records if "Carried forward" in r.getMessage()] == []

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger=STRANDED_LOGGER):
        wet = carry_forward(catalog)
    assert len(wet.carried) == 1
    assert len([r for r in caplog.records if "Carried forward" in r.getMessage()]) == 1
