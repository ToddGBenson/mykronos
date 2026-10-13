"""Repairing `fixed` on PowerShell findings that only moved (TheHub #60734).

The lake shape this undoes: while PSScriptAnalyzer paths were build dirs every
finding was keyed on its line, an edit moved two of them down the file, and
absence closed the old ids as `fixed` although the code was untouched. Then
#795 re-keyed the moved ones onto repo-relative paths and carry-forward
superseded their prefixed rows.

Built through the real ingest path, scan by scan, rather than written into
the lake by hand.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.fingerprint import FINGERPRINT_V3_SNIPPET, IDENTITY_KEY
from mykronos.lake import Catalog, carry_forward, reconcile_absences
from mykronos.repair_build_path_fixed import repair_build_path_fixed
from tests.conftest import REPO, issue_token
from tests.test_concourse_build_paths import RULE, SCRIPT, STORED_PATH, _scan

MOVED = "Cmdlet 'Drop' has positional parameter."
REMOVED = "Cmdlet 'Invoke-Api' has positional parameter."


def _old(line: int, message: str) -> dict[str, Any]:
    """What the pre-#795 uploader submitted: a prefixed path, keyed on the line."""
    return {
        "rule_id": RULE,
        "title": f"{RULE}: {message}",
        "severity": "low",
        "file_path": STORED_PATH,
        "line_start": line,
        "line_end": line,
        "raw_finding_json": {"RuleName": RULE},
    }


def _new(line: int, message: str) -> dict[str, Any]:
    """What #795's uploader submits for the same finding, naming the old id."""
    return {
        "rule_id": RULE,
        "title": f"{RULE}: {message}",
        "severity": "low",
        "file_path": SCRIPT,
        "line_start": line,
        "line_end": line,
        "symbol": "Invoke-Thing",
        "code_snippet": f"Drop $x 'positional' # line {line}",
        "raw_finding_json": {
            "RuleName": RULE,
            IDENTITY_KEY: {
                "rule": FINGERPRINT_V3_SNIPPET,
                "v2_file_path": STORED_PATH,
                "v2_symbol": None,
                "v2_code_snippet": None,
            },
        },
    }


def _status(catalog: Catalog) -> dict[tuple[str, int, str], dict[str, Any]]:
    columns = ("finding_id", "status", "superseded_by", "superseded_source", "first_seen_at")
    return {
        (str(r[0]), int(r[1]), str(r[2]).split(": ", 1)[1]): dict(zip(columns, r[3:], strict=True))
        for r in catalog.query(
            "SELECT file_path, line_start, title, finding_id, status, superseded_by, "
            "superseded_source, first_seen_at FROM findings",
            [],
        )
    }


@pytest.fixture
def lake(client: TestClient, catalog: Catalog, run_compaction: Callable[[], Any]) -> Catalog:
    """Two `MOVED` findings shift down five lines; one `REMOVED` finding of a
    pair really goes. Absence closes all three old ids as fixed."""
    token = issue_token(client, REPO, "sast")
    _scan(client, token, [_old(10, MOVED), _old(20, MOVED), _old(40, REMOVED), _old(50, REMOVED)])
    run_compaction()
    for _ in range(2):
        _scan(client, token, [_old(15, MOVED), _old(25, MOVED), _old(50, REMOVED)])
        run_compaction()
    assert reconcile_absences(catalog).total_fixed == 3

    _scan(client, token, [_new(15, MOVED), _new(25, MOVED), _new(50, REMOVED)])
    run_compaction()
    assert len(carry_forward(catalog).carried) == 3
    return catalog


def test_a_dry_run_reports_and_writes_nothing(lake: Catalog) -> None:
    before = _status(lake)
    result = repair_build_path_fixed(lake, dry_run=True)

    assert _status(lake) == before
    by_message = {g.title.split(": ", 1)[1]: g for g in result.groups}
    moved = by_message[MOVED]
    assert (moved.before, moved.after, moved.moved) == (2, 2, 2)
    assert [(old_line, new_line) for _o, _n, old_line, new_line in moved.pairs] == [
        (10, 15),
        (20, 25),
    ]
    removed = by_message[REMOVED]
    assert (removed.before, removed.after) == (2, 1)
    assert not removed.pairs and "not conserved" in removed.reason
    assert result.summary().endswith(
        "2 superseded by the finding they moved to, 1 left fixed and reported"
    )


def test_a_conserved_group_is_superseded_by_where_it_moved(lake: Catalog) -> None:
    repair_build_path_fixed(lake)
    rows = _status(lake)

    for old_line, new_line in ((10, 15), (20, 25)):
        old = rows[(STORED_PATH, old_line, MOVED)]
        successor = rows[(SCRIPT, new_line, MOVED)]
        assert old["status"] == "superseded"
        assert old["superseded_source"] == "rekey"
        assert old["superseded_by"] == successor["finding_id"]
        # The first sighting is the original one, not the edit's.
        assert successor["first_seen_at"] == old["first_seen_at"]
        assert successor["status"] == "open"


def test_a_group_whose_count_changed_is_left_fixed(lake: Catalog) -> None:
    repair_build_path_fixed(lake)
    assert _status(lake)[(STORED_PATH, 40, REMOVED)]["status"] == "fixed"


def test_running_it_twice_changes_nothing_the_second_time(lake: Catalog) -> None:
    repair_build_path_fixed(lake)
    after_first = _status(lake)
    second = repair_build_path_fixed(lake)

    assert _status(lake) == after_first
    assert sum(len(g.pairs) for g in second.groups) == 0
