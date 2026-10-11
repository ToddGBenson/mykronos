"""A finding's identity does not move with unrelated edits (B-067, D-139).

`finding_id` hashes the enclosing `symbol` with the snippet (spec 05 §5).
Under `v2-snippet` the adapter's symbol was the first declaration-shaped line
anywhere above the finding, and a snippet sliced from disk carried two lines
of context either side. So inserting a function above a module-level finding
re-keyed it, an edit two lines away re-keyed it, and three of TheHub's
`lifecycle.py` findings were filed under `stories` — a word in a docstring.

The second half of this file is the migration: a decision recorded under the
old identity must arrive on the new one, at ingestion, without a similarity
guess.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.adapters import ScanContext, sarif_to_findings
from mykronos.adapters.snippet import (
    infer_symbol,
    infer_symbol_v2,
    slice_snippet,
    slice_snippet_v2,
    v2_identity,
)
from mykronos.dashboard import DashboardQueries
from mykronos.fingerprint import (
    FINGERPRINT_V3_SNIPPET,
    compute_finding_id,
    identity_rule_of,
    snippet_similarity,
    v2_predecessor_id,
)
from mykronos.lake import Catalog, carry_forward
from mykronos.lake.carry_forward import MIN_SIMILARITY
from mykronos.schemas import FindingSubmission, utcnow
from tests.conftest import REPO, post_findings, post_scan

RULE = "python.lang.security.audit.formatted-sql-query"
FILE = "orders.py"

MODULE_LEVEL = '''import os

from db import cursor


class Config:
    dsn = os.environ["DSN"]


QUERY = "SELECT * FROM orders WHERE id = " + os.environ["ORDER"]
'''
MODULE_LEVEL_LINE = 10

#: The 2026-09-10 reproduction: one function inserted above the flagged line.
WITH_A_HELPER_ABOVE = MODULE_LEVEL.replace(
    "\n\nQUERY", '\n\ndef helper():\n    return 1\n\n\nQUERY'
)

#: The shape of TheHub's `lifecycle.py` that produced `symbol = 'stories'`:
#: a docstring sentence the Java/C# pattern reads as a method declaration.
LIFECYCLE = '''from sqlalchemy import text


def _deploy_run_sha_for_story(db, story_id):
    """Which run carried this story.

    six stories (58504, 58506, 58514, 58515, 58541, 58543) were live in
    the window this reads, and `meta -> 'stories'` is a containment test.
    """
    row = db.execute(
        text(
            "SELECT r.sha FROM deploy_runs r "
            "WHERE r.meta -> 'stories' @> CAST(:sid AS jsonb) "
            "LIMIT 1"
        ),
        {"sid": f"[{int(story_id)}]"},
    )
    return row
'''
LIFECYCLE_LINE = 11  # the `text(` call


def _context(workspace: Path | None) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="sast",
        tool_name="semgrep",
        tool_version="1.0",
        commit_sha="a91f2c7",
        branch="main",
        workspace=workspace,
    )


def _sarif(line: int, uri: str = FILE) -> bytes:
    """A Semgrep-shaped result with no snippet, so the adapter reads the file."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Semgrep", "rules": [{"id": RULE}]}},
                    "results": [
                        {
                            "ruleId": RULE,
                            "level": "error",
                            "message": {"text": "SQL built from the environment."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": line, "endLine": line},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def _adapter(workspace: Path, source: str, line: int, uri: str = FILE) -> FindingSubmission:
    (workspace / uri).write_text(source, encoding="utf-8")
    result = sarif_to_findings(_sarif(line, uri), _context(workspace))
    assert len(result.findings) == 1
    return result.findings[0]


def _identity(finding: FindingSubmission) -> tuple[str, str]:
    """Exactly what `/api/ingest/findings` computes."""
    return compute_finding_id(
        repo_full_name=REPO,
        capability="sast",
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        symbol=finding.symbol,
        code_snippet=finding.code_snippet,
        line_start=finding.line_start,
        identity_rule=identity_rule_of(finding.raw_finding_json),
    )


# ---------------------------------------------------------------------------
# The same finding keeps its identity across an unrelated edit
# ---------------------------------------------------------------------------


class TestIdentitySurvivesUnrelatedEdits:
    def test_inserting_a_function_above_a_module_level_finding(self, tmp_path: Path) -> None:
        """The B-067 reproduction. Under v2 the symbol went Config -> helper."""
        before = _adapter(tmp_path, MODULE_LEVEL, MODULE_LEVEL_LINE)
        after = _adapter(tmp_path, WITH_A_HELPER_ABOVE, MODULE_LEVEL_LINE + 4)

        assert before.symbol is None and after.symbol is None
        assert _identity(before) == _identity(after)
        assert _identity(after)[1] == FINGERPRINT_V3_SNIPPET

        # And the old rule really did move it — the defect, pinned.
        assert infer_symbol_v2(MODULE_LEVEL.splitlines(), MODULE_LEVEL_LINE) == "Config"
        assert (
            infer_symbol_v2(WITH_A_HELPER_ABOVE.splitlines(), MODULE_LEVEL_LINE + 4)
            == "helper"
        )

    def test_editing_a_line_next_to_the_finding(self, tmp_path: Path) -> None:
        """The slice was the finding plus two lines either side, so this
        re-keyed it. The matched line is all that is hashed now."""
        before = _adapter(tmp_path, LIFECYCLE, LIFECYCLE_LINE)
        neighbour_edited = LIFECYCLE.replace(
            "    row = db.execute(", "    # bound below\n    row = db.execute("
        )
        after = _adapter(tmp_path, neighbour_edited, LIFECYCLE_LINE + 1)

        assert before.code_snippet == after.code_snippet == "        text("
        assert _identity(before) == _identity(after)

    def test_a_function_inserted_above_the_enclosing_one(self, tmp_path: Path) -> None:
        before = _adapter(tmp_path, LIFECYCLE, LIFECYCLE_LINE)
        inserted = LIFECYCLE.replace(
            "\n\ndef _deploy_run_sha_for_story",
            "\n\ndef run_claims_story(meta, story_id):\n    return True\n"
            "\n\ndef _deploy_run_sha_for_story",
        )
        after = _adapter(tmp_path, inserted, LIFECYCLE_LINE + 4)

        assert _identity(before) == _identity(after)

    def test_a_real_change_to_the_flagged_code_still_changes_it(self, tmp_path: Path) -> None:
        """The counterweight: identity must not be so sticky that a fix is
        invisible."""
        before = _adapter(tmp_path, MODULE_LEVEL, MODULE_LEVEL_LINE)
        fixed = MODULE_LEVEL.replace('" + os.environ["ORDER"]', '?"')
        after = _adapter(tmp_path, fixed, MODULE_LEVEL_LINE)

        assert _identity(before) != _identity(after)

    def test_a_disk_slice_is_the_matched_lines_only(self) -> None:
        lines = [f"line{i}" for i in range(1, 21)]
        assert slice_snippet(lines, 10, 10) == "line10"
        assert slice_snippet(lines, 10, 12) == "line10\nline11\nline12"
        # The v2 slice is kept for lineage, unchanged.
        assert slice_snippet_v2(lines, 10, 10) == "line8\nline9\nline10\nline11\nline12"


# ---------------------------------------------------------------------------
# A symbol is never taken from a string literal
# ---------------------------------------------------------------------------


class TestSymbolIsTheEnclosingDeclaration:
    def test_the_lifecycle_case(self) -> None:
        """AC4: `_deploy_run_sha_for_story`, not `stories`."""
        lines = LIFECYCLE.splitlines()
        assert infer_symbol(lines, LIFECYCLE_LINE, FILE) == "_deploy_run_sha_for_story"
        assert infer_symbol_v2(lines, LIFECYCLE_LINE) == "stories"

    @pytest.mark.parametrize(
        ("source", "line", "path"),
        [
            # A Python def inside a triple-quoted string, above module code.
            ('SQL = """\ndef injected(x):\n"""\nrun(SQL)\n', 4, "a.py"),
            # A string that is a whole Python statement of its own.
            ('def outer():\n    pass\n"def fake(a):"\nrun()\n', 4, "a.py"),
            # A JavaScript function inside a template literal.
            ("const t = `\nfunction fake(a) {\n`;\nrun(t);\n", 4, "a.js"),
            # ... and inside a block comment.
            ("/*\nfunction fake(a) {\n*/\nrun();\n", 4, "a.js"),
            # A Java-shaped sentence inside a Python string continuation.
            ('x = (\n    "public void fake(int a) "\n)\nrun(x)\n', 4, "a.py"),
        ],
    )
    def test_never_from_a_string_or_comment(self, source: str, line: int, path: str) -> None:
        assert infer_symbol(source.splitlines(), line, path) is None

    def test_a_string_inside_the_function_does_not_hide_it(self) -> None:
        source = (
            "function handler(req) {\n"
            '  const s = "} function fake() {";\n'
            "  // } class Nope {\n"
            "  bad(req);\n"
            "}\n"
        )
        assert infer_symbol(source.splitlines(), 4, "a.js") == "handler"

    @pytest.mark.parametrize(
        ("source", "line", "path", "expected"),
        [
            # Python: bounded by indentation. A closed function is not a scope.
            ("def helper():\n    return 1\n\nQUERY = run()\n", 4, "a.py", None),
            # ... and the enclosing method, not a sibling above it.
            (
                "class A:\n    def one(self):\n        pass\n\n"
                "    def two(self):\n        if x:\n            bad()\n",
                7, "a.py", "two",
            ),
            # Brace languages: bounded by braces.
            ("function helper() {\n  return 1;\n}\nbad();\n", 4, "a.js", None),
            (
                "class View {\n  render() {\n    if (x) {\n      bad();\n    }\n  }\n}\n",
                4, "a.js", "render",
            ),
            ("func (s *Server) Handle(w, r) {\n  bad()\n}\n", 2, "a.go", "Handle"),
            ("helper() {\n  echo \"${#arr}\"\n}\nmain() {\n  rm -rf $x\n}\n", 5, "a.sh", "main"),
            # An extension this does not know: no guess.
            ("def handler():\n    bad()\n", 2, "a.txt", None),
        ],
    )
    def test_bounded_by_the_language(
        self, source: str, line: int, path: str, expected: str | None
    ) -> None:
        assert infer_symbol(source.splitlines(), line, path) == expected


# ---------------------------------------------------------------------------
# The migration: decisions follow the re-key, exactly
# ---------------------------------------------------------------------------

SCAN_ONE = "bbbbbbbb-0000-0000-0000-000000000001"
SCAN_TWO = "bbbbbbbb-0000-0000-0000-000000000002"


def _scan(
    client: TestClient, auth: dict[str, str], scan_run_id: str, sha: str, minute: int
) -> None:
    started = datetime(2026, 10, 11, 12, minute, tzinfo=UTC).replace(tzinfo=None)
    for completed in (None, started.isoformat()):
        body: dict[str, Any] = {
            "scan_run_id": scan_run_id,
            "commit_sha": sha,
            "branch": "main",
            "tool_name": "semgrep",
            "started_at": started.isoformat(),
            "scan_status": "success",
            "pr_number": None,
            "triggered_by": "push",
        }
        if completed:
            body["completed_at"] = completed
        assert post_scan(client, auth, **body).status_code == 200


def _v2_payload(source: str, line: int) -> dict[str, Any]:
    """What an uploader from before this change submitted for `line`."""
    lines = source.splitlines()
    return {
        "rule_id": RULE,
        "title": "Formatted SQL query",
        "severity": "high",
        "file_path": FILE,
        "line_start": line,
        "line_end": line,
        "symbol": infer_symbol_v2(lines, line),
        "code_snippet": slice_snippet_v2(lines, line, line),
        "raw_finding_json": {"ruleId": RULE},
    }


def _v3_payload(workspace: Path, source: str, line: int) -> dict[str, Any]:
    finding = _adapter(workspace, source, line)
    payload = finding.model_dump(mode="json", exclude_none=True)
    payload["title"] = "Formatted SQL query"
    payload["severity"] = "high"
    return payload


def _ids(catalog: Catalog) -> dict[str, tuple[Any, ...]]:
    return {
        str(row[0]): row[1:]
        for row in catalog.query(
            "SELECT finding_id, status, first_seen_scan_run_id, accepted_until, "
            "       accepted_reason_code, superseded_by, fingerprint_version "
            "FROM findings WHERE file_path = ?",
            [FILE],
        )
    }


def test_an_accepted_risk_arrives_on_the_rekeyed_finding_at_ingestion(
    client: TestClient,
    auth: dict[str, str],
    admin_auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
    tmp_path: Path,
) -> None:
    """A one-line finding, re-keyed by nothing but the uploader upgrade.

    Its v2 snippet was five lines and its v3 snippet is one, so the content
    matcher would rightly refuse the pair. The adapter's own record of the old
    identity is what carries the acceptance — with its review date and reason
    — and it lands before any gate can count the finding as introduced.
    """
    _scan(client, auth, SCAN_ONE, "1111111", minute=0)
    old = _v2_payload(LIFECYCLE, LIFECYCLE_LINE)
    assert post_findings(client, auth, [old], scan_run_id=SCAN_ONE).status_code == 200
    run_compaction()
    (old_id,) = _ids(catalog)

    until = (utcnow().date() + timedelta(days=30)).isoformat()
    response = client.patch(
        f"/api/dashboard/findings/{old_id}/status",
        json={
            "status": "accepted_risk",
            "reason": "the variable is set by the deploy, not a user",
            "accepted_reason_code": "compensating_control",
            "accepted_until": until,
        },
        headers=admin_auth,
    )
    assert response.status_code == 200, response.text
    run_compaction()

    # The same file, unchanged, scanned by the upgraded uploader.
    _scan(client, auth, SCAN_TWO, "2222222", minute=30)
    new = _v3_payload(tmp_path, LIFECYCLE, LIFECYCLE_LINE)
    assert snippet_similarity(old["code_snippet"], new["code_snippet"]) < MIN_SIMILARITY
    assert post_findings(client, auth, [new], scan_run_id=SCAN_TWO).status_code == 200
    run_compaction()

    rows = _ids(catalog)
    (new_id,) = set(rows) - {old_id}
    assert rows[new_id][0] == "accepted_risk"
    assert rows[new_id][1] == SCAN_ONE, "first seen by the old scan, not this one"
    assert str(rows[new_id][2]) == until
    assert rows[new_id][3] == "compensating_control"
    assert rows[new_id][5] == FINGERPRINT_V3_SNIPPET
    assert DashboardQueries(catalog).introduced_by(REPO, "2222222") == {}

    # And the old row is withdrawn against its successor, not stranded.
    result = carry_forward(catalog)
    assert result.stranded == []
    assert [(c.from_finding_id, c.to_finding_id, c.exact) for c in result.carried] == [
        (old_id, new_id, True)
    ]
    rows = _ids(catalog)
    assert rows[old_id][0] == "superseded"
    assert rows[old_id][4] == new_id
    assert rows[new_id][0] == "accepted_risk"


def test_a_finding_the_new_rule_leaves_alone_keeps_its_row(
    client: TestClient,
    auth: dict[str, str],
    catalog: Catalog,
    run_compaction: Callable[[], Any],
) -> None:
    """A tool-supplied snippet whose symbol was already right is not re-keyed:
    v3 hashes the same inputs the same way, so there is nothing to carry."""
    source = "def handler(req):\n    run(req)\n"
    _scan(client, auth, SCAN_ONE, "1111111", minute=0)
    old = _v2_payload(source, 2) | {"code_snippet": "run(req)"}
    post_findings(client, auth, [old], scan_run_id=SCAN_ONE)
    run_compaction()

    assert infer_symbol(source.splitlines(), 2, FILE) == old["symbol"] == "handler"
    new = old | {
        "raw_finding_json": v2_identity(
            old["raw_finding_json"],
            snippet="run(req)", symbol="handler", v2_snippet="run(req)", v2_symbol="handler",
        )
    }
    assert v2_predecessor_id(
        repo_full_name=REPO, capability="sast", rule_id=RULE, file_path=FILE,
        symbol="handler", code_snippet="run(req)", line_start=2,
        raw_finding_json=new["raw_finding_json"],
    ) is None

    _scan(client, auth, SCAN_TWO, "2222222", minute=30)
    post_findings(client, auth, [new], scan_run_id=SCAN_TWO)
    run_compaction()

    rows = _ids(catalog)
    assert len(rows) == 1
    ((status, first_seen, *_rest, version),) = rows.values()
    assert (status, first_seen, version) == ("open", SCAN_ONE, FINGERPRINT_V3_SNIPPET)
