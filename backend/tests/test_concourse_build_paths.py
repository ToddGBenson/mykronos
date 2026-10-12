"""A finding's path is repo-relative under Concourse too (TheHub #60734, D-160).

Concourse runs a task in `/tmp/build/<handle>/` with the checkout mounted
beside it as `source`. PSScriptAnalyzer reports absolute paths, and the
normaliser only knew GitHub's runner layout, so every PSSA finding was stored
as `tmp/build/e542859e/source/scripts/...` -- 48 open in mykronos and 68 in
personal-soc, measured 2026-10-12. The upload's `--workspace` is the upload
task's own `/tmp/build/<other handle>/source`, so it could not match either.

Stripping the prefix changes those findings' ids: the path is an input, and
a path that now resolves to a real file also gains the snippet and symbol it
never had. So the adapter records the path the finding was stored under, and
ingestion links the new id to the old one exactly (D-139's mechanism):
the new row inherits the old one's first sighting and decision, and
`carry_forward` withdraws the old row as `superseded`. Neither half is counted
as a fix or as something the commit introduced, which is the accounting the
Oracle gate's posture credits read.

Findings here come out of the real adapters.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.adapters.base import ScanContext
from mykronos.adapters.sarif import _clean_uri, sarif_to_findings
from mykronos.adapters.sast_psscriptanalyzer import normalize as pssa_normalize
from mykronos.fingerprint import (
    FINGERPRINT_V1_LINE,
    IDENTITY_KEY,
    compute_finding_id,
    v2_predecessor_id,
)
from mykronos.lake import Catalog, carry_forward, reconcile_absences
from tests.conftest import ADMIN_TOKEN, REPO, issue_token, post_findings, post_scan

HANDLE = "e542859e"
SCRIPT = "scripts/Invoke-Thing.ps1"
RULE = "PSAvoidUsingPositionalParameters"
LINE = 3
SOURCE = "function Invoke-Thing {\n    param($Name)\n    Write-Output $Name 'positional'\n}\n"
#: What the lake holds for these findings today: the prefix without its
#: leading slash, because `_clean_uri` stripped that and nothing else.
STORED_PATH = f"tmp/build/{HANDLE}/source/{SCRIPT}"


def _context(workspace: Path | None) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="sast",
        tool_name="psscriptanalyzer",
        tool_version="1.25.0",
        commit_sha="abc1234",
        branch="main",
        workspace=workspace,
    )


def _checkout(tmp_path: Path) -> Path:
    """The upload task's `source`: a different build handle from the analyser's."""
    workspace = tmp_path / "tmp" / "build" / "0f0f0f0f" / "source"
    (workspace / "scripts").mkdir(parents=True, exist_ok=True)
    (workspace / SCRIPT).write_text(SOURCE, encoding="utf-8")
    return workspace


def _pssa_json(path: str = f"/{STORED_PATH}") -> bytes:
    """`Invoke-ScriptAnalyzer | ConvertTo-Json`, as the Concourse task writes it."""
    return json.dumps(
        [
            {
                "RuleName": RULE,
                "Severity": 1,
                "ScriptName": "Invoke-Thing.ps1",
                "ScriptPath": path,
                "Line": LINE,
                "Column": 5,
                "Message": "Cmdlet 'Write-Output' has positional parameter.",
            }
        ]
    ).encode()


def _pssa_sarif(*uris: str) -> bytes:
    """A PSScriptAnalyzer SARIF document (ConvertToSARIF's shape)."""
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PSScriptAnalyzer",
                            "version": "1.25.0",
                            "rules": [{"id": RULE, "shortDescription": {"text": RULE}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": RULE,
                            "level": "warning",
                            "message": {"text": "Cmdlet has positional parameter."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": LINE},
                                    }
                                }
                            ],
                        }
                        for uri in uris
                    ],
                }
            ],
        }
    ).encode()


def _stored_id() -> str:
    """The id these findings have in the lake: `v1-line`, keyed on the
    prefixed path, because no snippet could be read from a path that is not
    in the checkout. Measured: all 116 such rows are `v1-line` with neither a
    snippet nor a symbol."""
    finding_id, version = compute_finding_id(
        repo_full_name=REPO,
        capability="sast",
        rule_id=RULE,
        file_path=STORED_PATH,
        line_start=LINE,
    )
    assert version == FINGERPRINT_V1_LINE
    return finding_id


def _predecessor(finding: Any) -> str | None:
    return v2_predecessor_id(
        repo_full_name=REPO,
        capability="sast",
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        symbol=finding.symbol,
        code_snippet=finding.code_snippet,
        line_start=finding.line_start,
        raw_finding_json=finding.raw_finding_json,
    )


# ---------------------------------------------------------------------------
# The normaliser
# ---------------------------------------------------------------------------


class TestTheNormaliser:
    @pytest.mark.parametrize(
        "uri",
        [
            f"/tmp/build/{HANDLE}/source/{SCRIPT}",
            f"tmp/build/{HANDLE}/source/{SCRIPT}",
            f"file:///tmp/build/{HANDLE}/source/{SCRIPT}",
            f"\\tmp\\build\\{HANDLE}\\source\\scripts\\Invoke-Thing.ps1",
        ],
    )
    def test_the_build_dir_is_stripped(self, uri: str) -> None:
        assert _clean_uri(uri) == SCRIPT

    def test_with_a_workspace_from_another_build(self) -> None:
        """The upload's `--workspace` is its own handle, never the analyser's."""
        assert _clean_uri(f"/{STORED_PATH}", Path("/tmp/build/0f0f0f0f/source")) == SCRIPT

    @pytest.mark.parametrize(
        "path",
        [
            "tmp/build/notes.md",
            "docs/tmp/build/e542859e/source/x.ps1",
            "tmp/build/not-a-handle/source/x.ps1",
            "scripts/Invoke-Thing.ps1",
        ],
    )
    def test_anything_else_is_left_alone(self, path: str) -> None:
        assert _clean_uri(path) == path


class TestThePsscriptanalyzerSarif:
    def test_the_stored_path_is_repo_relative(self) -> None:
        """Both spellings the story names, in one PSSA SARIF document."""
        result = sarif_to_findings(_pssa_sarif(f"/{STORED_PATH}", STORED_PATH), _context(None))

        assert [f.file_path for f in result.findings] == [SCRIPT, SCRIPT]

    def test_it_names_the_id_the_finding_had(self, tmp_path: Path) -> None:
        workspace = _checkout(tmp_path)
        [finding] = sarif_to_findings(_pssa_sarif(f"/{STORED_PATH}"), _context(workspace)).findings

        assert finding.raw_finding_json[IDENTITY_KEY]["v2_file_path"] == STORED_PATH
        assert _predecessor(finding) == _stored_id()

    def test_a_path_that_did_not_change_records_nothing(self, tmp_path: Path) -> None:
        workspace = _checkout(tmp_path)
        [finding] = sarif_to_findings(_pssa_sarif(SCRIPT), _context(workspace)).findings

        assert "v2_file_path" not in finding.raw_finding_json[IDENTITY_KEY]


class TestThePsscriptanalyzerAdapter:
    """The JSON the Concourse lane actually uploads, through the same normaliser."""

    def test_the_stored_path_is_repo_relative(self) -> None:
        [finding] = pssa_normalize(_pssa_json(), _context(None)).findings
        assert finding.file_path == SCRIPT

    def test_the_file_is_now_read_so_the_finding_is_anchored_in_it(self, tmp_path: Path) -> None:
        """The prefix was why every one of them was `v1-line`: no snippet."""
        [finding] = pssa_normalize(_pssa_json(), _context(_checkout(tmp_path))).findings
        assert finding.code_snippet and "Write-Output" in finding.code_snippet

    def test_it_names_the_id_the_finding_had(self, tmp_path: Path) -> None:
        [finding] = pssa_normalize(_pssa_json(), _context(_checkout(tmp_path))).findings
        assert _predecessor(finding) == _stored_id()


# ---------------------------------------------------------------------------
# The lake: re-keyed, not fixed-and-introduced
# ---------------------------------------------------------------------------

_RUNS = iter(range(1, 10_000))


def _scan(client: TestClient, token: str, findings: list[dict[str, Any]]) -> str:
    run_id = f"00000000-0000-0000-0060-{next(_RUNS):012d}"
    headers = {"Authorization": f"Bearer {token}"}
    response = post_scan(
        client,
        headers,
        scan_run_id=run_id,
        capability="sast",
        tool_name="psscriptanalyzer",
        branch="main",
        scan_status="success",
        pr_number=None,
        triggered_by="push",
    )
    assert response.status_code == 200, response.text
    response = post_findings(client, headers, findings, scan_run_id=run_id, capability="sast")
    assert response.status_code == 200, response.text
    return run_id


def _as_stored() -> list[dict[str, Any]]:
    """What the uploader submitted before this change, as the lake recorded it."""
    return [
        {
            "rule_id": RULE,
            "title": f"{RULE}: Cmdlet 'Write-Output' has positional parameter.",
            "severity": "low",
            "file_path": STORED_PATH,
            "line_start": LINE,
            "line_end": LINE,
            "raw_finding_json": {"RuleName": RULE},
        }
    ]


def _from_adapter(workspace: Path | None) -> list[dict[str, Any]]:
    return [
        f.model_dump(mode="json")
        for f in pssa_normalize(_pssa_json(), _context(workspace)).findings
    ]


def _rows(catalog: Catalog) -> dict[str, dict[str, Any]]:
    columns = (
        "file_path",
        "finding_id",
        "status",
        "first_seen_at",
        "first_seen_scan_run_id",
        "superseded_by",
        "superseded_source",
    )
    return {
        row[0]: dict(zip(columns, row, strict=True))
        for row in catalog.query(f"SELECT {', '.join(columns)} FROM findings", [])
    }


class TestExistingFindingsAreReKeyed:
    @pytest.mark.parametrize("readable", [True, False], ids=["v3-snippet", "v1-line"])
    def test_one_finding_stays_one_finding(
        self,
        client: TestClient,
        catalog: Catalog,
        run_compaction: Callable[[], Any],
        tmp_path: Path,
        readable: bool,
    ) -> None:
        """The story's AC3. `readable=False` is a checkout the file cannot be
        read from: the successor stays `v1-line`, and must still link."""
        token = issue_token(client, REPO, "sast")
        first_run = _scan(client, token, _as_stored())
        run_compaction()
        old = _rows(catalog)[STORED_PATH]
        assert old["finding_id"] == _stored_id()

        _scan(client, token, _from_adapter(_checkout(tmp_path) if readable else None))
        run_compaction()

        new = _rows(catalog)[SCRIPT]
        # Not introduced by this commit: it carries the old first sighting.
        assert new["first_seen_scan_run_id"] == first_run
        assert new["first_seen_at"] == old["first_seen_at"]

        result = carry_forward(catalog)
        assert [(c.from_finding_id, c.to_finding_id, c.exact) for c in result.carried] == [
            (old["finding_id"], new["finding_id"], True)
        ]

        # Two more scans: the absence reconciler has every chance to call the
        # old row fixed, and must find nothing to close.
        for _ in range(2):
            _scan(client, token, _from_adapter(_checkout(tmp_path) if readable else None))
            run_compaction()
        assert reconcile_absences(catalog).total_fixed == 0

        rows = _rows(catalog)
        assert rows[STORED_PATH]["status"] == "superseded"
        assert rows[STORED_PATH]["superseded_by"] == new["finding_id"]
        assert rows[STORED_PATH]["superseded_source"] == "carry_forward"
        assert rows[SCRIPT]["status"] == "open"
        assert not [r for r in rows.values() if r["status"] == "fixed"]

    def test_a_decision_moves_with_it(
        self,
        client: TestClient,
        catalog: Catalog,
        run_compaction: Callable[[], Any],
        tmp_path: Path,
    ) -> None:
        token = issue_token(client, REPO, "sast")
        _scan(client, token, _as_stored())
        run_compaction()
        response = client.patch(
            f"/api/dashboard/findings/{_stored_id()}/status",
            json={"status": "false_positive", "reason": "the parameter is positional by design"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert response.status_code == 200, response.text

        _scan(client, token, _from_adapter(_checkout(tmp_path)))
        run_compaction()

        assert _rows(catalog)[SCRIPT]["status"] == "false_positive"
