"""In-repo scanner suppressions, recorded and shown (TheHub #60963, decision #60815 option B).

A `# nosemgrep`, a `# checkov:skip=` or any SARIF result the tool reports as
suppressed is the repository's author saying "I have answered this". Spec 05
s7 keeps that out of the findings table, because `suppressed` is a platform
disposition a rescan must not overwrite. Until now the platform kept nothing
else either: one warning line on the scan run, and no record of what was
silenced, by whom, or until when.

Now each one is a row of its own (not a finding), listed on the repository
page with its expiry, and an expired one is a lane-health fact.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from mykronos.adapters import ScanContext, sarif_to_findings
from mykronos.adapters.sarif import suppressions_from_sarif
from mykronos.lake.catalog import Catalog
from tests.conftest import REPO, issue_token, post_scan
from tests.test_onboarding import onboard

PAST = "2020-01-31"
FUTURE = "2999-12-31"
SCAN_A = "11111111-1111-1111-1111-111111111111"
SCAN_B = "22222222-2222-2222-2222-222222222222"


def _result(
    rule: str = "python.lang.security.audit.eval",
    uri: str = "app/views.py",
    line: int = 42,
    suppression: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule,
        "level": "error",
        "message": {"text": "eval of user input"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
    }
    if suppression is not None:
        result["suppressions"] = [suppression]
    return result


def _sarif(*results: dict[str, Any], tool: str = "Semgrep OSS") -> bytes:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": tool, "rules": []}},
                    "results": list(results),
                }
            ],
        }
    ).encode()


def _nosemgrep(**extra: Any) -> dict[str, Any]:
    return {"kind": "inSource", "justification": "input is a constant", **extra}


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="sast",
        tool_name="semgrep",
        tool_version="1.0",
        commit_sha="a91f2c7",
        branch="main",
    )


class TestReadingTheSarif:
    def test_one_suppressed_result_is_one_record(self) -> None:
        records = suppressions_from_sarif(_sarif(_result(suppression=_nosemgrep())))

        assert len(records) == 1
        record = records[0]
        assert record.tool == "Semgrep OSS"
        assert record.rule_id == "python.lang.security.audit.eval"
        assert record.file_path == "app/views.py"
        assert record.line == 42
        assert record.kind == "inSource"
        assert record.justification == "input is a constant"
        assert record.expires_at is None

    def test_an_expiry_in_the_property_bag_is_read(self) -> None:
        records = suppressions_from_sarif(
            _sarif(_result(suppression=_nosemgrep(properties={"expiry": FUTURE})))
        )

        assert str(records[0].expires_at) == FUTURE

    def test_a_rejected_suppression_is_not_a_suppression(self) -> None:
        records = suppressions_from_sarif(
            _sarif(_result(suppression=_nosemgrep(status="rejected")))
        )

        assert records == []

    def test_an_unsuppressed_result_is_not_recorded(self) -> None:
        assert suppressions_from_sarif(_sarif(_result())) == []

    def test_something_that_is_not_sarif_yields_nothing(self) -> None:
        assert suppressions_from_sarif(b"not json at all") == []
        assert suppressions_from_sarif(b'{"results": []}') == []

    def test_it_is_still_not_a_finding(self) -> None:
        """Guard for spec 05 s7: recording it changes nothing about findings."""
        result = sarif_to_findings(_sarif(_result(suppression=_nosemgrep())), _context())

        assert result.findings == []


class TestTheLaneHealthFact:
    def test_an_expired_suppression_is_named_first(self) -> None:
        result = sarif_to_findings(
            _sarif(_result(suppression=_nosemgrep(properties={"expiry": PAST}))), _context()
        )

        fact = result.warnings[0]
        assert "expired" in fact
        assert "python.lang.security.audit.eval" in fact
        assert "app/views.py:42" in fact
        assert PAST in fact

    def test_a_suppression_with_no_expiry_is_flagged(self) -> None:
        result = sarif_to_findings(_sarif(_result(suppression=_nosemgrep())), _context())

        assert "no expiry" in result.warnings[0]

    def test_a_live_expiry_raises_no_fact(self) -> None:
        result = sarif_to_findings(
            _sarif(_result(suppression=_nosemgrep(properties={"expiry": FUTURE}))), _context()
        )

        assert not any("expired" in w or "no expiry" in w for w in result.warnings)


def _raw(client: TestClient, token: str, body: bytes, scan_run_id: str = SCAN_A) -> Any:
    return client.post(
        "/api/ingest/raw",
        params={"scan_run_id": scan_run_id, "capability": "sast", "filename": "semgrep.sarif"},
        content=body,
        headers={"Authorization": f"Bearer {token}"},
    )


def _list(client: TestClient, admin_auth: dict[str, str], repo_id: str) -> Any:
    return client.get(f"/api/dashboard/repos/{repo_id}/suppressions", headers=admin_auth)


class TestRecordedAtIngest:
    def test_archiving_a_sarif_stores_one_row_and_no_finding(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        auth: dict[str, str],
        token: str,
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        repo_id = str(onboard(client, admin_auth).json()["id"])
        post_scan(client, auth)

        assert _raw(client, token, _sarif(_result(suppression=_nosemgrep()))).status_code == 200
        run_compaction()

        body = _list(client, admin_auth, repo_id).json()
        assert body["repo_full_name"] == REPO
        assert len(body["suppressions"]) == 1
        row = body["suppressions"][0]
        assert row["tool"] == "Semgrep OSS"
        assert row["capability"] == "sast"
        assert row["rule_id"] == "python.lang.security.audit.eval"
        assert row["file_path"] == "app/views.py"
        assert row["line"] == 42
        assert row["justification"] == "input is a constant"
        assert row["expires_at"] is None
        assert row["status"] == "no_expiry"
        assert catalog.query("SELECT count(*) FROM findings")[0][0] == 0

    def test_status_is_expired_or_active_by_the_date(
        self, client: TestClient, admin_auth: dict[str, str], token: str
    ) -> None:
        repo_id = str(onboard(client, admin_auth).json()["id"])
        _raw(
            client,
            token,
            _sarif(
                _result(line=1, suppression=_nosemgrep(properties={"expiry": PAST})),
                _result(line=2, suppression=_nosemgrep(properties={"expiry": FUTURE})),
            ),
        )

        rows = {r["line"]: r for r in _list(client, admin_auth, repo_id).json()["suppressions"]}
        assert rows[1]["status"] == "expired"
        assert rows[1]["expires_at"] == PAST
        assert rows[2]["status"] == "active"
        assert _list(client, admin_auth, repo_id).json()["counts"] == {
            "expired": 1,
            "no_expiry": 0,
            "active": 1,
        }

    def test_a_newer_scan_replaces_the_tools_rows(
        self, client: TestClient, admin_auth: dict[str, str], token: str
    ) -> None:
        """A pragma that was removed stops being listed."""
        repo_id = str(onboard(client, admin_auth).json()["id"])
        _raw(client, token, _sarif(_result(suppression=_nosemgrep())), scan_run_id=SCAN_A)

        _raw(client, token, _sarif(_result()), scan_run_id=SCAN_B)

        assert _list(client, admin_auth, repo_id).json()["suppressions"] == []

    def test_two_files_of_one_scan_both_count(
        self, client: TestClient, admin_auth: dict[str, str], token: str
    ) -> None:
        """CodeQL writes one SARIF per language under one scan run."""
        repo_id = str(onboard(client, admin_auth).json()["id"])
        _raw(client, token, _sarif(_result(line=1, suppression=_nosemgrep())))
        _raw(client, token, _sarif(_result(line=2, suppression=_nosemgrep())))

        assert len(_list(client, admin_auth, repo_id).json()["suppressions"]) == 2

    def test_a_rearchived_file_is_not_counted_twice(
        self, client: TestClient, admin_auth: dict[str, str], token: str
    ) -> None:
        repo_id = str(onboard(client, admin_auth).json()["id"])
        body = _sarif(_result(suppression=_nosemgrep()))
        _raw(client, token, body)
        _raw(client, token, body)

        assert len(_list(client, admin_auth, repo_id).json()["suppressions"]) == 1

    def test_a_raw_file_that_is_not_sarif_is_archived_and_records_nothing(
        self, client: TestClient, admin_auth: dict[str, str], token: str
    ) -> None:
        repo_id = str(onboard(client, admin_auth).json()["id"])

        assert _raw(client, token, b"plain text log").status_code == 200
        assert _list(client, admin_auth, repo_id).json()["suppressions"] == []

    def test_another_repositorys_rows_are_not_listed(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        mine = str(onboard(client, admin_auth).json()["id"])
        other_token = issue_token(client, "example-org/other", "sast")
        _raw(client, other_token, _sarif(_result(suppression=_nosemgrep())))

        assert _list(client, admin_auth, mine).json()["suppressions"] == []


class TestTheRoute:
    def test_an_unknown_repo_is_a_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        assert _list(client, admin_auth, "no-such-repo").status_code == 404

    def test_a_viewer_may_read_it(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth: dict[str, str]
    ) -> None:
        repo_id = str(onboard(client, admin_auth).json()["id"])

        assert _list(client, viewer_auth, repo_id).status_code == 200
