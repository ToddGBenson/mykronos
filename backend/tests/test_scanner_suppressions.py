"""In-repository scanner suppressions are recorded and shown (TheHub #60963).

Decision 60815, option B. A `nosemgrep`, a `checkov:skip` or any other SARIF
suppression is the repository's author answering a result. Since spec 05 §7
that result is not ingested as a finding, and that stays true. What changes is
that the answer is no longer only a line in a warning: it is kept as a
suppression row (repository, tool, rule, file, line, justification, expiry),
listed on the repository page, and one whose expiry has passed is raised as a
lane-health fact naming it.

Pinned here:

- the adapter turns a suppressed result into a suppression, never a finding;
- an expiry is read from the suppression's properties or its justification,
  and a passed one becomes a lane-health fact at the front of the warnings;
- the uploader posts the set, and an older backend refusing it never costs
  the scan run;
- the ingest route stores the set, replaces it on a rescan, and writes no
  finding;
- the read route lists every column and flags `expired` / `no expiry`;
- a suppression never changes a platform disposition (spec 05 §7).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.adapters import sarif_to_findings
from mykronos.adapters.registry import normalize_results
from mykronos.db.models import AuditLogEntry, ScannerSuppression
from mykronos.lake import Catalog
from mykronos.upload import upload
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_adapters import context, sarif
from tests.test_lake import one, set_status
from tests.test_onboarding import onboard
from tests.test_upload import RecordingClient, make_args

SCAN = "11111111-1111-1111-1111-111111111111"
FUTURE = "2099-01-01"
PAST = "2020-01-01"


def suppressed(**suppression: Any) -> dict[str, Any]:
    return {"suppressions": [{"kind": "inSource", **suppression}]}


def suppression_item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "rule_id": "python.lang.security.audit.eval",
        "file_path": "src/app.py",
        "line": 12,
        "justification": "input is a constant",
        "expires_at": None,
        "kind": "inSource",
        "status": "accepted",
    }
    item.update(overrides)
    return item


def post_suppressions(
    client: TestClient,
    auth: dict[str, str],
    items: list[dict[str, Any]],
    *,
    scan_run_id: str = SCAN,
    tool: str = "semgrep",
    branch: str = "main",
) -> Any:
    return client.post(
        "/api/ingest/suppressions",
        json={
            "scan_run_id": scan_run_id,
            "capability": "sast",
            "tool_name": tool,
            "branch": branch,
            "commit_sha": "a91f2c7",
            "suppressions": items,
        },
        headers=auth,
    )


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------


class TestAdapter:
    def test_a_suppressed_result_becomes_a_suppression_not_a_finding(self) -> None:
        result = sarif_to_findings(
            sarif(
                rule_id="CKV_DOCKER_3",
                uri="Dockerfile",
                start_line=4,
                extra_result=suppressed(justification="base image runs as root by design"),
            ),
            context(),
        )

        assert result.findings == []
        assert result.suppressions is not None
        (row,) = result.suppressions
        assert row.rule_id == "CKV_DOCKER_3"
        assert row.file_path == "Dockerfile"
        assert row.line == 4
        assert row.justification == "base image runs as root by design"
        assert row.expires_at is None
        assert row.kind == "inSource"

    def test_expiry_is_read_from_the_suppression_properties(self) -> None:
        result = sarif_to_findings(
            sarif(extra_result=suppressed(properties={"expires": FUTURE})), context()
        )
        assert result.suppressions is not None
        assert result.suppressions[0].expires_at == date(2099, 1, 1)

    def test_expiry_is_read_from_the_justification(self) -> None:
        result = sarif_to_findings(
            sarif(extra_result=suppressed(justification=f"vendor fix pending; expires {FUTURE}")),
            context(),
        )
        assert result.suppressions is not None
        assert result.suppressions[0].expires_at == date(2099, 1, 1)

    def test_a_passed_expiry_is_a_lane_health_fact_naming_it(self) -> None:
        result = sarif_to_findings(
            sarif(
                rule_id="CKV_DOCKER_3",
                uri="Dockerfile",
                start_line=4,
                extra_result=suppressed(properties={"expiry": PAST}),
            ),
            context(),
        )

        # First, because only the first warning reaches the ScanRun's detail.
        fact = result.warnings[0]
        assert "expired" in fact
        assert "CKV_DOCKER_3" in fact
        assert "Dockerfile:4" in fact
        assert PAST in fact
        # Still a suppression, still not a finding: an expired pragma is the
        # author's to renew or remove, not the platform's to overrule.
        assert result.findings == []

    def test_no_expiry_raises_no_expired_fact(self) -> None:
        result = sarif_to_findings(sarif(extra_result=suppressed()), context())
        assert not any("expired" in w for w in result.warnings)

    def test_a_rejected_suppression_is_a_finding_and_not_recorded(self) -> None:
        result = sarif_to_findings(
            sarif(extra_result=suppressed(status="rejected")), context()
        )
        assert len(result.findings) == 1
        assert result.suppressions == []

    def test_a_sarif_with_nothing_suppressed_reports_an_empty_set(self) -> None:
        """Empty, not None: "this tool reports suppressions and there are none"
        is what clears a set the repository has since removed."""
        result = sarif_to_findings(sarif(), context())
        assert result.suppressions == []

    def test_several_files_are_merged(self, tmp_path: Path) -> None:
        results = tmp_path / "codeql-results"
        results.mkdir()
        (results / "a.sarif").write_bytes(sarif(rule_id="r/a", extra_result=suppressed()))
        (results / "b.sarif").write_bytes(sarif(rule_id="r/b", extra_result=suppressed()))

        merged = normalize_results("sast", "codeql", results, context())

        assert merged.suppressions is not None
        assert sorted(s.rule_id for s in merged.suppressions) == ["r/a", "r/b"]


# --------------------------------------------------------------------------
# The uploader
# --------------------------------------------------------------------------


class TestUploader:
    def _results(self, tmp_path: Path, payload: bytes) -> Path:
        directory = tmp_path / "codeql-results"
        directory.mkdir()
        (directory / "python.sarif").write_bytes(payload)
        return directory

    def test_the_set_is_posted_with_the_scan_run(self, tmp_path: Path) -> None:
        results = self._results(
            tmp_path, sarif(extra_result=suppressed(justification=f"expires {FUTURE}"))
        )
        client = RecordingClient()

        upload(make_args(results, tmp_path), client=client)

        (body,) = client.bodies_for("/api/ingest/suppressions")
        assert body["scan_run_id"] == "run-1"
        assert body["capability"] == "sast"
        assert body["tool_name"] == "codeql"
        assert body["branch"] == "main"
        (item,) = body["suppressions"]
        assert item["rule_id"] == "py/sql-injection"
        assert item["file_path"] == "orders/query.py"
        assert item["line"] == 9
        assert item["expires_at"] == FUTURE

    def test_an_older_backend_refusing_the_set_never_costs_the_scan(
        self, tmp_path: Path
    ) -> None:
        results = self._results(tmp_path, sarif(extra_result=suppressed()))
        client = RecordingClient()
        client.fail_on.add("/api/ingest/suppressions")

        outcome = upload(make_args(results, tmp_path), client=client)

        assert outcome.scan_status.value == "success"
        final = client.bodies_for("/api/ingest/scan-run")[-1]
        assert final["scan_status"] == "success"
        assert "suppressions" not in (final.get("detail") or "")


# --------------------------------------------------------------------------
# Ingest and read
# --------------------------------------------------------------------------


class TestIngest:
    def test_one_suppression_is_one_row_and_no_finding(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        post_scan(client, auth, finding_count=0)
        response = post_suppressions(
            client, auth, [suppression_item(justification="constant input", expires_at=FUTURE)]
        )
        assert response.status_code == 200, response.text
        assert response.json()["accepted"] == 1

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            (row,) = session.execute(select(ScannerSuppression)).scalars().all()
            assert row.repo_full_name == REPO
            assert row.tool == "semgrep"
            assert row.rule_id == "python.lang.security.audit.eval"
            assert row.file_path == "src/app.py"
            assert row.line == 12
            assert row.justification == "constant input"
            assert row.expires_at == date(2099, 1, 1)
            audit = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "scanner_suppression.ingested")
            ).scalars().all()
            assert len(audit) == 1

        run_compaction()
        assert catalog.query("SELECT count(*) FROM findings")[0][0] == 0

    def test_a_rescan_replaces_the_set(self, client: TestClient, auth: dict[str, str]) -> None:
        post_suppressions(client, auth, [suppression_item(line=1), suppression_item(line=2)])
        post_suppressions(client, auth, [suppression_item(line=2)], scan_run_id="rescan")

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            rows = session.execute(select(ScannerSuppression)).scalars().all()
            assert [r.line for r in rows] == [2]

    def test_another_tool_or_branch_keeps_its_own_set(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        post_suppressions(client, auth, [suppression_item()])
        post_suppressions(client, auth, [], scan_run_id="r2", tool="checkov")
        post_suppressions(client, auth, [], scan_run_id="r3", branch="feature")

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert len(session.execute(select(ScannerSuppression)).scalars().all()) == 1

    def test_the_capability_must_be_granted(self, client: TestClient) -> None:
        other = {"Authorization": f"Bearer {issue_token(client, REPO, 'secrets')}"}
        response = post_suppressions(client, other, [suppression_item()])
        assert response.status_code == 403

    def test_another_repositorys_scan_run_is_refused(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        theirs = {
            "Authorization": f"Bearer {issue_token(client, 'example-org/other', 'sast')}"
        }
        post_scan(client, theirs, repo_full_name="example-org/other", scan_run_id="theirs")
        response = post_suppressions(client, auth, [suppression_item()], scan_run_id="theirs")
        assert response.status_code == 409


class TestRepoPage:
    def test_lists_every_column_and_flags_expiry(
        self, client: TestClient, auth: dict[str, str], admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        post_suppressions(
            client,
            auth,
            [
                suppression_item(rule_id="r/expired", line=1, expires_at=PAST),
                suppression_item(rule_id="r/forever", line=2, expires_at=None),
                suppression_item(rule_id="r/later", line=3, expires_at=FUTURE),
            ],
        )

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/suppressions", headers=admin_auth
        )
        assert response.status_code == 200, response.text
        page = response.json()
        rows = {r["rule_id"]: r for r in page["suppressions"]}

        assert set(rows) == {"r/expired", "r/forever", "r/later"}
        for row in rows.values():
            for column in ("repo_full_name", "tool", "rule_id", "file_path", "line",
                           "justification", "expires_at"):
                assert column in row
            assert row["repo_full_name"] == REPO
            assert row["tool"] == "semgrep"
        assert rows["r/expired"]["expiry_state"] == "expired"
        assert rows["r/forever"]["expiry_state"] == "no_expiry"
        assert rows["r/forever"]["expires_at"] is None
        assert rows["r/later"]["expiry_state"] == "active"

        (fact,) = page["lane_health"]
        assert "r/expired" in fact and "src/app.py:1" in fact and PAST in fact
        assert page["counts"] == {"expired": 1, "no_expiry": 1, "active": 1}

    def test_an_unknown_repo_is_a_404(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.get("/api/dashboard/repos/nope/suppressions", headers=admin_auth)
        assert response.status_code == 404


class TestDispositions:
    def test_a_suppression_never_changes_a_platform_disposition(
        self, client: TestClient, auth: dict[str, str], catalog: Catalog, run_compaction
    ) -> None:
        """Spec 05 §7: `suppressed` / `false_positive` are platform decisions a
        rescan must not overwrite. Recording the repository's own pragma for
        the same rule and file is a separate list and touches no finding."""
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        (finding_id,) = one(catalog, "SELECT finding_id FROM findings")
        set_status(catalog, finding_id, "false_positive")

        post_suppressions(
            client,
            auth,
            [suppression_item(rule_id="CWE-89", file_path="orders/query.py", line=214)],
            scan_run_id="rescan",
        )
        post_findings(client, auth, [finding_payload()], scan_run_id="rescan")
        run_compaction()

        (status,) = one(catalog, "SELECT status FROM findings")
        assert status == "false_positive"


def test_payload_round_trips_as_json() -> None:
    """The adapter's model is what the uploader sends; a date must serialise."""
    result = sarif_to_findings(
        sarif(extra_result=suppressed(properties={"expires": FUTURE})), context()
    )
    assert result.suppressions is not None
    dumped = json.loads(result.suppressions[0].model_dump_json())
    assert dumped["expires_at"] == FUTURE
