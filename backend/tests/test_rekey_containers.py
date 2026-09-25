"""Container findings keyed on their image, and the one-time move across.

`v2-package` made one CVE in twenty images one finding, and let a decision
about one image silently cover the rest. These tests pin three things: the new
identity separates images, the adapter supplies the image, and the migration
carries each decision only as far as the evidence for it reaches.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from mykronos.adapters.base import ScanContext
from mykronos.adapters.containers_trivy import normalize
from mykronos.fingerprint import (
    FINGERPRINT_CONTAINER,
    FINGERPRINT_DEPENDENCY,
    compute_finding_id,
    image_repository,
)
from mykronos.rekey_containers import rekey_containers
from mykronos.reprocess import reprocess
from mykronos.schemas import TriggeredBy
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard
from tests.test_reprocess import _set_raw_ref

APP = "192.168.0.14:5000/app:0a1b2c3d"
PG = "postgres:15"
GOSU = "usr/local/bin/gosu"


def _result(rule: str, package: str, uri: str, fixed: str = "") -> dict:
    return {
        "ruleId": rule,
        "level": "warning",
        "message": {
            "text": (
                f"Package: {package}\nInstalled Version: 1.0\nVulnerability {rule}\n"
                f"Severity: MEDIUM\nFixed Version: {fixed}\nLink: [x](https://x)"
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "ROOTPATH"},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _sarif(image: str | None, results: list[dict]) -> dict:
    # Trivy declares each rule with a short description, which becomes the
    # title; the per-result message, carrying the package lines, becomes the
    # description the adapter parses.
    rules = [
        {"id": rule, "shortDescription": {"text": f"{rule} summary"}}
        for rule in sorted({r["ruleId"] for r in results})
    ]
    run: dict = {
        "tool": {"driver": {"name": "Trivy", "version": "0.58.1", "rules": rules}},
        "results": results,
    }
    if image is not None:
        run["properties"] = {"imageName": image}
    return {"version": "2.1.0", "runs": [run]}


APP_REPORT = _sarif(
    APP,
    [
        _result("CVE-1", "libc6", "app"),
        _result("CVE-3", "stdlib", GOSU),
    ],
)
PG_REPORT = _sarif(
    PG,
    [
        _result("CVE-1", "libc6", "library/postgres"),
        _result("CVE-2", "perl-base", "library/postgres", fixed="5.40.1-6+deb13u1"),
        _result("CVE-3", "stdlib", GOSU),
    ],
)


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="containers",
        tool_name="trivy",
        tool_version="0.58.1",
        commit_sha="a91f2c7",
        branch="main",
        workflow_run_id="",
        triggered_by=TriggeredBy.PUSH,
        workspace=None,
    )


class TestImageRepository:
    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            ("postgres:15", "library/postgres"),
            ("library/postgres", "library/postgres"),
            ("ghcr.io/zaproxy/zaproxy:2.17.0", "zaproxy/zaproxy"),
            ("192.168.0.14:5000/mykronos-backend:e7087e9f", "mykronos-backend"),
            ("localhost:5000/mykronos-backend", "mykronos-backend"),
            ("hashicorp/vault:2.1.1", "hashicorp/vault"),
            ("concourse/concourse@sha256:ff7ee75c", "concourse/concourse"),
        ],
    )
    def test_tag_digest_and_registry_host_are_not_the_image(
        self, reference: str, expected: str
    ) -> None:
        assert image_repository(reference) == expected


class TestIdentity:
    def _id(self, image: str | None) -> tuple[str, str]:
        return compute_finding_id(
            repo_full_name=REPO,
            capability="containers",
            rule_id="CVE-1",
            file_path="x",
            package_name="libc6",
            image=image,
        )

    def test_the_same_package_in_two_images_is_two_findings(self) -> None:
        assert self._id(APP)[0] != self._id(PG)[0]
        assert self._id(APP)[1] == FINGERPRINT_CONTAINER

    def test_a_new_commit_tag_is_the_same_finding(self) -> None:
        """The application images are tagged with a SHA. Keying on the tag
        would re-key every container finding on every commit."""
        assert self._id(APP)[0] == self._id("192.168.0.14:5000/app:ffffffff")[0]

    def test_a_runner_that_sends_no_image_keeps_the_old_identity(self) -> None:
        """An uploader pinned to an older ref still produces `v2-package`
        ids, which is what lets the server and runners upgrade separately."""
        finding_id, version = self._id(None)
        assert version == FINGERPRINT_DEPENDENCY
        assert finding_id == compute_finding_id(
            repo_full_name=REPO,
            capability="containers",
            rule_id="CVE-1",
            file_path="x",
            package_name="libc6",
        )[0]


class TestAdapter:
    def test_every_finding_is_stamped_with_the_report_image(self) -> None:
        outcome = normalize(json.dumps(PG_REPORT).encode(), _context())
        assert {f.raw_finding_json["image"] for f in outcome.findings} == {PG}

    def test_a_report_naming_two_images_attributes_neither(self) -> None:
        mixed = _sarif(APP, [_result("CVE-1", "libc6", "app")])
        mixed["runs"].append({**_sarif(PG, [])["runs"][0]})
        outcome = normalize(json.dumps(mixed).encode(), _context())
        assert all("image" not in f.raw_finding_json for f in outcome.findings)
        assert any("names no single image" in w for w in outcome.warnings)


@pytest.fixture
def old_estate(client, admin_auth, run_compaction):
    """Two images, scanned by an uploader that did not stamp the image.

    Three decisions were recorded under the old identity:
    - CVE-1/libc6, labelled `app`: its lineage image is unambiguous.
    - CVE-2/perl-base, `no_vendor_fix`: the re-derived scan names a fix.
    - CVE-3/stdlib at a path both images ship: cannot be placed.
    """
    onboard(client, admin_auth)
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'containers')}"}
    settings = client.app.state.settings
    client.post(
        "/api/ingest/scan-run",
        json={
            "scan_run_id": "ctr-1",
            "repo_full_name": REPO,
            "capability": "containers",
            "tool_name": "trivy",
            "tool_version": "0.58.1",
            "commit_sha": "a91f2c7",
            "branch": "main",
            "triggered_by": "push",
            "started_at": "2026-08-12T09:00:00",
            "scan_status": "success",
            "finding_count": 3,
        },
        headers=auth,
    )
    old = [
        ("CVE-1", "libc6", "app"),
        ("CVE-2", "perl-base", "library/postgres"),
        ("CVE-3", "stdlib", GOSU),
    ]
    client.post(
        "/api/ingest/findings",
        json={
            "scan_run_id": "ctr-1",
            "capability": "containers",
            "findings": [
                {
                    "rule_id": rule,
                    "title": f"{package} {rule}",
                    "description": "old shape",
                    "severity": "medium",
                    "file_path": uri,
                    "package_name": package,
                    "package_version": "1.0",
                }
                for rule, package, uri in old
            ],
        },
        headers=auth,
    )
    folder = settings.raw_dir / "example-org" / "payments-api" / "ctr-1"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "trivy-app.sarif").write_text(json.dumps(APP_REPORT), encoding="utf-8")
    (folder / "trivy-estate-postgres-15.sarif").write_text(
        json.dumps(PG_REPORT), encoding="utf-8"
    )
    catalog = client.app.state.catalog
    run_compaction()
    # The pointer names one file, as the real one did: the last uploaded.
    _set_raw_ref(catalog, "ctr-1", "raw/example-org/payments-api/ctr-1/trivy-app.sarif")

    ids = {
        rule: row[0]
        for rule, row in (
            (r, catalog.query("SELECT finding_id FROM findings WHERE rule_id = ?", [r])[0])
            for r, _, _ in old
        )
    }
    until = (date.today() + timedelta(days=60)).isoformat()
    for rule in ids:
        response = client.patch(
            f"/api/dashboard/findings/{ids[rule]}/status",
            json={
                "status": "accepted_risk",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": until,
                "reason": "no Debian fix",
            },
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
    return catalog, ids


def _rows(catalog, where: str = "1=1", params: list | None = None) -> list[tuple]:
    return catalog.query(
        "SELECT rule_id, package_name, json_extract_string(raw_finding_json, '$.image'), "
        "       status, fingerprint_version, superseded_by, superseded_source, "
        "       accepted_reason_code, first_seen_at "
        f"FROM findings WHERE {where} ORDER BY rule_id, 3",
        params or [],
    )


class TestTheMigration:
    def test_a_decision_moves_only_to_the_image_it_was_made_about(
        self, client, old_estate, run_compaction
    ) -> None:
        catalog, _ids = old_estate
        settings = client.app.state.settings
        rekey_containers(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        libc = {
            row[2]: row[3]
            for row in _rows(catalog, "rule_id = 'CVE-1' AND fingerprint_version = ?",
                             [FINGERPRINT_CONTAINER])
        }
        assert libc == {APP: "accepted_risk", PG: "open"}

    def test_a_no_vendor_fix_acceptance_is_not_carried_onto_a_fixable_image(
        self, client, old_estate, run_compaction
    ) -> None:
        catalog, ids = old_estate
        settings = client.app.state.settings
        result = rekey_containers(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert result.repos[0].premise_false == [ids["CVE-2"]]
        (perl,) = _rows(catalog, "rule_id = 'CVE-2' AND fingerprint_version = ?",
                        [FINGERPRINT_CONTAINER])
        assert perl[3] == "open"

    def test_a_decision_on_a_path_two_images_share_is_stranded_not_guessed(
        self, client, old_estate, run_compaction
    ) -> None:
        catalog, ids = old_estate
        settings = client.app.state.settings
        result = rekey_containers(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        assert result.repos[0].stranded == [ids["CVE-3"]]
        statuses = {row[3] for row in _rows(
            catalog, "rule_id = 'CVE-3' AND fingerprint_version = ?", [FINGERPRINT_CONTAINER]
        )}
        assert statuses == {"open"}

    def test_old_rows_are_superseded_by_rekey_never_fixed(
        self, client, old_estate, run_compaction
    ) -> None:
        catalog, ids = old_estate
        settings = client.app.state.settings
        rekey_containers(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        old = _rows(catalog, "fingerprint_version = ?", [FINGERPRINT_DEPENDENCY])
        assert {(row[3], row[6]) for row in old} == {("superseded", "rekey")}
        (app_libc,) = catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = 'CVE-1' "
            "AND json_extract_string(raw_finding_json, '$.image') = ?",
            [APP],
        )
        (pointer,) = catalog.query(
            "SELECT superseded_by FROM findings WHERE finding_id = ?", [ids["CVE-1"]]
        )
        assert pointer[0] == app_libc[0]

    def test_the_lineage_image_keeps_its_first_sighting(
        self, client, old_estate, run_compaction
    ) -> None:
        catalog, ids = old_estate
        (first_seen,) = catalog.query(
            "SELECT first_seen_at FROM findings WHERE finding_id = ?", [ids["CVE-1"]]
        )
        settings = client.app.state.settings
        rekey_containers(catalog, client.app.state.buffer, settings.raw_dir)
        run_compaction()

        (carried,) = catalog.query(
            "SELECT first_seen_at FROM findings WHERE rule_id = 'CVE-1' "
            "AND json_extract_string(raw_finding_json, '$.image') = ?",
            [APP],
        )
        assert carried[0] == first_seen[0]

    def test_a_dry_run_writes_nothing(self, client, old_estate, run_compaction) -> None:
        catalog, _ids = old_estate
        before = _rows(catalog)
        settings = client.app.state.settings
        result = rekey_containers(
            catalog, client.app.state.buffer, settings.raw_dir, dry_run=True
        )
        run_compaction()

        assert result.repos[0].carried == 1
        assert _rows(catalog) == before


class TestReprocessReadsEveryArchivedReport:
    def test_a_second_image_is_not_retired_because_the_pointer_names_the_first(
        self, client, old_estate, run_compaction
    ) -> None:
        """`raw_output_ref` names one file of a multi-image scan. Reading
        only that file reproduced one image and retired the other's
        findings as no longer reported."""
        catalog, _ids = old_estate
        settings = client.app.state.settings
        result = reprocess(
            catalog, client.app.state.buffer, settings.raw_dir, capability="containers"
        )
        run_compaction()

        assert result.scans[0].produced == 5
        images = {row[2] for row in _rows(catalog, "status = 'open'")}
        assert images == {APP, PG}
