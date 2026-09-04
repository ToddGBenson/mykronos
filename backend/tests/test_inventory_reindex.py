"""Rebuilding the component inventory from archived SBOMs (B-039).

The extractor runs on Atlas evidence submission, so a repository whose SBOM was
archived before that code existed has a downloadable document and no rows in
the index. On the live deployment that was every repository: both served a
complete CycloneDX SBOM while `sbom_components` held zero rows.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import REPO
from tests.test_onboarding import onboard


def _archive_sbom(client: TestClient, components: list[dict[str, Any]]) -> str:
    """Put a CycloneDX document in the lake the way `/api/ingest/raw` does."""
    settings = client.app.state.settings
    ref = "raw/example/sbom.json"
    path = settings.datalake_dir / ref
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": components}),
        encoding="utf-8",
    )
    return ref


def _evidence(client: TestClient, ref: str) -> None:
    client.app.state.buffer.append(
        "sscs_evidence",
        [
            {
                "evidence_id": "ev-1",
                "repo_full_name": REPO,
                "commit_sha": "abc123",
                "sbom_ref": ref,
                "evaluated_at": "2026-09-01T00:00:00",
            }
        ],
    )


class TestReindex:
    def test_it_reads_an_sbom_the_index_never_saw(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        onboard(client, admin_auth)
        ref = _archive_sbom(
            client,
            [
                {"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
                {"name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3"},
            ],
        )
        _evidence(client, ref)
        run_compaction()

        body = client.post(
            "/api/dashboard/inventory/reindex",
            params={"dry_run": False},
            headers=admin_auth,
        ).json()

        assert body["sboms_found"] == 1
        assert body["sboms_read"] == 1
        assert body["components"] == 2
        assert body["repos"] == [REPO]

    def test_a_dry_run_writes_nothing(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """It writes to a table other views read, so the safe default is to
        show somebody what would happen."""
        onboard(client, admin_auth)
        _evidence(client, _archive_sbom(client, [{"name": "lodash", "version": "4.17.21"}]))
        run_compaction()

        body = client.post("/api/dashboard/inventory/reindex", headers=admin_auth).json()
        run_compaction()

        assert body["dry_run"] is True
        assert body["components"] == 1
        assert not client.app.state.catalog.all_files("sbom_components")

    def test_it_is_idempotent(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """Safe to run repeatedly: the SBOM's own ref is the natural key for
        'we have already read that document'."""
        onboard(client, admin_auth)
        _evidence(client, _archive_sbom(client, [{"name": "lodash", "version": "4.17.21"}]))
        run_compaction()

        client.post(
            "/api/dashboard/inventory/reindex",
            params={"dry_run": False},
            headers=admin_auth,
        )
        run_compaction()
        second = client.post(
            "/api/dashboard/inventory/reindex",
            params={"dry_run": False},
            headers=admin_auth,
        ).json()

        assert second["sboms_read"] == 0
        assert second["already_indexed"] == 1
        assert second["components"] == 0

    def test_a_pruned_file_is_counted_not_raised(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """Retention prunes archived bytes while the evidence row survives, so
        a missing file is expected rather than exceptional."""
        onboard(client, admin_auth)
        _evidence(client, "raw/example/gone.json")
        run_compaction()

        body = client.post(
            "/api/dashboard/inventory/reindex",
            params={"dry_run": False},
            headers=admin_auth,
        ).json()

        assert body["unreadable"] == 1
        assert body["sboms_read"] == 0

    def test_a_viewer_is_refused(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        assert (
            client.post(
                "/api/dashboard/inventory/reindex", headers=viewer_auth
            ).status_code
            == 403
        )


class TestLatestOnly:
    def test_it_indexes_the_newest_sbom_per_repository(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """177 archived SBOMs across two repositories on the live estate.

        Indexing all of them would put every version a library has ever been
        at into a table whose whole purpose is answering "what do we run
        *now*", so a lookup would return builds that shipped months ago.
        """
        onboard(client, admin_auth)
        old_ref = "raw/example/sbom-old.json"
        new_ref = "raw/example/sbom-new.json"
        settings = client.app.state.settings
        for ref, version in ((old_ref, "4.17.20"), (new_ref, "4.17.21")):
            path = settings.datalake_dir / ref
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [{"name": "lodash", "version": version}],
                    }
                ),
                encoding="utf-8",
            )
        client.app.state.buffer.append(
            "sscs_evidence",
            [
                {
                    "evidence_id": "ev-old",
                    "repo_full_name": REPO,
                    "commit_sha": "old",
                    "sbom_ref": old_ref,
                    "evaluated_at": "2026-01-01T00:00:00",
                },
                {
                    "evidence_id": "ev-new",
                    "repo_full_name": REPO,
                    "commit_sha": "new",
                    "sbom_ref": new_ref,
                    "evaluated_at": "2026-09-01T00:00:00",
                },
            ],
        )
        run_compaction()

        body = client.post(
            "/api/dashboard/inventory/reindex",
            params={"dry_run": False},
            headers=admin_auth,
        ).json()

        assert body["sboms_found"] == 1, "one document per repository, the newest"
        assert body["components"] == 1
        run_compaction()
        versions = client.app.state.catalog.query(
            "SELECT DISTINCT package_version FROM sbom_components"
        )
        assert [v[0] for v in versions] == ["4.17.21"]
