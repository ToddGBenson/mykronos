"""The component inventory and incident mode (spec 29 §1, §1.4, §2).

The SBOM has been generated on every Atlas run since spec 07 and only ever
archived — downloadable per repository, queryable across none of them. So the
one question that matters at two in the morning could not be answered about
data the platform had already collected.

The test that matters most is `test_a_repository_with_no_sbom_is_not_reported
_as_clean`. Converting an absence of data into a statement of safety is the
single worst thing this view could do, and it is the thing it would do by
default.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import blast_radius, incident, inventory
from mykronos.lake.catalog import Catalog
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


def cyclonedx(*components: dict[str, Any]) -> dict[str, Any]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}


def component(
    name: str = "lodash", version: str = "4.17.21", **overrides: Any
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "version": version,
        "purl": f"pkg:npm/{name}@{version}",
        "licenses": [{"license": {"id": "MIT"}}],
    }
    payload.update(overrides)
    return payload


def seed_components(
    client: TestClient,
    run_compaction: Any,
    sbom: dict[str, Any],
    repo_full_name: str = REPO,
    commit_sha: str = "a" * 40,
) -> int:
    count = inventory.record(
        client.app.state.buffer,  # type: ignore[attr-defined]
        sbom,
        repo_full_name=repo_full_name,
        commit_sha=commit_sha,
        scan_run_id="run-1",
    )
    run_compaction()
    return count


class TestExtraction:
    def test_one_row_per_resolved_component(self) -> None:
        rows = inventory.rows_from_sbom(
            cyclonedx(component(), component("axios", "1.6.0")),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert {r["package_name"] for r in rows} == {"lodash", "axios"}
        assert rows[0]["ecosystem"] == "npm"

    def test_the_id_is_stable_across_scans(self) -> None:
        """A dependency that has not changed keeps its row and its
        `first_seen_at`, so "when did we first take this version" is
        answerable without a second table."""
        first = inventory.component_id(REPO, "npm", "lodash", "4.17.21")
        second = inventory.component_id(REPO, "npm", "lodash", "4.17.21")

        assert first == second

    def test_a_different_version_is_a_different_row(self) -> None:
        """Routine in npm, and "we have three copies and one is patched" is
        the actual state a single row would hide."""
        rows = inventory.rows_from_sbom(
            cyclonedx(component(version="4.17.20"), component(version="4.17.21")),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert len({r["component_id"] for r in rows}) == 2

    def test_the_same_component_twice_in_one_document_is_one_row(self) -> None:
        rows = inventory.rows_from_sbom(
            cyclonedx(component(), component()),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert len(rows) == 1

    def test_a_nameless_component_is_dropped(self) -> None:
        """It cannot be matched against a CVE, joined to another repository,
        or shown to anybody — and stored as an empty string it would group
        with every other one."""
        rows = inventory.rows_from_sbom(
            cyclonedx({"version": "1.0"}, component()),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert len(rows) == 1

    def test_direct_is_null_when_the_sbom_does_not_say(self) -> None:
        """Not `false`. "Syft did not say" and "this is transitive" are
        different facts, and the second is a claim this platform cannot make
        from a document that does not contain it."""
        rows = inventory.rows_from_sbom(
            cyclonedx(component()),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert rows[0]["direct"] is None

    def test_direct_is_read_where_it_is_stated(self) -> None:
        rows = inventory.rows_from_sbom(
            cyclonedx(component(relationship="direct")),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert rows[0]["direct"] is True

    def test_licenses_ride_along(self) -> None:
        """Spec 22 already computed these and aggregated them away into
        counts. "Which repository has the GPL one" is a question the aggregate
        cannot answer."""
        rows = inventory.rows_from_sbom(
            cyclonedx(component()),
            repo_full_name=REPO,
            commit_sha="a" * 40,
            scan_run_id="run-1",
        )

        assert json.loads(rows[0]["license_ids_json"]) == ["mit"]

    def test_an_spdx_document_reads_too(self) -> None:
        """Both dialects, because `AtlasConfig.sbom_format` lets a repository
        choose one."""
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "licenseDeclared": "Apache-2.0",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.31.0",
                        }
                    ],
                }
            ],
        }

        rows = inventory.rows_from_sbom(
            spdx, repo_full_name=REPO, commit_sha="a" * 40, scan_run_id="run-1"
        )

        assert rows[0]["package_name"] == "requests"
        assert rows[0]["ecosystem"] == "pypi"

    def test_a_document_with_nothing_in_it_is_not_a_crash(self) -> None:
        assert (
            inventory.rows_from_sbom(
                {}, repo_full_name=REPO, commit_sha="a" * 40, scan_run_id="run-1"
            )
            == []
        )


class TestQuerying:
    def test_a_package_name_finds_the_repository(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        seed_components(client, run_compaction, cyclonedx(component()))

        found = inventory.exposure(catalog, "lodash")

        assert [e.repo_full_name for e in found] == [REPO]
        assert found[0].versions == ["4.17.21"]

    def test_the_versions_are_listed_not_collapsed(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """"We have three copies and one is patched" is the actual state."""
        seed_components(
            client,
            run_compaction,
            cyclonedx(component(version="4.17.20"), component(version="4.17.21")),
        )

        assert inventory.exposure(catalog, "lodash")[0].versions == [
            "4.17.20",
            "4.17.21",
        ]

    def test_a_purl_matches_exactly_and_says_so(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        seed_components(client, run_compaction, cyclonedx(component()))

        found = inventory.exposure(catalog, "pkg:npm/lodash@4.17.21")

        assert found[0].matched_by == "purl"

    def test_a_purl_without_a_version_still_matches(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """Callers paste both forms, and an exact match on the bare purl would
        find nothing while looking like a definitive answer."""
        seed_components(client, run_compaction, cyclonedx(component()))

        assert inventory.exposure(catalog, "pkg:npm/lodash")

    def test_a_name_match_says_it_was_a_name_match(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """Matching on name is a guess that is usually right. Reported rather
        than smoothed over — a package renamed upstream matches by name and
        not by purl."""
        seed_components(client, run_compaction, cyclonedx(component()))

        assert inventory.exposure(catalog, "lodash")[0].matched_by == "name"

    def test_the_observation_date_rides_on_the_row(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """Stale data presented as current is the failure mode this view could
        most easily have."""
        seed_components(client, run_compaction, cyclonedx(component()))

        found = inventory.exposure(catalog, "lodash")[0]

        assert found.observed_at is not None
        assert found.commit_sha == "a" * 40

    def test_an_empty_query_returns_nothing(self, catalog: Catalog) -> None:
        assert inventory.exposure(catalog, "   ") == []


class TestBlastRadiusFromTheGraph:
    def test_a_package_in_a_repository_counts_without_a_finding(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """D-069 counted findings because package names were unavailable. The
        measure spec 19 §2.4 actually asked for is a fact about dependence,
        not about complaints."""
        seed_components(client, run_compaction, cyclonedx(component()))

        assert inventory.dependents(catalog, "lodash") == 1
        assert blast_radius.build(catalog)["lodash"] == 1

    def test_the_source_is_published(
        self, client: TestClient, catalog: Catalog, run_compaction
    ) -> None:
        """A reader who cannot tell which population produced a count cannot
        tell whether a zero means "nothing depends on this" or "nothing has
        complained about it yet"."""
        seed_components(client, run_compaction, cyclonedx(component()))

        assert blast_radius.resolution(catalog) in {"graph", "mixed"}

    def test_a_portfolio_with_no_sbom_still_answers_from_findings(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """The fallback stays. A repository with no SBOM is not a repository
        with no dependencies."""
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-1337", package_name="lodash", symbol="x")],
        )
        run_compaction()

        assert blast_radius.build(catalog).get("lodash") == 1
        assert blast_radius.resolution(catalog) == "findings"

    def test_the_larger_of_the_two_wins(
        self, client: TestClient, auth, catalog: Catalog, run_compaction
    ) -> None:
        """A portfolio part-way through adopting Atlas has both kinds of
        repository at once, and picking one source outright would either drop
        the SBOM-less repositories or throw the graph away."""
        seed_components(client, run_compaction, cyclonedx(component()))
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-1337", package_name="lodash", symbol="x")],
        )
        run_compaction()

        assert blast_radius.build(catalog)["lodash"] >= 1
        assert blast_radius.resolution(catalog) == "mixed"


class TestIncidentMode:
    def _view(self, client: TestClient, query: str) -> Any:
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            return incident.look_up(
                client.app.state.catalog,  # type: ignore[attr-defined]
                session,
                query,
            )

    def test_a_repository_with_no_sbom_is_not_reported_as_clean(
        self, client: TestClient, admin_auth
    ) -> None:
        """The single worst thing this view could do, and the thing it would
        do by default. An absence of data is not a statement of safety."""
        onboard(client, admin_auth)

        view = self._view(client, "lodash")

        assert view.clear == []
        assert REPO in view.not_checked

    def test_a_scanned_repository_with_no_match_is_clear(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component("axios", "1.6.0")))

        view = self._view(client, "lodash")

        assert view.clear == [REPO]
        assert view.not_checked == []

    def test_it_finds_the_affected_repository(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))

        view = self._view(client, "lodash")

        assert [a.repo_full_name for a in view.affected] == [REPO]
        assert view.affected[0].versions == ["4.17.21"]

    def test_exposure_and_a_finding_are_different_facts(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A repository can contain a vulnerable package with no finding,
        because its last scan predates the advisory."""
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))

        view = self._view(client, "lodash")

        assert view.affected[0].open_findings == 0

    def test_an_open_finding_shows_beside_the_exposure(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CVE-2026-1337",
                    package_name="lodash",
                    severity="critical",
                    symbol="x",
                )
            ],
        )
        run_compaction()

        view = self._view(client, "lodash")

        assert view.affected[0].open_findings == 1
        assert view.affected[0].highest_severity == "critical"

    def test_a_cve_resolves_through_the_findings_that_cite_it(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A CVE is not an inventory key — the inventory holds packages."""
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-1337", package_name="lodash", symbol="x")],
        )
        run_compaction()

        view = self._view(client, "CVE-2026-1337")

        assert view.kind == "cve"
        assert [a.repo_full_name for a in view.affected] == [REPO]

    def test_a_cve_nothing_has_reported_says_so_rather_than_all_clear(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """Reporting every repository as unaffected by a CVE the platform
        simply cannot recognise is the same error as calling an unscanned
        repository clean."""
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))

        view = self._view(client, "CVE-2099-9999")

        assert view.affected == []

    def test_worst_first(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """Read under time pressure. An open finding outranks mere
        presence."""
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))
        seed_components(
            client, run_compaction, cyclonedx(component()), repo_full_name="acme/other"
        )
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-1337", package_name="lodash", symbol="x")],
        )
        run_compaction()

        view = self._view(client, "lodash")

        assert view.affected[0].repo_full_name == REPO

    def test_the_note_states_what_an_sbom_cannot_see(self, client: TestClient) -> None:
        note = incident.as_dict(self._view(client, "lodash"))["note"]

        assert "vendored" in note
        assert "not a clean result" in note


class TestTheEndpoint:
    def test_it_answers(self, client: TestClient, admin_auth, run_compaction) -> None:
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))

        body = client.get(
            "/api/dashboard/incident", params={"q": "lodash"}, headers=admin_auth
        ).json()

        assert body["kind"] == "package"
        assert body["affected"][0]["repo_full_name"] == REPO

    def test_an_empty_query_is_refused(
        self, client: TestClient, admin_auth
    ) -> None:
        r = client.get(
            "/api/dashboard/incident", params={"q": ""}, headers=admin_auth
        )

        assert r.status_code == 422

    def test_a_viewer_may_read_it(
        self, client: TestClient, admin_auth, viewer_auth, run_compaction
    ) -> None:
        """A read, and the person who has just been paged is not always an
        admin."""
        onboard(client, admin_auth)
        seed_components(client, run_compaction, cyclonedx(component()))

        r = client.get(
            "/api/dashboard/incident", params={"q": "lodash"}, headers=viewer_auth
        )

        assert r.status_code == 200


class TestIngestion:
    """The default `auth` fixture grants `sast` only, so every test here mints
    its own `atlas` token. A capability a token does not hold is a 403, which
    reads here as "the endpoint refused the payload" and would make these pass
    or fail for entirely the wrong reason."""

    @pytest.fixture
    def atlas_auth(self, client: TestClient) -> dict[str, str]:
        from tests.conftest import issue_token

        return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}

    def test_the_atlas_submission_records_the_inventory(
        self, client: TestClient, auth, atlas_auth, catalog: Catalog, run_compaction
    ) -> None:
        """A third read of a file the runner produced and this platform
        already archived — no new upload, no template change."""
        post_scan(client, atlas_auth, capability="atlas", tool_name="osv-scanner")
        archived = client.post(
            "/api/ingest/raw",
            params={
                "scan_run_id": "atlas-1",
                "capability": "atlas",
                "filename": "sbom.json",
            },
            content=json.dumps(cyclonedx(component())).encode(),
            headers=atlas_auth,
        )
        assert archived.status_code == 200

        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 1}],
                "sbom_ref": archived.json()["raw_output_ref"],
            },
            headers=atlas_auth,
        )

        assert response.status_code == 200
        assert response.json()["components_recorded"] == 1
        run_compaction()
        assert catalog.count("sbom_components") == 1

    def test_a_submission_with_no_sbom_still_records_evidence(
        self, client: TestClient, atlas_auth
    ) -> None:
        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 1}],
            },
            headers=atlas_auth,
        )

        assert response.status_code == 200
        assert response.json()["components_recorded"] == 0

    def test_an_unreadable_sbom_does_not_cost_the_trust_score(
        self, client: TestClient, atlas_auth
    ) -> None:
        """The evidence row is what a release gate reads. Losing it because an
        SBOM was truncated in transit would trade the number that matters for
        a convenience index."""
        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 4, "critical_vulns": 1}],
                "sbom_ref": "raw/nope/does-not-exist.json",
            },
            headers=atlas_auth,
        )

        assert response.status_code == 200
        assert response.json()["trust_score"] is not None
        assert response.json()["components_recorded"] == 0

    def test_a_ref_pointing_outside_the_archive_is_refused(
        self, client: TestClient, atlas_auth
    ) -> None:
        """The value arrives from a workflow, and a caller who can post
        evidence must not be able to name a file outside the lake."""
        response = client.post(
            "/api/ingest/atlas",
            json={
                "commit_sha": "a" * 40,
                "ecosystems": [{"ecosystem": "npm", "dependency_count": 1}],
                "sbom_ref": "../../../../etc/passwd",
            },
            headers=atlas_auth,
        )

        assert response.status_code == 200
        assert response.json()["components_recorded"] == 0
