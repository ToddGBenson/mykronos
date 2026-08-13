"""Atlas — supply-chain trust scoring and evidence (spec 07)."""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from mykronos.atlas import evidence_id, score
from mykronos.db.models import CapabilityConfig
from mykronos.schemas import EcosystemEvidence
from tests.conftest import REPO, issue_token
from tests.test_onboarding import onboard


@pytest.fixture
def atlas_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}


def eco(**overrides) -> EcosystemEvidence:
    payload = {"ecosystem": "npm", "dependency_count": 100}
    payload.update(overrides)
    return EcosystemEvidence(**payload)


def submission(**overrides) -> dict:
    payload = {
        "commit_sha": "a91f2c7",
        "ecosystems": [{"ecosystem": "npm", "dependency_count": 100}],
        "provenance": {"builder": "github-actions", "run_id": "9900123"},
    }
    payload.update(overrides)
    return payload


def post(client, auth, **overrides):
    return client.post("/api/ingest/atlas", json=submission(**overrides), headers=auth)


class TestTrustScore:
    def test_a_clean_tree_scores_100(self) -> None:
        assert score([eco()]).trust_score == 100

    def test_vulnerabilities_are_curved_not_summed(self) -> None:
        """20 × log2(1 + n). Five criticals used to floor the score at 0 — and
        so did five hundred (spec 07 §5)."""
        five = score([eco(critical_vulns=5)])
        fifty = score([eco(critical_vulns=50)])

        assert five.trust_score > 0, "five criticals should not floor the score"
        assert fifty.trust_score < five.trust_score, "ranking must be preserved"

    def test_the_raw_score_survives_the_floor(self) -> None:
        """Two repos both displaying 0 still need an order."""
        bad = score([eco(critical_vulns=500, high_vulns=500)])
        worse = score([eco(critical_vulns=5000, high_vulns=5000)])

        assert bad.trust_score == worse.trust_score == 0
        assert worse.raw_trust_score < bad.raw_trust_score
        assert worse.floored is True

    def test_severity_is_weighted(self) -> None:
        assert (
            score([eco(critical_vulns=4)]).trust_score
            < score([eco(high_vulns=4)]).trust_score
            < score([eco(medium_vulns=4)]).trust_score
        )

    def test_floating_versions_are_penalised_proportionally(self) -> None:
        half = score([eco(dependency_count=100, floating_versions=50)])
        all_of_them = score([eco(dependency_count=100, floating_versions=100)])

        assert half.trust_score == 95
        assert all_of_them.trust_score == 90

    def test_ratio_terms_cannot_saturate(self) -> None:
        """A ratio is already bounded at 1, which is why it stays linear."""
        worst = score(
            [eco(dependency_count=100, floating_versions=100, stale_dependencies=100)]
        )

        assert worst.trust_score == 80

    def test_packages_with_no_maintenance_data_leave_the_denominator(self) -> None:
        """spec 07 §8: excluding them beats counting them as fresh or as stale,
        because either default is a claim the data does not support."""
        known = score(
            [
                eco(
                    dependency_count=100,
                    stale_dependencies=10,
                    maintenance_data_available_for=20,
                )
            ]
        )
        assumed = score([eco(dependency_count=100, stale_dependencies=10)])

        # 10/20 stale is a much worse signal than 10/100.
        assert known.trust_score < assumed.trust_score

    def test_a_monorepo_sums_across_ecosystems(self) -> None:
        """spec 07 §8 — one row per commit, counts summed."""
        combined = score(
            [
                eco(ecosystem="npm", dependency_count=100, critical_vulns=1),
                eco(ecosystem="pypi", dependency_count=50, high_vulns=2),
            ]
        )

        assert combined.dependency_count == 150
        assert combined.vulnerable_dependency_count == 3

    def test_the_arithmetic_is_recorded(self) -> None:
        result = score([eco(critical_vulns=3)])
        term = next(t for t in result.terms if t["key"] == "critical_vulnerabilities")

        assert "log2(1 + 3)" in term["detail"]

    def test_it_is_reproducible(self) -> None:
        """spec 07 §7 makes this an acceptance criterion."""
        counts = [eco(critical_vulns=2, high_vulns=7, dependency_count=213)]

        assert score(counts) == score(counts)

    def test_the_id_is_derived_from_repo_and_commit(self) -> None:
        assert evidence_id(REPO, "abc") == evidence_id(REPO, "abc")
        assert evidence_id(REPO, "abc") != evidence_id(REPO, "def")



class TestAScanThatResolvedNothing:
    """Spec 07 §5a. TheHub scanned clean for weeks: osv-scanner was told not to
    resolve transitively, its manifests declare ranges rather than pins, so it
    resolved zero dependencies — and zero vulnerabilities out of zero packages
    took every penalty term to zero and scored a perfect 100. The failure and
    the ideal produced the same number."""

    def test_no_dependencies_scores_null_not_100(self) -> None:
        assessment = score([eco(dependency_count=0)])

        assert assessment.trust_score is None
        assert assessment.raw_trust_score is None
        assert assessment.assessed is False

    def test_no_ecosystems_at_all_scores_null(self) -> None:
        assert score([]).trust_score is None

    def test_it_says_why(self) -> None:
        """The reason has to travel with the row: "not assessed" on a dashboard
        with no explanation is the kind of thing people route around."""
        terms = score([]).terms

        assert [t["key"] for t in terms] == ["not_assessed"]
        assert "no dependencies" in terms[0]["detail"].lower()

    def test_a_real_scan_is_unaffected(self) -> None:
        assessment = score([eco(dependency_count=100)])

        assert assessment.trust_score == 100
        assert assessment.assessed is True

    def test_the_null_reaches_the_lake(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[{"ecosystem": "npm", "dependency_count": 0}],
        )
        run_compaction()

        rows = catalog.query("SELECT trust_score, raw_trust_score FROM sscs_evidence")
        assert rows == [(None, None)]

    def test_it_is_not_reported_as_below_the_minimum(
        self, client, admin_auth, atlas_auth
    ) -> None:
        """A release gate that blocks on an unassessed scan blocks on a
        measurement that never happened. It has to say "unknown", not "bad" —
        the same distinction the score itself is drawing."""
        onboard(client, admin_auth)

        body = post(
            client,
            atlas_auth,
            ecosystems=[{"ecosystem": "npm", "dependency_count": 0}],
        ).json()

        assert body["trust_score"] is None
        assert body["below_minimum"] is False

    def test_oracle_does_not_credit_it(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """A repo with no assessed supply chain must look the same to Oracle as
        a repo that has never run Atlas at all."""
        from mykronos.config import get_settings
        from mykronos.oracle.engine import OracleEngine
        from mykronos.oracle.policy import load_policy

        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[{"ecosystem": "npm", "dependency_count": 0}],
        )
        run_compaction()

        engine = OracleEngine(catalog, load_policy(get_settings().oracle_policy_path))
        assert engine._sscs_trust(REPO) is None

    def test_maturity_does_not_count_it_as_evidence(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        from mykronos.maturity import sscs_evidence_count
        from mykronos.schemas import utcnow

        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[{"ecosystem": "npm", "dependency_count": 0}],
        )
        run_compaction()

        assert sscs_evidence_count(catalog, REPO, utcnow()) == 0

    def test_the_trend_line_breaks_rather_than_coasting(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """Carrying the last real score forward would draw a flat healthy line
        over the exact period nobody was measuring."""
        from mykronos.maturity import trend_series

        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[{"ecosystem": "npm", "dependency_count": 0}],
        )
        run_compaction()

        assert all(point.trust_score is None for point in trend_series(catalog, REPO))


class TestIngestion:
    def test_evidence_is_written(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        response = post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 1}
            ],
        )
        run_compaction()

        assert response.status_code == 200, response.text
        rows = catalog.query(
            "SELECT dependency_count, vulnerable_dependency_count, trust_score "
            "FROM sscs_evidence"
        )
        assert rows == [(100, 1, 80)]

    def test_the_score_is_computed_server_side(
        self, client, admin_auth, atlas_auth
    ) -> None:
        """Not accepted from the runner: spec 07 §7 requires reproducibility,
        and a score the workflow calculates drifts between action versions."""
        onboard(client, admin_auth)
        payload = submission()
        payload["trust_score"] = 100

        response = client.post("/api/ingest/atlas", json=payload, headers=atlas_auth)

        assert response.status_code == 422

    def test_rescanning_a_commit_upserts(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()
        post(client, atlas_auth)
        run_compaction()

        assert catalog.count("sscs_evidence") == 1

    def test_a_release_adds_its_sbom_to_the_commits_existing_row(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """spec 07 §7: exactly one evidence row per tagged release, and the
        push scan of the same commit came first."""
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        run_compaction()

        assert catalog.count("sscs_evidence") == 1
        assert catalog.query("SELECT tag_or_release, sbom_ref FROM sscs_evidence") == [
            ("v2.1.0", "raw/sbom.json")
        ]

    def test_a_later_push_scan_does_not_blank_the_release_evidence(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """The SBOM belongs to the commit, and a rescan of that commit does not
        un-release it."""
        onboard(client, admin_auth)
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        run_compaction()
        post(client, atlas_auth)
        run_compaction()

        assert catalog.query("SELECT tag_or_release, sbom_ref FROM sscs_evidence") == [
            ("v2.1.0", "raw/sbom.json")
        ]

    def test_both_land_in_one_compaction_window_without_loss(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        """The D-020 failure mode, on this table: the push row carries no SBOM
        and would win the batch collapse if the patch columns were not
        declared."""
        onboard(client, admin_auth)
        post(client, atlas_auth, tag_or_release="v2.1.0", sbom_ref="raw/sbom.json")
        post(client, atlas_auth)
        run_compaction()

        assert catalog.query("SELECT sbom_ref FROM sscs_evidence") == [
            ("raw/sbom.json",)
        ]

    def test_provenance_and_ecosystem_detail_are_kept(
        self, client, admin_auth, atlas_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 100, "critical_vulns": 1},
                {"ecosystem": "pypi", "dependency_count": 40, "high_vulns": 2},
            ],
        )
        run_compaction()

        provenance, ecosystems = catalog.query(
            "SELECT provenance_json, ecosystems_json FROM sscs_evidence"
        )[0]
        assert json.loads(provenance)["run_id"] == "9900123"
        detail = json.loads(ecosystems)
        assert [e["ecosystem"] for e in detail["ecosystems"]] == ["npm", "pypi"]
        assert detail["score_terms"], "the arithmetic travels with the row"

    def test_below_minimum_is_reported_even_when_not_blocking(
        self, client, admin_auth, atlas_auth
    ) -> None:
        """So the workflow log says what would have happened."""
        repo_id = onboard(client, admin_auth).json()["id"]
        with client.app.state.db.session() as session:
            session.add(
                CapabilityConfig(
                    repo_onboarding_id=repo_id,
                    capability="atlas",
                    config_json={"min_trust_score": 95},
                )
            )

        body = post(
            client,
            atlas_auth,
            ecosystems=[
                {"ecosystem": "npm", "dependency_count": 10, "critical_vulns": 2}
            ],
        ).json()

        assert body["below_minimum"] is True
        assert body["blocking"] is False

    def test_the_atlas_grant_is_required(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        other = {
            "Authorization": f"Bearer {issue_token(client, 'example-org/other', 'sast')}"
        }

        assert post(client, other).status_code == 403

    def test_the_repo_comes_from_the_token(self, client, admin_auth, atlas_auth) -> None:
        onboard(client, admin_auth)
        payload = submission()
        payload["repo_full_name"] = "someone/else"

        response = client.post("/api/ingest/atlas", json=payload, headers=atlas_auth)

        assert response.status_code == 422


class TestTheWorkflow:
    """The rendered workflow, not the scoring.

    Both bugs here were invisible until the capability first ran for real:
    the SBOM step had never executed, and when it finally did it documented
    the wrong software.
    """

    @pytest.fixture
    def rendered(self) -> str:
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)
        return library.render(
            "atlas",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
        ).content

    def test_the_sbom_documents_the_repo_not_the_runner(self, rendered: str) -> None:
        """`cyclonedx-py environment` documents the interpreter the workflow
        is running in — which by that point holds mykronos and osv-scanner,
        because the previous step installed them. It had never looked at the
        repository, and on a polyglot repo it saw only Python.

        It survived review because it ran only on releases, and no onboarded
        repository tags releases, so it had never executed once.
        """
        # Comment lines stripped: the template explains why the old tool was
        # wrong, and that explanation names it. Asserting on the whole file
        # would fail on the documentation rather than on the behaviour.
        commands = "\n".join(
            line for line in rendered.splitlines() if not line.lstrip().startswith("#")
        )

        assert "cyclonedx-py" not in commands
        assert "cyclonedx-bom" not in commands
        assert "anchore/syft" in commands
        assert "scan dir:/src" in commands

    def test_the_sbom_tool_is_pinned(self, rendered: str) -> None:
        """Evidence produced by an unknown version of the tool is worth less
        than none."""
        assert "anchore/syft:latest" not in rendered
        assert re.search(r"anchore/syft:v\d+\.\d+\.\d+", rendered)

    def test_an_empty_sbom_is_not_archived(self, rendered: str) -> None:
        """A repo pinning nothing has no resolved dependency set to record.
        Archiving an empty document would show an SBOM present for a file
        describing no software."""
        assert "COMPONENTS" in rendered
        assert "rm -f sbom.json" in rendered

    def test_the_archive_step_keys_on_the_file_not_the_event(
        self, rendered: str
    ) -> None:
        """Two copies of the same condition is how they come to disagree, and
        the failure mode is a curl against a file that is not there."""
        assert "hashFiles('sbom.json')" in rendered

    def test_the_sbom_runs_off_releases_too(self, rendered: str) -> None:
        """spec 07 §2 asks for one per tag. Stopping there meant repositories
        that never tag produced none at all, and their evidence showed no SBOM
        with nothing to say it was waiting."""
        assert "refs/heads/main" in rendered
        assert "github.event_name == 'release'" in rendered

    @pytest.mark.parametrize(
        ("configured", "expected"),
        [("cyclonedx", "cyclonedx-json"), ("spdx", "spdx-json")],
    )
    def test_both_configured_formats_map_to_a_real_syft_format(
        self, configured: str, expected: str
    ) -> None:
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)
        rendered = library.render(
            "atlas",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
            config={"sbom_format": configured},
        ).content

        assert f'FORMAT="{configured}"' in rendered
        assert expected in rendered


OSV_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "osv-scanner", "rules": [
                {"id": "GHSA-5p4m-2wfm-xmqj",
                 "shortDescription": {"text": "js-yaml quadratic CPU"}}
            ]}},
            "results": [
                {
                    "ruleId": "GHSA-5p4m-2wfm-xmqj",
                    "level": "error",
                    "message": {
                        "text": "Package 'js-yaml@4.3.0' is vulnerable to "
                                "'GHSA-5p4m-2wfm-xmqj'."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "file:///home/runner/work/mykronos/"
                                           "mykronos/frontend/package-lock.json"
                                }
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


class TestTheOsvAdapter:
    """Two defects the first real Atlas scan exposed."""

    def _normalize(self, document=None, workspace=None):
        import json as _json

        from mykronos.adapters.atlas_osv import normalize
        from mykronos.adapters.base import ScanContext

        context = ScanContext(
            repo_full_name="ToddGBenson/mykronos",
            capability="atlas",
            tool_name="osv-scanner",
            tool_version="1.0",
            commit_sha="a" * 40,
            branch="main",
            workspace=workspace,
        )
        return normalize(
            _json.dumps(document or OSV_SARIF).encode(), context
        )

    def test_the_package_is_extracted_from_the_message(self) -> None:
        """osv-scanner puts it nowhere structured, and Patchwork's dependency
        fixer keys on exactly these two fields (spec 08 §4). Null means every
        dependency finding falls through to `triaged` and no fix is offered —
        the capability that finds vulnerable dependencies producing findings
        the one that fixes them cannot read."""
        finding = self._normalize().findings[0]

        assert finding.package_name == "js-yaml"
        assert finding.package_version == "4.3.0"

    def test_a_scoped_npm_name_keeps_its_scope(self) -> None:
        """`@babel/traverse@7.0.0` — the name contains an `@`, so the version
        comes from the last one, not the first."""
        document = json.loads(json.dumps(OSV_SARIF))
        document["runs"][0]["results"][0]["message"]["text"] = (
            "Package '@babel/traverse@7.23.2' is vulnerable to 'GHSA-x'."
        )

        finding = self._normalize(document).findings[0]

        assert finding.package_name == "@babel/traverse"
        assert finding.package_version == "7.23.2"

    def test_the_runner_path_is_stripped(self) -> None:
        """`home/runner/work/<repo>/<repo>/...` is not clickable, and finding
        identity derives from the path — so a runner layout change would
        reopen every finding as new work nobody did."""
        finding = self._normalize().findings[0]

        assert finding.file_path == "frontend/package-lock.json"

    def test_an_explicit_workspace_is_preferred(self) -> None:
        from pathlib import Path

        finding = self._normalize(
            workspace=Path("/home/runner/work/mykronos/mykronos")
        ).findings[0]

        assert finding.file_path == "frontend/package-lock.json"

    def test_an_unparseable_message_warns_rather_than_guessing(self) -> None:
        """A silent miss here shows up much later as Patchwork offering no
        fixes, which is a hard symptom to trace back to a message format."""
        document = json.loads(json.dumps(OSV_SARIF))
        document["runs"][0]["results"][0]["message"]["text"] = "something else"

        outcome = self._normalize(document)

        assert outcome.findings[0].package_name is None
        assert any("package specifier" in w for w in outcome.warnings)
