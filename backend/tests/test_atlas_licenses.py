"""License compliance and denylists — spec 22 §1, §3.

Syft has captured license metadata for every SBOM this platform has ever
generated and nothing read it. These are the two things that now do: a
scoring term, and findings for what a repository has banned outright.
"""

from __future__ import annotations

import pytest

from mykronos import atlas, atlas_counts, atlas_sbom
from mykronos.capabilities import AtlasConfig
from mykronos.schemas import EcosystemEvidence


def component(name, licenses=None, *, ecosystem="npm", version="1.0.0"):
    entry = {
        "name": name,
        "version": version,
        "purl": f"pkg:{ecosystem}/{name}@{version}",
    }
    if licenses is not None:
        entry["licenses"] = [{"license": {"id": lic}} for lic in licenses]
    return entry


def cyclonedx(*components):
    return {"bomFormat": "CycloneDX", "components": list(components)}


class TestReadingLicenses:
    def test_it_counts_per_ecosystem(self) -> None:
        sbom = cyclonedx(
            component("lodash", ["MIT"]),
            component("express", ["MIT"]),
            component("requests", ["Apache-2.0"], ecosystem="pypi"),
        )

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {
            "npm": {"mit": 2},
            "pypi": {"apache-2.0": 1},
        }

    def test_identifiers_are_case_folded(self) -> None:
        """Real SBOMs carry `MIT`, `mit` and `Mit` for the same license
        depending on which metadata source Syft read it from. Three keys for
        one license would split every count."""
        sbom = cyclonedx(component("a", ["MIT"]), component("b", ["mit"]))

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {"npm": {"mit": 2}}

    def test_a_component_with_no_licenses_is_unknown(self) -> None:
        """A key, not an omission. "We looked and the SBOM says nothing" is a
        fact worth its own small penalty, and it is not the same as the
        license pass never having run."""
        assert atlas_sbom.licenses_by_ecosystem(cyclonedx(component("x"))) == {
            "npm": {"unknown": 1}
        }

    def test_a_dual_licensed_component_counts_against_both(self) -> None:
        """Deliberately sums to more than the dependency count. The question
        the penalty asks is how many components carry a flagged license, and
        a dual-licensed one does carry it."""
        sbom = cyclonedx(component("x", ["MIT", "GPL-3.0"]))

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {
            "npm": {"gpl-3.0": 1, "mit": 1}
        }

    def test_only_suffix_is_kept_distinct_from_the_bare_identifier(self) -> None:
        """`GPL-3.0-only` and `GPL-3.0-or-later` are genuinely different
        terms. Collapsing them would ban more than somebody asked for, so
        both appear in `FLAGGED_LICENSES` explicitly instead."""
        sbom = cyclonedx(component("a", ["GPL-3.0-only"]), component("b", ["GPL-3.0"]))

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {
            "npm": {"gpl-3.0": 1, "gpl-3.0-only": 1}
        }

    def test_an_expression_is_read_too(self) -> None:
        """CycloneDX allows `{expression: "..."}` where the license is not a
        single SPDX id, and Syft emits it."""
        sbom = {
            "components": [
                {"name": "x", "purl": "pkg:npm/x@1", "licenses": [{"expression": "MIT"}]}
            ]
        }

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {"npm": {"mit": 1}}


class TestSpdx:
    def test_spdx_packages_are_read_the_same_way(self) -> None:
        """`AtlasConfig.sbom_format` lets a repo choose, so both dialects
        have to work — a repo on SPDX must not silently get no licenses."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "lodash",
                    "versionInfo": "4.17.21",
                    "licenseDeclared": "MIT",
                    "externalRefs": [
                        {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}
                    ],
                }
            ],
        }

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {"npm": {"mit": 1}}

    def test_noassertion_is_unknown_not_a_license(self) -> None:
        """SPDX for "the tool did not determine this". Recording it verbatim
        would put a pseudo-license in the counts and let somebody ban it by
        name."""
        sbom = {"packages": [{"name": "x", "licenseDeclared": "NOASSERTION"}]}

        assert atlas_sbom.licenses_by_ecosystem(sbom) == {"unknown": {"unknown": 1}}


class TestScoring:
    def eco(self, **licenses):
        return EcosystemEvidence(
            ecosystem="npm", dependency_count=10, licenses_seen=licenses
        )

    def test_a_flagged_license_produces_a_term(self) -> None:
        result = atlas.score([self.eco(**{"gpl-3.0": 3, "mit": 7})])

        terms = {term["key"]: term for term in result.terms}
        assert terms["flagged_licenses"]["count"] == 3
        assert "gpl-3.0" in terms["flagged_licenses"]["detail"]

    def test_a_permissive_tree_gets_no_license_term(self) -> None:
        """The correct answer for the permissive majority of any dependency
        tree, and the reason `FLAGGED_LICENSES` is a short list rather than
        "any license we have not seen"."""
        result = atlas.score([self.eco(mit=9, **{"apache-2.0": 1})])

        assert not [t for t in result.terms if "license" in t["key"]]

    def test_unknown_licenses_cost_less_than_flagged_ones(self) -> None:
        """"We do not know" is a lesser risk than "we know it obliges", and
        unknown is also the more common shape — a heavier weight would drown
        the term that means something."""
        unknown = atlas.score([self.eco(unknown=4)])
        flagged = atlas.score([self.eco(**{"gpl-3.0": 4})])

        assert unknown.terms[0]["penalty"] < flagged.terms[0]["penalty"]

    def test_the_penalty_is_curved(self) -> None:
        """The D-018 discipline every other term here follows. A monorepo
        with two hundred GPL components has a licensing question to answer,
        not a trust score of zero, and a linear term would floor it there and
        stop distinguishing it from one with a thousand."""
        few = atlas.score([self.eco(**{"gpl-3.0": 5})]).terms[0]["penalty"]
        many = atlas.score([self.eco(**{"gpl-3.0": 500})]).terms[0]["penalty"]

        assert many < few * 100

    def test_licenses_alone_never_produce_a_score_from_nothing(self) -> None:
        """spec 07 §5a's null state governs. A scan that resolved no
        dependencies is unassessed, and a license pass over an SBOM full of
        components osv-scanner could not check must not turn that into a
        number."""
        result = atlas.score(
            [
                EcosystemEvidence(
                    ecosystem="npm", dependency_count=0, licenses_seen={"gpl-3.0": 3}
                )
            ]
        )

        assert result.trust_score is None

    def test_an_empty_licenses_map_changes_nothing(self) -> None:
        """Every evidence row written before spec 22 has one. They must score
        exactly as they did."""
        before = atlas.score([EcosystemEvidence(ecosystem="npm", dependency_count=10)])
        after = atlas.score([self.eco()])

        assert before.trust_score == after.trust_score == 100


class TestDenylistFindings:
    SBOM = cyclonedx(
        component("left-pad", ["MIT"]),
        component("gplthing", ["GPL-3.0"]),
        component("fine", ["MIT"]),
    )

    def test_a_banned_package_produces_a_finding(self) -> None:
        """A finding, not a score deduction. A silent penalty buries a policy
        violation in a single number nobody reads term by term."""
        findings = atlas_sbom.denylist_findings(
            self.SBOM, banned_packages=["left-pad"], blocked_licenses=[]
        )

        assert [f["rule_id"] for f in findings] == ["atlas-banned-package"]
        assert findings[0]["package_name"] == "left-pad"

    def test_it_fires_without_any_vulnerability(self) -> None:
        """The point of §3: `left-pad` has no advisory against it. The ban is
        the finding."""
        findings = atlas_sbom.denylist_findings(
            self.SBOM, banned_packages=["left-pad"], blocked_licenses=[]
        )

        assert len(findings) == 1

    def test_a_blocked_license_produces_a_finding(self) -> None:
        findings = atlas_sbom.denylist_findings(
            self.SBOM, banned_packages=[], blocked_licenses=["GPL-3.0"]
        )

        assert [f["rule_id"] for f in findings] == ["atlas-blocked-license"]
        assert findings[0]["package_name"] == "gplthing"

    def test_banned_and_blocked_are_two_findings_not_one(self) -> None:
        """spec 22 §6. They are different facts about the same package, and
        disposing of one should not silently dispose of the other."""
        findings = atlas_sbom.denylist_findings(
            cyclonedx(component("bad", ["GPL-3.0"])),
            banned_packages=["bad"],
            blocked_licenses=["gpl-3.0"],
        )

        assert sorted(f["rule_id"] for f in findings) == [
            "atlas-banned-package",
            "atlas-blocked-license",
        ]

    def test_the_restrictive_license_governs(self) -> None:
        """A component offering MIT *and* GPL-3.0 is flagged. The permissive
        option being available does not make the restrictive one absent."""
        findings = atlas_sbom.denylist_findings(
            cyclonedx(component("dual", ["MIT", "GPL-3.0"])),
            banned_packages=[],
            blocked_licenses=["gpl-3.0"],
        )

        assert len(findings) == 1

    def test_no_config_means_no_findings_and_no_work(self) -> None:
        assert (
            atlas_sbom.denylist_findings(
                self.SBOM, banned_packages=[], blocked_licenses=[]
            )
            == []
        )


class TestConfig:
    def test_the_lists_default_empty(self) -> None:
        config = AtlasConfig()

        assert config.banned_packages == []
        assert config.blocked_licenses == []

    def test_blank_entries_are_dropped(self) -> None:
        """A list that looks like it bans something while banning nothing is
        the worst outcome available here."""
        config = AtlasConfig(banned_packages=["left-pad", "", "  "])

        assert config.banned_packages == ["left-pad"]

    def test_entries_are_trimmed(self) -> None:
        assert AtlasConfig(blocked_licenses=[" gpl-3.0 "]).blocked_licenses == ["gpl-3.0"]


class TestTheCountsMerge:
    REPORT = {
        "results": [
            {
                "packages": [
                    {"package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}}
                ]
            }
        ]
    }

    def test_licenses_land_on_the_matching_ecosystem_row(self) -> None:
        rows = atlas_counts.summarise(self.REPORT, {"npm": {"mit": 1}})

        assert rows[0]["ecosystem"] == "npm"
        assert rows[0]["licenses_seen"] == {"mit": 1}

    def test_an_ecosystem_only_the_sbom_knows_still_gets_a_row(self) -> None:
        """osv-scanner skips ecosystems it cannot check advisories for. Those
        components still have licenses, and dropping them would make the
        license counts disagree with the SBOM for no visible reason."""
        rows = atlas_counts.summarise(self.REPORT, {"golang": {"mit": 3}})

        by_eco = {row["ecosystem"]: row for row in rows}
        assert by_eco["golang"]["licenses_seen"] == {"mit": 3}
        assert by_eco["golang"]["dependency_count"] == 0

    def test_no_license_pass_leaves_the_field_empty(self) -> None:
        """Empty is "not computed", which is what every pre-spec-22 runner
        emits and what the platform must keep reading as such."""
        assert atlas_counts.summarise(self.REPORT)[0]["licenses_seen"] == {}

    @pytest.mark.parametrize("licenses", [None, {}])
    def test_the_row_shape_is_unchanged_otherwise(self, licenses) -> None:
        row = atlas_counts.summarise(self.REPORT, licenses)[0]

        assert row["maintenance_data_available_for"] is None
        assert row["dependency_count"] == 1
