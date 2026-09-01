"""License compliance and denylists — spec 22 §1, §3.

Syft has captured license metadata for every SBOM this platform has ever
generated and nothing read it. These are the two things that now do: a
scoring term, and findings for what a repository has banned outright.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mykronos import atlas, atlas_counts, atlas_sbom
from mykronos.capabilities import AtlasConfig
from mykronos.schemas import EcosystemEvidence

#: `backend/tests/` -> repo root, for the CI-definition files below.
REPO_ROOT = Path(__file__).resolve().parents[2]


def _term(assessment, key):
    """One score term by key.

    Positional indexing was fine while the terms list only carried the terms
    that scored. `stale_dependencies` is now always present so the page can
    tell not-measured from measured-zero (B-004), which moves every other
    term's index.
    """
    matches = [t for t in assessment.terms if t["key"] == key]
    assert matches, f"no {key!r} term in {[t['key'] for t in assessment.terms]}"
    return matches[0]


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

        assert _term(unknown, "unknown_licenses")["penalty"] < _term(
            flagged, "flagged_licenses"
        )["penalty"]

    def test_the_penalty_is_curved(self) -> None:
        """The D-018 discipline every other term here follows. A monorepo
        with two hundred GPL components has a licensing question to answer,
        not a trust score of zero, and a linear term would floor it there and
        stop distinguishing it from one with a thousand."""
        few = _term(atlas.score([self.eco(**{"gpl-3.0": 5})]), "flagged_licenses")[
            "penalty"
        ]
        many = _term(atlas.score([self.eco(**{"gpl-3.0": 500})]), "flagged_licenses")[
            "penalty"
        ]

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


class TestBothCiSystemsProduceLicenseEvidence:
    """The license pass has to run on the path the real repos take (B-005).

    `atlas_counts` computes `licenses_seen` only when handed `--sbom`. The
    Actions template passed it; the two Concourse pipelines did not, and both
    primary repositories are Concourse-scanned. Because the evidence write is
    an upsert and both CI systems scan the same commits, whether a repository
    had license data depended on which pipeline finished last — intermittent
    missing data rather than a broken feature, which is the hardest shape to
    diagnose from a dashboard.

    Spec 22 listed this work as Built. It was built, and it was invisible on
    the path that mattered.
    """

    PIPELINES = (
        "deploy/concourse/pipelines/mykronos.yml",
        "deploy/concourse/pipelines/thehub.yml",
    )
    TEMPLATE = "workflow-templates/atlas.yml.j2"

    def _text(self, relative: str) -> str:
        return (REPO_ROOT / relative).read_text(encoding="utf-8")

    @pytest.mark.parametrize("relative", PIPELINES)
    def test_the_concourse_atlas_task_passes_sbom(self, relative: str) -> None:
        text = self._text(relative)

        assert "python -m mykronos.atlas_counts" in text, (
            f"{relative} no longer calls atlas_counts; this guard is stale."
        )
        assert "--sbom sbom-out/" in text, (
            f"{relative} calls atlas_counts without --sbom, so `licenses_seen` "
            "stays empty and the platform reads it as not-computed. Both "
            "primary repos are Concourse-scanned (B-005)."
        )

    @pytest.mark.parametrize("relative", PIPELINES)
    def test_freshness_stays_opt_in_on_the_concourse_path(self, relative: str) -> None:
        """Capable, and off. Spec 07 §7 requires the outbound registry call be
        opted into, so the flag is reachable but never unconditional."""
        text = self._text(relative)

        assert "ATLAS_CHECK_FRESHNESS" in text, (
            f"{relative} cannot pass --check-freshness at all, so "
            "`stale_dependencies` is structurally zero there (B-004)."
        )
        assert "$SBOM_ARGS --check-freshness" in text
        # Never on without the switch being set.
        assert '"${ATLAS_CHECK_FRESHNESS:-false}" = "true"' in text

    def test_the_actions_template_still_passes_it_too(self) -> None:
        """The fix is parity, not a swap. If the Actions path ever loses the
        flag, the race comes back pointing the other way."""
        text = self._text(self.TEMPLATE)

        assert '--sbom sbom.json' in text
        assert "--check-freshness" in text

    def test_ordering_between_the_two_systems_no_longer_decides_the_outcome(
        self,
    ) -> None:
        """The property the race broke, stated directly: the same commit
        scanned by either system computes the same license evidence, because
        both now run the same pass over the same SBOM."""
        licenses = atlas_sbom.licenses_by_ecosystem(cyclonedx(component("lodash", ["MIT"])))

        actions_rows = atlas_counts.summarise(self.REPORT, licenses)
        concourse_rows = atlas_counts.summarise(self.REPORT, licenses)

        assert actions_rows == concourse_rows
        assert actions_rows[0]["licenses_seen"] == {"mit": 1}

    REPORT = {
        "results": [
            {
                "packages": [
                    {"package": {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"}}
                ]
            }
        ]
    }


class TestTheStaleTermSaysWhichZeroItIs:
    """Not-measured and measured-zero are different facts (B-004).

    The freshness pass is opt-in (spec 07 §7) and nothing opts in, so
    `stale_dependencies` is zero on every repository. Until now the term was
    emitted only when it scored, so "nobody asked" and "asked, nothing stale"
    were both rendered as the term being absent — indistinguishable, which is
    the zero spec 22 §2.1 was written to fix wearing a different hat.
    """

    def eco(self, stale=0, known=None):
        return EcosystemEvidence(
            ecosystem="npm",
            dependency_count=10,
            stale_dependencies=stale,
            maintenance_data_available_for=known,
        )

    def test_never_measured_is_marked_unavailable(self) -> None:
        term = _term(atlas.score([self.eco()]), "stale_dependencies")

        assert term["available"] is False
        assert term["penalty"] == 0.0
        assert "Not measured" in term["detail"]
        assert "not a statement that nothing is stale" in term["detail"]

    def test_measured_and_clean_is_a_real_zero(self) -> None:
        term = _term(atlas.score([self.eco(stale=0, known=10)]), "stale_dependencies")

        assert "available" not in term
        assert term["penalty"] == 0.0
        assert "0/10" in term["detail"]
        assert "nothing is stale" in term["detail"]

    def test_measured_and_stale_still_scores(self) -> None:
        term = _term(atlas.score([self.eco(stale=5, known=10)]), "stale_dependencies")

        assert "available" not in term
        assert term["penalty"] > 0
        assert term["count"] == 5

    def test_the_two_zeroes_are_distinguishable(self) -> None:
        """The property, stated as one assertion: the page can tell them
        apart, which is the whole point of emitting both."""
        not_measured = _term(atlas.score([self.eco()]), "stale_dependencies")
        measured_clean = _term(
            atlas.score([self.eco(stale=0, known=10)]), "stale_dependencies"
        )

        assert not_measured["penalty"] == measured_clean["penalty"] == 0.0
        assert not_measured != measured_clean

    def test_neither_zero_changes_the_score(self) -> None:
        """Making the state visible must not move any trust score. A term that
        renders differently and scores identically is the entire change."""
        assert (
            atlas.score([self.eco()]).trust_score
            == atlas.score([self.eco(stale=0, known=10)]).trust_score
        )
