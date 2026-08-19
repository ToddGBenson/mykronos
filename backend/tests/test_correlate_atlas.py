"""Atlas findings reach toxic-combination detection — spec 22 §4.

`atlas` has been in `DEFAULT_CORRELATION_CAPABILITIES` since spec 08 shipped
and no rule ever named it, so a vulnerable *application* dependency behind a
reachable service was never detected — while the identical shape in a
container layer was.
"""

from __future__ import annotations

from mykronos.patchwork import correlate


def finding(finding_id, rule_id, capability, *, title="", severity="high", path=""):
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "title": title or rule_id,
        "file_path": path,
        "capability": capability,
        "severity": severity,
    }


REACHABLE = finding(
    "d1", "ZAP-10202", "dast", title="Server leaks version information via banner"
)


class TestExploitableDependencyReachable:
    def test_an_atlas_cve_pairs_with_a_reachable_service(self) -> None:
        combos = correlate.detect(
            [finding("a1", "CVE-2024-4812", "atlas"), REACHABLE]
        )

        assert [c.rule_id for c in combos] == ["vulnerable-image-and-live-service"]
        assert combos[0].finding_ids == frozenset({"a1", "d1"})

    def test_a_container_cve_still_pairs_the_same_way(self) -> None:
        """The rule this widens already covered the container half; widening
        it must not cost that."""
        combos = correlate.detect(
            [finding("c1", "CVE-2024-4812", "containers"), REACHABLE]
        )

        assert [c.rule_id for c in combos] == ["vulnerable-image-and-live-service"]

    def test_the_severity_floor_still_applies(self) -> None:
        """Every image and every dependency tree carries low-severity CVEs.
        Without the floor this rule fires on every repository that runs a web
        server, which is the definition of a rule nobody reads."""
        combos = correlate.detect(
            [finding("a1", "CVE-2024-0001", "atlas", severity="low"), REACHABLE]
        )

        assert combos == []

    def test_an_atlas_cve_alone_is_not_a_combination(self) -> None:
        """A CVE nobody can reach is backlog, not a shortlist."""
        assert correlate.detect([finding("a1", "CVE-2024-4812", "atlas")]) == []

    def test_the_same_cve_in_both_halves_fires_once(self) -> None:
        """The common case: one vulnerable package appears in the built image
        *and* in the manifest. `detect` claims a finding for at most one
        combination, so widening the rule must not produce two rows describing
        the same risk."""
        combos = correlate.detect(
            [
                finding("c1", "CVE-2024-4812", "containers"),
                finding("a1", "CVE-2024-4812", "atlas"),
                REACHABLE,
            ]
        )

        assert len(combos) == 1
        # Whichever half matched, the reachable finding is in it exactly once.
        assert "d1" in combos[0].finding_ids
        assert len(combos[0].finding_ids) == 2


class TestMultiCapabilityRequirements:
    """The mechanism the widening rests on: one requirement, several
    capabilities — rather than a third requirement, which `detect` would
    demand a distinct finding for and so stop the rule firing for a
    repository that only has one half."""

    def test_either_capability_satisfies_the_requirement(self) -> None:
        requirement = correlate.Requirement(
            r"CVE-", capability=("containers", "atlas")
        )

        for capability in ("containers", "atlas"):
            assert correlate._matches(
                requirement, finding("x", "CVE-1", capability)
            )

    def test_an_unlisted_capability_does_not(self) -> None:
        requirement = correlate.Requirement(
            r"CVE-", capability=("containers", "atlas")
        )

        assert not correlate._matches(requirement, finding("x", "CVE-1", "sast"))

    def test_a_plain_string_capability_still_works(self) -> None:
        """Every existing rule passes a single string; the tuple form is
        additive, not a migration."""
        requirement = correlate.Requirement(r"CVE-", capability="containers")

        assert correlate._matches(requirement, finding("x", "CVE-1", "containers"))
        assert not correlate._matches(requirement, finding("x", "CVE-1", "atlas"))
