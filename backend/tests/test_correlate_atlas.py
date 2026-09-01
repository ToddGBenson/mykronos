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


#: Titles taken verbatim from ZAP output in this estate on 2026-09-01, not
#: invented. The rule matched none of the 147 open DAST findings before this,
#: while the suite passed — because every test above pairs against
#: `"Server leaks version information via banner"`, a sentence ZAP does not
#: produce. A rule tested only against its own vocabulary is a rule tested
#: against nothing.
REAL_ZAP_TITLES = {
    "discloses_what_runs": [
        'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) at GET /repos',
    ],
    "hardening_gap": [
        "X-Content-Type-Options Header Missing at GET /triage",
        "Missing Anti-clickjacking Header at GET /",
        "Content Security Policy (CSP) Header Not Set at GET /decisions",
        "Information Disclosure - Suspicious Comments at GET /frontend/js/dashboard",
        "ZAP is Out of Date at GET /api/dashboard/portfolio",
    ],
}


def _dast_requirement():
    rule = next(
        r
        for r in correlate.BUILT_IN_RULES
        if r.rule_id == "vulnerable-image-and-live-service"
    )
    return rule.requires[1]


class TestTheRuleMatchesTheScannerActuallyRun:
    """The vocabulary has to be the scanner's, not the spec author's.

    ZAP is the only DAST scanner this platform runs. The rule asked for
    `banner|version|fingerprint`; ZAP says "Server Leaks Information via
    X-Powered-By". Measured on 2026-09-01: zero of 147 open DAST findings
    matched, so the rule could not fire on the estate it was written for.
    """

    def test_it_matches_a_service_disclosing_what_it_runs(self) -> None:
        requirement = _dast_requirement()

        for title in REAL_ZAP_TITLES["discloses_what_runs"]:
            assert correlate._matches(
                requirement,
                finding("d", "ZAP-10037-CWE-497", "dast", title=title, severity="low"),
            ), f"the rule should match ZAP's own phrasing: {title!r}"

    def test_it_does_not_match_a_hardening_gap(self) -> None:
        """These are most of ZAP's output. Matching them would fire this rule
        on every repository that serves HTTP, which is the definition of a
        rule nobody reads.

        `Information Disclosure - Suspicious Comments` is here deliberately: a
        leaked developer comment says nothing about which component is
        running, so pairing one with a high CVE would be a combination in name
        only. A first pass at this fix matched it and was narrowed.

        `ZAP is Out of Date` is about the scanner, not the service.
        """
        requirement = _dast_requirement()

        for title in REAL_ZAP_TITLES["hardening_gap"]:
            assert not correlate._matches(
                requirement,
                finding("d", "ZAP-10021-CWE-693", "dast", title=title, severity="low"),
            ), f"the rule should not fire on {title!r}"

    def test_a_ghsa_advisory_counts_as_a_known_exploitable_component(self) -> None:
        """The same class of risk as a CVE, and frequently the only identifier
        a finding carries. Matching one and not the other excluded findings
        for the way their id happened to be issued."""
        combinations = correlate.detect(
            [
                finding("c1", "GHSA-6v7p-g79w-8964", "containers", severity="high"),
                finding(
                    "d1",
                    "ZAP-10037",
                    "dast",
                    title=REAL_ZAP_TITLES["discloses_what_runs"][0],
                    severity="low",
                ),
            ]
        )

        assert [c.rule_id for c in combinations] == [
            "vulnerable-image-and-live-service"
        ]

    def test_the_dast_half_has_no_severity_floor(self) -> None:
        """Deliberate: a version banner is information whatever severity the
        scanner assigns it, and ZAP rates most disclosure findings low or
        info. A floor here would reintroduce the bug this fixes."""
        assert _dast_requirement().min_severity is None
