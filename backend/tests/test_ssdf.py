"""SSDF adherence, evidenced rather than asserted (SP 800-218)."""

from __future__ import annotations

from mykronos import ssdf


def _by_id(results: list[ssdf.PracticeResult]) -> dict[str, ssdf.PracticeResult]:
    return {r.practice_id: r for r in results}


class TestEvidenceNotIntent:
    def test_an_enabled_but_silent_lane_evidences_nothing(self) -> None:
        """The move this whole module exists to refuse.

        If enabling a capability counted, a repository could claim coverage by
        flipping a toggle — which is exactly what the maturity model was
        written to prevent, in a frame where the output goes to an auditor.
        """
        results = _by_id(
            ssdf.assess(
                reporting_capabilities=set(),
                enabled_capabilities={"iac"},
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        pw9 = results["PW.9"]
        assert pw9.status == "not_evidenced"
        assert any("never reported" in m for m in pw9.missing)

    def test_a_reporting_lane_meets_it(self) -> None:
        results = _by_id(
            ssdf.assess(
                reporting_capabilities={"iac"},
                enabled_capabilities={"iac"},
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        assert results["PW.9"].status == "met"
        assert results["PW.9"].evidence

    def test_partial_is_a_real_answer(self) -> None:
        """A practice covered by four lanes where one reports is neither met
        nor unmet, and saying so beats rounding in either direction."""
        results = _by_id(
            ssdf.assess(
                reporting_capabilities={"unit"},
                enabled_capabilities={"unit", "functional", "dast", "qa"},
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        pw8 = results["PW.8"]
        assert pw8.status == "partial"
        assert pw8.evidence and pw8.missing


class TestControls:
    def test_an_unreadable_control_is_not_a_failure(self) -> None:
        """Unknown is not absent. Reporting a control the platform could not
        read as unmet would be as wrong as reporting it as a pass."""
        results = _by_id(
            ssdf.assess(
                reporting_capabilities=set(),
                enabled_capabilities=set(),
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        assert any("could not be read" in m for m in results["PS.2"].missing)

    def test_a_confirmed_control_meets_its_practice(self) -> None:
        results = _by_id(
            ssdf.assess(
                reporting_capabilities=set(),
                enabled_capabilities=set(),
                confirmed_controls={"signed_commits_required"},
                known_controls={"signed_commits_required"},
            )
        )

        assert results["PS.2"].status == "met"


class TestWhatItRefusesToMap:
    def test_organisational_practices_are_absent_not_failed(self) -> None:
        """PO.1 and PO.2 are organisational and no scanner observes them. A
        framework view that lists practices it cannot assess teaches people to
        ignore the ones it can."""
        ids = {p.practice_id for p in ssdf.PRACTICES}

        assert "PO.1" not in ids
        assert "PO.2" not in ids

    def test_design_is_never_auto_evidenced(self) -> None:
        """PW.1 maps to no capability on purpose. A threat model derived from
        findings evidences detection, not design, and mapping a scanner to it
        would be the inflation this module refuses."""
        results = _by_id(
            ssdf.assess(
                reporting_capabilities={"sast", "dast", "containers", "atlas", "iac"},
                enabled_capabilities=set(),
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        assert results["PW.1"].status == "not_evidenced"
        assert results["PW.1"].how_to_evidence

    def test_every_practice_says_how_to_evidence_it(self) -> None:
        for practice in ssdf.PRACTICES:
            assert practice.how_to_evidence, practice.practice_id


class TestSummary:
    def test_counts_by_status_and_never_a_percentage(self) -> None:
        """No single number, deliberately: the practices are not equally
        weighted or equally applicable, and one figure invites the rounding
        this module exists to prevent."""
        counts = ssdf.summarise(
            ssdf.assess(
                reporting_capabilities={"iac"},
                enabled_capabilities={"iac"},
                confirmed_controls=set(),
                known_controls=set(),
            )
        )

        assert set(counts) == {"met", "partial", "not_evidenced", "not_applicable"}
        assert sum(counts.values()) == len(ssdf.PRACTICES)
