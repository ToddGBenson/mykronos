"""The test estate: what kinds of testing exist, and what kinds do not."""

from __future__ import annotations

from mykronos import test_estate


def _by_key(results: list[test_estate.KindResult]) -> dict[str, test_estate.KindResult]:
    return {r.key: r for r in results}


class TestCoverageIsAStateNotANumber:
    def test_runs_without_a_coverage_document_are_never_zero_percent(self) -> None:
        """The trap this class exists for.

        On 2026-09-03 this estate had 227 unit runs and not one coverage
        figure. Rendering that as 0% would be a fabricated measurement of a
        real suite — worse than a blank, because a blank invites the question
        and a zero answers it wrongly.
        """
        lanes = {
            lane.capability: lane
            for lane in test_estate.lane_health(
                [{"capability": "unit", "runs": 227, "succeeded": 213, "failed": 14}],
                enabled={"unit"},
            )
        }

        assert lanes["unit"].coverage_state == "never_reported"
        assert lanes["unit"].line_coverage is None

    def test_a_lane_that_never_ran_is_distinct_from_one_with_no_coverage(self) -> None:
        """"No tests here" and "tests that never measured coverage" are
        different problems and must not render the same."""
        lanes = {
            lane.capability: lane
            for lane in test_estate.lane_health([], enabled=set())
        }

        assert lanes["functional"].coverage_state == "no_runs"
        assert lanes["functional"].runs == 0

    def test_a_reported_figure_is_carried_through(self) -> None:
        lanes = {
            lane.capability: lane
            for lane in test_estate.lane_health(
                [{"capability": "unit", "runs": 5, "line_coverage": 0.83}],
                enabled={"unit"},
            )
        }

        assert lanes["unit"].coverage_state == "reported"
        assert lanes["unit"].line_coverage == 0.83

    def test_every_test_lane_gets_a_row_even_with_no_data(self) -> None:
        """An absent lane is a row saying so. Omitting it makes a repository
        with no tests look like one the platform was never pointed at."""
        lanes = test_estate.lane_health([], enabled=set())

        assert {lane.capability for lane in lanes} == set(test_estate.TEST_LANES)


class TestEvidenceNotIntent:
    def test_an_enabled_but_silent_lane_evidences_no_testing(self) -> None:
        results = _by_key(test_estate.assess(reporting_capabilities=set()))

        assert results["unit"].presence == "absent"

    def test_a_reporting_lane_evidences_its_kind(self) -> None:
        results = _by_key(test_estate.assess(reporting_capabilities={"unit"}))

        assert results["unit"].presence == "observed"
        assert results["unit"].evidence

    def test_only_demonstrated_regressions_count(self) -> None:
        """An asserted link is somebody's claim that a test covers a finding.
        Counting it here would make the view report testing it never saw."""
        absent = _by_key(test_estate.assess(reporting_capabilities=set()))
        present = _by_key(
            test_estate.assess(reporting_capabilities=set(), demonstrated_regressions=3)
        )

        assert absent["security_regression"].presence == "absent"
        assert present["security_regression"].presence == "observed"


class TestWhatItNamesAsMissing:
    def test_unobservable_kinds_are_listed_rather_than_omitted(self) -> None:
        """The entire point. A view showing only the testing that exists can
        never tell anybody what is missing."""
        results = _by_key(test_estate.assess(reporting_capabilities={"unit", "qa"}))

        for key in (
            "contract",
            "end_to_end",
            "performance",
            "accessibility",
            "resilience",
            "smoke",
        ):
            assert results[key].presence == "absent", key
            assert results[key].how_to_evidence, key

    def test_every_kind_says_how_to_evidence_it(self) -> None:
        for kind in test_estate.KINDS:
            assert kind.how_to_evidence, kind.key
            assert kind.why.endswith("?"), kind.key


class TestSummary:
    def test_counts_and_never_a_maturity_score(self) -> None:
        """No single figure: the kinds are not equally applicable, so a
        library would lose points for correctly having no smoke test."""
        counts = test_estate.summarise(
            test_estate.assess(reporting_capabilities={"unit"})
        )

        assert set(counts) == {"observed", "absent"}
        assert sum(counts.values()) == len(test_estate.KINDS)
