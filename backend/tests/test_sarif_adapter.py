"""[#497] Severity mapping for SARIF results.

A `security-severity` of exactly 0.0 is how a tool spells "I have not scored
this", not a measurement of no risk. The bands start at 0.1, so 0.0 fell past
all of them into INFO.
"""

from __future__ import annotations

import pytest

from mykronos.adapters import sarif
from mykronos.schemas import Severity


class TestAnUnscoredFindingIsNotInformational:
    """[#497] `security-severity: 0.0` means "not scored", not "no risk".

    Trivy emits it for every UNKNOWN-severity vulnerability and names the
    state in the same rule (`tags: [..., 'UNKNOWN']`). The bands start at
    0.1, so 0.0 fell past all of them to INFO: 100 of the 138 container
    findings ever filed at `info` arrived that way, including two open
    glibc CVEs with no published fix.
    """

    @staticmethod
    def _result_and_rule(score: str | float | None, level: str = "note"):
        rule = {"id": "CVE-2026-8674", "defaultConfiguration": {"level": level}}
        if score is not None:
            rule["properties"] = {
                "security-severity": score,
                "tags": ["vulnerability", "security", "UNKNOWN"],
            }
        return {"ruleId": "CVE-2026-8674", "level": level}, rule

    def test_a_zero_score_falls_through_to_the_level(self) -> None:
        result, rule = self._result_and_rule("0.0")
        severity, score = sarif._severity_for(result, rule)

        assert severity is Severity.LOW, (
            "0.0 is how trivy spells UNKNOWN; landing in INFO presents an "
            "unrated CVE with the weight of a cosmetic observation."
        )
        assert score is None, (
            "Carrying 0.0 forward would report a measurement nobody made."
        )

    def test_a_zero_score_as_a_float_is_treated_the_same(self) -> None:
        result, rule = self._result_and_rule(0.0)

        assert sarif._severity_for(result, rule)[0] is Severity.LOW

    def test_a_real_low_score_is_still_low_and_keeps_its_number(self) -> None:
        result, rule = self._result_and_rule("0.1", level="error")
        severity, score = sarif._severity_for(result, rule)

        assert severity is Severity.LOW
        assert score == pytest.approx(0.1), (
            "0.1 is a real score and must outrank the result level."
        )

    def test_a_high_score_still_wins_over_the_level(self) -> None:
        result, rule = self._result_and_rule("9.8", level="note")
        severity, score = sarif._severity_for(result, rule)

        assert severity is Severity.CRITICAL
        assert score == pytest.approx(9.8)

    def test_an_unscored_finding_with_no_level_still_is_not_info(self) -> None:
        """No `level` and no usable score: SARIF's own default is medium, and
        that is a better answer than informational for something unrated."""
        rule = {"id": "X", "properties": {"security-severity": "0.0"}}

        assert sarif._severity_for({"ruleId": "X"}, rule)[0] is not Severity.INFO
