"""Unit and functional suites report a ScanRun and no findings (D-046)."""

from __future__ import annotations

from mykronos.adapters.base import ScanContext
from mykronos.adapters.tests_junit import normalize
from mykronos.schemas import ScanStatus


def context(capability: str = "unit") -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability=capability,
        tool_name="junit",
        tool_version="",
        commit_sha="0" * 40,
        branch="main",
    )


def report(tests=10, failures=0, errors=0, skipped=0) -> bytes:
    return (
        f'<testsuites><testsuite name="suite" tests="{tests}" '
        f'failures="{failures}" errors="{errors}" skipped="{skipped}"/></testsuites>'
    ).encode()


class TestItNeverProducesFindings:
    def test_a_passing_suite(self) -> None:
        result = normalize(report(), context())

        assert result.findings == []
        assert result.scan_status is ScanStatus.SUCCESS

    def test_a_failing_suite_still_produces_no_findings(self) -> None:
        """The whole of D-046. A failing assertion is not a vulnerability, and
        routing it into the findings table would let a broken test raise a
        repository's security risk score - making deletion an improvement."""
        result = normalize(report(tests=10, failures=3), context())

        assert result.findings == []
        assert result.scan_status is ScanStatus.FAILURE


class TestStatus:
    def test_failures_and_errors_both_fail_the_run(self) -> None:
        assert normalize(report(failures=1), context()).scan_status is ScanStatus.FAILURE
        assert normalize(report(errors=1), context()).scan_status is ScanStatus.FAILURE

    def test_the_count_is_reported(self) -> None:
        result = normalize(report(tests=10, failures=2, errors=1), context())

        assert "3 of 10 test(s) failed" in result.warnings[0]

    def test_no_report_is_not_a_pass(self) -> None:
        """A repository with no tests and one whose tests never ran look
        identical in a build log. They must not look identical here."""
        result = normalize(b"", context())

        assert result.scan_status is ScanStatus.NO_APPLICABLE_TARGETS
        assert "no suite is known to have run" in result.warnings[0]

    def test_a_suite_of_zero_tests_is_not_a_pass(self) -> None:
        result = normalize(report(tests=0), context())

        assert result.scan_status is ScanStatus.NO_APPLICABLE_TARGETS

    def test_everything_skipped_is_not_a_pass(self) -> None:
        """Green in most CI views, and not evidence that anything was
        verified."""
        result = normalize(report(tests=8, skipped=8), context())

        assert result.scan_status is ScanStatus.NO_APPLICABLE_TARGETS
        assert "nothing was verified" in result.warnings[0]

    def test_some_skipped_still_passes_but_says_so(self) -> None:
        result = normalize(report(tests=10, skipped=2), context())

        assert result.scan_status is ScanStatus.SUCCESS
        assert "8 test(s) passed, 2 skipped" in result.warnings[0]

    def test_a_clean_run_is_not_reported_as_degraded(self) -> None:
        assert normalize(report(), context()).warnings == []

    def test_malformed_xml_is_a_partial_failure(self) -> None:
        result = normalize(b"<testsuites", context())

        assert result.scan_status is ScanStatus.PARTIAL_FAILURE


class TestShapes:
    def test_a_bare_testsuite_element_is_accepted(self) -> None:
        """pytest writes <testsuites><testsuite/></testsuites>; some runners
        write a single <testsuite> at the root."""
        raw = b'<testsuite name="s" tests="4" failures="1"/>'

        assert normalize(raw, context()).scan_status is ScanStatus.FAILURE

    def test_several_suites_are_summed(self) -> None:
        raw = (
            b'<testsuites>'
            b'<testsuite tests="5" failures="0"/>'
            b'<testsuite tests="5" failures="2"/>'
            b"</testsuites>"
        )

        result = normalize(raw, context())

        assert result.scan_status is ScanStatus.FAILURE
        assert "2 of 10" in result.warnings[0]

    def test_functional_uses_the_same_adapter(self) -> None:
        assert normalize(report(), context("functional")).findings == []

    def test_qa_uses_the_same_adapter(self) -> None:
        """A broken documentation link is a defect and is not a
        vulnerability. Same reasoning as a failing assertion (D-046)."""
        assert normalize(report(tests=28), context("qa")).findings == []


class TestRegistration:
    def test_both_capabilities_resolve_to_junit(self) -> None:
        from mykronos.adapters.registry import default_tool, get_adapter

        assert default_tool("unit") == "junit"
        assert default_tool("functional") == "junit"
        assert default_tool("qa") == "junit"
        assert get_adapter("unit", "junit").pattern == "*.xml"
