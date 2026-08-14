"""JUnit XML to a ScanRun with no findings (D-046).

Unit and functional suites report through the same ingestion path as every
scanner, and produce nothing in the findings table. What reaches the lake is
that a suite ran, how it ended, and how many cases failed.

JUnit XML because it is the one format every runner already emits — pytest,
jest, go-junit-report, Maven, dotnet. Asking each repository to adopt a
Mykronos-specific format would be asking it to change its build to be
observed, which is how observation gets switched off.

**No findings, deliberately.** A failing assertion is not a vulnerability. It
has no severity that means what a CVE's means, and routing it into the
findings table would put it into Oracle's risk score — so a broken test would
raise a repository's security risk and deleting the test would lower it. The
pipeline stops the build; the risk score stays about risk.
"""

from __future__ import annotations

from xml.etree import ElementTree

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import ScanStatus


def _ints(element: ElementTree.Element, *names: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for name in names:
        try:
            out[name] = int(element.get(name) or 0)
        except ValueError:
            out[name] = 0
    return out


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Read a JUnit XML report. Never produces findings."""
    result = AdapterResult()
    text = raw_output.decode("utf-8", errors="replace").strip()

    if not text:
        # Distinct from "the suite passed". A repository with no tests and a
        # repository whose tests were never run look identical in a build log
        # and must not look identical here.
        result.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        result.warn("No test report was produced, so no suite is known to have run.")
        return result

    try:
        root = ElementTree.fromstring(text)  # noqa: S314 - the build's own output
    except ElementTree.ParseError as exc:
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        result.warn(f"Test report is not parseable JUnit XML: {exc}")
        return result

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        result.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        result.warn("The report contains no test suites.")
        return result

    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        counts = _ints(suite, "tests", "failures", "errors", "skipped")
        for key in totals:
            totals[key] += counts.get(key, 0)

    failed = totals["failures"] + totals["errors"]
    ran = totals["tests"] - totals["skipped"]

    if totals["tests"] == 0:
        result.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        result.warn("The suite reported zero test cases.")
        return result

    if failed:
        result.scan_status = ScanStatus.FAILURE
        result.warn(
            f"{failed} of {totals['tests']} test(s) failed "
            f"({totals['failures']} failure(s), {totals['errors']} error(s))."
        )
    elif ran == 0:
        # Everything was skipped. Green in most CI views, and not evidence of
        # anything having been tested.
        result.scan_status = ScanStatus.NO_APPLICABLE_TARGETS
        result.warn(
            f"All {totals['skipped']} test(s) were skipped, so nothing was verified."
        )
    elif totals["skipped"]:
        result.warn(f"{ran} test(s) passed, {totals['skipped']} skipped.")

    return result
