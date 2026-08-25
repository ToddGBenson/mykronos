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

**Coverage reports are read here too (spec 31 §4).** A repository that writes
`coverage.xml` beside `unit.xml` was, until this, handing a Cobertura document
to a JUnit parser: it found no `testsuite` element, reported "the report
contains no test suites", and downgraded a green run to
`no_applicable_targets`. So the file that carried the most useful context
about a suite was actively making the record worse. Cobertura and JaCoCo are
recognised by their root element and yield coverage rather than a warning.

Coverage is **not a security metric** and is labelled that way wherever it is
shown. A green sparkline says the tests that exist passed; 90% coverage with
zero regression links (spec 31 §3) says the tests are thorough about something
other than the things that have actually gone wrong here.
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


def _rate(element: ElementTree.Element, name: str) -> float | None:
    """A Cobertura rate attribute as 0..1, or `None` if it is absent."""
    value = element.get(name)
    if value is None:
        return None
    try:
        rate = float(value)
    except ValueError:
        return None
    return max(0.0, min(1.0, rate))


def _jacoco_ratio(root: ElementTree.Element, counter_type: str) -> float | None:
    """JaCoCo reports covered/missed pairs rather than a rate.

    Only the report-level counters, not the per-package ones nested inside:
    `iter` would sum every level of the tree and count the same lines several
    times over.
    """
    for counter in root.findall("counter"):
        if counter.get("type") != counter_type:
            continue
        covered = _ints(counter, "covered")["covered"]
        missed = _ints(counter, "missed")["missed"]
        total = covered + missed
        return (covered / total) if total else None
    return None


def _coverage(root: ElementTree.Element) -> AdapterResult | None:
    """A coverage document, or `None` if this is not one.

    Recognised by root element rather than by filename: `coverage.xml` is a
    convention and not a rule, and a report named `results.xml` is still a
    report.
    """
    if root.tag == "coverage":  # Cobertura — pytest-cov, coverage.py, jest.
        result = AdapterResult()
        result.line_coverage = _rate(root, "line-rate")
        result.branch_coverage = _rate(root, "branch-rate")
    elif root.tag == "report":  # JaCoCo — Maven, Gradle.
        result = AdapterResult()
        result.line_coverage = _jacoco_ratio(root, "LINE")
        result.branch_coverage = _jacoco_ratio(root, "BRANCH")
    else:
        return None

    if result.line_coverage is None and result.branch_coverage is None:
        # The right shape and nothing in it. Said rather than silently
        # treated as a coverage report that measured zero.
        result.warn("A coverage report was found but carried no usable rates.")
    return result


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Read a JUnit XML report, or a coverage report. Never produces findings."""
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

    coverage = _coverage(root)
    if coverage is not None:
        return coverage

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
