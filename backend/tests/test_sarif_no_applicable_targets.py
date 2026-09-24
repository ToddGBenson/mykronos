"""[#59989/#60071] A repository with no IaC must be able to SAY so.

keel has zero Terraform, zero Dockerfiles, zero charts, and an `iac` job that
correctly declines to scan. Until this change there was no honest way to record
that outcome:

  * an empty SARIF reads as "scanned, found nothing" -- identical to a repo
    that was scanned and came back clean;
  * no SARIF at all is reported by `normalize_results` as FAILURE, which says
    the scanner broke when it did exactly the right thing.

Both are wrong, in opposite directions, and the estate has been sitting on the
first one. `ScanStatus.NO_APPLICABLE_TARGETS` already existed, was already
emitted by two adapters, and was already treated as a reporting outcome by
Oracle -- the only missing piece was a way for a SARIF-producing tool to reach
it. The marker rides in the run's property bag (SARIF 2.1.0 §3.8), which is
what that bag is for.

WHAT THIS DOES NOT DO, stated here so nobody reads more into it. `coverage()`
still reads lane timestamps, so a lane that uploads this status still reads as
covered on the dashboard -- the distinction now survives into the lake and dies
one layer later than it did. The coverage state fed by ScanStatus is a
deliberately separate change, because it moves every coverage number in the
estate and amends a written standard.
"""

from __future__ import annotations

from pathlib import Path

from mykronos.adapters import sarif
from mykronos.adapters.base import ScanContext
from mykronos.schemas import ScanStatus


def context(workspace: Path | None = None) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/keel",
        capability="iac",
        tool_name="checkov",
        tool_version="3.2.0",
        commit_sha="a91f2c7",
        branch="main",
        workspace=workspace,
    )


def _run(status: str | None = None, reason: str | None = None, results=None) -> dict:
    run: dict = {
        "tool": {"driver": {"name": "checkov"}},
        "results": results if results is not None else [],
    }
    bag: dict = {}
    if status is not None:
        bag["scanStatus"] = status
    if reason is not None:
        bag["reason"] = reason
    if bag:
        run["properties"] = {"mykronos": bag}
    return run


def _doc(*runs: dict) -> str:
    import json

    return json.dumps({"version": "2.1.0", "runs": list(runs)})


class TestATooWithNothingToScanSaysSo:
    def test_the_marker_produces_no_applicable_targets(self) -> None:
        out = sarif.sarif_to_findings(
            _doc(_run("no_applicable_targets", "no IaC files found")), context()
        )

        assert out.scan_status is ScanStatus.NO_APPLICABLE_TARGETS
        assert out.findings == []

    def test_the_tools_own_reason_survives(self) -> None:
        """A status with no reason is what gets argued about six months later.

        The tool knows which file types it looked for. The platform does not,
        and must not invent an explanation on its behalf.
        """
        out = sarif.sarif_to_findings(
            _doc(_run("no_applicable_targets", "no *.tf, Dockerfile or chart")),
            context(),
        )

        assert any("no *.tf, Dockerfile or chart" in w for w in out.warnings)

    def test_a_marker_with_no_reason_still_says_something(self) -> None:
        out = sarif.sarif_to_findings(_doc(_run("no_applicable_targets")), context())

        assert out.scan_status is ScanStatus.NO_APPLICABLE_TARGETS
        assert out.warnings, "a bare status must not arrive silently"


class TestTheMarkerChangesNothingForEverythingElse:
    """The whole value of a property bag is that a tool which does not set it
    is unaffected. These are the cases that must not move."""

    def test_an_unmarked_empty_sarif_is_still_a_clean_scan(self) -> None:
        out = sarif.sarif_to_findings(_doc(_run()), context())

        assert out.scan_status is ScanStatus.SUCCESS, (
            "scanned-and-found-nothing is a real result and must keep reporting "
            "as one -- this is the case the marker exists to be DISTINCT from"
        )

    def test_a_document_with_no_runs_is_untouched(self) -> None:
        out = sarif.sarif_to_findings('{"version": "2.1.0", "runs": []}', context())

        assert out.scan_status is ScanStatus.SUCCESS

    def test_an_unrelated_property_bag_is_ignored(self) -> None:
        run = _run()
        run["properties"] = {"semmle": {"formatSpecifier": "sarifv2.1.0"}}

        out = sarif.sarif_to_findings(_doc(run), context())

        assert out.scan_status is ScanStatus.SUCCESS

    def test_a_scan_status_of_some_other_value_is_not_honoured(self) -> None:
        """Only this one status is readable from the document.

        A tool that could declare itself SUCCESS or FAILURE through its own
        output would be grading itself, and the platform's whole job is to
        grade it. `no_applicable_targets` is safe to accept because it is a
        statement about the REPOSITORY -- which the tool can see and the
        platform cannot -- rather than about the scan.
        """
        out = sarif.sarif_to_findings(_doc(_run("success")), context())

        assert out.scan_status is ScanStatus.SUCCESS
        out = sarif.sarif_to_findings(_doc(_run("failure")), context())
        assert out.scan_status is ScanStatus.SUCCESS


class TestAMixedDocumentIsNotNotApplicable:
    """EVERY run must declare it, not any.

    CodeQL writes one SARIF per language and the adapter accumulates several
    documents into one outcome. A repository that has Terraform but no charts
    would produce one scanned run and one empty one; reporting the pair as "not
    applicable" would hide the half that WAS scanned, which is the same class of
    error as reporting an unscanned repo as clean.
    """

    def test_one_marked_run_beside_a_scanned_one_falls_through(self) -> None:
        scanned = _run(
            results=[
                {
                    "ruleId": "CKV_DOCKER_2",
                    "level": "warning",
                    "message": {"text": "No HEALTHCHECK"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "Dockerfile"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ]
        )
        out = sarif.sarif_to_findings(
            _doc(_run("no_applicable_targets", "no charts"), scanned), context()
        )

        assert out.scan_status is not ScanStatus.NO_APPLICABLE_TARGETS
        assert len(out.findings) == 1, (
            "the scanned half must still be ingested -- suppressing it is how a "
            "partially-covered repository reads as an exempt one"
        )
