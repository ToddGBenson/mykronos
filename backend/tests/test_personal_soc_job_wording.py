"""What `ci.py` says personal-soc's gate jobs do, held against the pipeline
(TheHub #60852).

TheHub #60852 changed three personal-soc lanes and left the registry describing
the old ones: `doc-drift` still "fails the build" although it is report-only,
`external-exposure` still "alerts" although it now fails on a port nobody
allowlisted, and `netassess-ingest` said nothing about which postures fail it
or that host changes are posted. A description a reader trusts and the build
contradicts is the defect the CI audit was looking for, so each sentence here
is checked against the line of `personal-soc.yml` that makes it true.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mykronos.ci import ACKNOWLEDGED_UNMAPPED_JOBS, CAPABILITY_BY_JOB, PERSONAL_SOC

PIPELINE = (
    Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "personal-soc.yml"
)


def reason(job: str) -> str:
    return ACKNOWLEDGED_UNMAPPED_JOBS[(PERSONAL_SOC, job)]


@pytest.fixture(scope="module")
def pipeline() -> str:
    return PIPELINE.read_text(encoding="utf-8")


class TestDocDrift:
    def test_it_is_described_as_report_only(self) -> None:
        text = reason("doc-drift")

        assert "report-only" in text
        assert "fails the build, files nothing" not in text
        assert "does not fail the build" in text

    def test_the_pipeline_is_report_only(self, pipeline: str) -> None:
        assert "doc-drift is REPORT ONLY" in pipeline


class TestTheNetworkLanesFile:
    """TheHub #60813 (option A). The three exposure lanes were acknowledged as
    uploading nothing, and #60852's sentences said what each failed on. They
    still fail on exactly that, and now file `network` to Mykronos against
    personal-soc - so they are mapped, not acknowledged, and what they judge is
    held to the pipeline here and to the adapters in test_network_lanes.py."""

    @pytest.mark.parametrize(
        "job", ["external-exposure", "netassess-ingest", "netassess-freshness"]
    )
    def test_each_is_a_network_lane_not_an_unmapped_one(self, job: str) -> None:
        assert CAPABILITY_BY_JOB[(PERSONAL_SOC, job)] == "network"
        assert (PERSONAL_SOC, job) not in ACKNOWLEDGED_UNMAPPED_JOBS

    @pytest.mark.parametrize(
        ("job", "tool", "results_file"),
        [
            ("external-exposure", "shodan-internetdb", "external-exposure.json"),
            ("netassess-ingest", "netassess", "netassess-run.json"),
            ("netassess-freshness", "netassess-freshness", "netassess-freshness.json"),
        ],
    )
    def test_each_uploads_its_own_tool_against_personal_soc(
        self, pipeline: str, job: str, tool: str, results_file: str
    ) -> None:
        body = pipeline.split(f"MYKRONOS_JOB={job} python -m mykronos.upload", 1)[1][:600]
        assert f"--capability network --tool {tool}" in body
        assert f"--results-path results/{results_file}" in body
        assert "--repo ToddGBenson/personal-soc" in body


class TestExternalExposure:
    def test_the_pipeline_judges_against_the_allowlist(self, pipeline: str) -> None:
        assert "exposure-allowlist.yml" in pipeline
        assert "a visible port is NOT allowlisted" in pipeline

    def test_an_unanswered_lookup_is_filed_as_unknown(self, pipeline: str) -> None:
        assert '{"check": "unknown", "reason": "no public IP resolved"}' in pipeline
        assert '{"indexed": false}' in pipeline


class TestNetassessIngest:
    @pytest.mark.parametrize(
        "pipeline_line",
        [
            "EXPORTS PRESENT",
            "SMBv1 ENABLED",
            "broadcasting",
            "NAS lists shares without credentials",
            "it did not run, so it is not a pass",
        ],
    )
    def test_each_failing_posture_is_still_judged(self, pipeline: str, pipeline_line: str) -> None:
        assert pipeline_line in pipeline

    def test_host_changes_are_posted_not_failed(self, pipeline: str) -> None:
        assert "reported, not a failure" in pipeline

    def test_the_run_is_written_before_any_check_can_stop_the_task(self, pipeline: str) -> None:
        written = pipeline.index("results/netassess-run.json")
        first_check = pipeline.index("# -- 1. is this a real scan?")
        assert written < first_check
