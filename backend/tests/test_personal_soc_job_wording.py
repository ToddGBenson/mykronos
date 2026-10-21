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

from mykronos.ci import ACKNOWLEDGED_UNMAPPED_JOBS, PERSONAL_SOC

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


class TestExternalExposure:
    def test_it_is_described_as_failing_on_an_unallowlisted_port(self) -> None:
        text = reason("external-exposure")

        assert "allowlist" in text
        assert "fails" in text
        assert "alerts; uploads nothing" not in text

    def test_the_pipeline_judges_against_the_allowlist(self, pipeline: str) -> None:
        assert "exposure-allowlist.yml" in pipeline
        assert "a visible port is NOT allowlisted" in pipeline


class TestNetassessIngest:
    @pytest.mark.parametrize(
        ("described", "pipeline_line"),
        [
            ("NFS exports", "EXPORTS PRESENT"),
            ("SMBv1", "SMBv1 ENABLED"),
            ("open Wi-Fi access point", "broadcasting"),
            ("anonymous shares", "NAS lists shares without credentials"),
            ("did not run", "it did not run, so it is not a pass"),
        ],
    )
    def test_each_failing_posture_is_named_and_real(
        self, pipeline: str, described: str, pipeline_line: str
    ) -> None:
        assert described in reason("netassess-ingest")
        assert pipeline_line in pipeline

    def test_host_changes_are_posted_not_failed(self, pipeline: str) -> None:
        text = reason("netassess-ingest")

        assert "posts host" in text
        assert "reported, not a failure" in pipeline
