"""A published image must name the commit it is tagged with (#382).

Three images were each tagged with their commit; two could not say it, and
nothing failed. The containers lane now reads the build SHA the image records
from the config Trivy already pulled, and the adapter reports an image that
records nothing apart from one that records the wrong commit -- different
fixes, different severities, never one rule.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos import image_provenance
from mykronos.adapters import containers_trivy
from mykronos.adapters.base import ScanContext
from mykronos.fingerprint import compute_finding_id
from mykronos.image_provenance import RULE_ABSENT, RULE_MISMATCH

REPO_ROOT = Path(__file__).resolve().parents[2]

SHA = "6b250a56878323b6c5f53747a398bc3ae36405e6"
OTHER = "0123456789abcdef0123456789abcdef01234567"
IMAGE = f"192.168.1.10:5000/mykronos-frontend:{SHA}"


def _config(*env: str) -> dict[str, object]:
    """An OCI image config, the shape `crane config` and `docker inspect` print."""
    return {"config": {"Env": ["PATH=/usr/local/bin:/usr/bin", *env]}}


def _trivy_json(*env: str) -> dict[str, object]:
    """Trivy's JSON report, which nests the same config at Metadata.ImageConfig."""
    return {"ArtifactName": IMAGE, "Metadata": {"ImageConfig": _config(*env)}, "Results": []}


def _sarif(properties: dict[str, object] | None) -> dict[str, object]:
    run: dict[str, object] = {"tool": {"driver": {"name": "Trivy", "version": "0.70.0"}},
                              "results": []}
    if properties is not None:
        run["properties"] = properties
    return {"version": "2.1.0", "runs": [run]}


def _context(commit: str = SHA) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability="containers",
        tool_name="trivy",
        tool_version="0.70.0",
        commit_sha=commit,
        branch="main",
    )


def _normalize(env: tuple[str, ...], image: str = IMAGE, commit: str = SHA):
    properties: dict[str, object] = {"imageName": image}
    image_provenance.stamp(properties, _config(*env))
    return containers_trivy.normalize(json.dumps(_sarif(properties)).encode(), _context(commit))


class TestWhatTheImageRecords:
    def test_reads_the_stamp_from_an_image_config(self) -> None:
        assert image_provenance.recorded_build_sha(_config(f"MYKRONOS_BUILD_SHA={SHA}")) == (
            "MYKRONOS_BUILD_SHA", SHA,
        )

    def test_reads_it_from_a_trivy_report_too(self) -> None:
        report = _trivy_json(f"MYKRONOS_BUILD_SHA={SHA}")
        assert image_provenance.recorded_build_sha(report) == ("MYKRONOS_BUILD_SHA", SHA)

    def test_thehubs_spelling_counts(self) -> None:
        assert image_provenance.recorded_build_sha(_config(f"HUB_BUILD_SHA={SHA}"))[1] == SHA

    @pytest.mark.parametrize(
        "env",
        [(), ("MYKRONOS_BUILD_SHA=",), ("HUB_BUILD_SHA=unknown",)],
        ids=["no-variable", "empty-build-arg", "unknown"],
    )
    def test_nothing_usable_is_none(self, env: tuple[str, ...]) -> None:
        """#382's table: `HUB_BUILD_SHA=unknown` is MISSING, not a value."""
        assert image_provenance.recorded_build_sha(_config(*env))[1] is None


class TestTheVerdict:
    def test_match(self) -> None:
        assert image_provenance.assess(IMAGE, "MYKRONOS_BUILD_SHA", SHA, OTHER).verdict == "match"

    def test_an_abbreviated_stamp_matches_its_full_tag(self) -> None:
        verdict = image_provenance.assess(IMAGE, "MYKRONOS_BUILD_SHA", SHA[:12], SHA).verdict
        assert verdict == "match"

    def test_mismatch_is_against_the_tag(self) -> None:
        """The tag is the claim being checked, even when the scanned commit
        happens to agree with the stamp."""
        result = image_provenance.assess(IMAGE, "MYKRONOS_BUILD_SHA", OTHER, OTHER)
        assert result.verdict == "mismatch"
        assert result.expected == SHA

    def test_a_tag_that_is_not_a_commit_falls_back_to_the_scanned_one(self) -> None:
        latest = IMAGE.replace(SHA, "latest")
        assert image_provenance.assess(latest, "MYKRONOS_BUILD_SHA", SHA, SHA).verdict == "match"
        assert image_provenance.assess(latest, "X", OTHER, SHA).verdict == "mismatch"

    def test_absent(self) -> None:
        assert image_provenance.assess(IMAGE, "MYKRONOS_BUILD_SHA", None, SHA).verdict == "absent"

    def test_a_registry_port_is_not_a_tag(self) -> None:
        assert image_provenance.tag_of("192.168.1.10:5000/mykronos-backend") == ""
        assert image_provenance.tag_of(f"r:5000/x:{SHA}@sha256:abc") == SHA


class TestTheContainersAdapterReportsIt:
    def test_absent_is_a_medium_finding_of_its_own_rule(self) -> None:
        outcome = _normalize(())

        [finding] = outcome.findings
        assert finding.rule_id == RULE_ABSENT
        assert finding.severity == "medium"
        assert "mykronos-frontend" in finding.title
        assert finding.raw_finding_json["verdict"] == "absent"

    def test_mismatch_is_a_distinct_higher_severity_finding(self) -> None:
        outcome = _normalize((f"MYKRONOS_BUILD_SHA={OTHER}",))

        [finding] = outcome.findings
        assert finding.rule_id == RULE_MISMATCH
        assert finding.severity == "high"
        assert OTHER in finding.description and SHA in finding.description

    def test_a_match_says_nothing(self) -> None:
        outcome = _normalize((f"MYKRONOS_BUILD_SHA={SHA}",))

        assert outcome.findings == []
        assert outcome.warnings == []

    def test_an_image_nobody_stamped_was_not_asked(self) -> None:
        """A third-party image records no commit of ours. "Not checked" must
        not read as "absent"."""
        raw = json.dumps(_sarif({"imageName": "redis:7-alpine"})).encode()

        assert containers_trivy.normalize(raw, _context()).findings == []

    def test_the_same_image_failing_next_commit_is_the_same_finding(self) -> None:
        """Repo-level identity, with no SHA in the title: one open finding per
        image until a build fixes it, not one per commit."""
        ids = set()
        for commit in (SHA, OTHER):
            [finding] = _normalize((), image=f"r:5000/mykronos-frontend:{commit}",
                                   commit=commit).findings
            ids.add(
                compute_finding_id(
                    repo_full_name="ToddGBenson/mykronos",
                    capability="containers",
                    rule_id=finding.rule_id,
                    title=finding.title,
                )
            )
        assert len(ids) == 1


class TestAnnotate:
    def test_only_reports_with_a_json_twin_are_stamped(self, tmp_path: Path) -> None:
        (tmp_path / "trivy-mykronos-frontend.sarif").write_text(
            json.dumps(_sarif({"imageName": IMAGE})), encoding="utf-8"
        )
        (tmp_path / "trivy-mykronos-frontend.json").write_text(
            json.dumps(_trivy_json()), encoding="utf-8"
        )
        (tmp_path / "trivy-estate-redis.sarif").write_text(
            json.dumps(_sarif({"imageName": "redis:7-alpine"})), encoding="utf-8"
        )

        assert image_provenance.main(["--annotate", str(tmp_path)]) == 0

        ours = json.loads((tmp_path / "trivy-mykronos-frontend.sarif").read_text("utf-8"))
        theirs = json.loads((tmp_path / "trivy-estate-redis.sarif").read_text("utf-8"))
        assert ours["runs"][0]["properties"][image_provenance.PROPERTY] == {
            "variable": "MYKRONOS_BUILD_SHA",
            "recorded": None,
        }
        assert image_provenance.PROPERTY not in theirs["runs"][0]["properties"]
        # And end to end: the stamped report produces the absent finding.
        outcome = containers_trivy.normalize(
            (tmp_path / "trivy-mykronos-frontend.sarif").read_bytes(), _context()
        )
        assert [f.rule_id for f in outcome.findings] == [RULE_ABSENT]


class TestTheLaneIsWired:
    """Read out of the committed pipeline: the regression is a change to it."""

    def _containers(self) -> dict[str, object]:
        path = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
        jobs = {j["name"]: j for j in yaml.safe_load(path.read_text("utf-8"))["jobs"]}
        return jobs["containers"]

    def test_published_images_are_scanned_to_json_and_converted(self) -> None:
        scan = next(s for s in self._containers()["plan"] if s.get("task") == "scan-images")
        body = "\n".join(scan["config"]["run"]["args"])
        assert '--format json --output "results/trivy-${image}.json"' in body
        assert "trivy convert --format sarif" in body

    def test_the_upload_stamps_before_it_uploads(self) -> None:
        scan = next(s for s in self._containers()["plan"] if s.get("task") == "scan-images")
        body = "\n".join(scan["ensure"]["config"]["run"]["args"])
        assert body.index("mykronos.image_provenance") < body.index("mykronos.upload")


class TestTheHubLaneIsWired:
    """TheHub #60929: the same check in TheHub's containers lane.

    Only the mykronos lane stamped its reports, so a thehub image that could
    not name its commit produced no finding at all. These read the committed
    thehub.yml and then run the files it names through the real annotate step
    and adapter, so a lane that stops writing the JSON twin goes red here.
    """

    THEHUB_IMAGE = f"registry.example:5000/thehub:{SHA}"

    def _containers(self) -> dict[str, Any]:
        path = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
        jobs = {j["name"]: j for j in yaml.safe_load(path.read_text("utf-8"))["jobs"]}
        return jobs["containers"]

    def _scan(self) -> dict[str, Any]:
        return next(s for s in self._containers()["plan"] if s.get("task") == "scan-image")

    def _report_paths(self) -> tuple[str, str]:
        """(json, sarif) the thehub image's scan writes, as the lane spells them."""
        body = "\n".join(self._scan()["config"]["run"]["args"])
        start = body.index('trivy image "${REGISTRY}/thehub:${SHA}"')
        own = body[start : body.index("estate_total=0")]
        json_out = re.search(r"--format json --output (\S+)", own)
        convert = re.search(
            r"trivy convert --format sarif\s*\\?\s*--output (\S+) (\S+)", own
        )
        assert json_out and convert, "the thehub image is not scanned to JSON and converted"
        assert convert.group(2) == json_out.group(1), "the SARIF is not converted from the JSON"
        return json_out.group(1), convert.group(1)

    def _run(self, tmp_path: Path, *env: str) -> list[Any]:
        json_path, sarif_path = self._report_paths()
        results = tmp_path / "results"
        results.mkdir()
        sarif = results / Path(sarif_path).name
        twin = results / Path(json_path).name
        # annotate pairs X.sarif with X.json: the lane must name them so.
        assert twin == sarif.with_suffix(".json"), (json_path, sarif_path)
        sarif.write_text(json.dumps(_sarif({"imageName": self.THEHUB_IMAGE})), "utf-8")
        report = {"ArtifactName": self.THEHUB_IMAGE,
                  "Metadata": {"ImageConfig": _config(*env)}, "Results": []}
        twin.write_text(json.dumps(report), "utf-8")
        assert image_provenance.main(["--annotate", str(results)]) == 0
        context = ScanContext(
            repo_full_name="ToddGBenson/TheHub",
            capability="containers",
            tool_name="trivy",
            tool_version="0.70.0",
            commit_sha=SHA,
            branch="develop",
        )
        return containers_trivy.normalize(sarif.read_bytes(), context).findings

    def test_an_unstamped_thehub_image_raises_a_finding(self, tmp_path: Path) -> None:
        # `unknown` is what every thehub image carried before the build arg.
        [finding] = self._run(tmp_path, "HUB_BUILD_SHA=unknown")
        assert finding.rule_id == RULE_ABSENT
        assert "thehub" in finding.title
        assert finding.raw_finding_json["variable"] == "HUB_BUILD_SHA"

    def test_a_thehub_image_naming_another_commit_is_a_mismatch(self, tmp_path: Path) -> None:
        [finding] = self._run(tmp_path, f"HUB_BUILD_SHA={OTHER}")
        assert finding.rule_id == RULE_MISMATCH

    def test_a_thehub_image_naming_its_commit_says_nothing(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, f"HUB_BUILD_SHA={SHA}") == []

    def test_the_upload_stamps_before_it_uploads_and_never_instead(self) -> None:
        body = "\n".join(self._scan()["ensure"]["config"]["run"]["args"])
        stamp = body.index("python -m mykronos.image_provenance --annotate results")
        assert stamp < body.index("python -m mykronos.upload")
        # PS-3: the upload runs after a failed scan; a stamp that cannot run
        # must not take the upload down with it under `set -e`.
        line = body[stamp : body.index("\n", body.index("\n", stamp) + 1)]
        assert "|| echo" in line, line

    def test_the_build_passes_the_commit_the_image_records(self) -> None:
        """AC: all three images name their commit. thehub records it as
        HUB_BUILD_SHA only when the build passes it; mykronos's two images
        are asserted by the lane test above and their Dockerfiles."""
        path = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
        build = yaml.safe_load(path.read_text("utf-8"))
        jobs = {j["name"]: j for j in build["jobs"]}
        text = json.dumps(jobs["build"])
        assert '--build-arg \\"HUB_BUILD_SHA=${SHA}\\"' in text
        assert '--destination \\"${REGISTRY}/thehub:${SHA}\\"' in text
        for dockerfile in ("backend/Dockerfile", "frontend/Dockerfile"):
            source = (REPO_ROOT / dockerfile).read_text("utf-8")
            assert "ENV MYKRONOS_BUILD_SHA=${MYKRONOS_BUILD_SHA}" in source, dockerfile
