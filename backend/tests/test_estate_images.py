"""Deriving the images this estate actually runs (#427).

The containers lane scanned four images because it only ever scanned images it
*built*: the workflow template builds every Dockerfile it finds, and the
Concourse jobs scan the tags `publish` pushed. Vault, MinIO, Concourse,
Postgres, Redis, nginx and a `registry:2` from 2023 were never in scope for
anything, which the lake shows as an absence — not one `musl`, `busybox`,
`apk-tools`, `nginx`, `redis` or `postgres` package has ever been recorded by
any container scan, for any repository.

These tests are mostly about the *derivation*, not the scan, because that is
where the next defect would be. A hardcoded list of fifteen images would close
the issue and be wrong the first time a service is added, so the list comes
from the compose files that start the containers. The last class here checks
that against this repository's real `deploy/` tree, since a derivation that is
correct on fixtures and empty on the estate would look exactly like success.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

from mykronos.estate_images import (
    ComposeService,
    Derivation,
    classify_tag,
    derive,
    discover_compose_files,
    interpolate,
    main,
    services_from_compose,
    split_reference,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _estate() -> tuple[str, ...]:
    """This repository's own derived image list, read once."""
    return tuple(derive(REPO_ROOT).images())


class TestInterpolation:
    def test_a_default_is_used_when_the_variable_is_unset(self) -> None:
        resolved, unresolved = interpolate("${MYKRONOS_IMAGE_BACKEND:-mykronos-backend:latest}", {})
        assert resolved == "mykronos-backend:latest"
        assert unresolved == []

    def test_the_variable_wins_when_it_is_set(self) -> None:
        resolved, _ = interpolate(
            "${MYKRONOS_IMAGE_BACKEND:-mykronos-backend:latest}",
            {"MYKRONOS_IMAGE_BACKEND": "localhost:5000/mykronos-backend:abc123"},
        )
        assert resolved == "localhost:5000/mykronos-backend:abc123"

    def test_an_unset_variable_with_no_default_is_reported_not_guessed(self) -> None:
        """A reference that still contains a variable is not scannable. Naming
        it here beats a Trivy failure three steps away."""
        resolved, unresolved = interpolate("${REGISTRY}/thehub:${SHA}", {})
        assert unresolved == ["REGISTRY", "SHA"]
        assert "$" not in resolved

    def test_a_bare_dollar_name_is_interpolated_too(self) -> None:
        resolved, unresolved = interpolate("$REGISTRY/thehub:v1", {"REGISTRY": "localhost:5000"})
        assert resolved == "localhost:5000/thehub:v1"
        assert unresolved == []


class TestReferenceSplitting:
    @pytest.mark.parametrize(
        ("reference", "repository", "tag"),
        [
            ("postgres:15", "postgres", "15"),
            ("hashicorp/vault:1.21.4", "hashicorp/vault", "1.21.4"),
            ("ghcr.io/zaproxy/zaproxy:2.17.0", "ghcr.io/zaproxy/zaproxy", "2.17.0"),
            ("nginx", "nginx", ""),
            # The colon that is a port, not a tag.
            ("localhost:5000/mykronos-backend", "localhost:5000/mykronos-backend", ""),
            ("localhost:5000/mykronos-backend:abc", "localhost:5000/mykronos-backend", "abc"),
            ("alpine@sha256:deadbeef", "alpine", "sha256:deadbeef"),
        ],
    )
    def test_the_tag_is_the_colon_after_the_last_slash(
        self, reference: str, repository: str, tag: str
    ) -> None:
        assert split_reference(reference) == (repository, tag)


class TestTagKind:
    """What a `docker pull` could possibly buy.

    Measured, not assumed: re-pulling every tag this estate runs removes about
    13% of its HIGH/CRITICAL findings, because most of them sit on
    exact-version pins where a pull is a no-op by definition.
    """

    @pytest.mark.parametrize(
        ("reference", "kind"),
        [
            ("nginx:alpine", "floating"),
            ("redis:latest", "floating"),
            ("nginx", "floating"),
            ("postgres:15", "major_line"),
            ("pgvector/pgvector:pg16", "major_line"),
            ("redis:7-alpine", "major_line"),
            ("registry:2", "major_line"),
            ("hashicorp/vault:1.21.4", "pinned"),
            ("concourse/concourse:7.14", "pinned"),
            ("alpine:3.19", "pinned"),
            ("minio/minio:RELEASE.2025-04-22T22-12-26Z", "pinned"),
            ("alpine@sha256:deadbeef", "digest"),
        ],
    )
    def test_the_tag_says_how_much_a_pull_could_change(self, reference: str, kind: str) -> None:
        assert classify_tag(reference) == kind


class TestWhatIsSkipped:
    """An image built here is already scanned; scanning it again by tag would
    file a second copy of every finding under a second path."""

    def test_a_service_with_a_build_section_is_not_an_upstream_image(self) -> None:
        services, _ = services_from_compose(
            "services:\n  web:\n    image: myapp:latest\n    build: .\n", "compose.yml"
        )
        assert [service.origin for service in services] == ["built_here"]
        assert "build:" in services[0].reason

    def test_a_deploy_time_override_is_this_pipeline_s_own_artefact(self) -> None:
        """`postgres:15` and `mykronos-backend:latest` are structurally
        identical -- one unqualified segment and a tag -- so the classifier
        reads how the line is written rather than guessing from the name."""
        services, _ = services_from_compose(
            "services:\n"
            "  backend:\n"
            "    image: ${MYKRONOS_IMAGE_BACKEND:-mykronos-backend:latest}\n",
            "compose.yml",
        )
        assert [service.origin for service in services] == ["built_here"]

    def test_a_configurable_registry_in_front_of_an_upstream_image_is_still_upstream(self) -> None:
        """Only a *whole* substitution is the deploy-time override. Treating
        every `$` as first-party would skip a mirrored upstream image
        silently, which is the failure this issue is about."""
        services, _ = services_from_compose(
            "services:\n  a:\n    image: ${BASE:-docker.io}/redis:7-alpine\n", "compose.yml"
        )
        assert [service.origin for service in services] == ["upstream"]
        assert services[0].reference == "docker.io/redis:7-alpine"

    def test_a_literal_reference_is_upstream(self) -> None:
        services, _ = services_from_compose(
            "services:\n  db:\n    image: postgres:15\n", "compose.yml"
        )
        assert [service.origin for service in services] == ["upstream"]

    def test_an_unset_variable_with_no_default_is_unresolved_not_upstream(self) -> None:
        services, _ = services_from_compose(
            "services:\n  db:\n    image: ${DB_IMAGE}\n", "compose.yml"
        )
        assert [service.origin for service in services] == ["unresolved"]

    def test_an_unresolved_image_is_never_handed_to_the_scanner(self) -> None:
        derivation = _derivation_of(
            [ComposeService("compose.yml", "db", "${DB_IMAGE}", "", "unresolved", "unset")]
        )
        assert derivation.images() == []


class TestTheListIsDerived:
    def test_the_same_image_run_by_four_services_is_scanned_once(self) -> None:
        """Four of TheHub's containers run `pgvector/pgvector:pg16`. Scanning
        it four times files four copies of one finding under one path."""
        services, _ = services_from_compose(
            "services:\n"
            "  a:\n    image: pgvector/pgvector:pg16\n"
            "  b:\n    image: pgvector/pgvector:pg16\n"
            "  c:\n    image: redis:7-alpine\n",
            "compose.yml",
        )
        derivation = _derivation_of(services)
        assert derivation.images() == ["pgvector/pgvector:pg16", "redis:7-alpine"]

    def test_a_new_service_joins_the_scan_with_no_list_to_update(self) -> None:
        """The property the whole design exists for: a hardcoded list of the
        fifteen images running today is the next defect."""
        before, _ = services_from_compose(
            "services:\n  db:\n    image: postgres:15\n", "compose.yml"
        )
        after, _ = services_from_compose(
            "services:\n  db:\n    image: postgres:15\n  cache:\n    image: redis:7-alpine\n",
            "compose.yml",
        )
        assert _derivation_of(after).images() == ["postgres:15", "redis:7-alpine"]
        assert _derivation_of(before).images() == ["postgres:15"]

    def test_vendored_and_fixture_compose_files_are_not_searched(self, tmp_path: Path) -> None:
        (tmp_path / "docker-compose.yml").write_text("services:\n  db:\n    image: postgres:15\n")
        vendored = tmp_path / "node_modules" / "thing"
        vendored.mkdir(parents=True)
        (vendored / "docker-compose.yml").write_text("services:\n  x:\n    image: evil:1\n")
        assert [path.name for path in discover_compose_files(tmp_path)] == ["docker-compose.yml"]
        assert derive(tmp_path).images() == ["postgres:15"]

    def test_both_spellings_and_both_names_are_found(self, tmp_path: Path) -> None:
        (tmp_path / "compose.yaml").write_text("services:\n  a:\n    image: redis:7-alpine\n")
        (tmp_path / "docker-compose.prod.yml").write_text(
            "services:\n  b:\n    image: nginx:alpine\n"
        )
        assert derive(tmp_path).images() == ["nginx:alpine", "redis:7-alpine"]

    def test_an_unparseable_compose_file_warns_instead_of_failing_the_lane(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "docker-compose.yml").write_text("services:\n  a:\n   image: [ unclosed\n")
        (tmp_path / "compose.yml").write_text("services:\n  b:\n    image: redis:7-alpine\n")
        derivation = derive(tmp_path)
        assert derivation.images() == ["redis:7-alpine"]
        assert any("could not be parsed" in warning for warning in derivation.warnings)

    def test_no_compose_file_is_reported_rather_than_looking_like_success(
        self, tmp_path: Path
    ) -> None:
        derivation = derive(tmp_path)
        assert derivation.images() == []
        assert any("no compose file" in warning for warning in derivation.warnings)


class TestThisEstate:
    """The derivation against the real `deploy/` tree.

    A derivation that passes on fixtures and returns nothing here would look
    exactly like success, which is the failure mode #427 is about.
    """

    @pytest.mark.parametrize(
        "reference",
        [
            "hashicorp/vault:1.21.4",
            "concourse/concourse:7.14",
            "minio/minio:RELEASE.2025-04-22T22-12-26Z",
            "registry:2",
            "postgres:15",
            "ghcr.io/zaproxy/zaproxy:2.17.0",
        ],
    )
    def test_the_images_427_names_are_now_in_scope(self, reference: str) -> None:
        assert reference in _estate()

    def test_the_application_images_are_left_to_the_lane_that_builds_them(self) -> None:
        assert not [image for image in _estate() if image.startswith("mykronos-")]

    def test_nothing_unresolved_reaches_the_scanner(self) -> None:
        assert not [image for image in _estate() if "$" in image or not image]


class TestTheLanesThatRunHere:
    """The wiring, read out of the committed pipelines.

    A module nothing calls is not coverage. Both containers jobs enumerated
    images by name -- `for image in mykronos-backend mykronos-frontend`, and
    `trivy image .../thehub:$SHA` -- which is exactly why the estate's other
    images were never scanned, and it is a two-line revert away from being
    true again. Read from the file, with no network, for the reason
    `test_pipeline_gate_wiring.py` gives: the regression this guards against
    is a change to the file.
    """

    @pytest.mark.parametrize("pipeline", ["mykronos.yml", "thehub.yml"])
    def test_the_containers_job_derives_its_image_list(self, pipeline: str) -> None:
        job = _containers_job(pipeline)
        tasks = [step["task"] for step in job["plan"] if "task" in step]
        assert "derive-estate-images" in tasks, tasks

        derive = next(step for step in job["plan"] if step.get("task") == "derive-estate-images")
        body = "\n".join(derive["config"]["run"]["args"])
        assert "mykronos.estate_images" in body
        assert "estate/images.txt" in body

    @pytest.mark.parametrize("pipeline", ["mykronos.yml", "thehub.yml"])
    def test_the_scan_reads_the_derived_list_rather_than_a_list_of_names(
        self, pipeline: str
    ) -> None:
        body = _scan_task_body(pipeline)
        assert "done < estate/images.txt" in body
        executable = "\n".join(
            line for line in body.splitlines() if not line.lstrip().startswith("#")
        )
        for hardcoded in (
            "hashicorp/vault",
            "minio/minio",
            "concourse/concourse",
            "registry:2",
            "redis:7-alpine",
            "pgvector",
        ):
            assert hardcoded not in executable

    @pytest.mark.parametrize("pipeline", ["mykronos.yml", "thehub.yml"])
    def test_an_estate_image_that_would_not_scan_fails_the_lane(self, pipeline: str) -> None:
        body = _scan_task_body(pipeline)
        assert 'test -s "results/trivy-estate-${safe}.sarif"' in body

    @pytest.mark.parametrize("pipeline", ["mykronos.yml", "thehub.yml"])
    def test_each_estate_image_gets_its_own_report(self, pipeline: str) -> None:
        """A shared report name is how 600 container results became 118."""
        assert 'results/trivy-estate-${safe}.sarif' in _scan_task_body(pipeline)


def _containers_job(pipeline: str) -> dict[str, object]:
    path = REPO_ROOT / "deploy" / "concourse" / "pipelines" / pipeline
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    jobs = {job["name"]: job for job in document["jobs"]}
    # A floor before a conclusion: a pipeline that parsed to no jobs would
    # pass every assertion below by having nothing to contradict them.
    assert jobs, f"{pipeline} parsed to no jobs"
    return dict(jobs["containers"])


def _scan_task_body(pipeline: str) -> str:
    job = _containers_job(pipeline)
    plan = job["plan"]
    assert isinstance(plan, list)
    scan = next(
        step for step in plan if str(step.get("task", "")).startswith("scan-image")
    )
    return "\n".join(scan["config"]["run"]["args"])


class TestTheCommandLine:
    """The pipelines consume this as a file, so the output contract is part of
    the change rather than a convenience."""

    def test_text_is_one_reference_per_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  a:\n    image: postgres:15\n  b:\n    image: redis:7-alpine\n"
        )
        assert main(["--root", str(tmp_path)]) == 0
        assert capsys.readouterr().out == "postgres:15\nredis:7-alpine\n"

    def test_json_carries_the_provenance_and_the_tag_kind(self, tmp_path: Path) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  vault:\n    image: hashicorp/vault:1.21.4\n"
        )
        out = tmp_path / "images.json"
        assert main(["--root", str(tmp_path), "--format", "json", "--output", str(out)]) == 0
        payload = json.loads(out.read_text())
        assert payload["images"] == [
            {
                "reference": "hashicorp/vault:1.21.4",
                "tag_kind": "pinned",
                "run_by": ["docker-compose.yml::vault"],
            }
        ]

    def test_the_summary_goes_to_stderr_so_the_list_stays_pipeable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  a:\n    image: postgres:15\n"
            "  b:\n    image: ${MYKRONOS_IMAGE_BACKEND:-mykronos-backend:latest}\n"
        )
        assert main(["--root", str(tmp_path)]) == 0
        captured = capsys.readouterr()
        assert captured.out == "postgres:15\n"
        assert "skipped" in captured.err
        assert "major_line" in captured.err

    def test_a_missing_root_is_an_error_rather_than_an_empty_list(self, tmp_path: Path) -> None:
        assert main(["--root", str(tmp_path / "nope")]) == 2

    def test_the_process_environment_is_off_unless_asked_for(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The same tree must derive the same list wherever it runs, or the
        scan depends on whoever's shell started it."""
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  a:\n    image: ${BASE:-docker.io}/postgres:15\n"
        )
        monkeypatch.setenv("BASE", "someone-elses-mirror.invalid")
        assert main(["--root", str(tmp_path)]) == 0
        assert capsys.readouterr().out == "docker.io/postgres:15\n"

    def test_set_supplies_a_compose_variable(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  a:\n    image: ${BASE}/redis:7-alpine\n"
        )
        assert main(["--root", str(tmp_path), "--set", "BASE=docker.io"]) == 0
        assert capsys.readouterr().out == "docker.io/redis:7-alpine\n"


def _derivation_of(services: list[ComposeService]) -> Derivation:
    derivation = Derivation()
    derivation.services.extend(services)
    return derivation
