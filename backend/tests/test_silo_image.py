"""The artifact store runs SILO with Debian's current CA bundle (TheHub #61023).

SILO's distroless image carries one Debian package that matters to a scanner:
`ca-certificates`. Every published release up to RELEASE.2026-10-26 still ships
20250419~deb12u1, and DLA-4845-1 is fixed in 20250419~deb12u2. Distroless has
no shell and no package manager, so neither `apt-get upgrade` nor the
image-refresh recipes reach it; the fix is a two-stage build that takes the
fixed package's files from a pinned Debian 12 and lays them over the pinned
vendor image, dpkg record included, so the scanner reads the version that is
actually there.

These hold what makes that safe to rely on: compose builds the image rather
than running a vendor tag that might shadow it, every FROM is one exact pin,
the build refuses a package older than the fix, the shipped stage changes
nothing but those files, and the containers lane builds and scans the image
under the `pgsty/silo` name its findings already carry.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from mykronos.estate_images import derive
from mykronos.fingerprint import image_repository

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "concourse" / "docker-compose.yml"
RECIPE = REPO_ROOT / "deploy" / "images" / "silo"
DOCKERFILE = RECIPE / "Dockerfile"

#: The fixed package version (DLA-4845-1).
FIXED = "20250419~deb12u2"
VENDOR_FROM = re.compile(
    r"^pgsty/silo:RELEASE\.[0-9T-]+Z-distroless@sha256:[0-9a-f]{64}$"
)
DEBIAN_FROM = re.compile(r"^debian:12[\w.-]*@sha256:[0-9a-f]{64}$")


def _minio() -> dict[str, object]:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    return dict(services["minio"])


def _instructions() -> list[tuple[str, str]]:
    """(INSTRUCTION, argument) pairs, continuation lines joined, comments dropped."""
    logical: list[str] = []
    buffer = ""
    for raw in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append(buffer + line)
        buffer = ""
    pairs = []
    for line in logical:
        word, _, rest = line.partition(" ")
        pairs.append((word.upper(), rest.strip()))
    return pairs


def _stages() -> list[tuple[str, list[tuple[str, str]]]]:
    """(FROM argument, that stage's instructions), in order."""
    stages: list[tuple[str, list[tuple[str, str]]]] = []
    for word, arg in _instructions():
        if word == "FROM":
            stages.append((arg, []))
        elif stages:
            stages[-1][1].append((word, arg))
    return stages


class TestComposeBuildsIt:
    def test_the_minio_service_is_built_from_the_recipe(self) -> None:
        minio = _minio()
        build = minio.get("build")
        assert isinstance(build, dict), "minio is still a vendor `image:` with no build"
        assert build.get("context") == "../images/silo"

    def test_the_local_tag_can_never_be_a_vendor_tag(self) -> None:
        """A `build:` whose `image:` names a tag that exists on Docker Hub runs
        that tag whenever it is already in the local store, without building:
        the vendor's deb12u1 image, under the name of the fix."""
        minio = _minio()
        assert minio["image"] == "pgsty/silo:local"
        assert minio.get("pull_policy") == "build"

    def test_the_healthcheck_is_still_the_binary_s_own(self) -> None:
        healthcheck = _minio()["healthcheck"]
        assert isinstance(healthcheck, dict)
        assert healthcheck["test"] == ["CMD", "/usr/bin/silo", "healthcheck", "ready"]


class TestTheRecipe:
    def test_every_from_is_one_exact_pin(self) -> None:
        stages = _stages()
        assert len(stages) == 2, [image for image, _ in stages]
        (certs, _), (runtime, _) = stages
        certs_image, _, alias = certs.partition(" AS ")
        assert DEBIAN_FROM.match(certs_image), certs
        assert alias == "certs"
        assert VENDOR_FROM.match(runtime), runtime

    def test_the_vendor_pin_is_the_reviewed_release(self) -> None:
        """RELEASE.2026-11-12 (TheHub #61620): x/net 0.62.0, Go 1.27.4. The
        binary moves only by a reviewed change to this digest."""
        (_, _), (runtime, _) = _stages()
        assert runtime.startswith("pgsty/silo:RELEASE.2026-11-12T00-00-00Z-distroless@")
        assert runtime.endswith(
            "@sha256:a72e17773bdeb151999f9bf9d3bd842fb03850a577b730ab8c63343bb1f468fd"
        )

    def test_the_build_refuses_a_package_older_than_the_fix(self) -> None:
        (_, certs), _ = _stages()
        args = dict(arg.split("=", 1) for word, arg in certs if word == "ARG" and "=" in arg)
        assert args.get("CA_CERTIFICATES_FLOOR") == FIXED
        runs = " ".join(arg for word, arg in certs if word == "RUN")
        assert 'dpkg --compare-versions "${version}" ge "${CA_CERTIFICATES_FLOOR}"' in runs

    def test_the_shipped_stage_only_copies_files_from_the_certs_stage(self) -> None:
        """Distroless has no shell, so a RUN here cannot work, and anything
        else (USER, ENTRYPOINT, CMD, ENV) would change how SILO runs."""
        _, (_, runtime) = _stages()
        assert runtime, "the shipped stage is the vendor image unchanged"
        assert {word for word, _ in runtime} == {"COPY"}, runtime
        assert all(arg.startswith("--from=certs ") for _, arg in runtime), runtime

    def test_the_bundle_and_its_dpkg_record_move_together(self) -> None:
        """The scanner reads the version from the dpkg record, the TLS stack
        reads the bundle; replacing one without the other is either a fix the
        scanner cannot see or a version claim with the old certificates."""
        _, (_, runtime) = _stages()
        targets = {arg.split()[-1] for _, arg in runtime}
        assert "/etc/ssl/certs/ca-certificates.crt" in targets
        assert "/var/lib/dpkg/status.d/" in targets


class TestTheContainersLaneScansIt:
    def test_the_lane_builds_it_rather_than_pulling_the_vendor_tag(self) -> None:
        derivation = derive(REPO_ROOT)
        assert not [image for image in derivation.images() if "pgsty/silo" in image]
        builds = {build.name: build for build in derivation.builds()}
        assert "pgsty/silo" in builds, builds
        assert builds["pgsty/silo"].context == "deploy/images/silo"
        assert builds["pgsty/silo"].dockerfile == "deploy/images/silo/Dockerfile"
        assert builds["pgsty/silo"].role == "service"

    def test_the_built_image_keeps_the_vendor_image_s_finding_identity(self) -> None:
        """The lane pushes `<registry>/pgsty/silo:<sha>`; identity drops the
        host and the tag, so the deb12u1 finding is the same finding and goes
        absent rather than being re-keyed beside a new one."""
        vendor = "pgsty/silo:RELEASE.2026-10-15T00-00-00Z-distroless@sha256:" + "7" * 64
        assert image_repository("registry.example:5000/pgsty/silo:abc123") == image_repository(
            vendor
        )
