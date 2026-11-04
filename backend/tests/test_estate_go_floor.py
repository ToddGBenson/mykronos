"""The estate's Go binaries are built on a standard library past CVE-2026-111943.

The containers lane reported CVE-2026-111943 (HIGH, Go standard library, fixed
in 1.26.10 and 1.27.3) in five static binaries this repository declares:
`bin/vault`, Concourse's `vrf`, SILO's `usr/bin/silo`, the registry-src
`bin/registry`, and `gosu` in the Concourse database's Postgres image. No
package upgrade reaches a Go binary's standard library, so the only fix is a
build on a newer toolchain: a vendor release built on one, or our own rebuild.

Measured 2026-11-04 by reading each binary's build stamp, and confirmed with
Trivy 0.73.0 on a current database (CVE-2026-111943 count, old -> new pin):

    hashicorp/vault      2.2.0 -> 2.2.1                        go1.27.3   1 -> 0
    concourse/concourse  8.3.1 -> 8.3.3                        go1.27.3  26 -> 0
    pgsty/silo           RELEASE.2026-10-15 -> RELEASE.2026-10-26  go1.27.3   1 -> 0
    registry-src         builder golang:1.27.2 -> golang:1.27.3

Each new vendor pin also scans strictly better overall (vault 3 -> 2 high,
Concourse 117 -> 7 high and 5 -> 0 critical, SILO 3 -> 1 high).

These are floors, not exact pins: image-refresh moves tags and digests
(mykronos #976), so a later release or a `-p<date>` derivative passes, and only
a pin back onto a build that links the vulnerable standard library fails.

Not covered: `gosu` in `postgres:15`. The newest `postgres:15` still ships a
gosu built on go1.24.6, so there is no vendor build to move to, and that one
finding is a risk acceptance, not a pin.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "concourse" / "docker-compose.yml"
REGISTRY_SRC = REPO_ROOT / "deploy" / "images" / "registry-src" / "Dockerfile"
SETUP = REPO_ROOT / "deploy" / "concourse" / "setup.ps1"

#: The first Go release on each line that carries the fix.
GO_FIXED = {(1, 26): (1, 26, 10), (1, 27): (1, 27, 3)}

#: The oldest vendor release measured to be built on a fixed Go.
VERSION_FLOORS: dict[str, tuple[int, ...]] = {
    "hashicorp/vault": (2, 2, 1),
    "concourse/concourse": (8, 3, 3),
}
#: SILO tags are release dates, so its floor is one.
SILO_FLOOR = "2026-10-26"

_PATCH_SUFFIX = re.compile(r"-p\d{8}$")
_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_SILO_TAG = re.compile(r"^RELEASE\.(\d{4}-\d{2}-\d{2})T")


def _compose() -> dict[str, Any]:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _references() -> list[tuple[str, str]]:
    """Every (where, image reference) the compose file declares.

    Both the service's `image:` and its `x-mykronos-build` base and publish
    name count: image-refresh builds the derivative on the base, so a base
    that lagged the image would rebuild the vulnerable binary.
    """
    found: list[tuple[str, str]] = []
    for name, service in (_compose().get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        if isinstance(service.get("image"), str):
            found.append((f"{name}.image", service["image"]))
        build = service.get("x-mykronos-build")
        if isinstance(build, dict):
            for key in ("base", "publish"):
                if isinstance(build.get(key), str):
                    found.append((f"{name}.x-mykronos-build.{key}", build[key]))
    return found


def _split(reference: str) -> tuple[str, str]:
    """`[${REGISTRY}/|host:port/]repo:tag[@digest]` -> (repo, tag)."""
    name = reference.split("@", 1)[0]
    name = re.sub(r"^\$\{[^}]*\}/", "", name)
    head, _, rest = name.partition("/")
    if rest and (":" in head or "." in head or head == "localhost"):
        name = rest
    repo, _, tag = name.rpartition(":")
    return (repo, tag) if repo else (name, "")


def _version(tag: str) -> tuple[int, ...] | None:
    match = _SEMVER.match(_PATCH_SUFFIX.sub("", tag))
    return tuple(int(part) for part in match.groups()) if match else None


def _pins(repository: str) -> list[tuple[str, str]]:
    return [(where, ref) for where, ref in _references() if _split(ref)[0] == repository]


class TestVendorPins:
    @pytest.mark.parametrize("repository", sorted(VERSION_FLOORS))
    def test_every_pin_is_a_release_built_on_a_fixed_go(self, repository: str) -> None:
        pins = _pins(repository)
        assert pins, f"{repository} is no longer declared in {COMPOSE.name}"
        floor = VERSION_FLOORS[repository]
        for where, reference in pins:
            version = _version(_split(reference)[1])
            assert version is not None, f"{where}: {reference} is not an exact x.y.z release"
            assert version >= floor, (
                f"{where}: {reference} predates {'.'.join(map(str, floor))}, the first "
                f"{repository} release built on a Go past CVE-2026-111943"
            )

    def test_silo_is_a_release_built_on_a_fixed_go(self) -> None:
        pins = _pins("pgsty/silo")
        assert pins, f"pgsty/silo is no longer declared in {COMPOSE.name}"
        for where, reference in pins:
            match = _SILO_TAG.match(_split(reference)[1])
            assert match, f"{where}: {reference} is not a dated RELEASE tag"
            assert match.group(1) >= SILO_FLOOR, (
                f"{where}: {reference} predates RELEASE.{SILO_FLOOR}, the first SILO "
                "release built on a Go past CVE-2026-111943"
            )

    def test_every_vendor_pin_is_held_by_digest(self) -> None:
        # A floor on a tag alone would pass while the digest it named moved.
        for repository in [*VERSION_FLOORS, "pgsty/silo"]:
            for where, reference in _pins(repository):
                if where.endswith(".publish"):
                    continue
                assert re.search(r"@sha256:[0-9a-f]{64}$", reference), f"{where}: {reference}"

    def test_setup_generates_keys_with_the_concourse_the_estate_runs(self) -> None:
        # setup.ps1 runs the Concourse image to mint keys; a stale tag there
        # pulls a second, older Concourse onto the host.
        declared = {_split(ref)[1] for _, ref in _pins("concourse/concourse")}
        used = set(re.findall(r"concourse/concourse:([\w.-]+)", SETUP.read_text(encoding="utf-8")))
        assert used, "setup.ps1 no longer names a Concourse image"
        assert used <= declared, f"setup.ps1 uses {sorted(used)}, compose declares {sorted(declared)}"


class TestRegistryRebuild:
    def test_the_builder_toolchain_carries_the_fix(self) -> None:
        text = REGISTRY_SRC.read_text(encoding="utf-8")
        match = re.search(r"^FROM golang:(\d+)\.(\d+)\.(\d+)[\w.-]*@sha256:[0-9a-f]{64} AS build$", text, re.M)
        assert match, "registry-src no longer builds on one digest-pinned golang toolchain"
        version = tuple(int(part) for part in match.groups())
        fixed = GO_FIXED.get(version[:2])
        assert fixed is not None, f"go{'.'.join(map(str, version))} is on a line this floor does not know"
        assert version >= fixed, (
            f"registry-src builds on go{'.'.join(map(str, version))}, which links a standard "
            f"library with CVE-2026-111943 (fixed in go{'.'.join(map(str, fixed))})"
        )

    def test_the_toolchain_is_not_silently_replaced(self) -> None:
        # GOTOOLCHAIN=local is what makes the FROM line the Go that is linked.
        assert "GOTOOLCHAIN=local" in REGISTRY_SRC.read_text(encoding="utf-8")
