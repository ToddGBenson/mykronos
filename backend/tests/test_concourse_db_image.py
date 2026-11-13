"""Concourse's database is built here: postgres 15 with gosu rebuilt (TheHub #61617).

Every stock postgres:15 build ships /usr/local/bin/gosu built on go1.24.6, whose
standard library carries CVE-2025-68121 (CRITICAL) and two dozen HIGH, and no
package upgrade reaches a Go binary's standard library. The
`deploy/images/postgres-gosu` recipe rebuilds the same gosu release on the
registry-src toolchain and lays it over the vendor image, plus `apt-get
upgrade`. Measured with Trivy 0.58.1 on 2026-11-13 (critical/high): vendor
15.20 2/149, the build 1/122; the CRITICAL left is libxml2 CVE-2026-6653, with
no Debian fix.

These hold what makes that safe to rely on: both stages are one exact pin, the
gosu source is a verified commit, the toolchain is past the fixes and cannot be
swapped silently, the binary that ships is the one the gosu stage built, and
the image-refresh recipe publishes under the `library/postgres` identity the
lake's findings and acceptances already carry.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from mykronos import image_refresh as ir
from mykronos.fingerprint import image_repository

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "deploy" / "concourse" / "docker-compose.yml"
RECIPE = REPO_ROOT / "deploy" / "images" / "postgres-gosu"
DOCKERFILE = RECIPE / "Dockerfile"

#: The first Go on each line past CVE-2025-68121 and CVE-2026-111943.
GO_FIXED: dict[tuple[int, int], tuple[int, int, int]] = {(1, 26): (1, 26, 10), (1, 27): (1, 27, 3)}

POSTGRES_BASE = re.compile(r"^postgres:15\.(\d+)@sha256:[0-9a-f]{64}$")
GOLANG_FROM = re.compile(
    r"^FROM golang:(\d+)\.(\d+)\.(\d+)[\w.-]*@sha256:[0-9a-f]{64} AS gosu$", re.M
)


def _text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def _service() -> dict[str, Any]:
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    return dict(services["concourse-db"])


def _arg_default(name: str) -> str:
    match = re.search(rf"^ARG {name}=(\S+)$", _text(), re.M)
    assert match, f"{DOCKERFILE.name} no longer declares ARG {name} with a default"
    return match.group(1)


class TestDockerfile:
    def test_the_runtime_base_is_postgres_15_by_digest(self) -> None:
        # 16 needs a dump-and-restore of the volume; a tag alone could move.
        assert POSTGRES_BASE.match(_arg_default("BASE_IMAGE"))
        assert re.search(r"^FROM \$\{BASE_IMAGE\}$", _text(), re.M)

    def test_the_gosu_stage_is_one_digest_pinned_toolchain_past_the_fixes(self) -> None:
        matches = GOLANG_FROM.findall(_text())
        assert len(matches) == 1, "the gosu stage is not one digest-pinned golang FROM"
        version = tuple(int(part) for part in matches[0])
        fixed = GO_FIXED.get((version[0], version[1]))
        assert fixed is not None, f"go{version} is on a line this test does not know"
        assert version >= fixed

    def test_every_from_is_one_of_the_two_pins(self) -> None:
        froms = re.findall(r"^FROM\s+(.+)$", _text(), re.M)
        assert len(froms) == 2, froms
        assert GOLANG_FROM.match(f"FROM {froms[0]}"), froms[0]
        assert froms[1] == "${BASE_IMAGE}"

    def test_the_toolchain_is_not_silently_replaced(self) -> None:
        # GOTOOLCHAIN=local is what makes the FROM line the Go that is linked.
        assert "GOTOOLCHAIN=local" in _text()
        assert "CGO_ENABLED=0" in _text()

    def test_gosu_is_built_from_a_verified_commit(self) -> None:
        assert re.fullmatch(r"\d+\.\d+", _arg_default("GOSU_TAG"))
        assert re.fullmatch(r"[0-9a-f]{40}", _arg_default("GOSU_COMMIT"))
        assert "https://github.com/tianon/gosu.git" in _text()
        assert 'test "$(git rev-parse HEAD)" = "${GOSU_COMMIT}"' in _text()

    def test_the_shipped_gosu_is_the_one_the_stage_built(self) -> None:
        text = _text()
        assert re.search(r"^COPY --from=gosu /out/gosu /usr/local/bin/gosu$", text, re.M)
        # The copy lands after the upgrade, so no package can put the vendor's back.
        assert text.index("apt-get -y") < text.index("COPY --from=gosu")
        assert re.search(r"^RUN gosu nobody true$", text, re.M)

    def test_the_build_refuses_a_binary_on_another_go(self) -> None:
        version = ".".join(GOLANG_FROM.findall(_text())[0])
        assert f"go{version}" in _text().replace("\\.", ".")

    def test_nothing_changes_who_the_server_runs_as(self) -> None:
        # The vendor entrypoint drops to `postgres` through gosu; no USER,
        # ENTRYPOINT, CMD or VOLUME may override what the base declares.
        for instruction in ("USER", "ENTRYPOINT", "CMD", "VOLUME"):
            assert not re.search(rf"^{instruction}\b", _text(), re.M), instruction


class TestRecipe:
    def test_the_database_is_built_from_this_recipe(self) -> None:
        build = _service()["x-mykronos-build"]
        assert build["context"] == "../images/postgres-gosu"
        assert build["refresh_arg"] == "APT_REFRESH"

    def test_the_recipe_base_is_the_dockerfile_default(self) -> None:
        # The lane passes `base` as BASE_IMAGE; a default that lagged it
        # would make a local build differ from the published one.
        assert _service()["x-mykronos-build"]["base"] == _arg_default("BASE_IMAGE")

    def test_publish_keeps_the_vendor_identity_and_the_base_version(self) -> None:
        build = _service()["x-mykronos-build"]
        base_tag = build["base"].split("@", 1)[0]
        assert build["publish"] == f"library/{base_tag}"
        assert image_repository(f"registry.example:5000/{build['publish']}-p20261113") == (
            image_repository(_service()["image"])
        )

    def test_the_baseline_is_digest_pinned(self) -> None:
        baseline = _service()["x-mykronos-build"].get("baseline")
        if baseline is not None:
            assert POSTGRES_BASE.match(baseline)

    def test_the_lane_plans_it(self) -> None:
        recipes = ir.plan_mykronos(REPO_ROOT, "20261113", "registry.example:5000")
        recipe = next(r for r in recipes if any(s.endswith("::concourse-db") for s in r.services))
        assert recipe.context == "deploy/images/postgres-gosu"
        assert recipe.candidate == "registry.example:5000/library/postgres:15.20-p20261113"
        assert ("BASE_IMAGE", _service()["x-mykronos-build"]["base"]) in recipe.build_args
