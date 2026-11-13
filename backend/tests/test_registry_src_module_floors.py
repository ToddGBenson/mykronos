"""The registry-src rebuild links every Go module past its known advisories.

`/bin/registry` is a static Go binary, so an `apk upgrade` never reaches the
modules it links: each fix is a `go get` of a pinned version in the recipe,
before `go mod vendor` and the build. distribution v3.1.2 requires:

    golang.org/x/net                       v0.59.0  (HTTP/2 denial of service, fixed 0.60.0)
    go.opentelemetry.io/otel/.../otlptrace v1.3x    (CVE-2026-81870, fixed 1.45.0)
    github.com/klauspost/compress          v1.18.4  (CVE-2026-63209, fixed 1.18.7)
    github.com/go-jose/go-jose/v4          v4.1.4   (CVE-2026-116587 / GHSA-mgcc-cww5-fp2q,
                                                     HIGH, RSA JWK parsing denial of service,
                                                     fixed 4.1.6; five more advisories fixed 4.1.7)

These are floors, not exact pins: a later version passes, and only a recipe
that drops the bump, or pins it back below the fix, fails. A bump that is
declared but never reaches `go get` would build the vendor's version, so each
one must be fed to `go get` and printed by the build's `go list` check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_SRC = REPO_ROOT / "deploy" / "images" / "registry-src" / "Dockerfile"

#: module -> (Dockerfile ARG that pins it, first version past its advisories)
MODULE_FLOORS: dict[str, tuple[str, tuple[int, ...]]] = {
    "golang.org/x/net": ("X_NET", (0, 60, 0)),
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace": ("OTEL_EXPORTERS", (1, 45, 0)),
    "github.com/klauspost/compress": ("KLAUSPOST_COMPRESS", (1, 18, 7)),
    "github.com/go-jose/go-jose/v4": ("GO_JOSE", (4, 1, 6)),
}


def _text() -> str:
    return REGISTRY_SRC.read_text(encoding="utf-8")


def _arg(name: str) -> str | None:
    match = re.search(rf"^ARG {name}=(\S+)$", _text(), re.M)
    return match.group(1) if match else None


def _instructions() -> list[str]:
    """The Dockerfile's instructions with line continuations joined."""
    return [line for line in re.sub(r"\\\n", " ", _text()).splitlines() if line.strip()]


@pytest.mark.parametrize("module", sorted(MODULE_FLOORS))
class TestRegistryModuleFloors:
    def test_the_pin_is_past_the_fix(self, module: str) -> None:
        arg, floor = MODULE_FLOORS[module]
        value = _arg(arg)
        assert value is not None, f"registry-src no longer pins {module} with ARG {arg}"
        match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", value)
        assert match, f"ARG {arg}={value} is not an exact vX.Y.Z module version"
        version = tuple(int(part) for part in match.groups())
        assert version >= floor, (
            f"{module} {value} predates v{'.'.join(map(str, floor))}, the first release "
            "past its known advisories"
        )

    def test_the_pin_reaches_go_get(self, module: str) -> None:
        arg, _ = MODULE_FLOORS[module]
        gets = [line for line in _instructions() if "go get" in line]
        assert gets, "registry-src no longer runs go get"
        assert any(f'"{module}@${{{arg}}}"' in line for line in gets), (
            f"ARG {arg} is declared but {module} is not fetched at it, so the build "
            "links the version distribution requires"
        )

    def test_the_build_log_shows_the_linked_version(self, module: str) -> None:
        listed = [line for line in _instructions() if "go list -m" in line]
        assert any(module in line.split("go list -m", 1)[1] for line in listed), (
            f"the go list check no longer prints {module}"
        )
