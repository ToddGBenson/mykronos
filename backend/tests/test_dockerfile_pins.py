"""Every Dockerfile FROM names its base image by digest (TheHub #61634).

A floating tag means a rebuild can pick up a different base image than the one
that was scanned, and nothing records which one shipped. `check_pinned_ref.py`
covers the runner refs and `test_patchwork_base_image` the generator; this
walks every Dockerfile in the repository, as `test_dockerfile_syntax` does.

A FROM is pinned when it carries `@sha256:`, names an earlier stage, is
`scratch`, or is `${ARG}` where the ARG's default carries a digest. An ARG with
no default is a build argument the caller supplies; those Dockerfiles are
listed in BUILD_ARG_FROMS, and the test fails if a new one appears unlisted.

Dependabot's `docker` ecosystem is what rolls the digests forward, so the
backend and frontend entries are checked too: without them a pin only ages.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from tests.test_dockerfile_syntax import DOCKERFILES, REPO_ROOT, logical_instructions

# Dockerfiles whose FROM is a build argument with no default: the image
# refresh job passes a digest-pinned reference when it builds them.
BUILD_ARG_FROMS = {
    "deploy/images/apk-upgrade/Dockerfile": "BASE_IMAGE",
    "deploy/images/apt-upgrade/Dockerfile": "BASE_IMAGE",
}

_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def unpinned_froms(text: str, rel: str = "") -> list[str]:
    """Readable messages for each FROM in `text` that has no digest."""
    problems: list[str] = []
    stages: set[str] = set()
    arg_defaults: dict[str, str] = {}
    seen_from = False
    for number, instruction in logical_instructions(text):
        word, _, rest = instruction.partition(" ")
        keyword = word.upper()
        if keyword == "ARG" and not seen_from:
            name, eq, value = rest.strip().partition("=")
            arg_defaults[name.strip()] = value.strip().strip("\"'") if eq else ""
            continue
        if keyword != "FROM":
            continue
        seen_from = True
        tokens = [t for t in rest.split() if not t.startswith("--")]
        image = tokens[0]
        is_named = len(tokens) >= 3 and tokens[1].upper() == "AS"
        stage = tokens[2].lower() if is_named else ""
        ref = re.fullmatch(r"\$\{(\w+)\}|\$(\w+)", image)
        if image.lower() == "scratch" or image.lower() in stages:
            pass
        elif ref:
            arg = ref.group(1) or ref.group(2)
            default = arg_defaults.get(arg, "")
            pinned_default = bool(default) and bool(_DIGEST.search(default))
            listed = not default and BUILD_ARG_FROMS.get(rel) == arg
            if not (pinned_default or listed):
                problems.append(f"line {number}: FROM ${{{arg}}} has no digest-pinned default")
        elif not _DIGEST.search(image):
            problems.append(f"line {number}: FROM {image} is not pinned by @sha256 digest")
        if stage:
            stages.add(stage)
    return problems


def test_the_audit_finds_every_dockerfile() -> None:
    names = {_rel(p) for p in DOCKERFILES}
    for expected in ("backend/Dockerfile", "frontend/Dockerfile", "deploy/zap-pinned/Dockerfile"):
        assert expected in names


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=_rel)
def test_every_from_is_digest_pinned(dockerfile: Path) -> None:
    problems = unpinned_froms(dockerfile.read_text(encoding="utf-8"), _rel(dockerfile))
    assert not problems, f"{_rel(dockerfile)}: {problems}"


DIGEST = "a" * 64


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        (f"FROM node:22-slim@sha256:{DIGEST} AS a\nFROM a AS b\n", True),
        ("FROM node:22-slim AS a\n", False),
        ("FROM node:22-slim@sha256:abc AS a\n", False),
        (f"FROM --platform=linux/amd64 x:1@sha256:{DIGEST}\n", True),
        ("FROM scratch\n", True),
        (f"ARG B=x:1@sha256:{DIGEST}\nFROM ${{B}}\n", True),
        ("ARG B=x:1\nFROM ${B}\n", False),
        ("ARG B\nFROM ${B}\n", False),
        (f"FROM x:1@sha256:{DIGEST} AS a\nFROM b\n", False),
    ],
)
def test_the_audit_tells_pinned_from_floating(text: str, ok: bool) -> None:
    assert (unpinned_froms(text) == []) is ok


def test_a_build_arg_from_must_be_listed() -> None:
    text = "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n"
    assert unpinned_froms(text, "deploy/images/apk-upgrade/Dockerfile") == []
    assert unpinned_froms(text, "deploy/images/new/Dockerfile")


def _updates() -> list[dict]:
    path = REPO_ROOT / ".github" / "dependabot.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["updates"]


@pytest.mark.parametrize("directory", ["/backend", "/frontend"])
def test_dependabot_refreshes_the_image_digests(directory: str) -> None:
    entries = [
        u
        for u in _updates()
        if u["package-ecosystem"] == "docker" and u["directory"] == directory
    ]
    assert len(entries) == 1, f"no docker entry for {directory}"
    entry = entries[0]
    assert entry["schedule"]["interval"] == "weekly"
    assert entry["cooldown"]["default-days"] >= 7
