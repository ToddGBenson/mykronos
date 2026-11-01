"""Every Dockerfile in the repository parses (TheHub #61115).

#1052 joined two `ENV` pairs in backend/Dockerfile with a literal backslash-n
instead of a line break. BuildKit refused the instruction ("can't find = in
"\\n""), so Delivery could not publish a backend image, and nothing after
1b52775 could deploy. No pull-request check builds an image, so the change
merged green.

These tests read each Dockerfile the way BuildKit does for the parts that
matter here: lines ending in a backslash join into one instruction, comment
lines inside a continuation are dropped, and the instruction word must be
one Docker knows. Then `ENV`, `ARG` and `LABEL` must be `name=value` pairs,
and no instruction other than `RUN` may carry a literal backslash-n (a shell
command can mean one, an `ENV` value never does). They run in
`backend-tests`, which gates every pull request.

None of these Dockerfiles uses a parser directive or a heredoc. The first
test fails if one appears, because this reader would then misread it.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories that hold no Dockerfile of ours.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".next", "__pycache__"}

INSTRUCTIONS = {
    "ADD",
    "ARG",
    "CMD",
    "COPY",
    "ENTRYPOINT",
    "ENV",
    "EXPOSE",
    "FROM",
    "HEALTHCHECK",
    "LABEL",
    "MAINTAINER",
    "ONBUILD",
    "RUN",
    "SHELL",
    "STOPSIGNAL",
    "USER",
    "VOLUME",
    "WORKDIR",
}

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def _is_dockerfile(name: str) -> bool:
    return (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name.endswith(".Dockerfile")
    )


def _dockerfiles() -> list[Path]:
    found: list[Path] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        found.extend(Path(root) / name for name in files if _is_dockerfile(name))
    return sorted(found)


DOCKERFILES = _dockerfiles()


def logical_instructions(text: str) -> list[tuple[int, str]]:
    """(first line number, joined text) for each instruction, as BuildKit joins them."""
    out: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        if pending and stripped.startswith("#"):
            # A comment inside a continuation is removed, not a terminator.
            continue
        if not pending:
            start = number
        if line.rstrip().endswith("\\"):
            pending.append(line.rstrip()[:-1])
            continue
        pending.append(line)
        out.append((start, " ".join(part.strip() for part in pending if part.strip())))
        pending = []
    if pending:
        out.append((start, " ".join(part.strip() for part in pending if part.strip())))
    return out


def syntax_errors(text: str) -> list[str]:
    """What BuildKit would reject in this Dockerfile, as readable messages."""
    errors: list[str] = []
    for number, instruction in logical_instructions(text):
        word, _, rest = instruction.partition(" ")
        keyword = word.upper()
        if keyword not in INSTRUCTIONS:
            errors.append(f"line {number}: unknown instruction {word!r}")
            continue
        if keyword != "RUN" and "\\n" in rest:
            errors.append(f"line {number}: {keyword} carries a literal \\n")
        if keyword in {"ENV", "LABEL", "ARG"}:
            try:
                tokens = shlex.split(rest, posix=True)
            except ValueError as exc:
                errors.append(f"line {number}: {keyword} does not tokenise ({exc})")
                continue
            if not tokens:
                errors.append(f"line {number}: {keyword} with nothing after it")
            for token in tokens:
                name, eq, _ = token.partition("=")
                if keyword == "ARG" and not eq:
                    # `ARG NAME` with no default is valid.
                    eq = "="
                if not eq or not _NAME.match(name):
                    errors.append(
                        f"line {number}: {keyword} token {token!r} is not name=value"
                    )
    return errors


def test_there_are_dockerfiles_to_check() -> None:
    names = {p.relative_to(REPO_ROOT).as_posix() for p in DOCKERFILES}
    assert {"backend/Dockerfile", "frontend/Dockerfile"} <= names, names


@pytest.mark.parametrize(
    "dockerfile", DOCKERFILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix()
)
def test_dockerfile_has_no_directive_or_heredoc_this_reader_cannot_follow(
    dockerfile: Path,
) -> None:
    text = dockerfile.read_text(encoding="utf-8")
    assert not re.search(r"(?im)^#\s*(escape|syntax|check)\s*=", text), (
        f"{dockerfile.name} uses a parser directive; extend test_dockerfile_syntax.py"
    )
    assert "<<" not in text, (
        f"{dockerfile.name} uses a heredoc; extend test_dockerfile_syntax.py"
    )


@pytest.mark.parametrize(
    "dockerfile", DOCKERFILES, ids=lambda p: p.relative_to(REPO_ROOT).as_posix()
)
def test_dockerfile_parses(dockerfile: Path) -> None:
    errors = syntax_errors(dockerfile.read_text(encoding="utf-8"))
    assert not errors, f"{dockerfile.relative_to(REPO_ROOT).as_posix()}: " + "; ".join(errors)


# The reader itself: each defect it exists to catch, and the forms it must accept.

_1052_ENV = (
    "ENV A=/app/a.yaml \\\n"
    "    MYKRONOS_ENVIRONMENT_MAP_PATH=/app/environment-map-v1.yaml \\n"
    "    MYKRONOS_CREDENTIAL_EXPIRY_PATH=/app/credential-expiry-v1.yaml \\\n"
    "    PYTHONUNBUFFERED=1\n"
)


def test_the_1052_line_is_rejected() -> None:
    errors = syntax_errors(_1052_ENV)
    assert any("literal \\n" in e for e in errors), errors


def test_the_1055_fix_is_accepted() -> None:
    fixed = _1052_ENV.replace(" \\n    ", " \\\n    ")
    assert syntax_errors(fixed) == []


@pytest.mark.parametrize(
    "text",
    [
        "EVN A=1\n",
        "ENV A\n",
        "LABEL = \n",
        'ENV A="unterminated\n',
    ],
)
def test_malformed_instructions_are_rejected(text: str) -> None:
    assert syntax_errors(text), text


def test_valid_forms_are_accepted() -> None:
    text = (
        "# comment\r\n"
        "FROM python:3.13-slim AS build\r\n"
        'ARG MYKRONOS_BUILD_SHA=""\r\n'
        "ARG BASE_IMAGE\r\n"
        "ENV MYKRONOS_BUILD_SHA=${MYKRONOS_BUILD_SHA} \\\r\n"
        "    # a comment inside the continuation\r\n"
        "    B=\"two words\"\r\n"
        "RUN printf 'a\\nb' > /x\r\n"
        'LABEL org.opencontainers.image.source="x"\r\n'
    )
    assert syntax_errors(text) == []
