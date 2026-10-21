#!/usr/bin/env python3
"""Regenerate the backend's hash-locked dependency sets.

    python scripts/lock_backend.py                         # re-lock, keeping pins
    python scripts/lock_backend.py --upgrade-package fastapi
    python scripts/lock_backend.py --upgrade               # everything to latest

Two files, both generated from backend/pyproject.toml and never edited by hand:

  backend/requirements.txt      the runtime set; the image installs exactly
                                this with `--require-hashes` (backend/Dockerfile)
  backend/requirements-dev.txt  runtime + the `dev` extra; the unit, coverage
                                and lint-and-types lanes install this

The dev set is constrained by the runtime one, so a package both carry is at
the same version in both: the tests exercise the dependency set that ships.

Targets the image, not this machine: Python 3.13 on x86_64 Linux, which is
`python:3.13-slim` and the hosted runners. A lock resolved for Windows would
leave out uvloop and pull in colorama, and the image would install neither
correctly.

Pins are kept unless an `--upgrade*` flag is passed through, so adding a
dependency to pyproject.toml re-locks without moving anything else.

uv is pinned. A different uv can resolve, order or annotate the same inputs
differently, and a lock that changes with the tool that wrote it is not a lock.

The files keep uv's own `uv pip compile ...` header rather than naming this
script: that header is how Dependabot's pip updater recognises a compiled
requirements file and learns the flags to regenerate it with.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"

#: Released 2026-10-03. Bump deliberately, and re-lock in the same commit.
UV_VERSION = "0.12.23"

#: The image's interpreter and platform (backend/Dockerfile `FROM python:3.13-slim`).
TARGET = ["--python-version", "3.13", "--python-platform", "x86_64-manylinux_2_28"]


def _uv() -> list[str]:
    """`python -m uv` at the pinned version, or exit saying how to get it."""
    uv = [sys.executable, "-m", "uv"]
    try:
        out = subprocess.run([*uv, "--version"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        sys.exit(f"uv is not installed for {sys.executable}: pip install uv=={UV_VERSION}")
    version = out.stdout.split()[1] if out.stdout.split()[1:] else out.stdout.strip()
    if version != UV_VERSION:
        sys.exit(f"uv {version} found, {UV_VERSION} required: pip install uv=={UV_VERSION}")
    return uv


def _compile(uv: list[str], output: str, extra: list[str], passthrough: list[str]) -> None:
    subprocess.run(
        [
            *uv, "pip", "compile", "pyproject.toml",
            *extra,
            "--generate-hashes",
            *TARGET,
            "--quiet",
            "-o", output,
            *passthrough,
        ],
        check=True,
        cwd=BACKEND,
    )


def main(argv: list[str]) -> int:
    uv = _uv()
    _compile(uv, "requirements.txt", [], argv)
    # Runtime first, then dev constrained by it: an upgrade lands in both.
    _compile(uv, "requirements-dev.txt", ["--extra", "dev", "-c", "requirements.txt"], argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
