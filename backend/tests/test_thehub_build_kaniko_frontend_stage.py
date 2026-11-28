"""thehub/build bakes the commit's own frontend, as deploy.sh's build does (TheHub #62421).

TheHub's backend/Dockerfile copies the UI from a `frontend` stage that
deploy.sh's BuildKit build replaces with the checkout's ./frontend, a NAMED
context (docker-compose.build.yml, TheHub #61029). Kaniko has no named
contexts, so until #62421 this job copied the placeholder instead (#61640:
a cross-stage copy of `/` makes kaniko read /proc and fail). That image
carried a marker where the UI belongs, and deploy.sh Step 4.35 and
rollback.sh 4c refuse to swap such an image into production: the digest
this job pushed could be tested, scanned and demoed, never deployed.

Fast deploys pull the digest that passed (FD-1 / FD-2 of epic 61328), so the
digest has to be production's. The job now puts the commit's frontend/ into
the kaniko context as .ci-frontend/ and rewrites the one line that copies the
stage to copy it from there. `COPY . .` carries .ci-frontend/ to /app as
well, so the rewrite removes it there, and --single-snapshot keeps it out of
every layer. The Dockerfile's own stamp step then stamps sw.js and fails the
build if it does not carry the commit.

These run the job's real script with a stub executor.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "build"
TASK = "kaniko"
EXECUTOR = "/kaniko/executor"
SHA = "a" * 40
DIGEST = "sha256:" + "d" * 64

STAGE_COPY = "COPY --from=frontend / /app/frontend/"
BAKED = ["COPY .ci-frontend/ /app/frontend/", "RUN rm -rf /app/.ci-frontend"]
DOCKERFILE = f"""FROM python:3.14-slim AS builder
# on deploy.sh's build `COPY --from=frontend` below reads the checkout's
FROM scratch AS frontend
COPY frontend_not_baked/ /
FROM python:3.14-slim
COPY . .
{STAGE_COPY}
RUN true
"""
SW_JS = "const CACHE_NAME = 'thehub-__BUILD_VERSION__';\n"


def _script() -> str:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in doc["jobs"] if j["name"] == JOB)
    step = next(s for s in job["plan"] if s.get("task") == TASK)
    return str(step["config"]["run"]["args"][-1])


def _run(tmp_path: Path, dockerfile: str, frontend: bool = True) -> tuple[int, str, list[str]]:
    """Run the task's script; returns (rc, output, the args kaniko got)."""
    sh = shutil.which("bash")
    if sh is None:
        pytest.skip("no bash on this host")
    stub = tmp_path / "executor"
    # Prints each argument and, like kaniko, writes the pushed digest to
    # --digest-file.
    stub.write_text(
        "#!/bin/sh\nprev=''\nfor a in \"$@\"; do echo \"ARG $a\";\n"
        f"  [ \"$prev\" = --digest-file ] && printf '%s' '{DIGEST}' > \"$a\"\n"
        "  prev=\"$a\"; done\n",
        encoding="utf-8",
    )
    (tmp_path / "meta").mkdir()
    (tmp_path / "meta" / "sha").write_text(SHA, encoding="utf-8")
    backend = tmp_path / "source" / "backend"
    backend.mkdir(parents=True)
    (backend / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    if frontend:
        ui = tmp_path / "source" / "frontend"
        (ui / "js").mkdir(parents=True)
        (ui / "sw.js").write_text(SW_JS, encoding="utf-8")
        (ui / "index.html").write_text("<html>__BUILD_VERSION__</html>\n", encoding="utf-8")
        (ui / "js" / "app.js").write_text("// ui\n", encoding="utf-8")
    script = _script()
    assert EXECUTOR in script, f"{JOB}/{TASK} no longer calls {EXECUTOR}"
    out = subprocess.run(
        [sh, "-ec", script.replace(EXECUTOR, f"sh '{stub.as_posix()}'")],
        cwd=tmp_path,
        env={"REGISTRY": "registry.invalid", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return out.returncode, out.stdout + out.stderr, re.findall(r"(?m)^ARG (.*)$", out.stdout)


def _given(args: list[str]) -> str:
    return args[args.index("--dockerfile") + 1] if "--dockerfile" in args else ""


def test_the_commits_frontend_is_baked_from_the_context(tmp_path: Path) -> None:
    rc, output, args = _run(tmp_path, DOCKERFILE)
    assert rc == 0, output
    given = _given(args)
    assert given == "meta/Dockerfile.kaniko", (
        f"kaniko was given {given!r}; the committed Dockerfile's `{STAGE_COPY}` "
        "fails kaniko, and the placeholder is not an image production can run"
    )
    built = (tmp_path / given).read_text(encoding="utf-8")
    # Only that one line changes: the rest of the Dockerfile is TheHub's own.
    assert built == DOCKERFILE.replace(STAGE_COPY, "\n".join(BAKED))
    baked = tmp_path / "source" / "backend" / ".ci-frontend"
    assert (baked / "sw.js").read_text(encoding="utf-8") == SW_JS, (
        "the frontend goes in as committed; the Dockerfile's own step stamps it"
    )
    assert (baked / "js" / "app.js").is_file()


def test_only_the_frontend_lands_in_the_context_and_never_in_the_image(tmp_path: Path) -> None:
    """`COPY . .` carries .ci-frontend/ to /app; the rewrite removes it there
    and one snapshot keeps it out of every layer."""
    rc, output, args = _run(tmp_path, DOCKERFILE)
    assert rc == 0, output
    assert sorted(p.name for p in (tmp_path / "source" / "backend").iterdir()) == [
        ".ci-frontend",
        "Dockerfile",
    ]
    assert "--single-snapshot" in args


def test_the_pushed_digest_is_printed(tmp_path: Path) -> None:
    rc, output, args = _run(tmp_path, DOCKERFILE)
    assert rc == 0, output
    assert args[args.index("--digest-file") + 1] == "meta/digest"
    assert f"pushed registry.invalid/thehub:{SHA} at {DIGEST}" in output


def test_a_dockerfile_without_the_stage_copy_is_built_as_committed(tmp_path: Path) -> None:
    rc, output, args = _run(tmp_path, "FROM python:3.14-slim\nRUN true\n")
    assert rc == 0, output
    assert _given(args) == "source/backend/Dockerfile"
    assert not (tmp_path / "source" / "backend" / ".ci-frontend").exists()


@pytest.mark.parametrize(
    "line",
    [
        # TheHub #61642's durable shape: the stage hands a directory across.
        "COPY --from=frontend /frontend/ /app/frontend/",
        "COPY --from=frontend /. /app/frontend/",
        "COPY --from=frontend / /app/frontend",
    ],
)
def test_every_copy_of_the_stage_to_app_frontend_is_baked(tmp_path: Path, line: str) -> None:
    rc, output, args = _run(tmp_path, DOCKERFILE.replace(STAGE_COPY, line))
    assert rc == 0, output
    built = (tmp_path / _given(args)).read_text(encoding="utf-8").splitlines()
    assert line not in built
    assert built[built.index(BAKED[0]) + 1] == BAKED[1]


def test_a_commit_without_a_frontend_fails_by_name(tmp_path: Path) -> None:
    rc, output, args = _run(tmp_path, DOCKERFILE, frontend=False)
    assert rc != 0
    assert "#62421" in output
    assert args == [], "kaniko ran with nothing to bake"


@pytest.mark.parametrize(
    "line",
    [
        "COPY --from=frontend / /app/static/",
        "copy --chown=0:0 --from=frontend / /app/frontend",
    ],
)
def test_any_other_copy_of_the_stage_root_fails_by_name(tmp_path: Path, line: str) -> None:
    rc, output, args = _run(tmp_path, DOCKERFILE.replace(STAGE_COPY, line))
    assert rc != 0
    assert "#61640" in output
    assert args == [], "kaniko ran on a Dockerfile it cannot build"
