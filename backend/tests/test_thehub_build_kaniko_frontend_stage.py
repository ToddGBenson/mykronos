"""thehub/build never hands kaniko a cross-stage copy of `/` (TheHub #61640).

TheHub's backend/Dockerfile gained `FROM scratch AS frontend` and, in the
shipped stage, `COPY --from=frontend / /app/frontend/` (TheHub #61029). A
cross-stage dependency on `/` makes kaniko save its own root filesystem, and
that copy skips only /kaniko, so it reads /proc and fails: "could not save
file: copying file: read /proc/1/attr/apparmor/current: invalid argument"
(builds 230 and 231). These run the job's real script with a stub executor
and pin that kaniko is given a Dockerfile that copies the placeholder from the
context instead, and that the rewrite never lands inside the build context.
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

STAGE_COPY = "COPY --from=frontend / /app/frontend/"
CONTEXT_COPY = "COPY frontend_not_baked/ /app/frontend/"
DOCKERFILE = f"""FROM python:3.14-slim AS builder
# on deploy.sh's build `COPY --from=frontend` below reads the checkout's
FROM scratch AS frontend
COPY frontend_not_baked/ /
FROM python:3.14-slim
{STAGE_COPY}
RUN true
"""


def _script() -> str:
    doc: dict[str, Any] = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in doc["jobs"] if j["name"] == JOB)
    step = next(s for s in job["plan"] if s.get("task") == TASK)
    return str(step["config"]["run"]["args"][-1])


def _run(tmp_path: Path, dockerfile: str) -> tuple[int, str, str]:
    """Run the task's script; returns (rc, output, the --dockerfile kaniko got)."""
    sh = shutil.which("bash")
    if sh is None:
        pytest.skip("no bash on this host")
    stub = tmp_path / "executor"
    stub.write_text(
        '#!/bin/sh\nfor a in "$@"; do echo "ARG $a"; done\n', encoding="utf-8"
    )
    (tmp_path / "meta").mkdir()
    (tmp_path / "meta" / "sha").write_text("a" * 40, encoding="utf-8")
    backend = tmp_path / "source" / "backend"
    backend.mkdir(parents=True)
    (backend / "Dockerfile").write_text(dockerfile, encoding="utf-8")
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
    args = re.findall(r"(?m)^ARG (.*)$", out.stdout)
    given = args[args.index("--dockerfile") + 1] if "--dockerfile" in args else ""
    return out.returncode, out.stdout + out.stderr, given


def test_the_frontend_placeholder_is_copied_from_the_context(tmp_path: Path) -> None:
    rc, output, given = _run(tmp_path, DOCKERFILE)
    assert rc == 0, output
    assert given == "meta/Dockerfile.kaniko", (
        f"kaniko was given {given!r}; the committed Dockerfile's "
        f"`{STAGE_COPY}` fails kaniko reading /proc"
    )
    built = (tmp_path / given).read_text(encoding="utf-8")
    assert CONTEXT_COPY in built.splitlines()
    assert STAGE_COPY not in built.splitlines()
    # Only that one line changes: the rest of the Dockerfile is TheHub's own.
    assert built == DOCKERFILE.replace(STAGE_COPY, CONTEXT_COPY)


def test_the_rewrite_never_lands_in_the_build_context(tmp_path: Path) -> None:
    """`COPY . .` would bake a file written under source/backend into the image."""
    rc, output, _ = _run(tmp_path, DOCKERFILE)
    assert rc == 0, output
    assert sorted(p.name for p in (tmp_path / "source" / "backend").iterdir()) == [
        "Dockerfile"
    ]


def test_a_dockerfile_without_the_stage_copy_is_built_as_committed(
    tmp_path: Path,
) -> None:
    rc, output, given = _run(tmp_path, "FROM python:3.14-slim\nRUN true\n")
    assert rc == 0, output
    assert given == "source/backend/Dockerfile"


def test_a_subdirectory_of_the_frontend_stage_is_built_as_committed(
    tmp_path: Path,
) -> None:
    """TheHub #61642's durable shape: kaniko saves a subdirectory fine, as it
    saves /wheels, so the guard must not refuse it."""
    durable = DOCKERFILE.replace(
        "COPY frontend_not_baked/ /\n", "COPY frontend_not_baked/ /frontend/\n"
    ).replace(STAGE_COPY, "COPY --from=frontend /frontend/ /app/frontend/")
    rc, output, given = _run(tmp_path, durable)
    assert rc == 0, output
    assert given == "source/backend/Dockerfile"
    assert not (tmp_path / "meta" / "Dockerfile.kaniko").exists()


@pytest.mark.parametrize(
    "line",
    [
        "COPY --from=frontend / /app/static/",
        "COPY --from=frontend /. /app/frontend/",
        "copy --chown=0:0 --from=frontend / /app/frontend",
    ],
)
def test_any_other_copy_of_the_stage_root_fails_by_name(
    tmp_path: Path, line: str
) -> None:
    rc, output, given = _run(tmp_path, DOCKERFILE.replace(STAGE_COPY, line))
    assert rc != 0
    assert "#61640" in output
    assert given == "", "kaniko ran on a Dockerfile it cannot build"
