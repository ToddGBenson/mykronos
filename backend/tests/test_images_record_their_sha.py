"""Every image Mykronos publishes can name the commit it was built from (#382).

A container cannot read the tag it was started from, so an image that is only
tagged with its SHA cannot answer "what commit are you?". The backend has
carried `MYKRONOS_BUILD_SHA` since #361; the frontend carried nothing, which
is the same defect waiting for something to depend on it. These pin both
halves of the fix: the Dockerfile declares the variable in the stage that
ships, and every build path passes the value.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
DELIVERY = REPO_ROOT / ".github" / "workflows" / "delivery.yml"


def _final_stage(dockerfile: Path) -> str:
    """The text of the last `FROM` stage: the one the image actually is."""
    text = dockerfile.read_text(encoding="utf-8")
    stages = re.split(r"(?m)^FROM\s", text)
    return stages[-1]


@pytest.mark.parametrize("component", ["backend", "frontend"])
def test_the_shipped_stage_records_the_build_sha(component: str) -> None:
    stage = _final_stage(REPO_ROOT / component / "Dockerfile")
    assert re.search(r'(?m)^ARG MYKRONOS_BUILD_SHA=""\s*$', stage), (
        f"{component}/Dockerfile's final stage declares no MYKRONOS_BUILD_SHA "
        "build-arg (an ARG in an earlier stage does not reach this one)"
    )
    assert re.search(r"(?m)^ENV MYKRONOS_BUILD_SHA=\$\{MYKRONOS_BUILD_SHA\}", stage), (
        f"{component}/Dockerfile does not keep MYKRONOS_BUILD_SHA in the image's "
        "environment, so the running container still cannot read it"
    )


def _kaniko_builds() -> dict[str, str]:
    """`mykronos-<component>` destination -> the executor command that builds it."""
    document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    builds: dict[str, str] = {}
    for job in document["jobs"]:
        for step in job["plan"]:
            args = (step.get("config") or {}).get("run", {}).get("args") or []
            for arg in args:
                for line in str(arg).splitlines():
                    found = re.search(r"/mykronos-(backend|frontend):", line)
                    if "/kaniko/executor" in line and found:
                        builds[found.group(1)] = line
    return builds


def test_every_pipeline_image_build_passes_the_sha() -> None:
    builds = _kaniko_builds()
    assert set(builds) == {"backend", "frontend"}, builds
    for component, command in builds.items():
        assert '--build-arg "MYKRONOS_BUILD_SHA=${SHA}"' in command, (
            f"publish-{component} builds mykronos-{component} without passing its SHA"
        )


def test_the_actions_delivery_build_passes_the_sha() -> None:
    """Read only: it already passed the value for both matrix components."""
    text = DELIVERY.read_text(encoding="utf-8")
    assert "MYKRONOS_BUILD_SHA=${{ github.sha }}" in text
