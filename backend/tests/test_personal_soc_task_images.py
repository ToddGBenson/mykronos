"""guard and doc-drift install nothing when they run (TheHub #62351).

Both tasks ran `apt-get install git` on the `pwsh` image at the start of every
build, inside a 150 s deadline. guard 28 to 29.1 and doc-drift 29 to 30.1
(2026-11-26 to 2026-11-28) all stopped there, exit 75, with nothing judged.
The mirror was not always the slow part. In doc-drift 30.1, apt had fetched
everything 7 s in, and dpkg still had not finished when the deadline hit; in
the last green build (28) it took 11 s. A cache of the downloads would not
have helped. An image that already carries git does: no apt and no dpkg.

So the two tasks run on a prebuilt, digest-pinned image that ships PowerShell
and git together. These tests hold that: no apt line in either script, an
image pinned by digest that the job fetches with retries, and a plain failure
when git is missing, rather than a doc-drift report that lists no changes.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from tests.test_personal_soc_check_run_wiring import _doc, _jobs

#: (job, task) pairs that must install nothing at run time.
NO_RUNTIME_INSTALL = [("guard", "no-personal-data"), ("doc-drift", "find-doc-drift")]

#: A line that RUNS a package manager, not one that mentions it in a comment.
_INSTALLS = re.compile(r"(?:^|[;&|(]\s*|\bthen\s+|\bdo\s+|\belse\s+)(apt-get|apt|dpkg)\s+\S")


def _task(job: str, name: str) -> dict[str, Any]:
    step = next(
        (s for s in _jobs()[job]["plan"] if s.get("task") == name),
        None,
    )
    assert step is not None, f"{job} has no `{name}` task"
    return dict(step)


def _script(step: dict[str, Any]) -> str:
    return str(step["config"]["run"]["args"][-1])


def _code(script: str) -> list[str]:
    return [line.strip() for line in script.splitlines() if not line.strip().startswith("#")]


@pytest.mark.parametrize("job,name", NO_RUNTIME_INSTALL)
def test_the_task_installs_no_package(job: str, name: str) -> None:
    runs = [line for line in _code(_script(_task(job, name))) if _INSTALLS.search(line)]
    assert not runs, f"{job}/{name} still installs at run time: {runs}"


@pytest.mark.parametrize("job,name", NO_RUNTIME_INSTALL)
def test_the_image_is_pinned_by_digest_and_fetched_with_retries(job: str, name: str) -> None:
    image = _task(job, name).get("image")
    assert image, f"{job}/{name} names no `image:` resource"
    resource = next((r for r in _doc()["resources"] if r["name"] == image), None)
    assert resource is not None, f"`{image}` is not a resource"
    assert resource["type"] == "registry-image"
    # PS-8: a digest, so the bytes the worker caches cannot change under the
    # tag. test_every_digest_pin_records_its_date checks the pinned: line.
    digest = (resource.get("version") or {}).get("digest", "")
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), f"`{image}` is not pinned by digest"
    gets = [s for s in _jobs()[job]["plan"] if s.get("get") == image]
    assert gets, f"{job} never fetches `{image}`"
    assert all(s.get("attempts") for s in gets), "PS-12: a fetch retries"


@pytest.mark.parametrize("job,name", NO_RUNTIME_INSTALL)
def test_a_missing_git_fails_before_anything_is_judged(job: str, name: str) -> None:
    # Find-DocDrift with no git prints no changed files, which reads as "the
    # docs are current"; guard's ls-files check would pass on empty output.
    code = _code(_script(_task(job, name)))
    probe = next((i for i, line in enumerate(code) if "command -v git" in line), None)
    assert probe is not None, f"{job}/{name} does not check that its image carries git"
    first_git = next(i for i, line in enumerate(code) if re.match(r"git\s", line))
    assert probe < first_git
