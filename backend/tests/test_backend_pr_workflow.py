"""The backend PR check stays what D-162 says it is (TheHub #60747).

The acceptance criterion this pins: "PRs from forks run without access to
repository secrets, asserted by the workflow configuration". GitHub withholds
secrets from a fork's `pull_request` run. It hands them to `pull_request_target`,
which also checks out with a write token. So the guarantee depends on the
trigger and on the workflow naming no secret, and both are tested here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "backend-pr.yml"


@pytest.fixture(scope="module")
def text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def document(text: str) -> dict[str, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(text)
    # PyYAML reads a bare `on:` key as the boolean True.
    loaded["on"] = loaded.pop(True, loaded.get("on"))
    return loaded


def test_it_runs_on_pull_request_and_nothing_that_carries_secrets(
    document: dict[str, Any],
) -> None:
    assert set(document["on"]) == {"pull_request"}


def test_it_names_no_secret(text: str) -> None:
    code = re.sub(r"#.*", "", text)
    assert "secrets." not in code
    assert "pull_request_target" not in code


def test_the_token_is_read_only(document: dict[str, Any]) -> None:
    assert document["permissions"] == {"contents": "read"}
    for job in document["jobs"].values():
        assert "permissions" not in job, "a job must not widen the token"


def test_the_check_is_named_backend_tests(document: dict[str, Any]) -> None:
    """The context name a branch-protection rule would require (D-162)."""
    assert document["jobs"]["backend-tests"]["name"] == "backend-tests"


def test_there_is_no_path_filter(document: dict[str, Any]) -> None:
    """A filtered-out PR never gets the check, and a required one would then
    wait forever (D-110). The suite also reads docs, pipelines and specs."""
    assert not (document["on"]["pull_request"] or {}).get("paths")
    assert not (document["on"]["pull_request"] or {}).get("paths-ignore")


def test_every_action_is_pinned_by_sha(document: dict[str, Any]) -> None:
    for job in document["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses:
                assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses), uses


def test_it_runs_the_whole_suite_in_parallel(document: dict[str, Any]) -> None:
    steps = document["jobs"]["backend-tests"]["steps"]
    run = " ".join(str(step.get("run", "")) for step in steps)
    assert "python -m pytest" in run
    assert "-n auto" in run
    # The whole suite: no path, -k or -m narrows it.
    arguments = run[run.index("python -m pytest") + len("python -m pytest") :]
    assert not re.search(r"\s(-k|-m)\s|tests/", arguments), arguments


def test_the_secret_hygiene_check_runs_alone(document: dict[str, Any]) -> None:
    """A fast check that can be required before the whole suite is (#821)."""
    job = document["jobs"]["secret-hygiene"]
    assert job["name"] == "secret-hygiene"
    run = " ".join(str(step.get("run", "")) for step in job["steps"])
    assert "tests/test_no_secret_on_a_command_line.py" in run
    # It installs pytest only, so the test must not need the backend.
    assert "-e " not in run and ".[dev]" not in run
    assert "--noconftest" in run


def test_the_secret_hygiene_test_needs_only_the_standard_library() -> None:
    source = (Path(__file__).parent / "test_no_secret_on_a_command_line.py").read_text(
        encoding="utf-8"
    )
    imports = re.findall(r"^(?:from|import) (\w+)", source, re.MULTILINE)
    assert set(imports) <= {"__future__", "re", "pathlib"}, imports
