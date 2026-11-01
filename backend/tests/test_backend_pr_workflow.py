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


# TheHub #61011: #1014 changed .gitleaks.toml and merged while gitleaks had
# never run against the new config. `secret-hygiene` is required, so it is
# where gitleaks proves every allowlist entry.

GITLEAKS_SHA256 = "a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb"


def _secret_hygiene_run(document: dict[str, Any]) -> str:
    steps = document["jobs"]["secret-hygiene"]["steps"]
    return "\n".join(str(step.get("run", "")) for step in steps)


def test_secret_hygiene_installs_the_pinned_gitleaks_by_checksum(
    document: dict[str, Any],
) -> None:
    """The version the Concourse lane pins, and its bytes, not only its tag."""
    run = _secret_hygiene_run(document)
    assert "/download/v8.28.0/gitleaks_8.28.0_linux_x64.tar.gz" in run
    assert f"{GITLEAKS_SHA256}  " in run and "sha256sum -c" in run
    pipeline = WORKFLOW.parents[2] / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
    assert GITLEAKS_SHA256 in pipeline.read_text(encoding="utf-8"), (
        "the Concourse lane moved; move this pin with it"
    )


def test_secret_hygiene_proves_every_allowlist_entry_over_the_history(
    document: dict[str, Any],
) -> None:
    job = document["jobs"]["secret-hygiene"]
    checkout = next(
        s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")
    )
    # The fixtures an entry exists for live in history (a branch commit and its
    # squash-merge), so a shallow clone would call a needed entry unused.
    assert checkout.get("with", {}).get("fetch-depth") == 0
    run = _secret_hygiene_run(document)
    assert "scripts/check_gitleaks_allowlist.py" in run
    assert "--config .gitleaks.toml" in run
    assert "--mode git" in run


def test_secret_hygiene_runs_the_allowlist_check_tests_against_real_gitleaks(
    document: dict[str, Any],
) -> None:
    run = _secret_hygiene_run(document)
    assert "tests/test_gitleaks_allowlist_check.py" in run
    # Set, so the real-gitleaks tests fail rather than skip if the install broke.
    assert "MYKRONOS_REQUIRE_GITLEAKS=1" in run


def test_the_allowlist_check_tests_need_only_the_standard_library() -> None:
    source = (Path(__file__).parent / "test_gitleaks_allowlist_check.py").read_text(
        encoding="utf-8"
    )
    imports = set(re.findall(r"^(?:from|import) (\w+)", source, re.MULTILINE))
    assert imports <= {
        "__future__", "collections", "importlib", "os", "pathlib", "shutil", "subprocess",
        "sys", "tomllib", "typing", "pytest",
    }, imports
    script = (WORKFLOW.parents[2] / "scripts" / "check_gitleaks_allowlist.py").read_text(
        encoding="utf-8"
    )
    imports = set(re.findall(r"^(?:from|import) (\w+)", script, re.MULTILINE))
    assert "pytest" not in imports and "mykronos" not in imports, imports
