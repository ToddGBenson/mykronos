"""The App's permission set is pinned to its call sites (D-161, TheHub #60725).

`REQUIRED_PERMISSIONS` drifted from the code in both directions: it listed
`issues: write` for writes D-133 had made obsolete, while the registered App
held no `issues` permission at all. These tests make the set a function of the
methods that spend it, so each of these fails until somebody declares it:

- a new `GitHubClient` method, read or write;
- a REST call that writes without being declared at `write`;
- a declared write whose permission is not required, and a required
  permission no method spends.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from typing import Any

import pytest

from mykronos.github import client as gh
from mykronos.github.client import (
    METHOD_PERMISSIONS,
    OPTIONAL_PERMISSIONS,
    REQUIRED_PERMISSIONS,
    UNGRANTABLE_PERMISSIONS,
    FakeGitHubClient,
    GitHubClient,
    PermissionDeniedError,
    RestGitHubClient,
)

REPO = "example-org/example-repo"

#: The verbs that change something on GitHub.
WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

#: REST methods that send a write verb without writing. GraphQL takes every
#: query as a POST, and this one only reads a Projects board.
READS_OVER_POST = {"project_field_values", "get_files"}


def _public_methods(cls: type) -> set[str]:
    return {
        name for name, member in vars(cls).items() if callable(member) and not name.startswith("_")
    }


def _write_verbs(method: Any) -> set[str]:
    """The HTTP verbs a `RestGitHubClient` method passes to `_request`/`_json`."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
    verbs: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"_request", "_json"}
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            verbs.add(str(node.args[0].value).upper())
    return verbs & WRITE_VERBS


def _declared_writes() -> set[str]:
    return {
        permission
        for grants in METHOD_PERMISSIONS.values()
        for permission, level in grants
        if level == "write"
    }


class TestEveryMethodIsDeclared:
    def test_every_protocol_method_names_its_permission(self) -> None:
        missing = _public_methods(GitHubClient) - set(METHOD_PERMISSIONS)
        assert not missing, (
            f"{sorted(missing)} spend a GitHub App permission nobody declared. "
            "Add each to METHOD_PERMISSIONS in github/client.py (D-161)."
        )

    def test_nothing_declared_is_a_method_that_is_gone(self) -> None:
        stale = set(METHOD_PERMISSIONS) - _public_methods(GitHubClient)
        assert not stale, f"{sorted(stale)} are declared but no longer exist"

    @pytest.mark.parametrize("cls", [FakeGitHubClient, RestGitHubClient])
    def test_both_implementations_have_exactly_the_protocol(self, cls: type) -> None:
        extra = (_public_methods(cls) - _public_methods(GitHubClient)) - {"add_repo"}
        assert not extra, f"{cls.__name__} has {sorted(extra)} outside the protocol"


class TestEveryWriteIsDeclared:
    @pytest.mark.parametrize("name", sorted(_public_methods(RestGitHubClient)))
    def test_a_rest_write_is_declared_at_write(self, name: str) -> None:
        verbs = _write_verbs(getattr(RestGitHubClient, name))
        if not verbs or name in READS_OVER_POST:
            return
        levels = {level for _permission, level in METHOD_PERMISSIONS.get(name, ())}
        assert "write" in levels, (
            f"RestGitHubClient.{name} sends {sorted(verbs)} but METHOD_PERMISSIONS "
            "declares no write for it"
        )

    def test_the_read_over_post_exemption_is_still_needed(self) -> None:
        for name in READS_OVER_POST:
            assert _write_verbs(getattr(RestGitHubClient, name)), name
            assert all(level == "read" for _p, level in METHOD_PERMISSIONS[name])


class TestTheRequiredSetIsEarned:
    def test_every_declared_write_is_required_at_write(self) -> None:
        for permission in _declared_writes():
            assert REQUIRED_PERMISSIONS.get(permission) == "write", permission

    def test_every_required_write_is_spent_by_a_method(self) -> None:
        required_writes = {p for p, level in REQUIRED_PERMISSIONS.items() if level == "write"}
        unearned = required_writes - _declared_writes()
        assert not unearned, (
            f"{sorted(unearned)} are required at write but no method writes with them. "
            "Lower or remove them, and record why in a decision."
        )

    def test_every_required_read_is_spent_by_a_method(self) -> None:
        declared = {p for grants in METHOD_PERMISSIONS.values() for p, _level in grants}
        for permission, level in REQUIRED_PERMISSIONS.items():
            assert permission in declared, f"{permission}: {level} is spent by nothing"

    def test_every_declared_read_is_held(self) -> None:
        held = {**REQUIRED_PERMISSIONS, **OPTIONAL_PERMISSIONS}
        for name, grants in METHOD_PERMISSIONS.items():
            for permission, _level in grants:
                assert permission in held or permission in UNGRANTABLE_PERMISSIONS, (
                    f"{name} needs {permission}, which is neither required nor optional"
                )

    def test_the_set_is_what_d161_records(self) -> None:
        """The literal set, so changing it is a visible decision, not a side effect."""
        assert REQUIRED_PERMISSIONS == {
            "contents": "write",
            "workflows": "write",
            "secrets": "write",
            "pull_requests": "write",
            "checks": "write",
            "actions": "write",
            "issues": "read",
            "metadata": "read",
        }


class TestTheFakeEnforcesTheDeclaredWrites:
    """The fake is what the rest of the suite trusts, so it has to refuse a
    write when the App holds only `read` of the permission declared for it."""

    CALLS = {
        "create_branch": lambda c: c.create_branch(REPO, "b", "main"),
        "create_pull_request": lambda c: c.create_pull_request(
            REPO, head="b", base="main", title="t", body="b"
        ),
        "close_pull_request": lambda c: c.close_pull_request(REPO, 1),
        "put_actions_secret": lambda c: c.put_actions_secret(REPO, "S", "v", "k"),
        "create_check_run": lambda c: c.create_check_run(
            REPO, name="n", head_sha="s", conclusion=None, title="t", summary="s"
        ),
        "dispatch_workflow": lambda c: c.dispatch_workflow(REPO, "w.yml", "main"),
        "set_workflow_state": lambda c: c.set_workflow_state(REPO, "w.yml", enabled=False),
    }

    def test_every_write_method_is_exercised_here(self) -> None:
        writes = {
            name
            for name, grants in METHOD_PERMISSIONS.items()
            if any(level == "write" for _p, level in grants)
        }
        # Each shares its permission with a method above.
        siblings = {"commit_files", "update_pull_request", "update_check_run"}
        untested = writes - set(self.CALLS) - siblings
        assert not untested, f"add {sorted(untested)} to CALLS"

    @pytest.mark.parametrize("name", sorted(CALLS))
    async def test_read_only_is_refused(self, name: str) -> None:
        (permission, _level), *_ = METHOD_PERMISSIONS[name]
        held = {**REQUIRED_PERMISSIONS, **OPTIONAL_PERMISSIONS, permission: "read"}
        fake = FakeGitHubClient(permissions=held)
        fake.add_repo(REPO)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await self.CALLS[name](fake)
        assert f"{permission}: write" in str(excinfo.value)


def test_the_issue_writes_are_gone() -> None:
    """D-161: MyKronos files no GitHub issues. The four methods that did are
    removed from the protocol, not merely uncalled."""
    for name in ("create_issue", "update_issue", "comment_on_issue", "close_issue"):
        assert not hasattr(GitHubClient, name), name
        assert not hasattr(gh.RestGitHubClient, name), name
