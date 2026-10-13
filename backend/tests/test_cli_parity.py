"""`mykronos parity` end to end, with both CI systems stubbed.

The comparison logic has its own tests (test_ci.py, test_parity_targets.py);
nothing ran the command itself, which is how it shipped reading a variable
only another subcommand binds and raising UnboundLocalError on every run that
reached the comparison.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import mykronos.cli as cli
from mykronos.ci import PipelineStatus
from tests.conftest import REPO
from tests.test_onboarding import onboard


def _concourse(*args: Any, **kwargs: Any) -> SimpleNamespace:
    """`ConcourseClient.status_for` is synchronous, unlike `ActionsClient`'s.
    Not a class with a `def status_for`: test_async_contracts matches doubles
    by method name, and would read one as a sync stand-in for the async
    Actions method."""
    return SimpleNamespace(
        status_for=lambda repo: PipelineStatus(repo_full_name=repo, pipeline=None, url=None)
    )


class _Actions:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def status_for(self, repo: str) -> PipelineStatus:
        return PipelineStatus(repo_full_name=repo, pipeline=None, url=None)


class _Factory:
    def for_installation(self, installation_id: Any) -> None:
        return None


def test_parity_reaches_a_verdict(
    client, admin_auth, settings, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    assert onboard(client, admin_auth).status_code in (200, 201)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "ConcourseClient", _concourse)
    monkeypatch.setattr(cli, "ActionsClient", _Actions)
    monkeypatch.setattr(cli, "_github_factory", lambda _settings: _Factory())

    code = cli.main(["parity", REPO])

    assert code in (0, 1)
    assert "capability" in capsys.readouterr().out
