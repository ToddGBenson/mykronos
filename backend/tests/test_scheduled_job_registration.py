"""Which background jobs the app schedules, and when it must not.

The installation reconciler asks GitHub whether each onboarded repository's
installation still exists, and marks it `removed` on a 404. With no GitHub App
configured the factory is the in-memory fake, which answers 404 for every
installation it was not seeded with - so the reconciler removed every
repository the demo seeded, seventeen seconds after seeding, on every rebuild.
The Concourse `demo-and-dast` lane then refused to scan an environment that
looked unseeded; it had passed once in its history.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

import mykronos.main as main
from mykronos.config import Settings


class _RealLikeFactory:
    """Anything that is not the fake stands in for a configured GitHub App."""

    def for_installation(self, installation_id: int) -> Any:  # pragma: no cover
        raise AssertionError("no job may run in this test")


def _scheduled(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, factory: Any = None
) -> list[str]:
    names: list[str] = []

    def record(name: str, interval: int, run: Any, db: Any = None) -> Any:
        # Recorded at registration, and nothing is ever run: the real `_every`
        # fires each job shortly after boot, which is not what this is testing.
        names.append(name)

        async def _idle() -> None:
            return None

        return _idle()

    monkeypatch.setattr(main, "_every", record)
    if factory is not None:
        monkeypatch.setattr(main, "_build_github_factory", lambda _settings: factory)
    with TestClient(main.create_app(settings.model_copy(update={"run_jobs_in_background": True}))):
        pass
    return names


def test_a_faked_github_does_not_reconcile_installations(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    names = _scheduled(monkeypatch, settings)

    assert "rotation" in names, f"jobs were not scheduled at all: {names}"
    assert "installations" not in names


def test_a_real_github_still_reconciles_installations(
    monkeypatch: pytest.MonkeyPatch, settings: Settings
) -> None:
    """The guard must not switch the job off where it matters: a missed
    uninstall webhook is only ever caught by this sweep (spec 02 §5.6)."""
    names = _scheduled(monkeypatch, settings, factory=_RealLikeFactory())

    assert "installations" in names
