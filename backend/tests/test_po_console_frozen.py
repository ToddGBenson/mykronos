"""The Product Owner console's story and sprint writes are frozen (D-177)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.api import product_owner
from tests.test_product_owner import FakeHub, connect  # noqa: F401 -- `connect` is a fixture

SENTENCE = "Frozen read-only since 2026-11-13: stories and sprints live in the Hub"

WRITES: list[tuple[str, dict[str, Any] | None]] = [
    ("stories/7/pull", None),
    ("stories/8/return", None),
    ("rank", {"story_id": 7, "direction": "up"}),
    ("template", {"template": "keel"}),
]


@pytest.fixture(autouse=True)
def _frozen(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(product_owner, "WRITES_FROZEN", True)


@pytest.mark.parametrize(("path", "payload"), WRITES)
def test_a_story_or_sprint_write_answers_410_with_the_sentence(
    client: TestClient,
    admin_auth: dict[str, str],
    connect: Callable[..., tuple[str, FakeHub]],  # noqa: F811
    path: str,
    payload: dict[str, Any] | None,
) -> None:
    repo_id, hub = connect([])
    response = client.post(
        f"/api/dashboard/repos/{repo_id}/product-owner/{path}", headers=admin_auth, json=payload
    )
    assert response.status_code == 410
    assert response.json()["detail"] == SENTENCE
    assert hub.calls == []  # TheHub was never asked


def test_the_read_view_still_answers(
    client: TestClient,
    admin_auth: dict[str, str],
    connect: Callable[..., tuple[str, FakeHub]],  # noqa: F811
) -> None:
    repo_id, _ = connect([])
    response = client.get(f"/api/dashboard/repos/{repo_id}/product-owner", headers=admin_auth)
    assert response.status_code == 200
