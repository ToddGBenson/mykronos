"""i2i grooming API — spec 17 §7.2, retired by D-161.

The routes stay so their callers (the agent work queue names one) get a
reason instead of a 404, and they write nothing to GitHub.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO
from tests.test_onboarding import onboard

PATHS = (
    "/api/triage/some-finding/groom",
    "/api/triage/repos/some-repo/combinations/some-combination/groom",
)


@pytest.mark.parametrize("path", PATHS)
def test_grooming_is_gone_and_says_where_work_items_live(
    path: str, client: TestClient, admin_auth: dict[str, str]
) -> None:
    response = client.post(path, headers=admin_auth)

    assert response.status_code == 410
    detail = response.json()["detail"]
    assert "D-161" in detail
    assert "TheHub" in detail


@pytest.mark.parametrize("path", PATHS)
def test_a_viewer_is_still_refused_before_being_told(
    path: str, client: TestClient, viewer_auth: dict[str, str]
) -> None:
    assert client.post(path, headers=viewer_auth).status_code == 403


def test_a_groom_opens_no_issue(client: TestClient, admin_auth: dict[str, str]) -> None:
    onboard(client, admin_auth)

    client.post("/api/triage/some-finding/groom", headers=admin_auth)

    app: Any = client.app
    fake = app.state.github_factory.client
    assert fake.repos[REPO].issues == []
    assert not [call for call in fake.calls if "issue" in call[0]]
