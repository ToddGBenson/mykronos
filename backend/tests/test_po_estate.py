"""The Product Owner estate roll-up (spec 35 §8.7, D-148)."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from mykronos import product_owner as po
from tests.conftest import REPO
from tests.po_support import MANIFEST, FakeHub, attach_hub, onboard, story

KEEL = "example-org/keel"
SOC = "example-org/personal-soc"

KEEL_MANIFEST = MANIFEST.replace("tag: repo:payments-api", "tag: repo:keel").replace(
    "name: keel-style", "name: keel"
)


def estate(client: TestClient, auth: dict[str, str]) -> Any:
    response = client.get("/api/dashboard/product-owner/estate", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def seed(client: TestClient, github: Any) -> dict[str, str]:
    ids = {REPO: onboard(client), KEEL: onboard(client, KEEL), SOC: onboard(client, SOC)}
    github.repos[REPO].branches["main"][po.MANIFEST_PATH] = MANIFEST
    github.add_repo(KEEL, files={po.MANIFEST_PATH: KEEL_MANIFEST})
    github.add_repo(SOC, files={"README.md": "# soc"})
    hub = FakeHub(
        [
            # payments-api: two in the sprint, one done; one fails its check.
            story(id=1, bucket="sprint", gate="verified"),
            story(id=2, bucket="sprint", gate="clarified", acceptance_criteria=[]),
            story(id=3, bucket="sprint", gate="in_progress"),
            # keel: one in the sprint.
            story(id=4, bucket="sprint", gate="in_progress", tags=["repo:keel"]),
            story(id=5, bucket="backlog", tags=["repo:keel"]),
            # personal-soc declares nothing, and has one by the default tag.
            story(id=6, bucket="sprint", gate="ready", tags=["repo:personal-soc"]),
        ]
    )
    attach_hub(client, hub)
    return ids


class TestEstate:
    def test_every_repository_is_listed_with_its_process(
        self, client: TestClient, viewer_auth: dict[str, str], github: Any
    ) -> None:
        ids = seed(client, github)
        body = estate(client, viewer_auth)
        rows = {row["repo_full_name"]: row for row in body["rows"]}
        assert set(rows) == {REPO, KEEL, SOC}
        assert rows[REPO]["process"] == "declared"
        assert rows[KEEL]["manifest_name"] == "keel"
        # No manifest: listed, and said so, not omitted.
        assert rows[SOC]["process"] == "declares no process"
        assert rows[SOC]["sprint_committed"] == 1
        assert rows[REPO]["link"] == f"/repos/{ids[REPO]}?tab=product-owner"

    def test_each_row_is_the_repositorys_own_tab(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        github: Any,
    ) -> None:
        ids = seed(client, github)
        rows = {row["repo_full_name"]: row for row in estate(client, viewer_auth)["rows"]}
        for name, repo_id in ids.items():
            tab = client.get(
                f"/api/dashboard/repos/{repo_id}/product-owner", headers=viewer_auth
            ).json()
            assert rows[name]["sprint_done"] == tab["sprint_progress"]["done"]
            assert rows[name]["sprint_committed"] == tab["sprint_progress"]["committed"]
            assert rows[name]["needs_human"] == sum(
                1 for item in tab["needs_human"] if item["story_id"] is not None
            )

    def test_the_totals_row_is_the_sum_of_the_rows(
        self, client: TestClient, viewer_auth: dict[str, str], github: Any
    ) -> None:
        seed(client, github)
        body = estate(client, viewer_auth)
        rows, totals = body["rows"], body["totals"]
        assert totals["repos"] == len(rows) == 3
        for key in ("sprint_done", "sprint_committed", "needs_human"):
            assert totals[key] == sum(row[key] or 0 for row in rows), key
        assert totals["sprint_committed"] == 5
        assert totals["sprint_done"] == 1
        assert totals["declared"] + totals["declares_no_process"] == 3
        assert totals["rows_without_hub"] == 0

    def test_without_the_hub_the_sprint_columns_are_absent_not_zero(
        self, client: TestClient, viewer_auth: dict[str, str], github: Any
    ) -> None:
        seed(client, github)
        client.app.state.hub = None  # type: ignore[attr-defined]
        body = estate(client, viewer_auth)
        assert all(row["sprint_committed"] is None for row in body["rows"])
        assert body["totals"]["rows_without_hub"] == 3
