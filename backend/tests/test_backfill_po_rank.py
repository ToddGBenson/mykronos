"""The one-shot copy of `po_backlog_rank` into TheHub's `po_rank` (B-068).

The table is built with plain SQL rather than the model, because the model is
retired and the script has to keep working against a database that still holds
the table.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import httpx2
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from mykronos import product_owner as po
from mykronos.backfill_po_rank import backfill_po_rank


class Hub:
    def __init__(self, stories: dict[int, dict[str, Any]]) -> None:
        self.stories = stories
        self.patches: list[tuple[str, Any]] = []
        self.patch_status = 200

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        sid = int(request.url.path.rsplit("/", 1)[-1])
        if request.method == "PATCH":
            body = json.loads(request.content)
            self.patches.append((request.url.path, body))
            if self.patch_status != 200:
                return httpx2.Response(self.patch_status, json={"detail": "not today"})
            self.stories[sid].update(body)
            return httpx2.Response(200, json=self.stories[sid])
        if sid not in self.stories:
            return httpx2.Response(404, json={"detail": "Story not found"})
        return httpx2.Response(200, json=self.stories[sid])

    def client(self) -> po.HubClient:
        return po.HubClient(
            "http://hub.test", "t", transport=httpx2.MockTransport(self.handler)
        )


@pytest.fixture
def engine(tmp_path) -> Iterator[Engine]:
    eng = create_engine(f"sqlite:///{tmp_path / 'ops.db'}")
    yield eng
    eng.dispose()


def seed(engine: Engine, rows: list[tuple[str, int, int]]) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE po_backlog_rank (repo_id VARCHAR(36), story_id INTEGER, "
                "rank INTEGER, updated_at DATETIME, updated_by VARCHAR(255), "
                "PRIMARY KEY (repo_id, story_id))"
            )
        )
        for repo_id, story_id, rank in rows:
            connection.execute(
                text("INSERT INTO po_backlog_rank (repo_id, story_id, rank) VALUES (:r, :s, :k)"),
                {"r": repo_id, "s": story_id, "k": rank},
            )


def run(engine: Engine, hub: Hub, *, dry_run: bool) -> Any:
    return asyncio.run(backfill_po_rank(engine, hub.client(), dry_run=dry_run))


def test_it_copies_each_rank_and_only_po_rank(engine: Engine) -> None:
    seed(engine, [("repo-a", 1, 1), ("repo-a", 2, 2)])
    hub = Hub({1: {"id": 1, "po_rank": None}, 2: {"id": 2, "po_rank": None}})
    report = run(engine, hub, dry_run=False)
    assert hub.patches == [
        ("/api/dev/stories/1", {"po_rank": 1}),
        ("/api/dev/stories/2", {"po_rank": 2}),
    ]
    assert report.copied == [(1, 1), (2, 2)]


def test_a_dry_run_writes_nothing_and_says_so(engine: Engine) -> None:
    seed(engine, [("repo-a", 1, 1)])
    hub = Hub({1: {"id": 1, "po_rank": None}})
    report = run(engine, hub, dry_run=True)
    assert hub.patches == []
    lines = report.lines(dry_run=True)
    assert "would copy: story 1 -> po_rank 1" in "\n".join(lines)
    assert lines[-1] == "(dry run, nothing written)"


def test_a_story_gone_from_the_hub_is_skipped_and_reported(engine: Engine) -> None:
    seed(engine, [("repo-a", 1, 1), ("repo-a", 404, 2)])
    hub = Hub({1: {"id": 1, "po_rank": None}})
    report = run(engine, hub, dry_run=False)
    assert report.not_found == [404]
    assert report.copied == [(1, 1)]


def test_a_story_ranked_by_two_repositories_is_reported_not_resolved(
    engine: Engine,
) -> None:
    seed(engine, [("repo-a", 5, 1), ("repo-b", 5, 3)])
    hub = Hub({5: {"id": 5, "po_rank": None}})
    report = run(engine, hub, dry_run=False)
    assert hub.patches == []
    assert report.conflicts == {5: [("repo-a", 1), ("repo-b", 3)]}
    assert any("NOT RESOLVED: story 5" in line for line in report.lines(dry_run=False))


def test_a_rank_already_in_the_hub_is_left_alone(engine: Engine) -> None:
    seed(engine, [("repo-a", 1, 4)])
    hub = Hub({1: {"id": 1, "po_rank": 2}})
    report = run(engine, hub, dry_run=False)
    assert hub.patches == []
    assert report.already_ranked == [(1, 4, 2)]


def test_a_refusal_is_reported_and_the_rest_continue(engine: Engine) -> None:
    seed(engine, [("repo-a", 1, 1)])
    hub = Hub({1: {"id": 1, "po_rank": None}})
    hub.patch_status = 422
    report = run(engine, hub, dry_run=False)
    assert report.refused == [(1, "not today")]
    assert report.copied == []


def test_no_table_means_nothing_to_copy(engine: Engine) -> None:
    hub = Hub({})
    report = run(engine, hub, dry_run=True)
    assert report.table_absent
    assert report.lines(dry_run=True) == ["po_backlog_rank does not exist: nothing to copy."]
