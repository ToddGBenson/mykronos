"""The Today run sheet's actions: Merge in order and Deploy (TheHub #61142), shipped off.

Operator decision 2026-11-04: build them now and ship them switched off. A
server-side flag (`runsheet_actions_enabled`) defaults off; while it is off
the routes refuse and the sheet says so, so no button renders.

They keep Start-Here's batch rules: one batch, TheHub first, each merged at
the head the sheet showed (`--match-head-commit`), stop at the first
failure, never move an approved head. The server never merges and never
deploys (spec 08 section 3, spec 10 section 2; the GitHub client still has no
merge method, which `test_patchwork.py` holds): it re-checks what it can read
and queues the request for the host runner, which keeps the host-only guards.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import runsheet as rs
from mykronos import runsheet_actions as ra
from mykronos.github.client import ChecksSummary, GitHubError, PullRequest
from tests.po_support import audit_entries

THEHUB = "ToddGBenson/TheHub"
MK = "ToddGBenson/mykronos"
HEAD_A = "a" * 40
HEAD_B = "b" * 40
HEAD_C = "c" * 40
MAIN = "d" * 40
RUNNING = "e" * 40


def _item(repo: str, number: int, head: str, state: str = rs.READY) -> rs.Item:
    return rs.Item(
        text=f"{repo}#{number}: PR {number}",
        state=state,
        reason="approved at its head",
        owner=rs.OWNER_YOU,
        ref=f"{repo}#{number}",
        url=f"https://github.com/{repo}/pull/{number}",
        sha=head,
    )


def _view(*rows: tuple[str, int, str, str]) -> rs.Step:
    return rs.Step(
        key="merge",
        title="Merge",
        state=rs.READY,
        summary="",
        items=[_item(repo, n, head, state) for repo, n, head, state in rows],
    )


class FakeReader:
    """GitHub's live single-PR read; `down` makes every read raise."""

    def __init__(self, live: dict[tuple[str, int], PullRequest], down: bool = False):
        self.live = live
        self.down = down
        self.reads: list[str] = []

    def client_for(self, repo: str) -> FakeReader | None:
        return self

    async def get_pull_request(self, repo: str, number: int) -> PullRequest | None:
        self.reads.append(f"{repo}#{number}")
        if self.down:
            raise GitHubError("GitHub is down", status=502)
        return self.live.get((repo, number))


def _live(repo: str, number: int, head: str, **overrides: Any) -> PullRequest:
    base: dict[str, Any] = {
        "number": number,
        "url": f"https://github.com/{repo}/pull/{number}",
        "head_branch": f"feat/{number}",
        "head_sha": head,
        "base_branch": "main",
        "state": "open",
    }
    base.update(overrides)
    return PullRequest(**base)


def _ask(*rows: tuple[str, int, str]) -> list[ra.MergeAsk]:
    return [ra.MergeAsk(repo_full_name=r, number=n, head_sha=h) for r, n, h in rows]


async def _check(step: rs.Step, reader: FakeReader, asks: list[ra.MergeAsk]) -> ra.BatchCheck:
    return await ra.check_batch(asks, step=step, client_for=reader.client_for)


class TestTheBatchRules:
    def test_thehub_goes_first_then_oldest_number_per_repository(self) -> None:
        ordered = ra.order_batch(_ask((MK, 9, HEAD_A), (THEHUB, 20, HEAD_B), (MK, 3, HEAD_C)))

        assert [(a.repo_full_name, a.number) for a in ordered] == [
            (THEHUB, 20), (MK, 3), (MK, 9),
        ]

    async def test_a_ready_batch_is_accepted_in_merge_order_at_the_heads_shown(self) -> None:
        step = _view((MK, 9, HEAD_A, rs.READY), (THEHUB, 20, HEAD_B, rs.READY))
        reader = FakeReader(
            {(MK, 9): _live(MK, 9, HEAD_A), (THEHUB, 20): _live(THEHUB, 20, HEAD_B)}
        )

        result = await _check(step, reader, _ask((MK, 9, HEAD_A), (THEHUB, 20, HEAD_B)))

        assert result.accepted
        assert [(o.repo_full_name, o.number, o.head_sha) for o in result.outcomes] == [
            (THEHUB, 20, HEAD_B), (MK, 9, HEAD_A),
        ]
        assert [o.result for o in result.outcomes] == ["accepted", "accepted"]

    async def test_a_moved_head_refuses_the_whole_batch(self) -> None:
        """Never move an approved head, and never queue one that moved."""
        step = _view((MK, 1, HEAD_A, rs.READY), (MK, 2, HEAD_B, rs.READY))
        reader = FakeReader({(MK, 1): _live(MK, 1, HEAD_A), (MK, 2): _live(MK, 2, HEAD_C)})

        result = await _check(step, reader, _ask((MK, 1, HEAD_A), (MK, 2, HEAD_B)))

        assert not result.accepted
        assert "head moved" in result.outcomes[1].reason
        assert result.outcomes[0].result == "not_queued"

    async def test_a_stacked_pull_request_is_refused(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.READY))
        reader = FakeReader({(MK, 1): _live(MK, 1, HEAD_A, base_branch="feat/base")})

        result = await _check(step, reader, _ask((MK, 1, HEAD_A)))

        assert not result.accepted
        assert "stacked" in result.outcomes[0].reason

    async def test_one_the_sheet_no_longer_calls_ready_is_refused(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.BLOCKED))
        reader = FakeReader({(MK, 1): _live(MK, 1, HEAD_A)})

        result = await _check(step, reader, _ask((MK, 1, HEAD_A)))

        assert not result.accepted
        assert "not ready" in result.outcomes[0].reason

    async def test_one_not_on_the_sheet_is_refused(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.READY))
        reader = FakeReader({(MK, 7): _live(MK, 7, HEAD_A)})

        result = await _check(step, reader, _ask((MK, 7, HEAD_A)))

        assert not result.accepted
        assert "not on the run sheet" in result.outcomes[0].reason

    async def test_a_head_the_sheet_did_not_show_is_refused(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.READY))
        reader = FakeReader({(MK, 1): _live(MK, 1, HEAD_B)})

        result = await _check(step, reader, _ask((MK, 1, HEAD_B)))

        assert not result.accepted
        assert "not the head the run sheet showed" in result.outcomes[0].reason

    async def test_a_closed_or_unreadable_pull_request_is_refused(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.READY), (MK, 2, HEAD_B, rs.READY))
        reader = FakeReader({(MK, 1): _live(MK, 1, HEAD_A, state="closed")})

        result = await _check(step, reader, _ask((MK, 1, HEAD_A), (MK, 2, HEAD_B)))

        assert not result.accepted
        assert "not open" in result.outcomes[0].reason
        assert "could not be read" in result.outcomes[1].reason

    async def test_github_down_refuses_rather_than_trusting_the_sheet(self) -> None:
        step = _view((MK, 1, HEAD_A, rs.READY))

        result = await _check(step, FakeReader({}, down=True), _ask((MK, 1, HEAD_A)))

        assert not result.accepted
        assert "could not be read" in result.outcomes[0].reason


def _deploy_step(state: str = rs.READY, gate: str = rs.READY) -> rs.Step:
    return rs.Step(
        key="deploy",
        title="Deploy",
        state=state,
        summary="",
        items=[rs.Item("risk gate", gate, "go", rs.OWNER_CI)],
    )


def _facts(**overrides: Any) -> rs.DeployFacts:
    base: dict[str, Any] = {
        "repo": MK,
        "running_sha": RUNNING,
        "main_sha": MAIN,
        "delivery": ("completed", "success"),
        "lanes": {"unit": "succeeded", "lint-and-types": "succeeded"},
        "decision": {"found": True, "recommendation": "go"},
        "now": datetime(2026, 11, 9, 18, 0),
    }
    base.update(overrides)
    return rs.DeployFacts(**base)


class TestTheDeployGuards:
    def test_every_guard_green_is_no_refusal(self) -> None:
        assert ra.deploy_refusal(_deploy_step(), _facts(), MAIN, open_requests=0) is None

    @pytest.mark.parametrize(
        ("step", "facts", "sha", "open_requests", "why"),
        [
            (_deploy_step(rs.BLOCKED), _facts(), MAIN, 0, "not ready"),
            (_deploy_step(gate=rs.WAITING), _facts(), MAIN, 0, "risk gate"),
            (_deploy_step(), _facts(), HEAD_A, 0, "main is"),
            (_deploy_step(), _facts(), MAIN, 1, "already queued"),
            (_deploy_step(), _facts(lanes={"unit": "failed", "lint-and-types": "succeeded"}),
             MAIN, 0, "unit"),
            (_deploy_step(), _facts(delivery=("completed", "failure")), MAIN, 0, "Delivery"),
            (_deploy_step(), _facts(now=datetime(2026, 11, 9, 3, 0)), MAIN, 0, "backup window"),
        ],
        ids=["step", "gate", "sha", "queued", "lane", "delivery", "window"],
    )
    def test_each_guard_refuses_on_its_own(
        self, step: rs.Step, facts: rs.DeployFacts, sha: str, open_requests: int, why: str
    ) -> None:
        refusal = ra.deploy_refusal(step, facts, sha, open_requests=open_requests)

        assert refusal is not None and why in refusal


# -- The routes -----------------------------------------------------------------


@pytest.fixture
def actions_on(client: TestClient) -> TestClient:
    client.app.state.settings = client.app.state.settings.model_copy(  # type: ignore[attr-defined]
        update={"runsheet_actions_enabled": True}
    )
    return client


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    minted = client.post(
        "/api/agents/credentials",
        json={"family": "claude-opus-5.5", "purpose": "runsheet-test"},
        headers=admin_auth,
    )
    assert minted.status_code == 201, minted.text
    return {"Authorization": f"Bearer {minted.json()['token']}"}


MERGE_BODY = {
    "pull_requests": [{"repo_full_name": MK, "number": 1, "head_sha": HEAD_A}],
    "acknowledged_host_guards": True,
}
DEPLOY_BODY = {"sha": MAIN, "acknowledged_host_guards": True}


class TestSwitchedOff:
    def test_the_flag_defaults_off(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        assert client.app.state.settings.runsheet_actions_enabled is False  # type: ignore[attr-defined]

    def test_merge_is_refused_while_off(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        r = client.post("/api/dashboard/today/merge", json=MERGE_BODY, headers=admin_auth)

        assert r.status_code == 403
        assert "switched off" in r.json()["detail"]

    def test_deploy_is_refused_while_off(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        r = client.post("/api/dashboard/today/deploy", json=DEPLOY_BODY, headers=admin_auth)

        assert r.status_code == 403

    def test_the_sheet_says_the_actions_are_off(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = client.get("/api/dashboard/today", headers=admin_auth).json()

        assert body["actions_enabled"] is False


class TestWhoMayPress:
    @pytest.mark.parametrize("path", ["/api/dashboard/today/merge", "/api/dashboard/today/deploy"])
    def test_an_agent_is_refused_even_when_on(
        self, actions_on: TestClient, admin_auth: dict[str, str], path: str
    ) -> None:
        body = MERGE_BODY if path.endswith("merge") else DEPLOY_BODY

        r = actions_on.post(path, json=body, headers=_agent(actions_on, admin_auth))

        assert r.status_code == 403

    @pytest.mark.parametrize("path", ["/api/dashboard/today/merge", "/api/dashboard/today/deploy"])
    def test_a_viewer_is_refused(
        self, actions_on: TestClient, viewer_auth: dict[str, str], path: str
    ) -> None:
        body = MERGE_BODY if path.endswith("merge") else DEPLOY_BODY

        assert actions_on.post(path, json=body, headers=viewer_auth).status_code == 403


def _patch_merge(monkeypatch: pytest.MonkeyPatch, step: rs.Step, reader: FakeReader) -> None:
    async def view(state: Any, now: datetime) -> rs.Step:
        return step

    monkeypatch.setattr(ra, "merge_view", view)
    monkeypatch.setattr(ra, "reader_for", lambda state: reader.client_for)


def _one_ready(head: str) -> tuple[rs.Step, FakeReader]:
    return _view((MK, 1, HEAD_A, rs.READY)), FakeReader({(MK, 1): _live(MK, 1, head)})


class TestTheMergeRoute:
    def test_the_host_guards_must_be_acknowledged(
        self, actions_on: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = {**MERGE_BODY, "acknowledged_host_guards": False}

        r = actions_on.post("/api/dashboard/today/merge", json=body, headers=admin_auth)

        assert r.status_code == 422

    def test_a_batch_is_at_most_five(
        self, actions_on: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = {
            "pull_requests": [
                {"repo_full_name": MK, "number": n, "head_sha": HEAD_A} for n in range(6)
            ],
            "acknowledged_host_guards": True,
        }

        r = actions_on.post("/api/dashboard/today/merge", json=body, headers=admin_auth)

        assert r.status_code == 422

    def test_it_queues_the_batch_and_audits_each_pull_request(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos.db.models import RunsheetRequest

        _patch_merge(monkeypatch, *_one_ready(HEAD_A))

        r = actions_on.post("/api/dashboard/today/merge", json=MERGE_BODY, headers=admin_auth)

        assert r.status_code == 202, r.text
        body = r.json()
        assert body["state"] == "queued"
        assert [o["result"] for o in body["outcomes"]] == ["accepted"]
        with actions_on.app.state.db.session() as session:  # type: ignore[attr-defined]
            (row,) = session.query(RunsheetRequest).filter_by(kind="merge").all()
            assert row.items == [{"repo_full_name": MK, "number": 1, "head_sha": HEAD_A}]
        entries = audit_entries(actions_on, "runsheet.merge_request")
        assert [(e.detail["number"], e.detail["head_sha"]) for e in entries] == [(1, HEAD_A)]

    def test_one_batch_at_a_time(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_merge(monkeypatch, *_one_ready(HEAD_A))
        actions_on.post("/api/dashboard/today/merge", json=MERGE_BODY, headers=admin_auth)

        r = actions_on.post("/api/dashboard/today/merge", json=MERGE_BODY, headers=admin_auth)

        assert r.status_code == 409
        assert "already queued" in r.json()["detail"]["reason"]

    def test_a_refused_batch_is_a_409_with_reasons_and_queues_nothing(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mykronos.db.models import RunsheetRequest

        _patch_merge(monkeypatch, *_one_ready(HEAD_B))

        r = actions_on.post("/api/dashboard/today/merge", json=MERGE_BODY, headers=admin_auth)

        assert r.status_code == 409
        assert "head moved" in r.json()["detail"]["outcomes"][0]["reason"]
        with actions_on.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.query(RunsheetRequest).count() == 0
        entry = audit_entries(actions_on, "runsheet.merge_request")[0]
        assert entry.detail["outcome"] == "refused"


class TestTheDeployRoute:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, facts: rs.DeployFacts) -> None:
        async def view(state: Any, now: datetime) -> tuple[rs.Step, rs.DeployFacts]:
            return _deploy_step(), facts

        monkeypatch.setattr(ra, "deploy_view", view)

    def test_it_queues_one_request_for_the_host_runner(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, _facts())

        r = actions_on.post("/api/dashboard/today/deploy", json=DEPLOY_BODY, headers=admin_auth)

        assert r.status_code == 202, r.text
        body = r.json()
        assert body["state"] == "queued"
        assert body["sha"] == MAIN
        assert any("host" in note for note in body["notes"])
        assert audit_entries(actions_on, "runsheet.deploy_request")[0].detail["sha"] == MAIN

    def test_a_second_request_is_refused_while_one_is_queued(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, _facts())
        actions_on.post("/api/dashboard/today/deploy", json=DEPLOY_BODY, headers=admin_auth)

        r = actions_on.post("/api/dashboard/today/deploy", json=DEPLOY_BODY, headers=admin_auth)

        assert r.status_code == 409
        assert "already queued" in r.json()["detail"]

    def test_a_guard_refusal_is_a_409_and_audited(
        self, actions_on: TestClient, admin_auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, replace(_facts(), main_sha=HEAD_A))

        r = actions_on.post("/api/dashboard/today/deploy", json=DEPLOY_BODY, headers=admin_auth)

        assert r.status_code == 409
        entry = audit_entries(actions_on, "runsheet.deploy_request")[0]
        assert entry.detail["outcome"] == "refused"
