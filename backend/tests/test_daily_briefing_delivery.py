"""The daily briefing's board and pull-request side (TheHub #60861, B3).

"Needs you today", sprint health, pull-request readiness, and the board check
that keeps suggested focus and next-sprint candidates to new work. TheHub and
GitHub are both fakes here: `FakeHub` behind `httpx2.MockTransport`, and
`FakeGitHubClient`. Each source has a "could not read" test as well as its
ordinary one, and the cache has its own.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from mykronos import briefing_sources, daily_briefing, delivery_sources
from mykronos.delivery_sources import BoardRead, DeliveryInputs, OpenPullRequest
from mykronos.github.client import ChecksSummary, PullRequest
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload
from tests.po_support import FakeHub, attach_hub, story
from tests.po_support import onboard as onboard_row
from tests.test_daily_briefing import _everything_read, _get, _scan, _section
from tests.test_onboarding import onboard


@pytest.fixture(autouse=True)
def _fresh_cache() -> Any:
    delivery_sources.clear_cache()
    yield
    delivery_sources.clear_cache()


@pytest.fixture
def gathered(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    holder: dict[str, Any] = {"inputs": _everything_read()}
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: holder["inputs"])
    return holder


def _iso(delta: timedelta) -> str:
    return (utcnow() - delta).isoformat()


def _pr(
    github: Any,
    number: int,
    *,
    title: str = "A change",
    body: str = "",
    sha: str = "",
    conclusion: str | None = "success",
    mergeable: bool | None = True,
    mergeable_state: str = "clean",
    base: str = "main",
    draft: bool = False,
    branch: str = "",
    age_days: int = 2,
) -> PullRequest:
    sha = sha or f"{number:040d}"
    pr = PullRequest(
        number=number,
        url=f"https://github.com/{REPO}/pull/{number}",
        head_branch=branch or f"feat/x-{number}",
        title=title,
        draft=draft,
        created_at=utcnow() - timedelta(days=age_days),
        head_sha=sha,
        base_branch=base,
        mergeable=mergeable,
        mergeable_state=mergeable_state,
        body=body,
    )
    github.repos[REPO].pull_requests.append(pr)
    github.repos[REPO].check_runs.append({"head_sha": sha, "conclusion": conclusion})
    return pr


def _open_pr(**overrides: Any) -> OpenPullRequest:
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "number": 1,
        "url": "u",
        "title": "t",
        "draft": False,
        "head_branch": "feat/x",
        "base_branch": "main",
        "default_branch": "main",
        "opened_at": utcnow() - timedelta(days=1),
        "checks": ChecksSummary(total=2, passed=2),
        "mergeable": True,
        "mergeable_state": "clean",
        "detail_read": True,
    }
    values.update(overrides)
    return OpenPullRequest(**values)


# ---------------------------------------------------------------------------
# What a pull request says about itself
# ---------------------------------------------------------------------------


class TestReferences:
    def test_story_ids_from_title_body_and_branch(self) -> None:
        assert delivery_sources.story_refs(
            "fix(ci): follow-ups (TheHub #60848 #60851 #60853)",
            "Stories: 60900\n\nAlso touches #60901.",
            branch="feat/daily-briefing-b3-60861-v2",
        ) == [60848, 60851, 60853, 60900, 60901, 60861]

    def test_a_short_pull_request_number_is_not_a_story(self) -> None:
        assert delivery_sources.story_refs("Stacks on #975") == []

    def test_depends_on(self) -> None:
        assert delivery_sources.depends_on(
            "This stacks on #975; depends on ToddGBenson/mykronos#12."
        ) == [975, 12]


class TestReadiness:
    @pytest.mark.parametrize(
        ("overrides", "state"),
        [
            ({}, "ready"),
            ({"draft": True}, "draft"),
            ({"base_branch": "feat/b2"}, "waiting"),
            ({"depends_on": [975]}, "waiting"),
            ({"mergeable": False, "mergeable_state": "dirty"}, "conflict"),
            ({"checks": ChecksSummary(total=3, passed=2, failed=1)}, "red"),
            ({"mergeable_state": "behind"}, "behind"),
            ({"checks": None}, "unknown"),
            ({"checks": ChecksSummary(total=2, passed=1, pending=1)}, "pending"),
            ({"mergeable": None, "mergeable_state": "unknown"}, "unknown"),
            ({"mergeable": None, "detail_read": False}, "unknown"),
            ({"mergeable_state": "blocked"}, "ready"),
        ],
    )
    def test_states(self, overrides: dict[str, Any], state: str) -> None:
        assert daily_briefing.pr_readiness(_open_pr(**overrides), now=utcnow()).state == state

    def test_never_guessed_ready_without_a_verdict(self) -> None:
        r = daily_briefing.pr_readiness(_open_pr(mergeable=None), now=utcnow())
        assert r.state != "ready"


# ---------------------------------------------------------------------------
# Needs you today
# ---------------------------------------------------------------------------


class TestNeedsYou:
    def test_board_items_and_pull_requests(self, client, admin_auth, github, gathered) -> None:
        onboard_row(client)
        hub = FakeHub(
            [
                story(id=10, bucket="icebox", title="OPERATOR ACTION: rotate the Fly token",
                      created_at=_iso(timedelta(days=4))),
                story(id=11, bucket="icebox", title="An idea for later"),
                story(id=12, bucket="backlog", title="DECISION: keep the nightly DAST lane?"),
                story(id=13, bucket="backlog", title="Ordinary backlog story"),
            ]
        )
        attach_hub(client, hub)
        _pr(github, 1, title="Ready one")
        _pr(github, 2, title="Red one", conclusion="failure")
        _pr(github, 3, title="Conflicted", mergeable=False, mergeable_state="dirty")
        _pr(github, 4, title="Stacked", base="feat/daily-briefing-b2-60860")
        _pr(github, 5, title="Draft", draft=True)

        section = _section(_get(client, admin_auth), "needs_you_today")

        assert section["status"] == "ok", section["reason"]
        assert section["as_of"] is not None
        by_what = {line["what"]: line for line in section["lines"]}
        assert by_what[f"Merge {REPO}#1: Ready one"]["work"] == "merge"
        assert by_what["DECISION: keep the nightly DAST lane?"]["work"] == "decision"
        assert by_what["DECISION: keep the nightly DAST lane?"]["ref"] == "TheHub #12"
        action = by_what["OPERATOR ACTION: rotate the Fly token"]
        assert action["work"] == "story"
        assert "4 day(s)" in action["so_what"]
        assert not any("idea for later" in w or "Ordinary" in w for w in by_what)
        red = next(line for line in section["lines"] if f"{REPO}#2" in line["what"])
        assert red["work"] == "story" and "failed" in red["what"]
        stacked = next(line for line in section["lines"] if f"{REPO}#4" in line["what"])
        assert stacked["work"] == "merge"
        assert not any(f"{REPO}#5" in line["what"] for line in section["lines"])

        readiness = section["data"]["pr_readiness"]
        assert readiness["open"] == 5
        assert [r["number"] for r in readiness["ready"]] == [1]
        assert {r["number"]: r["state"] for r in readiness["blocked"]} == {
            2: "red", 3: "conflict", 4: "waiting"
        }
        assert [r["number"] for r in readiness["failed_checks"]] == [2]
        assert readiness["drafts"] == 1
        assert section["data"]["board"]["operator_actions"][0]["id"] == 10
        assert section["data"]["board"]["decisions"][0]["id"] == 12
        # Decisions lead the page's own lines after the merges.
        works = [line["work"] for line in section["lines"]]
        assert works.index("decision") < works.index("story")

    def test_hub_not_connected_is_partial_and_says_so(
        self, client, admin_auth, github, gathered
    ) -> None:
        onboard_row(client)
        _pr(github, 1)
        section = _section(_get(client, admin_auth), "needs_you_today")
        assert section["status"] == "partial"
        assert "TheHub is not connected" in section["reason"]
        assert section["lines"][0]["work"] == "merge"

    def test_hub_failing_is_partial(self, client, admin_auth, github, gathered) -> None:
        onboard_row(client)
        hub = FakeHub([])
        hub.failing.add("/api/dev/stories")
        attach_hub(client, hub)
        section = _section(_get(client, admin_auth), "needs_you_today")
        assert section["status"] == "partial"
        assert "TheHub's board could not be read" in section["reason"]

    def test_nothing_readable_is_unavailable_not_empty(self) -> None:
        delivery = DeliveryInputs(
            board=None, board_error="Hub down.", pull_requests=None,
            pull_requests_error="GitHub down.",
        )
        section = daily_briefing.needs_you_section(delivery, now=utcnow())
        assert section.status == "unavailable"
        assert "Hub down." in section.reason and "GitHub down." in section.reason
        assert section.lines == []

    def test_every_repository_unreachable_is_unavailable_for_prs(
        self, client, admin_auth, github, gathered
    ) -> None:
        onboard_row(client)
        del github.repos[REPO]
        attach_hub(client, FakeHub([]))
        section = _section(_get(client, admin_auth), "needs_you_today")
        assert section["status"] == "partial"
        assert "no onboarded repository" in section["reason"].lower()
        assert "pr_readiness" not in section["data"]

    def test_an_unreadable_mergeable_verdict_is_not_ready(
        self, client, admin_auth, github, gathered, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        onboard_row(client)
        attach_hub(client, FakeHub([]))
        _pr(github, 1)
        _pr(github, 2)
        monkeypatch.setattr(delivery_sources, "MAX_DETAIL_READS", 1)
        section = _section(_get(client, admin_auth), "needs_you_today")
        assert section["status"] == "partial"
        assert "no mergeable verdict" in section["reason"]
        assert section["data"]["pr_readiness"]["details_unread"] == 1
        assert len(section["data"]["pr_readiness"]["ready"]) == 1


# ---------------------------------------------------------------------------
# Sprint health
# ---------------------------------------------------------------------------


class TestSprintHealth:
    def test_gates_stuck_no_pr_and_deployed(self, client, admin_auth, github, gathered) -> None:
        onboard_row(client)
        hub = FakeHub(
            [
                story(id=60001, bucket="sprint", gate="in_progress", title="Has a PR",
                      updated_at=_iso(timedelta(hours=2))),
                story(id=60002, bucket="sprint", gate="ready", title="No PR yet",
                      updated_at=_iso(timedelta(hours=2))),
                story(id=60003, bucket="sprint", gate="in_progress", title="Stuck one",
                      updated_at=_iso(timedelta(days=5))),
                story(id=60004, bucket="sprint", gate="deployed", title="Shipped today",
                      updated_at=_iso(timedelta(hours=3))),
                story(id=60005, bucket="done", gate="verified", title="Closed last week",
                      updated_at=_iso(timedelta(days=6)), closed_at=_iso(timedelta(days=6))),
                story(id=60006, bucket="done", gate="verified", title="Closed today",
                      updated_at=_iso(timedelta(hours=1)), closed_at=_iso(timedelta(hours=1))),
            ]
        )
        attach_hub(client, hub)
        _pr(github, 7, title="feat: the thing (TheHub #60001)")
        _pr(github, 8, title="chore", branch="fix/stuck-60003")

        section = _section(_get(client, admin_auth), "sprint_health")

        assert section["status"] == "ok", section["reason"]
        data = section["data"]
        assert data["sprint_stories"] == 4
        assert data["by_gate"]["in_progress"] == 2
        assert data["by_gate"]["ready"] == 1
        assert data["by_gate"]["deployed"] == 1
        assert data["by_gate"]["intake"] == 0
        assert [s["id"] for s in data["stuck"]] == [60003]
        assert [s["id"] for s in data["no_pull_request"]] == [60002]
        assert sorted(s["id"] for s in data["deployed_last_24h"]) == [60004, 60006]
        works = {line["ref"]: line["work"] for line in section["lines"]}
        assert works == {"TheHub #60003": "decision", "TheHub #60002": "story"}

    def test_board_unreadable_is_unavailable(self, client, admin_auth, gathered) -> None:
        section = _section(_get(client, admin_auth), "sprint_health")
        assert section["status"] == "unavailable"
        assert "TheHub is not connected" in section["reason"]

    def test_no_pull_requests_read_is_partial(self) -> None:
        board = BoardRead(
            stories={"sprint": [story(id=60002, bucket="sprint", gate="ready")]},
            as_of=utcnow(),
        )
        section = daily_briefing.sprint_health_section(
            DeliveryInputs(board=board, pull_requests=None, pull_requests_error="GitHub down."),
            now=utcnow(),
        )
        assert section.status == "partial"
        assert "GitHub down." in section.reason
        assert section.data["no_pull_request"] is None


# ---------------------------------------------------------------------------
# Already on the board
# ---------------------------------------------------------------------------


def _line(what: str, ref: str = "", work: str = "story") -> daily_briefing.Line:
    return daily_briefing.Line(what=what, so_what="s", work=work, ref=ref)


class TestOnBoard:
    def test_by_referenced_id(self) -> None:
        stories = [story(id=1, detail="Fix group fix-abc123 from the briefing")]
        assert daily_briefing.on_board(_line("Upgrade lodash", ref="fix-abc123"), stories)

    def test_by_title(self) -> None:
        stories = [story(id=1, title="Repair the sast lane (failing).")]
        assert daily_briefing.on_board(_line("Repair the sast lane (failing)."), stories)

    def test_a_route_ref_is_not_an_id(self) -> None:
        stories = [story(id=1, detail="see /api/exposure")]
        line = _line("Something else", ref="/api/exposure")
        assert daily_briefing.on_board(line, stories) is None

    def test_a_short_title_does_not_match_by_containment(self) -> None:
        stories = [story(id=1, title="sast")]
        assert daily_briefing.on_board(_line("Repair the sast lane"), stories) is None

    def test_focus_leaves_out_what_is_already_a_story(self) -> None:
        now = utcnow()
        sections = [
            daily_briefing.Section(
                key="trust", title="Trust", status="ok", source="x", as_of=now,
                lines=[_line("Repair the sast lane in payments-api"), _line("Something new")],
            ),
            daily_briefing.Section(
                key="needs_you_today", title="Needs you", status="ok", source="x", as_of=now,
                lines=[_line("DECISION: x", work="decision")],
            ),
        ]
        board = BoardRead(
            stories={"backlog": [story(id=5, title="Repair the sast lane in payments-api")]},
            as_of=now,
        )
        focus = daily_briefing.focus_section(sections, now=now, board=board)
        assert focus.status == "ok"
        assert [line.what for line in focus.lines] == ["DECISION: x", "Something new"]
        assert focus.data["already_on_board"] == [
            {"what": "Repair the sast lane in payments-api", "story": "TheHub #5"}
        ]

    def test_focus_without_the_board_is_partial(self) -> None:
        now = utcnow()
        sections = [daily_briefing.Section(key="a", title="A", status="ok", source="x",
                                           as_of=now, lines=[_line("x")])]
        focus = daily_briefing.focus_section(sections, now=now, board=None,
                                             board_error="Hub down.")
        assert focus.status == "partial"
        assert "Hub down." in focus.reason

    def test_candidates_leave_out_existing_stories(
        self, client, admin_auth, auth, run_compaction, catalog, gathered
    ) -> None:
        onboard(client, admin_auth)
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        unfiltered = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=BoardRead(stories={}, as_of=utcnow())
        )
        assert unfiltered.status == "ok"
        fix = unfiltered.lines[0]
        board = BoardRead(
            stories={"backlog": [story(id=9, title="x", detail=f"Covers {fix.ref}.")]},
            as_of=utcnow(),
        )
        filtered = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=board
        )
        assert fix.ref not in [line.ref for line in filtered.lines]
        assert filtered.data["already_on_board"][0]["story"] == "TheHub #9"

        partial = daily_briefing.next_sprint_candidates(
            catalog, None, REPO, as_of=None, board=None, board_error="Hub down."
        )
        assert partial.status == "partial"
        assert "Hub down." in partial.reason


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------


class TestCache:
    def test_a_second_load_does_not_ask_again(self, client, admin_auth, github, gathered) -> None:
        onboard_row(client)
        hub = FakeHub([story(id=1, bucket="sprint")])
        attach_hub(client, hub)
        _pr(github, 1)

        _get(client, admin_auth)
        hub_calls, gh_calls = len(hub.calls), len(github.calls)
        _get(client, admin_auth)

        assert len(hub.calls) == hub_calls
        assert len(github.calls) == gh_calls

    def test_a_failure_after_a_success_serves_the_earlier_answer_as_partial(
        self, client, admin_auth, github, gathered, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        onboard_row(client)
        hub = FakeHub([story(id=12, bucket="backlog", title="DECISION: yes or no")])
        attach_hub(client, hub)
        _get(client, admin_auth)

        monkeypatch.setattr(delivery_sources, "BOARD_TTL_SECONDS", 0.0)
        hub.failing.add("/api/dev/stories")
        section = _section(_get(client, admin_auth), "needs_you_today")

        assert section["status"] == "partial"
        assert "TheHub's board could not be read" in section["reason"]
        assert "The board is as of" in section["reason"]
        assert any(line["what"] == "DECISION: yes or no" for line in section["lines"])

    def test_a_failure_is_not_cached(
        self, client, admin_auth, github, gathered
    ) -> None:
        onboard_row(client)
        hub = FakeHub([story(id=12, bucket="backlog", title="DECISION: yes or no")])
        hub.failing.add("/api/dev/stories")
        attach_hub(client, hub)
        assert _section(_get(client, admin_auth), "sprint_health")["status"] == "unavailable"

        hub.failing.clear()
        assert _section(_get(client, admin_auth), "sprint_health")["status"] == "ok"

    def test_too_old_to_stand_in(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cache: Any = delivery_sources._Cache()

        class Key:
            pass

        key = Key()
        cache.put(key, "answer", 0.0)
        assert cache.fresh(key, 10.0, 5.0) == "answer"
        assert cache.fresh(key, 10.0, 11.0) is None
        assert cache.fallback(key, delivery_sources.STALE_LIMIT_SECONDS - 1) == "answer"
        assert cache.fallback(key, delivery_sources.STALE_LIMIT_SECONDS + 1) is None


# ---------------------------------------------------------------------------
# GitHub's single-PR read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rest_get_pull_request_reads_mergeable_and_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mykronos.github.client import RestGitHubClient

    async def fake_json(self: Any, method: str, path: str, **_kwargs: Any) -> Any:
        return {
            "number": 7,
            "html_url": "https://github.com/o/r/pull/7",
            "state": "open",
            "head": {"ref": "feat/x-60861", "sha": "abc"},
            "base": {"ref": "main"},
            "title": "t",
            "created_at": "2026-10-20T00:00:00Z",
            "mergeable": False,
            "mergeable_state": "dirty",
            "body": "Stacks on #975",
        }

    client = RestGitHubClient.__new__(RestGitHubClient)
    monkeypatch.setattr(RestGitHubClient, "_json", fake_json)
    pr = await client.get_pull_request("o/r", 7)
    assert pr is not None
    assert pr.mergeable is False
    assert pr.mergeable_state == "dirty"
    assert pr.body == "Stacks on #975"

    async def computing(self: Any, method: str, path: str, **_kwargs: Any) -> Any:
        return {"number": 7, "html_url": "u", "mergeable": None}

    monkeypatch.setattr(RestGitHubClient, "_json", computing)
    pr = await client.get_pull_request("o/r", 7)
    assert pr is not None and pr.mergeable is None
