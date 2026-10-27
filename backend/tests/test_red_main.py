"""A gating lane that goes red on main is announced on the next poll (TheHub #60973).

These pin, against a Concourse faked from the API's own shapes (job list with
`finished_build` / `transition_build`; `source` versions with `metadata`; each
version's `input_to` builds):

* green -> red sends exactly one message: repo, lane, build, the first failing
  commit (12-char sha and subject) and the last green sha;
* red -> red sends nothing, including after a restart, because the state is
  in the database;
* red -> green sends one recovery message with the red duration;
* a build Concourse's versions do not cover says `commit unknown`;
* test totals come from an ingested JUnit run, or the message says none was
  uploaded; never test names, never build logs;
* the CI page exposes `red_since` and `first_bad_sha` per red gating lane.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import jobs, main, red_main
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.notify import Notification

NOW = datetime(2026, 10, 22, 20, 0, tzinfo=UTC)
REPO = "ToddGBenson/mykronos"
BASE = "/api/v1/teams/main/pipelines/mykronos"
GATING = {REPO: ["unit", "lint-and-types", "pin-check"]}


def sha(n: int) -> str:
    return f"{n:x}".rjust(2, "0") * 20


def ts(hours_ago: float) -> int:
    return int((NOW - timedelta(hours=hours_ago)).timestamp())


class Recorder:
    def __init__(self, *, delivers: bool = True) -> None:
        self.sent: list[Notification] = []
        self.delivers = delivers

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return self.delivers


def _job(name: str, status: str, build: int, *, transition: int | None = None,
         transition_status: str | None = None, ended: float = 0.5) -> dict[str, Any]:
    job: dict[str, Any] = {
        "name": name,
        "finished_build": {
            "id": 9000 + build, "name": str(build), "status": status,
            "start_time": ts(ended + 0.2), "end_time": ts(ended),
        },
    }
    if transition is not None:
        job["transition_build"] = {
            "id": 9000 + transition, "name": str(transition),
            "status": transition_status or status,
            "start_time": ts(ended + 2.2), "end_time": ts(ended + 2),
        }
    return job


def fake_concourse(
    jobs_payload: list[dict[str, Any]],
    commits: list[tuple[str, str, list[dict[str, Any]]]] | None = None,
    *,
    fail: str | None = None,
    base: str = BASE,
) -> tuple[red_main.Fetch, list[str]]:
    """`commits` newest first: (sha, subject, builds it was an input to)."""
    calls: list[str] = []
    routes: dict[str, Any] = {f"{base}/jobs": jobs_payload}
    versions = []
    for index, (ref, subject, builds) in enumerate(commits or []):
        version_id = 500 - index
        versions.append({
            "id": version_id,
            "version": {"ref": ref},
            "metadata": [
                {"name": "commit", "value": ref},
                {"name": "message", "value": f"{subject}\n\nbody text"},
            ],
        })
        routes[f"{base}/resources/source/versions/{version_id}/input_to"] = builds
    routes[f"{base}/resources/source/versions?limit={red_main.VERSION_WINDOW}"] = versions

    def fetch(path: str) -> Any:
        calls.append(path)
        if fail and fail in path:
            raise OSError("connection refused")
        if path not in routes:
            raise KeyError(path)
        return routes[path]

    return fetch, calls


def ib(job: str, build: int, status: str) -> dict[str, Any]:
    """One `input_to` build."""
    return {"id": 9000 + build, "name": str(build), "job_name": job, "status": status}


def all_green(**override: dict[str, Any]) -> list[dict[str, Any]]:
    jobs_payload = {
        "unit": _job("unit", "succeeded", 459),
        "lint-and-types": _job("lint-and-types", "succeeded", 700),
        "pin-check": _job("pin-check", "succeeded", 327),
    }
    jobs_payload.update(override)
    return list(jobs_payload.values())


#: main as Concourse saw it: unit #460 ran sha(3), #459 (green) ran sha(2).
HISTORY = [
    (sha(3), "feat: the change that broke unit", [ib("unit", 460, "failed"),
                                                  ib("pin-check", 328, "failed")]),
    (sha(2), "fix: the last good one", [ib("unit", 459, "succeeded"),
                                        ib("pin-check", 327, "succeeded")]),
    (sha(1), "older", [ib("unit", 458, "succeeded")]),
]

NO_TESTS: red_main.TestLookup = lambda repo, commit, lane: None  # noqa: E731


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


async def poll(db: Any, fetch: red_main.Fetch, notifier: Recorder | None = None, *,
               tests: red_main.TestLookup = NO_TESTS, now: datetime = NOW,
               link_base: str = "") -> red_main.RedMainReport:
    return await jobs.announce_red_main(
        "", db=db, gating=GATING, tests=tests, notifier=notifier, fetch=fetch,
        now=now, link_base=link_base,
    )


class TestGreenToRed:
    async def test_one_message_names_the_lane_build_and_both_commits(self, db: Any) -> None:
        notifier = Recorder()
        fetch, _ = fake_concourse(all_green(), HISTORY)
        await poll(db, fetch, notifier)
        assert notifier.sent == [], "green on first sight is recorded, not announced"

        fetch, _ = fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)
        await poll(db, fetch, notifier)

        [note] = notifier.sent
        body = "\n".join(note.lines)
        assert note.title == f"Red on main: {REPO} unit"
        assert note.level == "warning"
        assert "unit failed on main, build 460" in body
        assert f"First failing commit: {sha(3)[:12]} feat: the change that broke unit" in body
        assert sha(3)[:13] not in body, "a 12-character sha"
        assert "body text" not in body, "the subject line only"
        assert f"Last green: {sha(2)[:12]} (build 459)" in body

    async def test_the_first_failing_build_is_the_transition_build(self, db: Any) -> None:
        """Two red builds between polls: the first of them is the culprit."""
        notifier = Recorder()
        await poll(db, fake_concourse(all_green(), HISTORY)[0], notifier)
        history = [(sha(4), "later red", [ib("unit", 461, "failed")]), *HISTORY]

        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), history
        )[0], notifier)

        [note] = notifier.sent
        body = "\n".join(note.lines)
        assert "build 461" in body
        assert f"First failing commit: {sha(3)[:12]}" in body
        assert f"Last green: {sha(2)[:12]}" in body

    async def test_red_on_first_sight_is_announced(self, db: Any) -> None:
        notifier = Recorder()

        await poll(db, fake_concourse(all_green(unit=_job("unit", "errored", 460)), HISTORY)[0],
                   notifier)

        [note] = notifier.sent
        assert "unit errored on main" in "\n".join(note.lines)

    async def test_links_only_with_a_browser_url(self, db: Any) -> None:
        notifier = Recorder()
        fetch, _ = fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)

        await poll(db, fetch, notifier, link_base="https://ci.example.test/teams/main")

        [note] = notifier.sent
        assert note.lines[-1] == (
            "https://ci.example.test/teams/main/pipelines/mykronos/jobs/unit/builds/460"
        )


class TestRedToRed:
    async def test_sends_nothing(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)[0],
                   notifier)
        assert len(notifier.sent) == 1

        history = [(sha(4), "later", [ib("unit", 461, "failed")]), *HISTORY]
        fetch, calls = fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), history
        )
        await poll(db, fetch, notifier, now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 1
        assert calls == [f"{BASE}/jobs"], "no commit walk without a transition"

    async def test_a_restart_does_not_announce_it_again(self, settings: Settings) -> None:
        notifier = Recorder()
        first = Database(settings.database_url)
        first.create_all()
        fetch, _ = fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)
        await poll(first, fetch, notifier)
        first.close()

        # A new process: nothing in memory, the same database.
        second = Database(settings.database_url)
        second.create_all()
        try:
            await poll(second, fetch, notifier, now=NOW + timedelta(minutes=5))
        finally:
            second.close()

        assert len(notifier.sent) == 1

    async def test_an_undelivered_message_is_retried(self, db: Any) -> None:
        fetch, _ = fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)

        with pytest.raises(jobs.RedMainIncompleteError, match="not delivered"):
            await poll(db, fetch, Recorder(delivers=False))
        notifier = Recorder()
        await poll(db, fetch, notifier)

        assert len(notifier.sent) == 1


class TestRedToGreen:
    async def test_one_recovery_message_with_the_red_duration(self, db: Any) -> None:
        notifier = Recorder()
        # The first failing build ended 2.5h before NOW.
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), HISTORY
        )[0], notifier)

        green = all_green(unit=_job("unit", "succeeded", 462, ended=0.5))
        await poll(db, fake_concourse(green, HISTORY)[0], notifier)
        await poll(db, fake_concourse(green, HISTORY)[0], notifier,
                   now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 2, "one red, one recovery, nothing after"
        recovery = notifier.sent[1]
        body = "\n".join(recovery.lines)
        assert recovery.title == f"Green again on main: {REPO} unit"
        assert "build 462 succeeded after being red for 2.0h" in body
        assert f"It went red at build 460, commit {sha(3)[:12]}" in body


class TestRedGreenRedBetweenPolls:
    """Red, then green, then red again, all between two polls (review of #1013).

    The poll only sees red then red, but Concourse's `transition_build` has
    moved: it is a newer red build than the one the lane went red at, so a
    green build came in between and this is a new red, with a new culprit.
    """

    #: unit #462 ran sha(4) and passed; #463 ran sha(5) and failed.
    LATER = [
        (sha(5), "feat: a second, different break", [ib("unit", 463, "failed")]),
        (sha(4), "fix: unit green again", [ib("unit", 462, "succeeded")]),
        *HISTORY,
    ]

    async def test_a_new_red_is_announced_with_its_own_commit(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), HISTORY
        )[0], notifier)
        assert len(notifier.sent) == 1

        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 463, transition=463)), self.LATER
        )[0], notifier, now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 2, "the second red is news"
        body = "\n".join(notifier.sent[1].lines)
        assert f"First failing commit: {sha(5)[:12]} feat: a second, different break" in body
        assert f"Last green: {sha(4)[:12]} (build 462)" in body
        state = jobs.load_lane_states(db)[(REPO, "unit")]
        assert state.first_bad_build == "463"
        assert state.first_bad_sha == sha(5)

    async def test_the_same_red_episode_is_still_silent(self, db: Any) -> None:
        """Guard: an unchanged transition build is the same red, sent once."""
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), HISTORY
        )[0], notifier)

        history = [(sha(5), "later", [ib("unit", 463, "failed")]), *HISTORY]
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 463, transition=460)), history
        )[0], notifier, now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 1

    async def test_failed_then_errored_is_the_same_red(self, db: Any) -> None:
        """Concourse moves `transition_build` on failed -> errored too.

        Both are red and no green build ran in between, so it is the same red:
        silent, and the recorded culprit and start of the red are kept (second
        review of #1013, B1).
        """
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 460, transition=460)), HISTORY
        )[0], notifier)
        before = jobs.load_lane_states(db)[(REPO, "unit")]

        history = [(sha(5), "later", [ib("unit", 461, "errored")]), *HISTORY]
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "errored", 461, transition=461)), history
        )[0], notifier, now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 1, "no green ran: not news"
        state = jobs.load_lane_states(db)[(REPO, "unit")]
        assert state.first_bad_build == "460"
        assert state.first_bad_sha == sha(3)
        assert state.red_since == before.red_since
        assert state.build == "461"

        # The next poll sees the same transition: no commit walk again.
        fetch, calls = fake_concourse(
            all_green(unit=_job("unit", "errored", 461, transition=461)), history
        )
        await poll(db, fetch, notifier, now=NOW + timedelta(minutes=10))
        assert len(notifier.sent) == 1
        assert calls == [f"{BASE}/jobs"], "a checked transition is not walked again"

    async def test_an_unreadable_walk_is_checked_again_next_poll(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 461, transition=460)), HISTORY
        )[0], notifier)

        jobs_now = all_green(unit=_job("unit", "failed", 463, transition=463))
        with pytest.raises(jobs.RedMainIncompleteError, match="red-again check unreadable"):
            await poll(db, fake_concourse(jobs_now, self.LATER, fail="input_to")[0],
                       notifier, now=NOW + timedelta(minutes=5))
        assert len(notifier.sent) == 1

        await poll(db, fake_concourse(jobs_now, self.LATER)[0], notifier,
                   now=NOW + timedelta(minutes=10))
        assert len(notifier.sent) == 2, "the next readable poll finds the green"

    async def test_failed_aborted_failed_is_the_same_red(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 460, transition=460)), HISTORY
        )[0], notifier)

        history = [(sha(6), "again", [ib("unit", 462, "failed")]),
                   (sha(5), "later", [ib("unit", 461, "aborted")]), *HISTORY]
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "aborted", 461, transition=461)), history
        )[0], notifier, now=NOW + timedelta(minutes=5))
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 462, transition=462)), history
        )[0], notifier, now=NOW + timedelta(minutes=10))

        assert len(notifier.sent) == 1
        state = jobs.load_lane_states(db)[(REPO, "unit")]
        assert state.first_bad_build == "460"
        assert state.first_bad_sha == sha(3)

    async def test_a_red_with_no_recorded_first_build_is_still_re_announced(
        self, db: Any
    ) -> None:
        """N1: a red recorded without `first_bad_build` still sees a later green."""
        jobs.save_lane_state(db, red_main.LaneState(
            REPO, "mykronos", "unit", red_main.RED, "failed", "461",
            red_since=NOW - timedelta(hours=3),
        ))
        for lane, build in (("lint-and-types", "700"), ("pin-check", "327")):
            jobs.save_lane_state(db, red_main.LaneState(
                REPO, "mykronos", lane, red_main.GREEN, "succeeded", build,
            ))
        notifier = Recorder()
        await poll(db, fake_concourse(
            all_green(unit=_job("unit", "failed", 463, transition=463)), self.LATER
        )[0], notifier, now=NOW + timedelta(minutes=5))

        assert len(notifier.sent) == 1
        body = "\n".join(notifier.sent[0].lines)
        assert f"First failing commit: {sha(5)[:12]}" in body
        assert f"Last green: {sha(4)[:12]} (build 462)" in body


class TestUnresolvedCommit:
    async def test_a_build_outside_the_window_says_commit_unknown(self, db: Any) -> None:
        notifier = Recorder()
        old = [(sha(2), "unrelated", [ib("unit", 300, "succeeded")])]

        await poll(db, fake_concourse(all_green(unit=_job("unit", "failed", 460)), old)[0],
                   notifier)

        [note] = notifier.sent
        body = "\n".join(note.lines)
        assert "First failing commit: commit unknown" in body
        assert "Tests: not looked up, because the commit is unknown." in body

    async def test_unreadable_versions_say_commit_unknown(self, db: Any) -> None:
        notifier = Recorder()
        fetch, _ = fake_concourse(
            all_green(unit=_job("unit", "failed", 460)), HISTORY, fail="/versions"
        )

        await poll(db, fetch, notifier)

        [note] = notifier.sent
        body = "\n".join(note.lines)
        assert "First failing commit: commit unknown (source versions unreadable" in body
        assert "Last green: unknown." in body


class TestTheTestTotals:
    async def test_no_junit_says_no_test_report(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)[0],
                   notifier)

        [note] = notifier.sent
        assert "Tests: no test report uploaded." in note.lines

    async def test_an_ingested_junit_run_gives_suite_totals(self, db: Any) -> None:
        notifier = Recorder()
        asked: list[tuple[str, str, str]] = []

        def lookup(repo: str, commit: str, lane: str) -> red_main.TestTotals | None:
            asked.append((repo, commit, lane))
            return red_main.TestTotals(3, 120)

        await poll(db, fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)[0],
                   notifier, tests=lookup)

        [note] = notifier.sent
        assert "Tests: 3 of 120 tests failed." in note.lines
        assert asked == [(REPO, sha(3), "unit")]

    async def test_a_failed_lookup_still_announces_every_red_lane(self, db: Any) -> None:
        """A lake error must not abort the poll (review of #1013).

        Both red lanes are announced, the message says the lookup failed
        rather than claiming no report was uploaded, the reds are recorded
        so they are not sent twice, and the run is marked incomplete.
        """
        notifier = Recorder()

        def broken(repo: str, commit: str, lane: str) -> red_main.TestTotals | None:
            raise OSError("lake unreachable at http://lake.internal:9000")

        fetch, _ = fake_concourse(
            all_green(unit=_job("unit", "failed", 460),
                      **{"pin-check": _job("pin-check", "failed", 328)}),
            HISTORY,
        )
        with pytest.raises(jobs.RedMainIncompleteError, match="test totals unreadable"):
            await poll(db, fetch, notifier, tests=broken)

        assert sorted(n.title for n in notifier.sent) == [
            f"Red on main: {REPO} pin-check", f"Red on main: {REPO} unit",
        ]
        for note in notifier.sent:
            assert "Tests: the test report lookup failed." in note.lines
            assert "lake.internal" not in "\n".join(note.lines)
        states = jobs.load_lane_states(db)
        assert states[(REPO, "unit")].state == "red"
        assert states[(REPO, "pin-check")].state == "red"

        await poll(db, fetch, notifier, now=NOW + timedelta(minutes=5))
        assert len(notifier.sent) == 2, "recorded, so not announced again"

    def test_totals_are_read_back_from_the_adapter_detail(self) -> None:
        assert red_main.totals_from_run(
            "failure", "unit: 3 of 120 test(s) failed (2 failure(s), 1 error(s))."
        ) == red_main.TestTotals(3, 120)
        assert red_main.totals_from_run(
            "success", "118 test(s) passed, 2 skipped."
        ) == red_main.TestTotals(0, 120)
        assert red_main.totals_from_run("failure", None).phrase().startswith(
            "a test report was uploaded and failed"
        )

    def test_the_lake_lookup_matches_commit_and_lane(
        self, client: Any, auth: dict[str, str], catalog: Any, run_compaction: Any
    ) -> None:
        from tests.conftest import REPO as LAKE_REPO
        from tests.conftest import post_scan

        for run_id, job, detail in (
            ("22222222-2222-2222-2222-222222222222", "unit",
             "unit: 3 of 120 test(s) failed (3 failure(s), 0 error(s))."),
            ("33333333-3333-3333-3333-333333333333", "lint-and-types",
             "lint-and-types: 1 of 2 test(s) failed (1 failure(s), 0 error(s))."),
        ):
            response = post_scan(
                client, auth, scan_run_id=run_id, tool_name="junit", job=job,
                commit_sha=sha(3), scan_status="failure", finding_count=0, detail=detail,
            )
            assert response.status_code in (200, 201, 202), response.text
        run_compaction()

        lookup = jobs.junit_totals_lookup(catalog)

        assert lookup(LAKE_REPO, sha(3), "unit") == red_main.TestTotals(3, 120)
        assert lookup(LAKE_REPO, sha(3)[:12], "lint-and-types") == red_main.TestTotals(1, 2)
        assert lookup(LAKE_REPO, sha(3), "pin-check") is None, "another lane's report"
        assert lookup(LAKE_REPO, sha(2), "unit") is None, "another commit"


class TestCouldNotCheck:
    async def test_an_unreadable_pipeline_raises_and_keeps_the_state(self, db: Any) -> None:
        notifier = Recorder()
        await poll(db, fake_concourse(all_green(unit=_job("unit", "failed", 460)), HISTORY)[0],
                   notifier)

        with pytest.raises(jobs.RedMainIncompleteError, match="could not check"):
            await poll(db, fake_concourse([], fail="/jobs")[0], notifier)

        assert jobs.load_lane_states(db)[(REPO, "unit")].state == "red"
        assert len(notifier.sent) == 1

    async def test_a_missing_lane_is_named(self, db: Any) -> None:
        jobs_payload = [j for j in all_green() if j["name"] != "pin-check"]

        with pytest.raises(jobs.RedMainIncompleteError, match="no job named pin-check"):
            await poll(db, fake_concourse(jobs_payload, HISTORY)[0], Recorder())


class TestTheCiPage:
    async def test_red_since_and_first_bad_sha_per_red_lane(
        self, client: Any, admin_auth: dict[str, str]
    ) -> None:
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="concourse")
        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        database = client.app.state.db
        fetch, _ = fake_concourse(
            all_green(unit=_job("unit", "failed", 460, transition=460, ended=0.5)), HISTORY,
            base="/api/v1/teams/main/pipelines/payments-api",
        )
        await jobs.announce_red_main(
            "", db=database, gating={repo["repo_full_name"]: ["unit", "pin-check"]},
            tests=NO_TESTS, fetch=fetch, now=NOW,
        )

        page = client.get(
            f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth
        ).json()

        [lane] = page["red_gating_lanes"]
        assert lane["job"] == "unit"
        assert lane["first_bad_sha"] == sha(3)
        assert lane["last_green_sha"] == sha(2)
        assert datetime.fromisoformat(lane["red_since"]) == NOW - timedelta(hours=2.5)


class TestItIsScheduled:
    def _scheduled(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        from fastapi.testclient import TestClient

        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        monkeypatch.setattr(main, "_every", record)
        with TestClient(main.create_app(settings)):
            pass
        return captured

    def test_it_polls_every_five_minutes_with_the_default_lanes(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "http://concourse:8080",
        })
        calls: list[dict[str, Any]] = []

        async def fake(url: str, **kwargs: Any) -> Any:
            calls.append({"url": url, **kwargs})
            return red_main.RedMainReport()

        monkeypatch.setattr(main, "announce_red_main", fake)
        interval, job = self._scheduled(settings, monkeypatch)[jobs.RED_MAIN_JOB]

        import asyncio

        asyncio.run(job())
        assert interval == 300
        [call] = calls
        assert call["url"] == "http://concourse:8080"
        assert call["gating"] == {REPO: ["unit", "lint-and-types", "pin-check"]}
        assert call["link_base"] == "", "a compose service name is no browser link"

    def test_without_a_concourse_it_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(update={
            "run_jobs_in_background": True, "concourse_url": "",
        })
        assert jobs.RED_MAIN_JOB not in self._scheduled(settings, monkeypatch)
