"""One message per failing build, posted on a state change only (TheHub #61194).

The comms audit (#61176) counted 118 Concourse `job X failed/ERRORED` posts
in 14 days, 47 of them verbatim repeats, plus 89 post-merge `NO VERDICT` /
`DEVELOP IS RED` posts, 81 of them repeats: every failing build of every lane
posted from its own `on_failure` / `on_error` hook, with no memory of the
build before it. The one sender the audit called the model to copy was the
red-main poll (`red_main.py`), which posts only when a lane's recorded state
changes.

So that poll now covers every lane of every pipeline (`"*"`), and the hooks no
longer post. These pin:

* red, then red again (and an errored retry of a red lane, which is what
  every `NO VERDICT` re-post was) posts once; red to green posts one
  recovery, as a reply in the red message's thread;
* the counts for a flapping lane, poll by poll;
* the red message's Slack thread is recorded, so a later message about the
  same red (TheHub's deploy-stage failure) can reply in it, and the CI page
  exposes it for that;
* `"*"` reaches a lane nobody listed, and TheHub's lanes say `develop`;
* no committed pipeline posts to Slack from a hook any more, and the default
  configuration covers every one of them.

Slack is never called: the notifier is a recorder that returns made-up
message timestamps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos import jobs, red_main
from mykronos.config import Settings
from mykronos.db import Database
from mykronos.notify import Delivery, Notification
from tests.test_red_main import BASE, NOW, NO_TESTS, REPO, _job

THEHUB = "ToddGBenson/TheHub"
THEHUB_BASE = "/api/v1/teams/main/pipelines/thehub"


class ThreadRecorder:
    """A Slack bot that records what it was asked to post, never posting."""

    def __init__(self) -> None:
        self.posts: list[tuple[Notification, str]] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        return (await self.post(note)).delivered

    async def post(self, note: Notification, *, thread_ts: str = "") -> Delivery:
        self.posts.append((note, thread_ts))
        return Delivery(True, ts=f"1700000000.{len(self.posts):06d}", channel="C0TEST")

    @property
    def top_level(self) -> list[Notification]:
        return [note for note, thread in self.posts if not thread]

    @property
    def replies(self) -> list[tuple[Notification, str]]:
        return [(note, thread) for note, thread in self.posts if thread]


def concourse(jobs_payload: list[dict[str, Any]], base: str = BASE) -> red_main.Fetch:
    """Only the job list is served: commits are reported as unknown."""

    def fetch(path: str) -> Any:
        if path == f"{base}/jobs":
            return jobs_payload
        raise KeyError(path)

    return fetch


@pytest.fixture
def db(settings: Settings) -> Any:
    database = Database(settings.database_url)
    database.create_all()
    yield database
    database.close()


async def poll(db: Any, notifier: ThreadRecorder, jobs_payload: list[dict[str, Any]], *,
               repo: str = REPO, base: str = BASE) -> red_main.RedMainReport:
    return await jobs.announce_red_main(
        "", db=db, gating={repo: ["*"]}, tests=NO_TESTS, notifier=notifier,
        fetch=concourse(jobs_payload, base), now=NOW,
        branches={THEHUB: "develop"},
    )


def lane(status: str, build: int, name: str = "sast") -> list[dict[str, Any]]:
    """One lane nobody named in the configuration: `"*"` must find it."""
    return [_job(name, status, build), _job("unit", "succeeded", 10)]


class TestStateChangeOnly:
    async def test_red_then_red_again_posts_once(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, lane("failed", 2))
        await poll(db, notifier, lane("failed", 3))
        await poll(db, notifier, lane("failed", 4))

        [note] = notifier.top_level
        assert note.title == f"Red on main: {REPO} sast"
        assert notifier.replies == []

    async def test_an_errored_retry_of_a_red_lane_posts_nothing(self, db: Any) -> None:
        """Every `NO VERDICT` re-post was this: a retry of a lane already red."""
        notifier = ThreadRecorder()

        await poll(db, notifier, lane("failed", 2, "post-merge"))
        for build in (3, 4, 5, 6):
            await poll(db, notifier, lane("errored", build, "post-merge"))

        assert len(notifier.posts) == 1

    async def test_red_to_green_posts_one_recovery_in_the_red_thread(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, lane("failed", 2))
        await poll(db, notifier, lane("succeeded", 3))
        await poll(db, notifier, lane("succeeded", 4))

        [red] = notifier.top_level
        [(recovery, thread)] = notifier.replies
        assert recovery.title == f"Green again on main: {REPO} sast"
        assert thread == "1700000000.000001", "the red message's own ts"
        assert red is notifier.posts[0][0]

    async def test_green_on_first_sight_posts_nothing(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, lane("succeeded", 2))

        assert notifier.posts == []


class TestAFlappingLane:
    async def test_counts_poll_by_poll(self, db: Any) -> None:
        """G R R(errored) G R R G G R: three reds, three recoveries, nothing else.

        Each red is one top-level message; each recovery is one reply under
        the red it ends. Before this, every red build was its own top-level
        post: five here, and none for the recoveries."""
        notifier = ThreadRecorder()
        sequence = [
            ("succeeded", 0, 0),
            ("failed", 1, 0),
            ("errored", 1, 0),
            ("succeeded", 1, 1),
            ("failed", 2, 1),
            ("failed", 2, 1),
            ("succeeded", 2, 2),
            ("succeeded", 2, 2),
            ("failed", 3, 2),
        ]
        for build, (status, reds, recoveries) in enumerate(sequence, start=1):
            await poll(db, notifier, lane(status, build))
            assert (len(notifier.top_level), len(notifier.replies)) == (reds, recoveries), (
                f"after build {build} ({status})"
            )

        threads = [thread for _, thread in notifier.replies]
        assert threads == ["1700000000.000001", "1700000000.000003"]

    async def test_the_thread_is_recorded_until_the_lane_recovers(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, lane("failed", 1))
        state = jobs.load_lane_states(db)[(REPO, "sast")]
        assert (state.slack_channel, state.slack_ts) == ("C0TEST", "1700000000.000001")

        await poll(db, notifier, lane("errored", 2))
        state = jobs.load_lane_states(db)[(REPO, "sast")]
        assert state.slack_ts == "1700000000.000001", "red to red keeps the thread"

        await poll(db, notifier, lane("succeeded", 3))
        state = jobs.load_lane_states(db)[(REPO, "sast")]
        assert (state.state, state.slack_ts) == ("green", None)


class TestEveryLaneEveryPipeline:
    async def test_a_lane_nobody_listed_is_covered(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, [_job("set-pipeline", "errored", 7)])

        [note] = notifier.top_level
        assert "set-pipeline errored" in "\n".join(note.lines)

    async def test_thehub_lanes_name_develop(self, db: Any) -> None:
        notifier = ThreadRecorder()

        await poll(db, notifier, [_job("post-merge", "failed", 7)], repo=THEHUB,
                   base=THEHUB_BASE)

        [note] = notifier.top_level
        assert note.title == f"Red on develop: {THEHUB} post-merge"
        assert "post-merge failed on develop, build 7" in "\n".join(note.lines)


class TestTheCiPageCarriesTheThread:
    async def test_a_red_lane_exposes_its_slack_thread(
        self, client: Any, admin_auth: dict[str, str]
    ) -> None:
        from tests.test_onboarding import onboard

        onboard(client, admin_auth, scanned_by="concourse")
        repo = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        await jobs.announce_red_main(
            "", db=client.app.state.db, gating={repo["repo_full_name"]: ["*"]},
            tests=NO_TESTS, notifier=ThreadRecorder(), now=NOW,
            fetch=concourse([_job("unit", "failed", 460)],
                            "/api/v1/teams/main/pipelines/payments-api"),
        )

        page = client.get(
            f"/api/dashboard/repos/{repo['repo_id']}/ci", headers=admin_auth
        ).json()

        [red] = page["red_gating_lanes"]
        assert (red["slack_channel"], red["slack_ts"]) == ("C0TEST", "1700000000.000001")


def _pipelines() -> Path:
    for parent in Path(__file__).resolve().parents:
        found = parent / "deploy" / "concourse" / "pipelines"
        if (found / "thehub.yml").is_file():
            return found
    pytest.fail("deploy/concourse/pipelines not found above this test")


PIPELINES = ("mykronos", "thehub", "personal-soc")


@pytest.mark.parametrize("name", PIPELINES)
def test_no_pipeline_hook_posts_to_slack(name: str) -> None:
    """The poll is the one sender; a hook posting too is the old duplicate."""
    text = (_pipelines() / f"{name}.yml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    tasks: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("task"), str):
                tasks.append(node["task"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc["jobs"])
    assert "notify-slack" not in tasks
    assert "chat.postMessage" not in text
    assert "((slack-bot-token))" not in text


def test_the_default_covers_every_lane_of_every_committed_pipeline() -> None:
    from mykronos.ci import pipeline_name_for

    gating = Settings().red_main_gating_lanes
    covered = {pipeline_name_for(repo) for repo, lanes in gating.items() if "*" in lanes}
    assert set(PIPELINES) <= covered
    assert Settings().red_main_branches == {THEHUB: "develop"}
