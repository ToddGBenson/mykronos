"""A failing lane says how long it has been failing (TheHub #60906).

The briefing's "lanes that are failing" section printed the same paragraph
every morning: "One of these had one success in ten builds across five
weeks." That was `personal-soc/netassess-ingest` in August, typed into the
renderer, and it was printed under whatever happened to be red that day - a
lane whose one build failed an hour ago included. A single fresh failure was
presented as the five-week pattern.

`ci_repeat` measured what a pattern is (three consecutive same-class
failures, over 5,926 builds) and these pin the briefing to it: the streak is
read from the lane's own build list, a lane under the threshold is said to be
a first failure rather than a trend, and no sentence about a lane that is not
on the page is printed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mykronos import briefing, briefing_sources, daily_briefing
from mykronos.ci import JobStatus
from mykronos.ci_repeat import REPEAT_THRESHOLD
from mykronos.schemas import utcnow


def _builds(*statuses: str) -> list[dict[str, object]]:
    """Newest first, as Concourse lists them."""
    return [{"name": str(100 - i), "status": s} for i, s in enumerate(statuses)]


class FakeConcourse:
    def __init__(self, history: dict[tuple[str, str], list[dict[str, object]] | None]) -> None:
        self.history = history
        self.asked: list[tuple[str, str, int]] = []

    def job_builds(
        self, pipeline: str, job: str, *, limit: int = 10
    ) -> list[dict[str, object]] | None:
        self.asked.append((pipeline, job, limit))
        return self.history.get((pipeline, job))


def _job(name: str, status: str = "failed") -> JobStatus:
    return JobStatus(
        name=name,
        status=status,
        build_name="100",
        build_url=None,
        finished_at=datetime.now(UTC) - timedelta(hours=1),
    )


class TestTheStreakComesFromTheBuildList:
    def test_one_failure_after_a_pass_is_a_streak_of_one(self) -> None:
        ci = FakeConcourse({("soc", "ingest"): _builds("failed", "succeeded", "succeeded")})

        [lane] = briefing_sources.failing_lanes(ci, [("soc", _job("ingest"))])

        assert lane.consecutive_failures == 1
        assert lane.recent_builds == 3
        assert lane.recent_failures == 1
        assert lane.repeated is False

    def test_a_long_streak_is_repeated(self) -> None:
        ci = FakeConcourse(
            {("soc", "ingest"): _builds(*["failed"] * 9, "succeeded")}
        )

        [lane] = briefing_sources.failing_lanes(ci, [("soc", _job("ingest"))])

        assert lane.consecutive_failures == 9
        assert lane.recent_failures == 9
        assert lane.recent_builds == 10
        assert lane.repeated is True

    def test_errored_and_failed_do_not_share_a_streak(self) -> None:
        """`ci_repeat`'s AC4: a worker losing Vault is not a scanner's verdict."""
        ci = FakeConcourse(
            {("soc", "ingest"): _builds("failed", "errored", "errored", "errored")}
        )

        [lane] = briefing_sources.failing_lanes(ci, [("soc", _job("ingest"))])

        assert lane.consecutive_failures == 1

    def test_an_unreadable_history_is_unknown_not_one(self) -> None:
        ci = FakeConcourse({("soc", "ingest"): None})

        [lane] = briefing_sources.failing_lanes(ci, [("soc", _job("ingest"))])

        assert lane.consecutive_failures is None
        assert lane.repeated is None

    def test_enough_history_is_asked_for_to_see_the_threshold(self) -> None:
        ci = FakeConcourse({("soc", "ingest"): _builds("failed")})

        briefing_sources.failing_lanes(ci, [("soc", _job("ingest"))])

        [(_, _, limit)] = ci.asked
        assert limit > REPEAT_THRESHOLD


def _lane(streak: int | None, **kw: object) -> briefing.FailingLane:
    base: dict[str, object] = {
        "pipeline": "personal-soc",
        "job": "netassess-ingest",
        "last_status": "failed",
        "last_finished_at": utcnow() - timedelta(hours=2),
        "consecutive_failures": streak,
        "recent_builds": None if streak is None else max(streak, 10),
        "recent_failures": streak,
    }
    base.update(kw)
    return briefing.FailingLane(**base)  # type: ignore[arg-type]


class TestTheTextSaysWhatTheDataSays:
    def test_the_august_anecdote_is_gone(self, catalog) -> None:
        rendered = " ".join(
            briefing.render(briefing.build(catalog, failing_jobs=[_lane(1)])).split()
        )

        assert "one success in ten builds" not in rendered
        assert "five weeks" not in rendered

    def test_a_single_failure_is_not_called_a_pattern(self, catalog) -> None:
        rendered = briefing.render(briefing.build(catalog, failing_jobs=[_lane(1)]))

        assert "first failure" in rendered
        assert "not yet a pattern" in rendered

    def test_a_repeated_failure_says_how_many(self, catalog) -> None:
        rendered = briefing.render(briefing.build(catalog, failing_jobs=[_lane(9)]))

        assert "9 consecutive failed builds" in rendered
        assert "not yet a pattern" not in rendered

    def test_the_counts_in_the_header_are_the_lanes_on_the_page(self, catalog) -> None:
        rendered = " ".join(
            briefing.render(
                briefing.build(
                    catalog,
                    failing_jobs=[_lane(1), _lane(4, job="sast"), _lane(None, job="sca")],
                )
            ).split()
        )

        assert "1 has failed 3 or more builds running" in rendered
        assert "1 failed for the first time" in rendered
        assert "1 could not be read" in rendered


class TestTheDailyBriefing:
    def _trust(self, catalog, lanes: list[briefing.FailingLane]) -> daily_briefing.Section:
        report = briefing.build(catalog, failing_jobs=lanes)
        return daily_briefing.trust_section(report, None, as_of=None)

    def test_a_single_fresh_failure_is_not_a_story(self, catalog) -> None:
        [line] = self._trust(catalog, [_lane(1)]).lines

        assert line.work == daily_briefing.DECISION
        assert "not a trend" in line.so_what
        assert "failed its last build" in line.what

    def test_a_repeated_failure_is_a_story_with_its_count(self, catalog) -> None:
        [line] = self._trust(catalog, [_lane(5)]).lines

        assert line.work == daily_briefing.STORY
        assert "5 builds running" in line.what

    def test_an_unread_streak_keeps_the_conservative_reading(self, catalog) -> None:
        [line] = self._trust(catalog, [_lane(None)]).lines

        assert line.work == daily_briefing.STORY

    def test_the_counts_are_split(self, catalog) -> None:
        data = self._trust(catalog, [_lane(1), _lane(6, job="sast")]).data

        assert data["failing_jobs"] == 2
        assert data["failing_repeatedly"] == 1
