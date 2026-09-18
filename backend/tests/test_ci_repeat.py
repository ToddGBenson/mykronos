"""A lane stuck on one cause, and a detector that cannot go quiet (#59308).

Two things are under test here and the second one matters more.

The first is the detector: does it fire on three same-cause failures, stay
silent on two, and refuse to merge an `errored` run into a `failed` one.

The second is the estate's recurring defect -- **a control that reports
nothing looks exactly like a control that reports fine.** Ten-plus instances
of it were found in a week, one of them inside a test written to prevent
drift. So every test below that asserts "nothing was found" also asserts a
floor on what was looked at, and `test_a_sweep_that_inspected_nothing_...`
exists specifically to prove the two are distinguishable.

`test_the_measured_stampede_...` is the load-bearing one. It replays the real
shape of the keel outage of 2026-09-08 -- ten lanes erroring at the same
instant because Vault was sealed -- and pins the threshold to it. Lower
`REPEAT_THRESHOLD` to the 2 that #59308 was filed to prevent and that test
goes red naming the stampede, which is the only way a measured number stays
measured after the person who measured it has gone.
"""

from __future__ import annotations

import pytest

from mykronos.ci_repeat import (
    REPEAT_THRESHOLD,
    RepeatSweep,
    incident_for,
    render,
    sweep,
    trailing_streak,
)

HOUR = 3600
T0 = 1_757_000_000


def build(name: str, status: str, *, at: int = T0) -> dict[str, object]:
    return {
        "id": abs(hash((name, status, at))) % 10**6,
        "name": name,
        "status": status,
        "start_time": at,
        "end_time": at + 60,
    }


def lane(*statuses: str, start: int = T0) -> list[dict[str, object]]:
    """Newest-first, the order Concourse returns builds in."""
    out = []
    for i, s in enumerate(statuses):
        out.append(build(str(len(statuses) - i), s, at=start + (len(statuses) - i) * HOUR))
    return out


class FakeConcourse:
    """Only the four reads `sweep` uses. `None` means unreadable."""

    def __init__(self, lanes: dict[str, dict[str, list[dict[str, object]]]] | None) -> None:
        self._lanes = lanes
        self.jobs_unreadable: set[str] = set()
        self.builds_unreadable: set[tuple[str, str]] = set()
        self.build_calls: list[tuple[str, str, int]] = []

    def pipelines(self) -> list[str] | None:
        return None if self._lanes is None else sorted(self._lanes)

    def job_last_statuses(self, pipeline: str) -> dict[str, str | None] | None:
        if pipeline in self.jobs_unreadable:
            return None
        out: dict[str, str | None] = {}
        for job, builds in self._lanes[pipeline].items():
            finished = [b for b in builds if b["status"] not in ("started", "pending")]
            out[job] = str(finished[0]["status"]) if finished else None
        return out

    def job_builds(self, pipeline: str, job: str, *, limit: int = 10):
        self.build_calls.append((pipeline, job, limit))
        if (pipeline, job) in self.builds_unreadable:
            return None
        return self._lanes[pipeline][job][:limit]

    def pipeline_url(self, pipeline: str) -> str:
        return f"https://ci.example/teams/main/pipelines/{pipeline}"


# --------------------------------------------------------------- the streak


def test_three_same_cause_failures_is_an_incident() -> None:
    inc = incident_for("mykronos", "pin-check", lane("failed", "failed", "failed"))
    assert inc is not None
    assert inc.count == 3
    assert inc.cause == "failed"
    assert inc.key == ("mykronos", "pin-check", "failed")


def test_two_is_not_yet_an_incident() -> None:
    """The threshold #59308 exists to avoid. Two consecutive failures is the
    keel stampede, and the keel stampede healed itself on the third build."""
    assert incident_for("keel", "sca", lane("errored", "errored")) is None


def test_a_green_build_ends_the_streak() -> None:
    """The clear-check, which AC2 requires to be satisfiable. No state is
    held: one non-failing build and the lane simply stops being reported."""
    assert incident_for("thehub", "unit", lane("succeeded", "failed", "failed", "failed")) is None


def test_errored_and_failed_do_not_merge_into_one_streak() -> None:
    """AC4. A scanner's honest refusal is not a worker losing Vault, and an
    alert that adds them together is worse than no alert."""
    assert incident_for("mykronos", "unit", lane("failed", "errored", "errored")) is None
    assert incident_for("mykronos", "unit", lane("errored", "errored", "errored")) is not None


def test_an_aborted_build_neither_extends_nor_clears_a_streak() -> None:
    """Somebody cancelling is a decision with a person behind it -- `ci.py`
    already refuses to count it as a failure. It must not clear a real
    incident either, or cancelling one build would silence the lane."""
    inc = incident_for("thehub", "deploy-demo", lane("failed", "aborted", "failed", "failed"))
    assert inc is not None
    assert inc.count == 3


def test_a_running_build_does_not_clear_an_incident() -> None:
    """A retrigger in flight is the moment the lane is most likely still
    broken. Treating `started` as a non-failure would clear the alert exactly
    then."""
    inc = incident_for("thehub", "unit", lane("started", "failed", "failed", "failed"))
    assert inc is not None
    assert inc.count == 3


def test_trailing_streak_reports_only_the_current_run() -> None:
    """Not a historical one. `failing_jobs()` answers 'red now'; this answers
    'stuck now', and neither answers 'was red last Tuesday'."""
    assert trailing_streak(lane("succeeded", "failed", "failed", "failed")) is None
    cause, run = trailing_streak(lane("failed", "failed", "succeeded", "failed"))
    assert (cause, len(run)) == ("failed", 2)


def test_the_incident_carries_the_build_range_and_span() -> None:
    inc = incident_for(
        "mykronos",
        "pin-check",
        lane("failed", "failed", "failed", "failed"),
        pipeline_url="https://ci.example/teams/main/pipelines/mykronos",
    )
    assert inc is not None
    assert (inc.first_build, inc.last_build) == ("1", "4")
    assert inc.hours == pytest.approx(3.0)
    assert inc.url == "https://ci.example/teams/main/pipelines/mykronos/jobs/pin-check"


def test_an_incident_without_a_pipeline_url_has_no_link() -> None:
    """Rather than a link to nowhere, which reads as a real one."""
    inc = incident_for("mykronos", "pin-check", lane("failed", "failed", "failed"))
    assert inc is not None
    assert inc.url is None


# ------------------------------------------------- the measurement, pinned


def test_the_measured_stampede_does_not_fire_at_the_chosen_threshold() -> None:
    """THE REASON THE THRESHOLD IS 3.

    2026-09-08 17:28: keel's ten jobs all `get: daily` with `trigger: true`,
    one version landed, all ten scheduled onto two workers at the same instant
    -- and Vault was sealed. Ten lanes errored together. Every one of those
    streaks was exactly two builds long; by the third attempt Vault was open.

    At T=2 that single incident mints ten alerts, which is the "alarm nobody
    acts on" this estate has documented as its most repeated finding. At T=3
    it mints none. If anyone lowers the threshold, this test says why not.
    """
    stampede = {
        "keel": {
            job: lane("errored", "errored", "succeeded")
            for job in (
                "build",
                "compliance-daily",
                "iac",
                "lint",
                "platform-integrity",
                "sast",
                "sca",
                "secrets",
                "suppression-audit",
                "test",
            )
        }
    }
    client = FakeConcourse(stampede)

    at_two = sweep(client, threshold=2)
    assert at_two is not None
    assert len(at_two.incidents) == 10, "the stampede is real and T=2 does fire on it"

    at_default = sweep(client)
    assert at_default is not None
    assert at_default.threshold == REPEAT_THRESHOLD
    assert at_default.incidents == [], (
        "the chosen threshold must not fire on the keel Vault stampede of "
        "2026-09-08; if this went red, REPEAT_THRESHOLD was lowered below the "
        "measurement that justifies it"
    )
    # ...and it did not stay silent by looking at nothing.
    assert at_default.lanes_inspected == 10
    assert at_default.builds_inspected == 30


def test_the_threshold_is_the_measured_one() -> None:
    """A guard on the constant itself. #59308 was filed because a threshold
    nobody can trace to a measurement is the next ignored alert."""
    assert REPEAT_THRESHOLD == 3


# ------------------------------------------------------------- the sweep


def _estate() -> FakeConcourse:
    return FakeConcourse(
        {
            "mykronos": {
                "pin-check": lane("failed", "failed", "failed", "failed"),  # stuck
                "unit": lane("succeeded", "failed"),  # a flake
            },
            "thehub": {
                "deploy-demo": lane("failed", "failed", "failed"),  # stuck
                "sast": lane("succeeded", "succeeded"),  # fine
            },
            "keel": {"sca": lane("errored", "errored")},  # stampede
        }
    )


def test_a_sweep_finds_the_stuck_lanes_and_says_what_it_looked_at() -> None:
    result = sweep(_estate())
    assert result is not None
    assert [(i.pipeline, i.job, i.count) for i in result.incidents] == [
        ("mykronos", "pin-check", 4),
        ("thehub", "deploy-demo", 3),
    ]
    # The floor. Had discovery narrowed to one pipeline, the incident list
    # would still look plausible -- this is what makes that visible.
    assert result.lanes_inspected == 5
    assert result.complete
    # Two of the five are green right now and had their history skipped; the
    # lane count still accounts for all five.
    assert result.histories_read == 3
    assert result.builds_inspected == 9


def test_the_green_lane_shortcut_cannot_hide_a_stuck_lane() -> None:
    """The shortcut is only sound because a trailing failure streak requires
    the latest finished build to be a failure. These are the cases where that
    is easy to get wrong: an abort on top of a streak, a retrigger still
    running on top of one, and a lane that has never finished a build."""
    client = FakeConcourse(
        {
            "thehub": {
                "aborted-on-top": lane("aborted", "failed", "failed", "failed"),
                "running-on-top": lane("started", "failed", "failed", "failed"),
                "never-ran": lane("started"),
            }
        }
    )
    result = sweep(client)
    assert result is not None
    assert [i.job for i in result.incidents] == ["aborted-on-top", "running-on-top"]
    assert result.lanes_inspected == 3
    # All three had to be fetched: none of them is green.
    assert result.histories_read == 3


def test_a_green_lane_is_counted_but_not_fetched() -> None:
    client = FakeConcourse({"thehub": {"fine": lane("succeeded", "failed", "failed", "failed")}})
    result = sweep(client)
    assert result is not None
    assert result.incidents == []
    assert result.lanes_inspected == 1
    assert result.histories_read == 0
    assert client.build_calls == [], "a green lane's history need not be read"


def test_one_incident_per_lane_per_cause() -> None:
    """AC2's dedup, and it holds across sweeps: an unchanged lane yields the
    same key, so a caller deduping on it never mints a second alert."""
    first = sweep(_estate())
    second = sweep(_estate())
    assert first is not None and second is not None
    keys = [i.key for i in first.incidents]
    assert len(keys) == len(set(keys))
    assert keys == [i.key for i in second.incidents]


def test_unreachable_concourse_is_none_not_an_empty_sweep() -> None:
    """ "Nothing is stuck" and "could not ask" must not render the same."""
    assert sweep(FakeConcourse(None)) is None
    assert "could not be reached" in render(None)


def test_an_unreadable_lane_is_reported_not_skipped() -> None:
    client = _estate()
    client.builds_unreadable.add(("thehub", "deploy-demo"))
    client.jobs_unreadable.add("keel")
    result = sweep(client)
    assert result is not None
    assert not result.complete
    assert sorted(result.unreadable) == ["keel", "thehub/deploy-demo"]
    assert "this answer is partial" in render(result)
    # thehub/deploy-demo was discovered and then failed to read, so it counts
    # as a lane and is named in `unreadable`. keel could not be enumerated at
    # all, so its lane was never discovered -- which is exactly why the
    # pipeline itself is named instead.
    assert result.lanes_inspected == 4
    assert result.histories_read == 1


def test_history_must_exceed_the_threshold() -> None:
    """The silent-never-fires bug. Asking for 3 builds while requiring a
    streak of 3 can still fire; asking for 3 while requiring 4 never can, and
    the output of that mistake is indistinguishable from a healthy estate."""
    with pytest.raises(ValueError, match="silently never fire"):
        sweep(_estate(), threshold=4, history=4)
    with pytest.raises(ValueError, match="not a repeat"):
        sweep(_estate(), threshold=1)


def test_the_sweep_asks_for_more_history_than_the_threshold() -> None:
    client = _estate()
    sweep(client, threshold=3, history=9)
    assert client.build_calls, "the sweep read no builds at all"
    assert {limit for _, _, limit in client.build_calls} == {9}


# ------------------------------------- the vacuous pass, made impossible


def test_a_clean_estate_says_how_much_it_checked() -> None:
    clean = FakeConcourse({"mykronos": {"unit": lane("succeeded", "succeeded", "succeeded")}})
    result = sweep(clean)
    assert result is not None
    assert result.incidents == []
    assert result.lanes_inspected == 1
    text = render(result)
    assert "No lane has failed" in text
    assert "1 lanes, 0 histories read, 0 builds inspected" in text


def test_a_sweep_that_inspected_nothing_does_not_read_as_a_clean_estate() -> None:
    """The defect this whole file is shaped around. An empty estate and a
    broken discovery step both produce zero incidents; only one of them is
    good news, and the rendered text must not be the same."""
    nothing = sweep(FakeConcourse({}))
    assert nothing is not None
    assert nothing.incidents == []
    assert nothing.lanes_inspected == 0

    clean = sweep(FakeConcourse({"mykronos": {"unit": lane("succeeded", "succeeded")}}))
    assert clean is not None

    assert "WARNING" in render(nothing)
    assert "not a clean estate" in render(nothing)
    assert "WARNING" not in render(clean)
    assert render(nothing) != render(clean)


def test_every_pipeline_with_no_jobs_still_counts_as_zero_lanes() -> None:
    """A pipeline that exists but lists no jobs inspects nothing, and the
    floor must catch that rather than average it away against a healthy
    neighbour."""
    result = sweep(FakeConcourse({"empty": {}}))
    assert result is not None
    assert result.lanes_inspected == 0
    assert "WARNING" in render(result)


def test_render_names_every_incident_it_found() -> None:
    result = sweep(_estate())
    assert result is not None
    text = render(result)
    for inc in result.incidents:
        assert f"{inc.pipeline}/{inc.job}" in text
        assert inc.cause in text
    assert "5 lanes, 3 histories read, 9 builds inspected" in text


def test_the_sweep_result_cannot_claim_more_than_it_saw() -> None:
    """A direct guard on the floor fields: they are derived from the reads
    that actually happened, so they cannot be right while discovery is
    broken."""
    client = _estate()
    result = sweep(client)
    assert result is not None
    assert result.histories_read == len(client.build_calls)
    assert result.lanes_inspected >= result.histories_read
    assert isinstance(result, RepeatSweep)
