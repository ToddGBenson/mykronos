"""Lanes that did not run because an upstream lane did not pass (TheHub#349).

THE DEFECT THIS PINS. On 2026-09-10 `thehub/deploy-demo` began failing on a
CRLF in an acknowledgement file. Four jobs were gated on it with `passed:` --
`dast-demo`, `api-inventory`, `oracle-gate` (the go/no-go gate) and `insider`
(insider-risk, one edge further down) -- and none of them produced a build for
seven days. None was failing: each one's last build was green. None was paused.
So `failing_jobs` and `paused_jobs` both said nothing, correctly by their own
definitions, and the briefing had no third state to put them in.

The fixture below is that pipeline, shaped the way Concourse's anonymous job
list serves it. Its control is the case whose answer is already known: those
four jobs MUST be named, behind `deploy-demo`, and the healthy lanes MUST NOT.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mykronos import agent_work, briefing
from mykronos.ci import BlockedJob, ConcourseClient, blocked_jobs_in
from mykronos.schemas import utcnow

URL = "http://ci.test/teams/main/pipelines/thehub"

#: Epoch seconds. The demo deploy failed at DEPLOY_FAILED; everything behind
#: it last ran on the version before that, so its builds are older.
GOOD = 1_000_000
DEPLOY_FAILED = GOOD + 3_600


def _job(
    name: str,
    status: str | None = "succeeded",
    *,
    passed: list[str] | None = None,
    start: int = GOOD,
    end: int | None = None,
    paused: bool = False,
    running: bool = False,
    build: str = "7",
) -> dict[str, Any]:
    raw: dict[str, Any] = {"name": name, "inputs": [{"name": "python", "resource": "python"}]}
    if passed is not None:
        raw["inputs"].append(
            {"name": "source", "resource": "source", "passed": passed, "trigger": True}
        )
    if status is not None:
        raw["finished_build"] = {
            "name": build,
            "status": status,
            "start_time": start,
            "end_time": end if end is not None else start + 60,
        }
    if paused:
        raw["paused"] = True
    if running:
        raw["next_build"] = {"name": "8", "status": "started"}
    return raw


SIX = ["secrets", "sast", "dependencies", "containers", "prompt-evals", "iac"]


def _the_seven_dark_days() -> list[dict[str, Any]]:
    """TheHub's graph as it stood on 2026-09-10, with `deploy-demo` red."""
    return [
        _job("unit"),
        _job("build", passed=["unit"]),
        *[_job(n, passed=["build" if n == "containers" else "unit"]) for n in SIX],
        _job("deploy-demo", "failed", passed=SIX, start=DEPLOY_FAILED, build="88"),
        _job("dast-demo", passed=["deploy-demo"]),
        _job("api-inventory", passed=["deploy-demo"]),
        _job("oracle-gate", passed=["deploy-demo"]),
        _job("insider", passed=["oracle-gate", "api-inventory", "dast-demo"]),
        _job("dast-prod"),  # time-triggered, no `passed:` at all
    ]


def _by_job(found: list[BlockedJob]) -> dict[str, BlockedJob]:
    return {b.job.name: b for b in found}


class TestTheRule:
    def test_the_seven_dark_days_are_named(self) -> None:
        """The control: exactly the four jobs that went dark, and why."""
        found = _by_job(blocked_jobs_in(_the_seven_dark_days(), URL))

        assert sorted(found) == ["api-inventory", "dast-demo", "insider", "oracle-gate"]
        for name in ("api-inventory", "dast-demo", "oracle-gate"):
            assert (found[name].blocked_by, found[name].root) == ("deploy-demo", "deploy-demo")
            assert found[name].root_state == "failed"
        # One edge further down, behind the same root, and says which way.
        assert found["insider"].root == "deploy-demo"
        assert found["insider"].blocked_by in {"api-inventory", "dast-demo", "oracle-gate"}

    def test_their_own_last_build_is_green_which_is_the_point(self) -> None:
        found = _by_job(blocked_jobs_in(_the_seven_dark_days(), URL))
        assert found["oracle-gate"].job.status == "succeeded"

    def test_it_points_at_the_root_build(self) -> None:
        held = _by_job(blocked_jobs_in(_the_seven_dark_days(), URL))["dast-demo"]
        assert held.root_build_url == f"{URL}/jobs/deploy-demo/builds/88"
        assert held.root_since == datetime.fromtimestamp(DEPLOY_FAILED + 60, tz=UTC)

    def test_a_healthy_pipeline_holds_nothing_back(self) -> None:
        jobs = _the_seven_dark_days()
        jobs[8] = _job("deploy-demo", passed=SIX, start=DEPLOY_FAILED)
        assert blocked_jobs_in(jobs, URL) == []

    def test_a_job_that_started_after_the_failure_is_not_held_by_it(self) -> None:
        """It ran on something else after the upstream went red, so the red
        build is not what stopped it."""
        jobs = [
            _job("deploy-demo", "failed", start=DEPLOY_FAILED),
            _job("dast-demo", passed=["deploy-demo"], start=DEPLOY_FAILED + 600),
        ]
        assert blocked_jobs_in(jobs, URL) == []

    def test_a_job_that_never_built_behind_a_red_upstream_is_held(self) -> None:
        jobs = [
            _job("deploy-demo", "errored", start=DEPLOY_FAILED),
            _job("dast-demo", None, passed=["deploy-demo"]),
        ]
        held = _by_job(blocked_jobs_in(jobs, URL))["dast-demo"]
        assert held.root_state == "errored"
        assert held.job.status is None

    def test_a_paused_upstream_starves_everything_behind_it(self) -> None:
        jobs = [
            _job("deploy-demo", paused=True, start=DEPLOY_FAILED),
            _job("dast-demo", passed=["deploy-demo"], start=DEPLOY_FAILED + 600),
        ]
        held = _by_job(blocked_jobs_in(jobs, URL))["dast-demo"]
        assert held.root_state == "paused"

    @pytest.mark.parametrize(
        "own",
        [
            {"status": "failed"},  # the failing section's
            {"status": "errored"},
            {"paused": True},  # the paused section's
            {"running": True},  # it has a build on the way
        ],
    )
    def test_the_other_states_are_not_reported_twice(self, own: dict[str, Any]) -> None:
        jobs = [
            _job("deploy-demo", "failed", start=DEPLOY_FAILED),
            _job("dast-demo", passed=["deploy-demo"], **own),
        ]
        assert blocked_jobs_in(jobs, URL) == []

    def test_an_aborted_upstream_is_not_a_stop(self) -> None:
        """`aborted` is somebody cancelling, the same exclusion `failing_jobs` makes."""
        jobs = [
            _job("deploy-demo", "aborted", start=DEPLOY_FAILED),
            _job("dast-demo", passed=["deploy-demo"]),
        ]
        assert blocked_jobs_in(jobs, URL) == []

    def test_a_red_upstream_is_named_ahead_of_a_held_one(self) -> None:
        jobs = [
            _job("a", "failed", start=DEPLOY_FAILED),
            _job("b", passed=["a"]),
            _job("c", "failed", start=DEPLOY_FAILED),
            _job("d", passed=["b", "c"]),
        ]
        assert _by_job(blocked_jobs_in(jobs, URL))["d"].blocked_by == "c"

    def test_an_unknown_upstream_name_is_skipped_not_guessed(self) -> None:
        assert blocked_jobs_in([_job("x", passed=["gone"])], URL) == []

    def test_a_cycle_cannot_hang_it(self) -> None:
        jobs = [_job("a", passed=["b"]), _job("b", passed=["a"])]
        assert blocked_jobs_in(jobs, URL) == []


class _Response:
    def __init__(self, payload: object, status: int = 200) -> None:
        self._payload, self.status = payload, status

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")

    def json(self) -> object:
        return json.loads(json.dumps(self._payload))


@pytest.fixture
def concourse(monkeypatch):
    routes: dict[str, object] = {}

    def fake_get(url: str, timeout: float = 0) -> _Response:
        for suffix, payload in routes.items():
            if url.endswith(suffix):
                return _Response(payload)
        return _Response(None, status=404)

    monkeypatch.setattr("mykronos.ci.httpx2.get", fake_get)
    return ConcourseClient("http://concourse:8080", external_url="http://ci.test"), routes


class TestTheSweep:
    def test_it_reads_every_pipeline_anonymously(self, concourse) -> None:
        client, routes = concourse
        routes["/api/v1/pipelines"] = [{"name": "thehub"}, {"name": "keel"}]
        routes["/pipelines/thehub/jobs"] = _the_seven_dark_days()
        routes["/pipelines/keel/jobs"] = [_job("unit"), _job("sast", passed=["unit"])]

        found = client.blocked_jobs()

        assert found is not None
        assert sorted(f"{p}/{b.job.name}" for p, b in found) == [
            "thehub/api-inventory", "thehub/dast-demo", "thehub/insider", "thehub/oracle-gate",
        ]
        # The browser's URL, never the one this process reaches Concourse on.
        assert all("concourse:8080" not in (b.root_build_url or "") for _, b in found)

    def test_an_unreachable_concourse_is_none_not_empty(self, concourse) -> None:
        client, _ = concourse
        assert client.blocked_jobs() is None


def _lane(**kw: Any) -> briefing.BlockedLane:
    base: dict[str, Any] = {
        "pipeline": "thehub",
        "job": "oracle-gate",
        "blocked_by": "deploy-demo",
        "root": "deploy-demo",
        "root_state": "failed",
        "since": utcnow() - timedelta(days=7),
        "last_status": "succeeded",
        "last_finished_at": utcnow() - timedelta(days=7, hours=1),
        "build_url": "http://ci.test/teams/main/pipelines/thehub/jobs/deploy-demo/builds/88",
    }
    base.update(kw)
    return briefing.BlockedLane(**base)


HEADING = "LANES THAT DID NOT RUN BECAUSE AN UPSTREAM LANE DID NOT PASS"


class TestTheBriefing:
    def test_a_held_lane_is_named_with_its_root(self, catalog) -> None:
        rendered = briefing.render(briefing.build(catalog, blocked_jobs=[_lane()]))

        assert HEADING in rendered
        assert "thehub/oracle-gate" in rendered
        assert "behind deploy-demo (failed)" in rendered
        assert "(7 days)" in rendered
        assert "its own last build succeeded" in rendered

    def test_a_transitive_hold_says_which_way(self, catalog) -> None:
        rendered = briefing.render(
            briefing.build(catalog, blocked_jobs=[_lane(job="insider", blocked_by="oracle-gate")])
        )
        assert "via oracle-gate" in rendered

    def test_nothing_held_prints_no_section(self, catalog) -> None:
        assert HEADING not in briefing.render(briefing.build(catalog, blocked_jobs=[]))

    def test_could_not_ask_does_not_read_as_nothing_held(self, catalog) -> None:
        unknown = briefing.render(briefing.build(catalog, blocked_jobs=None))
        nothing = briefing.render(briefing.build(catalog, blocked_jobs=[]))

        assert HEADING in unknown
        assert unknown != nothing

    def test_it_is_a_state_of_its_own_beside_failing_and_paused(self, catalog) -> None:
        """Three states, three sections. The root is failing; what it stops is
        not, and must not be folded into it."""
        rendered = briefing.render(
            briefing.build(
                catalog,
                blocked_jobs=[_lane()],
                failing_jobs=[
                    briefing.FailingLane(
                        pipeline="thehub", job="deploy-demo", last_status="failed"
                    )
                ],
                paused_jobs=[],
            )
        )
        failing_at = rendered.index("LANES THAT ARE FAILING AND NOBODY SWITCHED OFF")
        held_at = rendered.index(HEADING)
        assert failing_at < held_at
        assert "thehub/oracle-gate" in rendered[held_at:]
        assert "thehub/oracle-gate" not in rendered[failing_at:held_at]

    def test_it_reaches_the_json_briefing(self, catalog) -> None:
        """`mykronos briefing --json` is `dataclasses.asdict` of the report."""
        import dataclasses

        report = dataclasses.asdict(briefing.build(catalog, blocked_jobs=[_lane()]))
        assert report["blocked"][0]["root"] == "deploy-demo"
        assert report["blocked_unknown"] is False


NOW = datetime(2026, 10, 15, tzinfo=UTC)


def _report(**kw: Any) -> briefing.Briefing:
    values: dict[str, Any] = {"generated_at": NOW, "total_open": 0}
    values.update(kw)
    return briefing.Briefing(**values)


def _queue(report: briefing.Briefing) -> agent_work.WorkQueue:
    from mykronos.adminauth import ActorKind, Principal, Role

    agent = Principal(actor="agent:test:abc", role=Role.AGENT, kind=ActorKind.AGENT)
    return agent_work.build(
        report,
        agent,
        triage_rows=[],
        acceptances=[],
        approval_requests=[],
        repo_ids={},
        now=NOW,
        probe_interval_seconds=21_600,
        playbook_version="1.0",
    )


class TestTheAgentWorkQueue:
    def test_the_root_item_names_what_it_is_stopping(self) -> None:
        """No item per held lane -- an agent would re-run jobs that cannot run.
        The root's item carries them as evidence instead."""
        queue = _queue(
            _report(
                failing=[
                    briefing.FailingLane(
                        pipeline="thehub", job="deploy-demo", last_status="failed"
                    )
                ],
                blocked=[_lane(), _lane(job="dast-demo")],
            )
        )
        ci = [i for i in queue.items if i.kind.startswith("ci_job")]
        assert [i.item_id for i in ci] == ["ci_job_failing:thehub/deploy-demo"]
        refs = [e.ref for e in ci[0].evidence]
        assert "thehub/oracle-gate" in refs and "thehub/dast-demo" in refs

    def test_a_paused_root_carries_them_too(self) -> None:
        queue = _queue(
            _report(
                paused=[briefing.PausedLane(pipeline="thehub", job="deploy-demo")],
                blocked=[_lane(root_state="paused")],
            )
        )
        item = next(i for i in queue.items if i.kind == "ci_job_paused")
        assert any(e.ref == "thehub/oracle-gate" for e in item.evidence)

    def test_could_not_ask_is_an_unknown(self) -> None:
        queue = _queue(_report(blocked_unknown=True))
        assert [u.source for u in queue.unknown] == ["concourse"]
