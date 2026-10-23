"""A gating lane on main went red: say so on the next poll, with the commit (TheHub #60973).

A red gating lane on a default branch stops the scan lanes and the risk gate
behind it. Until this, the fastest signal was `gate_liveness`, which waits for
the oldest unjudged commit to be six hours old, reads only the mykronos
pipeline, and names lanes rather than the commit that broke them. `ci_repeat`
waits for three failures of the same cause. So a `unit` that went red on main
in the evening reached somebody the next morning.

This is the push, one poll after the build finishes. For each configured
repository it reads the pipeline's job list (the same anonymous read
`ConcourseClient.jobs` makes) and compares each gating lane's
`finished_build` status with what was last recorded for it:

* **green -> red** (or red the first time it is seen): one message naming the
  repository, the lane, the build, the first failing commit and the last
  green one. The commits come from the `source` resource's versions and each
  version's `input_to` builds, the anonymous reads `gate_liveness` makes. A
  build not found in that window is reported as `commit unknown`, never left
  out.
* **red -> red**: nothing. The recorded state is the de-duplication key, and
  it is stored in the database, so a restart does not post it again.
* **red -> green**: one recovery message with how long the lane was red.

Test results are suite totals only (D-046: the JUnit adapter records counts,
never test names), and build logs are never read (`ci`'s design). A message
says "<failed> of <total> tests failed" when a JUnit run for that commit and
lane reached the lake, and "no test report uploaded" when none did.

`aborted`, pending and never-run builds change nothing: an abort is somebody
cancelling (`ConcourseClient.FAILED_STATUSES`), and a build with no result is
not evidence either way.

Pure apart from the injected `fetch` (one Concourse API path, raising on
failure, as `gate_liveness` takes it) and `tests` (one lake lookup).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from mykronos.ci import pipeline_name_for

#: Reads one Concourse API path and returns the parsed JSON. Raises on failure.
Fetch = Callable[[str], Any]

#: The git resource every lane takes main's commits from, in all three
#: committed pipelines (`deploy/concourse/pipelines/*.yml`).
SOURCE_RESOURCE = "source"
#: How many of main's commits to walk back through to find the first failing
#: build and the last green one. Only read on a transition, never per poll.
VERSION_WINDOW = 50
#: The same pair `ConcourseClient.FAILED_STATUSES` and `gate_liveness` use.
RED_STATUSES = frozenset({"failed", "errored"})
GREEN = "green"
RED = "red"

#: What `adapters/tests_junit` writes into a failing run's `detail`.
_FAILED_OF = re.compile(r"(\d+) of (\d+) test\(s\) failed")
#: ...and into a passing run's, when some cases were skipped.
_PASSED = re.compile(r"(\d+) test\(s\) passed, (\d+) skipped")


@dataclass(frozen=True)
class TestTotals:
    """A JUnit run's suite totals, as far as the run recorded them.

    `total` is None when the run stored no count: a passing run with nothing
    skipped writes no `detail` at all. `failed` is None for a failed run whose
    detail carries no count, because 0 would be a claim."""

    failed: int | None
    total: int | None

    def phrase(self) -> str:
        if self.failed is None:
            return "a test report was uploaded and failed, with no count recorded"
        if self.total is None:
            return f"{self.failed} tests failed (total not recorded)"
        return f"{self.failed} of {self.total} tests failed"


#: `(repo_full_name, commit_sha, lane)` -> that lane's newest JUnit totals
#: for the commit, or None if no test report was uploaded for it.
TestLookup = Callable[[str, str, str], TestTotals | None]


def totals_from_run(scan_status: str | None, detail: str | None) -> TestTotals:
    """A JUnit scan run's totals, read back from its stored `detail`."""
    text = detail or ""
    match = _FAILED_OF.search(text)
    if match:
        return TestTotals(int(match.group(1)), int(match.group(2)))
    match = _PASSED.search(text)
    if match:
        return TestTotals(0, int(match.group(1)) + int(match.group(2)))
    if scan_status == "failure":
        return TestTotals(failed=None, total=None)
    return TestTotals(0, None)


@dataclass
class LaneState:
    """What was last recorded for one gating lane. Persisted between polls."""

    repo_full_name: str
    pipeline: str
    job: str
    #: `green` or `red`.
    state: str
    #: Concourse's word for the latest finished build.
    status: str | None = None
    build: str | None = None
    #: When the lane went red: the first failing build's end, or start.
    red_since: datetime | None = None
    first_bad_build: str | None = None
    #: Full sha, or None when it could not be resolved.
    first_bad_sha: str | None = None
    last_green_sha: str | None = None


@dataclass(frozen=True)
class Message:
    kind: str  # `red` or `recovered`
    repo_full_name: str
    job: str
    title: str
    lines: tuple[str, ...]


@dataclass
class RedMainReport:
    messages: list[Message] = field(default_factory=list)
    #: Every lane's state after this poll, changed or not.
    states: list[LaneState] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.unreadable


@dataclass(frozen=True)
class _Resolved:
    first_bad_sha: str | None = None
    first_bad_subject: str = ""
    last_green_sha: str | None = None
    last_green_build: str | None = None
    #: Why the walk stopped short, when it did.
    problem: str = ""


def _epoch(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        return None
    return datetime.fromtimestamp(value, tz=UTC)


def _build(raw: Any) -> dict[str, Any]:
    return raw if isinstance(raw, dict) else {}


def _when(build: dict[str, Any]) -> datetime | None:
    return _epoch(build.get("end_time")) or _epoch(build.get("start_time"))


def _order(build: dict[str, Any]) -> int | None:
    """A build's position in its job's history: the global id, else its number."""
    for key in ("id", "name"):
        try:
            return int(build[key])
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _subject(entry: dict[str, Any]) -> str:
    for item in entry.get("metadata") or []:
        if isinstance(item, dict) and item.get("name") == "message":
            first = str(item.get("value") or "").strip().splitlines()
            return first[0][:120] if first else ""
    return ""


def _resolve(
    fetch: Fetch, base: str, job: str, bad_build: dict[str, Any]
) -> _Resolved:
    """The commit `bad_build` ran, and the newest commit this job passed before it.

    Walks main's commits newest first and asks Concourse which builds each was
    an input to. Never raises: an unreadable step ends the walk with what was
    found so far, and the message says what is unknown.
    """
    bad_name = str(bad_build.get("name") or "")
    bad_order = _order(bad_build)
    try:
        versions = fetch(f"{base}/resources/{SOURCE_RESOURCE}/versions?limit={VERSION_WINDOW}")
        if not isinstance(versions, list):
            raise ValueError("not a version list")
    except Exception:  # noqa: BLE001 - reported as unknown, never raised
        # The error text is left out: it carries the internal API address,
        # and the message goes to Slack.
        return _Resolved(problem=f"{SOURCE_RESOURCE} versions unreadable")

    found = _Resolved()
    for entry in versions:
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        ref = version.get("ref") if isinstance(version, dict) else None
        if not isinstance(ref, str) or not ref or entry.get("id") is None:
            continue
        try:
            builds = fetch(f"{base}/resources/{SOURCE_RESOURCE}/versions/{entry['id']}/input_to")
        except Exception:  # noqa: BLE001 - reported as unknown, never raised
            return replace(found, problem=f"builds of {ref[:12]} unreadable")
        mine = [
            b for b in builds or []
            if isinstance(b, dict) and b.get("job_name") == job
        ]
        if found.first_bad_sha is None and any(str(b.get("name")) == bad_name for b in mine):
            found = replace(found, first_bad_sha=ref, first_bad_subject=_subject(entry))
        greens = [
            b for b in mine
            if b.get("status") == "succeeded"
            and (bad_order is None or (_order(b) or 0) < bad_order)
        ]
        if found.last_green_sha is None and greens:
            newest = max(greens, key=lambda b: _order(b) or 0)
            found = replace(
                found, last_green_sha=ref, last_green_build=str(newest.get("name") or "") or None
            )
        if found.first_bad_sha is not None and found.last_green_sha is not None:
            break
    return found


def _hours(start: datetime | None, end: datetime) -> str:
    if start is None:
        return "for an unknown time"
    return f"for {max((end - start).total_seconds(), 0) / 3600:.1f}h"


def _job_url(link_base: str, pipeline: str, job: str, build: str | None) -> str:
    if not link_base:
        return ""
    url = f"{link_base}/pipelines/{pipeline}/jobs/{job}"
    return f"{url}/builds/{build}" if build else url


def evaluate(
    fetch: Fetch,
    *,
    gating: dict[str, list[str]],
    prior: dict[tuple[str, str], LaneState],
    tests: TestLookup,
    now: datetime,
    team: str = "main",
    link_base: str = "",
) -> RedMainReport:
    """One poll: every configured gating lane against its recorded state.

    `gating` maps a repository to its gating lanes; its pipeline is
    `pipeline_name_for(repo)`. `prior` is what the last poll recorded, keyed
    on `(repo_full_name, job)`. `link_base` is a browser-reachable Concourse
    team URL (`ConcourseClient.pipeline_url` minus the pipeline), or "" for no
    links. Never raises.
    """
    report = RedMainReport()
    for repo, lanes in gating.items():
        pipeline = pipeline_name_for(repo)
        base = f"/api/v1/teams/{team}/pipelines/{pipeline}"
        try:
            jobs = fetch(f"{base}/jobs")
            if not isinstance(jobs, list):
                raise ValueError("not a job list")
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            report.unreadable.append(f"{pipeline} jobs: {exc}")
            report.states.extend(
                state for (r, _), state in prior.items() if r == repo
            )
            continue
        by_name = {str(j.get("name")): j for j in jobs if isinstance(j, dict)}
        for lane in lanes:
            before = prior.get((repo, lane))
            job = by_name.get(lane)
            if job is None:
                report.unreadable.append(f"{pipeline} has no job named {lane}")
                if before is not None:
                    report.states.append(before)
                continue
            after, message = _step(
                fetch, base, repo, pipeline, lane, job, before, tests, now, link_base
            )
            if after is not None:
                report.states.append(after)
            if message is not None:
                report.messages.append(message)
    return report


def _step(
    fetch: Fetch,
    base: str,
    repo: str,
    pipeline: str,
    lane: str,
    job: dict[str, Any],
    before: LaneState | None,
    tests: TestLookup,
    now: datetime,
    link_base: str,
) -> tuple[LaneState | None, Message | None]:
    finished = _build(job.get("finished_build"))
    status = finished.get("status")
    build = str(finished["name"]) if finished.get("name") else None
    if status in RED_STATUSES:
        observed = RED
    elif status == "succeeded":
        observed = GREEN
    else:
        # Aborted, pending or never run: no evidence either way.
        return before, None

    if observed == GREEN:
        after = LaneState(repo, pipeline, lane, GREEN, str(status), build)
        if before is None or before.state == GREEN:
            return after, None
        green_at = _when(finished) or now
        lines = [
            f"{lane} is green again on main: build {build or '?'} succeeded "
            f"after being red {_hours(before.red_since, green_at)}.",
            "It went red at build "
            f"{before.first_bad_build or '?'}, commit "
            f"{(before.first_bad_sha or 'unknown')[:12]}.",
        ]
        url = _job_url(link_base, pipeline, lane, build)
        if url:
            lines.append(url)
        return after, Message(
            "recovered", repo, lane, f"Green again on main: {repo} {lane}", tuple(lines)
        )

    if before is not None and before.state == RED:
        # Red to red: the news was sent when it went red.
        return replace(before, status=str(status), build=build), None

    # Green to red, or red the first time this lane is seen. The first failing
    # build is Concourse's transition build when that is red too: several red
    # builds may have finished since the last poll.
    transition = _build(job.get("transition_build"))
    bad = transition if transition.get("status") in RED_STATUSES else finished
    bad_build = str(bad["name"]) if bad.get("name") else build
    resolved = _resolve(fetch, base, lane, bad)
    after = LaneState(
        repo,
        pipeline,
        lane,
        RED,
        str(status),
        build,
        red_since=_when(bad) or now,
        first_bad_build=bad_build,
        first_bad_sha=resolved.first_bad_sha,
        last_green_sha=resolved.last_green_sha,
    )
    lines = [f"{repo}: {lane} {status} on main, build {build or '?'}."]
    if resolved.first_bad_sha:
        subject = f" {resolved.first_bad_subject}" if resolved.first_bad_subject else ""
        lines.append(
            f"First failing commit: {resolved.first_bad_sha[:12]}{subject} "
            f"(build {bad_build or '?'})."
        )
    else:
        why = resolved.problem or (
            f"build {bad_build or '?'} is not among the last {VERSION_WINDOW} commits "
            f"of {SOURCE_RESOURCE}"
        )
        lines.append(f"First failing commit: commit unknown ({why}).")
    if resolved.last_green_sha:
        lines.append(
            f"Last green: {resolved.last_green_sha[:12]} "
            f"(build {resolved.last_green_build or '?'})."
        )
    else:
        lines.append("Last green: unknown.")
    if not resolved.first_bad_sha:
        lines.append("Tests: not looked up, because the commit is unknown.")
    else:
        totals = tests(repo, resolved.first_bad_sha, lane)
        lines.append(
            "Tests: no test report uploaded." if totals is None else f"Tests: {totals.phrase()}."
        )
    url = _job_url(link_base, pipeline, lane, build)
    if url:
        lines.append(url)
    return after, Message("red", repo, lane, f"Red on main: {repo} {lane}", tuple(lines))
