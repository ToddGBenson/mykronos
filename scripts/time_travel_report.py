"""File the nightly time-travel run's failures as one Hub story (TheHub #61109).

The `time-travel` job in `deploy/concourse/pipelines/mykronos.yml` runs the
backend unit suite under libfaketime, with the clock moved forward by the
pipeline var `time-travel-offset` (45 days to start with). A test that only
passes because of today's date -- #1034's 30-day NVD retry window, which held
fourteen lanes red on main at midnight on 2026-10-31 -- fails there weeks
before it fails on main.

This script reads that run's JUnit report and, when anything failed, makes
sure exactly one open Hub story says so:

- no open story carries `SOURCE_REF`: one is filed, to the backlog;
- one does, and its list of failing tests is the same: nothing is written;
- one does, and the list changed: that story's detail is rewritten in place.

So a test that stays broken for a week is one story, not seven. A story that
was closed is not reopened: the next red night files a new one, because a
closed story is a decision somebody made about the old failures.

A green run writes nothing. The job's own colour is the run's verdict, and the
job gates nothing (no other job has `passed: [time-travel]`) and uploads
nothing to Mykronos, so a red night never turns `unit` or anything behind it
red.

Exit codes: 0 when the report was read and the Hub (if needed) was written;
2 when the report is missing or unreadable, which is an error, not a verdict;
3 when the Hub refused or could not be reached. The job exits with pytest's
own code whatever this returns, so a filing failure never hides a red suite.

Stdlib only: it runs in the task after the suite, under the real clock, and
must not depend on the packages the suite just exercised.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: How a story this files is found again. Also a tag, so the board can filter.
SOURCE_REF = "time-travel:mykronos-unit"
SOURCE_KIND = "mykronos-time-travel"
TAG = "time-travel"
REPO_TAG = "repo:mykronos"

#: The buckets an open story can be in: TheHub's BUCKETS less `done`. A story
#: parked in the icebox is still open, so it is still the one story.
OPEN_BUCKETS = ("icebox", "backlog", "sprint")

#: The marker the failing tests are listed under in a story's detail, so the
#: next run can compare without parsing prose.
LIST_MARKER = "Failing tests:"


@dataclass(frozen=True)
class Run:
    tests: int
    failing: tuple[str, ...]


class ReportError(RuntimeError):
    """The JUnit report could not be read: the suite never reached a verdict."""


class HubError(RuntimeError):
    """TheHub refused a write or could not be reached."""


def read_report(path: Path) -> Run:
    """Every failed or errored test case, as `classname::name`, sorted."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ReportError(f"no readable JUnit report at {path}: {exc}") from exc
    cases = list(root.iter("testcase"))
    if not cases:
        raise ReportError(f"the JUnit report at {path} has no test cases")
    failing = set()
    for case in cases:
        if case.find("failure") is not None or case.find("error") is not None:
            name = case.get("name", "?")
            cls = case.get("classname", "")
            failing.add(f"{cls}::{name}" if cls else name)
    return Run(tests=len(cases), failing=tuple(sorted(failing)))


def listed_tests(detail: str) -> tuple[str, ...]:
    """The failing tests a story already lists, from its `LIST_MARKER` block."""
    lines = detail.splitlines()
    try:
        start = lines.index(LIST_MARKER) + 1
    except ValueError:
        return ()
    names = []
    for line in lines[start:]:
        if not line.startswith("- `"):
            break
        names.append(line[3:].rstrip("`"))
    return tuple(sorted(names))


def story_detail(run: Run, *, offset: str, commit: str) -> str:
    listing = "\n".join(f"- `{name}`" for name in run.failing)
    return "\n".join(
        [
            f"The nightly `time-travel` job ran the mykronos backend unit suite with the "
            f"clock moved to now{offset} (libfaketime) at commit `{commit}`, and "
            f"{len(run.failing)} of {run.tests} tests failed. Each one passes today and will "
            "fail on main once the real clock reaches the date it assumes: a fixed date, "
            "a window measured from `now()`, or an expiry.",
            "",
            "Fix each by pinning its clock (pass `now=` or a fixed datetime) rather than "
            "by moving its dates forward: moved dates are the same bomb with a later fuse.",
            "",
            LIST_MARKER,
            listing,
            "",
            f"Filed and kept current by `scripts/time_travel_report.py` (TheHub #61109). "
            f"This list is rewritten in place while the story is open; `{SOURCE_REF}` "
            "is how the job finds it.",
        ]
    )


def story_payload(run: Run, *, offset: str, commit: str) -> dict[str, Any]:
    count = len(run.failing)
    return {
        "title": (
            f"Time-travel unit run: {count} test{'s' if count != 1 else ''} fail at "
            f"now{offset}, so they will fail on main"
        ),
        "detail": story_detail(run, offset=offset, commit=commit),
        "bucket": "backlog",
        "tags": [TAG, REPO_TAG],
        "source_kind": SOURCE_KIND,
        "source_ref": SOURCE_REF,
        "acceptance_criteria": [
            f"The nightly time-travel job is green at now{offset} for every test listed.",
            "Each fixed test pins its clock instead of moving its dates.",
        ],
    }


#: (method, path, body) -> (status, parsed body)
Send = Callable[[str, str, dict[str, Any] | None], tuple[int, Any]]


def http_sender(base_url: str, token: str, *, timeout: float = 20.0) -> Send:
    base = base_url.rstrip("/")

    def send(method: str, path: str, body: dict[str, Any] | None) -> tuple[int, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            base + path,
            data=data,
            method=method,
            headers={"X-Hub-Token": token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - a configured URL
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw, status = exc.read(), exc.code
        except (urllib.error.URLError, OSError) as exc:
            # The exception text can carry the URL; the class is enough.
            raise HubError(f"TheHub could not be reached ({type(exc).__name__})") from exc
        try:
            return status, json.loads(raw or b"null")
        except ValueError:
            return status, None

    return send


def open_story(send: Send) -> dict[str, Any] | None:
    """The open story this job filed earlier, if there is one."""
    for bucket in OPEN_BUCKETS:
        path = f"/api/dev/stories?bucket={bucket}&repo=mykronos&limit=1000"
        status, body = send("GET", path, None)
        if status != 200 or not isinstance(body, list):
            raise HubError(f"TheHub did not list the {bucket} (HTTP {status})")
        for story in body:
            if not isinstance(story, dict) or story.get("closed_at"):
                continue
            if story.get("source_ref") == SOURCE_REF:
                return story
    return None


def report(run: Run, send: Send, *, offset: str, commit: str) -> str:
    """Make the Hub agree with this run. Returns what it did, as a sentence."""
    if not run.failing:
        return f"time-travel: all {run.tests} tests pass at now{offset}; nothing to file."
    existing = open_story(send)
    if existing is None:
        payload = story_payload(run, offset=offset, commit=commit)
        status, body = send("POST", "/api/dev/stories", payload)
        if not 200 <= status < 300:
            raise HubError(f"TheHub refused the story (HTTP {status})")
        story_id = body.get("id") if isinstance(body, dict) else None
        return f"time-travel: filed TheHub #{story_id} for {len(run.failing)} failing test(s)."
    story_id = existing.get("id")
    if listed_tests(str(existing.get("detail") or "")) == run.failing:
        return f"time-travel: TheHub #{story_id} already lists these {len(run.failing)} test(s)."
    status, _ = send(
        "PATCH",
        f"/api/dev/stories/{story_id}",
        {"detail": story_detail(run, offset=offset, commit=commit)},
    )
    if not 200 <= status < 300:
        raise HubError(f"TheHub refused the update to #{story_id} (HTTP {status})")
    return f"time-travel: updated TheHub #{story_id} to {len(run.failing)} failing test(s)."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--offset", required=True, help="the libfaketime offset, e.g. +45d")
    parser.add_argument("--commit", required=True)
    args = parser.parse_args(argv)

    try:
        run = read_report(args.junit)
    except ReportError as exc:
        print(f"::error::time-travel: {exc}", file=sys.stderr)
        return 2
    for name in run.failing:
        print(f"time-travel: FAILS at now{args.offset}: {name}")

    url = os.environ.get("HUB_URL", "")
    token = os.environ.get("HUB_STORY_TOKEN", "")
    if run.failing and (not url or not token):
        print(
            "::error::time-travel: HUB_URL or HUB_STORY_TOKEN is empty, so these failures "
            "were not filed. Store it: vault-secret.ps1 set hub-story-token -Scope pipeline "
            "-Pipeline mykronos.",
            file=sys.stderr,
        )
        return 3
    try:
        print(report(run, http_sender(url, token), offset=args.offset, commit=args.commit))
    except HubError as exc:
        print(f"::error::time-travel: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
