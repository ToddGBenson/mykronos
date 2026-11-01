#!/usr/bin/env python3
"""Compare `Start-Here -Check` with the Today run sheet (TheHub #61141).

The run sheet (`GET /api/dashboard/today`) is trusted only after it has
agreed with the operator's terminal script for seven days in a row. This is
the comparison: it reads one `Start-Here -Check` transcript and one run-sheet
body, says per step whether they agree, and appends the verdict to a log.

    # one comparison (exit 0 when every compared step agrees, 1 when not)
    python scripts/runsheet_compare.py --start-here start-here.txt \\
        --today today.json --log runsheet-compare.jsonl

    # the run sheet read live, with an agent credential kept in a file
    python scripts/runsheet_compare.py --start-here start-here.txt \\
        --api-url http://127.0.0.1:8100 --token-file <path> --log ...

    # the acceptance verdict: the run of agreeing days (exit 0 at seven)
    python scripts/runsheet_compare.py --summary runsheet-compare.jsonl

Capture the transcript with `pwsh -File Start-Here.ps1 -Check *> file`, and
read the run sheet in the same minute: the two read live state.

What is compared, and what is not:

* **Decide**: the request ids Start-Here lists as decidable (their first
  eight characters, which is all it prints) against the run sheet's ready
  Decide items.
* **Merge**: the pull requests Start-Here offers (a line with no `not yet:`
  under it) against the run sheet's ready Merge items, for the repositories
  Start-Here's Merges section names. Start-Here covers a fixed list; the run
  sheet covers every onboarded repository, and the others are out of scope.
* **Deploy**: Start-Here's outcome mapped to the run sheet's state, and the
  running and main shas when both print them. An outcome decided by a guard
  only the host can see (the TheHub deploy lock, Delivery's hold flag) is
  skipped, never counted as agreement or disagreement.
* **Tasks** are not compared: Start-Here's one-offs are host scripts.

Standard library only, so it runs anywhere Python does.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

#: A deploy outcome only the host can see; never compared.
HOST_ONLY = "host-only"
#: The run of agreeing days the story asks for.
DAYS_REQUIRED = 7

_SECTION = re.compile(r"^== \[[^\]]*\] (?P<n>\d)\. ")
_SECTION_KEYS = {"1": "decide", "2": "merge", "3": "deploy"}
_DECIDE = re.compile(r"^  (?P<id>[0-9a-f]{8})  \S+\s+\S+\s+\S")
_MERGE = re.compile(r"^  (?P<repo>[^\s#/]+/[^\s#]+)#(?P<n>\d+)  (?P<rest>.*)$")
_NOT_READY = ("NOT merging:", "not approved at its head")
_SHAS = re.compile(r"running: (?P<running>\S+)\s+main: (?P<main>\S+)")
_SUMMARY_SHAS = re.compile(
    r"deploy (?P<main>[0-9a-f]{7}): production runs (?P<running>[0-9a-f]{7})"
)

#: Start-Here's deploy lines, in the order it checks them, to a state.
_DEPLOY_OUTCOMES: tuple[tuple[str, str], ...] = (
    ("production is on main", "done"),
    ("the Delivery session deploys", HOST_ONLY),
    ("is the backup window", "waiting"),
    ("HubOps is deploying TheHub", HOST_ONLY),
    ("Delivery concluded", "blocked"),
    ("lane is red", "blocked"),
    ("Delivery has not succeeded yet", "waiting"),
    ("The gate refused", "blocked"),
    ("Force-deploy", "ready"),
    ("to production?", "ready"),
)


@dataclass
class StartHere:
    decide: set[str] = field(default_factory=set)
    merge_ready: set[str] = field(default_factory=set)
    merge_repos: set[str] = field(default_factory=set)
    deploy: str | None = None
    running: str = ""
    main: str = ""
    #: The sections the transcript contained, by run-sheet step key.
    sections: set[str] = field(default_factory=set)


def parse_start_here(text: str) -> StartHere:
    out = StartHere()
    section: str | None = None
    lines = text.splitlines()
    for index, raw in enumerate(lines):
        line = raw.rstrip()
        header = _SECTION.match(line)
        if header:
            section = _SECTION_KEYS.get(header["n"])
            if section:
                out.sections.add(section)
            continue
        if line.startswith("== "):
            section = None
            continue
        if section == "decide":
            m = _DECIDE.match(line)
            if m:
                out.decide.add(m["id"])
        elif section == "merge":
            m = _MERGE.match(line)
            if not m:
                continue
            ref = f"{m['repo']}#{m['n']}"
            out.merge_repos.add(m["repo"])
            follows = lines[index + 1].strip() if index + 1 < len(lines) else ""
            if m["rest"].startswith(_NOT_READY) or follows.startswith("not yet:"):
                continue
            out.merge_ready.add(ref)
        elif section == "deploy":
            shas = _SHAS.search(line)
            if shas:
                out.running, out.main = shas["running"][:7], shas["main"][:7]
                continue
            if out.deploy is None:
                for needle, state in _DEPLOY_OUTCOMES:
                    if needle in line:
                        out.deploy = state
                        break
    return out


@dataclass
class Result:
    #: Step key -> agreed. A step absent here was not compared.
    steps: dict[str, bool] = field(default_factory=dict)
    diffs: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def agree(self) -> bool:
        return bool(self.steps) and all(self.steps.values())


def _step(sheet: dict[str, Any], key: str) -> dict[str, Any] | None:
    steps: list[dict[str, Any]] = sheet.get("steps") or []
    return next((step for step in steps if step.get("key") == key), None)


def _ready(step: dict[str, Any]) -> set[str]:
    return {str(i.get("ref") or "") for i in step.get("items") or [] if i.get("state") == "ready"}


def _sets(key: str, theirs: set[str], ours: set[str], result: Result) -> None:
    agreed = True
    for ref in sorted(theirs - ours):
        result.diffs.append(f"{key}: {ref} ready in Start-Here only")
        agreed = False
    for ref in sorted(ours - theirs):
        result.diffs.append(f"{key}: {ref} ready on the run sheet only")
        agreed = False
    result.steps[key] = agreed


def compare(start_here: StartHere, sheet: dict[str, Any]) -> Result:
    result = Result()
    for key in ("decide", "merge", "deploy"):
        if key not in start_here.sections:
            result.skipped.append(f"{key}: not in the Start-Here transcript")
            continue
        step = _step(sheet, key)
        if step is None or step.get("status") == "unavailable":
            why = (step or {}).get("reason") or "absent"
            result.diffs.append(f"{key}: the run sheet could not read it ({why})")
            result.steps[key] = False
            continue
        if key == "decide":
            _sets(key, start_here.decide, {ref[:8] for ref in _ready(step)}, result)
        elif key == "merge":
            ours = {ref for ref in _ready(step) if ref.split("#")[0] in start_here.merge_repos}
            _sets(key, start_here.merge_ready, ours, result)
        else:
            _deploy(start_here, step, result)
    return result


def _deploy(start_here: StartHere, step: dict[str, Any], result: Result) -> None:
    if start_here.deploy == HOST_ONLY:
        result.skipped.append("deploy: Start-Here was decided by a guard only the host can see")
        return
    if start_here.deploy is None:
        result.skipped.append("deploy: no outcome line in the Start-Here transcript")
        return
    agreed = True
    state = str(step.get("state") or "")
    if state != start_here.deploy:
        result.diffs.append(f"deploy: Start-Here {start_here.deploy}, run sheet {state}")
        agreed = False
    shas = _SUMMARY_SHAS.search(str(step.get("summary") or ""))
    if shas and start_here.running and start_here.main:
        theirs = (start_here.running, start_here.main)
        ours = (shas["running"], shas["main"])
        if theirs != ours:
            result.diffs.append(
                f"deploy: Start-Here running {theirs[0]} main {theirs[1]}, "
                f"run sheet running {ours[0]} main {ours[1]}"
            )
            agreed = False
    result.steps["deploy"] = agreed


@dataclass
class Summary:
    #: Consecutive days, ending at the newest logged day, with at least one
    #: run and every run agreeing.
    streak: int
    agreeing_days: list[str]
    disagreeing_days: list[str]

    @property
    def passed(self) -> bool:
        return self.streak >= DAYS_REQUIRED


def _day(at: str) -> date:
    return datetime.fromisoformat(at.replace("Z", "+00:00")).astimezone(UTC).date()


def summarise(lines: list[str]) -> Summary:
    days: dict[date, bool] = {}
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        day = _day(str(record["at"]))
        days[day] = days.get(day, True) and bool(record.get("agree"))
    streak = 0
    if days:
        cursor = max(days)
        while days.get(cursor) is True:
            streak += 1
            cursor -= timedelta(days=1)
    return Summary(
        streak=streak,
        agreeing_days=[d.isoformat() for d in sorted(days) if days[d]],
        disagreeing_days=[d.isoformat() for d in sorted(days) if not days[d]],
    )


def _read_sheet(args: argparse.Namespace) -> dict[str, Any]:
    if args.today:
        body: dict[str, Any] = json.loads(Path(args.today).read_text(encoding="utf-8"))
        return body
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    request = urllib.request.Request(
        args.api_url.rstrip("/") + "/api/dashboard/today",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - operator's own URL
        live: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    return live


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--start-here", help="a Start-Here -Check transcript")
    parser.add_argument("--today", help="a saved GET /api/dashboard/today body")
    parser.add_argument("--api-url", help="read the run sheet live from this API")
    parser.add_argument("--token-file", help="a file holding the API credential")
    parser.add_argument("--log", help="append the verdict to this JSON-lines file")
    parser.add_argument("--summary", help="print the agreeing-day run of this log")
    args = parser.parse_args(argv)

    if args.summary:
        summary = summarise(Path(args.summary).read_text(encoding="utf-8").splitlines())
        print(f"{summary.streak} agreeing day(s) in a row; {DAYS_REQUIRED} required")
        if summary.disagreeing_days:
            print("disagreed on: " + ", ".join(summary.disagreeing_days))
        return 0 if summary.passed else 1

    if not args.start_here or not (args.today or (args.api_url and args.token_file)):
        parser.error("--start-here and either --today or --api-url with --token-file")
    transcript = Path(args.start_here).read_text(encoding="utf-8", errors="replace")
    result = compare(parse_start_here(transcript), _read_sheet(args))
    for key, agreed in result.steps.items():
        print(f"{key}: {'agrees' if agreed else 'DIFFERS'}")
    for line in result.diffs:
        print(f"  {line}")
    for line in result.skipped:
        print(f"  not compared: {line}")
    if args.log:
        record = {
            "at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "agree": result.agree,
            "steps": result.steps,
            "diffs": result.diffs,
            "skipped": result.skipped,
        }
        with Path(args.log).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
    return 0 if result.agree else 1


if __name__ == "__main__":
    sys.exit(main())
