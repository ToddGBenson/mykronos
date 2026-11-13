"""Was this lane killed for memory, rather than judged? (TheHub #61117)

The mykronos pipeline's `unit`, `coverage` (TheHub #61210) and `lint-and-types`
tasks call this after the suite and before the upload:

    python ../scripts/memory_kill.py pytest --rc "$rc" --junit ../../results/unit.xml
    python ../scripts/memory_kill.py lint --rc-ruff "$rc_ruff" --rc-mypy "$rc_mypy"

`run` (TheHub #61606) wraps the suite itself: `python ../scripts/memory_kill.py run -- <cmd>`
re-runs it once, after waiting up to 5 minutes for MemAvailable to pass the
budget, when and only when it was killed (exit 137, or pytest exit 1 with only
dead xdist workers in its report) and the time allows, and returns the
command's own exit code.

It prints one line, the reason, when the run reached no verdict because
something was SIGKILLed for memory, and prints nothing otherwise. It always
exits 0: the task decides what to do with the answer.

What counts as killed for memory:

- pytest itself exited 137 (`Killed  python -m pytest -q -n 6`, unit #479);
- pytest exited 1 and EVERY failure or error in its JUnit report is an xdist
  worker crash (`[gwN] node down: Not properly terminated` in the log, which
  xdist records as "worker 'gwN' crashed while running '<test>'": unit #484
  and #485);
- ruff or mypy exited 137 (`Killed  python -m mypy mykronos`, lint #462/#466).

A real result anywhere wins over a kill: a failing test beside a crashed
worker (unit #486), or a ruff failure beside a killed mypy, is a verdict and
is never downgraded to an outage. It runs after the task's locked install, so
defusedxml is there; nothing else outside the standard library is needed.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from xml.etree import ElementTree  # ParseError only; the parse is defusedxml's

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

KILLED = 137
# The whole `message` attribute of the report xdist writes for a dead worker,
# and nothing else: never the body, which for a real failure can quote
# anything, this script's own output included (review B1 on #1084). xdist's
# report has when="???", so pytest's junitxml writes it through append_error
# as `failed on setup with "<msg>"` (#485's shape), or bare through
# append_failure.
CRASHED = re.compile(
    r"""(failed on (setup|teardown) with ")?worker '[^']+' crashed while running '[^']*'"?"""
)
TAIL = "This is not a test failure and not a red commit: re-run the job (TheHub #61117)."


def _reason(what: str) -> str:
    return f"INFRASTRUCTURE, NOT A VERDICT: killed: out of memory - {what}. {TAIL}"


def _crashes_and_real(junit: Path) -> tuple[int, int] | None:
    """(crashed workers, real failures) in a JUnit report, or None if unreadable."""
    try:
        root = SafeElementTree.parse(junit).getroot()
    except (OSError, ElementTree.ParseError, DefusedXmlException):
        return None
    if root is None:
        return None
    crashes = real = 0
    for case in root.iter("testcase"):
        for bad in list(case.findall("failure")) + list(case.findall("error")):
            if CRASHED.fullmatch(bad.get("message") or ""):
                crashes += 1
            else:
                real += 1
    return crashes, real


def pytest_verdict(rc: int, junit: Path) -> str:
    if rc == KILLED:
        return _reason(f"pytest was SIGKILLed (exit {KILLED}) before it wrote a verdict")
    if rc != 1:
        return ""
    counts = _crashes_and_real(junit)
    if counts is None:
        return ""
    crashes, real = counts
    if crashes and not real:
        return _reason(
            f"{crashes} xdist worker(s) were killed from outside (node down: Not properly "
            "terminated) and no test failed on its own"
        )
    return ""


def lint_verdict(rc_ruff: int, rc_mypy: int) -> str:
    rcs = {"ruff": rc_ruff, "mypy": rc_mypy}
    if any(rc not in (0, KILLED) for rc in rcs.values()):
        return ""
    killed = [name for name, rc in rcs.items() if rc == KILLED]
    if not killed:
        return ""
    names = " and ".join(killed)
    verb = "were" if len(killed) > 1 else "was"
    return _reason(f"{names} {verb} SIGKILLed (exit {KILLED}) before it reached a verdict")


def mem_available_mb() -> int | None:
    """MemAvailable from /proc/meminfo in MiB, or None where there is no /proc."""
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _call(cmd: Sequence[str]) -> int:
    """subprocess.call, with a death by signal N returned as 128+N like a shell does."""
    rc = subprocess.call(list(cmd))
    return 128 - rc if rc < 0 else rc


def _junit_of(cmd: Sequence[str]) -> Path | None:
    """The report a pytest command writes (`--junitxml=PATH`), if it names one."""
    for arg in cmd:
        if arg.startswith("--junitxml="):
            return Path(arg.split("=", 1)[1])
    return None


def was_killed(cmd: Sequence[str], rc: int) -> bool:
    """Exit 137, or pytest exit 1 where every failure in its report is a dead xdist worker."""
    if rc == KILLED:
        return True
    junit = _junit_of(cmd)
    if rc != 1 or junit is None:
        return False
    counts = _crashes_and_real(junit)
    return counts is not None and counts[0] > 0 and counts[1] == 0


def run_with_retry(
    cmd: Sequence[str],
    *,
    budget_mb: int = 1536,
    wait_s: float = 300.0,
    max_s: float = 3600.0,
    poll_s: float = 5.0,
    call: Callable[[Sequence[str]], int] = _call,
    available: Callable[[], int | None] = mem_available_mb,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    killed: Callable[[Sequence[str], int], bool] = was_killed,
) -> int:
    """Run `cmd`; when it was killed for memory, wait for memory and run it once more.

    Killed means exit 137, or pytest exit 1 where every failure in its JUnit
    report is a dead xdist worker (the classifier's own test, so a failing test
    beside a crashed worker is a verdict and never retries). A lane killed for
    memory judged nothing (TheHub #61117), and Concourse never re-runs a job
    without a new commit, so a person re-triggered it 30-60 minutes later
    (TheHub #61606). Any other exit code, including 1, 2 and 5 from a real
    failure, is returned as it is. The re-run happens only when the first run's
    time plus the wait plus a second run of the same length fits in `max_s`
    (the lane's soft budget, well under every task's hard timeout); otherwise
    the kill is reported as before. The second run's exit code is the result;
    if it is a kill again the report says it was re-run.
    """
    start = clock()
    rc = call(cmd)
    if not killed(cmd, rc):
        return rc
    first_s = clock() - start
    name = " ".join(cmd[:3])
    if 2 * first_s + wait_s > max_s:
        print(
            f"memory-retry: {name} was killed after {first_s:.0f}s; no re-run, because a "
            f"wait of up to {wait_s:.0f}s and a second run do not fit in {max_s:.0f}s.",
            flush=True,
        )
        return rc
    print(
        f"memory-retry: {name} was killed (exit {rc}) after {first_s:.0f}s; waiting for "
        "memory, then re-running once.",
        flush=True,
    )
    deadline = clock() + wait_s
    while True:
        free = available()
        if free is None or free > budget_mb:
            break
        if clock() >= deadline:
            print(
                f"memory-retry: {free} MiB available, under the {budget_mb} MiB budget "
                f"after {wait_s:.0f}s; re-running anyway.",
                flush=True,
            )
            break
        sleep(poll_s)
    rc = call(cmd)
    if killed(cmd, rc):
        again = f"{name} was killed (exit {rc}) again on the re-run; re-ran once"
        print(f"::error::{_reason(again)}", file=sys.stderr, flush=True)
    else:
        print(f"memory-retry: re-ran once after the kill; the re-run exited {rc}.", flush=True)
    return rc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="lane", required=True)
    p = sub.add_parser("pytest")
    p.add_argument("--rc", type=int, required=True)
    p.add_argument("--junit", type=Path, required=True)
    lint = sub.add_parser("lint")
    lint.add_argument("--rc-ruff", type=int, required=True)
    lint.add_argument("--rc-mypy", type=int, required=True)
    r = sub.add_parser("run", help="run a command, re-running it once if it is SIGKILLed")
    r.add_argument("--budget-mb", type=int, default=int(os.environ.get("MEMORY_BUDGET_MB") or "1536"))
    r.add_argument("--wait-s", type=float, default=300.0)
    r.add_argument("--max-s", type=float, default=float(os.environ.get("MEMORY_RETRY_MAX_S") or "3600"))
    r.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.lane == "run":
        cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not cmd:
            parser.error("run: no command")
        return run_with_retry(cmd, budget_mb=args.budget_mb, wait_s=args.wait_s, max_s=args.max_s)
    if args.lane == "pytest":
        reason = pytest_verdict(args.rc, args.junit)
    else:
        reason = lint_verdict(args.rc_ruff, args.rc_mypy)
    if reason:
        print(reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
