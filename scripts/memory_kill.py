"""Was this lane killed for memory, rather than judged? (TheHub #61117)

The mykronos pipeline's `unit` and `lint-and-types` tasks call this after the
suite and before the upload:

    python ../scripts/memory_kill.py pytest --rc "$rc" --junit ../../results/unit.xml
    python ../scripts/memory_kill.py lint --rc-ruff "$rc_ruff" --rc-mypy "$rc_mypy"

It prints one line, the reason, when the run reached no verdict because
something was SIGKILLed for memory, and prints nothing otherwise. It always
exits 0: the task decides what to do with the answer.

What counts as killed for memory:

- pytest itself exited 137 (`Killed  python -m pytest -q -n 6`, unit #479);
- pytest exited 1 and EVERY failure or error in its JUnit report is an xdist
  worker crash (`[gwN] node down: Not properly terminated`, reported as
  "worker 'gwN' crashed while running ...": unit #484 and #485);
- ruff or mypy exited 137 (`Killed  python -m mypy mykronos`, lint #462/#466).

A real result anywhere wins over a kill: a failing test beside a crashed
worker (unit #486), or a ruff failure beside a killed mypy, is a verdict and
is never downgraded to an outage. It runs after the task's locked install, so
defusedxml is there; nothing else outside the standard library is needed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from xml.etree import ElementTree  # ParseError only; the parse is defusedxml's

from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

KILLED = 137
CRASHED = re.compile(r"worker '[^']+' crashed while running|node down: Not properly terminated")
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
            text = f"{bad.get('message') or ''}\n{bad.text or ''}"
            if CRASHED.search(text):
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
    return _reason(f"{names} was SIGKILLed (exit {KILLED}) before it reached a verdict")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="lane", required=True)
    p = sub.add_parser("pytest")
    p.add_argument("--rc", type=int, required=True)
    p.add_argument("--junit", type=Path, required=True)
    lint = sub.add_parser("lint")
    lint.add_argument("--rc-ruff", type=int, required=True)
    lint.add_argument("--rc-mypy", type=int, required=True)
    args = parser.parse_args(argv)
    if args.lane == "pytest":
        reason = pytest_verdict(args.rc, args.junit)
    else:
        reason = lint_verdict(args.rc_ruff, args.rc_mypy)
    if reason:
        print(reason)
    return 0


if __name__ == "__main__":
    sys.exit(main())
