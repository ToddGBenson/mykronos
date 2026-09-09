#!/usr/bin/env python3
"""Does the repository that owns a pipeline agree with the copy we apply? (B-055)

`check_applied_pipelines.py` (D-081) compares the *applied* pipeline to this
repository's file. That is one of two directions, and the other one is where
the security defect lived.

TheHub's promotion gate was fixed in TheHub's own repository on `main`. The
copy that gets applied lives here, and it never received the change: for two
weeks `insider` carried `passed: [oracle-gate]` instead of
`passed: [oracle-gate, api-inventory, dast-demo]`, so a commit whose demo DAST
had failed stayed eligible for `deploy-prod`. Both checks were green the whole
time. The applied pipeline matched this repository exactly, and this repository
was the copy that was wrong.

So this compares the third pair: **the owning repository's copy against ours**.

**What is compared, and why not the whole file.** The two files are not meant
to be identical -- ours is 4,100 lines and TheHub's `develop` is 7,900, mostly
inline task scripts -- and a whole-file diff would report hundreds of
differences nobody should act on, which is how a check stops being read. What
must agree is the part that governs: every job's name, and every `passed:`
constraint on every `get:` in it. That is the promotion gate. It is also
exactly what regressed.

    python scripts/check_pipeline_gates.py               # report
    python scripts/check_pipeline_gates.py --quiet       # exit code only
    python scripts/check_pipeline_gates.py --ref develop # one branch

Exit 0 when the deciding branch agrees with our copy, 1 when it does not. Only
one branch decides -- `develop` for TheHub, because every commit lands there
and that is where the pipeline is scanned (B-045). `main` is reported and never
failed on: it lags by design, and a check that goes red for an expected lag is
one nobody reads. `--ref` makes whichever branch you name the deciding one.

Fails soft when GitHub cannot be reached, for the same reason the
applied-pipeline check does: "no network here" is not drift.
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Our copy, and the repository that owns the original. Only pipelines whose
#: source lives somewhere else belong here: `mykronos.yml` is owned by this
#: repository, so there is no second copy to disagree with.
SOURCES = {
    "thehub": {
        "ours": "deploy/concourse/pipelines/thehub.yml",
        "repo": "ToddGBenson/TheHub",
        "path": "concourse/pipelines/thehub.yml",
        #: The branch this check *fails* on. Every commit in that repository
        #: lands on `develop` and the pipeline is scanned there (B-045), so
        #: `develop` is where a gate change appears first and where a
        #: disagreement with our copy means something is about to run
        #: ungated.
        "gate_ref": "develop",
        #: Reported, never failed on. `main` lags `develop` by design here --
        #: it is missing `dast-staging` today -- and failing on a lag that is
        #: expected is how a check becomes the one nobody reads.
        "also_report": ("main",),
    },
}


@dataclass
class Report:
    missing_here: list[str] = field(default_factory=list)
    missing_there: list[str] = field(default_factory=list)
    gate: list[str] = field(default_factory=list)

    @property
    def differs(self) -> bool:
        return bool(self.missing_here or self.missing_there or self.gate)


def fetch(repo: str, path: str, ref: str) -> str | None:
    """The file as that repository has it, or None if it cannot be read."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/contents/{path}?ref={ref}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
        return base64.b64decode(payload["content"]).decode("utf-8")
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


def gates(config: dict[str, Any]) -> dict[str, dict[str, list[str]]]:
    """Every job's `passed:` constraints, by job and then by resource.

    Nested steps are walked rather than only the top level: a `get` inside an
    `in_parallel` or a `do` gates promotion exactly as much as one written
    flat, and reading only the outer list is how a check misses the constraint
    it exists to read.
    """
    out: dict[str, dict[str, list[str]]] = {}
    for job in config.get("jobs") or []:
        if not isinstance(job, dict) or "name" not in job:
            continue
        found: dict[str, list[str]] = {}

        def walk(steps: Any, into: dict[str, list[str]] = found) -> None:
            if isinstance(steps, dict):
                steps = [steps]
            for step in steps or []:
                if not isinstance(step, dict):
                    continue
                if "get" in step and step.get("passed"):
                    into[str(step["get"])] = sorted(str(p) for p in step["passed"])
                for key in ("do", "in_parallel", "try", "on_failure", "on_success", "ensure"):
                    nested = step.get(key)
                    if isinstance(nested, dict) and "steps" in nested:
                        walk(nested["steps"], into)
                    elif nested is not None:
                        walk(nested, into)

        walk(job.get("plan"))
        out[str(job["name"])] = found
    return out


def compare(ours: dict[str, Any], theirs: dict[str, Any]) -> Report:
    """Ours against theirs, at the level that governs promotion."""
    report = Report()
    mine, yours = gates(ours), gates(theirs)

    report.missing_here = sorted(set(yours) - set(mine))
    report.missing_there = sorted(set(mine) - set(yours))

    for job in sorted(set(mine) & set(yours)):
        for resource in sorted(set(mine[job]) | set(yours[job])):
            a, b = mine[job].get(resource), yours[job].get(resource)
            if a == b:
                continue
            report.gate.append(
                f"{job}: get {resource} passed: ours={a if a is not None else '(none)'} "
                f"theirs={b if b is not None else '(none)'}"
            )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-pipeline-gates", description=__doc__)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--ref", help="Check only this branch")
    args = parser.parse_args(argv)

    unreachable: list[str] = []
    differing: list[str] = []

    for pipeline, source in SOURCES.items():
        ours = yaml.safe_load((REPO_ROOT / str(source["ours"])).read_text(encoding="utf-8"))
        gate_ref = str(source["gate_ref"])
        refs = (
            (args.ref,) if args.ref else (gate_ref, *(str(r) for r in source["also_report"]))
        )

        for ref in refs:
            label = f"{source['repo']}@{ref}"
            decides = ref == gate_ref or args.ref is not None
            raw = fetch(str(source["repo"]), str(source["path"]), str(ref))
            if raw is None:
                unreachable.append(label)
                continue

            report = compare(ours, yaml.safe_load(raw))
            if report.differs and decides:
                differing.append(label)
            if args.quiet:
                continue

            print("=" * 70)
            print(f"{pipeline}  ({source['ours']})  vs  {label}")
            if not decides:
                print("  (reported only -- this branch lags by design and never fails the check)")
            print("=" * 70)
            if not report.differs:
                print("  the promotion gate matches, job for job")
            else:
                for job in report.missing_here:
                    print(f"  JOB MISSING HERE   {job} exists there and not in our copy")
                for job in report.missing_there:
                    print(f"  JOB MISSING THERE  {job} exists here and not in theirs")
                for line in report.gate:
                    print(f"  GATE  {line}")
            print()

    if unreachable:
        # Fails open, like the applied-pipeline check: not being able to read
        # GitHub from this machine is not a disagreement about the gate.
        print(f"Could not read from GitHub, so not checked: {', '.join(unreachable)}")

    if differing:
        print("These copies do not agree about what gates promotion:")
        for label in differing:
            print(f"  {label}")
        print(
            "A fix that lands in the owning repository does not reach the pipeline "
            "that runs until this repository's copy carries it too (B-055, D-081)."
        )
        return 1

    if not args.quiet and not unreachable:
        print("Every owning repository agrees with the copy we apply.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
