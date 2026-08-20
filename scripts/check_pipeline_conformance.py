"""Do the Concourse pipelines still follow the pipeline standard? (D-078)

A standard nobody checks is a comment. `docs/pipeline-standard.md` exists
because thirty-eight hand-rolled jobs drifted apart in every way they could;
nothing stops the thirty-ninth from drifting the same way except this.

Deliberately structural rather than clever. Every rule below is checked by
asking a question about the parsed pipeline — does this job have a preflight
step, does that task carry a timeout — and each maps to one numbered rule with
the failure it prevents written out in the standard.

Six of the ten rules are machine-checkable and are checked here:

    PS-2   a job that talks to Mykronos probes it first
    PS-3   a scanner's exit code cannot skip the upload
    PS-4   scanning lanes wait for the quality gate
    PS-6   no lane names its own branch
    PS-7   every non-hook task has a timeout
    PS-8   no binary is fetched into a shell unverified
    PS-10  the notifier verifies delivery
    (plus: every job appears in a group, or Concourse hides it)

The other four are judgement — whether a stage reports the *right* capability
(PS-1), whether a granted capability has a lane (PS-5), whether a credential
belongs in Vault (PS-9), whether the taxonomy still describes the pipeline.
Those are reviewed against the standard by a person, and the conformance table
in the standard is where the answer is written down.

    python scripts/check_pipeline_conformance.py          # report + exit code
    python scripts/check_pipeline_conformance.py --quiet  # exit code only

`tests/test_pipeline_conformance.py` runs this over both pipelines, so the
`unit` lane is what actually enforces it — which means a pipeline change that
breaks the standard fails the quality gate before it can reach a scanner.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

#: `personal-soc` is deliberately absent: it scans a network on a timer rather
#: than a commit through a delivery pipeline, so the quality-gate and
#: scan-then-upload rules do not describe it. Add it here the day it grows a
#: commit-triggered lane.
PIPELINES = (
    "deploy/concourse/pipelines/mykronos.yml",
    "deploy/concourse/pipelines/thehub.yml",
)

#: Steps that are hooks rather than work. They carry their timeout on the
#: shared anchor, so looking for one on the step would report every use of the
#: anchor as a violation.
HOOK_TASKS = frozenset({"preflight", "report-to-hub", "notify-slack"})

#: A job with no `passed:` is conformant when it *is* the gate — which is
#: derived below from what other jobs depend on, rather than listed here, so
#: that adding a lane to the quality gate does not also mean editing this file.
#:
#: `pin-check` is the one standing exception and it is deliberate: D-074 gives
#: it no dependants on purpose, because a stale pin should be a loud red job
#: rather than a stopped fleet.
GATE_EXEMPT = frozenset({"pin-check"})


def _walk(node: Any, visit: Any) -> None:
    if isinstance(node, dict):
        visit(node)
        for value in node.values():
            _walk(value, visit)
    elif isinstance(node, list):
        for value in node:
            _walk(value, visit)


def _scripts(job: dict[str, Any]) -> str:
    """Every shell body in the job, concatenated.

    The block scalars are where all the interesting behaviour lives, and the
    length filter drops `-ec` and other argv noise.
    """
    found: list[str] = []

    def visit(node: dict[str, Any]) -> None:
        run = node.get("run")
        if isinstance(run, dict):
            found.extend(
                arg for arg in (run.get("args") or []) if isinstance(arg, str) and len(arg) > 40
            )

    _walk(job, visit)
    return "\n".join(found)


def _uncommented(raw: str) -> str:
    """The file with comment lines removed.

    Both pipelines describe the unsafe forms they replaced, in comments, so a
    naive grep reports the explanation as the violation. A rule that cannot be
    explained next to the code is a rule the next person deletes.
    """
    return "\n".join(line for line in raw.split("\n") if not line.lstrip().startswith("#"))


def check_pipeline(path: Path) -> tuple[list[str], list[tuple[str, ...]]]:
    """Violations, and a row per job for the report."""
    raw = path.read_text(encoding="utf-8")
    document = yaml.safe_load(raw)
    name = path.name
    problems: list[str] = []
    rows: list[tuple[str, ...]] = []

    # The quality gate, derived: any job something else waits on. A lane with
    # no `passed:` that nothing depends on is a lane scanning ungated commits.
    depended_on: set[str] = set()

    def collect(node: Any) -> None:
        if isinstance(node, dict) and node.get("passed"):
            depended_on.update(node["passed"])

    _walk(document["jobs"], collect)

    for job in document["jobs"]:
        job_name = job["name"]
        body = _scripts(job)
        plan = job["plan"]

        talks = any(
            marker in body
            for marker in ("mykronos.upload", "/api/ingest/", "/api/oracle/", "/api/patchwork/")
        )
        has_preflight = any(step.get("task") == "preflight" for step in plan)
        if talks and not has_preflight:
            problems.append(f"{name}:{job_name} PS-2 reports to Mykronos without a preflight probe")

        uploads = "mykronos.upload" in body
        # Any of these keeps the upload reachable past a failed scanner:
        # `|| rc=$?`, `<var>=${PIPESTATUS[0]}`, or an explicit `set +e` region.
        captures = bool(re.search(r"\|\| \w+=\$\?|\w+=\$\{PIPESTATUS|set \+e", body))
        ensured = any(isinstance(step.get("ensure"), dict) for step in plan)
        if uploads and not captures and not ensured:
            problems.append(
                f"{name}:{job_name} PS-3 a failing scanner would skip the upload — "
                f"capture the exit code, or move the upload into an `ensure:` hook"
            )

        untimed: list[str] = []

        def visit(node: dict[str, Any], sink: list[str] = untimed) -> None:
            task = node.get("task")
            if isinstance(task, str) and task not in HOOK_TASKS and "timeout" not in node:
                sink.append(task)

        _walk(plan, visit)
        if untimed:
            problems.append(f"{name}:{job_name} PS-7 task(s) with no timeout: {sorted(untimed)}")

        triggered = any(step.get("get") == "source" and step.get("trigger") for step in plan)
        gated = bool(plan[0].get("passed"))
        exempt = job_name in GATE_EXEMPT or job_name in depended_on
        if triggered and not gated and not exempt:
            problems.append(f"{name}:{job_name} PS-4 triggers on a commit with no quality gate")

        capabilities = sorted(set(re.findall(r"--capability (\w+)", body)))
        rows.append(
            (
                job_name,
                "yes" if has_preflight else ("--" if not talks else "MISS"),
                "n/a" if not uploads else ("rc" if captures else "ensure"),
                "yes" if not untimed else "MISS",
                ",".join(capabilities) or "-",
                "yes" if gated else "--",
            )
        )

    literal_branches = re.findall(r"--branch (?!\")\S+", raw)
    if literal_branches:
        problems.append(f"{name} PS-6 branch named literally: {sorted(set(literal_branches))}")

    code = _uncommented(raw)
    if re.search(r"curl[^\n]*\|\s*sh", code):
        problems.append(f"{name} PS-8 an installer is piped into a shell")
    downloads = len(re.findall(r"curl -sSfL -o \S+\n?\s*http|releases/download/", code))
    checksums = code.count("sha256sum -c -")
    if downloads and checksums < 3:
        problems.append(f"{name} PS-8 {checksums} checksum(s) for {downloads} download reference(s)")

    if '"ok":true' not in raw:
        problems.append(f"{name} PS-10 the notifier does not check the response body")

    jobs = {job["name"] for job in document["jobs"]}
    grouped = {n for group in document.get("groups", []) for n in group["jobs"]}
    if jobs - grouped:
        problems.append(f"{name} jobs in no group, so Concourse hides them: {sorted(jobs - grouped)}")
    if grouped - jobs:
        problems.append(f"{name} groups name jobs that do not exist: {sorted(grouped - jobs)}")

    return problems, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-pipeline-conformance", description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="Exit code only, no table.")
    args = parser.parse_args(argv)

    all_problems: list[str] = []
    for relative in PIPELINES:
        path = REPO_ROOT / relative
        problems, rows = check_pipeline(path)
        all_problems.extend(problems)
        if args.quiet:
            continue
        print("=" * 78)
        print(relative)
        print("=" * 78)
        header = ("job", "PS-2", "PS-3", "PS-7", "reports", "PS-4")
        print(f"{header[0]:<18}{header[1]:<6}{header[2]:<8}{header[3]:<6}{header[4]:<24}{header[5]}")
        print("-" * 78)
        for row in rows:
            print(f"{row[0]:<18}{row[1]:<6}{row[2]:<8}{row[3]:<6}{row[4][:23]:<24}{row[5]}")
        print()

    if all_problems:
        print("The pipelines do not follow docs/pipeline-standard.md:")
        for problem in all_problems:
            print(f"  - {problem}")
        return 1

    print("Both pipelines follow docs/pipeline-standard.md.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
