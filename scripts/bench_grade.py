#!/usr/bin/env python3
"""Grade the detectors against a seeded corpus (spec 23 §1).

Spec 04 §7's acceptance criterion has never been implementable. Its bar — "at
least one `Finding`" — cannot distinguish a scanner catching nine of ten seeded
injections from one catching one, and there was no seeded corpus to try it
against. A search for precision, recall, false negatives or ground truth across
this repository returned prose about the concepts and no measurement of any of
them.

So the platform runs fifteen checks and cannot say how well any of them works
on code like its own. That is worth fixing before anything agentic is built and
independently of whether anything agentic is ever built, which is why this is
workstream 1 and everything else in spec 23 is gated behind it.

**No LLM anywhere in this.** AVDH needs a grading agent because its findings
land on real client code with no ground truth. A seeded corpus has a manifest,
so grading is a diff.

**Matching is by file and line window, never by rule id.** A rule identifier is
a free-form string the reporting tool chose (spec 18 §6), so pinning a grade to
one would grade the tool's naming rather than its detection — and a manifest
would need rewriting every time a scanner renamed a rule. The manifest names
the expected *capability*, which is a fact about which lane should have caught
it.

Usage:

    python scripts/bench_grade.py bench/manifest.yaml \\
        --repo ToddGBenson/mykronos-bench --commit "$SHA" \\
        --lake ./datalake --out results/bench.xml
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import yaml

#: How far a finding may sit from its seeded line and still be the same issue.
#: The fingerprint already assumes this much drift — a finding two lines off
#: after an unrelated edit is the same finding (spec 05 §5) — and a grader
#: stricter than the identity model would report regressions the platform
#: itself does not believe in.
LINE_TOLERANCE = 5


@dataclass(frozen=True)
class Seed:
    """One deliberately-planted vulnerability."""

    identifier: str
    file: str
    line_start: int
    line_end: int
    capability: str
    description: str = ""

    def covers(self, path: str, line: int | None) -> bool:
        if path.replace("\\", "/").lstrip("./") != self.file.replace("\\", "/").lstrip("./"):
            return False
        if line is None:
            # A finding with no line — a dependency advisory, a secret in a
            # file the scanner did not locate precisely — matches on the file
            # alone. Refusing it would mark a real detection as a miss for
            # lacking a coordinate the tool never produces.
            return True
        return self.line_start - LINE_TOLERANCE <= line <= self.line_end + LINE_TOLERANCE


@dataclass
class CapabilityGrade:
    capability: str
    detected: list[Seed] = field(default_factory=list)
    missed: list[Seed] = field(default_factory=list)

    @property
    def seeded_total(self) -> int:
        return len(self.detected) + len(self.missed)

    @property
    def seeded_detected(self) -> int:
        return len(self.detected)

    @property
    def recall(self) -> float | None:
        """`None` rather than 0.0 when nothing was seeded for this capability.

        An empty denominator is not a failing grade — the same rule spec 31 §3
        applies to regression coverage, for the same reason: a lane with
        nothing to find has not failed to find it.
        """
        if not self.seeded_total:
            return None
        return round(self.seeded_detected / self.seeded_total, 3)


def load_manifest(path: Path) -> list[Seed]:
    """Read `bench/manifest.yaml`. Raises on anything it cannot trust."""
    document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    seeds: list[Seed] = []
    for index, entry in enumerate(document.get("seeded") or [], start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry {index} in {path} is not a mapping.")
        missing = [k for k in ("file", "capability") if not entry.get(k)]
        if missing:
            raise ValueError(
                f"Entry {index} in {path} is missing: {', '.join(missing)}. "
                "A seed with no file or no expected capability cannot be "
                "graded, and counting it as a miss would mark a detector down "
                "for the manifest's mistake."
            )
        start = int(entry.get("line_start") or entry.get("line") or 0)
        seeds.append(
            Seed(
                identifier=str(entry.get("id") or f"seed-{index}"),
                file=str(entry["file"]),
                line_start=start,
                line_end=int(entry.get("line_end") or start),
                capability=str(entry["capability"]),
                description=str(entry.get("description") or ""),
            )
        )
    if not seeds:
        raise ValueError(
            f"{path} lists no seeded vulnerabilities. An empty corpus grades "
            "every detector at 100% recall, which is worse than not grading "
            "them at all."
        )
    return seeds


def findings_for(lake: Path, repo_full_name: str, commit_sha: str) -> list[dict[str, Any]]:
    """Every finding the real pipelines recorded for this commit.

    Read from the lake rather than from a scanner's output file, deliberately:
    the thing being graded is what the platform *ingested*, so an adapter that
    drops a finding on the way in is a detection failure this notices. Grading
    raw tool output would measure the tools and exempt the platform.
    """
    import duckdb  # imported here so `--help` works without the lake deps

    pattern = (lake / "findings" / "**" / "*.parquet").as_posix()
    connection = duckdb.connect(":memory:")
    try:
        rows = connection.execute(
            f"""
            SELECT capability, file_path, line_start, rule_id, severity, status
            FROM read_parquet('{pattern}', hive_partitioning = 1, union_by_name = 1)
            WHERE asset_id = ? AND scan_run_id IN (
                SELECT scan_run_id FROM read_parquet(
                    '{(lake / "scan_runs" / "**" / "*.parquet").as_posix()}',
                    hive_partitioning = 1, union_by_name = 1
                ) WHERE repo_full_name = ? AND commit_sha = ?
            )
            """,
            [repo_full_name, repo_full_name, commit_sha],
        ).fetchall()
    finally:
        connection.close()

    return [
        {
            "capability": str(r[0] or ""),
            "file_path": str(r[1] or ""),
            "line_start": int(r[2]) if r[2] is not None else None,
            "rule_id": str(r[3] or ""),
            "severity": str(r[4] or ""),
            "status": str(r[5] or ""),
        }
        for r in rows
    ]


def grade(
    seeds: list[Seed], findings: list[dict[str, Any]]
) -> tuple[dict[str, CapabilityGrade], list[dict[str, Any]]]:
    """`(per-capability grades, unmatched findings)`.

    A seed is detected when *any* finding from its expected capability lands
    in its window. Matching within the capability rather than across it is the
    point of the benchmark: a secret scanner finding a SQL injection by
    accident is not the secrets lane working.
    """
    grades: dict[str, CapabilityGrade] = {}
    matched_findings: set[int] = set()

    for seed in seeds:
        entry = grades.setdefault(seed.capability, CapabilityGrade(seed.capability))
        hit = False
        for index, finding in enumerate(findings):
            if finding["capability"] != seed.capability:
                continue
            if seed.covers(finding["file_path"], finding["line_start"]):
                matched_findings.add(index)
                hit = True
        (entry.detected if hit else entry.missed).append(seed)

    unmatched = [f for i, f in enumerate(findings) if i not in matched_findings]
    return grades, unmatched


def to_junit(
    grades: dict[str, CapabilityGrade], unmatched: list[dict[str, Any]]
) -> bytes:
    """JUnit XML, so the grade travels the road every other quality lane does.

    A `functional` ScanRun on the bench repository (D-046): a detector missing
    a seeded bug is a defect in the platform, not a vulnerability in the
    corpus, and giving it a severity would put detector quality into a
    security risk score.

    **No precision figure, and `unmatched` is not a failure.** The corpus is
    seeded, not *clean*: an unmatched finding may be a genuine flaw somebody
    wrote by accident while writing a fixture. Calling it a false positive
    would manufacture a quality number out of an assumption. It is reported as
    a count for a human to investigate, and it fails nothing.
    """
    total = sum(g.seeded_total for g in grades.values())
    failures = sum(len(g.missed) for g in grades.values())
    suite = ElementTree.Element(
        "testsuite",
        name="mykronos-bench",
        tests=str(total),
        failures=str(failures),
        errors="0",
        skipped="0",
    )

    # One case per seed, detected or not — so `tests` equals the number of
    # cases the report actually contains. A count with no cases behind it is a
    # report that cannot be checked.
    for capability in sorted(grades):
        entry = grades[capability]
        missed = {seed.identifier for seed in entry.missed}
        for seed in sorted(
            [*entry.detected, *entry.missed], key=lambda s: (s.file, s.line_start)
        ):
            case = ElementTree.SubElement(
                suite,
                "testcase",
                classname=f"detect.{capability}",
                name=f"{seed.identifier} ({seed.file}:{seed.line_start})",
            )
            if seed.identifier in missed:
                failure = ElementTree.SubElement(
                    case,
                    "failure",
                    message=f"{capability} did not report this seeded issue",
                )
                failure.text = seed.description or seed.file

    # Recorded as a property rather than as a passing or failing case: it is
    # information, and a lane whose green depends on nobody having written an
    # extra bug into a fixture would be green for the wrong reason.
    properties = ElementTree.SubElement(suite, "properties")
    ElementTree.SubElement(
        properties, "property", name="unmatched_findings", value=str(len(unmatched))
    )
    for capability in sorted(grades):
        entry = grades[capability]
        ElementTree.SubElement(
            properties,
            "property",
            name=f"recall.{capability}",
            value="not-seeded" if entry.recall is None else f"{entry.recall}",
        )

    return ElementTree.tostring(suite, encoding="utf-8", xml_declaration=True)


def render_summary(
    grades: dict[str, CapabilityGrade], unmatched: list[dict[str, Any]]
) -> str:
    lines = ["Detector benchmark (spec 23 §1)", ""]
    for capability in sorted(grades):
        entry = grades[capability]
        recall = "—" if entry.recall is None else f"{entry.recall:.0%}"
        lines.append(
            f"  {capability:<12} {entry.seeded_detected}/{entry.seeded_total} "
            f"seeded issues detected  ({recall})"
        )
        for seed in entry.missed:
            lines.append(f"      missed: {seed.file}:{seed.line_start}  {seed.description}")
    lines += [
        "",
        f"  {len(unmatched)} finding(s) matched no manifest entry.",
        "  Not reported as false positives and not counted against anything:",
        "  the corpus is seeded, not clean, and an unmatched finding may be a",
        "  real flaw somebody wrote by accident. Investigate, do not assume.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="bench/manifest.yaml")
    parser.add_argument("--repo", required=True, help="The bench repository's full name.")
    parser.add_argument("--commit", required=True, help="The commit that was scanned.")
    parser.add_argument("--lake", type=Path, required=True, help="Data lake directory.")
    parser.add_argument("--out", type=Path, help="Where to write the JUnit XML.")
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help=(
            "Exit non-zero if any capability's recall falls below this. Off by "
            "default: the first runs of a new corpus establish a baseline, and "
            "a threshold picked before there is one is a number somebody "
            "invented."
        ),
    )
    args = parser.parse_args(argv)

    try:
        seeds = load_manifest(args.manifest)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Could not read the manifest: {exc}", file=sys.stderr)
        return 2

    findings = findings_for(args.lake, args.repo, args.commit)
    grades, unmatched = grade(seeds, findings)

    print(render_summary(grades, unmatched))

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(to_junit(grades, unmatched))
        print(f"\nWrote {args.out}")

    if args.fail_under is not None:
        below = [
            f"{g.capability} at {g.recall:.0%}"
            for g in grades.values()
            if g.recall is not None and g.recall < args.fail_under
        ]
        if below:
            print(
                f"\nBelow the {args.fail_under:.0%} floor: {', '.join(below)}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
