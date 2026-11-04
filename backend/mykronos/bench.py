"""The detector benchmark, graded inside the platform (spec 23 §1.6, TheHub #60742).

`scripts/bench_grade.py` grades the detectors against the seeded corpus from a
lake directory on disk. Nothing ever ran it: a Concourse task has no lake, and
the corpus repository did not exist. So no per-rule figure existed anywhere
and no change to triage could be graded.

This is the same grade, taken where the lake is. The `bench` job posts the
platform commit it is running for to `POST /api/ingest/bench-run`; the
platform reads the corpus repository's newest scanned commit from the lake,
reads `bench/manifest.yaml` at that commit through the GitHub App, grades, and
stores a :class:`~mykronos.db.models.BenchRun` with both commits. The job
exits with the run's verdict.

Matching is `bench_grade`'s, and `test_bench_runs.py` holds the two to one
answer: by file and line window within the seed's capability, five lines of
drift, never by rule id. What this adds is the per-rule view the triage work
(#60736) needs, and it adds it without the number spec 23 §1.3 refuses:

* **recall per rule** — of the seeds in this rule's capability, how many this
  rule's findings landed on;
* **`precision_floor` per rule** — matched findings over reported findings.
  The corpus is seeded, not clean: an unmatched finding may be a real flaw a
  fixture carries by accident. So matched/reported is the *least* the
  precision can be, and it is named as a floor everywhere it appears. Calling
  it precision would turn every accidental fixture bug into a false positive.

**No LLM anywhere in this**, as in the script.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

#: As `scripts/bench_grade.py`, and for its reason: the fingerprint already
#: assumes this much drift (spec 05 §5).
LINE_TOLERANCE = 5

#: Where the manifest lives in the corpus repository (spec 23 §1.2).
MANIFEST_PATH = "bench/manifest.yaml"

GRADED = "graded"
NOT_MEASURED = "not_measured"
MANIFEST_INVALID = "manifest_invalid"
STATUSES = (GRADED, NOT_MEASURED, MANIFEST_INVALID)


@dataclass(frozen=True)
class Seed:
    """One deliberately planted vulnerability."""

    identifier: str
    file: str
    line_start: int
    line_end: int
    capability: str
    description: str = ""

    def covers(self, path: str, line: int | None) -> bool:
        if _norm(path) != _norm(self.file):
            return False
        if line is None:
            # A finding with no line matches on the file alone, as the script
            # does: refusing it would mark a real detection as a miss for
            # lacking a coordinate the tool never produces.
            return True
        return self.line_start - LINE_TOLERANCE <= line <= self.line_end + LINE_TOLERANCE


def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _ratio(numerator: int, denominator: int) -> float | None:
    """`None` for an empty denominator: nothing to find is not a failure to find it."""
    return round(numerator / denominator, 3) if denominator else None


@dataclass
class CapabilityFigure:
    capability: str
    seeded_total: int = 0
    seeded_detected: int = 0
    missed: list[str] = field(default_factory=list)
    #: Whether any scan of this capability ran at the graded commit. A
    #: capability nobody scanned has no recall to report: its 0 would be the
    #: empty lake's, not the detector's (#60015, per capability).
    scanned: bool = True

    @property
    def recall(self) -> float | None:
        if not self.scanned:
            return None
        return _ratio(self.seeded_detected, self.seeded_total)

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "scanned": self.scanned,
            "seeded_total": self.seeded_total,
            "seeded_detected": self.seeded_detected,
            "recall": self.recall,
            "missed": list(self.missed),
        }


@dataclass
class RuleFigure:
    capability: str
    rule_id: str
    findings: int = 0
    matched: int = 0
    seeds_detected: int = 0
    seeds_in_capability: int = 0

    @property
    def unmatched(self) -> int:
        return self.findings - self.matched

    @property
    def recall(self) -> float | None:
        return _ratio(self.seeds_detected, self.seeds_in_capability)

    @property
    def precision_floor(self) -> float | None:
        return _ratio(self.matched, self.findings)

    def as_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "rule_id": self.rule_id,
            "findings": self.findings,
            "matched": self.matched,
            "unmatched": self.unmatched,
            "seeds_detected": self.seeds_detected,
            "seeds_in_capability": self.seeds_in_capability,
            "recall": self.recall,
            "precision_floor": self.precision_floor,
        }


@dataclass
class Grade:
    capabilities: list[CapabilityFigure]
    rules: list[RuleFigure]
    unmatched_findings: int


def parse_manifest(text: str | None) -> list[Seed]:
    """The seeds in `bench/manifest.yaml`. Raises ValueError on anything it cannot trust."""
    if text is None:
        raise ValueError(f"{MANIFEST_PATH} does not exist at the graded commit.")
    try:
        document = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{MANIFEST_PATH} is not valid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{MANIFEST_PATH} is not a mapping.")
    seeds: list[Seed] = []
    for index, entry in enumerate(document.get("seeded") or [], start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Entry {index} in {MANIFEST_PATH} is not a mapping.")
        missing = [k for k in ("file", "capability") if not entry.get(k)]
        if missing:
            raise ValueError(
                f"Entry {index} in {MANIFEST_PATH} is missing: {', '.join(missing)}."
            )
        try:
            start = int(entry.get("line_start") or entry.get("line") or 0)
            end = int(entry.get("line_end") or start)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Entry {index} in {MANIFEST_PATH} has a bad line: {exc}") from exc
        seeds.append(
            Seed(
                identifier=str(entry.get("id") or f"seed-{index}"),
                file=str(entry["file"]),
                line_start=start,
                line_end=end,
                capability=str(entry["capability"]),
                description=str(entry.get("description") or ""),
            )
        )
    if not seeds:
        raise ValueError(
            f"{MANIFEST_PATH} lists no seeded vulnerabilities. An empty corpus "
            "grades every detector at 100% recall, which is worse than no grade."
        )
    return seeds


def grade(
    seeds: list[Seed],
    findings: list[dict[str, Any]],
    scanned_capabilities: set[str] | None = None,
) -> Grade:
    """Per-capability recall, per-rule recall and precision floor, and the unmatched count.

    A seed is detected when any finding of its capability lands in its window,
    exactly as `bench_grade.grade` decides it. `scanned_capabilities`, when
    given, is the set of capabilities that ran a scan at the graded commit;
    a seeded capability outside it is reported unscanned with no recall.
    """
    capabilities: dict[str, CapabilityFigure] = {}
    rules: dict[tuple[str, str], RuleFigure] = {}
    seeds_hit_by_rule: dict[tuple[str, str], set[str]] = {}
    matched: set[int] = set()

    for finding in findings:
        key = (str(finding.get("capability") or ""), str(finding.get("rule_id") or ""))
        rules.setdefault(key, RuleFigure(*key)).findings += 1

    for seed in seeds:
        figure = capabilities.setdefault(
            seed.capability,
            CapabilityFigure(
                seed.capability,
                scanned=scanned_capabilities is None or seed.capability in scanned_capabilities,
            ),
        )
        figure.seeded_total += 1
        hit = False
        for index, finding in enumerate(findings):
            if finding.get("capability") != seed.capability:
                continue
            if seed.covers(str(finding.get("file_path") or ""), finding.get("line_start")):
                hit = True
                matched.add(index)
                key = (seed.capability, str(finding.get("rule_id") or ""))
                seeds_hit_by_rule.setdefault(key, set()).add(seed.identifier)
        if hit:
            figure.seeded_detected += 1
        else:
            figure.missed.append(seed.identifier)

    for index in matched:
        finding = findings[index]
        key = (str(finding.get("capability") or ""), str(finding.get("rule_id") or ""))
        rules[key].matched += 1

    for key, rule in rules.items():
        rule.seeds_detected = len(seeds_hit_by_rule.get(key, set()))
        cap = capabilities.get(key[0])
        rule.seeds_in_capability = cap.seeded_total if cap else 0

    return Grade(
        capabilities=[capabilities[c] for c in sorted(capabilities)],
        rules=[rules[k] for k in sorted(rules)],
        unmatched_findings=len(findings) - len(matched),
    )


# -- the lake -----------------------------------------------------------------


def latest_scanned_commit(catalog: Any, repo_full_name: str, branch: str) -> tuple[str, int] | None:
    """`(commit, scan runs at it)` for the corpus's newest scanned commit on `branch`.

    None when nothing has scanned the corpus on that branch: there is no grade
    to take, and 0% would be an artefact of an empty lake.
    """
    rows = catalog.query(
        """
        SELECT commit_sha, count(DISTINCT scan_run_id) AS runs,
               max(coalesce(completed_at, started_at)) AS last_at
        FROM scan_runs
        WHERE repo_full_name = ? AND coalesce(branch, '') = ? AND coalesce(commit_sha, '') <> ''
        GROUP BY commit_sha
        ORDER BY last_at DESC NULLS LAST, commit_sha
        LIMIT 1
        """,
        [repo_full_name, branch],
    )
    if not rows:
        return None
    return str(rows[0][0]), int(rows[0][1])


def scanned_capabilities(catalog: Any, repo_full_name: str, commit_sha: str) -> set[str]:
    """The capabilities that ran a scan at this commit."""
    rows = catalog.query(
        "SELECT DISTINCT capability FROM scan_runs WHERE repo_full_name = ? AND commit_sha = ?",
        [repo_full_name, commit_sha],
    )
    return {str(r[0]) for r in rows if r[0]}


def findings_for(catalog: Any, repo_full_name: str, commit_sha: str) -> list[dict[str, Any]]:
    """Every finding the platform ingested for this commit's scans.

    The lake, not a scanner's file, as in the script: an adapter that drops a
    finding on the way in is a detection failure this notices.
    """
    rows = catalog.query(
        """
        SELECT DISTINCT finding_id, capability, file_path, line_start, rule_id
        FROM findings
        WHERE asset_id = ? AND scan_run_id IN (
            SELECT scan_run_id FROM scan_runs WHERE repo_full_name = ? AND commit_sha = ?
        )
        """,
        [repo_full_name, repo_full_name, commit_sha],
    )
    return [
        {
            "capability": str(r[1] or ""),
            "file_path": str(r[2] or ""),
            "line_start": int(r[3]) if r[3] is not None else None,
            "rule_id": str(r[4] or ""),
        }
        for r in rows
    ]
