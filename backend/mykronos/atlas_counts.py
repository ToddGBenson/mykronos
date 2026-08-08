"""Turn osv-scanner output into per-ecosystem counts (spec 07 §4, §8).

Runs on the runner, like `aegis_signals`. It reports *counts*; the trust score
is computed in the platform so it stays reproducible and cannot drift between
action versions (spec 07 §5, §7).

    python -m mykronos.atlas_counts osv.json

Prints the `ecosystems` array of an `SscsEvidenceSubmission` on stdout.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any

#: OSV severity vocabulary → ours. OSV reports CVSS vectors and a
#: database-specific severity; osv-scanner surfaces the latter as these
#: strings when it can and omits it when it cannot.
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

#: An advisory with no severity is counted as medium rather than dropped.
#: Dropping it would understate the tree, and treating it as critical would
#: make every unrated advisory a release blocker.
DEFAULT_SEVERITY = "medium"

#: Ecosystem names osv-scanner emits, normalised to lowercase for the
#: submission. Anything unrecognised passes through as-is rather than being
#: bucketed as "other" — a name we do not know is still a name worth keeping.
_PINNED_MARKERS = ("^", "~", ">", "<", "*", "x")


def _severity_of(vulnerability: dict[str, Any]) -> str:
    """Worst severity any advisory database assigns this vulnerability."""
    ranked = ["low", "medium", "high", "critical"]
    worst = None
    for entry in vulnerability.get("severity") or []:
        mapped = SEVERITY_MAP.get(str(entry.get("score", "")).upper())
        if mapped and (worst is None or ranked.index(mapped) > ranked.index(worst)):
            worst = mapped
    if worst:
        return worst

    for entry in vulnerability.get("database_specific") or {}, vulnerability:
        if isinstance(entry, dict):
            raw = str(entry.get("severity", "")).upper()
            if raw in SEVERITY_MAP:
                return SEVERITY_MAP[raw]
    return DEFAULT_SEVERITY


def _is_floating(version: str) -> bool:
    """Whether a version string is a range rather than an exact pin.

    Best-effort by design: the point of the signal is the *proportion* of
    unpinned dependencies, and misreading a handful of exotic specifiers moves
    a ratio by a fraction of a percent.
    """
    if not version:
        return True
    return any(marker in version for marker in _PINNED_MARKERS)


def summarise(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Collapse an osv-scanner JSON report into per-ecosystem counts.

    Counted per *package*, not per advisory: a dependency with four CVEs is one
    vulnerable dependency, and `vulnerable_dependency_count` in spec 07 §3 is
    explicitly a count of packages. Counting advisories would let a single
    badly-tracked package look like a systemic problem.
    """
    ecosystems: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "dependency_count": 0,
            "critical_vulns": 0,
            "high_vulns": 0,
            "medium_vulns": 0,
            "low_vulns": 0,
            "floating_versions": 0,
            "stale_dependencies": 0,
        }
    )
    seen: dict[str, set[str]] = defaultdict(set)

    for result in report.get("results") or []:
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            ecosystem = str(info.get("ecosystem") or "unknown").lower()
            name = str(info.get("name") or "")
            version = str(info.get("version") or "")

            bucket = ecosystems[ecosystem]
            key = f"{name}@{version}"
            if key not in seen[ecosystem]:
                seen[ecosystem].add(key)
                bucket["dependency_count"] += 1
                if _is_floating(version):
                    bucket["floating_versions"] += 1

            vulnerabilities = package.get("vulnerabilities") or []
            if not vulnerabilities:
                continue

            # One count per package, at its worst severity.
            ranked = ["low", "medium", "high", "critical"]
            worst = max(
                (_severity_of(v) for v in vulnerabilities),
                key=ranked.index,
                default=None,
            )
            if worst:
                bucket[f"{worst}_vulns"] += 1

    return [
        {
            "ecosystem": ecosystem,
            "tool_name": "osv-scanner",
            # Not reported by osv-scanner, so it is omitted rather than
            # guessed: spec 07 §8 excludes packages with no maintenance data
            # from the stale ratio, and null is how the API is told to fall
            # back to dependency_count.
            "maintenance_data_available_for": None,
            **counts,
        }
        for ecosystem, counts in sorted(ecosystems.items())
    ]


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: python -m mykronos.atlas_counts <osv-report.json>", file=sys.stderr)
        return 2

    try:
        with open(args[0], encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        # An empty array rather than a crash: the workflow should still record
        # evidence that a scan ran, and an unreadable report is a scanner
        # problem the ScanRun already captures (spec 04 §7).
        print(f"Could not read {args[0]}: {exc}", file=sys.stderr)
        json.dump([], sys.stdout)
        return 0

    json.dump(summarise(report), sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
