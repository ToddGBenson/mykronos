"""Turn osv-scanner output into per-ecosystem counts (spec 07 §4, §8).

Runs on the runner, like `aegis_signals`. It reports *counts*; the trust score
is computed in the platform so it stays reproducible and cannot drift between
action versions (spec 07 §5, §7).

    python -m mykronos.atlas_counts osv.json --sbom sbom.json

Prints the `ecosystems` array of an `SscsEvidenceSubmission` on stdout.
"""

from __future__ import annotations

import argparse
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


def summarise(
    report: dict[str, Any],
    licenses: dict[str, dict[str, int]] | None = None,
    freshness: dict[str, dict[str, int]] | None = None,
) -> list[dict[str, Any]]:
    """Collapse an osv-scanner JSON report into per-ecosystem counts.

    Counted per *package*, not per advisory: a dependency with four CVEs is one
    vulnerable dependency, and `vulnerable_dependency_count` in spec 07 §3 is
    explicitly a count of packages. Counting advisories would let a single
    badly-tracked package look like a systemic problem.

    `licenses` is `atlas_sbom.licenses_by_ecosystem` output, merged in when the
    license pass ran (spec 22 §1). An ecosystem the SBOM names and osv-scanner
    does not gets a row of its own rather than being dropped — a component set
    the scanner could not check for advisories still has licenses worth
    recording, and silently discarding it would make the license counts
    disagree with the SBOM for no visible reason.
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

    seen_licenses = licenses or {}
    seen_freshness = freshness or {}
    for ecosystem in (*seen_licenses, *seen_freshness):
        ecosystems[ecosystem]  # noqa: B018 — defaultdict, creates the row

    rows = []
    for ecosystem, counts in sorted(ecosystems.items()):
        fresh = seen_freshness.get(ecosystem)
        if fresh:
            counts["stale_dependencies"] = fresh["stale"]
        rows.append(
            {
                "ecosystem": ecosystem,
                "tool_name": "osv-scanner",
                # None when the freshness lookup did not run for this
                # ecosystem — either not configured, or no registry this
                # module knows how to ask. spec 07 §8 falls back to
                # dependency_count for the stale ratio's denominator in that
                # case, which with a stale count of 0 contributes nothing.
                # A real number here is the whole point of spec 22 §2: for
                # the first time, "we checked 40 packages and 3 are
                # abandoned" is distinguishable from "we checked none".
                "maintenance_data_available_for": fresh["known"] if fresh else None,
                "licenses_seen": seen_licenses.get(ecosystem, {}),
                **counts,
            }
        )
    return rows


def _licenses(path: str | None) -> dict[str, dict[str, int]]:
    """License counts from the SBOM, or none of them.

    Tolerated failure throughout. The license penalty is worth a couple of
    points; the vulnerability counts in the same submission are worth the
    whole trust score, and an SBOM that will not parse must not cost them.
    """
    if not path:
        return {}
    from mykronos.atlas_sbom import licenses_by_ecosystem

    try:
        with open(path, encoding="utf-8") as handle:
            return licenses_by_ecosystem(json.load(handle))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {path}, skipping licenses: {exc}", file=sys.stderr)
        return {}


def _freshness(path: str | None, threshold_days: int) -> dict[str, dict[str, int]]:
    """Registry-derived staleness, or none of it.

    Opt-in: no `--check-freshness`, no outbound call. Same tolerated failure
    as the license pass — this is worth a term, the vulnerability counts in
    the same submission are worth the score.
    """
    if not path:
        return {}
    from mykronos.atlas_freshness import staleness

    try:
        with open(path, encoding="utf-8") as handle:
            return staleness(json.load(handle), threshold_days=threshold_days)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read {path}, skipping freshness: {exc}", file=sys.stderr)
        return {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mykronos-atlas-counts", description=__doc__
    )
    parser.add_argument("report", help="The osv-scanner JSON report.")
    parser.add_argument(
        "--sbom",
        default=None,
        help=(
            "The SBOM Syft produced. Enables the license pass (spec 22 §1); "
            "without it `licenses_seen` stays empty, which the platform reads "
            "as not-computed rather than as no-licenses-found."
        ),
    )
    parser.add_argument(
        "--check-freshness",
        action="store_true",
        help=(
            "Query the npm and PyPI registries for each package's last "
            "publish date (spec 22 §2). Off by default because it makes "
            "outbound calls to third parties, which spec 07 §7 requires be "
            "opted into. Needs --sbom."
        ),
    )
    parser.add_argument("--staleness-threshold-days", type=int, default=730)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        # An empty array rather than a crash: the workflow should still record
        # evidence that a scan ran, and an unreadable report is a scanner
        # problem the ScanRun already captures (spec 04 §7).
        print(f"Could not read {args.report}: {exc}", file=sys.stderr)
        json.dump([], sys.stdout)
        return 0

    json.dump(
        summarise(
            report,
            _licenses(args.sbom),
            _freshness(
                args.sbom if args.check_freshness else None,
                args.staleness_threshold_days,
            ),
        ),
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
