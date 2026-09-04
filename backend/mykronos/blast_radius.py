"""How much of the portfolio depends on a package (spec 19 §2.4).

A vulnerable package in a library forty repositories import is a different
priority from the same package in one leaf service, and nothing in this
platform could tell the difference: each repository's Atlas evidence is
self-contained, and every score derived from it is a statement about that
repository alone.

**Two populations, and the answer says which it used.** D-069 chose to count
*findings* because the resolved dependency set was not in the lake: package
names existed only where a scanner had complained about one. Spec 29 §1 put
the SBOM in the lake, so the measure spec 19 §2.4 originally asked for is now
computable — package name to the repositories that actually depend on it,
whether or not anybody has a finding on any of them.

The graph is used where it exists and the finding-derived count remains the
fallback, because a repository with no SBOM is not a repository with no
dependencies. Which one produced a number is reported rather than smoothed
over: they answer subtly different questions, and one of them systematically
under-reports. The same treatment `mapping_resolution` gets in spec 28.

Deliberately approximate either way. Package-name matching, not version
resolution: two repositories pinning different major versions of the same
library both count, because the question is "how concentrated is this
dependency in our portfolio", not "would one patch fix both". Exact cross-repo
version-graph resolution is a far larger undertaking than this signal is worth,
and pretending to it would make the number look more precise than it is.
"""

from __future__ import annotations

from typing import Any

from mykronos.lake.catalog import Catalog

#: Below this a package is not concentrated, it is merely used. SSCS trust
#: already penalises a repository for its own vulnerable dependencies; this
#: signal exists for the different fact that many teams are exposed to one
#: package at once, and a threshold of one or two would make it a general
#: dependency-count penalty wearing a new name.
DEFAULT_MIN_DEPENDENTS = 5


def _from_findings(catalog: Catalog) -> dict[str, int]:
    """Package name → repositories carrying an *open finding* on it (D-069).

    What this platform could measure before the SBOM reached the lake, and the
    fallback for every repository that still has no SBOM.

    What it costs, stated plainly because the number would otherwise look more
    complete than it is: a repository that depends on the package but whose
    scan found nothing wrong with it is not counted. This under-reports true
    dependency spread and never over-reports it, which is the correct
    direction for a signal that adds points.

    Resolved findings are excluded. A package somebody already fixed
    everywhere is not a concentration risk, and counting it would make the
    signal insensitive to exactly the work it is supposed to encourage.
    """
    rows = catalog.query(
        """
        SELECT lower(trim(package_name)) AS name, count(DISTINCT asset_id)
        FROM findings
        WHERE status = 'open'
          AND package_name IS NOT NULL
          AND trim(package_name) <> ''
        GROUP BY 1
        ORDER BY 1
        """
    )
    return {str(name): int(count) for name, count in rows}


def _from_graph(catalog: Catalog) -> dict[str, int]:
    """Package name → repositories that actually depend on it (spec 29 §1.4).

    The measure spec 19 §2.4 asked for and D-069 could not build. No
    finding required: a package present in three repositories reports three,
    which is the honest answer to "how concentrated is this dependency" and
    the one somebody triaging a fresh CVE needs.
    """
    if not catalog.all_files("sbom_components"):
        return {}
    rows = catalog.query(
        """
        SELECT lower(trim(package_name)) AS name, count(DISTINCT repo_full_name)
        FROM sbom_components
        WHERE package_name IS NOT NULL AND trim(package_name) <> ''
        GROUP BY 1
        ORDER BY 1
        """
    )
    return {str(name): int(count) for name, count in rows}


def build(catalog: Catalog) -> dict[str, int]:
    """Package name → how many distinct repositories carry it.

    The graph where it exists, the finding-derived count everywhere else, and
    the **larger of the two** per package rather than one source winning
    outright. A portfolio part-way through adopting Atlas has both kinds of
    repository in it at once, and picking a single source would either drop
    the SBOM-less repositories from every count or throw away the graph
    entirely because one repository lacks it.

    Taking the maximum is safe in the one direction that matters: the
    finding-derived count only ever misses repositories, never invents them,
    so it can raise a package's count above the graph's only where the graph
    itself has a hole.
    """
    counts = _from_findings(catalog)
    for name, count in _from_graph(catalog).items():
        counts[name] = max(counts.get(name, 0), count)
    return counts


def resolution(catalog: Catalog) -> str:
    """`graph`, `findings`, or `mixed` — what produced these numbers.

    Reported for the reason spec 28 reports `mapping_resolution`: the two
    populations answer subtly different questions, and a caller who cannot
    tell which one they are reading cannot tell whether a zero means "nothing
    depends on this" or "nothing has complained about it yet".
    """
    graph = bool(_from_graph(catalog))
    findings = bool(_from_findings(catalog))
    if graph and findings:
        return "mixed"
    if graph:
        return "graph"
    return "findings"


def snapshot(
    package_names: list[str],
    dependents: dict[str, int] | None,
    *,
    min_dependents: int = DEFAULT_MIN_DEPENDENTS,
    points_per_package: float = 0.0,
    source: str = "findings",
) -> tuple[dict[str, Any], float]:
    """The Oracle input, and its contribution (spec 19 §2.4).

    `available: false` until the portfolio map has been built at least once —
    the established pattern for every input here. A map that exists and simply
    contains none of this repository's packages is available and contributes
    zero, which is a different statement and reads differently in the
    reasoning.
    """
    if dependents is None:
        return (
            {
                "available": False,
                "contribution": 0.0,
                "reason": (
                    "No portfolio dependency map has been built yet "
                    "(spec 19 §2.4). Concentration is a fact about the whole "
                    "portfolio, so it cannot be derived from this "
                    "repository's evidence alone."
                ),
            },
            0.0,
        )

    concentrated = sorted(
        (name, dependents[name])
        for name in {n.strip().lower() for n in package_names if n and n.strip()}
        if dependents.get(name, 0) >= min_dependents
    )
    contribution = points_per_package * len(concentrated)
    return (
        {
            "available": True,
            "min_dependents": min_dependents,
            "packages_in_portfolio": len(dependents),
            # `graph`, `findings`, or `mixed` (spec 29 §1.4). Published for
            # the reason spec 28 publishes `mapping_resolution`: a reader who
            # cannot tell which population produced a count cannot tell
            # whether a zero means "nothing depends on this" or "nothing has
            # complained about it yet".
            "source": source,
            "concentrated_packages": [
                {"package_name": name, "dependent_repos": count}
                for name, count in concentrated
            ],
            "contribution": round(contribution, 2),
        },
        contribution,
    )
