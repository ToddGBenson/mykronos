"""How much of the portfolio depends on a package (spec 19 §2.4).

A vulnerable package in a library forty repositories import is a different
priority from the same package in one leaf service, and nothing in this
platform could tell the difference: each repository's Atlas evidence is
self-contained, and every score derived from it is a statement about that
repository alone.

This is the cheapest thing that reads across them, and it needs no new write
path: findings already record `package_name`, so counting how many distinct
repositories carry an open finding on each package is one query over rows the
lake already holds. See `build` for what that population does and does not
cover.

Deliberately approximate. Package-name matching, not version resolution: two
repositories pinning different major versions of the same library both count,
because the question is "how concentrated is this dependency in our
portfolio", not "would one patch fix both". Exact cross-repo version-graph
resolution is a far larger undertaking than this signal is worth, and
pretending to it would make the number look more precise than it is.
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


def build(catalog: Catalog) -> dict[str, int]:
    """Package name → how many distinct repositories carry a finding on it.

    Built from `findings.package_name`, not from the SBOM. `sscs_evidence`
    holds per-ecosystem *counts* — that is what spec 07 §4 asks the runner to
    report — so the full resolved dependency set is not in the lake and this
    could not be a true "who depends on what" map without a new write path.

    Findings are, and for a *prioritisation* signal they are the right
    population anyway: the question this answers is "is this vulnerable
    package one many teams are exposed to", and a repository with no finding
    on a package has nothing here to prioritise.

    What that costs, stated plainly because the number would otherwise look
    more complete than it is: a repository that depends on the package but
    whose scan found nothing wrong with it is not counted. The map therefore
    under-reports true dependency spread and never over-reports it, which is
    the correct direction for a signal that adds points.

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


def snapshot(
    package_names: list[str],
    dependents: dict[str, int] | None,
    *,
    min_dependents: int = DEFAULT_MIN_DEPENDENTS,
    points_per_package: float = 0.0,
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
            "concentrated_packages": [
                {"package_name": name, "dependent_repos": count}
                for name, count in concentrated
            ],
            "contribution": round(contribution, 2),
        },
        contribution,
    )
