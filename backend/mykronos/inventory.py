"""Which of our repositories contain this package? (spec 29 §1)

The SBOM has been generated on every Atlas run since spec 07 and only ever
archived — downloadable per repository, queryable across none of them. So the
one question that matters at two in the morning could not be answered about
data the platform had already collected and was storing as an opaque blob. The
honest answer to *"are we affected by this CVE"* was somebody opening four
SBOMs by hand.

**A third read of a file the runner already produced.** Not a new scan, not a
new tool, and — deliberately — not a new upload either: the SBOM is already
archived through `/api/ingest/raw` and its ref already arrives on the Atlas
evidence submission, so the components are extracted server-side from a file
that is already on disk. That means no workflow template changes, and it means
a repository whose SBOM was archived last month gets an inventory the next time
it reports rather than the next time somebody resyncs its workflow.

**What this table is not.** It stores what the SBOM contains, and says so
(spec 29 §1.3). Syft resolves what a build resolves; a vendored copy, a system
library inside a base image, and anything the manifest does not declare are all
outside it. Container findings cover the second. The first is a limit of SBOM
scope, stated once wherever this is surfaced rather than implied by an absence
of rows — because an inventory that quietly omits things is worse under time
pressure than no inventory at all.

**`purl` is the join key, name is the fallback, and the answer says which.**
Ecosystems disagree about naming and packages get renamed upstream. Matching on
the package URL where Syft emitted one is exact; matching on name is a guess
that is usually right, and the difference is reported rather than smoothed
over — the same treatment `mapping_resolution` gets in spec 28.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mykronos.atlas_sbom import _components, _ecosystem_of, _licenses_of
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How many components one SBOM may contribute. A guard, not a policy: four
#: repositories with a few thousand components each is well inside what the
#: compaction model already handles for findings, and a file claiming a
#: hundred thousand is a malformed or hostile document rather than a
#: dependency tree. Truncation is logged, never silent — spec 29 §4's own
#: rule that a bounded answer must say it is bounded.
MAX_COMPONENTS = 25_000


def component_id(repo_full_name: str, ecosystem: str, name: str, version: str) -> str:
    """Stable, so an unchanged dependency keeps its row and its `first_seen_at`.

    Keyed on the resolved identity rather than randomly: a rescan that sees the
    same tree must upsert it, not append a second copy of every component in
    the repository every week.
    """
    material = f"{repo_full_name}\x00{ecosystem}\x00{name}\x00{version}"
    return hashlib.sha256(material.encode()).hexdigest()


def _direct_flag(component: dict[str, Any]) -> bool | None:
    """Whether Syft called this a direct dependency, or `None`.

    `None` rather than `False` where the SBOM does not distinguish, which is
    most of them: "Syft did not say" and "this is transitive" are different
    facts, and the second is a claim this platform cannot make from a document
    that does not contain it.
    """
    for key in ("direct", "isDirect"):
        value = component.get(key)
        if isinstance(value, bool):
            return value
    relationship = str(component.get("relationship") or "").lower()
    if relationship in {"direct", "root"}:
        return True
    if relationship in {"transitive", "indirect"}:
        return False
    return None


def rows_from_sbom(
    sbom: dict[str, Any],
    *,
    repo_full_name: str,
    commit_sha: str,
    scan_run_id: str,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """One row per resolved component. Never raises on a malformed document."""
    stamp = now or utcnow()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    for component in _components(sbom):
        name = str(component.get("name") or "").strip()
        if not name:
            # A component with no name cannot be matched against a CVE, joined
            # to another repository, or shown to anybody. Dropped rather than
            # stored as an empty string that would group with every other one.
            continue
        version = str(component.get("version") or "").strip()
        ecosystem = _ecosystem_of(component)
        identifier = component_id(repo_full_name, ecosystem, name, version)
        if identifier in seen:
            # The same package at the same version listed twice in one
            # document. One row: the duplicate is a property of the SBOM, not
            # of the dependency tree.
            continue
        seen.add(identifier)

        licenses = sorted(set(_licenses_of(component)))
        rows.append(
            {
                "component_id": identifier,
                "repo_full_name": repo_full_name,
                "commit_sha": commit_sha,
                "scan_run_id": scan_run_id,
                "ecosystem": ecosystem,
                "package_name": name,
                "package_version": version,
                "direct": _direct_flag(component),
                "purl": str(component.get("purl") or ""),
                "license_ids_json": json.dumps(licenses) if licenses else None,
                "first_seen_at": stamp,
                "observed_at": stamp,
            }
        )
        if len(rows) >= MAX_COMPONENTS:
            logger.warning(
                "SBOM for %s carried more than %s components; the inventory is "
                "truncated and is not a complete picture of this repository.",
                repo_full_name,
                MAX_COMPONENTS,
            )
            break

    return rows


def record(
    buffer: WriteAheadBuffer,
    sbom: dict[str, Any],
    *,
    repo_full_name: str,
    commit_sha: str,
    scan_run_id: str,
    now: datetime | None = None,
) -> int:
    """Write a repository's resolved components. Returns how many."""
    rows = rows_from_sbom(
        sbom,
        repo_full_name=repo_full_name,
        commit_sha=commit_sha,
        scan_run_id=scan_run_id,
        now=now,
    )
    if rows:
        buffer.append("sbom_components", rows)
    return len(rows)


# ---------------------------------------------------------------------------
# Reading it back
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RepoExposure:
    """One repository's exposure to one package (spec 29 §2)."""

    repo_full_name: str
    versions: list[str] = field(default_factory=list)
    ecosystem: str = ""
    #: `purl` or `name` — how this repository was matched. A package renamed
    #: upstream matches by name and not by purl, and a view that did not say
    #: which would present a guess as an identity.
    matched_by: str = "name"
    #: The commit whose SBOM this came from, and when. An inventory as of six
    #: months ago presented as current is the failure mode this view could
    #: most easily have.
    commit_sha: str = ""
    observed_at: datetime | None = None


def _match_clause(query: str) -> tuple[str, list[Any], str]:
    """`(sql, params, kind)` for a package query.

    A purl is matched on its own prefix rather than on equality: callers paste
    `pkg:npm/lodash` as often as `pkg:npm/lodash@4.17.21`, and an exact match
    on the first would find nothing while looking like a definitive answer.
    """
    cleaned = query.strip()
    if cleaned.lower().startswith("pkg:"):
        base = cleaned.split("@")[0]
        return ("purl = ? OR purl LIKE ?", [cleaned, f"{base}@%"], "purl")
    return ("lower(package_name) = ?", [cleaned.lower()], "name")


def exposure(
    catalog: Catalog, query: str, *, limit: int = 500
) -> list[RepoExposure]:
    """Every repository containing this package, newest observation first.

    Grouped by repository and *not* collapsed across versions: "we have three
    copies and one is patched" is the actual state, and a single row per
    repository would hide the two that are not.
    """
    if not query.strip() or not catalog.all_files("sbom_components"):
        return []

    clause, params, kind = _match_clause(query)
    rows = catalog.query(
        f"""
        SELECT repo_full_name, package_version, ecosystem, commit_sha, observed_at
        FROM sbom_components
        WHERE {clause}
        ORDER BY repo_full_name, package_version
        LIMIT ?
        """,
        [*params, limit],
    )

    by_repo: dict[str, RepoExposure] = {}
    for repo, version, ecosystem, commit, observed in rows:
        key = str(repo)
        existing = by_repo.get(key)
        if existing is None:
            by_repo[key] = RepoExposure(
                repo_full_name=key,
                versions=[str(version)] if version else [],
                ecosystem=str(ecosystem or ""),
                matched_by=kind,
                commit_sha=str(commit or ""),
                observed_at=observed,
            )
            continue
        if version and str(version) not in existing.versions:
            existing.versions.append(str(version))

    return sorted(by_repo.values(), key=lambda e: e.repo_full_name)


def repos_with_an_sbom(catalog: Catalog) -> set[str]:
    """Every repository this inventory can speak about at all.

    The set that makes "not affected" meaningful. A repository absent from it
    has not been checked, and reporting it as unaffected would be the most
    dangerous thing this view could do — spec 29 §4 makes it an acceptance
    criterion for exactly that reason.
    """
    if not catalog.all_files("sbom_components"):
        return set()
    rows = catalog.query("SELECT DISTINCT repo_full_name FROM sbom_components")
    return {str(r[0]) for r in rows}


def dependents(catalog: Catalog, package_name: str) -> int:
    """How many repositories depend on this package (spec 29 §1.4).

    D-069 counted *findings* because package names were unavailable. They are
    available now, so the measure spec 19 §2.4 originally asked for is
    computable: a package in three repositories reports three, whether or not
    any of them has a finding on it.
    """
    if not package_name.strip() or not catalog.all_files("sbom_components"):
        return 0
    rows = catalog.query(
        "SELECT count(DISTINCT repo_full_name) FROM sbom_components "
        "WHERE lower(package_name) = ?",
        [package_name.strip().lower()],
    )
    return int(rows[0][0]) if rows else 0


def as_dict(item: RepoExposure) -> dict[str, Any]:
    return {
        "repo_full_name": item.repo_full_name,
        "versions": item.versions,
        "ecosystem": item.ecosystem,
        "matched_by": item.matched_by,
        "commit_sha": item.commit_sha,
        "observed_at": item.observed_at,
    }
