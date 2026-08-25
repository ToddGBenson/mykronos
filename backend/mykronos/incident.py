"""One question, every repository (spec 29 §2).

The operating assumption of this whole module is that it is read under time
pressure by somebody who has just been paged. Give it a CVE, a package name or
a purl, and it says which repositories contain it, at which versions, whether a
fix exists, what each repository's standing verdict is, and whether the CVE is
being exploited in the world right now.

**Nothing here is new information.** Every fact on this view is already in the
platform — the inventory (spec 29 §1), the findings, the Oracle decisions, the
KEV and EPSS matches, the risk profiles. The only new thing is that they are on
the same page, joined by package name and ordered by exposure. That is the
entire feature and it is worth more than any individual signal it displays,
because the alternative at 2am is five tabs and a mental join.

**"Not affected" is the dangerous answer, so this refuses to give it lightly.**
A repository with no SBOM is listed explicitly as *not checked*, never folded
into the clean set. An inventory that silently omits what it cannot see is
worse under pressure than no inventory: it converts an absence of data into a
statement of safety, which is the single failure this view could most easily
have and the one that would cost the most.

**As of when, on every row.** The inventory is as of each repository's last
Atlas scan, and that date rides on the row. Stale data presented as current is
the other way this view could quietly mislead somebody who is in a hurry.

**No automatic action.** A person asks the question and a person triggers the
batch. The platform does not open forty pull requests because KEV published
overnight — the same standard the "scan now" button and the override button
already hold.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from mykronos import inventory
from mykronos.db.models import RepoOnboarding, ThreatIntelMatch
from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

#: How many repositories one query reports on. Far above any real portfolio;
#: a guard against a query that matches a name every ecosystem uses.
MAX_REPOS = 200


@dataclass(frozen=True)
class Affected:
    """One repository's exposure (spec 29 §2)."""

    repo_full_name: str
    versions: list[str] = field(default_factory=list)
    ecosystem: str = ""
    matched_by: str = "name"
    commit_sha: str = ""
    observed_at: datetime | None = None
    #: The open findings on this package here, if any. Exposure and a finding
    #: are different facts: a repository can contain a vulnerable package with
    #: no finding because its last scan predates the advisory.
    open_findings: int = 0
    highest_severity: str = ""
    #: What the advisory says to upgrade to, where a scanner told us.
    fixed_version: str = ""
    #: Oracle's standing verdict, so triage order is obvious without opening
    #: each repository in turn.
    recommendation: str = ""
    risk_score: int | None = None


@dataclass(frozen=True)
class IncidentView:
    query: str
    kind: str
    affected: list[Affected] = field(default_factory=list)
    #: Repositories with an SBOM and no match — genuinely checked and clean.
    clear: list[str] = field(default_factory=list)
    #: Repositories this cannot speak about at all. Never reported as clean.
    not_checked: list[str] = field(default_factory=list)
    in_kev: bool | None = None
    epss_score: float | None = None


def _kind(query: str) -> str:
    cleaned = query.strip()
    if _CVE.match(cleaned):
        return "cve"
    if cleaned.lower().startswith("pkg:"):
        return "purl"
    return "package"


def _packages_for_cve(catalog: Catalog, cve_id: str) -> list[str]:
    """Which package names this CVE has been seen on, from findings.

    A CVE is not an inventory key — the inventory holds packages. So the
    advisory is resolved to package names through the findings that already
    cite it, which means a CVE nothing has ever reported on resolves to
    nothing and the view says so, rather than reporting every repository as
    unaffected by a CVE it simply cannot recognise.
    """
    if not catalog.all_files("findings"):
        return []
    rows = catalog.query(
        """
        SELECT DISTINCT lower(trim(package_name))
        FROM findings
        WHERE package_name IS NOT NULL AND trim(package_name) <> ''
          AND (upper(rule_id) = ? OR upper(title) LIKE ?)
        """,
        [cve_id.upper(), f"%{cve_id.upper()}%"],
    )
    return [str(r[0]) for r in rows if r[0]]


def _finding_context(
    catalog: Catalog, package_names: list[str]
) -> dict[str, dict[str, Any]]:
    """Per repository: open findings on these packages, and the fix if known."""
    if not package_names or not catalog.all_files("findings"):
        return {}
    placeholders = ", ".join("?" for _ in package_names)
    rows = catalog.query(
        f"""
        SELECT asset_id,
               count(*),
               max(severity),
               max(coalesce(
                   json_extract_string(raw_finding_json, '$.fixed_version'), ''
               ))
        FROM findings
        WHERE status = 'open'
          AND lower(trim(package_name)) IN ({placeholders})
        GROUP BY 1
        """,
        list(package_names),
    )
    return {
        str(repo): {
            "open_findings": int(count or 0),
            "highest_severity": str(severity or ""),
            "fixed_version": str(fixed or ""),
        }
        for repo, count, severity, fixed in rows
    }


def _verdicts(catalog: Catalog) -> dict[str, tuple[str, int | None]]:
    """Each repository's newest Oracle verdict, so triage order is obvious."""
    if not catalog.all_files("risk_decisions"):
        return {}
    rows = catalog.query(
        """
        SELECT repo_full_name, recommendation, overall_risk_score FROM (
            SELECT repo_full_name, recommendation, overall_risk_score,
                   row_number() OVER (
                       PARTITION BY repo_full_name ORDER BY evaluated_at DESC
                   ) AS rn
            FROM risk_decisions
        ) WHERE rn = 1
        """
    )
    return {
        str(repo): (str(rec or ""), int(score) if score is not None else None)
        for repo, rec, score in rows
    }


def look_up(
    catalog: Catalog,
    session: Session,
    query: str,
    *,
    limit: int = MAX_REPOS,
) -> IncidentView:
    """Answer "are we affected by this" across the portfolio."""
    cleaned = query.strip()
    kind = _kind(cleaned)
    view_kwargs: dict[str, Any] = {"query": cleaned, "kind": kind}

    if not cleaned:
        return IncidentView(**view_kwargs)

    if kind == "cve":
        match = session.get(ThreatIntelMatch, cleaned.upper())
        if match is not None:
            view_kwargs["in_kev"] = bool(match.in_kev)
            view_kwargs["epss_score"] = match.epss_score
        targets = _packages_for_cve(catalog, cleaned)
    else:
        targets = [cleaned]

    exposures: list[inventory.RepoExposure] = []
    for target in targets:
        exposures.extend(inventory.exposure(catalog, target, limit=limit))

    # `pkg:npm/lodash@4.17.21` → `lodash`. The findings table stores package
    # names, not purls, so joining back to findings needs the name the purl
    # encodes.
    package_names = (
        [cleaned.split("/")[-1].split("@")[0]] if kind == "purl" else targets
    )

    context = _finding_context(catalog, [name.lower() for name in package_names])
    verdicts = _verdicts(catalog)

    affected: list[Affected] = []
    seen: set[str] = set()
    for item in exposures:
        if item.repo_full_name in seen:
            continue
        seen.add(item.repo_full_name)
        extra = context.get(item.repo_full_name, {})
        recommendation, score = verdicts.get(item.repo_full_name, ("", None))
        affected.append(
            Affected(
                repo_full_name=item.repo_full_name,
                versions=item.versions,
                ecosystem=item.ecosystem,
                matched_by=item.matched_by,
                commit_sha=item.commit_sha,
                observed_at=item.observed_at,
                open_findings=int(extra.get("open_findings", 0)),
                highest_severity=str(extra.get("highest_severity", "")),
                fixed_version=str(extra.get("fixed_version", "")),
                recommendation=recommendation,
                risk_score=score,
            )
        )

    # Every repository the platform is watching, split three ways — and the
    # third way is the point. `not_checked` is what stops an absence of data
    # reading as a statement of safety.
    onboarded = {
        row.github_repo_full_name
        for row in session.query(RepoOnboarding).filter(
            RepoOnboarding.status != "removed"
        )
    }
    with_sbom = inventory.repos_with_an_sbom(catalog)

    return IncidentView(
        affected=sorted(
            affected,
            # Worst first: an open finding outranks mere presence, then the
            # standing verdict, then the name so the order is stable.
            key=lambda a: (
                -a.open_findings,
                {"no_go": 0, "review_recommended": 1, "go": 2}.get(a.recommendation, 3),
                a.repo_full_name,
            ),
        ),
        clear=sorted((with_sbom & onboarded) - seen),
        not_checked=sorted(onboarded - with_sbom),
        **view_kwargs,
    )


def as_dict(view: IncidentView) -> dict[str, Any]:
    return {
        "query": view.query,
        "kind": view.kind,
        "in_kev": view.in_kev,
        "epss_score": view.epss_score,
        "affected": [
            {
                "repo_full_name": item.repo_full_name,
                "versions": item.versions,
                "ecosystem": item.ecosystem,
                "matched_by": item.matched_by,
                "commit_sha": item.commit_sha,
                "observed_at": item.observed_at,
                "open_findings": item.open_findings,
                "highest_severity": item.highest_severity,
                "fixed_version": item.fixed_version,
                "recommendation": item.recommendation,
                "risk_score": item.risk_score,
            }
            for item in view.affected
        ],
        "clear": view.clear,
        "not_checked": view.not_checked,
        "note": (
            "Repositories under `not_checked` have no SBOM in the lake and "
            "this view cannot speak about them — they are not a clean result. "
            "Everything under `affected` is as of that repository's last "
            "Atlas scan, whose commit and date are on the row. The inventory "
            "covers what the SBOM resolved: a vendored copy or a library "
            "inside a base image is outside it, and container findings are "
            "where the second of those shows up."
        ),
    }
