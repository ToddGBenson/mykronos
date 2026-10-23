"""Libraries: onboard third-party libraries and manage the ones we have
(TheHub epic #60880, stories #60895-#60897).

Until this module the Libraries page was an SBOM inventory: it could say what
the estate carries and could not say whether anybody had decided it should.
Three things change that, each a section below.

**Requesting a library vets it (L1, #60895).** A request names an ecosystem,
a package and a version, and the platform reads the evidence itself: OSV for
known vulnerabilities, deps.dev for the license, release history, OpenSSF
Scorecard and transitive dependency count, and two checks that need no
network - a typosquat check against the libraries the estate already uses
plus a short list of popular ones, and a new-package check against the date
the package first appeared. Every check names its source, and one that could
not be read says `unavailable`: a vetting report that quietly reads "no
vulnerabilities" because OSV timed out is worse than no report.

**Approval goes through the approvals duty (L2, #60896).** The report is the
evidence of a `library_approval` request. The tier is computed from the
report - `flagged` (any flag, or any check unavailable) needs a person,
`clean` can also be approved by a delegated agent - so a requester cannot
describe a typosquat as routine. Approval writes the allowlist entry for the
ecosystem with the version policy requested; a rejection is copied back onto
the request with the approver's reason.

**Every library in use has a status (L3, #60897).** `approved`, `tolerated`
or `banned`, an owner and a version policy. A library in the SBOM that
nobody has recorded reads as `tolerated` with `status_source: default`, so
the status is never missing, and the baseline route records those
explicitly - which is what a repository needs before its PR check may block
(`library_check`). Flags are computed, never asserted: divergence and a
license change across in-use versions from the SBOM, EOL and abandonment
from the registry facts the `library-facts` job reads. A flag the platform
has no data for is `null`, never `false`.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.approvals.engine import (
    ApprovalError,
    Subject,
    register_adapter,
    register_dedicated_route,
    register_on_approved,
)
from mykronos.db.models import (
    ApprovalDecision,
    ApprovalRequest,
    AuditLogEntry,
    LibraryEntry,
    LibraryFacts,
    LibraryRequest,
)
from mykronos.lake.catalog import Catalog
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

DUTY = "library_approval"
ROUTE = "/api/libraries/requests"

#: purl ecosystem -> (OSV ecosystem, deps.dev system). The purl name is the
#: one `sbom_components.ecosystem` carries, so a request and the inventory
#: speak the same key.
ECOSYSTEMS: dict[str, tuple[str, str]] = {
    "npm": ("npm", "NPM"),
    "pypi": ("PyPI", "PYPI"),
    "golang": ("Go", "GO"),
    "maven": ("Maven", "MAVEN"),
    "cargo": ("crates.io", "CARGO"),
    "nuget": ("NuGet", "NUGET"),
}

STATUSES = ("approved", "tolerated", "banned")
VERSION_POLICIES = ("any", "exact", "minimum", "same_major")

OSV_URL = "https://api.osv.dev/v1/query"
DEPS_DEV = "https://api.deps.dev/v3"

#: A package younger than this is new: most malicious packages are caught and
#: removed within days, so age is cheap, real evidence.
NEW_PACKAGE_DAYS = 90
#: No release for this long reads as unmaintained (and, in use, abandoned).
UNMAINTAINED_DAYS = 730
#: OpenSSF Scorecard's overall score is 0-10.
LOW_SCORECARD = 4.0
#: More transitive dependencies than this is a heavy library to take on.
HEAVY_TRANSITIVE = 150

#: Popular names a typosquat imitates, beside whatever the estate already
#: uses. Short on purpose: the estate's own inventory is the better list,
#: because it is what a developer meant to type.
POPULAR: dict[str, frozenset[str]] = {
    "npm": frozenset(
        {
            "react", "react-dom", "lodash", "express", "axios", "next", "typescript",
            "chalk", "commander", "debug", "moment", "request", "webpack", "eslint",
            "jquery", "vue", "uuid", "dotenv", "yargs", "colors", "prettier", "jest",
        }
    ),
    "pypi": frozenset(
        {
            "requests", "numpy", "pandas", "django", "flask", "fastapi", "urllib3",
            "setuptools", "boto3", "pyyaml", "cryptography", "sqlalchemy", "pydantic",
            "httpx", "jinja2", "pytest", "certifi", "idna", "six", "python-dateutil",
            "beautifulsoup4", "pillow", "scipy", "matplotlib",
        }
    ),
}


class LibraryError(ValueError):
    """A library request or change the rules refuse. The message says why."""


def normalise(ecosystem: str, name: str) -> str:
    """The name two spellings of one package share.

    PyPI treats `-`, `_` and `.` as the same and ignores case (PEP 503); npm
    names are lower case. Elsewhere the name is kept, lower-cased.
    """
    name = name.strip()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


# -- Versions -------------------------------------------------------------------


def version_key(version: str) -> tuple[int, ...] | None:
    """The numeric parts of a version, or None when it has none.

    Deliberately simple: the policies below compare release numbers, and a
    version with no digits at all (`latest`, a git URL) cannot be judged."""
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:4]) if parts else None


def version_from_spec(spec: str) -> str:
    """The first version in a requirement spec (`^1.2.3`, `>=2.0,<3`)."""
    match = re.search(r"\d+(?:\.\d+)*", spec or "")
    return match.group(0) if match else ""


def version_allowed(policy: str, ref: str, version: str) -> bool:
    """Whether `version` meets the entry's version policy.

    A version that cannot be read fails every policy but `any`: an unreadable
    version is how a check would otherwise be walked around."""
    if policy == "any":
        return True
    candidate, reference = version_key(version), version_key(ref)
    if candidate is None or reference is None:
        return False
    if policy == "exact":
        return candidate == reference
    if policy == "minimum":
        return candidate >= reference
    if policy == "same_major":
        return candidate[0] == reference[0] and candidate >= reference
    return False


# -- Typosquat ------------------------------------------------------------------


def _distance(left: str, right: str) -> int:
    """Edit distance with adjacent transpositions (optimal string alignment)."""
    rows = [[0] * (len(right) + 1) for _ in range(len(left) + 1)]
    for i in range(len(left) + 1):
        rows[i][0] = i
    for j in range(len(right) + 1):
        rows[0][j] = j
    for i in range(1, len(left) + 1):
        for j in range(1, len(right) + 1):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if (
                i > 1
                and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(left)][len(right)]


def typosquat_candidates(ecosystem: str, name: str, known: set[str]) -> list[str]:
    """Known names this one is suspiciously close to, nearest first.

    A name that is itself known is not a typosquat of anything. Otherwise a
    name one edit from a known one, two edits from a known one of five or
    more characters, or equal to one once separators are ignored
    (`python_dateutil` for `python-dateutil` outside PyPI) is suspect.
    """
    target = normalise(ecosystem, name)
    pool = {normalise(ecosystem, k) for k in known} | set(POPULAR.get(ecosystem, ()))
    if target in pool:
        return []
    bare = re.sub(r"[-_.]", "", target)
    hits: list[tuple[int, str]] = []
    for other in pool:
        if abs(len(other) - len(target)) > 2:
            continue
        distance = _distance(target, other)
        if (
            distance == 1
            or (distance == 2 and len(other) >= 5)
            or re.sub(r"[-_.]", "", other) == bare
        ):
            hits.append((distance, other))
    return [other for _, other in sorted(hits)]


# -- Vetting (L1) ---------------------------------------------------------------

#: (method, url, json body) -> (status code, parsed JSON or None). Injected so
#: tests read fixtures and production reads the network; a transport error is
#: status 0, never an exception, so one dead source cannot sink the report.
Fetch = Callable[[str, str, dict[str, Any] | None], Awaitable[tuple[int, Any]]]


async def http_fetch(method: str, url: str, body: dict[str, Any] | None) -> tuple[int, Any]:
    import httpx2

    try:
        async with httpx2.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.request(method, url, json=body)
    except httpx2.HTTPError as exc:
        logger.info("Library vetting could not reach %s: %s", url, exc)
        return 0, None
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=None)


def _package_url(system: str, name: str) -> str:
    return f"{DEPS_DEV}/systems/{system}/packages/{quote(name, safe='')}"


def _check(status: str, source: str, **detail: Any) -> dict[str, Any]:
    return {"status": status, "source": source, **detail}


async def vet(
    ecosystem: str,
    name: str,
    version: str,
    *,
    fetch: Fetch,
    known: set[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """The vetting report for one package version. Never raises on a source
    being down: that check reads `unavailable` and the tier becomes `flagged`.
    """
    now = now or utcnow()
    ecosystem = ecosystem.strip().lower()
    name = name.strip()
    checks: dict[str, dict[str, Any]] = {}
    flags: list[str] = []

    similar = typosquat_candidates(ecosystem, name, known)
    checks["typosquat"] = _check(
        "ok",
        "estate SBOM inventory and the platform's popular-package list",
        suspected=bool(similar),
        similar_to=similar[:5],
    )
    if similar:
        flags.append("typosquat_suspected")

    mapping = ECOSYSTEMS.get(ecosystem)
    if mapping is None:
        for key in ("vulnerabilities", "license", "maintenance", "scorecard",
                    "new_package", "transitive"):
            checks[key] = _check(
                "unsupported", "", detail=f"No registry source for ecosystem '{ecosystem}'."
            )
        flags.append("unsupported_ecosystem")
        return _report(ecosystem, name, version, checks, flags, now)

    osv_ecosystem, system = mapping

    # OSV: known vulnerabilities in this exact version.
    status, body = await fetch(
        "POST", OSV_URL, {"version": version, "package": {"name": name, "ecosystem": osv_ecosystem}}
    )
    if status == 200 and isinstance(body, dict):
        vulns = [v for v in body.get("vulns") or [] if isinstance(v, dict)]
        ids = sorted(str(v.get("id")) for v in vulns if v.get("id"))
        checks["vulnerabilities"] = _check("ok", OSV_URL, count=len(ids), ids=ids[:25])
        if ids:
            flags.append("known_vulnerabilities")
    else:
        checks["vulnerabilities"] = _check("unavailable", OSV_URL, http_status=status)

    # deps.dev: the package's release history.
    package_url = _package_url(system, name)
    status, package = await fetch("GET", package_url, None)
    versions: list[dict[str, Any]] = []
    if status == 200 and isinstance(package, dict):
        versions = [v for v in package.get("versions") or [] if isinstance(v, dict)]
    if status == 404:
        flags.append("not_in_registry")
    published = [
        (when, str((v.get("versionKey") or {}).get("version") or ""), bool(v.get("isDefault")))
        for v in versions
        if (when := _parse_time(v.get("publishedAt"))) is not None
    ]
    if published:
        first = min(p[0] for p in published)
        default = next((p for p in published if p[2]), max(published))
        age = (now - first).days
        since_latest = (now - default[0]).days
        checks["new_package"] = _check(
            "ok", package_url, first_published_at=first.isoformat(), age_days=age,
            new=age < NEW_PACKAGE_DAYS,
        )
        checks["maintenance"] = _check(
            "ok", package_url, latest_version=default[1],
            latest_published_at=default[0].isoformat(), days_since_latest_release=since_latest,
            releases=len(published),
        )
        if age < NEW_PACKAGE_DAYS:
            flags.append("new_package")
        if since_latest > UNMAINTAINED_DAYS:
            flags.append("unmaintained")
        if version not in {p[1] for p in published}:
            flags.append("version_not_found")
    else:
        detail = "not in the registry" if status == 404 else "no release dates read"
        checks["new_package"] = _check("unavailable", package_url, http_status=status,
                                       detail=detail)
        checks["maintenance"] = _check("unavailable", package_url, http_status=status,
                                       detail=detail)

    # deps.dev: this version - license and the source repository.
    version_url = f"{package_url}/versions/{quote(version, safe='')}"
    status, detail_body = await fetch("GET", version_url, None)
    project_id = ""
    if status == 200 and isinstance(detail_body, dict):
        licenses = sorted(str(lic) for lic in detail_body.get("licenses") or [] if lic)
        checks["license"] = _check("ok", version_url, licenses=licenses)
        if not licenses or licenses == ["non-standard"]:
            flags.append("no_license")
        if detail_body.get("isDeprecated"):
            flags.append("deprecated")
        for project in detail_body.get("relatedProjects") or []:
            if isinstance(project, dict) and project.get("relationType") == "SOURCE_REPO":
                project_id = str((project.get("projectKey") or {}).get("id") or "")
                break
    else:
        checks["license"] = _check("unavailable", version_url, http_status=status)

    # OpenSSF Scorecard, through deps.dev's project record.
    if project_id:
        project_url = f"{DEPS_DEV}/projects/{quote(project_id, safe='')}"
        status, project_body = await fetch("GET", project_url, None)
        scorecard = project_body.get("scorecard") if isinstance(project_body, dict) else None
        scored = isinstance(scorecard, dict) and scorecard.get("overallScore") is not None
        if status == 200 and isinstance(scorecard, dict) and scored:
            score = float(scorecard["overallScore"])
            checks["scorecard"] = _check("ok", project_url, score=score, repository=project_id)
            if score < LOW_SCORECARD:
                flags.append("low_scorecard")
        elif status == 200:
            checks["scorecard"] = _check(
                "none", project_url, repository=project_id,
                detail="No Scorecard is published for the source repository.",
            )
        else:
            checks["scorecard"] = _check("unavailable", project_url, http_status=status)
    else:
        checks["scorecard"] = _check(
            "none", version_url, detail="The registry names no source repository to score."
        )

    # deps.dev: the resolved dependency graph of this version.
    graph_url = f"{version_url}:dependencies"
    status, graph = await fetch("GET", graph_url, None)
    if status == 200 and isinstance(graph, dict):
        nodes = [n for n in graph.get("nodes") or [] if isinstance(n, dict)]
        count = sum(1 for n in nodes if n.get("relation") != "SELF")
        checks["transitive"] = _check("ok", graph_url, dependency_count=count)
        if count > HEAVY_TRANSITIVE:
            flags.append("heavy_transitive")
    else:
        checks["transitive"] = _check("unavailable", graph_url, http_status=status)

    return _report(ecosystem, name, version, checks, flags, now)


def _report(
    ecosystem: str,
    name: str,
    version: str,
    checks: dict[str, dict[str, Any]],
    flags: list[str],
    now: datetime,
) -> dict[str, Any]:
    unavailable = sorted(k for k, c in checks.items() if c["status"] in ("unavailable",
                                                                          "unsupported"))
    sources = sorted({str(c["source"]) for c in checks.values() if c.get("source")})
    return {
        "package": {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "purl": f"pkg:{ecosystem}/{name}@{version}",
        },
        "checks": checks,
        "flags": sorted(set(flags)),
        "unavailable": unavailable,
        "sources": sources,
        "vetted_at": now.isoformat(),
    }


def vetting_tier(report: dict[str, Any]) -> str:
    """`flagged` when anything was found or anything could not be read."""
    return "flagged" if report.get("flags") or report.get("unavailable") else "clean"


# -- Approval (L2) --------------------------------------------------------------


def _adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
    """The tier comes from the vetting report, never from the requester.

    Only `ROUTE` builds the context (the generic approvals route refuses a
    duty with a dedicated route), so the report here is the platform's."""
    request = context.get("library_request")
    if not isinstance(request, dict):
        raise ApprovalError(f"A library approval is requested through {ROUTE}.")
    report = dict(request.get("vetting") or {})
    tier = vetting_tier(report)
    package = report.get("package") or {}
    evidence = json.loads(
        json.dumps(
            {
                "title": (
                    f"{request.get('ecosystem')} {request.get('package_name')}"
                    f"@{request.get('version')} ({tier})"
                ),
                "library_request_id": subject_ref,
                "ecosystem": request.get("ecosystem"),
                "package_name": request.get("package_name"),
                "version": request.get("version"),
                "purl": package.get("purl"),
                "reason": request.get("reason"),
                "owner": request.get("owner"),
                "version_policy": request.get("version_policy"),
                "vetting": report,
            },
            default=str,
        )
    )
    return Subject(tier=tier, evidence=evidence)


def _approver(session: Session, request_id: str, verdict: str) -> ApprovalDecision | None:
    return session.execute(
        select(ApprovalDecision)
        .where(ApprovalDecision.request_id == request_id, ApprovalDecision.verdict == verdict)
        .order_by(ApprovalDecision.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def on_approved(session: Session, request: ApprovalRequest) -> None:
    """Put the library on its ecosystem's allowlist, with the policy asked for.

    An existing entry is updated rather than duplicated: approving a library
    that was `tolerated` is exactly how it becomes `approved`. A `banned`
    entry is not overturned here - the route refuses to request one."""
    evidence = dict(request.evidence or {})
    ecosystem = str(evidence.get("ecosystem") or "")
    name = str(evidence.get("package_name") or "")
    decision = _approver(session, request.id, "approve")
    entry = session.execute(
        select(LibraryEntry).where(
            LibraryEntry.ecosystem == ecosystem, LibraryEntry.package_name == name
        )
    ).scalar_one_or_none()
    if entry is None:
        entry = LibraryEntry(ecosystem=ecosystem, package_name=name)
        session.add(entry)
    entry.status = "approved"
    entry.owner = str(evidence.get("owner") or entry.owner or "")
    entry.version_policy = str(evidence.get("version_policy") or "minimum")
    entry.version_ref = str(evidence.get("version") or "")
    entry.source = "approval"
    entry.approval_request_id = request.id
    entry.updated_by = decision.approver if decision else "platform"
    library_request = session.get(LibraryRequest, str(evidence.get("library_request_id") or ""))
    if library_request is not None:
        library_request.state = "approved"
        library_request.decided_by = entry.updated_by
        library_request.decision_reason = decision.rationale if decision else ""
    session.add(
        AuditLogEntry(
            actor=entry.updated_by,
            action="library.approved",
            entity_type="library",
            entity_id=f"{ecosystem}:{name}",
            detail={
                "version_policy": entry.version_policy,
                "version_ref": entry.version_ref,
                "owner": entry.owner,
                "approval_request_id": request.id,
            },
        )
    )


def sync_decisions(session: Session) -> int:
    """Copy rejections and expiries onto the library requests they decided.

    The engine has no rejection hook, and needs none: the decision and its
    rationale are already recorded on its hash chain. This makes the library
    request read complete without a second lookup. Returns how many moved."""
    pending = list(
        session.execute(
            select(LibraryRequest).where(LibraryRequest.state == "pending_approval")
        ).scalars()
    )
    moved = 0
    for row in pending:
        if not row.approval_request_id:
            continue
        approval = session.get(ApprovalRequest, row.approval_request_id)
        if approval is None or approval.state == "pending":
            continue
        if approval.state == "rejected":
            decision = _approver(session, approval.id, "reject")
            row.state = "rejected"
            row.decided_by = decision.approver if decision else ""
            row.decision_reason = decision.rationale if decision else ""
            session.add(
                AuditLogEntry(
                    actor=row.decided_by or "platform",
                    action="library.rejected",
                    entity_type="library",
                    entity_id=f"{row.ecosystem}:{row.package_name}",
                    detail={"reason": row.decision_reason, "approval_request_id": approval.id},
                )
            )
        elif approval.state in ("expired", "approved"):
            # `approved` lands here only if the hook ran in a request that
            # predates the row; the entry itself was written by the hook.
            row.state = approval.state
        else:
            continue
        moved += 1
    return moved


register_adapter(DUTY, _adapter)
register_on_approved(DUTY, on_approved)
register_dedicated_route(DUTY, ROUTE)


# -- Managing the libraries we have (L3) ---------------------------------------


@dataclass(frozen=True)
class InUse:
    """One library as the SBOM inventory has it."""

    ecosystem: str
    package_name: str
    repos: list[str]
    versions: list[str]
    licenses: dict[str, list[str]]


def in_use(catalog: Catalog, *, ecosystem: str | None = None) -> list[InUse]:
    """Every library in `sbom_components`, keyed by (ecosystem, normalised name),
    with the licenses each in-use version declares."""
    if not catalog.all_files("sbom_components"):
        return []
    where, params = "", []
    if ecosystem:
        where, params = "WHERE ecosystem = ?", [ecosystem]
    rows = catalog.query(
        f"""
        SELECT ecosystem, package_name, repo_full_name, package_version, license_ids_json
        FROM sbom_components
        {where}
        """,
        params,
    )
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for eco, name, repo, version, licenses_json in rows:
        eco = str(eco or "unknown")
        key = (eco, normalise(eco, str(name or "")))
        item = merged.setdefault(key, {"repos": set(), "versions": set(), "licenses": {}})
        item["repos"].add(str(repo))
        item["versions"].add(str(version or ""))
        try:
            declared = json.loads(licenses_json) if licenses_json else []
        except (TypeError, ValueError):
            declared = []
        if isinstance(declared, list) and declared:
            item["licenses"].setdefault(str(version or ""), set()).update(str(d) for d in declared)
    return [
        InUse(
            ecosystem=eco,
            package_name=name,
            repos=sorted(item["repos"]),
            versions=sorted(item["versions"]),
            licenses={v: sorted(ls) for v, ls in item["licenses"].items()},
        )
        for (eco, name), item in sorted(merged.items())
    ]


def flags_for(
    library: InUse,
    entry: LibraryEntry | None,
    facts: LibraryFacts | None,
    *,
    now: datetime | None = None,
) -> dict[str, bool | None]:
    """The four flags the story names plus the policy check. `None` means
    the platform holds no data to decide, which is not the same as `False`."""
    now = now or utcnow()
    license_sets = {tuple(ls) for ls in library.licenses.values()}
    license_changed: bool | None = len(license_sets) > 1 if license_sets else None
    eol: bool | None = None
    abandoned: bool | None = None
    if facts is not None and not facts.error:
        deprecated = set(facts.deprecated_versions or [])
        eol = any(v in deprecated for v in library.versions)
        if facts.latest_published_at is not None:
            abandoned = (now - facts.latest_published_at) > timedelta(days=UNMAINTAINED_DAYS)
        latest = set(facts.latest_licenses or [])
        if latest and license_sets:
            in_use_licenses = {lic for ls in license_sets for lic in ls}
            license_changed = bool(license_changed) or not latest <= in_use_licenses
    policy_violation: bool | None = None
    if entry is not None and entry.status != "banned":
        policy_violation = not all(
            version_allowed(entry.version_policy, entry.version_ref, v)
            for v in library.versions
        )
    return {
        "divergent": len(library.versions) > 1,
        "eol": eol,
        "abandoned": abandoned,
        "license_changed": license_changed,
        "version_policy_violation": policy_violation,
        "banned_in_use": entry is not None and entry.status == "banned",
    }


def entries(session: Session) -> dict[tuple[str, str], LibraryEntry]:
    return {
        (e.ecosystem, e.package_name): e for e in session.execute(select(LibraryEntry)).scalars()
    }


def all_facts(session: Session) -> dict[tuple[str, str], LibraryFacts]:
    return {
        (f.ecosystem, f.package_name): f for f in session.execute(select(LibraryFacts)).scalars()
    }


def managed(
    session: Session, catalog: Catalog, *, ecosystem: str | None = None
) -> list[dict[str, Any]]:
    """Every library in use, each with a status, an owner, a policy and flags."""
    recorded = entries(session)
    facts = all_facts(session)
    now = utcnow()
    out: list[dict[str, Any]] = []
    for library in in_use(catalog, ecosystem=ecosystem):
        key = (library.ecosystem, library.package_name)
        entry = recorded.get(key)
        out.append(
            {
                "ecosystem": library.ecosystem,
                "package_name": library.package_name,
                "repos": library.repos,
                "versions": library.versions,
                "status": entry.status if entry else "tolerated",
                "status_source": entry.source if entry else "default",
                "owner": entry.owner if entry else "",
                "version_policy": entry.version_policy if entry else "any",
                "version_ref": entry.version_ref if entry else "",
                "flags": flags_for(library, entry, facts.get(key), now=now),
                "facts_read_at": facts[key].fetched_at if key in facts else None,
            }
        )
    return out


def set_entry(
    session: Session,
    *,
    ecosystem: str,
    package_name: str,
    actor: str,
    status: str | None = None,
    owner: str | None = None,
    version_policy: str | None = None,
    version_ref: str | None = None,
    note: str | None = None,
) -> LibraryEntry:
    """Record a library's status, owner or version policy directly.

    `approved` is refused: it is what an approved `library_approval` request
    writes, and setting it by hand would skip the vetting and the approver."""
    ecosystem = ecosystem.strip().lower()
    name = normalise(ecosystem, package_name)
    if status is not None and status not in ("tolerated", "banned"):
        raise LibraryError(
            "A library becomes approved through a vetted request "
            f"(POST {ROUTE}); a direct change may set tolerated or banned."
        )
    if version_policy is not None and version_policy not in VERSION_POLICIES:
        raise LibraryError(f"version_policy must be one of {', '.join(VERSION_POLICIES)}.")
    entry = session.execute(
        select(LibraryEntry).where(
            LibraryEntry.ecosystem == ecosystem, LibraryEntry.package_name == name
        )
    ).scalar_one_or_none()
    before = (
        {"status": entry.status, "owner": entry.owner, "version_policy": entry.version_policy}
        if entry
        else None
    )
    if entry is None:
        entry = LibraryEntry(ecosystem=ecosystem, package_name=name, status="tolerated")
        session.add(entry)
    if status is not None:
        entry.status = status
        entry.source = "manual"
    if owner is not None:
        entry.owner = owner.strip()
    if version_policy is not None:
        entry.version_policy = version_policy
    if version_ref is not None:
        entry.version_ref = version_ref.strip()
    if note is not None:
        entry.note = note
    entry.updated_by = actor
    session.add(
        AuditLogEntry(
            actor=actor,
            action="library.updated",
            entity_type="library",
            entity_id=f"{ecosystem}:{name}",
            detail={
                "before": before,
                "status": entry.status,
                "owner": entry.owner,
                "version_policy": entry.version_policy,
                "version_ref": entry.version_ref,
            },
        )
    )
    session.flush()
    return entry


def baseline(session: Session, catalog: Catalog, *, actor: str) -> list[str]:
    """Record every in-use library nobody has recorded as `tolerated`.

    What turns the default status into a recorded one, so a repository's
    coverage can be shown before its PR check blocks. Never touches an
    existing entry. Returns the `ecosystem:name` keys it recorded."""
    recorded = entries(session)
    added: list[str] = []
    for library in in_use(catalog):
        key = (library.ecosystem, library.package_name)
        if key in recorded:
            continue
        session.add(
            LibraryEntry(
                ecosystem=library.ecosystem,
                package_name=library.package_name,
                status="tolerated",
                source="baseline",
                updated_by=actor,
            )
        )
        added.append(f"{library.ecosystem}:{library.package_name}")
    if added:
        session.add(
            AuditLogEntry(
                actor=actor,
                action="library.baseline",
                entity_type="library",
                entity_id="*",
                detail={"recorded": len(added)},
            )
        )
    return added


async def read_facts(ecosystem: str, name: str, *, fetch: Fetch) -> dict[str, Any]:
    """What deps.dev says about a package now: latest release, its licenses,
    and the versions it marks deprecated. `error` is set when it could not."""
    mapping = ECOSYSTEMS.get(ecosystem)
    if mapping is None:
        return {"error": f"No registry source for ecosystem '{ecosystem}'."}
    url = _package_url(mapping[1], name)
    status, body = await fetch("GET", url, None)
    if status != 200 or not isinstance(body, dict):
        return {"error": f"{url} answered {status}."}
    versions = [v for v in body.get("versions") or [] if isinstance(v, dict)]
    dated = [
        (when, str((v.get("versionKey") or {}).get("version") or ""), bool(v.get("isDefault")))
        for v in versions
        if (when := _parse_time(v.get("publishedAt"))) is not None
    ]
    deprecated = sorted(
        str((v.get("versionKey") or {}).get("version") or "")
        for v in versions
        if v.get("isDeprecated")
    )
    if not dated:
        return {"error": f"{url} lists no dated release.", "deprecated_versions": deprecated}
    latest = next((d for d in dated if d[2]), max(dated))
    licenses: list[str] = []
    status, detail = await fetch("GET", f"{url}/versions/{quote(latest[1], safe='')}", None)
    if status == 200 and isinstance(detail, dict):
        licenses = sorted(str(lic) for lic in detail.get("licenses") or [] if lic)
    return {
        "latest_version": latest[1],
        "latest_published_at": latest[0],
        "latest_licenses": licenses,
        "deprecated_versions": deprecated,
        "error": "",
    }


async def refresh_facts(
    db: Any, catalog: Catalog, *, fetch: Fetch, limit: int = 200
) -> dict[str, int]:
    """Read registry facts for in-use libraries, oldest read first."""
    libraries = in_use(catalog)
    with db.session() as session:
        read_at = {key: f.fetched_at for key, f in all_facts(session).items()}
    libraries.sort(key=lambda lib: read_at.get((lib.ecosystem, lib.package_name), datetime.min))
    read = failed = 0
    for library in libraries[:limit]:
        facts = await read_facts(library.ecosystem, library.package_name, fetch=fetch)
        with db.session() as session:
            row = session.execute(
                select(LibraryFacts).where(
                    LibraryFacts.ecosystem == library.ecosystem,
                    LibraryFacts.package_name == library.package_name,
                )
            ).scalar_one_or_none()
            if row is None:
                row = LibraryFacts(ecosystem=library.ecosystem, package_name=library.package_name)
                session.add(row)
            row.error = str(facts.get("error") or "")
            if not row.error:
                row.latest_version = str(facts.get("latest_version") or "")
                row.latest_published_at = facts.get("latest_published_at")
                row.latest_licenses = list(facts.get("latest_licenses") or [])
            row.deprecated_versions = list(facts.get("deprecated_versions") or [])
            row.fetched_at = utcnow()
        if facts.get("error"):
            failed += 1
        else:
            read += 1
    return {"read": read, "failed": failed, "libraries": len(libraries)}


def known_names(catalog: Catalog, ecosystem: str) -> set[str]:
    """The estate's in-use names in one ecosystem: the typosquat reference."""
    return {lib.package_name for lib in in_use(catalog, ecosystem=ecosystem)}
