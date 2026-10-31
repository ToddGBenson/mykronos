"""The weekly intelligence briefing, one Monday page per application
(TheHub #60865, B7 of epic #60858).

The daily briefing (`daily_briefing`) answers "what changed since yesterday
and is it work". This one answers the slower question a Monday asks: *what
does the outside world know this week that matters to what we ship?* For each
application:

- **Advisories** matched to what it ships: open SCA and container findings
  that name an advisory, ranked by exploitation (CISA KEV, EPSS), the severity
  re-read for this environment (`EnvironmentalScore`), and reachability where
  it was analysed (`ReachabilityReport`).
- **End of life**: images built on an end-of-life base OS (Trivy's
  `base_os_eol`).
- **Malicious packages**: OSV `MAL-` advisories matched to a dependency.
- **Threats fitted to the threat model**: advisories that land in a surface
  the repository declared (`surface_match`), with that surface's exposure.
- **External exposure**: what MyKronos's own anonymous probes saw at each
  registered public URL, and secrets found in the code.
- **Vendor changes** and **standards**: no feed is connected for either, and
  the page says so rather than leaving them out.

**Every item cites its source, and says so-what, action and confidence.** A
source is the advisory's public page or the MyKronos page holding the record.
`confidence` is `observed` (the record is a direct reading: a resolved
version, an image scan, a probe) or `inferred` (a declared version floor, a
match by name); `confidence_reason` names which, because a label a function
chose is a claim and the reason is what makes it checkable.

**A section that could not be read says so.** `None` inputs make the section
`unavailable` with the reason; a feed that does not exist is `not_available`.
Neither is an empty `ok` section, which reads as "all clear" (#401).

**Flash.** An item is `flash` only when it matches something shipped - seen
by a scan of the default branch - and is either known exploited (KEV) or
critical, here or as the scanner reported it. `briefing_flash` DMs those the
same day; everything else waits for Monday.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Literal

from mykronos import atlas_source, surface_match
from mykronos.threat_intel import extract_cve

Status = Literal["ok", "partial", "unavailable", "not_available"]
Confidence = Literal["observed", "inferred"]

#: Capabilities whose findings are advisories against a shipped component.
ADVISORY_CAPABILITIES = ("atlas", "containers")

#: Items per section on the page. The counts in `data` are complete.
MAX_ITEMS = 25

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0}

#: The feeds this page names as not connected. Named so the page can say
#: exactly what it is not reading.
VENDORS = (
    "model deprecations and aliases",
    "GitHub",
    "Cloudflare",
    "Concourse",
    "Next.js",
    "FastAPI",
)


@dataclass
class Item:
    what: str
    #: Why it matters to this application specifically.
    so_what: str
    action: str
    confidence: Confidence
    confidence_reason: str
    #: A public URL or a MyKronos page path. Never empty.
    source: str
    severity: str = ""
    #: First seen in the page's week.
    new_this_week: bool = False
    flash: bool = False
    flash_reason: str = ""
    #: Stable identity, so a flash is sent once per (application, key).
    key: str = ""


@dataclass
class Section:
    key: str
    title: str
    status: Status
    #: The store(s) the section reads.
    source: str
    as_of: datetime | None
    reason: str = ""
    items: list[Item] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class WeeklyPage:
    repo_full_name: str
    repo_id: str
    #: The Monday the page's week starts on, in the briefing's time zone.
    week_of: date
    generated_at: datetime
    sections: list[Section] = field(default_factory=list)

    def items(self) -> Iterable[Item]:
        for section in self.sections:
            yield from section.items

    def flashes(self) -> list[Item]:
        return [i for i in self.items() if i.flash]


@dataclass
class Inputs:
    """What `build` reads. `None` = could not be read."""

    repo_full_name: str
    repo_id: str
    #: Open findings: finding_id, capability, rule_id, title, severity,
    #: package_name, package_version, version_basis, file_path,
    #: raw_finding_json, first_seen_at, and `shipped` (seen by a scan of the
    #: default branch).
    findings: list[dict[str, Any]] | None = field(default_factory=list)
    #: CVE -> in_kev, kev_added_at, epss_score, epss_percentile.
    intel: dict[str, dict[str, Any]] | None = field(default_factory=dict)
    #: finding_id -> effective_severity.
    environmental: dict[str, str] | None = field(default_factory=dict)
    #: Repository paths nothing imports; None when never analysed.
    orphaned: set[str] | None = None
    #: Declared surfaces: id, kind, name, exposure, selectors.
    surfaces: list[dict[str, Any]] | None = field(default_factory=list)
    #: Registered public URLs: url, last_status, last_probed_at, last_detail.
    endpoints: list[dict[str, Any]] | None = field(default_factory=list)


def monday_of(local_day: date) -> date:
    return local_day - timedelta(days=local_day.weekday())


def _raw(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_finding_json")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def advisory_id(row: dict[str, Any]) -> str | None:
    """The advisory a finding is about: a CVE where one is named, else the
    tool's id when it is an advisory id (GHSA-, OSV's MAL-, PYSEC-...)."""
    cve = extract_cve(row.get("rule_id"), row.get("title"))
    if cve:
        return cve
    rule = str(row.get("rule_id") or "").strip()
    if "-" in rule and rule.split("-", 1)[0].isalpha() and rule.split("-", 1)[0].isupper():
        return rule
    return None


def advisory_url(advisory: str) -> str:
    if advisory.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{advisory}"
    if advisory.startswith("GHSA-"):
        return f"https://github.com/advisories/{advisory}"
    return f"https://osv.dev/vulnerability/{advisory}"


def finding_page(repo_id: str, finding_id: str) -> str:
    return f"/repos/{repo_id}/findings/{finding_id}"


def _component(row: dict[str, Any]) -> str:
    raw = _raw(row)
    package = str(row.get("package_name") or "").strip()
    version = str(row.get("package_version") or "").strip()
    name = f"{package}@{version}" if package and version else package or str(row.get("title") or "")
    image = raw.get("image")
    if row.get("capability") == "containers" and isinstance(image, str) and image:
        return f"{name} in image {image.split('@', 1)[0]}"
    path = str(row.get("file_path") or "")
    return f"{name} ({path})" if path else name


def _confidence(row: dict[str, Any]) -> tuple[Confidence, str]:
    basis = str(row.get("version_basis") or "")
    if row.get("capability") == "containers":
        return "observed", "read from a scan of the built image"
    if _raw(row).get("source_kind") == "sbom_document":
        # Ahead of `resolved`, deliberately. A committed SBOM document is
        # supplied to the lane as the record of what is installed, so a
        # finding read out of it is "resolved" against itself -- TheHub's
        # three pypdf highs were, from a document 7 days older than the scan
        # and older than the manifest (TheHub #60921).
        return (
            "inferred",
            "the version is read from a committed SBOM document, which may not "
            "describe what runs",
        )
    if basis == "resolved":
        return "observed", "the version is the one the lockfile resolves"
    if basis in ("declared_floor", "declared_pin"):
        return "inferred", f"the version is a {basis.replace('_', ' ')}, not what runs"
    return "inferred", "the scanner did not say whether the version is the one that runs"


def _severity_here(row: dict[str, Any], environmental: dict[str, str]) -> str:
    return environmental.get(str(row.get("finding_id")), "") or str(row.get("severity") or "")


def _is_new(row: dict[str, Any], since: datetime) -> bool:
    seen = row.get("first_seen_at")
    if isinstance(seen, datetime):
        naive = seen.replace(tzinfo=None) if seen.tzinfo else seen
        return naive >= since
    return False


def _flash(row: dict[str, Any], intel: dict[str, Any], here: str) -> tuple[bool, str]:
    """Exploited or critical, and shipped. Nothing else is a flash."""
    if not row.get("shipped"):
        return False, ""
    if intel.get("in_kev"):
        return True, "known exploited (CISA KEV) and shipped"
    if "critical" in (here, str(row.get("severity") or "")):
        return True, "critical and shipped"
    return False, ""


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------


def _unavailable(key: str, title: str, source: str, what: str) -> Section:
    return Section(key, title, "unavailable", source, None, reason=f"{what} could not be read.")


def _advisories(inputs: Inputs, since: datetime, now: datetime) -> Section:
    title, source = "Advisories matched to what we ship", "lake findings, threat_intel_matches"
    if inputs.findings is None:
        return _unavailable("advisories", title, source, "Findings")
    intel = inputs.intel or {}
    environmental = inputs.environmental or {}
    orphaned = inputs.orphaned
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    unreachable = 0
    for row in inputs.findings:
        if row.get("capability") not in ADVISORY_CAPABILITIES:
            continue
        advisory = advisory_id(row)
        if advisory is None or advisory.startswith("MAL-"):
            continue
        path = str(row.get("file_path") or "")
        if orphaned and path in orphaned:
            unreachable += 1
            continue
        groups.setdefault((advisory, str(row.get("package_name") or "")), []).append(row)

    scored: list[tuple[tuple[Any, ...], Item]] = []
    exploited = 0
    for (advisory, package), rows in groups.items():
        rows.sort(key=lambda r: (not r.get("shipped"), str(r.get("finding_id"))))
        row = rows[0]
        facts = intel.get(advisory, {}) if advisory.startswith("CVE-") else {}
        here = _severity_here(row, environmental)
        scanner = str(row.get("severity") or "")
        flash, flash_reason = _flash(row, facts, here)
        confidence, reason = _confidence(row)
        parts = []
        if facts.get("in_kev"):
            exploited += 1
            added = facts.get("kev_added_at")
            parts.append(f"Known exploited (CISA KEV{f' since {added}' if added else ''}).")
        epss = facts.get("epss_score")
        if isinstance(epss, int | float):
            parts.append(f"EPSS {epss:.1%} chance of exploitation in 30 days.")
        if here and here != scanner:
            parts.append(f"{here.capitalize()} here (scanner: {scanner}).")
        elif scanner:
            parts.append(f"{scanner.capitalize()}.")
        parts.append(
            "Shipped: seen on the default branch."
            if row.get("shipped")
            else "Only seen on a branch that is not the default."
        )
        if len(rows) > 1:
            parts.append(f"{len(rows)} findings.")
        if orphaned is None and row.get("capability") == "atlas":
            parts.append("Reachability not analysed.")
        # Said on the line, not left to the file name: a committed SBOM
        # document can be days older than the manifest (TheHub #60921).
        origin = atlas_source.note_for(_raw(row))
        if origin:
            parts.append(origin)
        fixed = str(_raw(row).get("fixed_version") or "").strip()
        action = (
            f"Upgrade {package or 'the component'} to {fixed} or later."
            if fixed
            else "No fix is published: accept with `no_vendor_fix` and a review date, "
            "or replace the component."
        )
        item = Item(
            what=f"{advisory} in {_component(row)}",
            so_what=" ".join(parts),
            action=action,
            confidence=confidence,
            confidence_reason=reason,
            source=advisory_url(advisory),
            severity=here or scanner,
            new_this_week=any(_is_new(r, since) for r in rows),
            flash=flash,
            flash_reason=flash_reason,
            key=f"advisory:{advisory}:{package}",
        )
        rank = (
            not facts.get("in_kev"),
            -_SEVERITY_RANK.get(here or scanner, 0),
            -(epss if isinstance(epss, int | float) else 0.0),
            advisory,
        )
        scored.append((rank, item))
    scored.sort(key=lambda pair: pair[0])
    items = [item for _, item in scored]
    status: Status = "ok" if inputs.intel is not None else "partial"
    reason = "" if inputs.intel is not None else "KEV and EPSS could not be read."
    return Section(
        "advisories",
        title,
        status,
        source,
        now,
        reason=reason,
        items=items[:MAX_ITEMS],
        data={
            "advisories": len(items),
            "known_exploited": exploited,
            "flash": sum(1 for i in items if i.flash),
            "new_this_week": sum(1 for i in items if i.new_this_week),
            "set_aside_unreachable": unreachable,
            "reachability_analysed": orphaned is not None,
        },
    )


def _end_of_life(inputs: Inputs, since: datetime, now: datetime) -> Section:
    title, source = "End-of-life runtimes and images", "lake findings (Trivy base_os_eol)"
    if inputs.findings is None:
        return _unavailable("end_of_life", title, source, "Findings")
    images: dict[str, dict[str, Any]] = {}
    for row in inputs.findings:
        raw = _raw(row)
        if row.get("capability") != "containers" or not raw.get("base_os_eol"):
            continue
        image = str(raw.get("image") or "").split("@", 1)[0] or "an image"
        entry = images.setdefault(
            image,
            {"base": str(raw.get("base_os") or "its base OS"), "count": 0, "row": row,
             "new": False, "shipped": False},
        )
        entry["count"] += 1
        entry["new"] = entry["new"] or _is_new(row, since)
        entry["shipped"] = entry["shipped"] or bool(row.get("shipped"))
    items = [
        Item(
            what=f"{image} is built on {entry['base']}, which is end-of-life",
            so_what=(
                f"{entry['count']} OS package finding(s) in it will never get a vendor fix"
                + (" and it ships from the default branch." if entry["shipped"] else ".")
            ),
            action="Rebuild on a supported base image (usually the next major tag upstream).",
            confidence="observed",
            confidence_reason="Trivy read the base OS release from the image itself",
            source=finding_page(inputs.repo_id, str(entry["row"].get("finding_id"))),
            severity="high",
            new_this_week=entry["new"],
            key=f"eol:{image}",
        )
        for image, entry in sorted(images.items())
    ]
    return Section(
        "end_of_life",
        title,
        "partial",
        source,
        now,
        reason=(
            "Base images are read from Trivy; language runtimes (Python, Node) are not "
            "measured yet."
        ),
        items=items[:MAX_ITEMS],
        data={"images": len(items)},
    )


def _malicious(inputs: Inputs, since: datetime, now: datetime) -> Section:
    title = "Malicious packages and maintainer takeovers"
    source = "lake findings (OSV MAL- advisories)"
    if inputs.findings is None:
        return _unavailable("malicious_packages", title, source, "Findings")
    environmental = inputs.environmental or {}
    items = []
    for row in inputs.findings:
        advisory = advisory_id(row)
        if advisory is None or not advisory.startswith("MAL-"):
            continue
        here = _severity_here(row, environmental)
        flash, flash_reason = _flash(row, {}, here)
        confidence, reason = _confidence(row)
        items.append(
            Item(
                what=f"{advisory}: malicious package {_component(row)}",
                so_what=(
                    "A package reported as malicious is in the dependency tree"
                    + (" of what ships." if row.get("shipped") else " of a branch.")
                ),
                action=(
                    "Remove it, rotate any credential the build or runtime could reach, "
                    "and check the lockfile history for when it arrived."
                ),
                confidence=confidence,
                confidence_reason=reason,
                source=advisory_url(advisory),
                severity=here or "critical",
                new_this_week=_is_new(row, since),
                flash=flash,
                flash_reason=flash_reason,
                key=f"malicious:{advisory}:{row.get('package_name') or ''}",
            )
        )
    return Section(
        "malicious_packages",
        title,
        "partial",
        source,
        now,
        reason="OSV malicious-package advisories are matched; maintainer-takeover reports "
        "have no feed connected.",
        items=items[:MAX_ITEMS],
        data={"malicious": len(items)},
    )


def _threat_model(inputs: Inputs, since: datetime, now: datetime) -> Section:
    title = "Threats fitted to our threat model"
    source = "declared surfaces (.sdlc/threat-model.yaml), lake findings"
    if inputs.findings is None or inputs.surfaces is None:
        return _unavailable(
            "threat_model", title, source, "Findings or the declared surfaces"
        )
    if not inputs.surfaces:
        return Section(
            "threat_model",
            title,
            "not_available",
            source,
            now,
            reason=(
                "This application declares no threat model, so nothing can be fitted "
                "to it. GET /repos/{id}/threat-model/draft drafts one (TheHub #60899)."
            ),
        )
    surfaces = [
        SimpleNamespace(
            id=s["id"], kind=s["kind"], name=s["name"], selectors=s.get("selectors") or {},
            exposure=s.get("exposure") or "unknown",
        )
        for s in inputs.surfaces
    ]
    intel = inputs.intel or {}
    environmental = inputs.environmental or {}
    items: list[tuple[tuple[Any, ...], Item]] = []
    #: Every advisory that lands in a declared surface, whatever its
    #: severity or exploitation. Which of them are listed depends on KEV and
    #: the re-score, so an item leaving the list is not a fix; leaving this
    #: set is (review of #1027).
    open_keys: set[str] = set()
    for row in inputs.findings:
        advisory = advisory_id(row)
        if advisory is None:
            continue
        found = surface_match.matches(row, surfaces)
        if not found:
            continue
        surface = found[0].surface
        open_keys.add(f"fit:{advisory}:{surface.id}")
        here = _severity_here(row, environmental)
        facts = intel.get(advisory, {})
        if not (facts.get("in_kev") or _SEVERITY_RANK.get(here, 0) >= 3):
            continue
        flash, flash_reason = _flash(row, facts, here)
        confidence, reason = _confidence(row)
        items.append(
            (
                (surface.exposure != "internet", -_SEVERITY_RANK.get(here, 0), advisory),
                Item(
                    what=f"{advisory} lands in {surface.name} ({surface.kind.replace('_', ' ')})",
                    so_what=(
                        f"The threat model declares {surface.name} as {surface.exposure}"
                        + ("; it is known exploited." if facts.get("in_kev") else ".")
                    ),
                    action=(
                        "Fix this before other advisories of its severity: it sits in a "
                        f"surface declared {surface.exposure}."
                    ),
                    confidence=confidence,
                    confidence_reason=f"{reason}; placed by the surface's selectors",
                    source=finding_page(inputs.repo_id, str(row.get("finding_id"))),
                    severity=here,
                    new_this_week=_is_new(row, since),
                    flash=flash,
                    flash_reason=flash_reason,
                    key=f"fit:{advisory}:{surface.id}",
                ),
            )
        )
    items.sort(key=lambda pair: pair[0])
    # A known-exploited medium is fitted only when KEV can be read.
    status: Status = "ok" if inputs.intel is not None else "partial"
    reason = "" if inputs.intel is not None else (
        "KEV could not be read, so known-exploited advisories below high are not fitted."
    )
    return Section(
        "threat_model",
        title,
        status,
        source,
        now,
        reason=reason,
        items=[i for _, i in items][:MAX_ITEMS],
        data={
            "fitted": len(items),
            "surfaces": len(surfaces),
            "open_keys": sorted(open_keys),
        },
    )


_EXPOSURE_SO_WHAT = {
    "open": "Anyone on the internet can read it without a credential.",
    "gated": "It answers, and asks for a credential first.",
    "unreachable": "It did not answer the probe.",
    "not_probed": "It has not been probed yet.",
}


def _exposure(inputs: Inputs, since: datetime, now: datetime) -> Section:
    title = "External exposure"
    source = "public_endpoints (anonymous probes), lake findings (secrets)"
    if inputs.endpoints is None and inputs.findings is None:
        return _unavailable("external_exposure", title, source, "Endpoints and findings")
    items: list[Item] = []
    for row in inputs.endpoints or []:
        probe = str(row.get("last_status") or "not_probed")
        probed = row.get("last_probed_at")
        items.append(
            Item(
                what=f"{row.get('url')}: {probe}",
                so_what=_EXPOSURE_SO_WHAT.get(probe, f"The last probe said {probe}."),
                action=(
                    "Confirm it is meant to be public without a gate."
                    if probe == "open"
                    else "Nothing, unless this should not answer from the internet."
                ),
                confidence="observed" if probed else "inferred",
                confidence_reason=(
                    f"an anonymous GET from outside on {probed:%Y-%m-%d}"
                    if isinstance(probed, datetime)
                    else "declared public; never probed"
                ),
                source=str(row.get("url") or ""),
                severity="medium" if probe == "open" else "info",
                key=f"exposure:{row.get('url')}",
            )
        )
    secrets = [r for r in inputs.findings or [] if r.get("capability") == "secrets"]
    if secrets:
        first = sorted(secrets, key=lambda r: str(r.get("finding_id")))[0]
        items.append(
            Item(
                what=f"{len(secrets)} open secret finding(s) in the code",
                so_what="A secret in a repository is readable by everyone who can read it, "
                "and by its history after it is removed.",
                action="Rotate each credential, then remove it; removing alone is not enough.",
                confidence="inferred",
                confidence_reason="a pattern match in the code; not checked against the service",
                source=finding_page(inputs.repo_id, str(first.get("finding_id"))),
                severity="high",
                new_this_week=any(_is_new(r, since) for r in secrets),
                key="exposure:secrets",
            )
        )
    status: Status = "partial"
    reason = (
        "Shodan/Censys, certificate transparency and DNS have no connector yet; this "
        "reads MyKronos's own anonymous probes and secret findings."
    )
    if inputs.endpoints is None:
        reason = "Registered public endpoints could not be read. " + reason
    return Section(
        "external_exposure", title, status, source, now, reason=reason,
        items=items[:MAX_ITEMS],
        data={"endpoints": len(inputs.endpoints or []), "secrets": len(secrets)},
    )


def _not_connected(key: str, title: str, what: str, now: datetime) -> Section:
    return Section(key, title, "not_available", "none", None, reason=what)


def build(inputs: Inputs, *, now: datetime, local_today: date) -> WeeklyPage:
    """One application's Monday page. Pure: every input is in `inputs`."""
    week_of = monday_of(local_today)
    # The week starts at local Monday midnight; first-seen times in the lake
    # are naive UTC, so a few hours' skew at the edge is accepted.
    since = datetime.combine(week_of, datetime.min.time())
    sections = [
        _advisories(inputs, since, now),
        _threat_model(inputs, since, now),
        _end_of_life(inputs, since, now),
        _malicious(inputs, since, now),
        _exposure(inputs, since, now),
        _not_connected(
            "vendor_changes",
            "Vendor changes",
            "No vendor change feed is connected (" + ", ".join(VENDORS) + ").",
            now,
        ),
        _not_connected(
            "standards", "Standards", "No standards feed is connected.", now
        ),
    ]
    return WeeklyPage(
        repo_full_name=inputs.repo_full_name,
        repo_id=inputs.repo_id,
        week_of=week_of,
        generated_at=now,
        sections=sections,
    )


# --------------------------------------------------------------------------
# Gathering
# --------------------------------------------------------------------------

_COLUMNS = (
    "finding_id",
    "capability",
    "rule_id",
    "title",
    "severity",
    "package_name",
    "package_version",
    "version_basis",
    "file_path",
    "raw_finding_json",
    "first_seen_at",
)


def read_findings(
    catalog: Any, repo_full_name: str, default_branch: str
) -> list[dict[str, Any]] | None:
    """Open findings, each marked `shipped` when the scan that last saw it
    was of the default branch (not a pull request)."""
    try:
        if not catalog.all_files("findings"):
            return []
        has_runs = bool(catalog.all_files("scan_runs"))
        columns = ", ".join(f"f.{c}" for c in _COLUMNS)
        if has_runs:
            rows = catalog.query(
                f"SELECT {columns}, (s.branch = ? AND s.pr_number IS NULL) AS shipped "
                "FROM findings f LEFT JOIN scan_runs s "
                "ON s.scan_run_id = f.last_seen_scan_run_id "
                "WHERE f.asset_id = ? AND f.status = 'open'",
                [default_branch, repo_full_name],
            )
        else:
            rows = [
                (*row, False)
                for row in catalog.query(
                    f"SELECT {columns} FROM findings f "
                    "WHERE f.asset_id = ? AND f.status = 'open'",
                    [repo_full_name],
                )
            ]
    except Exception:  # noqa: BLE001 - an unreadable lake is `None`, never an empty list
        return None
    out = []
    for row in rows:
        record = dict(zip((*_COLUMNS, "shipped"), row, strict=True))
        record["shipped"] = bool(record["shipped"])
        out.append(record)
    return out


def gather(
    db: Any, catalog: Any, repo_id: str, repo_full_name: str, default_branch: str
) -> Inputs:
    """Read every input for one application. A store that fails is `None`."""
    from sqlalchemy import select

    from mykronos.db.models import (
        EnvironmentalScore,
        PublicEndpoint,
        ReachabilityReport,
        RepoSurface,
        ThreatIntelMatch,
    )

    findings = read_findings(catalog, repo_full_name, default_branch)
    cves = {
        cve
        for row in findings or []
        if (cve := extract_cve(row.get("rule_id"), row.get("title")))
    }
    intel: dict[str, dict[str, Any]] | None
    environmental: dict[str, str] | None
    surfaces: list[dict[str, Any]] | None
    endpoints: list[dict[str, Any]] | None
    orphaned: set[str] | None = None
    try:
        with db.session() as session:
            intel = {
                row.cve_id: {
                    "in_kev": bool(row.in_kev),
                    "kev_added_at": row.kev_added_at,
                    "epss_score": row.epss_score,
                    "epss_percentile": row.epss_percentile,
                }
                for row in session.scalars(
                    select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(sorted(cves)))
                )
            } if cves else {}
    except Exception:  # noqa: BLE001
        intel = None
    try:
        with db.session() as session:
            environmental = {
                row.finding_id: row.effective_severity
                for row in session.scalars(
                    select(EnvironmentalScore).where(
                        EnvironmentalScore.repo_full_name == repo_full_name
                    )
                )
                if row.effective_severity
            }
    except Exception:  # noqa: BLE001
        environmental = None
    try:
        with db.session() as session:
            report = session.scalars(
                select(ReachabilityReport).where(
                    ReachabilityReport.repo_onboarding_id == repo_id
                )
            ).first()
            if report is not None:
                orphaned = set(report.orphaned_paths or [])
    except Exception:  # noqa: BLE001
        orphaned = None
    try:
        with db.session() as session:
            surfaces = [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "name": row.name,
                    "exposure": row.exposure,
                    "selectors": row.selectors or {},
                }
                for row in session.scalars(
                    select(RepoSurface).where(RepoSurface.repo_full_name == repo_full_name)
                )
            ]
    except Exception:  # noqa: BLE001
        surfaces = None
    try:
        with db.session() as session:
            endpoints = [
                {
                    "url": row.url,
                    "last_status": row.last_status,
                    "last_probed_at": row.last_probed_at,
                }
                for row in session.scalars(
                    select(PublicEndpoint).where(PublicEndpoint.repo_full_name == repo_full_name)
                )
            ]
    except Exception:  # noqa: BLE001
        endpoints = None
    return Inputs(
        repo_full_name=repo_full_name,
        repo_id=repo_id,
        findings=findings,
        intel=intel,
        environmental=environmental,
        orphaned=orphaned,
        surfaces=surfaces,
        endpoints=endpoints,
    )
