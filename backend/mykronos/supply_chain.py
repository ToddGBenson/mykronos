"""Which packages are vulnerable, and which of them you can actually do
something about.

The Supply chain tab reported a trust score, advisory counts by severity, and
an SBOM you could download. It never named a package. "You have 234 container
advisories" is a fact nobody can act on; "libc6 has 23 and none of them have a
published fix, while setuptools has 2 and both are fixed in 78.1.1" is two
different decisions.

**The join is the point.** The inventory lives in `sbom_components` and the
advisories live in `findings`, and neither table alone answers the question. A
component row says a package is present; a finding says an advisory exists.
Only together do they say whether the thing you are being asked to worry about
is direct or transitive, and whether there is a version to move to.

`fixed_version` is read out of the scanner's own output rather than assumed —
the same parse `guidance` uses, for the same reason. On 2026-09-01 the standing
advice for this class was "rebuild on a current base image", and Trivy had been
reporting no published fix for 231 of 234 findings the whole time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from mykronos.lake.catalog import Catalog

#: Worst first. Matches the ordering every other surface here uses.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Capabilities that report a vulnerability against a *package* rather than a
#: line of code. `atlas` is the dependency tree; `containers` is the image.
#: Both name a package and a version, and a reader does not care which scanner
#: found it — they care what to upgrade.
PACKAGE_CAPABILITIES = ("atlas", "containers")

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_FIXED = re.compile(r"Fixed Version:\s*(\S+)")


@dataclass
class VulnerablePackage:
    package_name: str
    ecosystem: str
    #: What is installed. Several versions of one package can be present in a
    #: tree; this is the one the advisories were reported against.
    installed_version: str
    advisories: int
    worst_severity: str
    #: Empty when no patched version has been published — which is the common
    #: case for OS packages and the single most decision-changing fact here.
    fixed_version: str
    #: `None` where the SBOM did not distinguish, which is most of them. Not
    #: `False`: "Syft did not say" and "this is transitive" are different
    #: facts, and the second is a claim this platform cannot make.
    direct: bool | None
    #: Advisories in CISA's Known Exploited Vulnerabilities catalogue. A fact,
    #: not a prediction, and it outranks severity.
    kev_count: int = 0
    cves: list[str] = field(default_factory=list)

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)


@dataclass
class SupplyChainAnalysis:
    packages: list[VulnerablePackage] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.packages)

    @property
    def fixable(self) -> int:
        return sum(1 for p in self.packages if p.fixable)

    @property
    def advisories(self) -> int:
        return sum(p.advisories for p in self.packages)

    @property
    def kev_packages(self) -> int:
        return sum(1 for p in self.packages if p.kev_count)

    @property
    def unfixable_advisories(self) -> int:
        """Advisories with nothing to upgrade to.

        Reported separately because it is the number that decides whether this
        is an afternoon of version bumps or a dispositioning pass — and the
        one the old counts hid completely.
        """
        return sum(p.advisories for p in self.packages if not p.fixable)


def _fixed_version(raw_json: str | None) -> str:
    """The patched version the scanner named, or "" when it named none."""
    if not raw_json:
        return ""
    try:
        raw = json.loads(raw_json)
    except (ValueError, TypeError):
        return ""
    text = str((raw.get("message") or {}).get("text", ""))
    match = _FIXED.search(text)
    if not match:
        return ""
    value = match.group(1).strip()
    # Trivy writes `Fixed Version:` with nothing after it when none exists, so
    # the regex happily captures whatever came next — which is `Link:`.
    return "" if value.startswith("Link") else value


def _directness(catalog: Catalog, repo_full_name: str) -> dict[str, bool | None]:
    """Whether each package is a direct dependency, from the newest SBOM."""
    if not catalog.all_files("sbom_components"):
        return {}
    rows = catalog.query(
        """
        SELECT package_name, any_value(direct)
        FROM sbom_components
        WHERE repo_full_name = ?
        GROUP BY 1
        """,
        [repo_full_name],
    )
    return {str(name): (None if direct is None else bool(direct)) for name, direct in rows}


def vulnerable_packages(
    catalog: Catalog,
    repo_full_name: str,
    *,
    kev_cves: set[str] | None = None,
) -> SupplyChainAnalysis:
    """Open package advisories for one repository, grouped by package.

    Grouped by package rather than by advisory because that is the unit of the
    decision: twenty-three advisories against `libc6` are one question about
    one package, and listing them separately is how a single decision looks
    like twenty-three pieces of work.

    `kev_cves` comes from the operational store rather than the lake, so it is
    passed in — this function stays a pure read of the lake and a test can
    exercise the KEV path without standing up a database.
    """
    if not catalog.all_files("findings"):
        return SupplyChainAnalysis()

    placeholders = ", ".join("?" for _ in PACKAGE_CAPABILITIES)
    rows = catalog.query(
        f"""
        SELECT package_name, package_version, capability, severity,
               rule_id, title, raw_finding_json
        FROM findings
        WHERE status = 'open'
          AND asset_id = ?
          AND capability IN ({placeholders})
          AND package_name IS NOT NULL AND package_name <> ''
        """,
        [repo_full_name, *PACKAGE_CAPABILITIES],
    )

    known_kev = {cve.upper() for cve in (kev_cves or set())}
    direct_by_package = _directness(catalog, repo_full_name)
    grouped: dict[str, dict[str, Any]] = {}

    for name, version, capability, severity, rule_id, title, raw_json in rows:
        package = str(name)
        entry = grouped.setdefault(
            package,
            {
                # `atlas` is a language ecosystem, `containers` is the image.
                # Not the SBOM's `ecosystem` field: that is absent for OS
                # packages, which are most of these.
                "ecosystem": "image" if str(capability) == "containers" else "dependency",
                "version": str(version or ""),
                "advisories": 0,
                "worst": "info",
                "fixed": "",
                "cves": set(),
                "kev": 0,
            },
        )
        entry["advisories"] += 1
        if SEVERITY_RANK.get(str(severity), 9) < SEVERITY_RANK.get(entry["worst"], 9):
            entry["worst"] = str(severity)

        # One published fix is enough to make the package actionable, so the
        # first non-empty wins rather than the last.
        if not entry["fixed"]:
            entry["fixed"] = _fixed_version(raw_json)

        for cve in _CVE.findall(f"{rule_id or ''} {title or ''}"):
            entry["cves"].add(cve.upper())
            if cve.upper() in known_kev:
                entry["kev"] += 1

    packages = [
        VulnerablePackage(
            package_name=name,
            ecosystem=str(entry["ecosystem"]),
            installed_version=str(entry["version"]),
            advisories=int(entry["advisories"]),
            worst_severity=str(entry["worst"]),
            fixed_version=str(entry["fixed"]),
            direct=direct_by_package.get(name),
            kev_count=int(entry["kev"]),
            cves=sorted(entry["cves"])[:12],
        )
        for name, entry in grouped.items()
    ]

    # Known-exploited first, then what you can actually fix, then severity,
    # then volume. Sorting on advisory count alone would put twenty-three
    # unfixable libc6 advisories above one exploited-in-the-wild package with
    # a patch waiting.
    packages.sort(
        key=lambda p: (
            not p.kev_count,
            not p.fixable,
            SEVERITY_RANK.get(p.worst_severity, 9),
            -p.advisories,
            p.package_name,
        )
    )
    return SupplyChainAnalysis(packages=packages)
