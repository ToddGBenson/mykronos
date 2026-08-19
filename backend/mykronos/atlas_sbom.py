"""A second read of the SBOM Syft already produced (spec 22 §1, §3).

Two things come out of it that osv-scanner cannot give: what licenses the
dependency tree carries, and whether any component is one this repository has
banned outright. Neither needs a new scan or a new tool — the SBOM is already
generated for every Atlas run and, until now, only archived.

Runner-side, like `atlas_counts`, for the reason spec 07 §7 makes an
acceptance criterion: the runner reports facts, the platform scores them.
Counting GPL components here and weighting them there means the weighting can
change without a resync across every onboarded repo.

    python -m mykronos.atlas_sbom sbom.json --banned-package left-pad

Prints `{"licenses": {...}, "findings": [...]}` on stdout.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from typing import Any

#: What a component with no license statement is recorded as. A key rather
#: than an omission, because "we looked and the SBOM says nothing" is a fact
#: worth a small penalty of its own (spec 22 §1.3) and is not the same as the
#: license pass never having run.
UNKNOWN = "unknown"

#: SPDX-style package purls carry the ecosystem: `pkg:npm/lodash@4.17.21`.
_PURL_ECOSYSTEM = re.compile(r"^pkg:([^/]+)/")


def _normalise(identifier: str) -> str:
    """Lowercased SPDX identifier.

    Config is written by a person — `GPL-3.0`, `gpl-3.0` and `GPL-3.0-only`
    all turn up — and an exact-case comparison would silently not match the
    license somebody meant to ban. Case is folded here; the `-only`/`-or-later`
    suffix distinction is *kept*, because those are genuinely different terms
    and collapsing them would ban more than was asked for.
    """
    return identifier.strip().lower()


def _ecosystem_of(component: dict[str, Any]) -> str:
    """The component's ecosystem, from its purl, or `unknown`.

    Matching `atlas_counts`' key space matters: the platform merges license
    counts into the per-ecosystem evidence rows that module produces, and an
    ecosystem name that does not match lands the licenses in a row nothing
    else populates.
    """
    purl = str(component.get("purl") or "")
    match = _PURL_ECOSYSTEM.match(purl)
    if match:
        return match.group(1).lower()
    return str(component.get("ecosystem") or UNKNOWN).lower()


def _licenses_of(component: dict[str, Any]) -> list[str]:
    """Every license this component declares, normalised.

    CycloneDX writes `licenses: [{license: {id | name}} | {expression}]`; Syft
    emits both shapes depending on what the source metadata offered, and a
    single component routinely carries several. All of them are returned:
    spec 22 §6 makes the restrictive one govern, and that can only be decided
    by a caller looking at the whole list.
    """
    found: list[str] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        detail = entry.get("license")
        if isinstance(detail, dict):
            value = detail.get("id") or detail.get("name") or ""
        else:
            value = entry.get("expression") or ""
        if str(value).strip():
            found.append(_normalise(str(value)))
    return found


def _components(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    """The component list, from either SBOM dialect.

    CycloneDX puts them under `components`, SPDX under `packages`, and
    `AtlasConfig.sbom_format` lets a repo choose. Reading both here rather
    than branching at the call site keeps the choice from leaking into
    everything downstream.
    """
    if isinstance(sbom.get("components"), list):
        return [c for c in sbom["components"] if isinstance(c, dict)]
    if isinstance(sbom.get("packages"), list):
        return [_from_spdx(p) for p in sbom["packages"] if isinstance(p, dict)]
    return []


def _from_spdx(package: dict[str, Any]) -> dict[str, Any]:
    """One SPDX package in the CycloneDX shape the rest of this module reads."""
    declared = package.get("licenseDeclared") or package.get("licenseConcluded") or ""
    licenses = []
    # `NOASSERTION` is SPDX for "the tool did not determine this", which is
    # exactly `unknown` — recording it verbatim would put a pseudo-license in
    # the counts and let somebody ban it by name.
    if declared and str(declared).upper() != "NOASSERTION":
        licenses = [{"license": {"id": str(declared)}}]
    purl = ""
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and ref.get("referenceType") == "purl":
            purl = str(ref.get("referenceLocator") or "")
            break
    return {
        "name": package.get("name") or "",
        "version": package.get("versionInfo") or "",
        "purl": purl,
        "licenses": licenses,
    }


def licenses_by_ecosystem(sbom: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Per-ecosystem license identifier → component count (spec 22 §1.2).

    A component declaring three licenses counts once against each of them, so
    these numbers sum to more than the dependency count. That is deliberate:
    the question the penalty asks is "how many components carry a flagged
    license", and a dual-licensed component carrying one does carry it.
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for component in _components(sbom):
        ecosystem = _ecosystem_of(component)
        declared = _licenses_of(component)
        if not declared:
            counts[ecosystem][UNKNOWN] += 1
            continue
        for identifier in set(declared):
            counts[ecosystem][identifier] += 1
    return {eco: dict(sorted(seen.items())) for eco, seen in sorted(counts.items())}


def denylist_findings(
    sbom: dict[str, Any],
    *,
    banned_packages: list[str],
    blocked_licenses: list[str],
    severity: str = "high",
) -> list[dict[str, Any]]:
    """A `Finding` per banned package and per blocked license (spec 22 §3.2).

    A finding, not a score deduction. A banned package is a policy violation
    somebody has to act on, and a silent penalty buries it in a single number
    nobody reads term by term.

    A package that is both banned *and* carrying a blocked license produces
    two rows (spec 22 §6). They are different facts about the same package,
    and disposing of one should not silently dispose of the other.
    """
    banned = {_normalise(name) for name in banned_packages if name.strip()}
    blocked = {_normalise(name) for name in blocked_licenses if name.strip()}
    if not banned and not blocked:
        return []

    findings: list[dict[str, Any]] = []
    for component in _components(sbom):
        name = str(component.get("name") or "")
        if not name:
            continue
        version = str(component.get("version") or "")
        ecosystem = _ecosystem_of(component)
        located = f"{ecosystem}:{name}@{version}" if version else f"{ecosystem}:{name}"

        if _normalise(name) in banned:
            findings.append(
                {
                    "rule_id": "atlas-banned-package",
                    "title": f"Banned package: {name}",
                    "severity": severity,
                    "description": (
                        f"`{name}` is listed in this repository's "
                        "`banned_packages`. It is present in the resolved "
                        "dependency tree regardless of whether any advisory "
                        "covers it — the ban is the finding."
                    ),
                    "file_path": located,
                    "package_name": name,
                    "package_version": version,
                }
            )

        for identifier in sorted(set(_licenses_of(component)) & blocked):
            findings.append(
                {
                    "rule_id": "atlas-blocked-license",
                    "title": f"Blocked license {identifier}: {name}",
                    "severity": severity,
                    "description": (
                        f"`{name}` declares `{identifier}`, which is listed in "
                        "this repository's `blocked_licenses`. A component "
                        "declaring several licenses is flagged if any one of "
                        "them is blocked — the restrictive terms govern, not "
                        "the most permissive ones also on offer."
                    ),
                    "file_path": located,
                    "package_name": name,
                    "package_version": version,
                }
            )
    return findings


#: SARIF's three levels. `high` and `critical` both land on `error` because
#: SARIF has no third step above warning, and a banned package is not a
#: suggestion.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Denylist findings in the format the upload step already reads.

    SARIF rather than a new ingestion endpoint, so these travel the same road
    every other finding on this platform travels — same normalisation, same
    dedup, same triage. A second path into the findings table would be a
    second place for the finding-id derivation to drift.

    An empty list still produces a valid document with `results: []`. "Scanned
    and found nothing" and "produced no output" read differently to the
    uploader, and only the first one is true here.
    """
    rules = {
        f["rule_id"]: {
            "id": f["rule_id"],
            "shortDescription": {
                "text": (
                    "Package banned by repository policy"
                    if f["rule_id"] == "atlas-banned-package"
                    else "License blocked by repository policy"
                )
            },
        }
        for f in findings
    }
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mykronos-atlas-denylist",
                        "informationUri": "https://github.com/ToddGBenson/mykronos",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f["rule_id"],
                        "level": _SARIF_LEVEL.get(f["severity"], "warning"),
                        "message": {"text": f"{f['title']}. {f['description']}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f["file_path"]}
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mykronos-atlas-sbom", description=__doc__
    )
    parser.add_argument("sbom", help="The CycloneDX or SPDX file Syft produced.")
    parser.add_argument("--banned-package", action="append", default=[])
    parser.add_argument("--blocked-license", action="append", default=[])
    parser.add_argument(
        "--sarif",
        default=None,
        help=(
            "Also write the findings as SARIF here, for the upload step to "
            "collect alongside osv-scanner's. Written even when empty: "
            "'scanned, found nothing' and 'produced no output' read "
            "differently to the uploader."
        ),
    )
    args = parser.parse_args(argv)

    try:
        with open(args.sbom, encoding="utf-8") as handle:
            sbom = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        # Empty rather than a crash, for the same reason `atlas_counts` does
        # it: an unreadable SBOM should cost the license pass, not the whole
        # Atlas run whose vulnerability counts are already computed.
        print(f"Could not read {args.sbom}: {exc}", file=sys.stderr)
        json.dump({"licenses": {}, "findings": []}, sys.stdout)
        return 0

    findings = denylist_findings(
        sbom,
        banned_packages=args.banned_package,
        blocked_licenses=args.blocked_license,
    )
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as handle:
            json.dump(to_sarif(findings), handle, ensure_ascii=False)

    json.dump(
        {"licenses": licenses_by_ecosystem(sbom), "findings": findings},
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
