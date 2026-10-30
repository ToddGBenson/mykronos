"""osv-scanner (spec 07 §3).

Thin wrapper over the shared SARIF converter. osv-scanner emits valid SARIF
and needs no bespoke parser, but it puts the one thing that makes a dependency
finding *actionable* — which package, at which version — only in the result
message:

    Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-5p4m-2wfm-xmqj'.

There is no `locations[].logicalLocations` entry, no rule property, nothing
structured. So the first real Atlas scan produced findings whose
`package_name` and `package_version` were both null.

That is not cosmetic. Patchwork's deterministic dependency fixer keys on those
two fields (spec 08 §4): with them null it cannot tell which requirement to
pin, so every dependency finding falls through to `triaged` and no fix is ever
offered. The capability that exists to find vulnerable dependencies was
producing findings the capability that exists to fix them could not read.

Parsing a message is fragile and this one is worth the fragility: it is a
fixed format string in osv-scanner, the pattern is anchored, and a miss leaves
the fields null — exactly where they were before.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from mykronos import atlas_baseline, atlas_constraints, cvss_vectors
from mykronos.adapters.base import AdapterResult, ScanContext, warn_if_identity_degrades
from mykronos.adapters.sarif import sarif_to_findings

logger = logging.getLogger(__name__)

#: `Package 'name@version' is vulnerable to 'ID'.`
#:
#: The name may itself contain `@` — npm scoped packages are `@scope/name` —
#: so the version is taken from the *last* `@`, not the first.
_PACKAGE = re.compile(r"Package '(?P<spec>[^']+)' is vulnerable to")

#: Files that name the version that actually gets installed. A finding from
#: one of these is about running software.
_LOCKFILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pdm.lock",
        "uv.lock",
        "cargo.lock",
        "gemfile.lock",
        "composer.lock",
        "go.sum",
        "packages.lock.json",
    }
)

#: Files that declare what the repository *permits*. With `--no-resolve`,
#: which both CIs pass deliberately and permanently (deps.dev returns an
#: internal error for any requirements.txt containing sqlalchemy, and an
#: extractor error fails the whole lane), osv-scanner assesses the version
#: the declaration names rather than the one that would be installed.
_MANIFESTS = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "package.json",
        "go.mod",
        "cargo.toml",
        "gemfile",
        "composer.json",
        "build.gradle",
        "pom.xml",
    }
)

#: SBOM file names osv-scanner recognises for `-L` (it detects the format by
#: name). A finding located in one was assessed against the SBOM's version,
#: which -- unlike a manifest's -- can describe what is installed (#322).
_SBOM_SUFFIXES = (".cdx.json", ".spdx.json")
_SBOM_NAMES = frozenset({"bom.json", "sbom.json"})

#: How many constraint facts are written before "and N more". Each is a
#: warning on the ScanRun, and a page of them would read as noise.
_CONSTRAINT_FACTS_NAMED = 5


def _is_sbom(name: str) -> bool:
    return name in _SBOM_NAMES or name.endswith(_SBOM_SUFFIXES)


Installed = dict[tuple[str, str], set[str]]


def _installed_index(context: ScanContext) -> Installed:
    """Every (ecosystem, name) -> versions the supplied SBOMs say are installed."""
    index: Installed = {}
    for path in context.sbom_paths:
        document = atlas_constraints.load_sbom(path)
        if document is None:
            continue
        for key, versions in atlas_constraints.installed_versions(document).items():
            index.setdefault(key, set()).update(versions)
    return index


def _installed(index: Installed, package: str, version: str | None) -> bool:
    if not version:
        return False
    for ecosystem in ("pypi", "npm"):
        key = (ecosystem, atlas_constraints.normalise_name(ecosystem, package))
        if version in index.get(key, ()):
            return True
    return False


#: An exact requirement. `==1.2.3` in Python, a bare `1.2.3` in npm. Anything
#: else -- `>=`, `^`, `~`, `*`, a bare name -- permits something newer, so the
#: version osv-scanner assessed is the oldest the repository accepts.
_PINNED = re.compile(r"(==|===)\s*[0-9]")
#: npm declares its requirement as the *value* for the package's key, so it
#: is read from that value rather than from the line. The first version
#: scanned the whole line, and a `package.json` written on one line let a
#: neighbouring package's exact pin decide this package's answer.
_NPM_EXACT = re.compile(r"^\s*(?:v|=)?\s*[0-9][0-9A-Za-z.+-]*\s*$")


def _requirement_line(text: str, package: str) -> str | None:
    """The line declaring `package`, or None if it cannot be found.

    Matched on the name at a word boundary rather than by parsing each
    ecosystem's manifest format. A miss leaves the basis unset, which is the
    honest outcome: nothing established it.
    """
    pattern = re.compile(
        r"^[^#\n]*(?<![\w.-])" + re.escape(package) + r"(?![\w.-])[^\n]*$",
        re.IGNORECASE | re.MULTILINE,
    )
    match = pattern.search(text)
    return match.group(0) if match else None


def _basis(
    file_path: str,
    package: str | None,
    workspace: Path | None,
    version: str | None = None,
    installed: Installed | None = None,
) -> Literal["resolved", "declared_floor", "declared_pin"] | None:
    """What the assessed version is a statement about (B-063).

    Returns None wherever the answer is not established -- an unrecognised
    file, a manifest that cannot be read, a package whose line is not found.
    A wrong `resolved` would say a finding describes running software when it
    does not, which is the reading this exists to prevent, so every uncertain
    case declines to answer.
    """
    if not file_path:
        return None
    name = PurePosixPath(file_path.replace("\\", "/")).name.lower()

    if name in _LOCKFILES:
        return "resolved"
    if _is_sbom(name):
        # `resolved` only where the SBOM itself records this package at this
        # version as installed. Syft transcribes `==` pins out of
        # requirements.txt into the SBOM it generates from a checkout, and a
        # finding on one of those is still about a declaration. Without the
        # SBOM to look in -- reprocessing an archived scan, say -- the answer
        # is not established.
        if package and installed and _installed(installed, package, version):
            return "resolved"
        return None
    if name not in _MANIFESTS:
        return None
    if not package or workspace is None:
        # A manifest, so this is a declaration rather than an installed
        # version -- but without the source there is no way to tell a pin
        # from a floor, and calling an exact pin a floor would be its own
        # false statement.
        return None

    try:
        text = (workspace / file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    if name == "package.json":
        spec = re.search(
            r'"' + re.escape(package) + r'"\s*:\s*"(?P<spec>[^"]*)"', text, re.IGNORECASE
        )
        if spec is None:
            return None
        return "declared_pin" if _NPM_EXACT.match(spec.group("spec")) else "declared_floor"

    line = _requirement_line(text, package)
    if line is None:
        return None
    return "declared_pin" if _PINNED.search(line) else "declared_floor"


def _split(spec: str) -> tuple[str, str | None]:
    name, separator, version = spec.rpartition("@")
    if not separator or not name:
        # No version, or a scoped name with nothing after it. Better to record
        # the name alone than to invent a version.
        return spec, None
    return name, version or None


def _fixed_versions(raw_output: bytes) -> dict[tuple[str, str], str]:
    """(vulnerability id, package) -> the fixed versions osv-scanner named.

    **The fixed version is in the SARIF; it is just not in the result.** Every
    other adapter reads its remediation out of the result's message, and for
    osv-scanner that message says only
    `Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-...'`. The remediation
    lives in the *rule*, as a markdown table:

        ### Fixed Versions

        | Vulnerability ID | Package Name | Fixed Version |
        | --- | --- | --- |
        | GHSA-5p4m-2wfm-xmqj | js-yaml | 3.15.1, 4.3.1 |

    Parsed here rather than in the shared SARIF reader because it is
    osv-scanner's own presentation, not a SARIF convention -- and because the
    cost of missing it is specific and was measured: every atlas finding was
    reported as having no published fix, including a critical unauthenticated
    RCE that had one (mykronos#256).

    **The table's id is usually not the finding's.** osv-scanner 2.x names a
    rule -- and so the finding's `rule_id` -- after the CVE or PYSEC id of an
    alias group, and fills the table with the *aliases* that carry the fix
    (rule `CVE-2026-115572`, row `GHSA-6c7f-9265-g8fw`; rule `PYSEC-2026-4320`,
    row `GHSA-6q48-6c7w-9gw2`). Keyed on the row id alone -- and 661 of 988 rows in
    the estate's archived scans name an id other than their rule's -- those
    findings read as having no published fix while OSV published one (TheHub
    #60909). So every row is also indexed under its rule's own id and
    `deprecatedIds`. Where aliases name different fixes the candidates are
    merged, and `_pick_fix` takes the highest on the installed line -- the
    one that satisfies every advisory in the group.
    """
    exact: dict[tuple[str, str], str] = {}
    grouped: dict[tuple[str, str], list[str]] = {}
    for rule in _rules(raw_output):
        rows = _fixed_rows(_markdown(rule))
        if not rows:
            continue
        names = [str(rule.get("id") or "")]
        deprecated = rule.get("deprecatedIds")
        if isinstance(deprecated, list):
            names += [str(alias) for alias in deprecated]
        for vulnerability, package, fixed in rows:
            exact[(vulnerability, package)] = fixed
            for name in filter(None, names):
                merged = grouped.setdefault((name, package), [])
                for part in fixed.split(","):
                    part = part.strip()
                    if part and part not in merged:
                        merged.append(part)
    table = {key: ", ".join(parts) for key, parts in grouped.items() if parts}
    table.update(exact)
    return table


def _rules(raw_output: bytes) -> list[dict[str, Any]]:
    try:
        document = json.loads(raw_output.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return []
    rules: list[dict[str, Any]] = []
    for run in document.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        rules.extend(r for r in driver.get("rules") or [] if isinstance(r, dict))
    return rules


def _markdown(rule: dict[str, Any]) -> str:
    help_ = rule.get("help")
    return str(help_.get("markdown") or "") if isinstance(help_, dict) else ""


def _fixed_rows(markdown: str) -> list[tuple[str, str, str]]:
    """(vulnerability id, package, fixed versions) for each row of one rule's table."""
    start = markdown.find("### Fixed Versions")
    if start < 0:
        return []
    rows: list[tuple[str, str, str]] = []
    begun = False
    for line in markdown[start:].splitlines()[1:]:
        line = line.strip()
        if not line.startswith("|"):
            # The table ends at the first non-row once *this* table has begun.
            # The first version tested the accumulated result instead, so
            # every rule after the first stopped at the blank line under its
            # own heading and only one rule per scan was ever read (#60909).
            if begun:
                break
            continue
        begun = True
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0] == "Vulnerability ID" or set(cells[0]) <= set("- "):
            continue  # header or separator
        rows.append((cells[0], cells[1], cells[2]))
    return rows


def _rules_without_fix(raw_output: bytes) -> set[str]:
    """Rule ids whose remediation osv-scanner wrote without a fixed version.

    osv-scanner's help text always carries a `## Remediation` section and adds
    `### Fixed Versions` only when OSV records one, so a Remediation section
    with no table is OSV saying no fix is published -- the known absence an
    empty `fixed_version` means. A rule with no help text says nothing either
    way and stays unrecorded: "not known" and "known to be none" are different
    answers, and only the second may tell anybody there is nothing to upgrade
    to (TheHub #60909).
    """
    absent: set[str] = set()
    for rule in _rules(raw_output):
        markdown = _markdown(rule)
        if "## Remediation" in markdown and "### Fixed Versions" not in markdown:
            absent.add(str(rule.get("id") or ""))
    absent.discard("")
    return absent


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def _pick_fix(installed: str | None, candidates: str) -> str:
    """The fix that applies to the version actually installed.

    osv-scanner names one fix per affected release line -- `3.15.1, 4.3.1` is
    two answers, not a list to take the first of. Handing a 3.x consumer
    `4.3.1` is a major upgrade wearing a patch's clothes, so the candidate
    sharing the installed major wins. Where aliases of one vulnerability named
    different fixes on the same line, the highest wins: only it satisfies
    every advisory in the group.

    Falls back to the lowest candidate when the installed version is unknown
    or matches no line: the smallest upgrade that could be right is a safer
    thing to advise than the largest.
    """
    options = [part.strip() for part in candidates.split(",") if part.strip()]
    if not options:
        return ""
    if installed:
        major = installed.lstrip("v=<>~^ ").split(".")[0]
        same_line = [o for o in options if o.lstrip("v").split(".")[0] == major]
        if same_line:
            return max(same_line, key=_version_key)
    return options[0]


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    # Deferred like the container adapter's, and for the same reason: the
    # package specifier this function parses out of the message is the anchor
    # that keeps these findings off the positional branch, and it is not set
    # until below (#325).
    outcome = sarif_to_findings(raw_output, context, warn_degraded=False)

    enriched = 0
    for finding in outcome.findings:
        if finding.package_name:
            continue
        match = _PACKAGE.search(finding.description or "") or _PACKAGE.search(
            finding.title or ""
        )
        if not match:
            continue
        finding.package_name, finding.package_version = _split(match.group("spec"))
        enriched += 1

    # Separate pass: every finding gets a basis, including the ones that
    # already carried a package name and skipped the enrichment above.
    installed = _installed_index(context) if context.sbom_paths else {}
    for finding in outcome.findings:
        finding.version_basis = _basis(
            finding.file_path or "",
            finding.package_name,
            context.workspace,
            finding.package_version,
            installed,
        )

    # Remediation, from the rule rather than the result (mykronos#256).
    # Same field and same contract as the containers adapter: Patchwork and
    # the acceptance sweep both read `fixed_version` off the raw record, and
    # an empty one is the meaningful answer "no fix published" rather than
    # "not looked up".
    fixes = _fixed_versions(raw_output)
    no_fix = _rules_without_fix(raw_output)
    resolved = 0
    for finding in outcome.findings:
        candidates = fixes.get((finding.rule_id, finding.package_name or ""))
        chosen = _pick_fix(finding.package_version, candidates) if candidates else ""
        if chosen:
            finding.raw_finding_json["fixed_version"] = chosen
            resolved += 1
        elif finding.rule_id in no_fix:
            # OSV published no fix. The empty value is that answer, as it is
            # for grype; the key's absence means nobody established one.
            finding.raw_finding_json["fixed_version"] = ""
    if fixes and not resolved:
        # The table was there and matched nothing, which means the ids or
        # package names stopped lining up -- worth saying, because the
        # symptom downstream is silent: every finding reads as unfixable.
        outcome.warn(
            "osv-scanner published fixed versions but none matched a finding "
            "by rule id and package. Dependency findings will report no "
            "available fix."
        )

    # osv-scanner 2.2's SARIF publishes `security-severity` and no vector, so
    # this finds nothing today; it keeps one if that changes (TheHub #60824).
    cvss_vectors.attach(outcome.findings, raw_output, source="osv-scanner")

    _report_broken_constraints(outcome, context)

    # After the fixed version is known: which commit answers for each
    # finding, and whether this one already fixes it (TheHub #61063).
    atlas_baseline.annotate(outcome.findings, context)

    floors = sum(1 for f in outcome.findings if f.version_basis == "declared_floor")
    if floors:
        # Said out loud on the scan rather than left to be noticed per
        # finding. The first reading of these was wrong in exactly this way:
        # they were reported as live HIGH vulnerabilities on an
        # internet-facing application, and corrected only after somebody
        # checked the version inside the running container.
        outcome.warn(
            f"{floors} finding(s) describe the version a requirement declares, not one "
            "this repository runs. Raising the floor closes them; it changes no "
            "running byte."
        )

    if outcome.findings and not enriched:
        # Worth a warning rather than silence: it means osv-scanner changed
        # its message format, and the symptom downstream is Patchwork quietly
        # offering no fixes at all.
        outcome.warn(
            "No osv-scanner finding carried a parseable package specifier. "
            "Dependency fixes cannot be generated without one."
        )

    # After enrichment, never before: the package name attached above is what
    # keeps these findings off the positional branch (#325).
    warn_if_identity_degrades(outcome, outcome.findings, context)

    return outcome


def _report_broken_constraints(outcome: AdapterResult, context: ScanContext) -> None:
    """Lane-health facts for installed versions outside the declared range (#322).

    Skipped when no SBOM was supplied: without one there is nothing to compare
    the declarations with, and silence is the honest answer. Written to the
    *front* of the warnings, because only the first reaches the ScanRun's
    `detail`, and this is the one direction of the floor-vs-installed gap that
    hides vulnerabilities rather than inventing them. Never a finding, never a
    gate.
    """
    if not context.sbom_paths:
        return
    violations = atlas_constraints.constraint_violations(
        context.workspace, context.sbom_paths
    )
    if not violations:
        return
    facts = [v.fact() for v in violations[:_CONSTRAINT_FACTS_NAMED]]
    if len(violations) > _CONSTRAINT_FACTS_NAMED:
        rest = violations[_CONSTRAINT_FACTS_NAMED:]
        facts.append(
            f"{len(rest)} more installed version(s) violate a declared constraint: "
            + ", ".join(f"{v.name} {'/'.join(v.installed)} vs `{v.spec}`" for v in rest)
        )
    for fact in facts:
        logger.warning("adapter: %s", fact)
    outcome.warnings[0:0] = facts
