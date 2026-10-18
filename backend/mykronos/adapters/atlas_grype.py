"""grype, as a second Atlas tool (mykronos#414).

keel's `mykronos-sca` lane runs `grype dir:. -o sarif` and uploads it as
`atlas`. Until this existed the scan succeeded and the upload failed with
"No adapter for capability 'atlas' with tool 'grype'".

grype emits valid SARIF, so this wraps the shared converter like the
osv-scanner adapter does, and fills the same four things so an atlas finding
reads the same whichever tool produced it: `package_name`, `package_version`,
`version_basis` and `raw_finding_json["fixed_version"]`. Where they live in
grype 0.87's output (`tests/data/grype-0.87.0-requirements.sarif`):

- **The result message** names the package and the version *this* match is
  about:

      A critical vulnerability in python package: pyyaml, version 5.3 was
      found at: /requirements.txt

  Read from here first because the rule is shared: grype keys a rule on
  vulnerability + package name, so two lockfiles holding two versions of one
  package produce two results under one rule.
- **The rule's `help.text`** carries a `Package:` / `Version:` /
  `Fix Version:` block, the fallback for the first two and the only place the
  fix is stated. An empty `Fix Version:` is grype saying no fix is published,
  recorded as `""` -- the same contract the containers and osv-scanner
  adapters keep.
- **`properties.purls`** on the rule, the last fallback for the package.

The rule id is kept as grype writes it (`GHSA-6757-jp84-gxfx-pyyaml`, or
`CVE-2021-1234-openssl`). The CVE readers (`threat_intel.extract_cve`,
`supply_chain`) search the rule id, so a CVE-keyed match is found there. The
bare advisory id is recorded as `raw_finding_json["vulnerability_id"]` for
anything that wants it without the package suffix. grype's SARIF names no
aliases, so a GHSA-keyed match carries no CVE -- exactly as osv-scanner's
does.

Identity is the package, not the line: grype reports every match at line 1 of
the manifest, so with `package_name` unset these findings would be keyed on a
position that means nothing.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from mykronos.adapters.atlas_osv import _basis, _pick_fix
from mykronos.adapters.base import AdapterResult, ScanContext, warn_if_identity_degrades
from mykronos.adapters.sarif import sarif_to_findings

logger = logging.getLogger(__name__)

#: `A <severity> vulnerability in <type> package: <name>, version <version>
#: was found at: <path>` (or `... was found in image <image> at: <path>`).
_MESSAGE = re.compile(r"package: (?P<name>[^,\s]+), version (?P<version>\S+) was found")
_HELP_PACKAGE = re.compile(r"^Package:[ \t]*(?P<value>\S+)[ \t]*$", re.MULTILINE)
_HELP_VERSION = re.compile(r"^Version:[ \t]*(?P<value>\S+)[ \t]*$", re.MULTILINE)
#: Present with nothing after it when no fix exists, so the value is optional.
_HELP_FIX = re.compile(r"^Fix Version:[ \t]*(?P<value>[^\n]*?)[ \t]*$", re.MULTILINE)
#: `pkg:pypi/pyyaml@5.3` -> name, version. Namespaced purls
#: (`pkg:npm/%40scope/name@1.0.0`) keep the namespace in the name.
_PURL = re.compile(r"^pkg:[^/]+/(?P<name>[^@?#]+)@(?P<version>[^?#]+)")


def _rules(raw_output: bytes) -> dict[str, dict[str, Any]]:
    """Rule id -> what its help text and purls say about the package."""
    try:
        document = json.loads(raw_output.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(document, dict):
        return {}

    table: dict[str, dict[str, Any]] = {}
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            if not isinstance(rule, dict) or not rule.get("id"):
                continue
            text = str((rule.get("help") or {}).get("text") or "")
            entry: dict[str, Any] = {}
            for key, pattern in (
                ("package", _HELP_PACKAGE),
                ("version", _HELP_VERSION),
                ("fix", _HELP_FIX),
            ):
                match = pattern.search(text)
                if match:
                    entry[key] = match.group("value").strip()
            purls = (rule.get("properties") or {}).get("purls")
            if isinstance(purls, list):
                for purl in purls:
                    match = _PURL.match(str(purl))
                    if match:
                        entry.setdefault("purl_name", match.group("name").replace("%40", "@"))
                        entry.setdefault("purl_version", match.group("version"))
                        break
            table[str(rule["id"])] = entry
    return table


def _vulnerability_id(rule_id: str, package: str | None) -> str:
    """`GHSA-6757-jp84-gxfx-pyyaml` -> `GHSA-6757-jp84-gxfx`."""
    if package:
        suffix = "-" + package
        if rule_id.lower().endswith(suffix.lower()) and len(rule_id) > len(suffix):
            return rule_id[: -len(suffix)]
    return rule_id


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    # Deferred churn warning, as in the osv-scanner and Trivy adapters: the
    # package name set below is what keeps these off the positional branch.
    outcome = sarif_to_findings(raw_output, context, warn_degraded=False)
    rules = _rules(raw_output)

    enriched = 0
    for finding in outcome.findings:
        rule = rules.get(finding.rule_id, {})

        if not finding.package_name:
            match = _MESSAGE.search(finding.description or "") or _MESSAGE.search(
                finding.title or ""
            )
            if match:
                finding.package_name = match.group("name")
                finding.package_version = finding.package_version or match.group("version")
            else:
                finding.package_name = rule.get("package") or rule.get("purl_name")
                finding.package_version = finding.package_version or (
                    rule.get("version") or rule.get("purl_version")
                )
            if finding.package_name:
                enriched += 1

        finding.version_basis = _basis(
            finding.file_path or "", finding.package_name, context.workspace
        )

        raw = finding.raw_finding_json
        raw["vulnerability_id"] = _vulnerability_id(finding.rule_id, finding.package_name)
        if "fix" in rule:
            # Empty is the answer "no fix published", not "not looked up".
            raw["fixed_version"] = (
                _pick_fix(finding.package_version, rule["fix"]) if rule["fix"] else ""
            )

    floors = sum(1 for f in outcome.findings if f.version_basis == "declared_floor")
    if floors:
        outcome.warn(
            f"{floors} finding(s) describe the version a requirement declares, not one "
            "this repository runs. Raising the floor closes them; it changes no "
            "running byte."
        )

    if outcome.findings and not enriched:
        outcome.warn(
            "No grype finding carried a parseable package. Dependency fixes "
            "cannot be generated without one."
        )

    warn_if_identity_degrades(outcome, outcome.findings, context)
    return outcome
