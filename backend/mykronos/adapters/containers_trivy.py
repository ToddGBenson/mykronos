"""Trivy container image scanning (spec 04 §3).

Wraps the shared SARIF converter, like the osv-scanner adapter and for the
same reason: Trivy emits valid SARIF but records the two fields that make a
vulnerability actionable — which package, at which version — only inside the
result message.

    Package: perl-modules-5.40
    Installed Version: 5.40.1-6
    Vulnerability CVE-2026-42496
    Severity: CRITICAL
    Fixed Version: 5.40.1-7

The first real container scan produced 118 findings with `package_name` and
`package_version` both null. A CVE with no package is not something anybody
can act on: you cannot tell which layer introduced it, whether it is
reachable, or what to bump. The fixed version is captured too — it is the
difference between "this image is vulnerable" and "rebuild on the current
base image and it is not".
"""

from __future__ import annotations

import logging
import re

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sarif import sarif_to_findings

logger = logging.getLogger(__name__)

_PACKAGE = re.compile(r"^Package:\s*(?P<name>\S+)\s*$", re.MULTILINE)
_INSTALLED = re.compile(r"^Installed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)
_FIXED = re.compile(r"^Fixed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    outcome = sarif_to_findings(raw_output, context)

    enriched = 0
    for finding in outcome.findings:
        text = finding.description or ""

        if not finding.package_name:
            match = _PACKAGE.search(text)
            if match:
                finding.package_name = match.group("name")
                enriched += 1
        if not finding.package_version:
            match = _INSTALLED.search(text)
            if match:
                finding.package_version = match.group("version")

        # Patchwork reads the fixed version from the raw record (spec 08 §4).
        # Trivy leaves the field present but empty when no fix exists yet,
        # which is a different and important answer from "unknown" — an OS
        # package with no fixed version cannot be remediated by rebuilding,
        # and a fix proposed for one would never work.
        fixed = _FIXED.search(text)
        if fixed and isinstance(finding.raw_finding_json, dict):
            finding.raw_finding_json["fixed_version"] = fixed.group("version")

    if outcome.findings and not enriched:
        outcome.warn(
            "No Trivy finding carried a parseable package line. Container "
            "findings will have no package attached and cannot be remediated."
        )

    return outcome
