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

import json
import logging
import re

from mykronos.adapters.base import AdapterResult, ScanContext, warn_if_identity_degrades
from mykronos.adapters.sarif import sarif_to_findings

logger = logging.getLogger(__name__)

_PACKAGE = re.compile(r"^Package:\s*(?P<name>\S+)\s*$", re.MULTILINE)
_INSTALLED = re.compile(r"^Installed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)
_FIXED = re.compile(r"^Fixed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    # The churn warning is deferred to the end of this function. A Trivy
    # result never carries a code snippet and never needs one — the package
    # name below is its anchor — but that field is still `None` while the
    # converter runs, so asking there announced that every container finding
    # would churn while every one of them was stored on a stable package key
    # (#325).
    outcome = sarif_to_findings(raw_output, context, warn_degraded=False)
    image = _image_name(raw_output)
    if outcome.findings and image is None:
        outcome.warn(
            "The Trivy report names no single image (runs[].properties.imageName), "
            "so its findings keep package-only identity and will merge with the "
            "same package in any other image."
        )

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

        # Part of the finding's identity (`FINGERPRINT_CONTAINER`). The SARIF
        # location cannot supply it: for an OS package Trivy writes the image
        # name there, but for a binary it writes a path inside the image, and
        # `usr/local/bin/gosu` is the same path in every image that ships it.
        if image is not None and isinstance(finding.raw_finding_json, dict):
            finding.raw_finding_json["image"] = image

    if outcome.findings and not enriched:
        outcome.warn(
            "No Trivy finding carried a parseable package line. Container "
            "findings will have no package attached and cannot be remediated."
        )

    warn_if_identity_degrades(outcome, outcome.findings, context)

    return outcome


def _image_name(raw_output: bytes) -> str | None:
    """The image this report describes, from Trivy's run-level properties.

    Trivy writes one run per image with `properties.imageName`. A report with
    no run, or with runs naming different images, cannot attribute a result
    to one image, so it answers `None` rather than guessing.
    """
    try:
        document = json.loads(raw_output)
    except (ValueError, UnicodeDecodeError):
        return None
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        return None
    names = {
        str(run["properties"].get("imageName") or "").strip()
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("properties"), dict)
    }
    names.discard("")
    return names.pop() if len(names) == 1 else None
