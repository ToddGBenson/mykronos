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

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

from mykronos import image_provenance
from mykronos.adapters.base import AdapterResult, ScanContext, warn_if_identity_degrades
from mykronos.adapters.sarif import sarif_to_findings
from mykronos.fingerprint import image_repository

logger = logging.getLogger(__name__)

_PACKAGE = re.compile(r"^Package:\s*(?P<name>\S+)\s*$", re.MULTILINE)
_INSTALLED = re.compile(r"^Installed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)
_FIXED = re.compile(r"^Fixed Version:\s*(?P<version>\S+)\s*$", re.MULTILINE)

#: The run property `annotate_base_os` writes: Trivy JSON's `Metadata.OS`,
#: verbatim -- `{"Family": "debian", "Name": "10.13", "EOSL": true}`.
#:
#: Why a stamp rather than a parse. Trivy's SARIF has no OS block at all (its
#: run properties are imageID, imageName, repoDigests, repoTags; checked
#: against Trivy 0.73.0), and its JSON report does. `EOSL` is the field Trivy
#: sets when the distribution release is past its end of service life, and it
#: omits the key when it is not -- so an absent key reads as "not known to be
#: EOL", never as "EOL". No release table is kept here: Trivy already ships
#: one, and a second copy would disagree with it the day either went stale.
OS_PROPERTY = "trivyOs"

#: Tag on `raw_finding_json` for a finding no package update will ever close
#: (mykronos#712). Distinct from an empty `fixed_version`, which means "no fix
#: yet" and is what `no_vendor_fix` acceptances wait on.
BASE_OS_EOL = "base_os_eol"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    # The churn warning is deferred to the end of this function. A Trivy
    # result never carries a code snippet and never needs one — the package
    # name below is its anchor — but that field is still `None` while the
    # converter runs, so asking there announced that every container finding
    # would churn while every one of them was stored on a stable package key
    # (#325).
    outcome = sarif_to_findings(raw_output, context, warn_degraded=False)
    image = _image_name(raw_output)
    role = _image_role(raw_output)
    eol_base = _eol_base_os(raw_output) if image is not None else None
    if outcome.findings and image is None:
        outcome.warn(
            "The Trivy report names no single image (runs[].properties.imageName), "
            "so its findings keep package-only identity and will merge with the "
            "same package in any other image."
        )

    enriched = 0
    eol_findings = 0
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
        # #666: what a compose file declared the image FOR, stamped onto the
        # report by `estate_images annotate-roles`. Only `tool` is recorded;
        # anything else, or nothing, leaves the finding counting as before.
        if role == "tool" and isinstance(finding.raw_finding_json, dict):
            finding.raw_finding_json["image_role"] = "tool"

        # #712: an OS package with no fixed version, on a distribution release
        # past end of service life, will never get one. Filing it with the
        # "no fix yet" findings sends it to a `no_vendor_fix` acceptance whose
        # premise -- re-open when a vendor ships -- cannot come true. Only OS
        # packages: a language package in the same image has its own upstream,
        # which the base OS's end of life says nothing about.
        raw = finding.raw_finding_json
        if (
            eol_base is not None
            and image is not None
            and isinstance(raw, dict)
            and not str(raw.get("fixed_version") or "").strip()
            and _is_os_package(finding.file_path, image)
        ):
            raw[BASE_OS_EOL] = True
            raw["base_os"] = eol_base
            eol_findings += 1

    if eol_findings:
        outcome.warn(
            f"{image} is built on {eol_base}, which is end-of-life: {eol_findings} "
            "finding(s) will never get a package fix. Rebuild it on a supported base "
            "image (usually a newer major tag upstream); a `no_vendor_fix` acceptance "
            "would wait for a vendor that will not ship (#712)."
        )

    if outcome.findings and not enriched:
        outcome.warn(
            "No Trivy finding carried a parseable package line. Container "
            "findings will have no package attached and cannot be remediated."
        )

    # After the package check above, which is about Trivy's results and must
    # not count these, and before the identity check, which must.
    outcome.findings.extend(_provenance_findings(raw_output, context))

    warn_if_identity_degrades(outcome, outcome.findings, context)

    return outcome


def _provenance_findings(raw_output: bytes, context: ScanContext) -> list[FindingSubmission]:
    """A finding for each published image that cannot name its commit (#382).

    Only runs `image_provenance --annotate` stamped are asked: those are the
    images this lane publishes. "Absent" and "mismatch" are separate rules at
    separate severities, because they are separate fixes, and a match says
    nothing. A finding rather than a warning because it must stay open, and
    show on the repository, until a build fixes it; a warning is read once in
    a build log, which is how two of three images went unnoticed.

    Repo-level identity (rule and title), with the image's repository in the
    title and its tag only in the description: the same image failing on the
    next commit is the same finding, not a new one per SHA.
    """
    try:
        document = json.loads(raw_output)
    except (ValueError, UnicodeDecodeError):
        return []
    runs = document.get("runs") if isinstance(document, dict) else None
    findings: list[FindingSubmission] = []
    for run in runs if isinstance(runs, list) else []:
        properties = run.get("properties") if isinstance(run, dict) else None
        if not isinstance(properties, dict):
            continue
        stamp = image_provenance.stamped(properties)
        image = str(properties.get("imageName") or "").strip()
        if stamp is None or not image:
            continue
        variable, recorded = stamp
        result = image_provenance.assess(image, variable, recorded, context.commit_sha)
        name = image.split("@", 1)[0].rsplit("/", 1)[-1].rsplit(":", 1)[0]
        record = {
            "image": image,
            "variable": result.variable,
            "recorded": result.recorded,
            "expected": result.expected,
            "verdict": result.verdict,
        }
        if result.verdict == "absent":
            findings.append(
                FindingSubmission(
                    rule_id=RULE_ABSENT,
                    title=f"Image {name} does not record the commit it was built from",
                    description=(
                        f"{image} carries no usable {result.variable} in its environment, "
                        f"so a running container cannot say which commit it is "
                        f"(expected {result.expected}). The tag is outside the box. Pass "
                        f"the SHA as a build arg and keep it with `ARG {result.variable}` "
                        f"then `ENV {result.variable}=${{{result.variable}}}` in the final "
                        f"stage (#382)."
                    ),
                    severity=Severity.MEDIUM,
                    raw_finding_json=record,
                )
            )
        elif result.verdict == "mismatch":
            findings.append(
                FindingSubmission(
                    rule_id=RULE_MISMATCH,
                    title=f"Image {name} records a different commit than it is published as",
                    description=(
                        f"{image} records {result.variable}={result.recorded}, but it "
                        f"is published as {result.expected}. Everything that asks the "
                        f"running process what it is will be told the wrong commit. The "
                        f"build passed a stale SHA or reused a layer that baked one in "
                        f"(#382)."
                    ),
                    severity=Severity.HIGH,
                    raw_finding_json=record,
                )
            )
    return findings


def _image_role(raw_output: bytes) -> str | None:
    """`properties.mykronosRole` when every run in the report agrees on it."""
    try:
        document = json.loads(raw_output)
    except (ValueError, UnicodeDecodeError):
        return None
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list) or not runs:
        return None
    roles = {
        str((run.get("properties") or {}).get("mykronosRole") or "")
        for run in runs
        if isinstance(run, dict)
    }
    return roles.pop() if len(roles) == 1 and "" not in roles else None


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


def _is_os_package(file_path: str | None, image: str) -> bool:
    """Whether a result is about an OS package rather than a file in the image.

    Trivy locates an OS-package result at the image's repository
    (`library/debian` for `debian:buster-slim`) and a language package or
    binary at a path inside the image (`usr/local/bin/gosu`). The repository
    is compared in `image_repository`'s form, the same one the fingerprint
    already relies on matching Trivy's.
    """
    if not file_path:
        return False
    return image_repository(file_path) == image_repository(image)


def _eol_base_os(raw_output: bytes) -> str | None:
    """`"debian 10.13"` when the report's OS is end-of-life, else None.

    Read from `properties.trivyOs` (see `OS_PROPERTY`) -- Trivy JSON's
    `Metadata.OS`. Absent, or `EOSL` anything but `true`, is None: the only
    evidence of an end of life accepted here is Trivy saying so.
    """
    try:
        document = json.loads(raw_output)
    except (ValueError, UnicodeDecodeError):
        return None
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list):
        return None
    for run in runs:
        properties = run.get("properties") if isinstance(run, dict) else None
        os_block = properties.get(OS_PROPERTY) if isinstance(properties, dict) else None
        if isinstance(os_block, dict) and os_block.get("EOSL") is True:
            name = f"{os_block.get('Family') or ''} {os_block.get('Name') or ''}".strip()
            return name or "an end-of-life OS"
    return None


def annotate_base_os(sarif: dict[str, Any], trivy_report: dict[str, Any]) -> bool:
    """Copy a Trivy JSON report's `Metadata.OS` onto the matching SARIF run.

    Matched on the image name (SARIF `properties.imageName`, JSON
    `ArtifactName`), so a directory of reports cannot cross-stamp. Returns
    whether anything was written. A JSON report with no OS block -- a
    distroless or scratch image -- writes nothing, which reads downstream as
    "not known to be end-of-life".
    """
    os_block = (trivy_report.get("Metadata") or {}).get("OS")
    artifact = str(trivy_report.get("ArtifactName") or "").strip()
    if not isinstance(os_block, dict) or not artifact:
        return False
    written = False
    for run in sarif.get("runs") or []:
        properties = run.get("properties") if isinstance(run, dict) else None
        if not isinstance(properties, dict):
            continue
        if str(properties.get("imageName") or "").strip() == artifact:
            properties[OS_PROPERTY] = dict(os_block)
            written = True
    return written


def main(argv: list[str] | None = None) -> int:
    """`python -m mykronos.adapters.containers_trivy --sarif X --trivy-json Y`.

    For a containers lane that wants base-OS end-of-life on its findings:
    scan once with `--format json`, `trivy convert --format sarif` from it,
    then stamp the SARIF with this before uploading.
    """
    parser = argparse.ArgumentParser(
        prog="python -m mykronos.adapters.containers_trivy",
        description="Stamp Trivy JSON's Metadata.OS onto the matching SARIF run (#712).",
    )
    parser.add_argument("--sarif", required=True, type=Path)
    parser.add_argument("--trivy-json", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        sarif = json.loads(args.sarif.read_text(encoding="utf-8"))
        report = json.loads(args.trivy_json.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        # Never fails the lane: the findings are worth more than the stamp.
        print(f"base-OS stamp skipped: {exc}", file=sys.stderr)
        return 0
    if annotate_base_os(sarif, report):
        args.sarif.write_text(json.dumps(sarif), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
