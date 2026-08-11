"""Gitleaks adapter (spec 04 §3, §4).

The one capability whose findings *are* the sensitive data, which changes two
things about how it is normalized.

**No snippet, ever.** Every other adapter captures surrounding source to give
findings a stable identity (spec 05 §5). Doing that here would copy the secret
into the lake, into `raw_finding_json`, and onto the dashboard. Instead a
constant redaction marker stands in for the snippet: identity becomes
(repo, capability, rule, file), which is stable under line movement — the
property D-001 exists for — without storing anything sensitive.

The consequence is deliberate: two AWS keys in one file are one finding rather
than two. "This file leaks an AWS key" is the actionable unit, and the fix is
the same either way.

**Severity is fixed, not tool-derived.** Gitleaks does not rank findings; it
either matched a rule or it did not. A committed live credential is a critical
finding regardless of which pattern caught it.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "gitleaks"

#: Stands in for the code snippet so identity is stable without the secret.
REDACTED = "<secret redacted by Mykronos>"

#: Keys whose values may hold the raw secret. Dropped from `raw_finding_json`
#: even though `--redact` should already have blanked them: the archive is
#: retained for a year (spec 05 §7) and a redaction flag missing from one
#: workflow must not turn that into a year-long secret store.
_SENSITIVE_KEYS = {"Secret", "Match", "Line"}


def _scrub(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: (REDACTED if key in _SENSITIVE_KEYS and value else value)
        for key, value in record.items()
    }


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse a Gitleaks JSON report."""
    result = AdapterResult()

    try:
        text = raw_output.decode("utf-8", errors="replace").strip()
        records = json.loads(text) if text else []
    except json.JSONDecodeError as exc:
        result.warn(f"Gitleaks output is not parseable JSON ({exc})")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    if records is None:
        # Gitleaks writes literal `null` rather than `[]` when it finds
        # nothing. That is a clean scan, not a broken one.
        records = []

    if not isinstance(records, list):
        result.warn("Gitleaks output is not a JSON array")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    for record in records:
        if not isinstance(record, dict):
            result.skipped += 1
            continue

        rule_id = str(record.get("RuleID") or "").strip()
        file_path = str(record.get("File") or "").strip() or None
        if not rule_id or not file_path:
            result.skipped += 1
            continue

        description = str(record.get("Description") or rule_id)
        start_line = record.get("StartLine")

        # The workflow runs `gitleaks detect` over a full-depth clone, which
        # scans *history*: each hit belongs to the commit that introduced it,
        # and `StartLine` is a line in that commit's version of the file, not
        # in the current one. Without the commit the location is frequently
        # unresolvable — the first real triage of these findings hit lines
        # holding a closing brace and an unrelated assertion, which reads as a
        # broken scanner rather than as a finding about the past.
        commit = str(record.get("Commit") or "").strip()
        where = (
            f"commit {commit[:10]}, which may not be the current content of "
            f"that file. Retrieve exactly what matched with "
            f"`git show {commit}:{file_path}`"
            if commit
            else f"{file_path} in the working tree"
        )

        result.findings.append(
            FindingSubmission(
                rule_id=rule_id[:255],
                title=f"Exposed secret: {description}"[:1000],
                description=(
                    f"Gitleaks rule '{rule_id}' matched at {file_path}:"
                    f"{start_line} in {where}. The value is redacted here and "
                    "in the archived output. If it is a real credential, "
                    "rotate it first: it is already in history, and deleting "
                    "the line does not remove it from anyone's existing clone."
                ),
                # Not derived from the tool: Gitleaks does not rank findings,
                # and a committed live credential is critical whichever
                # pattern caught it.
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_start=int(start_line) if isinstance(start_line, int) else None,
                line_end=(
                    int(record["EndLine"]) if isinstance(record.get("EndLine"), int) else None
                ),
                # Constant marker, never the matched text. See module docstring.
                code_snippet=REDACTED,
                raw_finding_json=_scrub(record),
            )
        )

    if result.skipped:
        result.warn(f"{result.skipped} Gitleaks record(s) were unusable and skipped")
        result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result
