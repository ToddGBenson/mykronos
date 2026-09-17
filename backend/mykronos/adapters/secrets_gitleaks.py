"""Gitleaks adapter (spec 04 §3, §4).

The one capability whose findings *are* the sensitive data, which changes two
things about how it is normalized.

**No snippet, ever.** Every other adapter captures surrounding source to give
findings a stable identity (spec 05 §5). Doing that here would copy the secret
into the lake, into `raw_finding_json`, and onto the dashboard. So this adapter
submits no snippet at all: `code_snippet` is `None`, and `compute_finding_id`
falls through to its positional branch, keyed on
(repo, capability, rule, file, line_start).

It used to pass a constant redaction marker there instead, and that was the
defect in #396. A constant is not a placeholder for the snippet; it is the
absence of one wearing a snippet's clothes. It normalizes non-empty, so the
snippet branch always won and `line_start` was never read — every hit of one
rule in one file collapsed into a single finding. On TheHub's latest scan, 34
detections were stored as 13 rows, and a `false_positive` verdict entered
against one of them silently covered seventeen real credentials nobody had
looked at (#398).

The positional branch is labelled degraded because identity churns when
unrelated lines shift above it. For secrets that trade is the right one and
the churn is mostly theoretical: a hit belongs to the commit that introduced
it, and a line in a commit that is already written never moves. When identity
does churn, the cost is a duplicate finding to re-triage — a failure in the
safe direction. Silent merging fails in the other one.

Two things that look like better anchors and are not. Hashing the secret would
survive line movement, but `--redact` means the adapter never receives the
value: `Secret` arrives literally as `"REDACTED"`. Gitleaks' own `Fingerprint`
field is prefixed with the commit sha, so it changes on every commit and would
make every secret a brand-new finding on every scan (#274); its `file:rule:line`
tail is precisely what the positional branch already computes.

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

#: Replaces any archived field that may still hold the raw secret. Never used
#: as fingerprint input — see the module docstring and #396.
REDACTED = "<secret redacted by Mykronos>"

#: Keys whose values may hold the raw secret. Dropped from `raw_finding_json`
#: even though `--redact` should already have blanked them: the archive is
#: retained for a year (spec 05 §7) and a redaction flag missing from one
#: workflow must not turn that into a year-long secret store.
_SENSITIVE_KEYS = {"Secret", "Match", "Line"}


def _line_number(value: Any) -> int | None:
    """Coerce a Gitleaks line field to an int, or `None` if it is not one.

    The line is the only thing separating two hits of the same rule in the
    same file (#396), so a line that arrives as `"757"` rather than `757` —
    which some report writers and every JSON round-trip through a string
    column can produce — must not silently become `None` and re-collapse the
    findings it was meant to keep apart. `bool` is excluded on purpose: it is
    an `int` subclass and `True` is not line 1.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


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
        start_line = _line_number(record.get("StartLine"))

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
                    f"{start_line if start_line is not None else '?'} in "
                    f"{where}. The value is redacted here and "
                    "in the archived output. If it is a real credential, "
                    "rotate it first: it is already in history, and deleting "
                    "the line does not remove it from anyone's existing clone."
                ),
                # Not derived from the tool: Gitleaks does not rank findings,
                # and a committed live credential is critical whichever
                # pattern caught it.
                severity=Severity.CRITICAL,
                file_path=file_path,
                # The sole separator between two hits of one rule in one file.
                line_start=start_line,
                line_end=_line_number(record.get("EndLine")),
                # Never the matched text, and never a stand-in for it either:
                # a constant snippet is identity material with no identity in
                # it, and it collapsed every hit of one rule in one file into
                # one finding (#396). `None` sends `compute_finding_id` to its
                # positional branch, which keys on `line_start` above.
                code_snippet=None,
                raw_finding_json=_scrub(record),
            )
        )

    if result.skipped:
        result.warn(f"{result.skipped} Gitleaks record(s) were unusable and skipped")
        result.scan_status = ScanStatus.PARTIAL_FAILURE

    return result
