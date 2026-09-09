"""PSScriptAnalyzer adapter (B-051).

`personal-soc` is 100% PowerShell and carries one capability, `secrets` -- so
gitleaks greps its content for credential patterns and nothing has ever
examined its 608 lines for a defect. CodeQL implements no PowerShell either,
so enabling `sast` there as it stood would have added a second green lane over
unread code rather than coverage.

**Severity arrives as an integer, and that is the trap.** PSScriptAnalyzer's
`Severity` is a .NET enum, and `ConvertTo-Json` serialises it as its ordinal:
`0` Information, `1` Warning, `2` Error, `3` ParseError. A reader expecting
"Warning" gets `1`, and a naive mapping would file every finding at the
default severity while looking like it worked. Both forms are accepted here
because `-EnumsAsStrings` exists and a repository may well pass it.

**Nothing maps above `medium`**, for the reason the ShellCheck adapter gives:
these are correctness levels from a linter, and a linter that can reach `high`
competes with the dependency scanner for the top of a queue it has no business
being at the top of. The rules that matter most here are security-relevant and
arrive as `Error` and `Warning` -- `PSAvoidUsingConvertToSecureStringWithPlainText`,
`PSAvoidUsingInvokeExpression`, `PSAvoidUsingPlainTextForPassword` -- and are
worth reading on their own terms rather than by rank.

The 2026-09-03 hand pass over `personal-soc` found no `Invoke-Expression`, no
`DownloadString`, no `-ExecutionPolicy Bypass` and no credential literals. A
clean result is what this lane should reproduce; reproducing it on every push
rather than once an afternoon is the point.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.sarif import _clean_uri
from mykronos.adapters.snippet import best_snippet
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "psscriptanalyzer"

#: The .NET enum, by ordinal and by name. See the module docstring for why
#: both: `ConvertTo-Json` writes the ordinal unless asked otherwise.
_SEVERITY: dict[str, Severity] = {
    "0": Severity.INFO,
    "information": Severity.INFO,
    "1": Severity.LOW,
    "warning": Severity.LOW,
    "2": Severity.MEDIUM,
    "error": Severity.MEDIUM,
    # A script that does not parse is a defect whatever else is true of it,
    # and it also means every other rule silently skipped that file.
    "3": Severity.MEDIUM,
    "parseerror": Severity.MEDIUM,
}

#: PSScriptAnalyzer documents each rule, and the docs are better writing than
#: anything this platform would generate. Linked rather than summarised.
_DOCS = "https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/rules/"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse `Invoke-ScriptAnalyzer | ConvertTo-Json` output."""
    result = AdapterResult()

    try:
        text = raw_output.decode("utf-8-sig", errors="replace").strip()
        payload: Any = json.loads(text) if text else []
    except json.JSONDecodeError as exc:
        result.warn(f"PSScriptAnalyzer output is not parseable JSON ({exc})")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    if isinstance(payload, dict):
        # `ConvertTo-Json` unwraps a single-element array into a bare object,
        # which is how a scan with exactly one finding looks. Reading only
        # lists would drop it, and a repository with one problem would report
        # a clean scan.
        payload = [payload]
    if payload is None:
        payload = []
    if not isinstance(payload, list):
        result.warn("PSScriptAnalyzer output is neither an object nor an array")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    for record in payload:
        if not isinstance(record, dict):
            result.skipped += 1
            continue

        rule_id = str(record.get("RuleName") or "").strip()
        raw_path = str(record.get("ScriptPath") or record.get("ScriptName") or "").strip()
        if not rule_id or not raw_path:
            # No rule means nothing to group by; no file means no location.
            # Either way the finding has no stable identity (spec 05 §5) and
            # would be filed anew on every run.
            result.skipped += 1
            continue

        # Absolute on the runner: `/home/runner/work/personal-soc/personal-soc/
        # Invoke-BreachCheck.ps1`. Shared with the SARIF converter rather than
        # reimplemented, so the knowledge of what a runner path looks like
        # lives in one place.
        file_path = _clean_uri(raw_path, context.workspace)

        line = record.get("Line")
        line_start = line if isinstance(line, int) else None
        message = str(record.get("Message") or rule_id).strip()
        severity = str(record.get("Severity", "")).strip().lower()

        snippet, symbol, _ = best_snippet(
            context_region_snippet=None,
            region_snippet=None,
            workspace=context.workspace,
            file_path=file_path,
            start_line=line_start,
            end_line=line_start,
        )

        result.findings.append(
            FindingSubmission(
                rule_id=rule_id[:255],
                title=f"{rule_id}: {message}"[:500],
                description=(
                    f"{message}\n\nWhat this rule checks and how to satisfy it: "
                    f"{_DOCS}{rule_id.lower()}"
                ),
                severity=_SEVERITY.get(severity, Severity.INFO),
                file_path=file_path,
                line_start=line_start,
                line_end=line_start,
                symbol=symbol,
                code_snippet=snippet,
                raw_finding_json=record,
            )
        )

    if result.skipped:
        result.warn(
            f"{result.skipped} PSScriptAnalyzer record(s) had no rule or no script "
            "and were skipped: a finding with neither has no stable identity."
        )
    return result
