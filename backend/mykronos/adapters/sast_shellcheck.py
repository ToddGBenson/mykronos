"""ShellCheck adapter (B-051).

CodeQL implements no shell language at all, and `keel` is 69% shell -- so 47
successful SAST runs read 30% of the repository and reported success over the
rest. This is the adapter that lets something read the other 219 KB.

**ShellCheck emits no SARIF**, so this parses its `json1` format rather than
going through the shared converter. `json1` rather than `json`: the older
format is a bare array with no envelope, and its `endLine`/`endColumn` are
absent for some checks, which makes a finding's extent unknowable exactly
where a snippet would help most.

**Its levels are about correctness, not exploitability, so nothing here maps
above `medium`.** ShellCheck is a linter. `error` means the shell will not do
what the author wrote; `warning` means it probably will not. Neither is a
statement that an attacker can do anything, and mapping them onto `high` would
put a linter's opinion beside a live CVE in the same ranked queue -- which is
how a queue stops being ranked by risk. The findings that *are*
security-relevant, like SC2115's `rm -rf "$x/"*` and SC2086's word splitting,
arrive as `warning` and `info` and are worth reading on their own terms.

The 2026-09-03 hand pass over keel and binnacle found 27 findings each, none
above `info`, and all three of the security-adjacent hits deliberate. That is
the baseline this lane should reproduce, and reproducing it on every push
rather than once an afternoon is the point.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mykronos.adapters.base import AdapterResult, ScanContext
from mykronos.adapters.snippet import best_snippet
from mykronos.schemas import FindingSubmission, ScanStatus, Severity

logger = logging.getLogger(__name__)

TOOL_NAME = "shellcheck"

#: ShellCheck's level to this platform's severity.
#:
#: Capped at `medium` on purpose. See the module docstring: these are
#: correctness levels, and a linter that can reach `high` competes with the
#: dependency scanner for the top of a queue it has no business being at the
#: top of.
_SEVERITY: dict[str, Severity] = {
    "error": Severity.MEDIUM,
    "warning": Severity.LOW,
    "info": Severity.INFO,
    "style": Severity.INFO,
}

#: `https://www.shellcheck.net/wiki/SC2086` is the canonical explanation of
#: every code, and it is better writing than anything this platform would
#: generate. Linked rather than summarised.
_WIKI = "https://www.shellcheck.net/wiki/"


def normalize(raw_output: bytes, context: ScanContext) -> AdapterResult:
    """Parse a ShellCheck `--format=json1` report."""
    result = AdapterResult()

    try:
        text = raw_output.decode("utf-8", errors="replace").strip()
        payload: Any = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        result.warn(f"ShellCheck output is not parseable JSON ({exc})")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    # `json1` wraps the findings in `{"comments": [...]}`; the older `json`
    # format is the bare array. Both are accepted -- a repository that pinned
    # the older flag should still get its findings, and every field read below
    # is present in both.
    comments: Any = payload.get("comments") if isinstance(payload, dict) else payload
    if comments is None:
        comments = []
    if not isinstance(comments, list):
        result.warn("ShellCheck output is not a list of comments")
        result.scan_status = ScanStatus.PARTIAL_FAILURE
        return result

    for comment in comments:
        if not isinstance(comment, dict):
            result.skipped += 1
            continue

        code = comment.get("code")
        file_path = str(comment.get("file") or "").strip()
        if code is None or not file_path:
            # Without a code there is no rule to group by, and without a file
            # there is no location: either way the finding has no identity
            # (spec 05 §5) and recording it would create a new one every run.
            result.skipped += 1
            continue

        rule_id = f"SC{code}"
        level = str(comment.get("level") or "info").lower()
        line_start = comment.get("line")
        line_end = comment.get("endLine") or line_start
        message = str(comment.get("message") or rule_id).strip()

        snippet, symbol, _ = best_snippet(
            context_region_snippet=None,
            region_snippet=None,
            workspace=context.workspace,
            file_path=file_path,
            start_line=line_start if isinstance(line_start, int) else None,
            end_line=line_end if isinstance(line_end, int) else None,
        )

        result.findings.append(
            FindingSubmission(
                rule_id=rule_id,
                title=f"{rule_id}: {message}"[:500],
                description=(
                    f"{message}\n\nShellCheck's explanation of this check, with "
                    f"examples of the correct and incorrect forms: {_WIKI}{rule_id}"
                ),
                severity=_SEVERITY.get(level, Severity.INFO),
                file_path=file_path,
                line_start=line_start if isinstance(line_start, int) else None,
                line_end=line_end if isinstance(line_end, int) else None,
                symbol=symbol,
                code_snippet=snippet,
                raw_finding_json=comment,
            )
        )

    if result.skipped:
        result.warn(
            f"{result.skipped} ShellCheck comment(s) had no code or no file and "
            "were skipped: a finding with neither has no stable identity."
        )
    return result
