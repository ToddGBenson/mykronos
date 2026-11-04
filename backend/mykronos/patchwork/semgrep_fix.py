"""Apply a Semgrep rule's own `fix:` output, and nothing else (TheHub #60746).

The deterministic fixer `apply-semgrep-fix` (registered in `fixers.FIXERS`).
It writes no code of its own. Semgrep already computed the replacement when it
matched: run with `--autofix --dryrun`, a rule carrying `fix:` or
`fix-regex:` puts the edit in the SARIF result's `fixes`
(`artifactChanges[].replacements[]`), and the SARIF adapter keeps the whole
result as the finding's `raw_finding_json`. This module applies that edit to
the file as it is now, so the pull request's diff is exactly Semgrep's fix
output: the same bytes `semgrep --autofix` would have written.

**What Semgrep's SARIF fix means.** Semgrep (1.97.0, the version the lane
pins) writes `deletedRegion` as the match's span but `insertedContent` as the
*whole fixed lines*, indentation and trailing code included. Applied by the
SARIF letter, that would duplicate everything outside the span. So the
replacement is read as Semgrep means it: the lines `startLine`..`endLine`
become `insertedContent`. It is applied only when the inserted text still
begins with what precedes the span on its first line and ends with what
follows it on its last, so a fix that does not line up with the file is
refused rather than guessed at.

**Only a named list of rules.** `SEMGREP_FIX_RULES` is the list, and
`semgrep_fix_rules.yml` beside this file is where the rules live. A Semgrep
`fix:` from a registry pack is not applied just because it exists: whether a
rewrite is mechanical is a property of the rule, decided when it is added here,
not of whatever pack a lane happens to run.

**The file must be the file Semgrep scanned.** A fix is positions in the
scanned commit. If the lines it names have changed since, the same positions
point at different code, so the fixer compares the result's region snippet
with the current lines and refuses on any difference rather than editing
whatever now sits at those columns.

No model is involved anywhere here (D-032, D-096), and a test asserts this
module imports none.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mykronos.patchwork.fixers import ProposedFix

logger = logging.getLogger(__name__)

FIXER_NAME = "apply-semgrep-fix"

#: The rules file, beside this module so the backend image carries it.
RULES_FILE = Path(__file__).with_name("semgrep_fix_rules.yml")

#: The named fix-rule list. Each id is a rule in `RULES_FILE` whose rewrite is
#: the right shape whatever the surrounding code does. A test holds the two
#: lists equal.
SEMGREP_FIX_RULES: tuple[str, ...] = (
    "mykronos-pyyaml-load-to-safe-load",
    "mykronos-jinja2-autoescape-disabled",
    "mykronos-flask-debug-enabled",
)

#: What a reviewer checks, per rule. The generic notes below are added to
#: every one.
_RULE_NOTES: dict[str, str] = {
    "mykronos-pyyaml-load-to-safe-load": (
        "`yaml.safe_load` refuses Python-specific tags (`!!python/object` and "
        "friends). If this document legitimately uses them, the load now "
        "raises instead of constructing the object; that is the point, but "
        "confirm no caller depended on it."
    ),
    "mykronos-jinja2-autoescape-disabled": (
        "Templates rendered by this Environment now escape every variable. A "
        "template that deliberately emits HTML from a variable needs `|safe` "
        "on that variable, which is a decision about that one value."
    ),
    "mykronos-flask-debug-enabled": (
        "The interactive debugger and the reloader are off for this entry "
        "point. If a developer relies on them locally, set them from an "
        "environment variable rather than restoring `debug=True` here."
    ),
}


def rule_name(rule_id: str) -> str | None:
    """The named rule `rule_id` is, or None when it is not one of them.

    Semgrep prefixes a local rule's id with its config path (`rules.` for
    `--config rules/x.yml`), so a match is either the bare id or one ending in
    `.<id>`.
    """
    for name in SEMGREP_FIX_RULES:
        if rule_id == name or rule_id.endswith(f".{name}"):
            return name
    return None


def _offset(lines: list[str], line: int, column: int) -> int | None:
    """Character offset of a 1-based SARIF (line, column), or None if outside."""
    if line < 1 or line > len(lines) + 1 or column < 1:
        return None
    if line == len(lines) + 1:
        return sum(len(text) for text in lines) if column == 1 else None
    body = lines[line - 1].rstrip("\r\n")
    if column - 1 > len(body):
        return None
    return sum(len(text) for text in lines[: line - 1]) + column - 1


def _replacements(raw: dict[str, Any], path: str) -> list[dict[str, Any]] | str:
    fixes = raw.get("fixes")
    if not isinstance(fixes, list) or not fixes:
        return "Semgrep reported no fix for this result."
    if len(fixes) != 1:
        return "Semgrep reported more than one fix; choosing between them is a judgement."
    changes = fixes[0].get("artifactChanges") if isinstance(fixes[0], dict) else None
    if not isinstance(changes, list) or len(changes) != 1:
        return "The fix does not change exactly one file."
    change = changes[0]
    uri = str(((change.get("artifactLocation") or {}).get("uri")) or "")
    if not uri or not (uri == path or uri.endswith(f"/{path}") or path.endswith(f"/{uri}")):
        return f"The fix names `{uri}`, not `{path}`."
    replacements = change.get("replacements")
    if not isinstance(replacements, list) or not replacements:
        return "The fix carries no replacement."
    return [r for r in replacements if isinstance(r, dict)]


def _snippet_matches(raw: dict[str, Any], lines: list[str]) -> bool:
    """The result's region text is still what the file holds at those lines."""
    locations = raw.get("locations") or []
    if not locations or not isinstance(locations[0], dict):
        return False
    region = (locations[0].get("physicalLocation") or {}).get("region") or {}
    start = region.get("startLine")
    end = region.get("endLine") or start
    snippet = (region.get("snippet") or {}).get("text")
    if not isinstance(start, int) or not isinstance(end, int) or not isinstance(snippet, str):
        return False
    if start < 1 or end > len(lines) or end < start:
        return False
    current = "".join(lines[start - 1 : end])
    return current.replace("\r\n", "\n").rstrip("\n") == snippet.replace("\r\n", "\n").rstrip(
        "\n"
    )


def explain(finding: dict[str, Any], content: str) -> ProposedFix | str:
    """The fix for `finding`, or why there is none (worded for a reader)."""
    rule_id = str(finding.get("rule_id") or "")
    name = rule_name(rule_id)
    if name is None:
        return f"`{rule_id}` is not in the named Semgrep fix-rule list."
    path = str(finding.get("file_path") or "")
    raw = finding.get("raw_finding_json")
    if not path or not isinstance(raw, dict):
        return "The finding carries no file or no Semgrep result."

    replacements = _replacements(raw, path)
    if isinstance(replacements, str):
        return replacements

    lines = content.splitlines(keepends=True)
    if not _snippet_matches(raw, lines):
        return (
            f"`{path}` has changed at the lines Semgrep matched, so its fix "
            "positions no longer name the same code. The next scan re-reports "
            "it against the current file."
        )

    spans: list[tuple[int, int, str]] = []
    bodies = [line.rstrip("\r\n") for line in lines]
    for replacement in replacements:
        region = replacement.get("deletedRegion") or {}
        inserted = (replacement.get("insertedContent") or {}).get("text")
        start_line = region.get("startLine")
        start_column = region.get("startColumn", 1)
        end_line = region.get("endLine", start_line)
        end_column = region.get("endColumn")
        if not (
            isinstance(start_line, int)
            and isinstance(start_column, int)
            and isinstance(end_line, int)
            and isinstance(end_column, int)
        ):
            return "A replacement region is incomplete."
        if not isinstance(inserted, str):
            return "A replacement carries no text."
        start = _offset(lines, start_line, start_column)
        end = _offset(lines, end_line, end_column)
        if start is None or end is None or end < start or end_line > len(bodies):
            return "A replacement region lies outside the file."
        # Semgrep's insertedContent is the fixed lines; the span's own text is
        # what lies between the untouched head of the first line and the
        # untouched tail of the last.
        head = bodies[start_line - 1][: start_column - 1]
        tail = bodies[end_line - 1][end_column - 1 :]
        if not (
            inserted.startswith(head)
            and inserted.endswith(tail)
            and len(inserted) >= len(head) + len(tail)
        ):
            return (
                "Semgrep's fix does not line up with the lines it names, so "
                "applying it would rewrite code outside the match."
            )
        spans.append((start, end, inserted[len(head) : len(inserted) - len(tail)]))

    spans.sort()
    for (_, previous_end, _), (start, _, _) in zip(spans, spans[1:], strict=False):
        if start < previous_end:
            return "Two replacements overlap."

    rewritten = content
    for start, end, inserted in reversed(spans):
        rewritten = rewritten[:start] + inserted + rewritten[end:]
    if rewritten == content:
        return "Semgrep's fix leaves the file unchanged."

    return ProposedFix(
        files={path: rewritten},
        summary=f"Apply Semgrep's fix for `{name}` in `{path}`",
        review_notes=[
            _RULE_NOTES[name],
            "The diff is Semgrep's own `fix:` output for this rule, applied "
            "as written: no other line moved. Re-running Semgrep on this "
            "branch should no longer report the finding, and Patchwork "
            "records whether it does.",
        ],
    )


def apply_semgrep_fix(finding: dict[str, Any], content: str) -> ProposedFix | None:
    """`fixers.Fixer`: the fix, or None when this fixer does not apply."""
    if finding.get("capability") != "sast":
        return None
    result = explain(finding, content)
    if isinstance(result, str):
        if rule_name(str(finding.get("rule_id") or "")) is not None:
            logger.info("%s declined %s: %s", FIXER_NAME, finding.get("finding_id"), result)
        return None
    return result
