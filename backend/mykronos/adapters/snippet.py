"""Snippet and symbol extraction — the inputs D-001 depends on.

`finding_id` is a hash of file, symbol and normalized code snippet (spec 05
§5). If an adapter supplies none of those, the API falls back to hashing
`line_start` and stamps `v1-line` — the churn-prone mode the fingerprint
change exists to avoid. So this module is not a nicety; it is what makes the
whole thing work.

Sources are tried in order of reliability:

1. `contextRegion.snippet` from SARIF — the tool's own snippet with
   surrounding lines. Best: the tool knows what it matched.
2. `region.snippet` from SARIF — the matched text alone.
3. The working tree on disk — read the file and slice it.
4. Nothing. Recorded as degradation, never disguised.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

#: Lines of context either side when slicing from disk. Enough that the
#: fingerprint survives a one-line edit nearby without being so wide that any
#: change in the function retires the finding.
CONTEXT_LINES = 2

MAX_SNIPPET_CHARS = 20_000  # matches FindingSubmission.code_snippet

#: Declaration patterns for the languages CodeQL supports. Deliberately
#: shallow — this is a heuristic, not a parser, and it only needs to be
#: *deterministic*, not correct. A consistently-wrong symbol still yields a
#: stable fingerprint; an inconsistent one would not.
_DECLARATION = re.compile(
    r"""^\s*(?:
        (?:async\s+)?def\s+(?P<py>\w+)                      # Python
      | (?:export\s+)?(?:async\s+)?function\s+(?P<js>\w+)   # JavaScript
      | func\s+(?:\([^)]*\)\s*)?(?P<go>\w+)                 # Go
      | (?:public|private|protected|internal|static|final|\s)*
        [\w<>\[\],.]+\s+(?P<java>\w+)\s*\([^;]*$            # Java / C#
      | class\s+(?P<cls>\w+)                                # class, most langs
      | (?:const|let|var)\s+(?P<arrow>\w+)\s*=\s*
        (?:async\s*)?(?:\([^)]*\)|\w+)\s*=>                 # JS arrow fn
    )""",
    re.VERBOSE,
)


def read_source_lines(workspace: Path | None, file_path: str) -> list[str] | None:
    """Read a file from the working tree, or None if that is not possible.

    Never raises. A SARIF result can reference a generated file, a path
    outside the checkout, or something binary — none of which should take down
    a scan that otherwise produced good findings.
    """
    if workspace is None or not file_path:
        return None

    candidate = (workspace / file_path).resolve()
    try:
        # Refuse to read outside the workspace. A malicious or malformed SARIF
        # with `../../etc/passwd` should not be able to pull host files into
        # finding records that then get stored and displayed.
        candidate.relative_to(workspace.resolve())
    except ValueError:
        logger.warning("Refusing to read %s: outside the workspace", file_path)
        return None

    try:
        return candidate.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, UnicodeError) as exc:
        logger.debug("Could not read %s: %s", file_path, exc)
        return None


def slice_snippet(
    lines: list[str], start_line: int | None, end_line: int | None
) -> str | None:
    """Take the finding's lines plus a little context. 1-indexed, inclusive."""
    if not lines or not start_line or start_line < 1:
        return None

    # Tolerate endLine < startLine. It is malformed SARIF, but a tool that
    # emits it should still produce a usable snippet rather than a finding
    # that silently degrades to positional identity.
    effective_end = max(end_line or start_line, start_line)

    first = max(0, start_line - 1 - CONTEXT_LINES)
    last = min(len(lines), effective_end + CONTEXT_LINES)
    if first >= last:
        return None

    return "\n".join(lines[first:last])[:MAX_SNIPPET_CHARS]


def infer_symbol(lines: list[str] | None, start_line: int | None) -> str | None:
    """Nearest enclosing declaration above the finding, best-effort.

    Scans backwards for the first line matching a declaration pattern. Being a
    heuristic is acceptable because `symbol` is one input among several in the
    fingerprint and it only has to disambiguate identical snippets in one
    file. What matters is determinism: the same file and line always produce
    the same answer, so identity does not wobble between scans.

    Returns None rather than guessing when nothing matches.
    """
    if not lines or not start_line:
        return None

    for index in range(min(start_line, len(lines)) - 1, -1, -1):
        match = _DECLARATION.match(lines[index])
        if match is None:
            continue
        name = next((v for v in match.groupdict().values() if v), None)
        if name and name not in {"if", "for", "while", "switch", "catch", "return"}:
            return name
    return None


def best_snippet(
    *,
    context_region_snippet: str | None,
    region_snippet: str | None,
    workspace: Path | None,
    file_path: str | None,
    start_line: int | None,
    end_line: int | None,
) -> tuple[str | None, str | None, str]:
    """Resolve the snippet and symbol for one finding.

    Returns ``(snippet, symbol, source)`` where `source` names which tier
    supplied the snippet — reported so a run that quietly fell back to
    positional identity is visible in the step summary rather than only in a
    trend line six weeks later.
    """
    lines = read_source_lines(workspace, file_path or "")
    symbol = infer_symbol(lines, start_line)

    if context_region_snippet and context_region_snippet.strip():
        return context_region_snippet[:MAX_SNIPPET_CHARS], symbol, "sarif-context"

    if region_snippet and region_snippet.strip():
        return region_snippet[:MAX_SNIPPET_CHARS], symbol, "sarif-region"

    from_disk = slice_snippet(lines or [], start_line, end_line)
    if from_disk:
        return from_disk, symbol, "workspace"

    return None, symbol, "none"
