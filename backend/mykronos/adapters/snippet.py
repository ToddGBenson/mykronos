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
3. The working tree on disk — read the file and slice the matched lines.
4. Nothing. Recorded as degradation, never disguised.

**`v3-snippet` (D-139, B-067).** The symbol is the declaration that
*encloses* the finding — bounded by indentation in Python and by braces
elsewhere, and never read out of a string literal or a comment — and a
snippet sliced from disk is the matched lines alone. Under `v2-snippet` both
were positional: the symbol was the first declaration-shaped line anywhere
above the finding, and the slice took two lines of context either side, so
an unrelated edit near or above a finding changed its identity.

The `v2` functions are kept, verbatim, for one purpose: `v2_identity` lets
the adapter say what a finding's old identity *was*, so ingestion can carry
the decisions recorded under it to the new one rather than strand them.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from mykronos.fingerprint import FINGERPRINT_V3_SNIPPET, IDENTITY_KEY

logger = logging.getLogger(__name__)

#: Lines of context either side when slicing from disk under `v2-snippet`.
#:
#: Kept only so the adapter can still say what a finding's `v2-snippet`
#: identity was (`v2_identity`). It is no longer part of any new identity: two
#: lines of context meant an edit two lines away from a finding changed its
#: hash (B-067).
V2_CONTEXT_LINES = 2

MAX_SNIPPET_CHARS = 20_000  # matches FindingSubmission.code_snippet

#: Declaration patterns for the languages CodeQL supports. Deliberately
#: shallow — this is a heuristic, not a parser. Under `v3-snippet` it is only
#: ever applied to text the scanners below have established is code: never to
#: a line inside a string literal or a comment, and only to a declaration
#: whose block is still open at the finding.
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

#: Keywords the Java/C# alternative can mistake for a method name.
_NOT_A_NAME = frozenset({"if", "for", "while", "switch", "catch", "return"})

#: A block header that is only a name and a parameter list: a JavaScript or
#: TypeScript class method (`render() {`), a shell function (`name() {`).
#: Tried only on the text directly before a `{`, never on a finding's own
#: line, where the same shape is an ordinary call.
_METHOD_HEADER = re.compile(
    r"""^\s*(?:(?:static|async|get|set|public|private|protected|readonly|override)\s+)*
        \#?(?P<name>[\w$-]+)\s*\((?:[^()]|\([^()]*\))*\)\s*(?::\s*[^{};=]+)?\s*$""",
    re.VERBOSE,
)
_NOT_A_METHOD = frozenset({*_NOT_A_NAME, "function", "with", "else", "do", "try", "finally"})

#: Python's two block-opening declarations, and nothing else. The Java/C#
#: alternative above is what read `stories` out of a TheHub docstring line
#: ("six stories (58504, ...") and gave it to three findings as their
#: enclosing function (B-067).
_PY_DECLARATION = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+(?P<name>\w+)")


@dataclass(frozen=True)
class _BraceSyntax:
    """Enough lexical knowledge of a brace language to tell code from text."""

    line_comment: str
    block_comment: tuple[str, str] | None
    quotes: str
    #: Quotes whose strings may run past the end of a line.
    multiline_quotes: str
    escape: str
    #: Whether a line-comment marker only counts after whitespace. Shell's `#`
    #: is a comment there and part of `${#var}` or `$#` anywhere else.
    comment_needs_boundary: bool = False


_C_STYLE = _BraceSyntax("//", ("/*", "*/"), "\"'`", "`", "\\")
#: `'a` is a Rust lifetime, not the start of a character literal.
_RUST = _BraceSyntax("//", ("/*", "*/"), '"', '"', "\\")
_SHELL = _BraceSyntax("#", None, "\"'", "\"'", "\\", comment_needs_boundary=True)
#: PowerShell escapes with a backtick, so `"C:\"` is a complete string.
_POWERSHELL = _BraceSyntax(
    "#", ("<#", "#>"), "\"'", "\"'", "`", comment_needs_boundary=True
)

_PYTHON = "python"

_LANGUAGES: dict[str, str | _BraceSyntax] = {
    ".py": _PYTHON,
    ".pyi": _PYTHON,
    **dict.fromkeys(
        (
            ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".java", ".cs",
            ".c", ".h", ".cc", ".cpp", ".hpp", ".kt", ".kts", ".swift", ".scala",
            ".php", ".dart", ".groovy",
        ),
        _C_STYLE,
    ),
    ".rs": _RUST,
    ".sh": _SHELL,
    ".bash": _SHELL,
    ".zsh": _SHELL,
    ".ps1": _POWERSHELL,
    ".psm1": _POWERSHELL,
}


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
    """The finding's own lines and nothing either side. 1-indexed, inclusive.

    No context lines (B-067): whatever is sliced is hashed, so context made an
    edit to an unrelated neighbouring line change the finding's identity.
    """
    return _slice(lines, start_line, end_line, context=0)


def slice_snippet_v2(
    lines: list[str], start_line: int | None, end_line: int | None
) -> str | None:
    """What `slice_snippet` returned under `v2-snippet`. Lineage only."""
    return _slice(lines, start_line, end_line, context=V2_CONTEXT_LINES)


def _slice(
    lines: list[str], start_line: int | None, end_line: int | None, *, context: int
) -> str | None:
    if not lines or not start_line or start_line < 1:
        return None

    # Tolerate endLine < startLine. It is malformed SARIF, but a tool that
    # emits it should still produce a usable snippet rather than a finding
    # that silently degrades to positional identity.
    effective_end = max(end_line or start_line, start_line)

    first = max(0, start_line - 1 - context)
    last = min(len(lines), effective_end + context)
    if first >= last:
        return None

    return "\n".join(lines[first:last])[:MAX_SNIPPET_CHARS]


def infer_symbol(
    lines: list[str] | None, start_line: int | None, file_path: str | None = None
) -> str | None:
    """The declaration enclosing the finding, or None (`v3-snippet`).

    - Python is bounded by indentation: only a `def` or `class` whose body
      the finding's statement sits in can name it. A module-level statement
      has no symbol, however many functions precede it.
    - Brace languages are bounded by braces: only a declaration whose block
      is still open at the finding can name it.
    - Neither ever reads a declaration out of a string literal or a comment.

    The language comes from the extension; one this does not know gets None
    rather than a guess, and the snippet still anchors the identity. What
    matters most is still determinism — the same file and line always give
    the same answer. Never raises.
    """
    if not lines or not start_line or start_line < 1 or not file_path:
        return None
    suffix = PurePosixPath(file_path.replace("\\", "/")).suffix.lower()
    language = _LANGUAGES.get(suffix)
    if language is None:
        return None
    try:
        if isinstance(language, _BraceSyntax):
            return _brace_symbol(lines, start_line, language)
        return _python_symbol(lines, start_line)
    except Exception:  # noqa: BLE001 — a heuristic must never fail a scan
        logger.debug("Symbol inference failed for %s:%s", file_path, start_line)
        return None


def infer_symbol_v2(lines: list[str] | None, start_line: int | None) -> str | None:
    """What `infer_symbol` returned under `v2-snippet`. Lineage only.

    Scans backwards, unbounded, for the first line matching a declaration
    pattern. Kept verbatim so `v2_identity` reproduces a finding's old
    identity exactly; never an input to a new one.
    """
    if not lines or not start_line:
        return None

    for index in range(min(start_line, len(lines)) - 1, -1, -1):
        name = _declared_name(lines[index])
        if name:
            return name
    return None


def _declared_name(text: str) -> str | None:
    match = _DECLARATION.match(text)
    if match is None:
        return None
    name = next((v for v in match.groupdict().values() if v), None)
    return None if name in _NOT_A_NAME else name


def _indent(line: str) -> int:
    expanded = line.expandtabs(8)
    return len(expanded) - len(expanded.lstrip())


def _python_statement_starts(lines: list[str], upto: int) -> list[bool]:
    """For each of the first `upto` lines, whether a statement begins on it.

    False inside a string literal (a docstring, a triple-quoted SQL block),
    inside an open bracket, after a backslash continuation, and for blank and
    comment-only lines: the lines whose indentation and text say nothing about
    which block the code is in.
    """
    starts: list[bool] = []
    quote: str | None = None
    depth = 0
    continued = False
    for line in lines[:upto]:
        stripped = line.strip()
        starts.append(
            quote is None
            and depth == 0
            and not continued
            and bool(stripped)
            and not stripped.startswith("#")
        )
        continued = False
        i, n = 0, len(line)
        while i < n:
            char = line[i]
            if quote is not None:
                if char == "\\":
                    i += 2
                elif line.startswith(quote, i):
                    i += len(quote)
                    quote = None
                else:
                    i += 1
                continue
            if char == "#":
                break
            if char in "\"'":
                triple = line[i : i + 3]
                quote = triple if triple in ('"""', "'''") else char
                i += len(quote)
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(0, depth - 1)
            elif char == "\\" and i == n - 1:
                continued = True
            i += 1
        if quote in ('"', "'"):
            # A one-quote string cannot cross a line. Malformed source; do not
            # let it swallow the rest of the file.
            quote = None
    return starts


def _python_symbol(lines: list[str], start_line: int) -> str | None:
    end = min(start_line, len(lines))
    starts = _python_statement_starts(lines, end)
    # The statement the finding is part of: a finding inside a multi-line call
    # or string belongs to the line that opened it.
    anchor = next((i for i in range(end - 1, -1, -1) if starts[i]), None)
    if anchor is None:
        return None
    match = _PY_DECLARATION.match(lines[anchor])
    if match:
        return match.group("name")
    limit = _indent(lines[anchor])
    for index in range(anchor - 1, -1, -1):
        if limit == 0:
            return None
        if not starts[index] or _indent(lines[index]) >= limit:
            continue
        match = _PY_DECLARATION.match(lines[index])
        if match:
            return match.group("name")
        # An `if`, `for`, `with` or `try` the finding sits in: keep climbing,
        # but only to something less indented than it.
        limit = _indent(lines[index])
    return None


def _brace_symbol(lines: list[str], start_line: int, syntax: _BraceSyntax) -> str | None:
    """The innermost named block still open at the start of the finding's line.

    Strings and comments are masked before anything is matched or a brace is
    counted. A block's name is read from its header — the code since the
    previous `;`, `{` or `}` — which may span lines (Allman braces, a long
    signature).
    """
    end = min(start_line, len(lines))
    stack: list[str | None] = []
    pending: list[str] = []
    quote: str | None = None
    block_end: str | None = None

    for index in range(end):
        line = lines[index]
        on_finding_line = index == end - 1
        begins_in_code = quote is None and block_end is None
        current: list[str] = []
        i, n = 0, len(line)
        while i < n:
            char = line[i]
            if block_end is not None:
                if line.startswith(block_end, i):
                    i += len(block_end)
                    block_end = None
                    current.append(" ")
                else:
                    i += 1
                continue
            if quote is not None:
                if line.startswith(syntax.escape, i):
                    i += len(syntax.escape) + 1
                elif char == quote:
                    quote = None
                    current.append(char)
                    i += 1
                else:
                    i += 1
                continue
            if syntax.block_comment and line.startswith(syntax.block_comment[0], i):
                block_end = syntax.block_comment[1]
                i += len(syntax.block_comment[0])
                continue
            if line.startswith(syntax.line_comment, i) and (
                not syntax.comment_needs_boundary or i == 0 or line[i - 1].isspace()
            ):
                break
            if char in syntax.quotes:
                quote = char
                current.append(char)
                i += 1
                continue
            if not on_finding_line and char in "{};":
                if char == "{":
                    stack.append(_block_name([*pending, "".join(current)]))
                elif char == "}" and stack:
                    stack.pop()
                pending, current = [], []
                i += 1
                continue
            current.append(char)
            i += 1
        if quote is not None and quote not in syntax.multiline_quotes:
            quote = None
        text = "".join(current)
        if on_finding_line:
            # A finding on a declaration's own line is about that declaration,
            # provided the line begins in code rather than inside a string.
            name = _declared_name(text) if begins_in_code else None
            if name:
                return name
        elif text.strip():
            pending.append(text)

    return next((name for name in reversed(stack) if name), None)


def _block_name(header: list[str]) -> str | None:
    """The name a block's header declares, or None for `if`, an object, etc."""
    named = next((name for name in map(_declared_name, header) if name), None)
    if named:
        return named
    match = _METHOD_HEADER.match(" ".join(part.strip() for part in header))
    if match and match.group("name") not in _NOT_A_METHOD:
        return match.group("name")
    return None


@dataclass(frozen=True)
class ResolvedSnippet:
    """One finding's snippet and symbol, and what they were under `v2-snippet`."""

    snippet: str | None
    symbol: str | None
    #: Which tier supplied the snippet. Diagnostic only.
    source: str
    v2_snippet: str | None
    v2_symbol: str | None


def best_snippet(
    *,
    context_region_snippet: str | None,
    region_snippet: str | None,
    workspace: Path | None,
    file_path: str | None,
    start_line: int | None,
    end_line: int | None,
) -> ResolvedSnippet:
    """Resolve the snippet and symbol for one finding.

    `source` is diagnostic only. It used to drive the churn warning, and that
    was #325: "no snippet" is not the condition identity degrades on — a
    package name or a symbol anchors a finding just as well, and a finding
    with no file at all is keyed on rule and title. The warning now asks
    `compute_finding_id` instead, via `base.warn_if_identity_degrades`.
    """
    lines = read_source_lines(workspace, file_path or "")
    symbol = infer_symbol(lines, start_line, file_path)
    v2_symbol = infer_symbol_v2(lines, start_line)

    for supplied, source in (
        (context_region_snippet, "sarif-context"),
        (region_snippet, "sarif-region"),
    ):
        if supplied and supplied.strip():
            tool_snippet = supplied[:MAX_SNIPPET_CHARS]
            return ResolvedSnippet(tool_snippet, symbol, source, tool_snippet, v2_symbol)

    from_disk = slice_snippet(lines or [], start_line, end_line)
    if from_disk:
        return ResolvedSnippet(
            from_disk,
            symbol,
            "workspace",
            slice_snippet_v2(lines or [], start_line, end_line),
            v2_symbol,
        )

    return ResolvedSnippet(None, symbol, "none", None, v2_symbol)


def v2_identity(
    raw: dict[str, Any] | None,
    *,
    snippet: str | None,
    symbol: str | None,
    v2_snippet: str | None,
    v2_symbol: str | None,
    v2_file_path: str | None = None,
) -> dict[str, Any]:
    """`raw` with the `v3-snippet` marker, and the `v2-snippet` inputs where
    they differ from the ones submitted.

    `v2_file_path` is the path the finding was stored under before its
    normaliser learned to strip a Concourse build directory (TheHub #60734,
    D-160). When it is given, `v2_snippet` and `v2_symbol` are what resolving
    *that* path produced, because those are the inputs of the id the finding
    actually has in the lake -- the predecessor is whatever was stored, not
    what an older rule would have computed from the corrected path.

    The finding's id is still computed only by the API (spec 05 §5); this
    carries the two inputs it cannot recompute, because computing the old
    symbol needs the source file and the API never has it. Ingestion hashes
    them into the id the finding had under `v2-snippet` and moves what was
    decided about that id onto this one (D-139).

    A key is present only when its value changed, so the common case — a
    tool-supplied snippet whose enclosing symbol was already right — adds a
    few bytes rather than a second copy of the snippet.
    """
    marker: dict[str, Any] = {"rule": FINGERPRINT_V3_SNIPPET}
    if v2_symbol != symbol:
        marker["v2_symbol"] = v2_symbol
    if v2_snippet != snippet:
        marker["v2_code_snippet"] = v2_snippet
    if v2_file_path is not None:
        marker["v2_file_path"] = v2_file_path
    return {**(raw if isinstance(raw, dict) else {}), IDENTITY_KEY: marker}
