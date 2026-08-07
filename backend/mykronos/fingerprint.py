"""Deterministic finding identity.

Implements specs/05-datalake.md §5. This module is the *only* place a
`finding_id` is ever produced — clients never supply one, so the rule has
exactly one implementation and stays auditable.

The property this module exists to guarantee: a finding survives unrelated
edits above it. Inserting an import at the top of a file must not retire the
finding and re-report it as new, because doing so destroys `first_seen_at`
and every metric derived from it.
"""

from __future__ import annotations

import hashlib
import re

FINGERPRINT_V2_SNIPPET = "v2-snippet"
"""Intended path: identity anchored to the code itself."""

FINGERPRINT_V1_LINE = "v1-line"
"""Degraded fallback when an adapter supplies no snippet or symbol.

Rows carrying this version are churn-prone by construction. They are counted
as a data-quality metric rather than being silently accepted as equivalent.
"""

FINGERPRINT_DEPENDENCY = "v2-package"
"""Dependency findings key on the package, not a source location."""

FINGERPRINT_REPO_LEVEL = "v2-repo"
"""Findings with neither a file nor a package (e.g. cloud posture checks)."""

# Field separator: a unit-separator byte cannot appear in any of the inputs we
# hash, so field boundaries are unambiguous and two different tuples can never
# serialise to the same string.
_SEP = "\x1f"
_NULL = "\x00<none>"

_WHITESPACE_RUN = re.compile(r"\s+")


def normalize_snippet(snippet: str) -> str:
    """Reduce a code snippet to a form stable under reformatting.

    Strips leading/trailing whitespace per line, collapses internal whitespace
    runs to a single space, and drops blank lines.

    Deliberately *not* language-aware — no comment stripping, no parsing, no
    case folding. Being dumb here is the point: a finding should survive
    reindentation and code motion, but must be correctly retired when the
    vulnerable code itself changes. Anything cleverer starts making judgement
    calls about which source changes are semantically meaningful, which is not
    a decision the dedup layer is entitled to make.
    """
    lines = (_WHITESPACE_RUN.sub(" ", line).strip() for line in snippet.splitlines())
    return "\n".join(line for line in lines if line)


def _digest(*parts: str | None) -> str:
    joined = _SEP.join(_NULL if p is None else p for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def compute_finding_id(
    *,
    repo_full_name: str,
    capability: str,
    rule_id: str,
    file_path: str | None = None,
    symbol: str | None = None,
    code_snippet: str | None = None,
    line_start: int | None = None,
    package_name: str | None = None,
    title: str | None = None,
) -> tuple[str, str]:
    """Return ``(finding_id, fingerprint_version)``.

    Dispatch follows the table in spec 05 §5:

    - ``package_name`` set  -> dependency finding, keyed on the package.
      Excludes ``package_version``: a CVE that still applies after a bump is
      the same finding; one that no longer applies is retired by the normal
      absence-reconciliation path.
    - ``file_path`` set     -> code finding, keyed on the normalized snippet
      and enclosing symbol. Falls back to ``line_start`` only when the adapter
      gave us neither, and says so via the returned version.
    - neither               -> repo-level finding, keyed on rule and title.
    """
    if package_name:
        return (
            _digest("dep", repo_full_name, capability, rule_id, package_name),
            FINGERPRINT_DEPENDENCY,
        )

    if file_path:
        normalized = normalize_snippet(code_snippet) if code_snippet else ""
        if normalized or symbol:
            return (
                _digest(
                    "code", repo_full_name, capability, rule_id, file_path, symbol, normalized
                ),
                FINGERPRINT_V2_SNIPPET,
            )
        # Degraded: no anchor in the code itself, so identity is positional and
        # will churn on unrelated edits. Recorded, not hidden.
        return (
            _digest(
                "code-line",
                repo_full_name,
                capability,
                rule_id,
                file_path,
                None if line_start is None else str(line_start),
            ),
            FINGERPRINT_V1_LINE,
        )

    return (
        _digest("repo", repo_full_name, capability, rule_id, title),
        FINGERPRINT_REPO_LEVEL,
    )
