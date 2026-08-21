"""Learning from a fix somebody closed (spec 25 §3.3).

The Remediation tab has flagged closed-unmerged pull requests for a while,
with a tooltip asking exactly the right question — *"worth asking whether the
fixes were wrong or simply unwanted"* — and then nothing asked it. A dismissed
finding teaches the Knowledge Store; a rejected fix taught nothing, though
both are a human verdict on machine output.

**Two codes that pull in opposite directions.** `fix_was_wrong` says the
change was incorrect, and should stop this fixer offering the same change for
the same rule here. `fix_was_unwanted` says the change was fine and the timing
or the priority was not — a scheduling disagreement, which must dampen nothing
at all. Collapsing them into "rejected" would make a team that defers work
look like a team whose fixer is broken.

**Asked on the pull request, not in this dashboard.** The moment somebody
closes a fix they are in GitHub, and a form they would have to come here to
fill in is a form nobody fills in. Patchwork's draft body carries a line to
edit; the webhook reads the body it is given on close. A reason nobody wrote
is recorded as `unstated` rather than guessed at.

**Never dampens the finding.** A rejected fix says nothing about whether the
vulnerability is real. Entries are written as `remediation_outcome`, and
`dampening.dampened_rules` only ever reads `finding_dismissal` — so "we did
not want this patch" cannot become "this was a false positive" by any path.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

#: What a closer may say, and what each one does.
FIX_WAS_WRONG = "fix_was_wrong"
FIX_WAS_UNWANTED = "fix_was_unwanted"
UNSTATED = "unstated"
REJECTION_CODES = (FIX_WAS_WRONG, FIX_WAS_UNWANTED)

#: The marker Patchwork writes into every draft body, and reads back out.
#: Deliberately an HTML comment plus a visible line: the comment is a stable
#: anchor a person will not accidentally reword, and the visible line is what
#: tells them the field exists at all.
REJECTION_MARKER = "<!-- mykronos:rejection-reason -->"

_REASON = re.compile(
    r"^\s*reason:\s*(" + "|".join(REJECTION_CODES) + r")\b[ \t]*(.*)$",
    re.IGNORECASE | re.MULTILINE,
)

#: How many `fix_was_wrong` verdicts for the same (repo, rule, fixer) before
#: this fixer stops offering that fix here.
#:
#: Two, not one. One rejection is a person's judgement about one diff and may
#: be about that file rather than about the fixer; two is a pattern, and the
#: cost of being wrong in this direction is only that a fix has to be written
#: by hand.
REJECTION_FLOOR = 2


def rejection_prompt() -> str:
    """The block Patchwork appends to every draft it opens."""
    return (
        f"{REJECTION_MARKER}\n"
        "### If you close this without merging\n"
        "\n"
        "Edit this line so Mykronos learns from it, then close:\n"
        "\n"
        f"`reason: {FIX_WAS_WRONG}` — the change is incorrect, or\n"
        f"`reason: {FIX_WAS_UNWANTED}` — the change is fine, we do not want it now.\n"
        "\n"
        "Anything after the code is kept as the written reason. Nothing here "
        "is required; an unstated reason is recorded as such rather than "
        "guessed at."
    )


def parse_rejection(body: str | None) -> tuple[str, str]:
    """`(code, reason_text)` from a closed pull request's body.

    Returns `(UNSTATED, "")` when nobody edited the line, which is the common
    case and is not a failure. Only the first stated code is read: a body with
    both is somebody who edited carelessly, and taking the first is the same
    rule GitHub applies to its own keyword parsing.
    """
    if not body:
        return (UNSTATED, "")
    match = _REASON.search(body)
    if match is None:
        return (UNSTATED, "")
    return (match.group(1).lower(), match.group(2).strip())


def rejection_count(
    catalog: Catalog, *, repo_full_name: str, rule_id: str, fixer_name: str
) -> int:
    """How often this fixer's fix for this rule has been called wrong here.

    Scoped to the repository on purpose. A fixer that is wrong about a rule in
    one codebase — a vendored tree, an unusual manifest layout — is not
    thereby wrong about it everywhere, and a fleet-wide veto learned from one
    repository would be the platform generalising from a sample of one.
    """
    if not catalog.all_files("remediation_events"):
        return 0
    rows = catalog.query(
        """
        SELECT count(*)
        FROM remediation_events e
        JOIN findings f ON f.finding_id = e.finding_id
        WHERE e.repo_full_name = ?
          AND f.rule_id = ?
          AND e.fixer_name = ?
          AND e.rejection_reason_code = ?
        """,
        [repo_full_name, rule_id, fixer_name, FIX_WAS_WRONG],
    )
    return int(rows[0][0]) if rows else 0


def is_dampened(
    catalog: Catalog, *, repo_full_name: str, rule_id: str, fixer_name: str
) -> tuple[bool, int]:
    """`(should_skip, count)` for one (repo, rule, fixer)."""
    count = rejection_count(
        catalog, repo_full_name=repo_full_name, rule_id=rule_id, fixer_name=fixer_name
    )
    return (count >= REJECTION_FLOOR, count)


def capture_reason(
    store: Any,
    *,
    repo_full_name: str,
    rule_id: str,
    fixer_name: str | None,
    code: str,
    reason: str,
) -> Any:
    """Record the verdict as a learning (spec 11 §4).

    Written as `remediation_outcome`, which `dampening.dampened_rules` does not
    read — so a rejected fix can never lower a finding's standing.
    """
    if code == UNSTATED:
        return None
    subject = f"{rule_id} / {fixer_name or 'unknown fixer'}"
    statement = (
        f"A Patchwork fix for {subject} was closed unmerged as "
        f"{code.replace('_', ' ')}."
    )
    return store.add_entry(
        source_type="remediation_outcome",
        subject=subject,
        source_ref=f"rejected_fix:{repo_full_name}:{rule_id}",
        text=statement,
        reason=reason,
        repo_full_name=repo_full_name,
    )
