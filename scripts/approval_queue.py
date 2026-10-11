"""The approval queue's decisions, kept where they can be tested (D-149).

`scripts/approval-queue.ps1` does the waiting, rebasing and merging. Every
choice it makes that is not I/O lives here, so a test can pin it:

- **order**: which open pull requests the queue takes, in what order, and
  which it refuses (a draft gets no request; a branch named `main` is never
  rewritten; a fork's branch cannot be pushed).
- **route**: who decides a request - the operator, or the platform-started
  reviewer. Governance is always the operator. The queue never approves as an
  agent itself: "agent" here means "ask the platform to start its reviewer".
- **check-decisions**: whether a union-merged `docs/DECISIONS.md` is still an
  append-only log - main's entries untouched and in place, the branch's after
  them, no number taken twice.
- **summary**: the evidence lines the operator is shown, and a default
  rationale built from that evidence.

CLI: `python approval_queue.py <command> <input.json>` prints JSON.
`check-decisions <base.md> <merged.md>` takes two Markdown paths, and
`check-decisions-git <repo> <merged.md>` reads the base from origin/main.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

DUTY = "pull_request_merge"

#: Branches the queue never force-pushes, whatever a PR says its head is.
PROTECTED_BRANCHES = frozenset({"main", "master"})

#: The tiers a delegation may cover. Governance is a person only (approval
#: policy `pull_request_merge.tiers.governance`), so it is never routed to the
#: reviewer even if a delegation claimed it.
DELEGABLE_TIERS = frozenset({"production", "routine"})

HEADING = re.compile(r"^## (D-\d+) — (.*)$", re.MULTILINE)
CONFLICT_MARKER = re.compile(r"^(<{7}|={7}|>{7})( |$)", re.MULTILINE)

MIN_RATIONALE_CHARS = 20


# -- Ordering -----------------------------------------------------------------


def order(prs: list[dict[str, Any]], numbers: list[int] | None) -> dict[str, Any]:
    """The queue, and every PR left out of it with the reason.

    With `numbers`, that order is kept exactly: the operator chose it. Without,
    every open PR is taken oldest first, which is the order they were written
    against main and so the order least likely to conflict.
    """
    by_number = {int(p["number"]): p for p in prs}
    skipped: list[dict[str, Any]] = []
    if numbers:
        wanted: list[dict[str, Any]] = []
        seen: set[int] = set()
        for n in numbers:
            if n in seen:
                continue
            seen.add(n)
            if n not in by_number:
                skipped.append(
                    {"number": n, "reason": "not open (merged, closed or unknown)"}
                )
            else:
                wanted.append(by_number[n])
    else:
        wanted = sorted(
            prs, key=lambda p: (str(p.get("createdAt", "")), int(p["number"]))
        )

    queue: list[int] = []
    for p in wanted:
        reason = refusal(p)
        if reason:
            skipped.append({"number": int(p["number"]), "reason": reason})
        else:
            queue.append(int(p["number"]))
    return {"queue": queue, "skipped": skipped}


def refusal(pr: dict[str, Any]) -> str | None:
    """Why the queue will not touch this PR, or `None`."""
    branch = str(pr.get("headRefName") or "")
    base = str(pr.get("baseRefName") or "main")
    if not branch:
        return "no head branch reported"
    if branch in PROTECTED_BRANCHES or branch == base:
        return f"refusing to rewrite '{branch}': the queue only force-pushes feature branches"
    if pr.get("isCrossRepository"):
        return "head is in a fork; the queue cannot push its branch"
    if pr.get("isDraft"):
        return "draft: the platform opens no approval request for a draft"
    if base != "main":
        return f"targets '{base}', not main"
    return None


# -- Routing ------------------------------------------------------------------


def route(
    tier: str,
    reviewer_mode: str | None,
    delegations: list[dict[str, Any]],
) -> dict[str, str]:
    """`operator` or `agent`, with the reason a person reads in the log.

    `agent` only when all three hold: the tier is delegable, the reviewer is
    `live`, and an active delegation covers this duty and tier. Anything else
    falls back to the operator - a request is never left with nobody to ask.
    """
    if tier not in DELEGABLE_TIERS:
        return {
            "route": "operator",
            "reason": f"tier '{tier}' is approved by a person only",
        }
    if (reviewer_mode or "").strip().lower() != "live":
        return {
            "route": "operator",
            "reason": f"the reviewer is in '{reviewer_mode or 'unknown'}' mode, not live",
        }
    for d in delegations:
        if d.get("active") and d.get("duty") == DUTY and tier in (d.get("tiers") or []):
            return {
                "route": "agent",
                "reason": f"delegation {d.get('id')} covers '{tier}'",
            }
    return {"route": "operator", "reason": f"no active delegation covers '{tier}'"}


# -- The decision log after a union merge ---------------------------------------


def headings(text: str) -> list[str]:
    return [number for number, _ in HEADING.findall(text)]


def check_decisions(base: str, merged: str) -> list[str]:
    """Problems with a union-merged decision log, or an empty list.

    `base` is main's file, `merged` is the rebased branch's. `merge=union`
    keeps both sides' lines without asking, so it can only be trusted after
    the result is read back:

    - main's headings come first, unchanged and in main's order. A union of
      two appends puts main's lines first; anything else means it interleaved.
    - the branch's new headings come after them, each a number main does not
      already use, none twice, ascending among themselves.

    Global numeric order is not required, and could not be: numbers are taken
    when a PR is written and land in merge order, so D-139 already precedes
    D-137 on main. Duplicates main already carries (D-046 to D-048, see D-082)
    are not this merge's to fix and are not reported.
    """
    problems: list[str] = []
    if CONFLICT_MARKER.search(merged):
        problems.append("the merged log still contains conflict markers")
    old = headings(base)
    new = headings(merged)
    if not old:
        # A log with no readable headings would check clean against anything.
        problems.append(
            "main's decision log has no readable D- headings; nothing was checked"
        )
        return problems
    if new[: len(old)] != old:
        problems.append(
            "main's entries are not intact at the head of the merged log: the union "
            "merge interleaved or dropped them"
        )
        return problems
    added = new[len(old) :]
    taken = set(old)
    reused = sorted({n for n in added if n in taken})
    if reused:
        problems.append(
            "the branch adds numbers main already uses: "
            + ", ".join(reused)
            + ". Renumber the branch's entry to the next free number."
        )
    twice = sorted(n for n, c in Counter(added).items() if c > 1)
    if twice:
        problems.append("the branch adds the same number twice: " + ", ".join(twice))
    nums = [int(n.split("-")[1]) for n in added]
    if nums != sorted(nums):
        problems.append(
            "the branch's new entries are out of numeric order: " + ", ".join(added)
        )
    return problems


# -- What the operator is shown ---------------------------------------------------


def summary(request: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """The lines a batch prompt shows for one request, and a default rationale."""
    files = list(evidence.get("files") or [])
    classes = Counter(str(f.get("class", "?")) for f in files)
    adds = sum(int(f.get("additions") or 0) for f in files)
    dels = sum(int(f.get("deletions") or 0) for f in files)
    sha = str(evidence.get("head_sha", ""))[:8]
    number = evidence.get("number", "?")
    title = str(evidence.get("title", "")).strip()
    class_text = ", ".join(f"{c} {n}" for c, n in sorted(classes.items())) or "no files"
    lines = [
        f"#{number} {title}",
        (
            f"  tier {request.get('tier')} | head {sha} | requested by "
            f"{request.get('requested_by')} ({request.get('requester_kind')})"
        ),
        f"  {len(files)} file(s): {class_text}; +{adds}/-{dels}",
    ]
    for f in files:
        flags = []
        if f.get("patch_truncated"):
            flags.append("patch truncated")
        if f.get("binary_or_unrendered"):
            flags.append("no patch")
        if f.get("previous_path"):
            flags.append(f"from {f['previous_path']}")
        extra = f" ({'; '.join(flags)})" if flags else ""
        lines.append(
            f"    [{f.get('class')}] {f.get('status')} {f.get('path')} "
            f"+{f.get('additions')}/-{f.get('deletions')}{extra}"
        )
    if evidence.get("files_listing_incomplete"):
        lines.append(
            "  file listing INCOMPLETE: GitHub truncated it; classed as the strictest"
        )
    rationale = (
        f"Read the evidence for #{number} at {sha} ({title[:80]}): {len(files)} file(s), "
        f"{class_text}, +{adds}/-{dels}. The diff matches the stated purpose and widens "
        "no agent's authority."
    )
    if len(rationale) < MIN_RATIONALE_CHARS:  # cannot happen with the text above
        rationale = rationale.ljust(MIN_RATIONALE_CHARS, ".")
    return {"lines": lines, "default_rationale": rationale}


# -- CLI ----------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write(__doc__ or "")
        return 2
    command = argv[1]
    if command == "check-decisions":
        base = Path(argv[2]).read_text(encoding="utf-8")
        merged = Path(argv[3]).read_text(encoding="utf-8")
        out: Any = {"problems": check_decisions(base, merged)}
    elif command == "check-decisions-git":
        # Main's log read as bytes from git, so no shell decodes it on the way.
        shown = subprocess.run(
            ["git", "-C", argv[2], "show", "origin/main:docs/DECISIONS.md"],
            capture_output=True,
            check=True,
        )
        merged = Path(argv[3]).read_text(encoding="utf-8")
        out = {"problems": check_decisions(shown.stdout.decode("utf-8"), merged)}
    else:
        data = json.loads(Path(argv[2]).read_text(encoding="utf-8-sig"))
        if command == "order":
            out = order(data.get("prs") or [], data.get("numbers") or None)
        elif command == "route":
            out = route(
                data["tier"], data.get("reviewer_mode"), data.get("delegations") or []
            )
        elif command == "summary":
            out = summary(data["request"], data["evidence"])
        else:
            sys.stderr.write(f"unknown command {command!r}\n")
            return 2
    sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
