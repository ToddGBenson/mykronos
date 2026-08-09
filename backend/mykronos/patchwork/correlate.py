"""Toxic combinations (spec 08 §2, stage 3; §5).

A set of findings that together represent more risk than any of them alone.
The canonical example is spec 08's own: an unauthenticated endpoint plus a
SQL-injectable query in the same request path. Separately, two medium
findings. Together, an unauthenticated database.

Two design choices worth stating:

**Rules are data, not code.** spec 08 §5 requires admins to be able to add
rules "without code changes", so a rule is a small declarative record — which
capabilities and rule-id patterns must co-occur, and within what scope. The
built-in set is deliberately tiny; a large default set of speculative
combinations would produce noise that discredits the real ones.

**A detected combination stops the individual fixes.** Findings inside a
combination are not fixed in isolation, because fixing one half of a toxic
pair can make the situation *look* resolved while the composite risk remains.
It is also spec 08 §8's conflicting-pull-request case: two fixes touching the
same request path produce two draft PRs that cannot both merge cleanly.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CombinationRule:
    """One declarative correlation rule (spec 08 §5)."""

    rule_id: str
    name: str
    #: Regexes, each of which must match at least one finding's rule_id for
    #: the combination to fire.
    requires: tuple[str, ...]
    #: `file` means the matches must be in the same file; `repo` means
    #: anywhere in the repository. `file` is the default because proximity is
    #: most of what makes a combination toxic rather than coincidental.
    scope: str = "file"
    explanation: str = ""


@dataclass(frozen=True)
class Combination:
    combination_id: str
    rule_id: str
    finding_ids: frozenset[str]
    rationale: str


#: Small on purpose. Every rule here is one where the composite risk is
#: genuinely different in kind from its parts, not merely larger.
BUILT_IN_RULES: tuple[CombinationRule, ...] = (
    CombinationRule(
        rule_id="unauth-injectable",
        name="Unauthenticated injectable endpoint",
        requires=(r"CWE-89|sql.?inj", r"CWE-306|CWE-287|missing.?auth|unauth"),
        scope="file",
        explanation=(
            "An injectable query and a missing authentication check in the "
            "same file. Either alone is serious; together they are an "
            "unauthenticated path to the database, and fixing only one of "
            "them leaves that true while making the code look attended to."
        ),
    ),
    CombinationRule(
        rule_id="secret-and-public-surface",
        name="Committed credential on a public surface",
        requires=(r"generic-api-key|aws-|secret|credential", r"CWE-306|unauth|public"),
        scope="file",
        explanation=(
            "A committed credential in a file that also has an "
            "unauthenticated surface. The credential is already leaked by "
            "being in git history; the unauthenticated surface is how someone "
            "finds out it is worth using."
        ),
    ),
)


def _matches(pattern: str, finding: dict[str, Any]) -> bool:
    haystack = f"{finding.get('rule_id', '')} {finding.get('title', '')}"
    return re.search(pattern, haystack, re.IGNORECASE) is not None


def combination_id(rule_id: str, finding_ids: frozenset[str]) -> str:
    """Derived from the rule and its members, so the same combination detected
    twice is the same combination (spec 08 §4)."""
    material = rule_id + "\x00" + "\x00".join(sorted(finding_ids))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def detect(
    findings: list[dict[str, Any]], rules: tuple[CombinationRule, ...] = BUILT_IN_RULES
) -> list[Combination]:
    """Every toxic combination present in this set of findings.

    A finding may appear in at most one combination — the first rule that
    claims it wins, in rule order. Allowing overlap would mean one finding
    generating several draft pull requests, which is the flooding spec 08 §5's
    backpressure exists to prevent, arriving by a different route.
    """
    claimed: set[str] = set()
    combinations: list[Combination] = []

    for rule in rules:
        groups: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            if str(finding["finding_id"]) in claimed:
                continue
            key = str(finding.get("file_path") or "") if rule.scope == "file" else "*"
            groups.setdefault(key, []).append(finding)

        for key, group in sorted(groups.items()):
            if rule.scope == "file" and not key:
                continue
            members: set[str] = set()
            for pattern in rule.requires:
                hit = next((f for f in group if _matches(pattern, f)), None)
                if hit is None:
                    members.clear()
                    break
                members.add(str(hit["finding_id"]))
            if len(members) < len(rule.requires):
                continue

            frozen = frozenset(members)
            claimed |= members
            where = f"in `{key}`" if rule.scope == "file" else "in this repository"
            combinations.append(
                Combination(
                    combination_id=combination_id(rule.rule_id, frozen),
                    rule_id=rule.rule_id,
                    finding_ids=frozen,
                    rationale=(
                        f"**{rule.name}** {where}. {rule.explanation} "
                        "Patchwork has not generated a fix: these need to be "
                        "addressed together, and fixing one in isolation would "
                        "close the finding without closing the risk."
                    ),
                )
            )

    return combinations
