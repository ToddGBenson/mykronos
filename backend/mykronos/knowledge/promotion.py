"""Tier promotion, and the policy proposal (spec 11 §2, §7, §9).

Two different acts, and spec 11 originally conflated them:

**Moving an entry between tiers** is a statement about what we have observed —
this rule is noise in four repos, not just one. It moves a row between JSONL
files on local disk, so there is no git repository to open a pull request
against. It is a proposal record, approved in the dashboard, audit-logged.

**Changing the Oracle policy** is a decision about what we will do. It edits
`oracle-policy-v1.yaml`, which *is* checked in, and it changes how every
repository in the estate is scored. That one gets a draft pull request.

Nothing here writes to a target tier or a policy file on its own. The
scheduled job finds candidates; a person decides.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mykronos.knowledge.store import KnowledgeStore

logger = logging.getLogger(__name__)

NEXT_TIER = {"personal": "team", "team": "org"}


@dataclass
class PromotionCandidate:
    """A pattern seen independently in enough places to be worth generalising."""

    subject: str
    source_type: str
    from_tier: str
    to_tier: str
    repos: list[str]
    mean_confidence: float
    total_observations: int
    reasons: list[str] = field(default_factory=list)
    #: How many contributing entries were marked `restricted`, and so had
    #: their reasons withheld from this candidate. Reported rather than
    #: hidden: a reviewer weighing a proposal is entitled to know that some of
    #: the evidence for it is not shown.
    reasons_withheld: int = 0

    @property
    def project_count(self) -> int:
        return len(self.repos)

    def summary(self) -> str:
        return (
            f"{self.subject} — seen in {self.project_count} repositories "
            f"({self.total_observations} observations, mean confidence "
            f"{self.mean_confidence:.2f})"
        )


def find_cross_project_candidates(
    store: KnowledgeStore,
    *,
    min_projects: int = 2,
    min_confidence: float = 0.7,
    as_of: datetime | None = None,
) -> list[PromotionCandidate]:
    """Patterns independently confirmed across repositories (spec 11 §9).

    Independence is the point, and it is why the grouping is by *repo* rather
    than by observation count. Ten dismissals of one rule in one repository is
    one team's opinion held firmly; three dismissals across three repositories
    is a rule that is probably noisy everywhere. Only the second generalises.

    **`restricted` entries contribute the observation but not the prose.**
    An earlier version of this excluded them entirely, which made promotion
    dead on arrival: `restricted` is the default for a captured dismissal, so
    nothing was ever a candidate and the feature was inert while appearing to
    work.

    The split that actually matches spec 11 §3 is finer. "Rule X was dismissed
    in repositories A and B" is an observation about a *rule*, and it is what
    generalises. "Because our payments vendor ships this pattern in every
    module" is somebody's free text about their own codebase, and it is what
    `restricted` protects. So a restricted entry counts toward the recurrence
    and its reasons are withheld — with the count of withheld reasons
    reported, because a reviewer weighing thin evidence should know some of it
    is not shown.
    """
    to_tier = NEXT_TIER.get(store.tier)
    if to_tier is None:
        return []

    grouped: dict[tuple[str, str], list[tuple[Any, float]]] = defaultdict(list)
    for entry, confidence in store.active_entries(
        min_confidence=min_confidence, as_of=as_of
    ):
        # An unreasoned entry contributes nothing at all: spec 11 §4 bars it
        # from promotion, and it is not evidence of anything beyond a click.
        if not entry.has_reason:
            continue
        if entry.repo_full_name is None:
            continue
        grouped[(entry.source_type, entry.subject)].append((entry, confidence))

    candidates = []
    for (source_type, subject), rows in sorted(grouped.items()):
        repos = sorted({entry.repo_full_name for entry, _ in rows if entry.repo_full_name})
        if len(repos) < min_projects:
            continue
        reasons: list[str] = []
        withheld = 0
        for entry, _ in rows:
            if entry.sensitivity == "restricted":
                withheld += 1
                continue
            reasons.extend(r for r in entry.reasons if r not in reasons)
        candidates.append(
            PromotionCandidate(
                subject=subject,
                source_type=source_type,
                from_tier=store.tier,
                to_tier=to_tier,
                repos=repos,
                mean_confidence=sum(c for _, c in rows) / len(rows),
                total_observations=sum(e.observations for e, _ in rows),
                reasons=reasons[:10],
                reasons_withheld=withheld,
            )
        )
    return candidates


def render_policy_proposal(candidates: list[PromotionCandidate]) -> str | None:
    """The body of a draft PR against `oracle-policy-v1.yaml` (spec 11 §7).

    Returns None when there is nothing to propose, so a scheduled job that
    finds nothing opens nothing — a weekly empty pull request is how people
    learn to ignore the ones that matter.

    Deliberately a *description of a change*, not a diff. The policy file is
    small, human-edited and carries comments that explain each number; a
    machine-generated patch would either lose those or have to reproduce them,
    and a reviewer reading "here is the evidence, here is the line to change"
    is better placed to judge than one reading a YAML hunk.
    """
    eligible = [c for c in candidates if c.source_type == "finding_dismissal"]
    if not eligible:
        return None

    lines = [
        "## Proposed Oracle policy change",
        "",
        "The rules below have been dismissed as false positives, **with "
        "written reasons**, in more than one repository independently. That "
        "is the bar spec 11 §2 sets for a learning to generalise: repeated "
        "dismissal in a single repository is one team's opinion held firmly, "
        "which is not the same thing.",
        "",
        "Nothing has been applied. Merging this pull request is what changes "
        "how every repository is scored.",
        "",
        "| Rule | Repositories | Observations | Mean confidence |",
        "| --- | ---: | ---: | ---: |",
    ]
    for candidate in eligible:
        lines.append(
            f"| `{candidate.subject}` | {candidate.project_count} | "
            f"{candidate.total_observations} | {candidate.mean_confidence:.2f} |"
        )

    lines += ["", "### What people actually said", ""]
    for candidate in eligible:
        lines.append(f"**`{candidate.subject}`** — {', '.join(candidate.repos)}")
        for reason in candidate.reasons[:5]:
            lines.append(f"- {reason}")
        if candidate.reasons_withheld:
            lines.append(
                f"- _{candidate.reasons_withheld} further "
                f"reason{'s' if candidate.reasons_withheld != 1 else ''} withheld: "
                "the entr"
                f"{'ies are' if candidate.reasons_withheld != 1 else 'y is'} marked "
                "`restricted` (spec 11 §3). The observation still counts toward "
                "the recurrence above._"
            )
        if not candidate.reasons:
            lines.append(
                "- _No reason may be shown for this rule. Weigh the proposal "
                "on the recurrence alone, or ask the repositories involved._"
            )
        lines.append("")

    lines += [
        "### Suggested change",
        "",
        "Add these rule ids to a `dampened_rules` list under "
        "`modifiers.false_positive_dampening` in `oracle-policy-v1.yaml`, and "
        "**bump `version`** — historical decisions keep the version they were "
        "scored with, so a past decision stays reproducible (spec 09 §10).",
        "",
        "```yaml",
        "modifiers:",
        "  false_positive_dampening:",
        "    dampened_rules:",
    ]
    lines += [f"      - {candidate.subject}" for candidate in eligible]
    lines += [
        "```",
        "",
        "### Before merging",
        "",
        "- Re-baseline `tests/test_oracle_golden.py`. It pins exact scores, so "
        "a policy edit that does not update them fails the build — which is "
        "the point.",
        "- Check the reasons above are about the *rule* rather than about one "
        "codebase's shape. \"Our generated directory trips this\" is an "
        "argument for a path exclusion, not for quietening the rule "
        "everywhere.",
        "",
        "<sub>Opened by the Mykronos promotion job. Never auto-applied "
        "(spec 11 §2, §10).</sub>",
    ]
    return "\n".join(lines)
