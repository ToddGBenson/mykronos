"""One finding, with everything the platform knows about it (B-032).

A finding's story was spread across eleven surfaces. Deciding what to do about
a single one meant visiting five pages, and three of the facts that would
change the decision — whether a fix exists, whether the lane can close it,
whether the code is reachable — were not on the page where the decision was
made.

**This is an assembly, not a new source of truth.** Every block reads a service
that already existed: guidance groups by change, supply chain knows fixed
versions, scan health knows whether a lane is reporting, threat intel knows
EPSS. Nothing here recomputes any of them, because two implementations of
"which findings does this fix close" would eventually disagree and both would
look right.

**One block is genuinely new.** "Can it close?" existed nowhere at finding
level — it was inferable from scan health if you knew to go and look. Stating
it here is what stops somebody fixing a defect twice because the first fix
appeared not to work.

The order is the order somebody asks in: what is it, does it matter *here*,
what do I do, what happened and can it end.
"""

from __future__ import annotations

import logging
from typing import Any

from mykronos import guidance, supply_chain

logger = logging.getLogger(__name__)

#: Consecutive clean scans a finding needs before it closes. Mirrors
#: `reconcile.REQUIRED_ABSENCES` rather than re-deriving it.
REQUIRED_ABSENCES = 2


def closure(
    *,
    capability: str,
    lane: dict[str, Any] | None,
) -> dict[str, Any]:
    """Whether this finding *can* close, and what is stopping it.

    The block that earns the page. A finding closes only after two consecutive
    successful scans observe its absence, so a lane that is failing — or that
    quietly stopped — freezes its findings open however thoroughly the defect
    was fixed. Nothing at finding level said so, which is how somebody comes to
    fix the same thing twice.
    """
    if lane is None:
        return {
            "can_close": False,
            "lane": capability,
            "reason": (
                f"No {capability} scan has ever run against this repository, so "
                "nothing can observe this finding's absence."
            ),
            "required_absences": REQUIRED_ABSENCES,
            "last_run_at": None,
        }

    failure_rate = float(lane.get("failure_rate") or 0.0)
    runs = int(lane.get("runs") or 0)
    healthy = runs > 0 and failure_rate < 1.0

    return {
        "can_close": healthy,
        "lane": capability,
        "reason": (
            f"The {capability} lane is reporting; fix it and the next "
            f"{REQUIRED_ABSENCES} clean scans close it without anybody "
            "touching this page."
            if healthy
            else (
                f"The {capability} lane is not producing successful scans, so "
                "this cannot close however thoroughly it is fixed. Repair the "
                "lane before the finding."
            )
        ),
        "required_absences": REQUIRED_ABSENCES,
        "last_run_at": lane.get("last_run_at"),
        "runs": runs,
        "failure_rate": failure_rate,
    }


def fix_for(catalog: Any, *, repo_full_name: str, rule_id: str) -> dict[str, Any] | None:
    """The change that would close this finding, and what else it closes.

    Guidance groups by change already; only the reverse index was missing, so
    a finding could not name its own group. Read live rather than stored: a
    group's membership changes as findings open and close, and a cached answer
    would say "closes 7" long after it closed 4.
    """
    for group in guidance.fix_groups(catalog, asset_id=repo_full_name):
        if rule_id in group.rules:
            return {
                "fix_id": group.fix_id,
                "action": group.action,
                "effort": group.effort,
                "steps": list(group.steps),
                "closes": group.findings,
                "rules": list(group.rules),
            }
    return None


def package_for(
    catalog: Any, *, repo_full_name: str, package_name: str | None
) -> dict[str, Any] | None:
    """Supply-chain facts, joined rather than duplicated.

    `fixed_version` is the one that changes the decision most often and lived
    furthest from it: 239 of 242 container findings on this estate have no
    upstream fix at all, and knowing which three do is the difference between
    a rebuild that closes something and one that closes nothing.
    """
    if not package_name:
        return None
    analysis = supply_chain.vulnerable_packages(catalog, repo_full_name)
    for package in analysis.packages:
        if package.package_name == package_name:
            return {
                "package_name": package.package_name,
                "ecosystem": package.ecosystem,
                "installed_version": package.installed_version,
                "fixed_version": package.fixed_version or None,
                # `bool`, not `is not None`. The scanner writes an empty string
                # when it has no fixed version, and `is not None` reported
                # "fixable: true" with nothing to upgrade to — the single most
                # misleading thing this block could say, on an estate where 239
                # of 242 container findings have no upstream fix at all.
                "fixable": bool(package.fixed_version),
                "direct": package.direct,
                "advisories": package.advisories,
            }
    return None


def missing_context(
    *,
    reachability_analysed: bool,
    surfaces_declared: int,
    has_risk_profile: bool,
) -> list[dict[str, str]]:
    """What this record cannot tell you, and why (B-033's shape, per finding).

    A record that silently omits reachability reads as "not reachable". Saying
    which inputs are absent is what keeps "does this matter here" an honest
    question rather than one answered by severity alone.
    """
    gaps: list[dict[str, str]] = []
    if not reachability_analysed:
        gaps.append(
            {
                "input": "reachability",
                "reason": "no reachability analysis has run on this repository",
            }
        )
    if not surfaces_declared:
        gaps.append(
            {
                "input": "exposure",
                "reason": "no attack surface has been declared for this repository",
            }
        )
    if not has_risk_profile:
        gaps.append(
            {
                "input": "business context",
                "reason": (
                    "no risk profile — internet exposure, data classification "
                    "and business criticality are unset"
                ),
            }
        )
    return gaps
