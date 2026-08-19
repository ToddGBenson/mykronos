"""Atlas — supply-chain trust scoring (spec 07).

The trust score is computed here rather than in the workflow, for the reason
spec 07 §7 makes an acceptance criterion: it has to be reproducible. A score
the runner calculates is a score that drifts the moment two repos are running
different versions of the action.

Deliberately not a model. spec 01 §6 requires every number the platform
produces to be explainable, and an admin should be able to reproduce any trust
score by hand from the stored evidence row.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

from mykronos.schemas import EcosystemEvidence, SscsEvidenceSubmission, utcnow

#: Penalty weights per severity (spec 07 §5).
VULN_WEIGHTS: dict[str, float] = {"critical": 20.0, "high": 10.0, "medium": 3.0}

#: Ratio penalties. Left linear because a ratio is already bounded at 1 and
#: cannot saturate the way an unbounded count can.
FLOATING_PENALTY = 10.0
STALE_PENALTY = 10.0

#: Copyleft and source-available terms that create real obligations on
#: redistribution (spec 22 §1.3). Deliberately short: the penalty is for
#: licenses that oblige, not for "a license we have not seen before". A
#: license absent from this list costs nothing, which is the correct answer
#: for the permissive majority of any dependency tree.
FLAGGED_LICENSES: frozenset[str] = frozenset(
    {
        "gpl-2.0",
        "gpl-2.0-only",
        "gpl-2.0-or-later",
        "gpl-3.0",
        "gpl-3.0-only",
        "gpl-3.0-or-later",
        "agpl-3.0",
        "agpl-3.0-only",
        "agpl-3.0-or-later",
        "sspl-1.0",
        "bsl-1.1",
        "elastic-2.0",
    }
)

#: Per component carrying a flagged license.
LICENSE_PENALTY_PER_FLAGGED = 2.0

#: Per component whose license the SBOM does not state. Smaller on purpose —
#: "we do not know" is a lesser risk than "we know it obliges", and unknown is
#: also the more common shape, so a heavier weight here would drown the terms
#: that mean something.
UNKNOWN_LICENSE_PENALTY = 0.5


def evidence_id(repo_full_name: str, commit_sha: str) -> str:
    """Derived from repo + commit (spec 07 §3).

    spec 07 §7 requires exactly one evidence row per tagged release and §8 one
    per commit. A random UUID cannot deliver either: a re-run would append a
    second row and both criteria would quietly stop holding.
    """
    return hashlib.sha256(
        f"{repo_full_name}\x00{commit_sha}".encode()
    ).hexdigest()


@dataclass(frozen=True)
class TrustAssessment:
    #: Null when the scan resolved no dependencies (spec 07 §5a). Deliberately
    #: not 0 and deliberately not 100: neither is true of a repository nobody
    #: managed to inspect, and 100 is the answer this used to give.
    trust_score: int | None
    raw_trust_score: float | None
    dependency_count: int
    vulnerable_dependency_count: int
    terms: list[dict[str, Any]]

    @property
    def floored(self) -> bool:
        return self.raw_trust_score is not None and self.raw_trust_score < 0

    @property
    def assessed(self) -> bool:
        """Whether anything was actually resolved to score."""
        return self.trust_score is not None


def _curve(count: int) -> float:
    """`log2(1 + count)` — the D-018 correction, applied here for the same reason.

    Subtracting linearly meant five critical CVEs floored the score at 0, and
    so did five hundred. That is not hypothetical for dependency scanning:
    `npm audit` on an unmaintained project reports dozens of criticals in
    transitive packages nobody chose directly. Every such repo would report
    trust_score 0, the trend line would be flat by construction, and Oracle's
    sscs_trust penalty would saturate identically for all of them.
    """
    return math.log2(1 + count)


def score(ecosystems: list[EcosystemEvidence]) -> TrustAssessment:
    """Compute the trust score from per-ecosystem counts (spec 07 §5, §8).

    A monorepo scans each ecosystem independently; counts are summed across
    them into one score, and the per-ecosystem detail is kept separately so
    the sum does not destroy it.
    """
    totals = {level: 0 for level in VULN_WEIGHTS}
    dependency_count = 0
    floating = 0
    stale = 0
    maintenance_known = 0
    flagged_licensed = 0
    unknown_licensed = 0
    flagged_names: set[str] = set()

    for eco in ecosystems:
        for identifier, count in (eco.licenses_seen or {}).items():
            if identifier == "unknown":
                unknown_licensed += count
            elif identifier in FLAGGED_LICENSES:
                flagged_licensed += count
                flagged_names.add(identifier)
        totals["critical"] += eco.critical_vulns
        totals["high"] += eco.high_vulns
        totals["medium"] += eco.medium_vulns
        dependency_count += eco.dependency_count
        floating += eco.floating_versions
        stale += eco.stale_dependencies
        # Private-registry packages have no published maintenance data. They
        # are excluded from the stale ratio's denominator rather than counted
        # as fresh or as stale (spec 07 §8) — either default would be a claim
        # the data does not support.
        maintenance_known += (
            eco.maintenance_data_available_for
            if eco.maintenance_data_available_for is not None
            else eco.dependency_count
        )

    terms: list[dict[str, Any]] = []
    penalty = 0.0

    for level, weight in VULN_WEIGHTS.items():
        count = totals[level]
        if count == 0:
            continue
        contribution = weight * _curve(count)
        penalty += contribution
        terms.append(
            {
                "key": f"{level}_vulnerabilities",
                "penalty": round(contribution, 2),
                "detail": f"{weight:.0f} × log2(1 + {count}) = {contribution:.1f}",
                "count": count,
            }
        )

    if dependency_count and floating:
        ratio = floating / dependency_count
        contribution = ratio * FLOATING_PENALTY
        penalty += contribution
        terms.append(
            {
                "key": "floating_versions",
                "penalty": round(contribution, 2),
                "detail": (
                    f"{floating}/{dependency_count} not pinned "
                    f"({ratio:.0%}) × {FLOATING_PENALTY:.0f} = {contribution:.1f}"
                ),
                "count": floating,
            }
        )

    if maintenance_known and stale:
        ratio = stale / maintenance_known
        contribution = ratio * STALE_PENALTY
        penalty += contribution
        terms.append(
            {
                "key": "stale_dependencies",
                "penalty": round(contribution, 2),
                "detail": (
                    f"{stale}/{maintenance_known} with no release in 2+ years "
                    f"({ratio:.0%}) × {STALE_PENALTY:.0f} = {contribution:.1f}. "
                    "Denominator excludes dependencies with no published "
                    "maintenance data."
                ),
                "count": stale,
            }
        )

    # Curved, like the vulnerability terms and for the same reason: a
    # monorepo pulling in two hundred GPL components has a licensing question
    # to answer, not a trust score of zero, and a linear term would floor it
    # there and stop distinguishing it from a repo with a thousand.
    if flagged_licensed:
        contribution = LICENSE_PENALTY_PER_FLAGGED * _curve(flagged_licensed)
        penalty += contribution
        terms.append(
            {
                "key": "flagged_licenses",
                "penalty": round(contribution, 2),
                "detail": (
                    f"{flagged_licensed} component(s) under "
                    f"{', '.join(sorted(flagged_names))}. "
                    f"{LICENSE_PENALTY_PER_FLAGGED:.0f} × "
                    f"log2(1 + {flagged_licensed}) = {contribution:.1f}"
                ),
                "count": flagged_licensed,
            }
        )

    if unknown_licensed:
        contribution = UNKNOWN_LICENSE_PENALTY * _curve(unknown_licensed)
        penalty += contribution
        terms.append(
            {
                "key": "unknown_licenses",
                "penalty": round(contribution, 2),
                "detail": (
                    f"{unknown_licensed} component(s) declare no license in "
                    f"the SBOM. {UNKNOWN_LICENSE_PENALTY} × "
                    f"log2(1 + {unknown_licensed}) = {contribution:.1f}"
                ),
                "count": unknown_licensed,
            }
        )

    # Nothing resolved, nothing to score (spec 07 §5a). This used to return
    # 100 — the same answer a repository with four hundred clean dependencies
    # gets — for a scan that inspected nothing at all. Most often it means the
    # project declares ranges rather than pins, so there is no concrete
    # version set to check advisories against, and the remedy is to pin them
    # rather than to celebrate.
    if dependency_count == 0:
        return TrustAssessment(
            trust_score=None,
            raw_trust_score=None,
            dependency_count=0,
            vulnerable_dependency_count=0,
            terms=[
                {
                    "key": "not_assessed",
                    "penalty": 0.0,
                    "detail": (
                        "No dependencies were resolved, so no supply-chain "
                        "trust was assessed. A project declaring version "
                        "ranges rather than pinned versions has no resolved "
                        "set for the scanner to check."
                    ),
                    "count": 0,
                }
            ],
        )

    raw = 100.0 - penalty
    return TrustAssessment(
        trust_score=int(round(max(0.0, min(100.0, raw)))),
        raw_trust_score=round(raw, 2),
        dependency_count=dependency_count,
        vulnerable_dependency_count=sum(totals.values()),
        terms=terms,
    )


def to_row(
    submission: SscsEvidenceSubmission,
    assessment: TrustAssessment,
    repo_full_name: str,
) -> dict[str, Any]:
    return {
        "evidence_id": evidence_id(repo_full_name, submission.commit_sha),
        "repo_full_name": repo_full_name,
        "commit_sha": submission.commit_sha,
        "tag_or_release": submission.tag_or_release,
        "sbom_ref": submission.sbom_ref,
        "dependency_count": assessment.dependency_count,
        "vulnerable_dependency_count": assessment.vulnerable_dependency_count,
        "trust_score": assessment.trust_score,
        "raw_trust_score": assessment.raw_trust_score,
        "provenance_json": json.dumps(submission.provenance, ensure_ascii=False),
        "ecosystems_json": json.dumps(
            {
                "ecosystems": [eco.model_dump() for eco in submission.ecosystems],
                # The arithmetic, kept with the row so the score is checkable
                # without re-deriving it from the counts.
                "score_terms": assessment.terms,
                "floored": assessment.floored,
            },
            ensure_ascii=False,
        ),
        "evaluated_at": utcnow(),
    }
