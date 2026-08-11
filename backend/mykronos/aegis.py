"""Aegis — insider-risk scoring (spec 06).

Read spec 06 §9 before changing anything here. Every other capability in
Mykronos scores code; this one scores a pull request by a named person, and
that difference drives most of the decisions in this file:

- the combined score is capped and the sub-signals are additive but bounded,
  so no single heuristic can produce a `block_recommended` on its own;
- every non-zero sub-signal must carry a rationale, because a person
  challenged by this is entitled to dispute a specific claim rather than a
  number;
- "not evaluated" is a distinct state from "evaluated, nothing found", and
  the two are never collapsed.

Scoring happens here rather than in the workflow so it is reproducible from
the stored breakdown and cannot drift between the runner's version of the
arithmetic and the platform's — the same reason Oracle's policy lives in the
backend.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from mykronos.schemas import InsiderRiskSubmission, SubSignal, utcnow

AEGIS_CHECK_RUN_NAME = "Mykronos / insider risk"

#: Recommendation bands. `block_recommended` starts at the configured
#: `block_threshold` (spec 06 §5, default 80).
REVIEW_THRESHOLD = 40

#: Weight ceiling per signal key. A heuristic that fires wrongly should cost a
#: review, never a block: the sum of any two is below the default block
#: threshold of 80, so blocking always requires at least three independent
#: signals agreeing.
SIGNAL_CAP: dict[str, float] = {
    "author_baseline": 25.0,
    "sensitive_path": 30.0,
    "ai_authorship": 25.0,
    "access_anomaly": 25.0,
    "privilege_adjacent": 30.0,
    # Review integrity (spec 06 §2a). These describe how a change was
    # reviewed, not who reviewed it — the mechanism every insider scenario
    # routes through, without modelling relationships between people.
    #
    # `self_approval` is the heaviest of the four because it is the only one
    # that is not a heuristic: either the approving login equals the author's
    # or it does not. It still cannot block alone, by the rule below.
    "self_approval": 30.0,
    "sole_approver": 20.0,
    "fast_approval": 15.0,
    "unverified_ai": 20.0,
}

#: Signals the platform will accept. An unknown key is dropped rather than
#: silently scored, so a workflow running an older or forked scorer cannot
#: invent a contribution nobody can interpret.
KNOWN_SIGNALS = frozenset(SIGNAL_CAP)


def signal_id(repo_full_name: str, pr_number: int, commit_sha: str) -> str:
    """Derived, not random (spec 06 §3).

    The workflow triggers on `synchronize`, so an unchanged head commit gets
    re-evaluated on every re-run. A random id would append a duplicate row
    each time and quietly build the per-author history spec 06 §9 forbids.
    """
    material = f"{repo_full_name}\x00{pr_number}\x00{commit_sha}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Assessment:
    signal_id: str
    insider_risk_score: int
    recommendation: str
    breakdown: dict[str, Any]
    ai_authorship_flag: bool | None

    @property
    def is_block(self) -> bool:
        return self.recommendation == "block_recommended"


def _clamp_signals(signals: list[SubSignal]) -> tuple[list[dict[str, Any]], list[str]]:
    """Cap each signal at its ceiling and drop unknown keys.

    Returns (accepted, dropped_keys). Dropping is reported rather than silent:
    a scorer sending signals this platform does not know about is a version
    mismatch worth surfacing, not something to absorb.
    """
    accepted: list[dict[str, Any]] = []
    dropped: list[str] = []
    seen: set[str] = set()

    for signal in signals:
        if signal.key not in KNOWN_SIGNALS or signal.key in seen:
            dropped.append(signal.key)
            continue
        seen.add(signal.key)
        cap = SIGNAL_CAP[signal.key]
        capped = min(signal.score, cap)
        accepted.append(
            {
                "key": signal.key,
                "score": round(capped, 2),
                "capped_at": cap if capped < signal.score else None,
                "rationale": signal.rationale,
            }
        )
    return accepted, dropped


def assess(
    submission: InsiderRiskSubmission,
    repo_full_name: str,
    *,
    block_threshold: int = 80,
    ai_disclosure_required: bool = True,
    ai_classifier_configured: bool = False,
) -> Assessment:
    """Combine sub-signals into a recommendation (spec 06 §2, §4).

    `ai_classifier_configured` is passed separately from the submission so the
    breakdown can distinguish the two ways `ai_authorship_flag` ends up null:
    nobody configured a classifier, or one was configured and could not be
    reached (spec 06 §7). Both mean "we did not look", but only one of them is
    a fault.
    """
    accepted, dropped = _clamp_signals(submission.signals)
    contributing = [s for s in accepted if s["score"] > 0]
    raw_total = sum(s["score"] for s in accepted)
    score = int(round(min(100.0, raw_total)))

    if score >= block_threshold:
        recommendation = "block_recommended"
    elif score >= REVIEW_THRESHOLD:
        recommendation = "review_recommended"
    else:
        recommendation = "pass"

    flag = submission.ai_authorship_flag
    if flag is None:
        ai_state = {
            "evaluated": False,
            "reason": (
                "No AI-authorship classifier is configured for this repository, "
                "so no diff was sent anywhere and nothing was assessed "
                "(spec 06 §5)."
                if not ai_classifier_configured
                else "A classifier is configured but did not return a result; "
                "Aegis scored the remaining signals (spec 06 §7)."
            ),
        }
    else:
        ai_state = {
            "evaluated": True,
            "likely_ai_and_undisclosed": flag,
            "disclosure_required": ai_disclosure_required,
        }

    breakdown = {
        "signals": accepted,
        "raw_total": round(raw_total, 2),
        "clamped": raw_total > 100.0,
        "thresholds": {"review": REVIEW_THRESHOLD, "block": block_threshold},
        "ai_authorship": ai_state,
        # Named so the row explains its own absences the way Oracle's
        # inputs_snapshot does: a reader must be able to tell "this signal
        # scored zero" from "this signal never ran".
        "signals_not_reported": sorted(
            KNOWN_SIGNALS - {s["key"] for s in accepted}
        ),
        "signals_rejected": sorted(set(dropped)),
        "contributing_count": len(contributing),
    }

    return Assessment(
        signal_id=signal_id(repo_full_name, submission.pr_number, submission.commit_sha),
        insider_risk_score=score,
        recommendation=recommendation,
        breakdown=breakdown,
        ai_authorship_flag=flag,
    )


def to_row(
    assessment: Assessment,
    submission: InsiderRiskSubmission,
    repo_full_name: str,
    *,
    check_run_id: str | None = None,
) -> dict[str, Any]:
    return {
        "signal_id": assessment.signal_id,
        "repo_full_name": repo_full_name,
        "pr_number": submission.pr_number,
        "commit_sha": submission.commit_sha,
        "author_login": submission.author_login,
        "insider_risk_score": assessment.insider_risk_score,
        "signal_breakdown": json.dumps(assessment.breakdown, ensure_ascii=False),
        "ai_authorship_flag": assessment.ai_authorship_flag,
        "recommendation": assessment.recommendation,
        "evaluated_at": utcnow(),
        "github_check_run_id": check_run_id,
    }


def render_check_run_summary(
    assessment: Assessment, submission: InsiderRiskSubmission
) -> str:
    """The Markdown a reviewer reads on the pull request.

    Written about the change, not about the person: "this PR touches auth
    config" rather than "this author is risky". Same facts, and the framing is
    the difference between a review prompt and an accusation (spec 06 §9).
    """
    breakdown = assessment.breakdown
    lines = [
        f"## {assessment.recommendation.replace('_', ' ').title()} — "
        f"insider-risk score {assessment.insider_risk_score}/100",
        "",
        "This is a **prompt to review this change carefully**, not a judgement "
        "about the person who wrote it. Aegis cannot block, merge or close a "
        "pull request, and it never changes anyone's access.",
        "",
    ]

    contributing = [s for s in breakdown["signals"] if s["score"] > 0]
    if contributing:
        lines += ["### What was observed", "", "| Score | Signal | Why |", "| ---: | --- | --- |"]
        for signal in contributing:
            lines.append(
                f"| +{signal['score']:.0f} | `{signal['key']}` | {signal['rationale']} |"
            )
    else:
        lines.append("### Nothing was observed\n\nNo signal scored above zero.")

    ai = breakdown["ai_authorship"]
    lines += ["", "### AI authorship", ""]
    if not ai["evaluated"]:
        lines.append(f"_Not evaluated._ {ai['reason']}")
    elif ai["likely_ai_and_undisclosed"]:
        lines.append(
            "Likely AI-generated and not disclosed in the pull request "
            "description. Disclosure is required on this repository."
        )
    else:
        lines.append("Evaluated; no undisclosed AI authorship detected.")

    not_reported = breakdown["signals_not_reported"]
    if not_reported:
        lines += [
            "",
            "### Not assessed",
            "",
            ", ".join(f"`{key}`" for key in not_reported)
            + " did not run — recorded as absent rather than as zero.",
        ]

    lines += [
        "",
        "---",
        "",
        f"<sub>Scored from {breakdown['contributing_count']} contributing signal(s) "
        f"against thresholds review ≥ {breakdown['thresholds']['review']}, "
        f"block ≥ {breakdown['thresholds']['block']}. Retained for a limited "
        "period and visible to administrators only (spec 06 §9).</sub>",
    ]
    return "\n".join(lines)
