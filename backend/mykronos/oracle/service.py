"""Evaluating, persisting and publishing a risk decision (spec 09 §7, §8).

Sits between the pure scoring engine and everything that wants a decision —
the PR gate, the daily portfolio job, the dashboard. Keeping persistence and
Check Run publication here rather than in the endpoint means the scheduled job
and the HTTP path cannot drift apart in what they record.

Decisions are written through the same buffer→compaction path as every other
lake row. Oracle runs inside the backend, so it writes to the buffer directly
rather than POSTing to its own ingestion API — the point of spec 05 §9's
single write path is one validating, deduplicating implementation, not one
HTTP hop.
"""

from __future__ import annotations

import json
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from mykronos.github.client import GitHubClient, GitHubError
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.oracle.engine import Decision, OracleEngine
from mykronos.oracle.policy import Policy
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

CHECK_RUN_NAME = "Mykronos / risk decision"

#: Recommendation → Check Run conclusion.
#:
#: `no_go` is only `failure` when the repo has opted into blocking. Otherwise
#: it is `neutral`: advisory by default is the platform-wide stance (spec 09
#: §6), and a red check nobody agreed to is how a security tool gets switched
#: off in its first week.
_CONCLUSION = {
    "go": "success",
    "review_recommended": "neutral",
    "no_go": "neutral",
}


@dataclass
class PublishedDecision:
    decision: Decision
    check_run_id: str | None = None
    blocking: bool = False
    check_run_error: str | None = None


def decision_to_row(decision: Decision, *, gate_outcome: str | None = None) -> dict[str, Any]:
    return {
        "decision_id": decision.decision_id,
        "repo_full_name": decision.repo_full_name,
        "decision_type": decision.decision_type,
        "pr_number": decision.pr_number,
        "release_tag": decision.release_tag,
        "commit_sha": decision.commit_sha,
        "overall_risk_score": decision.overall_risk_score,
        "recommendation": decision.recommendation,
        "inputs_snapshot": json.dumps(decision.inputs_snapshot, ensure_ascii=False),
        "reasoning": decision.reasoning,
        "policy_version": decision.policy_version,
        "evaluated_at": decision.evaluated_at,
        "human_override": None,
        "github_check_run_id": None,
        "gate_outcome": gate_outcome,
    }


def render_check_run_summary(decision: Decision, *, blocking: bool) -> str:
    """The Markdown a developer reads on their pull request.

    For most people this is the entire product, so it shows the arithmetic
    rather than just the verdict: a score you cannot check is a score you
    eventually stop believing.
    """
    snapshot = decision.inputs_snapshot
    totals = snapshot["totals"]

    lines = [
        f"## {decision.recommendation.replace('_', ' ').title()} — "
        f"{decision.overall_risk_score}/100",
        "",
        decision.reasoning,
        "",
        "### How this score was reached",
        "",
        "| Contribution | Input | Arithmetic |",
        "| ---: | --- | --- |",
    ]
    for term in snapshot["terms"]:
        lines.append(f"| +{term['contribution']:.1f} | {term['label']} | `{term['detail']}` |")
    if not snapshot["terms"]:
        lines.append("| 0.0 | _no open findings in scope_ | — |")

    lines += [
        f"| **{totals['raw_score']:.1f}** | **raw total** | |",
        f"| **{totals['overall_risk_score']}** | **final score** "
        f"| {'clamped to 100' if totals['clamped'] else 'within range'} |",
        "",
        "### Not yet consulted",
        "",
    ]
    unavailable = [
        (name, snapshot[name]["reason"])
        for name in (
            "insider_risk",
            "sscs_trust",
            "remediation_in_flight",
            "false_positive_dampening",
        )
        if not snapshot[name]["available"]
    ]
    if unavailable:
        for name, reason in unavailable:
            lines.append(f"- `{name}` — {reason}")
        lines.append("")
        lines.append(
            "_These are recorded as unavailable rather than zero, so this score "
            "is a partial picture by construction._"
        )
    else:
        lines.append("_All input categories were available._")

    lines += [
        "",
        "---",
        "",
        (
            "**This check is blocking for this repository.**"
            if blocking
            else "**Advisory only.** This check does not block the merge — "
            "blocking is opt-in per repository and off by default (spec 09 §6)."
        ),
        "",
        f"<sub>Policy `{decision.policy_version}` · decision "
        f"`{decision.decision_id}` · every number above is reproducible from "
        "the stored inputs snapshot.</sub>",
    ]
    return "\n".join(lines)


class OracleService:
    def __init__(
        self,
        catalog: Catalog,
        buffer: WriteAheadBuffer,
        policy: Policy,
    ) -> None:
        self.catalog = catalog
        self.buffer = buffer
        self.policy = policy
        self.engine = OracleEngine(catalog, policy)

    async def evaluate_and_publish(
        self,
        repo_full_name: str,
        *,
        decision_type: str = "portfolio",
        commit_sha: str = "",
        pr_number: int | None = None,
        release_tag: str | None = None,
        blocking: bool = False,
        github: GitHubClient | None = None,
    ) -> PublishedDecision:
        """Score, persist, and post a Check Run if there is somewhere to post it."""
        decision = self.engine.evaluate(
            repo_full_name,
            decision_type=decision_type,
            commit_sha=commit_sha,
            pr_number=pr_number,
            release_tag=release_tag,
        )

        row = decision_to_row(decision)
        published = PublishedDecision(decision=decision, blocking=blocking)

        if github is not None and commit_sha and decision_type != "portfolio":
            try:
                published.check_run_id = await github.create_check_run(
                    repo_full_name,
                    name=CHECK_RUN_NAME,
                    head_sha=commit_sha,
                    conclusion=(
                        "failure"
                        if blocking and decision.recommendation == "no_go"
                        else _CONCLUSION[decision.recommendation]
                    ),
                    title=(
                        f"{decision.recommendation.replace('_', ' ')} — "
                        f"{decision.overall_risk_score}/100"
                    ),
                    summary=render_check_run_summary(decision, blocking=blocking),
                )
                row["github_check_run_id"] = published.check_run_id
            except GitHubError as exc:
                # The decision is the record; the Check Run is how it is
                # displayed. Losing the display must not lose the decision, and
                # a scan that scored fine should not fail because GitHub was
                # briefly unavailable.
                published.check_run_error = str(exc)
                logger.warning(
                    "Could not post a check run for %s@%s: %s",
                    repo_full_name,
                    commit_sha,
                    exc,
                )

        # Written last, so the persisted row carries the check run id when
        # there is one.
        self.buffer.append("risk_decisions", [row])
        return published

    def record_gate_outcome(
        self, repo_full_name: str, pr_number: int, outcome: str
    ) -> str | None:
        """Record what actually happened to the pull request Oracle judged.

        This is the evidence for open question 5 — whether blocking mode should
        ever be turned on. Advisory mode gives you a natural experiment for
        free: every `no_go` that merged anyway is a merge blocking mode *would*
        have stopped, and the only honest way to argue for blocking is to point
        at those merges and show what they cost. Without this column the
        argument reduces to "the scanner said so", which is exactly the
        argument that gets security gates switched off.

        Only the most recent `pr_gate` decision for the PR is marked: earlier
        ones were superseded by later pushes and were never the standing
        verdict when the merge button was pressed.

        Returns the decision id, or None if Oracle never judged this PR.
        """
        rows = self.catalog.query(
            """
            SELECT decision_id, repo_full_name, decision_type, recommendation,
                   overall_risk_score, gate_outcome
            FROM risk_decisions
            WHERE repo_full_name = ? AND pr_number = ? AND decision_type = 'pr_gate'
            ORDER BY evaluated_at DESC
            LIMIT 1
            """,
            [repo_full_name, pr_number],
        )
        if not rows:
            return None

        decision_id, repo, decision_type, recommendation, score, existing = rows[0]
        if existing:
            # A PR closes once. A second delivery of the same event must not
            # rewrite the record — GitHub redelivers, and reopen/re-close would
            # otherwise overwrite the outcome that mattered.
            return str(decision_id)

        stub = Decision(
            decision_id=str(decision_id),
            repo_full_name=str(repo),
            decision_type=str(decision_type),
            commit_sha="",
            pr_number=pr_number,
            release_tag=None,
            overall_risk_score=int(score),
            recommendation=str(recommendation),
            reasoning="",
            inputs_snapshot={},
            policy_version="",
            evaluated_at=utcnow(),
        )
        self.buffer.append(
            "risk_decisions", [decision_to_row(stub, gate_outcome=outcome)]
        )
        logger.info(
            "Gate outcome for %s#%s (%s): %s",
            repo_full_name,
            pr_number,
            recommendation,
            outcome,
        )
        return str(decision_id)

    # -- reads ----------------------------------------------------------

    def shadow_mode_report(self, *, since: datetime | None = None) -> dict[str, Any]:
        """What blocking mode would have done, had it been on (spec 09 §6).

        Deliberately reports the counter-evidence in the same shape as the
        supporting evidence: `would_have_blocked` next to `overridden`, so the
        cost of turning blocking on is as visible as the benefit. A report that
        only counted caught issues would be an argument, not a measurement.
        """
        where = ["decision_type = 'pr_gate'", "gate_outcome IS NOT NULL"]
        params: list[Any] = []
        if since is not None:
            where.append("evaluated_at >= ?")
            params.append(since)
        clause = " AND ".join(where)

        rows = self.catalog.query(
            f"""
            SELECT recommendation, gate_outcome, human_override IS NOT NULL, count(*)
            FROM risk_decisions
            WHERE {clause}
            GROUP BY 1, 2, 3
            """,
            params,
        )

        totals = dict.fromkeys(
            (
                "decisions_with_a_known_outcome",
                "merged",
                "closed_unmerged",
                # no_go decisions that merged anyway: exactly the set blocking
                # mode would have stopped.
                "would_have_blocked",
                "would_have_blocked_and_overridden",
            ),
            0,
        )
        by_recommendation: dict[str, dict[str, int]] = {}

        for recommendation, outcome, overridden, raw_count in rows:
            count = int(raw_count)
            totals["decisions_with_a_known_outcome"] += count
            if outcome in ("merged", "closed_unmerged"):
                totals[str(outcome)] += count
            bucket = by_recommendation.setdefault(
                str(recommendation), {"merged": 0, "closed_unmerged": 0}
            )
            bucket[str(outcome)] = bucket.get(str(outcome), 0) + count
            if recommendation == "no_go" and outcome == "merged":
                totals["would_have_blocked"] += count
                if overridden:
                    totals["would_have_blocked_and_overridden"] += count

        return {
            **totals,
            "by_recommendation": by_recommendation,
            "interpretation": (
                "Every 'would_have_blocked' is a merge that blocking mode "
                "would have stopped. Whether that was the right call is not "
                "in this table — it needs the incident record for those "
                "merges. This is the denominator for that question, not the "
                "answer to it."
            ),
        }


    def recent_decisions(
        self,
        repo_full_name: str,
        *,
        decision_type: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        where = ["repo_full_name = ?"]
        params: list[Any] = [repo_full_name]
        if decision_type:
            where.append("decision_type = ?")
            params.append(decision_type)

        rows = self.catalog.query(
            f"""
            SELECT decision_id, decision_type, pr_number, release_tag, commit_sha,
                   overall_risk_score, recommendation, reasoning, policy_version,
                   evaluated_at, human_override, github_check_run_id, gate_outcome,
                   inputs_snapshot
            FROM risk_decisions
            WHERE {' AND '.join(where)}
            ORDER BY evaluated_at DESC
            LIMIT ?
            """,
            [*params, limit],
        )

        columns = [
            "decision_id",
            "decision_type",
            "pr_number",
            "release_tag",
            "commit_sha",
            "overall_risk_score",
            "recommendation",
            "reasoning",
            "policy_version",
            "evaluated_at",
            "human_override",
            "github_check_run_id",
            "gate_outcome",
            "inputs_snapshot",
        ]
        decisions = []
        for row in rows:
            record = dict(zip(columns, row, strict=True))
            for field_name in ("inputs_snapshot", "human_override"):
                if record.get(field_name):
                    # Unparseable JSON is returned as-is rather than dropped:
                    # a decision record you cannot read is still evidence.
                    with suppress(TypeError, json.JSONDecodeError):
                        record[field_name] = json.loads(record[field_name])
            decisions.append(record)
        return decisions

    def latest_portfolio_decisions(self) -> dict[str, dict[str, Any]]:
        """Most recent portfolio decision per repo, for the dashboard."""
        rows = self.catalog.query(
            """
            SELECT repo_full_name, overall_risk_score, recommendation, evaluated_at,
                   json_extract_string(inputs_snapshot, '$.totals.raw_score') AS raw_score
            FROM (
                SELECT *, row_number() OVER (
                    PARTITION BY repo_full_name ORDER BY evaluated_at DESC
                ) AS rn
                FROM risk_decisions
                WHERE decision_type = 'portfolio'
            ) WHERE rn = 1
            """
        )
        return {
            str(repo): {
                "overall_risk_score": int(score),
                "recommendation": str(recommendation),
                "evaluated_at": evaluated_at,
                # Ranking has to survive the clamp (D-018): repos that both
                # display 100 still need an order.
                "raw_score": float(raw or 0.0),
            }
            for repo, score, recommendation, evaluated_at, raw in rows
        }

    def find_decision(self, decision_id: str) -> dict[str, Any] | None:
        rows = self.catalog.query(
            "SELECT repo_full_name, decision_type, pr_number, recommendation, "
            "overall_risk_score, human_override FROM risk_decisions WHERE decision_id = ?",
            [decision_id],
        )
        if not rows:
            return None
        keys = [
            "repo_full_name",
            "decision_type",
            "pr_number",
            "recommendation",
            "overall_risk_score",
            "human_override",
        ]
        return dict(zip(keys, rows[0], strict=True))
