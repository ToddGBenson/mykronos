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
from typing import Any

from mykronos.github.client import GitHubClient, GitHubError
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.oracle.engine import Decision, OracleEngine
from mykronos.oracle.policy import Policy

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

    # -- reads ----------------------------------------------------------

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
