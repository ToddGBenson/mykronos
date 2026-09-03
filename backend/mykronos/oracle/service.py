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
from datetime import datetime, timedelta
from typing import Any

from mykronos.db.session import Database
from mykronos.github.client import GitHubClient, GitHubError
from mykronos.knowledge.store import KnowledgeStore
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.logsafe import scrub
from mykronos.oracle.engine import MODIFIER_CATEGORIES, Decision, OracleEngine
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


def _introduced_section(introduced: list[dict[str, Any]]) -> list[str]:
    """What this change brought in, worst first."""
    if not introduced:
        return [
            "### This change introduced nothing",
            "",
            "No new open finding is attributable to this commit. The score "
            "below describes the backlog that was already here.",
            "",
        ]

    by_severity: dict[str, int] = {}
    for row in introduced:
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
    tally = ", ".join(
        f"{by_severity[sev]} {sev}"
        for sev in ("critical", "high", "medium", "low", "info")
        if by_severity.get(sev)
    )

    lines = [
        f"### This change introduced {len(introduced)} finding"
        f"{'' if len(introduced) == 1 else 's'} — {tally}",
        "",
        "| Severity | Lane | Rule | Where |",
        "| --- | --- | --- | --- |",
    ]
    for row in introduced:
        where = row.get("file_path") or "—"
        if row.get("line_start"):
            where = f"{where}:{row['line_start']}"
        lines.append(
            f"| {row['severity']} | {row['capability']} | "
            f"`{row['rule_id']}` | {where} |"
        )
    lines += [
        "",
        "<sub>Attributed by the scan run that first saw each finding, so a "
        "finding your branch merely reproduces is not counted against it.</sub>",
        "",
    ]
    return lines


def render_check_run_summary(
    decision: Decision,
    *,
    blocking: bool,
    introduced: list[dict[str, Any]] | None = None,
) -> str:
    """The Markdown a developer reads on their pull request.

    For most people this is the entire product, so it shows the arithmetic
    rather than just the verdict: a score you cannot check is a score you
    eventually stop believing.

    **`introduced` leads, and the score follows it.** The score describes the
    repository's whole open backlog — the right answer to "how much risk does
    this carry" and the wrong one to "should this ship". On a repository with
    330 open findings the number barely moves between commits, so an author
    reading only the score sees the same check whether their change added a
    critical or removed one. What they can act on is the short list of things
    the change itself brought in, which is why it goes above the arithmetic
    rather than below it.

    Passing `None` renders the summary without the section, which is not the
    same as passing `[]` — an empty list is the good news that this change
    introduced nothing, and saying so is the most reassuring thing this check
    can report.
    """
    snapshot = decision.inputs_snapshot
    totals = snapshot["totals"]

    lines = [
        f"## {decision.recommendation.replace('_', ' ').title()} — "
        f"{decision.overall_risk_score}/100",
        "",
        decision.reasoning,
        "",
    ]

    if introduced is not None:
        lines += _introduced_section(introduced)

    lines += [
        "### How this score was reached",
        "",
        "_The repository's whole open backlog, not this change._",
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
        for name in MODIFIER_CATEGORIES
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


def _dashboard_queries(catalog: Any) -> Any:
    """Imported at call time, not at module load.

    `dashboard` imports Oracle's policy for its portfolio rendering; importing
    it back at module level here would make that a cycle. One call per merged
    commit in a 30-day window is not a hot path.
    """
    from mykronos.dashboard import DashboardQueries

    return DashboardQueries(catalog)


class OracleService:
    def __init__(
        self,
        catalog: Catalog,
        buffer: WriteAheadBuffer,
        policy: Policy,
        store: KnowledgeStore | None = None,
        *,
        db: Database | None = None,
    ) -> None:
        self.catalog = catalog
        self.buffer = buffer
        self.policy = policy
        self.engine = OracleEngine(catalog, policy, store, db=db)

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
            # Read once, here, rather than inside the renderer: the renderer is
            # pure and tested on its own, and a check run that fails to publish
            # should not be a query the catalog ran for nothing.
            try:
                introduced = _dashboard_queries(self.catalog).introduced_rows(
                    repo_full_name, commit_sha
                )
            except Exception:  # noqa: BLE001 - the score is still worth posting
                logger.warning(
                    "Could not read introduced findings for %s@%s; posting the "
                    "check run without that section.",
                    repo_full_name,
                    commit_sha,
                )
                introduced = None
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
                    summary=render_check_run_summary(
                        decision, blocking=blocking, introduced=introduced
                    ),
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
                    scrub(repo_full_name),
                    scrub(commit_sha),
                    scrub(exc),
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

    def shadow_mode_report(
        self, *, since: datetime | None = None, repo_full_name: str | None = None
    ) -> dict[str, Any]:
        """What blocking mode would have done, had it been on (spec 09 §6).

        Deliberately reports the counter-evidence in the same shape as the
        supporting evidence: `would_have_blocked` next to `overridden`, so the
        cost of turning blocking on is as visible as the benefit. A report that
        only counted caught issues would be an argument, not a measurement.

        **Two gates, and only one of them still exists.** `would_have_blocked`
        counts `no_go` decisions that merged — the composite-score gate, which
        D-048 and D-083 retired after it refused every commit in both
        pipelines. `would_have_blocked_on_introduced` counts what the *current*
        gate would refuse: a commit that introduced a critical or a high. The
        retired number is kept and labelled rather than deleted, so evidence
        gathered under the old model is still readable and is not mistaken for
        evidence about the new one.

        **The introduced count is judged now, not then.** It re-asks
        `introduced_by` for each decision's commit, and that reads current
        status — so a finding introduced then and dispositioned since does not
        count. That is the honest direction for a "should we switch this on"
        question: it reports what the gate would refuse *today*, given what is
        known today.
        """
        where = ["decision_type = 'pr_gate'", "gate_outcome IS NOT NULL"]
        params: list[Any] = []
        if since is not None:
            where.append("evaluated_at >= ?")
            params.append(since)
        if repo_full_name is not None:
            where.append("repo_full_name = ?")
            params.append(repo_full_name)
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
                "would_have_blocked_on_introduced",
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

        # The gate that actually runs (D-083). One `introduced_by` per merged
        # commit, not per decision: the same commit re-judged on three pushes
        # is one commit a gate would refuse once.
        merged_commits = {
            str(commit)
            for (commit,) in self.catalog.query(
                f"""
                SELECT DISTINCT commit_sha FROM risk_decisions
                WHERE {clause} AND gate_outcome = 'merged'
                  AND commit_sha IS NOT NULL AND commit_sha <> ''
                """,
                params,
            )
        }
        refused: list[dict[str, Any]] = []
        for commit in sorted(merged_commits):
            for repo in self._repos_for_commit(commit, repo_full_name):
                introduced = _dashboard_queries(self.catalog).introduced_by(repo, commit)
                if introduced.get("critical", 0) or introduced.get("high", 0):
                    refused.append(
                        {
                            "repo_full_name": repo,
                            "commit_sha": commit,
                            "introduced": introduced,
                        }
                    )
        totals["would_have_blocked_on_introduced"] = len(refused)

        return {
            **totals,
            "merged_commits_judged": len(merged_commits),
            "refused_on_introduced": refused,
            "by_recommendation": by_recommendation,
            "retired_model_note": (
                "`would_have_blocked` describes the composite-score gate that "
                "D-048 and D-083 retired — it refused every commit once a "
                "backlog existed. `would_have_blocked_on_introduced` is the "
                "gate that runs now: no new critical, no new high."
            ),
            "interpretation": (
                "Every 'would_have_blocked' is a merge that blocking mode "
                "would have stopped. Whether that was the right call is not "
                "in this table — it needs the incident record for those "
                "merges. This is the denominator for that question, not the "
                "answer to it."
            ),
        }


    def _repos_for_commit(
        self, commit_sha: str, repo_full_name: str | None
    ) -> list[str]:
        if repo_full_name is not None:
            return [repo_full_name]
        return [
            str(repo)
            for (repo,) in self.catalog.query(
                "SELECT DISTINCT repo_full_name FROM risk_decisions WHERE commit_sha = ?",
                [commit_sha],
            )
        ]

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

    def term_analytics(self, *, days: int = 30) -> dict[str, Any]:
        """What is actually driving risk across the fleet (spec 21 §3).

        A read-time aggregate over `inputs_snapshot`, which every decision
        already stores. No new computation at decision time and no new write
        path — the same shape the portfolio summary and the shadow-mode report
        already take, for the same reason: a rollup written at decision time is
        a second copy of the truth, free to disagree with the decisions it
        summarises.

        One decision per repository — the latest `portfolio` decision inside
        the window. Summing every decision would weight a repository by how
        often it happened to be evaluated, which is a fact about scan cadence
        rather than about risk.
        """
        since = utcnow() - timedelta(days=days)
        rows = self.catalog.query(
            """
            SELECT recommendation, inputs_snapshot FROM (
                SELECT
                    repo_full_name,
                    recommendation,
                    inputs_snapshot,
                    row_number() OVER (
                        PARTITION BY repo_full_name ORDER BY evaluated_at DESC
                    ) AS recency
                FROM risk_decisions
                WHERE decision_type = 'portfolio' AND evaluated_at >= ?
            )
            WHERE recency = 1
            """,
            [since],
        )

        totals: dict[str, dict[str, Any]] = {}
        repos_considered = 0
        no_go_repos = 0

        for recommendation, raw_snapshot in rows:
            try:
                snapshot = json.loads(raw_snapshot) if raw_snapshot else {}
            except json.JSONDecodeError:
                # One unreadable snapshot costs that repo's contribution, not
                # the report. A decision row this old or this broken is a fact
                # worth not crashing over.
                continue
            repos_considered += 1
            if recommendation == "no_go":
                no_go_repos += 1

            for term in snapshot.get("terms") or []:
                key = str(term.get("key") or "unknown")
                entry = totals.setdefault(
                    key,
                    {
                        "key": key,
                        "label": term.get("label") or key,
                        "total_contribution": 0.0,
                        "repos": 0,
                        # Counted separately so the ranking can be read two
                        # ways: a term worth 300 points across 30 repos is a
                        # fleet-wide policy question, and one worth 300 across
                        # 2 is a conversation with two teams.
                        "no_go_repos": 0,
                    },
                )
                entry["total_contribution"] += float(term.get("contribution") or 0.0)
                entry["repos"] += 1
                if recommendation == "no_go":
                    entry["no_go_repos"] += 1

        ranked = sorted(
            (
                {**entry, "total_contribution": round(entry["total_contribution"], 2)}
                for entry in totals.values()
            ),
            key=lambda entry: (-entry["total_contribution"], entry["key"]),
        )
        return {
            "window_days": days,
            "since": since.isoformat(),
            "repos_considered": repos_considered,
            "no_go_repos": no_go_repos,
            "terms": ranked,
            "note": (
                "One decision per repository — its latest portfolio decision "
                "in the window. Summing every decision would weight a "
                "repository by how often it was evaluated rather than by its "
                "risk. Contributions are pre-clamp (D-018), so they can sum "
                "past 100 for a repository pinned at the ceiling."
            ),
        }

    def policy_history(self) -> list[dict[str, Any]]:
        """Every policy version that has produced a decision (spec 21 §5).

        Not read from git. Spec 21 §5 imagined pulling `oracle-policy-v1.yaml`'s
        commit history through the GitHub API, which needs the App installed on
        the Mykronos repository itself — the same thing already blocking
        automatic policy-proposal PRs, and still not true.

        What the platform *can* answer without it turns out to be the more
        useful half anyway: which decisions were made under which version, and
        when each version was in force. That is the question somebody actually
        has when they find an old decision they disagree with — "was this
        scored under the rules we have now?" — and it is answered from
        `risk_decisions`, which records `policy_version` on every row.

        The diff between two versions is the part that stays missing, and the
        endpoint says so rather than implying this is the whole feature.
        """
        rows = self.catalog.query(
            """
            SELECT
                policy_version,
                count(*),
                min(evaluated_at),
                max(evaluated_at),
                count(*) FILTER (WHERE recommendation = 'no_go'),
                count(DISTINCT repo_full_name)
            FROM risk_decisions
            WHERE policy_version IS NOT NULL AND policy_version <> ''
            GROUP BY policy_version
            ORDER BY max(evaluated_at) DESC
            """
        )
        return [
            {
                "version": version,
                "decisions": int(count),
                "first_used": first.isoformat() if first else None,
                "last_used": last.isoformat() if last else None,
                "no_go_decisions": int(no_go),
                "repos": int(repos),
                # The current policy is the one loaded into this process, not
                # the one that decided most recently: a version bumped and
                # deployed but not yet exercised is in force and has no rows.
                "current": version == self.policy.version,
            }
            for version, count, first, last, no_go, repos in rows
        ]
