"""The agent fleet view for one repository (spec 35 §8.6, D-147).

What the agents did: autonomy runs, the verdict each story got from
verification, model cost, and for every gate failure the role TheHub's RACI
table makes Accountable for it.

**The RACI table is TheHub's.** It lives in TheHub's root CLAUDE.md ("RACI over
the agent fleet", AGENT-3 #48555) and is copied here row for row. A test pins
the copy, so any change to it is a deliberate one. Three activities have no
agent equivalent there (implementation, UX review, manual prod approval), and
the table says so on purpose. A failure there says **no agent owner**. It never
names an invented one.

**Dry runs are never shipped.** TheHub corrects its mislabelled `shipped`
dry runs on read (`autonomy_run_view`). This module uses the corrected status
and re-derives "did anything" from `dry_run` as well, through
`po_console.did_anything`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from mykronos import po_console as pc
from mykronos import product_owner as po


@dataclass(frozen=True)
class RaciRow:
    activity: str
    responsible: str
    #: Exactly one, as the table requires.
    accountable: str
    #: The table marks the operator Accountable because no agent does this
    #: job. A failure here has no agent owner.
    operator_only: bool


#: TheHub CLAUDE.md, "RACI over the agent fleet [AGENT-3 #48555]", in order.
RACI: tuple[RaciRow, ...] = (
    RaciRow("Idea intake & backlog triage", "Operator", "Synth (AIAgentOps)", False),
    RaciRow("Epic discovery & decomposition", "Operator", "Atlas (DevOps)", False),
    RaciRow("Requirements / ADR authorship", "Operator", "Warden (HubOps)", False),
    RaciRow("Technical design", "Operator", "Warden (HubOps)", False),
    RaciRow("Threat model / security review", "Operator", "Vance (SOC)", False),
    RaciRow("Sprint planning / pull", "Operator", "Warden (HubOps)", False),
    RaciRow("Implementation (Coding stage)", "Operator / Claude Code session", "Operator", True),
    RaciRow("Automated testing & coverage gate", "CI", "Atlas (DevOps)", False),
    RaciRow("UX / usability review", "Operator", "Operator", True),
    RaciRow("Data quality & freshness contracts", "Curator", "Curator (DataOps)", False),
    RaciRow("Build, package & artifact management", "CI", "Atlas (DevOps)", False),
    RaciRow("Deploy to staging + smoke test", "CI / deploy.sh", "Atlas (DevOps)", False),
    RaciRow("Manual approval → deploy to prod", "Operator", "Operator", True),
    RaciRow(
        "Post-deploy verification & incident escalation", "Beacon, IRRA", "Beacon (NOC)", False
    ),
)

_BY_ACTIVITY = {row.activity: row for row in RACI}

#: TheHub story gate -> the RACI activity whose gate it is.
GATE_ACTIVITY: dict[str, str] = {
    "intake": "Idea intake & backlog triage",
    "clarified": "Requirements / ADR authorship",
    "designed": "Technical design",
    "ready": "Sprint planning / pull",
    "in_progress": "Implementation (Coding stage)",
    "tested": "Automated testing & coverage gate",
    "deployed": "Deploy to staging + smoke test",
    "verified": "Post-deploy verification & incident escalation",
}

NO_AGENT_OWNER = "no agent owner"


def owner_of(hub_gate: str) -> tuple[RaciRow | None, str]:
    """The RACI row a failure at `hub_gate` belongs to, and the sentence the
    view shows: "blocked at <activity>, Accountable: <role>", or "… no agent
    owner" for an operator-only activity."""
    row = _BY_ACTIVITY.get(GATE_ACTIVITY.get(hub_gate, ""))
    if row is None:
        return None, f"blocked at {hub_gate}: no RACI activity covers this gate"
    if row.operator_only:
        return row, f"blocked at {row.activity}: {NO_AGENT_OWNER} (the operator is Accountable)"
    return row, f"blocked at {row.activity}, Accountable: {row.accountable}"


def gate_check_failures(
    stories: list[dict[str, Any]], manifest: po.ProcessManifest | None
) -> list[pc.GateFailure]:
    """Sprint stories failing the checklist of the gate they are at."""
    out: list[pc.GateFailure] = []
    for story in stories:
        check = po.check_story(story, manifest)
        if check.failed:
            out.append(
                pc.GateFailure(
                    story_id=int(story["id"]),
                    title=str(story.get("title") or ""),
                    kind="gate_check_failed",
                    hub_gate=str(story.get("gate") or "intake"),
                    detail=f"{check.failed} of {check.total} checks fail at {check.gate_name}",
                    at=story.get("updated_at"),
                )
            )
    return out


def run_rows(evidence: list[pc.StoryEvidence], since: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in evidence:
        for run in item.runs or []:
            started = pc.parse_time(run.get("started_at"))
            if started is None or started < since:
                continue
            cost = run.get("cost_usd")
            rows.append(
                {
                    "story_id": int(item.story["id"]),
                    "title": str(item.story.get("title") or ""),
                    "run_id": run.get("id"),
                    "status": run.get("status"),
                    "status_as_written": run.get("status_as_written"),
                    "dry_run": bool(run.get("dry_run")),
                    "shipped": pc.did_anything(run),
                    "cost_usd": float(cost) if isinstance(cost, int | float) else None,
                    "started_at": pc.iso(started),
                }
            )
    rows.sort(key=lambda r: r["started_at"] or "", reverse=True)
    return rows


def outcome_counts(runs: list[dict[str, Any]]) -> dict[str, int]:
    """By outcome. A dry run is `dry_run` whatever its status says, and only a
    live run counts as `shipped`."""
    counts: dict[str, int] = {"shipped": 0, "dry_run": 0}
    for run in runs:
        if run["dry_run"]:
            key = "dry_run"
        elif run["shipped"]:
            key = "shipped"
        else:
            key = str(run["status"] or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def verdicts(evidence: list[pc.StoryEvidence]) -> list[dict[str, Any]]:
    out = []
    for item in evidence:
        block = item.verification
        if not block:
            continue
        out.append(
            {
                "story_id": int(item.story["id"]),
                "title": str(item.story.get("title") or ""),
                "status": str(block.get("status") or "unknown"),
                "implementer_agent": block.get("implementer_agent"),
                "verifier_agent": block.get("verifier_agent"),
                "reason": block.get("reason"),
                "decided_at": block.get("decided_at") or block.get("submitted_at"),
            }
        )
    return out


def owned(failure: pc.GateFailure) -> dict[str, Any]:
    row, message = owner_of(failure.hub_gate)
    return {
        "failure": failure,
        "activity": row.activity if row else None,
        "accountable": None if row is None or row.operator_only else row.accountable,
        "operator_only": bool(row and row.operator_only),
        "message": message,
    }
