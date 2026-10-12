"""The Product Owner console's phase 2 views (spec 35 §8, D-144 - D-145).

Four views, each read from data MyKronos or TheHub already holds:

- **Delivery**: each commit the lake has seen, joined to the newest Oracle
  decision for it and to the deployment probe's running revision. MyKronos
  records only the running revision, so every other commit reads "not
  recorded", never "not deployed" (D-145).
- **Approvals inbox**: this repository's pending spec 34 requests. A request
  belongs to a repository through its frozen evidence, never through anything
  a caller says. The decision itself is the engine's (D-144); nothing here
  re-implements a rule.
- **Roles & agents**: the gates the manifest declares, beside the duties the
  platform enforces and the delegations that exist. Never merged into one
  word: a manifest's approver is free text that nothing enforces.
- **Retro**: computed from TheHub's record of the stories that closed, and
  the gates they failed on the way. No model writes it.

TheHub is read through `product_owner.HubClient`. A per-story read that fails
marks that story *unread*. It never counts as a clean story, because a failed
read is not evidence that nothing went wrong.
"""

from __future__ import annotations

import asyncio
import statistics
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from mykronos import product_owner as po

T = TypeVar("T")
R = TypeVar("R")

#: At most this many stories get per-story Hub reads in one view. A window
#: with more says how many were not read, rather than silently stopping.
MAX_STORY_READS = 40
#: Concurrent Hub requests from one view. TheHub runs on the same host, and a
#: console page should not be the thing that saturates it.
HUB_CONCURRENCY = 6
#: The shortest sha prefix treated as naming a commit. Shorter than git's own
#: default abbreviation, and two commits can share it.
MIN_SHA = 7

#: Autonomy statuses that mean the run stopped before finishing its work.
ABORTED = ("aborted_fail", "aborted_timeout", "aborted_cost", "aborted_deny")
#: `deploy_runs.final_status` values that are a failed deploy. `warned` is a
#: deploy that went out with a warning, which is not a failure.
FAILED_DEPLOY = ("failed", "failure", "error")


# --------------------------------------------------------------------------
# Small shared pieces
# --------------------------------------------------------------------------


def parse_time(value: Any) -> datetime | None:
    """An ISO timestamp from TheHub or the lake, as naive UTC. None when it is
    absent or not a timestamp: a guessed time is worse than none."""
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return moment.astimezone(UTC).replace(tzinfo=None) if moment.tzinfo else moment


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def sha_matches(left: str | None, right: str | None) -> bool:
    """Whether two shas name the same commit: one is a prefix of the other,
    and the shorter is long enough to mean something."""
    a, b = (left or "").strip().lower(), (right or "").strip().lower()
    if len(a) < MIN_SHA or len(b) < MIN_SHA:
        return False
    return a.startswith(b) or b.startswith(a)


async def gather_bounded(
    items: Iterable[T],
    fn: Callable[[T], Awaitable[R]],
    *,
    limit: int = HUB_CONCURRENCY,
) -> list[tuple[T, R | None, str | None]]:
    """`fn` over `items`, at most `limit` at a time. Each result carries the
    sentence of a `HubUnavailableError` instead of raising, so one failed read
    marks one story unread and does not lose the rest."""
    semaphore = asyncio.Semaphore(limit)

    async def one(item: T) -> tuple[T, R | None, str | None]:
        async with semaphore:
            try:
                return item, await fn(item), None
            except po.HubUnavailableError as exc:
                return item, None, str(exc)

    return list(await asyncio.gather(*(one(item) for item in items)))


# --------------------------------------------------------------------------
# Delivery (§8.1)
# --------------------------------------------------------------------------


def scan_rows(catalog: Any, repo_full_name: str, since: datetime) -> list[dict[str, Any]]:
    rows = catalog.query(
        """
        SELECT commit_sha, branch, pr_number, capability, scan_status,
               coalesce(completed_at, started_at) AS at, github_workflow_run_id,
               triggered_by
        FROM scan_runs
        WHERE repo_full_name = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
          AND coalesce(completed_at, started_at) >= ?
        """,
        [repo_full_name, since],
    )
    keys = ("sha", "branch", "pr_number", "capability", "status", "at", "run_id", "trigger")
    return [dict(zip(keys, row, strict=True)) for row in rows]


def decision_rows(catalog: Any, repo_full_name: str, since: datetime) -> list[dict[str, Any]]:
    rows = catalog.query(
        """
        SELECT commit_sha, pr_number, decision_type, recommendation, overall_risk_score,
               evaluated_at, gate_outcome, human_override
        FROM risk_decisions
        WHERE repo_full_name = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
          AND evaluated_at >= ?
        """,
        [repo_full_name, since],
    )
    keys = (
        "sha",
        "pr_number",
        "decision_type",
        "recommendation",
        "score",
        "evaluated_at",
        "gate_outcome",
        "human_override",
    )
    return [dict(zip(keys, row, strict=True)) for row in rows]


def canonical_shas(shas: Iterable[str]) -> dict[str, str]:
    """Each sha -> the longest sha it is a prefix of, so a short and a full
    spelling of one commit become one row rather than two."""
    unique = sorted({s.strip().lower() for s in shas if s and s.strip()}, key=len, reverse=True)
    mapping: dict[str, str] = {}
    for sha in unique:
        mapping[sha] = next(
            (full for full in unique if len(full) > len(sha) and full.startswith(sha)), sha
        )
    return mapping


@dataclass
class DeliveryRow:
    sha: str
    shipped: bool
    shipped_reason: str | None
    branches: list[str]
    pr_numbers: list[int]
    first_seen: datetime | None
    last_seen: datetime | None
    scans: list[dict[str, Any]]
    scan_failures: int
    decision: dict[str, Any] | None
    #: running | not_recorded (D-145). Never "not deployed".
    deployed: str


def actions_run_url(repo_full_name: str, run_id: Any) -> str | None:
    text = str(run_id or "").strip()
    return f"https://github.com/{repo_full_name}/actions/runs/{text}" if text.isdigit() else None


def build_delivery(
    repo_full_name: str,
    default_branch: str,
    scans: list[dict[str, Any]],
    decisions: list[dict[str, Any]],
    deployed_revision: str | None,
) -> list[DeliveryRow]:
    mapping = canonical_shas([r["sha"] for r in scans] + [r["sha"] for r in decisions])
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for row in scans:
        grouped.setdefault(mapping[row["sha"].strip().lower()], {"scans": [], "decisions": []})[
            "scans"
        ].append(row)
    for row in decisions:
        grouped.setdefault(mapping[row["sha"].strip().lower()], {"scans": [], "decisions": []})[
            "decisions"
        ].append(row)

    out: list[DeliveryRow] = []
    for sha, parts in grouped.items():
        sha_scans = sorted(parts["scans"], key=lambda r: parse_time(r["at"]) or datetime.min)
        sha_decisions = sorted(
            parts["decisions"], key=lambda r: parse_time(r["evaluated_at"]) or datetime.min
        )
        pushed = any(
            r["branch"] == default_branch and r["pr_number"] in (None, 0) for r in sha_scans
        )
        merged = any(r["gate_outcome"] == "merged" for r in sha_decisions)
        reason = (
            f"scanned on {default_branch}" if pushed else "pull request merged" if merged else None
        )
        times = [parse_time(r["at"]) for r in sha_scans] + [
            parse_time(r["evaluated_at"]) for r in sha_decisions
        ]
        seen = [t for t in times if t is not None]
        latest = sha_decisions[-1] if sha_decisions else None
        out.append(
            DeliveryRow(
                sha=sha,
                shipped=bool(reason),
                shipped_reason=reason,
                branches=sorted({str(r["branch"]) for r in sha_scans if r["branch"]}),
                pr_numbers=sorted(
                    {
                        int(r["pr_number"])
                        for r in sha_scans + sha_decisions
                        if r["pr_number"] not in (None, 0)
                    }
                ),
                first_seen=min(seen) if seen else None,
                last_seen=max(seen) if seen else None,
                scans=[
                    {
                        "capability": r["capability"],
                        "status": r["status"],
                        "at": iso(parse_time(r["at"])),
                        "run_url": actions_run_url(repo_full_name, r["run_id"]),
                    }
                    for r in sha_scans
                ],
                scan_failures=sum(
                    1 for r in sha_scans if str(r["status"] or "") not in ("success", "")
                ),
                decision=(
                    {
                        "decision_type": latest["decision_type"],
                        "recommendation": latest["recommendation"],
                        "score": latest["score"],
                        "evaluated_at": iso(parse_time(latest["evaluated_at"])),
                        "gate_outcome": latest["gate_outcome"],
                        "human_override": latest["human_override"],
                    }
                    if latest
                    else None
                ),
                deployed="running" if sha_matches(sha, deployed_revision) else "not_recorded",
            )
        )
    out.sort(key=lambda r: r.last_seen or datetime.min, reverse=True)
    return out


# --------------------------------------------------------------------------
# Approvals inbox (§8.2)
# --------------------------------------------------------------------------


def request_repo(duty: str, subject_ref: str, evidence: Any) -> str | None:
    """The repository a request is about, read from its frozen evidence.

    `repo` for a pull request merge and a risk acceptance, and
    `finding.repo_full_name` for a finding disposition. The subject ref's
    `owner/name#n@sha` shape is the fallback for a pull request whose evidence
    predates the `repo` key. None for a request about no repository, such as
    a delegation grant.
    """
    data = evidence if isinstance(evidence, dict) else {}
    repo = data.get("repo")
    if isinstance(repo, str) and repo.strip():
        return repo.strip()
    finding = data.get("finding")
    if isinstance(finding, dict):
        name = finding.get("repo_full_name")
        if isinstance(name, str) and name.strip():
            return name.strip()
    if duty == "pull_request_merge" and "#" in subject_ref:
        return subject_ref.split("#", 1)[0] or None
    return None


def same_repo(left: str | None, right: str | None) -> bool:
    return bool(left and right and left.lower() == right.lower())


def evidence_summary(duty: str, evidence: Any) -> str:
    """One line a person can recognise the request by. The evidence is the
    platform's, so this quotes it; it is not the requester's statement."""
    data = evidence if isinstance(evidence, dict) else {}
    if duty == "pull_request_merge":
        return f"#{data.get('number', '?')} {data.get('title', '')}".strip()
    if duty == "risk_acceptance":
        residual = (data.get("residual") or {}).get("severity", "")
        return f"{residual} acceptance: {str(data.get('justification') or '')[:160]}".strip()
    if duty == "finding_disposition":
        finding = data.get("finding") or {}
        return f"{finding.get('title', 'finding')} -> {data.get('status', '')}".strip(" ->")
    return str(data.get("title") or "")[:160]


def tier_needs(policy: Any, duty: str, tier: str) -> dict[str, Any] | None:
    """What the tier asks of an approver, as the policy states it. Shown so a
    person can see why the engine might refuse; never used to pre-judge."""
    try:
        rules = policy.duty(duty).tiers[tier]
    except (KeyError, ValueError):
        return None
    return {
        "approvers": [
            {"kind": a.kind, "delegation_required": a.delegation_required} for a in rules.approvers
        ],
        "quorum": rules.quorum,
        "independence": sorted(str(rule.value) for rule in rules.independence),
        "cooling_off_hours": rules.cooling_off_hours,
    }


# --------------------------------------------------------------------------
# Roles & agents (§8.3)
# --------------------------------------------------------------------------


def delegation_active(row: Any, now: datetime) -> bool:
    return not (row.revoked_at or row.suspended_at) and row.expires_at > now


def enforced_duties(policy: Any, delegations: list[Any], now: datetime) -> list[dict[str, Any]]:
    """Every duty and tier the platform enforces, and whether an agent can
    approve it now: `yes` (with the delegations), `no_active_delegation`, or
    `humans_only`."""
    out: list[dict[str, Any]] = []
    for duty in policy.duties.values():
        for tier in duty.tiers.values():
            agent = tier.admits("agent")
            covering = [
                d
                for d in delegations
                if d.duty == duty.name
                and tier.name in (d.tiers or [])
                and delegation_active(d, now)
            ]
            if agent is None:
                agent_now = "humans_only"
            elif not agent.delegation_required or covering:
                agent_now = "yes"
            else:
                agent_now = "no_active_delegation"
            out.append(
                {
                    "duty": duty.name,
                    "tier": tier.name,
                    "approvers": [a.kind for a in tier.approvers],
                    "quorum": tier.quorum,
                    "independence": sorted(str(rule.value) for rule in tier.independence),
                    "cooling_off_hours": tier.cooling_off_hours,
                    "agent_now": agent_now,
                    "delegations": [
                        {
                            "id": d.id,
                            "families": list(d.approver_families or []),
                            "expires_at": iso(d.expires_at),
                            "sampling": d.sampling,
                        }
                        for d in covering
                    ],
                }
            )
    return out


# --------------------------------------------------------------------------
# Per-story Hub evidence (shared by the retro and the fleet view)
# --------------------------------------------------------------------------


@dataclass
class StoryEvidence:
    story: dict[str, Any]
    #: TheHub's `/autonomy-cost` runs, status already corrected on read.
    runs: list[dict[str, Any]] | None = None
    #: `phase_docs.verification`, the latest block only.
    verification: dict[str, Any] | None = None
    deploys: list[dict[str, Any]] | None = None
    #: The reads that failed. A story with any is shown as unread, not clean.
    unread: list[str] = field(default_factory=list)


async def story_evidence(
    hub: po.HubClient, story: dict[str, Any], want: tuple[str, ...]
) -> StoryEvidence:
    sid = int(story["id"])
    evidence = StoryEvidence(story=story)
    paths = {
        "runs": f"/api/dev/stories/{sid}/autonomy-cost",
        "notes": f"/api/dev/stories/{sid}/notes",
        "deploys": f"/api/dev/stories/{sid}/deploys",
    }
    results = await asyncio.gather(
        *(hub.get_json(paths[name]) for name in want), return_exceptions=True
    )
    for name, result in zip(want, results, strict=True):
        if isinstance(result, BaseException):
            if not isinstance(result, po.HubUnavailableError):
                raise result
            evidence.unread.append(name)
            continue
        body = result if isinstance(result, dict) else {}
        if name == "runs":
            evidence.runs = [r for r in body.get("runs") or [] if isinstance(r, dict)]
        elif name == "notes":
            raw_docs = body.get("phase_docs")
            docs = raw_docs if isinstance(raw_docs, dict) else {}
            block = docs.get("verification")
            evidence.verification = block if isinstance(block, dict) else None
        else:
            evidence.deploys = [d for d in body.get("deploys") or [] if isinstance(d, dict)]
    return evidence


async def evidence_for(
    hub: po.HubClient, stories: list[dict[str, Any]], want: tuple[str, ...]
) -> tuple[list[StoryEvidence], int]:
    """Evidence for at most `MAX_STORY_READS` stories, and how many were left
    unread because of the cap."""
    chosen = stories[:MAX_STORY_READS]
    gathered = await gather_bounded(chosen, lambda s: story_evidence(hub, s, want))
    out = [
        result if result is not None else StoryEvidence(story=story, unread=list(want))
        for story, result, _ in gathered
    ]
    return out, max(0, len(stories) - len(chosen))


def did_anything(run: dict[str, Any]) -> bool:
    """A live run that shipped. Re-derived from `dry_run` as well as read from
    TheHub's corrected status, so an endpoint that forgot the correction
    cannot bring the mislabelled dry runs back (D-147)."""
    return run.get("status") == "shipped" and not run.get("dry_run")


@dataclass
class GateFailure:
    story_id: int
    title: str
    #: verification_rejected | run_aborted | deploy_failed | gate_check_failed
    kind: str
    #: TheHub's gate the failure happened at.
    hub_gate: str
    detail: str
    at: str | None


def failures_of(evidence: StoryEvidence, since: datetime | None = None) -> list[GateFailure]:
    """The gates one story failed on the way, from what TheHub recorded."""
    story = evidence.story
    sid, title = int(story["id"]), str(story.get("title") or "")
    out: list[GateFailure] = []
    block = evidence.verification or {}
    if block.get("status") == "rejected":
        out.append(
            GateFailure(
                story_id=sid,
                title=title,
                kind="verification_rejected",
                hub_gate="tested",
                detail=str(block.get("reason") or "rejected by verification, no reason given")[
                    :300
                ],
                at=block.get("decided_at"),
            )
        )
    for run in evidence.runs or []:
        started = parse_time(run.get("started_at"))
        if since is not None and (started is None or started < since):
            continue
        if run.get("status") in ABORTED:
            out.append(
                GateFailure(
                    story_id=sid,
                    title=title,
                    kind="run_aborted",
                    hub_gate="in_progress",
                    detail=f"autonomy run {run.get('id')} {run.get('status')}",
                    at=run.get("started_at"),
                )
            )
    for deploy in evidence.deploys or []:
        started = parse_time(deploy.get("started_at"))
        if since is not None and (started is None or started < since):
            continue
        if str(deploy.get("final_status") or "").lower() in FAILED_DEPLOY:
            out.append(
                GateFailure(
                    story_id=sid,
                    title=title,
                    kind="deploy_failed",
                    hub_gate="deployed",
                    detail=f"deploy {deploy.get('deploy_id') or deploy.get('id')} "
                    f"of {deploy.get('sha') or '?'} {deploy.get('final_status')}",
                    at=deploy.get("started_at"),
                )
            )
    return out


# --------------------------------------------------------------------------
# Retro (§8.4)
# --------------------------------------------------------------------------

RETRO_LIMITATION = (
    "TheHub keeps only the latest verification block per story, so a rejection "
    "followed by a passing resubmission is not visible here."
)


def stories(count: int, kind: str = "") -> str:
    return f"{count} {kind}stor{'y' if count == 1 else 'ies'}"


def closed_at(story: dict[str, Any]) -> datetime | None:
    return parse_time(story.get("closed_at")) or parse_time(story.get("moved_at"))


def build_retro(
    evidence: list[StoryEvidence],
    carried: list[dict[str, Any]],
    *,
    days: int,
    not_read: int,
) -> dict[str, Any]:
    """The computed retrospective (D-145). Every line is a count or a list a
    person can check against TheHub."""
    closed = [e.story for e in evidence]
    sizes: dict[str, int] = {}
    for story in closed:
        key = str(story.get("size") or "unsized")
        sizes[key] = sizes.get(key, 0) + 1
    cycles = [
        (end - start).total_seconds() / 86400
        for story in closed
        if (start := parse_time(story.get("created_at"))) and (end := closed_at(story))
    ]
    median = round(statistics.median(cycles), 1) if cycles else None
    failures = [f for e in evidence for f in failures_of(e)]
    failed_ids = {f.story_id for f in failures}
    no_ac = [int(s["id"]) for s in closed if not (s.get("acceptance_criteria") or [])]
    no_note = [int(s["id"]) for s in closed if not str(s.get("retrospective_md") or "").strip()]
    unread = [int(e.story["id"]) for e in evidence if e.unread]
    dry_runs = sum(1 for e in evidence for r in e.runs or [] if r.get("dry_run"))
    shipped_runs = sum(1 for e in evidence for r in e.runs or [] if did_anything(r))

    lines = [f"{stories(len(closed))} closed in the last {days} days."]
    if median is not None:
        lines.append(f"Median cycle time, created to closed: {median} days.")
    if closed:
        lines.append(
            f"{len(failed_ids)} of {len(closed)} failed at least one gate on the way."
            if failed_ids
            else "None failed a recorded gate on the way."
        )
    if no_ac:
        lines.append(f"{len(no_ac)} closed without acceptance criteria.")
    if no_note:
        lines.append(f"{len(no_note)} have no retrospective note in TheHub.")
    if carried:
        lines.append(f"{stories(len(carried), 'sprint ')} carried over from before the window.")
    lines.append(
        f"Autonomy: {shipped_runs} live run(s) shipped; {dry_runs} dry run(s), counted apart."
    )
    if unread:
        lines.append(f"{stories(len(unread))} could not be read from TheHub; not counted as clean.")
    if not_read:
        lines.append(
            f"{stories(not_read, 'more closed ')} not read: the view reads at most "
            f"{MAX_STORY_READS}."
        )
    return {
        "days": days,
        "closed": len(closed),
        "sizes": sizes,
        "median_cycle_days": median,
        "failed_stories": len(failed_ids),
        "failures": failures,
        "no_acceptance_criteria": no_ac,
        "no_retrospective_note": no_note,
        "carried_over": [int(s["id"]) for s in carried],
        "dry_runs": dry_runs,
        "shipped_runs": shipped_runs,
        "unread": unread,
        "not_read": not_read,
        "summary": lines,
        "limitation": RETRO_LIMITATION,
        "stories": [
            {
                "id": int(e.story["id"]),
                "title": str(e.story.get("title") or ""),
                "size": e.story.get("size") or None,
                "closed_at": iso(closed_at(e.story)),
                "unread": list(e.unread),
                "failed_gates": sorted({f.hub_gate for f in failures_of(e)}),
            }
            for e in evidence
        ],
    }


def window_start(days: int, now: datetime | None = None) -> datetime:
    from mykronos.schemas import utcnow

    return (now or utcnow()) - timedelta(days=days)
