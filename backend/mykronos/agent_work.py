"""The agent work queue: what needs doing, and what the platform does not know
(spec 36 §2–§3).

An agent operating this platform arrives with one question: *what needs doing,
and what don't you know?* Nine surfaces answer nine narrower questions, and
assembling the answer by hand is where `_unknown` flags get dropped and labels
get misread (#319). This module is that assembly, done once, from inputs the
platform already computes. It adds no analysis of its own: every item cites the
record it came from, the same rule `triage_story` and the Oracle's
`inputs_snapshot` follow.

Three things are decided here and nowhere else:

**The order.** Platform problems first, because a dead lane freezes every
finding in it and work on a frozen finding cannot be observed (D-098); findings
last. Within a band: severity, then size, then `item_id`, so the same state
gives the same order on every call.

**What could not be read.** A source that failed is listed in `unknown` and
contributes no items. It is never an empty list, which would claim the source
was asked and is clean.

**Which caveats apply.** Each is a fact the platform holds about a kind of
finding or record that an agent would otherwise have to remember (§3). Codes are
stable so an agent can branch on them; the sentences are for a person.

What it does not decide is anything an action does. `governed_by` is computed
with the same function the route uses, so the queue cannot promise a direct
write the route will refuse, but the route still makes the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from mykronos import finding_disposition
from mykronos.adminauth import Principal
from mykronos.briefing import Briefing

#: Bands, in the order an agent works them (spec 36 §2.2).
BAND_PLATFORM = 1
BAND_COMPOSITE = 2
BAND_APPROVAL = 3
BAND_ACCEPTANCE = 4
BAND_TOKEN = 5
BAND_FINDING = 6

#: Every kind of work item `build` can emit, in band order (spec 36 §2.2).
#:
#: The single source of the list. `agent-playbooks-v1.yaml` must hold exactly
#: one playbook per entry and `mykronos.playbooks` refuses a file that does
#: not; `WorkItem` refuses a kind not named here, so a new item kind cannot
#: reach an agent without a playbook being written for it first (spec 36 §5).
KINDS: tuple[str, ...] = (
    "lane_stalled",
    "ci_job_failing",
    "ci_job_paused",
    "platform_job_unhealthy",
    "toxic_combination",
    "public_exposure",
    "approval_needs_info",
    "acceptance_attention",
    "token_delivery",
    "triage",
)

#: An acceptance this close to `expires_at` is surfaced before it lapses.
ACCEPTANCE_LEAD_DAYS = 14

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Observations at these severities make an exposed endpoint a work item.
_EXPOSURE_SEVERITIES = ("critical", "high")


@dataclass
class Evidence:
    source: str
    ref: str
    detail: str = ""


@dataclass
class Precondition:
    description: str
    #: False when unmet, None when the platform cannot say.
    met: bool | None
    #: The `item_id` whose completion meets this, when it is in the queue.
    blocked_by: str | None = None


@dataclass
class ActionRef:
    label: str
    method: str
    path: str
    effect: str
    #: The approval duty this call is routed through for this principal, or
    #: None when the route writes directly.
    governed_by: str | None = None


@dataclass
class Caveat:
    code: str
    detail: str


@dataclass
class WorkItem:
    item_id: str
    kind: str
    band: int
    title: str
    summary: str
    done_when: str
    repo_full_name: str = ""
    severity: str | None = None
    #: How many findings this item holds open or covers; a tiebreak within a
    #: band, so the larger of two equal items comes first.
    weight: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    preconditions: list[Precondition] = field(default_factory=list)
    actions: list[ActionRef] = field(default_factory=list)
    caveats: list[Caveat] = field(default_factory=list)
    #: `<kind>@<version>` of the playbook that says how to work this item
    #: (spec 36 §5), stamped by `build`. Read it from
    #: `GET /api/agent/playbooks/{kind}`.
    playbook: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(
                f"Work item kind {self.kind!r} is not in agent_work.KINDS; add it there "
                "and write its playbook in agent-playbooks-v1.yaml."
            )


@dataclass
class Waiting:
    """Something that needs no action, listed so it is not mistaken for work."""

    kind: str
    ref: str
    repo_full_name: str
    detail: str


@dataclass
class Unknown:
    source: str
    detail: str


@dataclass
class WorkQueue:
    generated_at: datetime
    actor: str
    actor_kind: str
    items: list[WorkItem] = field(default_factory=list)
    waiting: list[Waiting] = field(default_factory=list)
    unknown: list[Unknown] = field(default_factory=list)


def _sort_key(item: WorkItem) -> tuple[int, int, int, str]:
    return (
        item.band,
        _SEVERITY_ORDER.get(str(item.severity or ""), 5),
        -item.weight,
        item.item_id,
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Band 1: the platform


def lane_id(repo: str, capability: str) -> str:
    return f"lane_stalled:{repo}:{capability}"


def _by_id(path: str, repo: str, repo_ids: dict[str, str]) -> str | None:
    """`path` with the repository's onboarding id where its full name stood.

    The briefing writes its lane actions as `/api/repos/<owner/repo>/scan`,
    and those routes take an onboarding id (`_resolve_repo`: a full name has a
    slash and cannot be one path segment), so the path it prints cannot be
    called. Rewritten here, where an agent will call it; None when the
    repository has no onboarding row, so no dead path is offered.
    """
    repo_id = repo_ids.get(repo)
    if not repo_id:
        return None
    return path.replace(f"/{repo}/", f"/{repo_id}/")


def _lane_items(briefing: Briefing, repo_ids: dict[str, str]) -> list[WorkItem]:
    items = []
    for lane in briefing.stalled:
        last = lane.last_success.isoformat() if lane.last_success else "never"
        path = _by_id(lane.action.path, lane.repo_full_name, repo_ids)
        actions = (
            []
            if path is None
            else [
                ActionRef(
                    label=lane.action.label,
                    method=lane.action.method,
                    path=path,
                    effect=lane.action.effect,
                )
            ]
        )
        summary = lane.detail or f"The {lane.capability} lane is {lane.reason}."
        if lane.reason == "blocked" and lane.blocked_by:
            summary += f" It waits on {lane.blocked_by}, which is the lane to repair."
        items.append(
            WorkItem(
                item_id=lane_id(lane.repo_full_name, lane.capability),
                kind="lane_stalled",
                band=BAND_PLATFORM,
                repo_full_name=lane.repo_full_name,
                weight=lane.open_findings,
                title=f"{lane.capability} for {lane.repo_full_name} is {lane.reason}",
                summary=summary,
                done_when=(
                    f"Two successful {lane.capability} runs. Until then none of its "
                    f"{lane.open_findings} open finding(s) can close, however well fixed."
                ),
                evidence=[
                    Evidence(
                        source="briefing.stalled",
                        ref=f"{lane.repo_full_name}/{lane.capability}",
                        detail=(
                            f"{lane.consecutive_failures}"
                            f"{'+' if lane.streak_capped else ''} consecutive failure(s); "
                            f"last success {last}"
                        ),
                    ),
                    *(
                        [
                            Evidence(
                                source="scan_run",
                                ref=f"/api/dashboard/scan-runs/{lane.last_scan_run_id}",
                                detail=(
                                    "the lane's most recent run: its outcome, what it "
                                    "changed, and the raw tool output it archived"
                                ),
                            )
                        ]
                        if lane.last_scan_run_id
                        else []
                    ),
                ],
                actions=actions,
            )
        )
    return items


def _held_behind(briefing: Briefing, pipeline: str, job: str) -> list[Evidence]:
    """The lanes this red or paused job is stopping (TheHub#349).

    Not an item of their own: the work is on the root, and an item per held
    lane would send an agent to re-run jobs that cannot run. Attached as
    evidence to the root's item instead, which is what its playbook asks to be
    handed to a person ("what depends on the job").
    """
    return [
        Evidence(
            source="concourse",
            ref=f"{held.pipeline}/{held.job}",
            detail=(
                f"did not run: behind {held.root} ({held.root_state})"
                + ("" if held.blocked_by == held.root else f" via {held.blocked_by}")
            ),
        )
        for held in sorted(briefing.blocked, key=lambda b: b.job)
        if held.pipeline == pipeline and held.root == job
    ]


def _ci_items(briefing: Briefing) -> list[WorkItem]:
    items = []
    for job in briefing.failing:
        items.append(
            WorkItem(
                item_id=f"ci_job_failing:{job.pipeline}/{job.job}",
                kind="ci_job_failing",
                band=BAND_PLATFORM,
                title=f"{job.pipeline}/{job.job} is failing",
                summary=(
                    "Failing on its trigger and not paused. Read the failed build's "
                    "output first; a re-run of a broken job fails again."
                ),
                done_when="The job's latest build succeeds.",
                evidence=[
                    Evidence(
                        source="concourse",
                        ref=job.build_url or f"{job.pipeline}/{job.job}",
                        detail=f"last status {job.last_status}",
                    ),
                    *_held_behind(briefing, job.pipeline, job.job),
                ],
            )
        )
    for paused in briefing.paused:
        items.append(
            WorkItem(
                item_id=f"ci_job_paused:{paused.pipeline}/{paused.job}",
                kind="ci_job_paused",
                band=BAND_PLATFORM,
                title=f"{paused.pipeline}/{paused.job} is paused",
                summary=(
                    "Somebody switched this job off. The build that was running when it "
                    "stopped is usually why; read it before unpausing."
                ),
                done_when="The job is unpaused and its next build succeeds.",
                evidence=[
                    Evidence(
                        source="concourse",
                        ref=paused.build_url or f"{paused.pipeline}/{paused.job}",
                        detail=f"last status {paused.last_status}",
                    ),
                    *_held_behind(briefing, paused.pipeline, paused.job),
                ],
            )
        )
    return items


def _job_items(briefing: Briefing) -> list[WorkItem]:
    items = []
    for job in briefing.unhealthy_jobs:
        name = str(getattr(job, "name", ""))
        status = str(getattr(job, "status", ""))
        items.append(
            WorkItem(
                item_id=f"platform_job_unhealthy:{name}",
                kind="platform_job_unhealthy",
                band=BAND_PLATFORM,
                weight=int(getattr(job, "consecutive_failures", 0) or 0),
                title=f"Scheduled job {name} is {status}",
                summary=str(getattr(job, "detail", "")),
                done_when="The job's next run succeeds.",
                evidence=[Evidence(source="job_runs", ref=name, detail=status)],
            )
        )
    return items


# ---------------------------------------------------------------------------
# Band 2: composite risk


def _toxic_items(briefing: Briefing) -> list[WorkItem]:
    dark = list((briefing.toxic_coverage or {}).get("cannot_fire") or [])
    items = []
    for combo in briefing.toxic:
        repo = str(combo.get("repo_full_name") or "")
        members = list(combo.get("members") or [])
        caveats = []
        if combo.get("partly_accepted"):
            caveats.append(
                Caveat(
                    "partly_accepted",
                    "A member is an accepted risk. The combination still counts: "
                    "accepting half of a toxic pair does not make the pair go away.",
                )
            )
        if dark:
            caveats.append(
                Caveat(
                    "rules_cannot_fire",
                    f"{len(dark)} combination rule(s) cannot fire on the data the lake "
                    "holds; no combination from them is not evidence of none.",
                )
            )
        combination_id = str(combo.get("combination_id") or "")
        # No action. The groom route answers 410 for every combination since
        # D-161, and offering it sent an agent to a call that cannot succeed
        # (#60756). The story is filed in TheHub; the playbook says how.
        items.append(
            WorkItem(
                item_id=f"toxic_combination:{repo}:{combination_id}",
                kind="toxic_combination",
                band=BAND_COMPOSITE,
                repo_full_name=repo,
                severity=str(combo.get("severity") or "") or None,
                weight=len(members),
                title=f"{combo.get('name')} in {repo}",
                summary=str(combo.get("rationale") or ""),
                done_when=(
                    "Any one member closes and the combination stops firing. Fixing one "
                    "half usually closes the finding without closing the risk; fix both."
                ),
                evidence=[
                    Evidence(
                        source="toxic.detect",
                        ref=str(m.get("finding_id") or ""),
                        detail=f"{m.get('severity')} {m.get('rule_id')}",
                    )
                    for m in members
                ],
                actions=[],
                caveats=caveats,
            )
        )
    return items


def _exposure_items(
    briefing: Briefing, *, now: datetime, probe_interval_seconds: int
) -> list[WorkItem]:
    items = []
    stale_after = timedelta(seconds=2 * max(probe_interval_seconds, 1))
    for endpoint in briefing.exposure:
        serious = [
            o
            for o in (endpoint.get("observations") or [])
            if str(o.get("severity") or "") in _EXPOSURE_SEVERITIES
        ]
        if not serious:
            continue
        worst = min(
            (str(o.get("severity")) for o in serious), key=lambda s: _SEVERITY_ORDER[s]
        )
        caveats = []
        probed = endpoint.get("last_probed_at")
        if probed:
            when = _aware(datetime.fromisoformat(str(probed)))
            if now - when > stale_after:
                caveats.append(
                    Caveat(
                        "probe_stale",
                        f"Last probed {when.isoformat()}, more than two probe intervals "
                        "ago. What an anonymous visitor gets today may differ.",
                    )
                )
        url = str(endpoint.get("url") or "")
        items.append(
            WorkItem(
                item_id=f"public_exposure:{endpoint.get('id')}",
                kind="public_exposure",
                band=BAND_COMPOSITE,
                repo_full_name=str(endpoint.get("repo_full_name") or ""),
                severity=worst,
                weight=len(serious),
                title=f"{url} gives an anonymous visitor something {worst}",
                summary="; ".join(str(o.get("title") or "") for o in serious),
                done_when=f"The next probe of {url} observes nothing high or critical.",
                evidence=[
                    Evidence(
                        source="exposure",
                        ref=url,
                        detail=f"{o.get('severity')} {o.get('kind')}: {o.get('detail')}",
                    )
                    for o in serious
                ],
                caveats=caveats,
            )
        )
    return items


# ---------------------------------------------------------------------------
# Band 3: the principal's own approval requests


def _approval_items(requests: list[dict[str, Any]]) -> tuple[list[WorkItem], list[Waiting]]:
    items: list[WorkItem] = []
    waiting: list[Waiting] = []
    for req in requests:
        if req.get("last_verdict") == "needs_info":
            items.append(
                WorkItem(
                    item_id=f"approval_needs_info:{req['id']}",
                    kind="approval_needs_info",
                    band=BAND_APPROVAL,
                    repo_full_name=str(req.get("repo_full_name") or ""),
                    title=f"Your {req['duty']} request on {req['subject_ref']} needs information",
                    summary=str(req.get("last_rationale") or ""),
                    done_when="The request is decided.",
                    evidence=[
                        Evidence(
                            source="approval_requests", ref=str(req["id"]), detail="needs_info"
                        )
                    ],
                    actions=[
                        ActionRef(
                            label="Read the request and its decisions",
                            method="GET",
                            path=f"/api/approvals/{req['id']}",
                            effect="A read. Answer by supplying what was asked for.",
                        )
                    ],
                )
            )
        else:
            waiting.append(
                Waiting(
                    kind="approval_pending",
                    ref=str(req["id"]),
                    repo_full_name=str(req.get("repo_full_name") or ""),
                    detail=(
                        f"{req['duty']} on {req['subject_ref']} is with an approver. "
                        "You cannot approve your own request."
                    ),
                )
            )
    return items, waiting


# ---------------------------------------------------------------------------
# Band 4: acceptances


def _acceptance_items(acceptances: list[dict[str, Any]], *, today: date) -> list[WorkItem]:
    items = []
    for record in acceptances:
        reasons = []
        status = str(record.get("status") or "")
        if status == "review_due":
            reasons.append(f"review was due {record.get('review_by')}")
        if status == "premise_failed":
            reasons.append("a premise it rests on no longer holds")
        if record.get("drift"):
            reasons.append(f"{record['drift']} open finding(s) match its scope and are not covered")
        expires = record.get("expires_at")
        if expires and status in ("active", "review_due"):
            left = (date.fromisoformat(str(expires)) - today).days
            if left <= ACCEPTANCE_LEAD_DAYS:
                reasons.append(f"it expires in {left} day(s)")
        if not reasons:
            continue
        record_id = str(record["id"])
        items.append(
            WorkItem(
                item_id=f"acceptance_attention:{record_id}",
                kind="acceptance_attention",
                band=BAND_ACCEPTANCE,
                repo_full_name=str(record.get("repo") or ""),
                severity=str(record.get("residual_severity") or "") or None,
                weight=int(record.get("findings") or 0),
                title=f"Acceptance {record_id[:8]} needs attention",
                summary="; ".join(reasons).capitalize() + ".",
                done_when="Renewed, revoked or closed.",
                evidence=[Evidence(source="risk_acceptances", ref=record_id, detail=status)],
                actions=[
                    ActionRef(
                        label="Renew it",
                        method="POST",
                        path=f"/api/risk-acceptances/{record_id}/renew",
                        effect="A new approval request. The record stays as it is until decided.",
                        governed_by="risk_acceptance",
                    )
                ],
            )
        )
    return items


# ---------------------------------------------------------------------------
# Band 5: tokens


def _token_items(briefing: Briefing) -> list[WorkItem]:
    items = []
    for token in briefing.tokens:
        caveats = []
        if token.state == "unverified":
            caveats.append(
                Caveat(
                    "do_not_rotate",
                    "Delivery of this token was never confirmed. Check that scans arrive; "
                    "rotating a token whose Vault copy works is how a repository goes "
                    "dark (D-097).",
                )
            )
        items.append(
            WorkItem(
                item_id=f"token_delivery:{token.repo_full_name}",
                kind="token_delivery",
                band=BAND_TOKEN,
                repo_full_name=token.repo_full_name,
                title=f"Ingestion token for {token.repo_full_name} is {token.state}",
                summary=(
                    f"{token.days_until_due:.0f} day(s) until rotation is due; scanned by "
                    f"{token.scanned_by or 'unknown'}, which this platform cannot deliver to."
                ),
                done_when=(
                    "A scan confirms the token arrives."
                    if token.state == "unverified"
                    else "Rotated by hand and a scan confirms the new token arrives."
                ),
                evidence=[Evidence(source="ingestion_tokens", ref=token.repo_full_name)],
                caveats=caveats,
            )
        )
    return items


# ---------------------------------------------------------------------------
# Band 6: findings


def _finding_caveats(row: dict[str, Any], *, lane_frozen: bool) -> list[Caveat]:
    caveats = []
    capability = str(row.get("capability") or "")
    if lane_frozen:
        caveats.append(
            Caveat(
                "lane_frozen",
                "This finding's lane is stalled. Nothing done to it will be observed "
                "until the lane runs successfully twice.",
            )
        )
    if capability == "dast":
        caveats.append(
            Caveat(
                "identity_is_the_route",
                "Since #440 a DAST finding's identity is its route: the query string "
                "is dropped and ephemeral ids are templated, so one disposition covers "
                "every URL on that route. The URL actually scanned is in "
                "raw_finding_json.instance.uri; read it before judging.",
            )
        )
    if capability == "containers":
        caveats.append(
            Caveat(
                "fix_is_a_package",
                "A fixed version names a patched package, not a patched image. Compare "
                "image digests before recommending a pull or a rebuild.",
            )
        )
    if row.get("version_basis") in ("declared_floor", "declared_pin"):
        caveats.append(
            Caveat(
                "declared_version",
                f"The version is the {str(row['version_basis']).replace('_', ' ')}, not the "
                "resolved one. The version that actually runs may differ.",
            )
        )
    if row.get("triage") == "true_positive":
        caveats.append(
            Caveat(
                "severity_only_triage",
                "'true_positive' is derived from severity alone; nothing has read the code.",
            )
        )
    return caveats


def _finding_actions(row: dict[str, Any], principal: Principal) -> list[ActionRef]:
    finding_id = str(row["finding_id"])
    severity = str(row.get("severity") or "")
    actions = [
        ActionRef(
            label="Claim it",
            method="POST",
            path=f"/api/dashboard/triage/{finding_id}/claim",
            effect="Marks it as yours for a while, so another agent does not work it too.",
        )
    ]
    if finding_disposition.governed(principal, severity):
        actions.append(
            ActionRef(
                label="Request a false-positive disposition",
                method="POST",
                path=f"/api/dashboard/findings/{finding_id}/disposition-requests",
                effect=(
                    "Freezes the evidence and asks someone independent. "
                    "It stays open until decided."
                ),
                governed_by="finding_disposition",
            )
        )
    else:
        actions.append(
            ActionRef(
                label="Disposition it",
                method="PATCH",
                path=f"/api/dashboard/findings/{finding_id}/status",
                effect="Sets the status directly, with your reason, attributed to you.",
            )
        )
    actions.append(
        ActionRef(
            label="Propose a risk acceptance",
            method="POST",
            path="/api/risk-acceptances",
            effect="An acceptance with a review date, decided by an approver.",
            governed_by="risk_acceptance",
        )
    )
    if row.get("capability") == "atlas":
        actions.append(
            ActionRef(
                label="Generate a fix",
                method="POST",
                path=f"/api/patchwork/findings/{finding_id}/fix",
                effect="Opens a draft pull request if a deterministic fixer applies. Never merges.",
            )
        )
    return actions


def _finding_items(
    rows: list[dict[str, Any]], briefing: Briefing, principal: Principal
) -> list[WorkItem]:
    stalled = {(lane.repo_full_name, lane.capability) for lane in briefing.stalled}
    items = []
    for row in rows:
        claimed_by = (row.get("state") or {}).get("claimed_by")
        if claimed_by and claimed_by != principal.actor:
            continue
        repo = str(row.get("repo_full_name") or "")
        capability = str(row.get("capability") or "")
        frozen = (repo, capability) in stalled
        preconditions = []
        if frozen:
            preconditions.append(
                Precondition(
                    description=f"The {capability} lane for {repo} runs successfully",
                    met=False,
                    blocked_by=lane_id(repo, capability),
                )
            )
        where = row.get("file_path") or row.get("package_name") or ""
        finding_id = str(row["finding_id"])
        items.append(
            WorkItem(
                item_id=f"triage:{finding_id}",
                kind="triage",
                band=BAND_FINDING,
                repo_full_name=repo,
                severity=str(row.get("severity") or "") or None,
                weight=1,
                title=f"{row.get('severity')} {capability} {row.get('rule_id')} in {repo}",
                summary=(
                    f"{row.get('title')}{f' ({where})' if where else ''}. "
                    f"Triage says {row.get('triage')}: {row.get('triage_rationale')}"
                ),
                done_when=(
                    "Dispositioned, or two successful scans observe it gone."
                ),
                evidence=[
                    Evidence(
                        source="findings",
                        ref=finding_id,
                        detail=(
                            f"rank {row.get('rank')}, first seen {row.get('first_seen_at')}, "
                            f"KEV {bool(row.get('in_kev'))}, EPSS {row.get('epss_score')}"
                        ),
                    )
                ],
                preconditions=preconditions,
                actions=_finding_actions(row, principal),
                caveats=_finding_caveats(row, lane_frozen=frozen),
            )
        )
    return items


# ---------------------------------------------------------------------------


def _briefing_unknowns(briefing: Briefing) -> list[Unknown]:
    unknown = []
    if briefing.failing_unknown or briefing.paused_unknown or briefing.blocked_unknown:
        unknown.append(
            Unknown(
                "concourse",
                "CI could not be asked which jobs are failing, paused or held back.",
            )
        )
    if briefing.jobs_unknown:
        unknown.append(Unknown("job_runs", "Scheduled-job health could not be read."))
    if briefing.tokens_unknown:
        unknown.append(Unknown("ingestion_tokens", "The token registry could not be read."))
    if briefing.toxic_unknown:
        unknown.append(Unknown("toxic", "Toxic combinations could not be computed."))
    if briefing.exposure_unknown:
        unknown.append(Unknown("exposure", "Public endpoints could not be read."))
    return unknown


def build(
    briefing: Briefing,
    principal: Principal,
    *,
    triage_rows: list[dict[str, Any]] | None,
    acceptances: list[dict[str, Any]] | None,
    approval_requests: list[dict[str, Any]] | None,
    repo_ids: dict[str, str],
    now: datetime,
    probe_interval_seconds: int,
    playbook_version: str,
) -> WorkQueue:
    """The queue for one principal. `None` for any input means it was not read.

    `repo_ids` maps each full name to its onboarding id, which is what every
    repository-scoped route takes. `playbook_version` is the loaded
    `agent-playbooks-v1.yaml`'s version; every item names its playbook with it.
    """
    now = _aware(now)
    queue = WorkQueue(
        generated_at=now,
        actor=principal.actor,
        actor_kind=principal.kind.value,
        unknown=_briefing_unknowns(briefing),
    )
    items = [
        *_lane_items(briefing, repo_ids),
        *_ci_items(briefing),
        *_job_items(briefing),
        *_toxic_items(briefing),
        *_exposure_items(briefing, now=now, probe_interval_seconds=probe_interval_seconds),
        *_token_items(briefing),
    ]

    if approval_requests is None:
        queue.unknown.append(
            Unknown("approval_requests", "Your approval requests could not be read.")
        )
    else:
        approval_items, approval_waiting = _approval_items(approval_requests)
        items += approval_items
        queue.waiting += approval_waiting

    if acceptances is None:
        queue.unknown.append(Unknown("risk_acceptances", "Acceptances could not be read."))
    else:
        items += _acceptance_items(acceptances, today=now.date())

    if triage_rows is None:
        queue.unknown.append(Unknown("triage", "The triage queue could not be read."))
    else:
        items += _finding_items(triage_rows, briefing, principal)

    for awaiting in briefing.awaiting:
        queue.waiting.append(
            Waiting(
                kind="awaiting_closure",
                ref=f"{awaiting.repo_full_name}/{awaiting.capability}",
                repo_full_name=awaiting.repo_full_name,
                detail=(
                    f"{awaiting.findings} finding(s) already absent from the newest scan; "
                    f"{awaiting.scans_needed} more successful scan(s) close them. No work needed."
                ),
            )
        )

    for item in items:
        item.playbook = f"{item.kind}@{playbook_version}"
    queue.items = sorted(items, key=_sort_key)
    return queue
