"""The Product Owner tab's API (spec 35, phase 1).

One read and three writes. The read assembles a repository's declared process
(its `.sdlc/process.yaml` on the default branch), its backlog and sprint from
TheHub, and the Oracle decision MyKronos already holds. The writes are all
admin-only and every one is audit-logged, including the ones TheHub refuses:
an audit log that records only what worked cannot answer "who tried to pull
that into the sprint?".

TheHub owns the stories (D-133). Nothing here edits a story's content; the two
Hub writes are a bucket move and the autonomy switch, and rank is MyKronos's
own table because TheHub has no field for it (B-068).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import governance, po_issues
from mykronos import product_owner as po
from mykronos.adminauth import PrincipalDep
from mykronos.db.models import PoBacklogRank, RepoGovernance, RepoOnboarding
from mykronos.github.client import GitHubError, PermissionDeniedError
from mykronos.process_templates import TEMPLATES
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["product-owner"])


# --------------------------------------------------------------------------
# Response shapes
# --------------------------------------------------------------------------


class CheckItemOut(BaseModel):
    id: str
    text: str
    evidence: str | None
    #: passed | failed | manual | unavailable. `unavailable` is an evidence key
    #: TheHub's response does not carry, which is "could not see", not "failed".
    status: str


class GateCheckOut(BaseModel):
    gate_id: str | None
    gate_name: str | None
    passed: int
    failed: int
    manual: int
    unavailable: int
    #: Checkable items only, so `passed / total` never counts a manual one as
    #: a miss.
    total: int
    items: list[CheckItemOut]


class StoryRiskOut(BaseModel):
    #: False when the story carries no `finding:` or `control:` tag.
    linked: bool
    #: Points removed, or null when not linked or no risk model exists.
    points: float | None
    findings_linked: int
    #: Of the linked findings, how many are open under the decision's scope.
    #: Only these remove points.
    findings_open: int
    controls_linked: list[str]
    note: str


class StoryOut(BaseModel):
    id: int
    title: str
    bucket: str
    #: TheHub's gate.
    gate: str
    #: The repository's own name for where this story is, when its manifest
    #: has a gate covering it (D-134).
    gate_name: str | None
    spine: str
    size: str | None
    tags: list[str]
    acceptance_criteria: int
    detail_length: int
    rank: int | None
    created_at: str | None
    updated_at: str | None
    check: GateCheckOut
    #: The manifest's Definition of Done against this story (spec 35 §7.3).
    #: Only for a story at a done-equivalent gate, and only when the manifest
    #: declares one; null otherwise.
    dod: GateCheckOut | None = None
    #: Oracle risk points this story would remove (spec 35 §7.4). Backlog
    #: stories only.
    risk: StoryRiskOut | None = None
    #: How the tab shows the story: `#<id>`. For a GitHub issue (B-072) `id`
    #: is the issue number and `ref` is `#<number>`.
    ref: str | None = None
    #: The issue on GitHub, for a GitHub-Issues backlog.
    url: str | None = None
    #: open | closed, for a GitHub issue. TheHub stories carry `bucket`.
    state: str | None = None


class ManifestOut(BaseModel):
    #: valid | invalid | absent | unreadable
    state: str
    path: str
    url: str | None
    error: str | None
    #: The parsed manifest when valid. Never a default dressed as declared.
    manifest: dict[str, Any] | None


class HubOut(BaseModel):
    connected: bool
    #: Why there are no stories, when there are none for a reason.
    error: str | None


class NeedsHumanOut(BaseModel):
    #: invalid_manifest | sprint_gate_failed | ready_manual_item | process_drift
    #: | dod_failed
    kind: str
    story_id: int | None
    title: str
    reason: str
    #: Who fixes it, where the item is a finding with an owner (drift).
    owner: str | None = None


class ObservationOut(BaseModel):
    """One declaration beside its observation (spec 35 §7.1). The two are
    separate fields so the view never merges them into one word."""

    id: str
    #: branch_control | gate_switch
    kind: str
    subject: str
    declared: str
    observed: str
    #: consistent | drift | unobserved. Only drift is a finding.
    status: str
    owner: str
    detail: str


class IssuesSourceOut(BaseModel):
    """How a `github_issues` backlog was read (spec 35 §9, D-156)."""

    labels: list[str]
    project: int | None
    gate_field: str
    sprint_labels: list[str]
    #: project | labels: where the gates shown came from.
    gate_source: str
    #: Why the gates are not from the project, when one was named.
    gate_note: str | None


class SprintProgressOut(BaseModel):
    done: int
    committed: int


class OracleOut(BaseModel):
    decision_type: str | None
    recommendation: str | None
    overall_risk_score: float | None
    evaluated_at: str | None
    commit_sha: str | None


class RiskModelOut(BaseModel):
    """What the 'by risk removed' order ranked by (the B-033 rule)."""

    available: bool
    decision_id: str | None
    evaluated_at: str | None
    policy_version: str | None
    #: False means the ranking carries no business context.
    risk_profile_available: bool
    #: The sentence the view shows, so every surface says the same thing.
    statement: str


class TemplateOut(BaseModel):
    id: str
    label: str
    summary: str


class ProductOwnerOut(BaseModel):
    repo_id: str
    repo_full_name: str
    default_branch: str
    #: Whether this caller may use the write controls. A viewer sees the tab
    #: read-only; the backend refuses the writes regardless.
    can_write: bool
    manifest: ManifestOut
    #: The spine steps, in order, and whether they are a default because the
    #: repository declares no valid process.
    spine: list[str]
    spine_is_default: bool
    backlog_tag: str
    include_untagged: bool
    #: manifest | default
    membership_source: str
    hub: HubOut
    needs_human: list[NeedsHumanOut]
    #: Every declaration the platform can compare with what it observes,
    #: including the consistent and unobserved ones (B-070).
    observations: list[ObservationOut]
    #: Starter manifests on offer. Only when the repository declares none
    #: (spec 35 §7.2); empty otherwise, so a declared process is never offered
    #: a replacement.
    templates: list[TemplateOut]
    counts: dict[str, int]
    sprint_progress: SprintProgressOut
    oracle: OracleOut | None
    backlog: list[StoryOut]
    sprint: list[StoryOut]
    risk_model: RiskModelOut
    #: Backlog story ids in the 'by risk removed' order. A view, never written:
    #: the manual rank is unchanged by it.
    backlog_by_risk: list[int]
    #: thehub | github_issues
    backlog_source: str = "thehub"
    #: Set when this source takes no writes from the tab, with the reason.
    writes_refused: str | None = None
    issues: IssuesSourceOut | None = None


class PoActionOut(BaseModel):
    story_id: int
    #: sprint_pull | return_to_backlog | rank
    action: str
    moved: bool
    autonomy_disabled: bool | None = None
    detail: str | None = None


class TemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    template: Literal["keel", "thehub", "lightweight"]


class TemplatePrOut(BaseModel):
    template: str
    #: False when a template pull request was already open and is returned.
    created: bool
    pr_number: int
    pr_url: str
    branch: str


class RankRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    story_id: int = Field(ge=1)
    direction: Literal["up", "down"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _require_writer(principal: Any, verb: str) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{verb} requires the 'admin' role; you have '{principal.role.value}'.",
        )


def _onboarding(request: Request, repo_id: str) -> tuple[str, str, int | None]:
    """(full name, default branch, installation id) for an onboarding id."""
    with request.app.state.db.session() as session:
        row = session.get(RepoOnboarding, repo_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"No repo {repo_id!r}. This takes the onboarding id from "
                    "/api/dashboard/portfolio, not an owner/repo name."
                ),
            )
        return (
            str(row.github_repo_full_name),
            str(row.default_branch or "main"),
            row.github_installation_id,
        )


def _hub(request: Request) -> po.HubClient | None:
    return getattr(request.app.state, "hub", None)


def _require_hub(request: Request) -> po.HubClient:
    hub = _hub(request)
    if hub is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "TheHub is not connected. Set MYKRONOS_HUB_API_URL and "
                "MYKRONOS_HUB_API_TOKEN to enable the Product Owner writes."
            ),
        )
    return hub


async def _read_manifest(
    request: Request, repo_full_name: str, branch: str, installation_id: int | None
) -> po.ManifestState:
    factory = getattr(request.app.state, "github_factory", None)
    if factory is None or installation_id is None:
        return po.ManifestState(
            state="unreadable", error="No GitHub installation to read the manifest with."
        )
    try:
        text = await factory.for_installation(installation_id).get_file(
            repo_full_name, po.MANIFEST_PATH, branch
        )
    except Exception:  # noqa: BLE001
        logger.warning("Could not read %s from %s", po.MANIFEST_PATH, repo_full_name)
        return po.ManifestState(
            state="unreadable",
            error=f"{po.MANIFEST_PATH} could not be read from GitHub.",
        )
    return po.parse_manifest(text)


def _governance_states(request: Request, repo_full_name: str) -> tuple[dict[str, str] | None, str]:
    """The stored governance reading's per-control states, or None with the
    reason when there is no current one (spec 35 §7.1).

    Stored, not read live: the governance sweep and the Insider Threat panel
    already keep this row current, and B-070 is a comparison against data the
    platform holds, not a second GitHub client. Stale is unobserved for the
    reason `governance.stored` gives -- a six-week-old reading of a setting is
    a claim about a repository that may have been reconfigured since.
    """
    with request.app.state.db.session() as session:
        row = session.get(RepoGovernance, repo_full_name)
        if row is None or not row.control_states:
            return None, "No governance reading is stored for this repository yet."
        cutoff = utcnow() - timedelta(days=governance.STALE_AFTER_DAYS)
        if row.read_at is None or row.read_at < cutoff:
            return None, (
                f"The last governance reading is older than {governance.STALE_AFTER_DAYS} days."
            )
        return dict(row.control_states), ""


async def _read_repo_files(
    request: Request,
    repo_full_name: str,
    branch: str,
    installation_id: int | None,
    paths: list[str],
) -> dict[str, str | None]:
    """Each path's text at `branch`, or None when absent or unreadable. The
    same client and call the manifest is read with."""
    factory = getattr(request.app.state, "github_factory", None)
    if factory is None or installation_id is None or not paths:
        return {path: None for path in paths}
    github = factory.for_installation(installation_id)
    out: dict[str, str | None] = {}
    for path in paths:
        try:
            out[path] = await github.get_file(repo_full_name, path, branch)
        except Exception:  # noqa: BLE001
            logger.warning("Could not read %s from %s", path, repo_full_name)
            out[path] = None
    return out


async def _observations(
    request: Request,
    repo_full_name: str,
    branch: str,
    installation_id: int | None,
    manifest: po.ProcessManifest | None,
) -> list[po.Observation]:
    if manifest is None:
        return []
    observations: list[po.Observation] = []
    if manifest.branch_controls is not None:
        states, reason = _governance_states(request, repo_full_name)
        observations += po.branch_control_observations(
            manifest, branch, states, unobserved_reason=reason
        )
    files = await _read_repo_files(
        request, repo_full_name, branch, installation_id, po.switch_files(manifest)
    )
    observations += po.gate_switch_observations(manifest, files)
    return observations


def _membership(state: po.ManifestState, repo_full_name: str) -> tuple[str, bool, str]:
    backlog = state.manifest.backlog if state.manifest is not None else None
    if isinstance(backlog, po.GithubIssuesBacklog):
        # Its backlog is GitHub's. TheHub reads elsewhere (retro, trace)
        # still match the repository's default tag.
        return po.default_tag(repo_full_name), False, "github_issues"
    if backlog is not None:
        return backlog.tag, backlog.include_untagged, "manifest"
    return po.default_tag(repo_full_name), False, "default"


def _ranks(request: Request, repo_id: str) -> dict[int, int]:
    with request.app.state.db.session() as session:
        rows = session.execute(
            select(PoBacklogRank).where(PoBacklogRank.repo_id == repo_id)
        ).scalars()
        return {row.story_id: row.rank for row in rows}


def _check_out(check: po.GateCheck) -> GateCheckOut:
    return GateCheckOut(
        gate_id=check.gate_id,
        gate_name=check.gate_name,
        passed=check.passed,
        failed=check.failed,
        manual=check.manual,
        unavailable=check.unavailable,
        total=check.total,
        items=[
            CheckItemOut(id=i.id, text=i.text, evidence=i.evidence, status=i.status)
            for i in check.items
        ],
    )


def _story_out(
    story: dict[str, Any],
    manifest: po.ProcessManifest | None,
    rank: int | None,
    dod: po.GateCheck | None = None,
) -> StoryOut:
    check = po.check_story(story, manifest)
    return StoryOut(
        id=int(story["id"]),
        title=str(story.get("title") or ""),
        bucket=str(story.get("bucket") or ""),
        gate=str(story.get("gate") or "intake"),
        gate_name=check.gate_name,
        spine=po.spine_step(story, manifest),
        size=story.get("size") or None,
        tags=[str(tag) for tag in story.get("tags") or []],
        acceptance_criteria=len(story.get("acceptance_criteria") or []),
        detail_length=len(story.get("detail") or ""),
        rank=rank,
        created_at=story.get("created_at"),
        updated_at=story.get("updated_at"),
        check=_check_out(check),
        dod=_check_out(dod) if dod is not None else None,
    )


def _issues_out(
    manifest: po.ProcessManifest | None, read: po_issues.IssuesRead | None
) -> IssuesSourceOut | None:
    if manifest is None or read is None or not po_issues.is_issues(manifest):
        return None
    backlog = manifest.backlog
    assert isinstance(backlog, po.GithubIssuesBacklog)
    return IssuesSourceOut(
        labels=list(backlog.labels),
        project=backlog.project,
        gate_field=backlog.gate_field,
        sprint_labels=list(backlog.sprint_labels),
        gate_source=read.gate_source,
        gate_note=read.gate_note,
    )


def _oracle(request: Request, repo_full_name: str) -> OracleOut | None:
    """The newest decision MyKronos already holds. Absent, not invented, when
    there is none or the lake cannot be read."""
    try:
        from mykronos.api.oracle import _service

        decisions = _service(request).recent_decisions(repo_full_name, limit=1)
    except Exception:  # noqa: BLE001
        logger.warning("Could not read the Oracle decision for %s", repo_full_name)
        return None
    if not decisions:
        return None
    latest = decisions[0]
    score = latest.get("overall_risk_score")
    evaluated = latest.get("evaluated_at")
    return OracleOut(
        decision_type=latest.get("decision_type"),
        recommendation=latest.get("recommendation"),
        overall_risk_score=float(score) if score is not None else None,
        evaluated_at=evaluated.isoformat() if isinstance(evaluated, datetime) else evaluated,
        commit_sha=latest.get("commit_sha"),
    )


def _scanned_commits(request: Request, repo_full_name: str, commits: list[str]) -> list[str] | None:
    """Which of `commits` have a successful scan run in the lake, as the lake
    spells them. None when the lake could not be read."""
    candidates = [c for c in commits if len(c) >= po.MIN_SHA]
    if not candidates:
        return []
    clause = " OR ".join(
        "starts_with(lower(commit_sha), ?) OR starts_with(?, lower(commit_sha))"
        for _ in candidates
    )
    params: list[Any] = [repo_full_name]
    for sha in candidates:
        params += [sha.lower(), sha.lower()]
    try:
        rows = request.app.state.catalog.query(
            f"""
            SELECT DISTINCT commit_sha FROM scan_runs
            WHERE repo_full_name = ? AND scan_status = 'success'
              AND length(commit_sha) >= {po.MIN_SHA} AND ({clause})
            """,
            params,
        )
    except Exception:  # noqa: BLE001
        logger.warning("Could not read scan runs for %s", repo_full_name)
        return None
    return [str(row[0]) for row in rows]


def _deployed_revision(request: Request, repo_id: str) -> str | None:
    with request.app.state.db.session() as session:
        row = session.get(RepoOnboarding, repo_id)
        return row.deployed_revision if row is not None else None


async def _dod_checks(
    request: Request,
    hub: po.HubClient,
    repo_id: str,
    repo_full_name: str,
    manifest: po.ProcessManifest,
    stories: list[dict[str, Any]],
) -> dict[int, po.GateCheck]:
    """The Definition of Done for each done-equivalent story (spec 35 §7.3)."""
    ids = [int(s["id"]) for s in stories]
    deploys = await asyncio.gather(*(hub.story_deploys(sid) for sid in ids))
    evidence = {sid: po.evidence_from_deploys(rows) for sid, rows in zip(ids, deploys, strict=True)}
    every_commit = sorted({c for commits, _ in evidence.values() for c in commits or []})
    scanned = _scanned_commits(request, repo_full_name, every_commit)
    revision = _deployed_revision(request, repo_id)
    out: dict[int, po.GateCheck] = {}
    for sid, (commits, deployed) in evidence.items():
        check = po.check_dod(
            manifest,
            po.DoneEvidence(
                commits=commits, deployed=deployed, scanned=scanned, deployed_revision=revision
            ),
        )
        if check is not None:
            out[sid] = check
    return out


def _portfolio_decision(request: Request, repo_full_name: str) -> dict[str, Any] | None:
    try:
        from mykronos.api.oracle import _service

        decisions = _service(request).recent_decisions(
            repo_full_name, decision_type="portfolio", limit=1
        )
    except Exception:  # noqa: BLE001
        logger.warning("Could not read the portfolio decision for %s", repo_full_name)
        return None
    return decisions[0] if decisions else None


def _findings(
    request: Request, repo_full_name: str, finding_ids: list[str]
) -> dict[str, tuple[str, str]]:
    """finding id -> (severity, status), the latest row of each."""
    if not finding_ids:
        return {}
    placeholders = ", ".join("?" for _ in finding_ids)
    try:
        rows = request.app.state.catalog.query(
            f"""
            SELECT finding_id, severity, status FROM findings
            WHERE asset_id = ? AND finding_id IN ({placeholders})
            ORDER BY last_seen_at
            """,
            [repo_full_name, *finding_ids],
        )
    except Exception:  # noqa: BLE001
        logger.warning("Could not read linked findings for %s", repo_full_name)
        return {}
    return {str(fid): (str(sev or ""), str(state or "")) for fid, sev, state in rows}


def _risk_statement(model: po.RiskModel) -> str:
    if not model.available:
        return model.reason
    when = (model.evaluated_at or "")[:10]
    text = (
        f"Ranked by the Oracle's portfolio decision of {when} (policy "
        f"{model.policy_version or 'unknown'}): finding bands and the governance term."
    )
    if not model.risk_profile_available:
        text += (
            " This repository has no risk profile, so the ranking carries no business "
            "context: it is finding severity and governance only (B-033)."
        )
    return text


def _story_risks(
    request: Request,
    repo_full_name: str,
    stories: list[dict[str, Any]],
    model: po.RiskModel,
) -> dict[int, StoryRiskOut]:
    linked = {int(s["id"]): po.links(s) for s in stories}
    every_finding = sorted({f for fids, _ in linked.values() for f in fids})
    findings = _findings(request, repo_full_name, every_finding) if model.available else {}
    states, _ = (
        _governance_states(request, repo_full_name)
        if any(controls for _, controls in linked.values())
        else (None, "")
    )
    policy = request.app.state.oracle_policy.governance
    out: dict[int, StoryRiskOut] = {}
    for sid, (fids, controls) in linked.items():
        if not fids and not controls:
            out[sid] = StoryRiskOut(
                linked=False, points=None, findings_linked=0, findings_open=0,
                controls_linked=[], note="not linked",
            )
            continue
        if not model.available:
            out[sid] = StoryRiskOut(
                linked=True, points=None, findings_linked=len(fids), findings_open=0,
                controls_linked=controls, note="no risk model",
            )
            continue
        by_severity: dict[str, int] = {}
        open_count = 0
        for fid in fids:
            found = findings.get(fid)
            if found is None or found[1] not in model.statuses_considered:
                continue
            open_count += 1
            by_severity[found[0]] = by_severity.get(found[0], 0) + 1
        points = po.band_points(model, by_severity) + po.control_points(
            model,
            states,
            controls,
            weights=governance.weights(),
            good_enough=policy.good_enough,
            points_at_zero=policy.points_at_zero,
        )
        notes = []
        if len(fids) > open_count:
            notes.append(f"{len(fids) - open_count} linked finding(s) not open")
        if controls and not model.governance_available:
            notes.append("governance was not in the decision")
        out[sid] = StoryRiskOut(
            linked=True,
            points=round(points, 2),
            findings_linked=len(fids),
            findings_open=open_count,
            controls_linked=controls,
            note="; ".join(notes),
        )
    return out


async def _repo_stories(
    hub: po.HubClient, tag: str, include_untagged: bool
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    backlog, sprint = await asyncio.gather(
        hub.list_stories("backlog"), hub.list_stories("sprint")
    )
    return (
        [s for s in backlog if po.belongs(s, tag, include_untagged)],
        [s for s in sprint if po.belongs(s, tag, include_untagged)],
    )


async def _require_member(
    request: Request, hub: po.HubClient, repo_id: str, story_id: int
) -> str:
    """This repository's full name, if the story is one of its own. A write
    through one repository's tab must not move another's story, or the audit
    entry names the wrong repository."""
    repo_full_name, branch, installation = _onboarding(request, repo_id)
    state = await _read_manifest(request, repo_full_name, branch, installation)
    tag, include_untagged, _ = _membership(state, repo_full_name)
    try:
        story = await hub.get_story(story_id)
    except po.HubUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    if story is None or not po.belongs(story, tag, include_untagged):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Story {story_id} is not one of {repo_full_name}'s (tag {tag}).",
        )
    return repo_full_name


def _audit(
    request: Request,
    principal: Any,
    *,
    action: str,
    repo_id: str,
    repo_full_name: str,
    story_id: int,
    **detail: Any,
) -> None:
    database = request.app.state.db
    with database.session() as session:
        database.audit(
            session,
            actor=principal.actor,
            action=action,
            entity_type="hub_story",
            entity_id=str(story_id),
            repo_id=repo_id,
            repo_full_name=repo_full_name,
            story_id=story_id,
            **detail,
        )


async def _read_issues(
    request: Request,
    repo_full_name: str,
    installation_id: int | None,
    manifest: po.ProcessManifest | None,
) -> po_issues.IssuesRead | None:
    """The GitHub-Issues backlog (B-072), or None when TheHub is the source."""
    if manifest is None or not po_issues.is_issues(manifest):
        return None
    factory = getattr(request.app.state, "github_factory", None)
    github = (
        factory.for_installation(installation_id)
        if factory is not None and installation_id is not None
        else None
    )
    return await po_issues.read_backlog(github, repo_full_name, manifest)


async def _refuse_read_only_source(
    request: Request, principal: Any, repo_id: str, story_id: int, action: str
) -> None:
    """Refuse a write to a GitHub-Issues backlog, and record that it was tried
    (D-156). Checked before TheHub is asked anything."""
    repo_full_name, branch, installation = _onboarding(request, repo_id)
    state = await _read_manifest(request, repo_full_name, branch, installation)
    if not po_issues.is_issues(state.manifest):
        return
    _audit(
        request,
        principal,
        action=action,
        repo_id=repo_id,
        repo_full_name=repo_full_name,
        story_id=story_id,
        outcome="refused_read_only_source",
    )
    raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=po_issues.WRITES_REFUSED)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------


@router.get("/repos/{repo_id}/product-owner", response_model=ProductOwnerOut)
async def product_owner(
    request: Request, repo_id: str, principal: PrincipalDep
) -> ProductOwnerOut:
    """A repository's declared process, backlog and sprint (spec 35 §3)."""
    repo_full_name, branch, installation = _onboarding(request, repo_id)
    state = await _read_manifest(request, repo_full_name, branch, installation)
    manifest = state.manifest
    tag, include_untagged, membership_source = _membership(state, repo_full_name)

    backlog_raw: list[dict[str, Any]] = []
    sprint_raw: list[dict[str, Any]] = []
    issues_read = await _read_issues(request, repo_full_name, installation, manifest)
    hub = _hub(request)
    if issues_read is not None:
        hub_out = HubOut(connected=issues_read.ok, error=issues_read.error)
    elif hub is None:
        hub_out = HubOut(connected=False, error="TheHub is not connected.")
    else:
        try:
            backlog_raw, sprint_raw = await _repo_stories(hub, tag, include_untagged)
            hub_out = HubOut(connected=True, error=None)
        except po.HubUnavailableError as exc:
            hub_out = HubOut(connected=False, error=str(exc))

    dod: dict[int, po.GateCheck] = {}
    done_raw = [s for s in backlog_raw + sprint_raw if po.is_done(s, manifest)]
    wants_dod = manifest is not None and bool(manifest.definition_of_done) and bool(done_raw)
    if hub is not None and hub_out.connected and manifest is not None and wants_dod:
        dod = await _dod_checks(request, hub, repo_id, repo_full_name, manifest, done_raw)

    ranks = _ranks(request, repo_id)
    ordered = po.order_backlog(backlog_raw, ranks)
    model = po.risk_model(_portfolio_decision(request, repo_full_name))
    risks = _story_risks(request, repo_full_name, ordered, model)
    backlog = [
        _story_out(s, manifest, ranks.get(int(s["id"])), dod.get(int(s["id"])))
        for s in ordered
    ]
    for story_out in backlog:
        story_out.risk = risks.get(story_out.id)
    by_risk = po.risk_order(
        ordered, {sid: risk.points for sid, risk in risks.items() if risk.linked}
    )
    sprint = [_story_out(s, manifest, None, dod.get(int(s["id"]))) for s in sprint_raw]
    sprint.sort(key=lambda s: (po.SPINE.index(s.spine), s.id))
    if issues_read is not None:
        backlog = [StoryOut.model_validate(s) for s in issues_read.backlog]
        sprint = [StoryOut.model_validate(s) for s in issues_read.sprint]

    observations = await _observations(request, repo_full_name, branch, installation, manifest)

    needs: list[NeedsHumanOut] = []
    if state.state == "invalid":
        needs.append(
            NeedsHumanOut(
                kind="invalid_manifest",
                story_id=None,
                title=po.MANIFEST_PATH,
                reason=state.error or "The manifest is invalid.",
            )
        )
    for observation in observations:
        if observation.status == "drift":
            needs.append(
                NeedsHumanOut(
                    kind="process_drift",
                    story_id=None,
                    title=f"Declared, not observed: {observation.subject}",
                    reason=observation.detail,
                    owner=observation.owner,
                )
            )
    for story in sprint:
        if story.check.failed:
            needs.append(
                NeedsHumanOut(
                    kind="sprint_gate_failed",
                    story_id=story.id,
                    title=story.title,
                    reason=f"{story.check.failed} of {story.check.total} checks fail "
                    f"at {story.check.gate_name}.",
                )
            )
    for story in backlog + sprint:
        if story.dod is not None and story.dod.failed:
            failing = [i.text for i in story.dod.items if i.status == "failed"]
            needs.append(
                NeedsHumanOut(
                    kind="dod_failed",
                    story_id=story.id,
                    title=story.title,
                    reason=f"Done, but {story.dod.failed} of {story.dod.total} "
                    f"Definition-of-Done checks fail: {'; '.join(failing)}.",
                )
            )
    for story in backlog + sprint:
        if story.spine == "ready" and story.check.manual:
            needs.append(
                NeedsHumanOut(
                    kind="ready_manual_item",
                    story_id=story.id,
                    title=story.title,
                    reason=f"{story.check.manual} manual checklist item(s) at "
                    f"{story.check.gate_name} need a person's judgement.",
                )
            )

    counts = {step: 0 for step in po.SPINE}
    for story in backlog + sprint:
        counts[story.spine] = counts.get(story.spine, 0) + 1

    url = f"https://github.com/{repo_full_name}/blob/{branch}/{po.MANIFEST_PATH}"
    return ProductOwnerOut(
        repo_id=repo_id,
        repo_full_name=repo_full_name,
        default_branch=branch,
        can_write=bool(principal.may_write) and issues_read is None,
        manifest=ManifestOut(
            state=state.state,
            path=po.MANIFEST_PATH,
            url=url if state.state in ("valid", "invalid") else None,
            error=state.error,
            manifest=manifest.model_dump(mode="json") if manifest is not None else None,
        ),
        spine=list(po.SPINE),
        spine_is_default=state.spine_is_default,
        backlog_tag=tag,
        include_untagged=include_untagged,
        membership_source=membership_source,
        hub=hub_out,
        needs_human=needs,
        observations=[
            ObservationOut(
                id=o.id,
                kind=o.kind,
                subject=o.subject,
                declared=o.declared,
                observed=o.observed,
                status=o.status,
                owner=o.owner,
                detail=o.detail,
            )
            for o in observations
        ],
        templates=(
            [TemplateOut(id=t.id, label=t.label, summary=t.summary) for t in TEMPLATES.values()]
            if state.state == "absent"
            else []
        ),
        counts=counts,
        sprint_progress=SprintProgressOut(
            done=sum(1 for s in sprint if s.spine == "done"), committed=len(sprint)
        ),
        oracle=_oracle(request, repo_full_name),
        backlog_source="github_issues" if issues_read is not None else "thehub",
        writes_refused=po_issues.WRITES_REFUSED if issues_read is not None else None,
        issues=_issues_out(manifest, issues_read),
        backlog=backlog,
        sprint=sprint,
        risk_model=RiskModelOut(
            available=model.available,
            decision_id=model.decision_id,
            evaluated_at=model.evaluated_at,
            policy_version=model.policy_version,
            risk_profile_available=model.risk_profile_available,
            statement=_risk_statement(model),
        ),
        backlog_by_risk=by_risk,
    )


@router.post(
    "/repos/{repo_id}/product-owner/stories/{story_id}/pull", response_model=PoActionOut
)
async def pull_into_sprint(
    request: Request, repo_id: str, story_id: int, principal: PrincipalDep
) -> PoActionOut:
    """Pull a story into the sprint: autonomy off first, then the move.

    The order is the safety property (spec 35 §4). A sprint move arms
    autonomous dispatch in TheHub, so a failure between the two calls must
    leave the story in the backlog with autonomy off, never in the sprint with
    autonomy armed. TheHub's refusal is shown verbatim and never retried.
    """
    _require_writer(principal, "Pulling a story into the sprint")
    await _refuse_read_only_source(request, principal, repo_id, story_id, "po.sprint_pull")
    hub = _require_hub(request)
    repo_full_name = await _require_member(request, hub, repo_id, story_id)

    try:
        outcome = await po.pull_into_sprint(hub, story_id)
    except po.HubUnavailableError as exc:
        # The toggle itself could not be sent, so nothing was moved.
        _audit(
            request,
            principal,
            action="po.sprint_pull",
            repo_id=repo_id,
            repo_full_name=repo_full_name,
            story_id=story_id,
            outcome="unreachable",
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    _audit(
        request,
        principal,
        action="po.sprint_pull",
        repo_id=repo_id,
        repo_full_name=repo_full_name,
        story_id=story_id,
        outcome="moved" if outcome.moved else f"refused_at_{outcome.refused_at}",
        autonomy_disabled=outcome.autonomy_disabled,
        hub_detail=outcome.detail,
    )
    if not outcome.moved:
        if outcome.refused_at == "move":
            detail = (
                f"Autonomy was switched off, and TheHub refused the move: {outcome.detail} "
                "The story is still in the backlog, with autonomy off."
            )
        else:
            detail = (
                f"TheHub refused to switch autonomy off, so the story was not moved: "
                f"{outcome.detail}"
            )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    return PoActionOut(
        story_id=story_id, action="sprint_pull", moved=True, autonomy_disabled=True
    )


@router.post(
    "/repos/{repo_id}/product-owner/stories/{story_id}/return", response_model=PoActionOut
)
async def return_to_backlog(
    request: Request, repo_id: str, story_id: int, principal: PrincipalDep
) -> PoActionOut:
    """Move a sprint story back to the backlog. Autonomy is left as it is: a
    backlog story is not dispatched, and switching it back on is a decision
    this tab does not make."""
    _require_writer(principal, "Returning a story to the backlog")
    await _refuse_read_only_source(request, principal, repo_id, story_id, "po.return_to_backlog")
    hub = _require_hub(request)
    repo_full_name = await _require_member(request, hub, repo_id, story_id)

    try:
        result = await hub.move(story_id, "backlog")
    except po.HubUnavailableError as exc:
        _audit(
            request,
            principal,
            action="po.return_to_backlog",
            repo_id=repo_id,
            repo_full_name=repo_full_name,
            story_id=story_id,
            outcome="unreachable",
        )
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    _audit(
        request,
        principal,
        action="po.return_to_backlog",
        repo_id=repo_id,
        repo_full_name=repo_full_name,
        story_id=story_id,
        outcome="moved" if result.ok else "refused",
        hub_detail=result.detail,
    )
    if not result.ok:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"TheHub refused the move: {result.detail}",
        )
    return PoActionOut(story_id=story_id, action="return_to_backlog", moved=True)


@router.post("/repos/{repo_id}/product-owner/rank", response_model=PoActionOut)
async def rank_story(
    request: Request, repo_id: str, body: RankRequest, principal: PrincipalDep
) -> PoActionOut:
    """Move one backlog story up or down a place.

    The order is computed from what TheHub returns now, so a story that left
    the backlog since the page loaded cannot hold a place. The whole visible
    order is written, which ranks every story on the page once one has been
    moved -- the ordering a person sees is the one stored.
    """
    _require_writer(principal, "Ranking the backlog")
    await _refuse_read_only_source(request, principal, repo_id, body.story_id, "po.rank")
    repo_full_name, branch, installation = _onboarding(request, repo_id)
    hub = _require_hub(request)
    state = await _read_manifest(request, repo_full_name, branch, installation)
    tag, include_untagged, _ = _membership(state, repo_full_name)
    try:
        backlog = [
            s for s in await hub.list_stories("backlog") if po.belongs(s, tag, include_untagged)
        ]
    except po.HubUnavailableError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

    current = [int(s["id"]) for s in po.order_backlog(backlog, _ranks(request, repo_id))]
    if body.story_id not in current:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Story {body.story_id} is not in {repo_full_name}'s backlog.",
        )
    order = po.moved(current, body.story_id, body.direction)

    database = request.app.state.db
    with database.session() as session:
        existing = {
            row.story_id: row
            for row in session.execute(
                select(PoBacklogRank).where(PoBacklogRank.repo_id == repo_id)
            ).scalars()
        }
        for position, story_id in enumerate(order, start=1):
            row = existing.get(story_id)
            if row is None:
                session.add(
                    PoBacklogRank(
                        repo_id=repo_id,
                        story_id=story_id,
                        rank=position,
                        updated_by=principal.actor,
                    )
                )
            elif row.rank != position:
                row.rank = position
                row.updated_by = principal.actor
        database.audit(
            session,
            actor=principal.actor,
            action="po.rank",
            entity_type="hub_story",
            entity_id=str(body.story_id),
            repo_id=repo_id,
            repo_full_name=repo_full_name,
            story_id=body.story_id,
            direction=body.direction,
            position=order.index(body.story_id) + 1,
        )
    return PoActionOut(story_id=body.story_id, action="rank", moved=order != current)


@router.post("/repos/{repo_id}/product-owner/template", response_model=TemplatePrOut)
async def open_template_pr(
    request: Request, repo_id: str, body: TemplateRequest, principal: PrincipalDep
) -> TemplatePrOut:
    """Open a draft pull request adding a starter `.sdlc/process.yaml`
    (spec 35 §7.2, B-069).

    Only for a repository whose default branch has no manifest: an invalid one
    is fixed in the repository, not replaced from here, and an unreadable one
    may well exist. Every attempt is audit-logged, including the refusals.
    """
    _require_writer(principal, "Opening a template pull request")
    repo_full_name, branch, installation = _onboarding(request, repo_id)
    database = request.app.state.db

    def audit(outcome: str, **detail: Any) -> None:
        with database.session() as session:
            database.audit(
                session,
                actor=principal.actor,
                action="po.template_pr",
                entity_type="repo_onboarding",
                entity_id=repo_id,
                repo_id=repo_id,
                repo_full_name=repo_full_name,
                template=body.template,
                outcome=outcome,
                **detail,
            )

    state = await _read_manifest(request, repo_full_name, branch, installation)
    if state.state != "absent":
        audit(f"refused_{state.state}")
        reason = {
            "valid": "already declares a process",
            "invalid": "has a manifest that is invalid; fix it in the repository",
            "unreadable": "has a manifest MyKronos could not read",
        }[state.state]
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{repo_full_name} {reason}, so no template is offered.",
        )

    factory = getattr(request.app.state, "github_factory", None)
    if factory is None or installation is None:  # pragma: no cover - absent implies readable
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No GitHub installation to open the pull request with.",
        )
    template = TEMPLATES[body.template]
    try:
        result = await po.open_template_pr(
            factory.for_installation(installation),
            repo_full_name,
            branch,
            template,
            now=utcnow(),
        )
    except PermissionDeniedError as exc:
        # Our own sentence, naming the permission the App lacks.
        audit("failed", reason="permission")
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except GitHubError as exc:
        logger.warning("Template PR failed for %s (HTTP %s)", repo_full_name, exc.status)
        audit("failed", reason=f"http_{exc.status}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"GitHub refused the pull request (HTTP {exc.status}).",
        ) from exc

    pull_request = result.pull_request
    audit(
        "opened" if result.created else "reused",
        pr_number=pull_request.number,
        pr_url=pull_request.url,
        branch=result.branch,
    )
    return TemplatePrOut(
        template=body.template,
        created=result.created,
        pr_number=pull_request.number,
        pr_url=pull_request.url,
        branch=result.branch,
    )
