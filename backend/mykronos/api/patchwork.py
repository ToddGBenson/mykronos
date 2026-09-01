"""Patchwork API (spec 08 §6).

The pipeline runs server-side rather than in the runner — spec 08 §6 asks for
that so the multi-agent work is observable and its cost is tracked in one
place. The workflow's job is to *ask*, which is why this endpoint takes the
repo from an ingestion token like every other capability entry point.

There is no endpoint here that merges anything, and there is no client method
it could call if there were (spec 08 §3).
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import PrincipalDep
from mykronos.api.ingest import TokenDep, _installation_client, _require_capability
from mykronos.db.models import RepoOnboarding, capability_config_for
from mykronos.patchwork import PatchworkPipeline
from mykronos.patchwork.pipeline import DEFAULT_SOURCE_CAPABILITIES
from mykronos.schemas import Capability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/patchwork", tags=["patchwork"])


class RunRequest(BaseModel):
    """What the workflow sends. No repo field — it comes from the token."""

    model_config = ConfigDict(extra="forbid")

    commit_sha: str = Field(default="", max_length=64)
    pr_number: int | None = None


class RunResult(BaseModel):
    findings_considered: int
    by_stage: dict[str, int]
    draft_prs_opened: int
    queued: int
    errors: list[str] = Field(
        default_factory=list,
        description=(
            "Failures that did not stop the run. Reported rather than raised: "
            "spec 08 §8 requires every finding to record where it got to even "
            "when the pipeline breaks partway."
        ),
    )
    note: str = (
        "Every pull request auto-remediation opens is a draft, and it has no "
        "ability to merge one — the GitHub client it uses exposes no merge "
        "operation (spec 08 §3)."
    )


class RemediationEventOut(BaseModel):
    event_id: str
    finding_id: str
    toxic_combination_id: str | None = None
    contributing_finding_ids: list[str] = Field(default_factory=list)
    pipeline_stage_reached: str
    triage_classification: str
    fix_pr_number: int | None = None
    fix_pr_url: str | None = None
    pr_status: str | None = None
    rationale: str
    created_at: Any = None
    updated_at: Any = None


class RemediationPage(BaseModel):
    repo_full_name: str
    events: list[RemediationEventOut]
    open_draft_prs: int
    note: str = (
        "Auto-remediation never merges. A draft pull request here is waiting "
        "for a person, and will wait indefinitely."
    )


class DigestRepoOut(BaseModel):
    repo_full_name: str
    finding_id: str
    fix_pr_number: int | None = None
    fix_pr_url: str | None = None
    pr_status: str | None = None


class DigestGroupOut(BaseModel):
    """One fix, repeated across the portfolio (spec 19 §3.4)."""

    rule_id: str
    title: str
    severity: str | None = None
    rationale: str = Field(
        default="",
        description=(
            "One representative rationale. They are generated from the same "
            "template for the same rule, so showing all twelve would be "
            "twelve copies of one sentence."
        ),
    )
    repos: list[DigestRepoOut]

    @property
    def count(self) -> int:
        return len(self.repos)


class DigestPage(BaseModel):
    groups: list[DigestGroupOut]
    total_open_prs: int
    note: str = (
        "Grouped for the reviewer, not merged for the machine. Each of these "
        "is still a separate pull request against a separate repository — "
        "one pull request touching ten repositories would break per-repo "
        "review and CODEOWNERS, which is the point of them."
    )


class EfficacyRowOut(BaseModel):
    """One fixer's — or one rule's — record (spec 25 §3.1)."""

    key: str = Field(description="The fixer name, or the rule_id, depending on the list.")
    attempts: int = Field(description="Fixes generated.")
    prs_opened: int = Field(description="Reached a draft pull request.")
    merged: int = Field(description="A person merged it.")
    rejected: int = Field(description="Closed unmerged.")
    verified: int = Field(
        description=(
            "The finding was gone from the verifying scan of the merge commit "
            "(spec 25 §2). This is the only column that says risk was removed."
        )
    )
    still_open: int = Field(
        description="Merged, re-scanned, and the finding was reported again."
    )
    unverified: int = Field(
        description=(
            "Merged but never established either way — inconclusive, not "
            "scanned, or still waiting. Deliberately not counted as a failure: "
            "the scan did not answer, which is not the same as the fix not "
            "working."
        )
    )
    median_seconds_to_verified: int | None = Field(
        default=None, description="Merge to verification. Null with nothing verified."
    )


class EfficacyPage(BaseModel):
    """Whether auto-remediation removes risk, or only opens pull requests.

    Two breakdowns because they answer different questions: `by_fixer` says
    which fixers work, `by_rule` says which rules are fixable here. A fixer
    that works everywhere except one rule is a different problem from a fixer
    nobody trusts, and one axis cannot tell them apart.
    """

    by_fixer: list[EfficacyRowOut]
    by_rule: list[EfficacyRowOut]
    note: str


class RemediationPreviewOut(BaseModel):
    """"Auto remediation identified" (spec 18 §7.2) — nothing written yet."""

    finding_id: str
    stage: str
    classification: str
    rationale: str
    toxic_combination_id: str | None = None
    contributing_finding_ids: list[str] = Field(default_factory=list)
    fixer_name: str | None = None
    fix_confidence: float | None = None
    fix_files: dict[str, str] | None = Field(
        default=None,
        description="Path -> full new content. Not a unified diff — the "
        "deterministic fixers already produce whole-file replacements, and "
        "this is what they produce, not a second representation of it.",
    )


class RemediationFixOut(BaseModel):
    """What actually happened (spec 18 §7.2) — the same StageOutcome the
    batch pipeline records, for one finding, on request."""

    finding_id: str
    stage: str
    classification: str
    rationale: str
    toxic_combination_id: str | None = None
    contributing_finding_ids: list[str] = Field(default_factory=list)
    fix_pr_number: int | None = None
    fix_pr_url: str | None = None
    pr_status: str | None = None
    note: str = (
        "Draft, and it stays that way. Auto-remediation has no ability to "
        "merge — the client it uses exposes no merge operation at all "
        "(spec 08 §3)."
    )


def _finding_repo(request: Request, finding_id: str) -> str:
    """The repo an existing finding belongs to, or a 404.

    Late import, matching `repo_events` below: `api.dashboard` imports from
    this module's neighbours at collection time, so importing it back at
    module load would be circular. A function-local import is not.
    """
    from mykronos.api.dashboard import _queries

    record = _queries(request).finding(finding_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No finding {finding_id}."
        )
    return str(record["repo_full_name"])


def _pipeline(request: Request, repo_full_name: str) -> tuple[PatchworkPipeline, str]:
    with request.app.state.db.session() as session:
        config = capability_config_for(session, repo_full_name, "patchwork")
        onboarding = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == repo_full_name
            )
        ).scalars().first()
        default_branch = onboarding.default_branch if onboarding else "main"

    sources = config.get("source_capabilities") or DEFAULT_SOURCE_CAPABILITIES
    pipeline = PatchworkPipeline(
        request.app.state.catalog,
        request.app.state.buffer,
        request.app.state.knowledge,
        min_confidence=float(config.get("min_confidence_to_generate_fix", 0.7)),
        max_open_draft_prs=int(config.get("max_open_draft_prs_per_repo", 10)),
        source_capabilities=tuple(sources),
        auto_fix_min_severity=str(config.get("auto_fix_min_severity", "high")),
    )
    return pipeline, default_branch


def _open_draft_count(request: Request, repo_full_name: str) -> int:
    """How many auto-remediation pull requests are still waiting for a person.

    Counted from the event table rather than from GitHub, deliberately: this
    runs on every pipeline invocation, and a list-pull-requests call per run
    would spend the repository's API budget on a number we already hold.
    """
    rows = request.app.state.catalog.query(
        "SELECT count(*) FROM remediation_events "
        "WHERE repo_full_name = ? AND pr_status IN ('draft_open', 'human_edited')",
        [repo_full_name],
    )
    return int(rows[0][0]) if rows else 0


@router.post("/run", response_model=RunResult)
async def run(request: Request, body: RunRequest, token: TokenDep) -> RunResult:
    """Run the pipeline for this repository (spec 08 §2, §6)."""
    _require_capability(token, Capability.PATCHWORK.value)

    pipeline, default_branch = _pipeline(request, token.repo_full_name)
    result = await pipeline.run(
        token.repo_full_name,
        github=_installation_client(request, token.repo_full_name),
        default_branch=default_branch,
        open_prs=_open_draft_count(request, token.repo_full_name),
    )

    return RunResult(
        findings_considered=len(result.outcomes),
        by_stage=result.by_stage(),
        draft_prs_opened=result.prs_opened,
        queued=result.queued,
        errors=result.errors,
    )


@router.post("/findings/{finding_id}/preview", response_model=RemediationPreviewOut)
async def preview_finding_fix(
    request: Request, finding_id: str, principal: PrincipalDep
) -> RemediationPreviewOut:
    """What auto-remediation would do for one finding, without doing it (spec 18 §7.2).

    Principal-authenticated, not a workflow token: this is a person looking
    at one finding, not CI asking about a repository. Every guardrail the
    batch pipeline applies still applies — see `PatchworkPipeline.run_one`.
    """
    repo_full_name = _finding_repo(request, finding_id)
    pipeline, default_branch = _pipeline(request, repo_full_name)
    outcome = await pipeline.run_one(
        repo_full_name,
        finding_id,
        github=_installation_client(request, repo_full_name),
        default_branch=default_branch,
        open_prs=_open_draft_count(request, repo_full_name),
        preview_only=True,
    )
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No open finding {finding_id} in {repo_full_name}.",
        )
    return RemediationPreviewOut(
        finding_id=outcome.finding_id,
        stage=outcome.stage,
        classification=outcome.classification,
        rationale=outcome.rationale,
        toxic_combination_id=outcome.toxic_combination_id,
        contributing_finding_ids=outcome.contributing,
        fixer_name=outcome.fixer_name,
        fix_confidence=outcome.fix_confidence,
        fix_files=outcome.fix_files,
    )


@router.post("/findings/{finding_id}/fix", response_model=RemediationFixOut)
async def fix_finding(
    request: Request, finding_id: str, principal: PrincipalDep
) -> RemediationFixOut:
    """Actually attempt a fix for one finding (spec 18 §7.2).

    Same pipeline, same guardrails, same draft-only PR `_open_draft_pr` has
    always opened — the only difference from `POST /run` is the scope: one
    finding a person picked, rather than every true-positive in the repo.

    Admin-only: opening a branch and a pull request on the customer's
    repository is a write, the same standard `PATCH /findings/{id}/status`
    already holds a disposition to. `preview` above needs no such gate — it
    writes nothing, to GitHub or to this platform's own state.
    """
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Generating a fix requires the 'admin' role; you have "
                f"'{principal.role.value}'."
            ),
        )
    repo_full_name = _finding_repo(request, finding_id)
    pipeline, default_branch = _pipeline(request, repo_full_name)
    outcome = await pipeline.run_one(
        repo_full_name,
        finding_id,
        github=_installation_client(request, repo_full_name),
        default_branch=default_branch,
        open_prs=_open_draft_count(request, repo_full_name),
        preview_only=False,
    )
    if outcome is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No open finding {finding_id} in {repo_full_name}.",
        )
    return RemediationFixOut(
        finding_id=outcome.finding_id,
        stage=outcome.stage,
        classification=outcome.classification,
        rationale=outcome.rationale,
        toxic_combination_id=outcome.toxic_combination_id,
        contributing_finding_ids=outcome.contributing,
        fix_pr_number=outcome.fix_pr_number,
        fix_pr_url=outcome.fix_pr_url,
        pr_status=outcome.pr_status,
    )


@router.get("/digest", response_model=DigestPage)
async def cross_repo_digest(
    request: Request,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> DigestPage:
    """The same fix, everywhere it is open (spec 19 §3.4).

    Ten repositories with the same unpinned dependency means ten draft pull
    requests, reviewed one at a time with nothing to say they are the same
    change. This groups them for the reviewer.

    Grouped by `rule_id`, which is not on `remediation_events` — it is on the
    finding, so this joins. The spec expected `(rule_id, fixer_name)`, and
    `fixer_name` is now recorded (spec 25 §3.1) — but the grouping stays by
    rule alone, for the reason D-071 gave: coarser is the safe direction here,
    because two fixers for one rule land in one card a reviewer can see,
    rather than one fixer's work being split across two cards they cannot.

    Ordered before `/repos/{repo_id}` — a literal path must not be shadowed
    by the parameterised one.
    """
    rows = request.app.state.catalog.query(
        """
        SELECT
            f.rule_id,
            f.title,
            f.severity,
            e.repo_full_name,
            e.finding_id,
            e.fix_pr_number,
            e.fix_pr_url,
            e.pr_status,
            e.rationale
        FROM remediation_events e
        JOIN findings f ON f.finding_id = e.finding_id
        WHERE e.fix_pr_url IS NOT NULL
          AND e.pr_status IN ('draft_open', 'human_edited')
        ORDER BY f.rule_id, e.repo_full_name
        """
    )

    grouped: dict[str, DigestGroupOut] = {}
    for rule_id, title, severity, repo, finding_id, number, url, pr_state, rationale in rows:
        group = grouped.get(str(rule_id))
        if group is None:
            group = DigestGroupOut(
                rule_id=str(rule_id),
                title=str(title or rule_id),
                severity=str(severity) if severity else None,
                rationale=str(rationale or ""),
                repos=[],
            )
            grouped[str(rule_id)] = group
        group.repos.append(
            DigestRepoOut(
                repo_full_name=str(repo),
                finding_id=str(finding_id),
                fix_pr_number=int(number) if number is not None else None,
                fix_pr_url=str(url) if url else None,
                pr_status=str(pr_state) if pr_state else None,
            )
        )

    # Widest first: a fix open in twelve repositories is the one worth
    # reviewing once and applying twelve times.
    groups = sorted(grouped.values(), key=lambda g: (-g.count, g.rule_id))
    return DigestPage(
        groups=groups[:limit],
        total_open_prs=sum(group.count for group in groups),
    )


_EFFICACY_SELECT = """
    SELECT
        {key} AS key,
        count(*) AS attempts,
        count(*) FILTER (WHERE e.fix_pr_number IS NOT NULL) AS prs_opened,
        count(*) FILTER (WHERE e.pr_status = 'merged') AS merged,
        count(*) FILTER (WHERE e.pr_status = 'closed_unmerged') AS rejected,
        count(*) FILTER (WHERE e.verification_outcome = 'verified_fixed') AS verified,
        count(*) FILTER (WHERE e.verification_outcome = 'still_open') AS still_open,
        count(*) FILTER (
            WHERE e.pr_status = 'merged'
              AND coalesce(e.verification_outcome, 'pending') NOT IN
                  ('verified_fixed', 'still_open')
        ) AS unverified,
        median(e.time_to_verified_seconds) FILTER (
            WHERE e.verification_outcome = 'verified_fixed'
        ) AS median_seconds
    FROM remediation_events e
    {join}
    WHERE {filter}
    GROUP BY {key}
    ORDER BY verified DESC, attempts DESC
"""


def _efficacy_rows(catalog: Any, *, key: str, join: str, filter_: str) -> list[EfficacyRowOut]:
    rows = catalog.query(_EFFICACY_SELECT.format(key=key, join=join, filter=filter_))
    return [
        EfficacyRowOut(
            key=str(row[0]),
            attempts=int(row[1]),
            prs_opened=int(row[2]),
            merged=int(row[3]),
            rejected=int(row[4]),
            verified=int(row[5]),
            still_open=int(row[6]),
            unverified=int(row[7]),
            median_seconds_to_verified=int(row[8]) if row[8] is not None else None,
        )
        for row in rows
    ]


@router.get("/efficacy", response_model=EfficacyPage)
async def efficacy(request: Request, principal: PrincipalDep) -> EfficacyPage:
    """Does auto-remediation actually remove risk? (spec 25 §3)

    Until the verification loop shipped, a fixer that opened pull requests
    nobody merged was indistinguishable from one that silently removed real
    risk every week: both showed as `pr_opened` rows. The first is a machine
    generating review load, and that load is paid by exactly the people this
    platform exists to help.

    Ordered before `/repos/{repo_id}` — a literal path must not be shadowed by
    the parameterised one.
    """
    catalog = request.app.state.catalog
    if not catalog.all_files("remediation_events"):
        return EfficacyPage(
            by_fixer=[], by_rule=[], note="Auto-remediation has not run yet."
        )

    by_fixer = _efficacy_rows(
        catalog,
        key="e.fixer_name",
        join="",
        filter_="e.fixer_name IS NOT NULL",
    )
    by_rule = _efficacy_rows(
        catalog,
        key="f.rule_id",
        join="JOIN findings f ON f.finding_id = e.finding_id",
        filter_="e.fixer_name IS NOT NULL",
    )
    return EfficacyPage(
        by_fixer=by_fixer,
        by_rule=by_rule,
        note=(
            "`verified` means the finding was gone from a scan of the merge "
            "commit — the only column here that says risk was removed. "
            "`unverified` is merged-but-not-established, which is not a "
            "failure: the scan did not answer."
        ),
    )


@router.get("/repos/{repo_id}", response_model=RemediationPage)
async def repo_events(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> RemediationPage:
    """What auto-remediation did, and did not do, for one repository (spec 08 §7)."""
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    columns = [
        "event_id",
        "finding_id",
        "toxic_combination_id",
        "contributing_finding_ids",
        "pipeline_stage_reached",
        "triage_classification",
        "fix_pr_number",
        "fix_pr_url",
        "pr_status",
        "rationale",
        "created_at",
        "updated_at",
    ]
    rows = request.app.state.catalog.query(
        f"SELECT {', '.join(columns)} FROM remediation_events "
        "WHERE repo_full_name = ? ORDER BY updated_at DESC LIMIT ?",
        [repo_full_name, limit],
    )

    import json

    events = []
    for row in rows:
        record = dict(zip(columns, row, strict=True))
        raw = record.get("contributing_finding_ids")
        try:
            record["contributing_finding_ids"] = json.loads(raw) if raw else []
        except (TypeError, json.JSONDecodeError):
            record["contributing_finding_ids"] = []
        events.append(RemediationEventOut(**record))

    return RemediationPage(
        repo_full_name=repo_full_name,
        events=events,
        open_draft_prs=_open_draft_count(request, repo_full_name),
    )
