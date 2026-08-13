"""Oracle API (spec 09 §7).

Two audiences with different credentials, which is why the auth differs per
endpoint:

- **`/evaluate`** is called by the `oracle-gate` workflow inside an onboarded
  repo, so it authenticates with that repo's ingestion token and requires the
  `oracle` capability grant. The repo comes from the token, never the payload.
- **Everything else** is a human reading or overriding decisions, so it uses
  the admin session.

`GET /policy` is deliberately readable by any authenticated caller. spec 09 §7
calls it transparency: anyone whose pull request Oracle judges is entitled to
see exactly how the number was produced.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos.adminauth import AdminDep, PrincipalDep
from mykronos.api.ingest import TokenDep
from mykronos.db.models import CapabilityConfig, RepoOnboarding
from mykronos.knowledge.capture import capture_override, safe_capture
from mykronos.logsafe import scrub
from mykronos.notify import Notification
from mykronos.oracle.service import OracleService, decision_to_row
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/oracle", tags=["oracle"])


class EvaluateRequest(BaseModel):
    """What the gate workflow sends.

    No `repo_full_name`: it comes from the ingestion token, so a workflow
    cannot request a decision about somebody else's repository.
    """

    model_config = ConfigDict(extra="forbid")

    decision_type: str = Field(pattern="^(pr_gate|release_gate|portfolio)$")
    commit_sha: str = Field(min_length=1, max_length=64)
    pr_number: int | None = None
    release_tag: str | None = Field(default=None, max_length=255)


class EvaluateResult(BaseModel):
    decision_id: str
    overall_risk_score: int
    recommendation: str
    reasoning: str
    policy_version: str
    blocking: bool
    check_run_id: str | None = None
    check_run_error: str | None = None


class OverrideRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        min_length=1,
        max_length=2000,
        description=(
            "Required, and validated as non-empty (spec 09 §9). An override "
            "without a reason is the single most valuable retro signal in the "
            "system thrown away (spec 11 §4)."
        ),
    )
    accepted_recommendation: str | None = Field(
        default=None,
        pattern="^(go|review_recommended|no_go)$",
        description="What the human decided instead. Defaults to 'go'.",
    )


class OverrideResult(BaseModel):
    decision_id: str
    original_recommendation: str
    accepted_recommendation: str
    overridden_by: str
    overridden_at: datetime


def _service(request: Request) -> OracleService:
    return OracleService(
        request.app.state.catalog,
        request.app.state.buffer,
        request.app.state.oracle_policy,
        request.app.state.knowledge,
    )


def _repo_blocking(request: Request, repo_full_name: str) -> bool:
    """Whether this repo opted Oracle into blocking (spec 09 §6).

    Off unless someone deliberately turned it on, per capability, per repo.
    """
    with request.app.state.db.session() as session:
        onboarding = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == repo_full_name
            )
        ).scalars().first()
        if onboarding is None:
            return False
        config = session.execute(
            select(CapabilityConfig)
            .where(CapabilityConfig.repo_onboarding_id == onboarding.id)
            .where(CapabilityConfig.capability == "oracle")
        ).scalars().first()
        return bool((config.config_json or {}).get("blocking")) if config else False


def _installation_client(request: Request, repo_full_name: str) -> Any:
    with request.app.state.db.session() as session:
        onboarding = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == repo_full_name
            )
        ).scalars().first()
    if onboarding is None:
        return None
    return request.app.state.github_factory.for_installation(
        onboarding.github_installation_id
    )


@router.post("/evaluate", response_model=EvaluateResult)
async def evaluate(
    request: Request,
    body: EvaluateRequest,
    token: TokenDep,
    background: BackgroundTasks,
) -> EvaluateResult:
    """Score a commit and publish the result (spec 09 §7, §8)."""
    if not token.permits("oracle"):
        granted = ", ".join(sorted(token.granted_capabilities)) or "none"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"'oracle' is not enabled for {token.repo_full_name}. "
                f"Currently granted: {granted}."
            ),
        )

    blocking = _repo_blocking(request, token.repo_full_name)
    published = await _service(request).evaluate_and_publish(
        token.repo_full_name,
        decision_type=body.decision_type,
        commit_sha=body.commit_sha,
        pr_number=body.pr_number,
        release_tag=body.release_tag,
        blocking=blocking,
        github=_installation_client(request, token.repo_full_name),
    )

    # A no_go is the one decision that stops a deploy, and the pipeline that
    # asked has already exited by the time anyone looks at it. Sent as a
    # background task so a slow webhook cannot add latency to a gate every
    # build waits on (spec 16 §14).
    if published.decision.recommendation == "no_go":
        background.add_task(
            request.app.state.notifier.send,
            Notification(
                title="Oracle refused a commit",
                detail=(
                    f"Score {published.decision.overall_risk_score}. "
                    f"{published.decision.reasoning or 'No reasoning recorded.'}\n"
                    f"Commit `{body.commit_sha}`. "
                    + (
                        "Blocking is on: the check run is red."
                        if published.blocking
                        else "Advisory only: blocking is off for this repository."
                    )
                ),
                repo_full_name=token.repo_full_name,
                level="critical",
            ),
        )

    return EvaluateResult(
        decision_id=published.decision.decision_id,
        overall_risk_score=published.decision.overall_risk_score,
        recommendation=published.decision.recommendation,
        reasoning=published.decision.reasoning,
        policy_version=published.decision.policy_version,
        blocking=published.blocking,
        check_run_id=published.check_run_id,
        check_run_error=published.check_run_error,
    )


@router.get("/policy")
async def active_policy(request: Request, principal: PrincipalDep) -> dict[str, Any]:
    """The policy currently in force, verbatim (spec 09 §7).

    Readable by viewers as well as admins. Anyone whose pull request Oracle
    judges is entitled to see how the number was produced — a risk score you
    are not allowed to inspect is one people learn to route around.
    """
    policy = request.app.state.oracle_policy
    return {
        "version": policy.version,
        "source": policy.raw,
        "note": (
            "Every score is reproducible from this file and the decision's "
            "inputs_snapshot. Changing it requires a pull request and a "
            "re-baseline of the golden tests."
        ),
    }


@router.get("/shadow-mode")
async def shadow_mode(
    request: Request,
    principal: PrincipalDep,
    days: Annotated[int, Query(ge=1, le=730)] = 90,
) -> dict[str, Any]:
    """What blocking mode would have done, had it been on (spec 09 §6).

    Advisory-by-default is not just a safety choice, it is a measurement: every
    `no_go` that merged anyway is a merge blocking mode would have stopped.
    This endpoint is the evidence anyone should have to produce before
    proposing that the gate start failing builds.

    Ordered before `/decisions/{repo_id}` because a literal path must not be
    shadowed by the parameterised one.
    """
    since = utcnow() - timedelta(days=days)
    report = _service(request).shadow_mode_report(since=since)
    return {"window_days": days, "since": since.isoformat(), **report}


@router.get("/decisions/{repo_id}")
async def decisions_for_repo(
    request: Request,
    repo_id: str,
    principal: PrincipalDep,
    decision_type: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Decision history for one repo, newest first (spec 09 §7)."""
    with request.app.state.db.session() as session:
        onboarding = session.get(RepoOnboarding, repo_id)
    if onboarding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No repo {repo_id!r}. This takes the onboarding id.",
        )

    return {
        "repo_full_name": onboarding.github_repo_full_name,
        "decisions": _service(request).recent_decisions(
            onboarding.github_repo_full_name,
            decision_type=decision_type,
            limit=limit,
        ),
    }


@router.post("/decisions/{decision_id}/override", response_model=OverrideResult)
async def override_decision(
    request: Request, decision_id: str, body: OverrideRequest, actor: AdminDep
) -> OverrideResult:
    """Record a human overriding a recommendation (spec 09 §6).

    The decision itself is never rewritten — spec 09 §10 needs past decisions
    to stay reproducible. The override is recorded *alongside* it, so the
    history shows both what Oracle said and what the human did about it.

    spec 09 §6 calls these "exactly the data that should most influence policy
    tuning over time", which is why the reason is mandatory rather than
    encouraged.
    """
    service = _service(request)
    existing = service.find_decision(decision_id)
    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No decision {decision_id}."
        )
    if existing.get("human_override"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This decision has already been overridden. Overrides are "
                "append-only history, not a field to edit — re-evaluate the "
                "commit if the situation changed."
            ),
        )

    accepted = body.accepted_recommendation or "go"
    override = {
        "overridden_by": actor,
        "overridden_at": utcnow().isoformat(),
        "reason": body.reason,
        "original_recommendation": existing["recommendation"],
        "accepted_recommendation": accepted,
    }

    # Upserts only human_override on the existing row (see compaction's
    # risk_decisions rule); score, snapshot and reasoning stay untouched.
    request.app.state.buffer.append(
        "risk_decisions",
        [
            {
                **decision_to_row(_stub_decision(decision_id, existing)),
                "human_override": json.dumps(override, ensure_ascii=False),
            }
        ],
    )

    with request.app.state.db.session() as session:
        request.app.state.db.audit(
            session,
            actor=actor,
            action="oracle.override",
            entity_type="risk_decision",
            entity_id=decision_id,
            repo=existing["repo_full_name"],
            original=existing["recommendation"],
            accepted=accepted,
            reason=body.reason,
        )

    # spec 11 §4. spec 09 §6 calls overrides "exactly the data that should
    # most influence policy tuning over time"; this is what makes that true
    # rather than aspirational.
    safe_capture(
        capture_override,
        request.app.state.knowledge,
        repo_full_name=existing["repo_full_name"],
        decision_id=decision_id,
        original_recommendation=existing["recommendation"],
        accepted_recommendation=accepted,
        reason=body.reason,
        score=int(existing["overall_risk_score"]),
    )

    logger.info(
        "Oracle decision %s overridden by %s: %s -> %s",
        scrub(decision_id),
        scrub(actor),
        scrub(existing["recommendation"]),
        scrub(accepted),
    )
    return OverrideResult(
        decision_id=decision_id,
        original_recommendation=existing["recommendation"],
        accepted_recommendation=accepted,
        overridden_by=actor,
        overridden_at=utcnow(),
    )


def _stub_decision(decision_id: str, existing: dict[str, Any]) -> Any:
    """The minimum row shape needed to carry an override through compaction.

    Compaction's upsert for `risk_decisions` only reads `human_override` and
    `github_check_run_id` from the incoming row, so the rest of these fields
    are never written over the stored decision — but they have to be present
    and correctly typed for the row to parse.
    """
    from mykronos.oracle.engine import Decision

    return Decision(
        decision_id=decision_id,
        repo_full_name=existing["repo_full_name"],
        decision_type=existing["decision_type"],
        commit_sha="",
        pr_number=existing.get("pr_number"),
        release_tag=None,
        overall_risk_score=int(existing["overall_risk_score"]),
        recommendation=existing["recommendation"],
        reasoning="",
        inputs_snapshot={},
        policy_version="",
        evaluated_at=utcnow(),
    )
