"""Rule vectors: analyst-confirmed CVSS vectors for findings with no CVE
(TheHub #60832, decision D3).

Reading lists a repository's rules that no published source gives a vector,
with their open-finding counts and the template that would pre-fill each.
Writing is three verbs with three different bars:

- **propose** (any writer, agents included): changes no score.
- **confirm** (a person only, `HumanDep`): from here the rule's findings are
  scored, with `vector_source=analyst`.
- **retire**: a proposal by any writer; a confirmed vector by a person only,
  because withdrawing it changes scores too.

Every write is audited as `rule_vector.<verb>`, in the caller's own name, and
the audit entry records the principal's kind, so "a person confirmed this" is
a fact the log states rather than one the route implies.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from mykronos import environment, rule_vectors
from mykronos.adminauth import HumanDep, Principal, PrincipalDep
from mykronos.db.models import RuleVector

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


class RuleVectorOut(BaseModel):
    id: str
    repo_full_name: str | None
    #: `repository` or `estate`.
    scope: str
    capability: str
    tool: str
    rule_id: str
    vector: str
    base_score: float | None
    #: proposed | confirmed | retired. Only `confirmed` is ever scored.
    status: str
    vector_source: str
    #: `cwe-vector-templates-v1:CWE-79`, or empty when typed by hand.
    proposed_from: str
    asserted_by: str
    asserted_at: datetime
    confirmed_by: str | None
    confirmed_at: datetime | None
    retired_by: str | None
    retired_at: datetime | None
    note: str


class TemplateOut(BaseModel):
    id: str
    cwe: str
    name: str
    vector: str
    base_score: float
    rationale: str


class RuleOut(BaseModel):
    capability: str
    tool: str
    rule_id: str
    #: One finding's title, so a person can tell what the rule is about.
    title: str
    #: Open findings of this rule that no published source gives a vector.
    findings: int
    cwes: list[str]
    #: The template that would pre-fill a proposal; null when no CWE the
    #: findings declare has one.
    suggested_template: TemplateOut | None
    #: Proposed and confirmed rows for this rule: this repository's and
    #: estate-wide.
    vectors: list[RuleVectorOut]
    #: The confirmed row the resolver uses now; null means these findings are
    #: unscored.
    applies: RuleVectorOut | None


class RuleVectorsPage(BaseModel):
    repo_full_name: str
    rules: list[RuleOut]
    #: Rules here with no confirmed vector: their findings are unscored.
    unscored_rules: int
    unscored_findings: int
    templates: list[TemplateOut]
    templates_version: str


class RuleVectorList(BaseModel):
    rule_vectors: list[RuleVectorOut]


class ProposeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The repository's onboarding id; omit for an estate-wide vector, which
    #: applies wherever a repository has no confirmed vector of its own.
    repo_id: str | None = Field(default=None, max_length=64)
    capability: str = Field(min_length=1, max_length=32)
    tool: str = Field(min_length=1, max_length=64)
    rule_id: str = Field(min_length=1, max_length=512)
    #: `CWE-79` or `cwe-vector-templates-v1:CWE-79`.
    template_id: str | None = Field(default=None, max_length=128)
    #: A CVSS 3.1 base vector. With a template, it is the template edited.
    vector: str | None = Field(default=None, max_length=256)
    note: str = Field(default="", max_length=2_000)


class EditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vector: str | None = Field(default=None, max_length=256)
    note: str | None = Field(default=None, max_length=2_000)


class RetireRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str | None = Field(default=None, max_length=2_000)


def _out(row: RuleVector) -> RuleVectorOut:
    return RuleVectorOut.model_validate(rule_vectors.as_dict(row))


def _template_out(template: rule_vectors.Template) -> TemplateOut:
    return TemplateOut(
        id=template.id,
        cwe=template.cwe,
        name=template.name,
        vector=template.vector,
        base_score=template.base_score,
        rationale=template.rationale,
    )


def _refused(exc: Exception) -> HTTPException:
    if isinstance(exc, rule_vectors.NotAPersonError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, rule_vectors.RuleVectorConflictError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc))


def _require_writer(principal: Principal, verb: str) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{verb} requires the 'admin' role; you have '{principal.role.value}'.",
        )


def _audit(request: Request, session: Any, principal: Principal, verb: str,
           row: RuleVector, **detail: Any) -> None:
    request.app.state.db.audit(
        session,
        actor=principal.actor,
        action=f"rule_vector.{verb}",
        entity_type="rule_vector",
        entity_id=row.id,
        repo_full_name=row.repo_full_name,
        capability=row.capability,
        tool=row.tool,
        rule_id=row.rule_id,
        vector=row.vector,
        status=row.status,
        proposed_from=row.proposed_from,
        **detail,
    )


@router.get("/repos/{repo_id}/rule-vectors", response_model=RuleVectorsPage)
async def repo_rule_vectors(
    request: Request, repo_id: str, principal: PrincipalDep
) -> RuleVectorsPage:
    """Rules whose open findings nothing publishes a CVSS vector for.

    SAST, DAST and secrets rules, mostly: no CVE, so no NVD vector, so no
    environmental score (D-106). Each rule says how many open findings it
    holds, which template would pre-fill a proposal, and any rule vector
    already proposed or confirmed for it. A confirmed one is listed as
    `applies`; until one is, the rule's findings stay unscored.
    """
    from mykronos.api.dashboard import _resolve_repo

    repo_full_name = _resolve_repo(request, repo_id)
    templates = rule_vectors.load_templates()
    findings = environment.open_findings(request.app.state.catalog, repo_full_name)
    with request.app.state.db.session() as session:
        rules = rule_vectors.rules_without_vector(
            session, findings, repo_full_name=repo_full_name, templates=templates
        )
        unscored = [r for r in rules if r.applies is None]
        return RuleVectorsPage(
            repo_full_name=repo_full_name,
            rules=[
                RuleOut(
                    capability=r.capability,
                    tool=r.tool,
                    rule_id=r.rule_id,
                    title=r.title,
                    findings=r.findings,
                    cwes=r.cwes,
                    suggested_template=_template_out(r.suggested) if r.suggested else None,
                    vectors=[_out(v) for v in r.vectors],
                    applies=_out(r.applies) if r.applies else None,
                )
                for r in rules
            ],
            unscored_rules=len(unscored),
            unscored_findings=sum(r.findings for r in unscored),
            templates=[_template_out(t) for t in templates.templates.values()],
            templates_version=templates.version,
        )


@router.get("/rule-vectors", response_model=RuleVectorList)
async def list_rule_vectors(
    request: Request,
    principal: PrincipalDep,
    rule_status: Annotated[str | None, Query(alias="status", max_length=16)] = None,
) -> RuleVectorList:
    """Every rule vector across the estate, newest first; optionally one state."""
    from sqlalchemy import select

    if rule_status is not None and rule_status not in rule_vectors.STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"status must be one of {', '.join(rule_vectors.STATUSES)}",
        )
    with request.app.state.db.session() as session:
        query = select(RuleVector).order_by(RuleVector.asserted_at.desc())
        if rule_status is not None:
            query = query.where(RuleVector.status == rule_status)
        return RuleVectorList(rule_vectors=[_out(r) for r in session.scalars(query)])


@router.post("/rule-vectors", response_model=RuleVectorOut, status_code=201)
async def propose_rule_vector(
    request: Request, body: ProposeRequest, principal: PrincipalDep
) -> RuleVectorOut:
    """Propose a CVSS 3.1 base vector for one rule. **Changes no score.**

    Any writer, agents included. From a template (`template_id`), by hand
    (`vector`), or a template edited (both). Only a person's confirmation
    makes it count.
    """
    _require_writer(principal, "Proposing a rule vector")
    repo_full_name: str | None = None
    if body.repo_id:
        from mykronos.api.dashboard import _resolve_repo

        repo_full_name = _resolve_repo(request, body.repo_id)
    with request.app.state.db.session() as session:
        try:
            row = rule_vectors.propose(
                session,
                repo_full_name=repo_full_name,
                capability=body.capability,
                tool=body.tool,
                rule_id=body.rule_id,
                asserted_by=principal.actor,
                vector=body.vector,
                template_id=body.template_id,
                note=body.note,
            )
        except (rule_vectors.RuleVectorError, LookupError) as exc:
            raise _refused(exc) from exc
        _audit(request, session, principal, "propose", row)
        return _out(row)


@router.patch("/rule-vectors/{rule_vector_id}", response_model=RuleVectorOut)
async def edit_rule_vector(
    request: Request, rule_vector_id: str, body: EditRequest, principal: PrincipalDep
) -> RuleVectorOut:
    """Edit a proposal. A confirmed vector is changed by proposing its
    replacement and confirming that, never in place."""
    _require_writer(principal, "Editing a rule vector")
    with request.app.state.db.session() as session:
        try:
            existing = session.get(RuleVector, rule_vector_id)
            before = existing.vector if existing is not None else None
            row = rule_vectors.edit(
                session, rule_vector_id, vector=body.vector, note=body.note
            )
        except (rule_vectors.RuleVectorError, LookupError) as exc:
            raise _refused(exc) from exc
        _audit(request, session, principal, "edit", row, previous_vector=before)
        return _out(row)


@router.post("/rule-vectors/{rule_vector_id}/confirm", response_model=RuleVectorOut)
async def confirm_rule_vector(
    request: Request, rule_vector_id: str, body: EditRequest, principal: HumanDep
) -> RuleVectorOut:
    """A person confirms a proposal, optionally editing its vector first.

    **A person only.** An agent's or automation's credential is refused here
    whatever else it may write. From this moment the rule's findings that no
    published source gives a vector are scored from this one, and the stored
    score names this row as its `vector_ref`. A confirmed vector this
    replaces is retired in the same transaction.
    """
    with request.app.state.db.session() as session:
        try:
            proposed = session.get(RuleVector, rule_vector_id)
            proposed_vector = proposed.vector if proposed is not None else None
            row, replaced = rule_vectors.confirm(
                session,
                rule_vector_id,
                principal=principal,
                vector=body.vector,
                note=body.note,
            )
        except (rule_vectors.RuleVectorError, rule_vectors.NotAPersonError, LookupError) as exc:
            raise _refused(exc) from exc
        _audit(
            request,
            session,
            principal,
            "confirm",
            row,
            proposed_vector=proposed_vector,
            edited=proposed_vector != row.vector,
            replaced=replaced.id if replaced is not None else None,
            replaced_vector=replaced.vector if replaced is not None else None,
        )
        return _out(row)


@router.post("/rule-vectors/{rule_vector_id}/retire", response_model=RuleVectorOut)
async def retire_rule_vector(
    request: Request, rule_vector_id: str, body: RetireRequest, principal: PrincipalDep
) -> RuleVectorOut:
    """Withdraw a proposal (any writer) or a confirmed vector (a person only:
    its findings go back to unscored)."""
    _require_writer(principal, "Retiring a rule vector")
    with request.app.state.db.session() as session:
        try:
            existing = session.get(RuleVector, rule_vector_id)
            was = existing.status if existing is not None else None
            row = rule_vectors.retire(
                session, rule_vector_id, principal=principal, note=body.note
            )
        except (rule_vectors.RuleVectorError, rule_vectors.NotAPersonError, LookupError) as exc:
            raise _refused(exc) from exc
        _audit(request, session, principal, "retire", row, previous_status=was)
        return _out(row)
