"""Operational tables — specs 02 §3, 03 §3, 05 §4, 12 §7."""

from __future__ import annotations

import json
import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from mykronos.schemas import utcnow


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON}


class Organization(Base):
    """spec 02 §3."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    github_org_login: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    repos: Mapped[list[RepoOnboarding]] = relationship(back_populates="org")


def get_or_create_organization(session: Session, login: str) -> Organization:
    """Find an org by login, creating it if this is the first repo from it.

    Lives here rather than in whichever API module needed it first: the
    webhook receiver, the manual registration endpoint and the tests all
    reach the same row, and `github_org_login` is unique, so a second
    hand-rolled copy of this is a constraint violation waiting to happen.
    """
    org = session.execute(
        select(Organization).where(Organization.github_org_login == login)
    ).scalars().first()
    if org is None:
        org = Organization(github_org_login=login)
        session.add(org)
        session.flush()
    return org


def capability_config_for(
    session: Session, repo_full_name: str, capability: str
) -> dict[str, Any]:
    """This repo's stored overrides for one capability, or `{}`.

    Returns the raw stored dict rather than a validated model: callers want
    one or two settings, and re-validating here would mean a config written
    under an older schema could raise from an unrelated read path.
    """
    onboarding = session.execute(
        select(RepoOnboarding).where(
            RepoOnboarding.github_repo_full_name == repo_full_name
        )
    ).scalars().first()
    if onboarding is None:
        return {}
    config = session.execute(
        select(CapabilityConfig)
        .where(CapabilityConfig.repo_onboarding_id == onboarding.id)
        .where(CapabilityConfig.capability == capability)
    ).scalars().first()
    return dict(config.config_json or {}) if config else {}


class RepoOnboarding(Base):
    """spec 02 §3, extended by spec 03 §4 with the idempotency fields."""

    __tablename__ = "repo_onboardings"
    __table_args__ = (
        # spec 02 §9: the same repo installed under two orgs (e.g. a fork) is
        # two independent onboardings, so the constraint is the pair.
        UniqueConstraint("org_id", "github_repo_full_name", name="uq_org_repo"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    github_repo_full_name: Mapped[str] = mapped_column(String(255), index=True)
    github_installation_id: Mapped[int] = mapped_column(Integer, index=True)

    #: pending_install | active | suspended | removed
    status: Mapped[str] = mapped_column(String(32), default="pending_install")

    #: Which CI is supposed to scan this repository (spec 03 §3a):
    #: `concourse`, `github_actions`, or `none`.
    #:
    #: Records intent, not coverage. Whether the scans actually arrive is a
    #: different question answered by the cross-check in spec 15 §4a - a repo
    #: can declare `concourse`, enable `dast`, and have no DAST job.
    #:
    #: Defaults to `concourse` because that is what is true here now. A
    #: default that installs Actions workflows into a repository whose
    #: Actions were deliberately removed is a default that undoes a decision.
    scanned_by: Mapped[str] = mapped_column(String(32), default="concourse")
    #: A deliberately-vulnerable corpus, scanned by the real pipelines so the
    #: detectors can be graded against known ground truth (spec 23 §1.2).
    #:
    #: **Excluded from every aggregate, and that is the whole reason the flag
    #: exists.** Seeded vulnerabilities are real findings in the lake — they
    #: have to be, or grading them would test a different code path from the
    #: one that runs — so without this the corpus becomes, permanently, the
    #: fleet's worst repository, and deliberately vulnerable code is counted
    #: as estate risk. The portfolio summary, the trend series and the
    #: maturity model all skip it.
    #:
    #: Its own findings, decisions and scans are untouched: the bench repo has
    #: a page like any other, because a benchmark whose results nobody can
    #: open is a benchmark nobody trusts.
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)

    #: Capabilities whose workflow-install PR has actually merged. This is the
    #: live set; `pending_capabilities` is what has been requested but not yet
    #: merged (spec 03 §4). Keeping them apart is what makes the installer
    #: idempotent — the diff is always requested-minus-active.
    enabled_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    pending_capabilities: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    pending_pr_number: Mapped[int | None] = mapped_column(Integer, default=None)

    default_branch: Mapped[str] = mapped_column(String(255), default="main")

    #: Where to ask this repository's deployment what revision it is running
    #: (#361). A GET returning JSON with a string at `build.sha`. mykronos's
    #: `/healthz` and TheHub's `/health` serve the sha only with their
    #: perimeter token (D-157, TheHub #60709), which the probe sends when
    #: `deployment_probe_tokens` names the URL's origin (#452).
    #:
    #: Empty is the common state and is not a fault. A repository with no
    #: deployment this platform can reach -- a library, a scanner, a config
    #: tree -- is a normal thing to be, and the portfolio reports it as
    #: `not_configured` rather than as a failed probe.
    deployment_probe_url: Mapped[str] = mapped_column(String(1024), default="")

    #: The last revision a probe actually read back, and when. Never inferred
    #: from the default branch, a tag, or a build number: the whole point is to
    #: record what the running process said about itself, and a value derived
    #: from anything else would reproduce the defect this exists to catch.
    deployed_revision: Mapped[str | None] = mapped_column(String(64), default=None)
    deployed_revision_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: not_configured | ok | unreachable | unparsed — see `mykronos.deployments`.
    deployment_probe_status: Mapped[str] = mapped_column(String(32), default="not_configured")
    #: How far the deployment sits behind `default_branch`, from the GitHub
    #: compare API, as the last sweep found it (#452): `DeploymentLag.to_json`.
    #: The cache the briefing and the dashboard read, so neither calls GitHub
    #: while rendering. Null until a sweep has run with a probe configured.
    deployment_lag: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=None)

    onboarded_by: Mapped[str] = mapped_column(String(255), default="")
    onboarded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    org: Mapped[Organization] = relationship(back_populates="repos")
    capability_configs: Mapped[list[CapabilityConfig]] = relationship(
        back_populates="repo", cascade="all, delete-orphan"
    )

    @property
    def is_schedulable(self) -> bool:
        """spec 02 §9: suspended is treated as removed for scheduling, but is
        kept distinct in the model so the dashboard can say "paused" rather
        than "gone"."""
        return self.status == "active"


class RiskProfile(Base):
    """What this application *is*, as an asset (spec 21 §1).

    Every other Oracle input is derived from what a scanner found. None of
    them can tell you whether an application is internet-facing or handles
    regulated data — no scan sees that, and a repo that is an internal build
    tool and one that is a public payments API otherwise score identically
    for the identical finding.

    Admin-authored, never inferred. One row per repository (unlike
    `CapabilityConfig`'s per-capability rows), and every field independently
    nullable: a partially-filled profile is still useful, and Oracle scores
    what is known rather than treating one missing field as "no profile".
    The distinction that matters is row-exists vs. row-absent — a profile
    saying "we don't know yet" is an auditable fact; no profile at all is
    `available: false`, never defaulted to "internal, low criticality",
    which would be a guess wearing a fact's clothes.
    """

    __tablename__ = "risk_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_onboarding_id: Mapped[str] = mapped_column(
        ForeignKey("repo_onboardings.id"), unique=True, index=True
    )
    internet_facing: Mapped[bool | None] = mapped_column(Boolean, default=None)
    #: public | internal | confidential | regulated
    data_classification: Mapped[str | None] = mapped_column(String(32), default=None)
    #: low | medium | high | critical
    business_criticality: Mapped[str | None] = mapped_column(String(16), default=None)
    #: Regulatory regimes (`pci`, `hipaa`, `soc2`, ...). An empty list is a
    #: real answer ("none apply"), distinct from the field never being asked.
    compliance_scope: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: Context only, never scored.
    owner: Mapped[str | None] = mapped_column(String(255), default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    #: Who last said this, and when. A risk profile that nobody owns is one
    #: nobody will correct when it goes stale.
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class ReachabilityReport(Base):
    """Which Python files nothing in the repository imports (spec 19 §2.1).

    Operational, not lake. Every other observation about a scan is
    append-only in the lake because its history is evidence — you have to be
    able to say what a finding looked like in March. This is not that: it is
    a fact about the current tree, superseded entirely by the next analysis,
    and keeping a row per commit would be a growing table nothing ever reads
    the old rows of. The same reasoning `RiskProfile` follows, and one row
    per repository for the same reason.

    Stored as a list of paths rather than a per-file table. The number of
    orphaned files in a repository is small by construction — a repository
    where most files are orphaned has a layout problem, not a reachability
    finding — and a table would buy joins nothing needs.

    Absence is meaningful and must stay so: no row means the analysis has
    never run for this repository, which Oracle reports as `available:
    false`. It must never read as "nothing is orphaned".
    """

    __tablename__ = "reachability_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_onboarding_id: Mapped[str] = mapped_column(
        ForeignKey("repo_onboardings.id"), unique=True, index=True
    )
    #: Only ever `python` today. Named rather than assumed so a second
    #: analyser can be added without every reader having to guess which
    #: language the numbers describe.
    language: Mapped[str] = mapped_column(String(32), default="python")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    #: Repo-relative paths. An empty list is a real answer — analysed, and
    #: everything is imported from somewhere.
    orphaned_paths: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: How many files the analysis actually read. The denominator: "3
    #: orphaned" means something different out of 12 files than out of 1,200.
    files_analysed: Mapped[int] = mapped_column(Integer, default=0)
    #: Files that would not parse. Never reported orphaned — their own
    #: imports are unknown, so anything they might import is unproven too.
    files_unparseable: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class CapabilityConfig(Base):
    """Per-repo, per-capability overrides (spec 02 §3)."""

    __tablename__ = "capability_configs"
    __table_args__ = (
        UniqueConstraint("repo_onboarding_id", "capability", name="uq_repo_capability"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_onboarding_id: Mapped[str] = mapped_column(
        ForeignKey("repo_onboardings.id"), index=True
    )
    capability: Mapped[str] = mapped_column(String(32))
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    repo: Mapped[RepoOnboarding] = relationship(back_populates="capability_configs")


class IngestionToken(Base):
    """One per repo, carrying capability grants separately (spec 05 §4, D-009).

    Only the SHA-256 is stored. The plaintext exists once, at issuance, on its
    way into the repo's Actions secret (spec 12 §2).
    """

    __tablename__ = "ingestion_tokens"

    token_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)

    #: active | superseded | revoked
    #: `superseded` is a token replaced by rotation that is still inside its
    #: overlap window — accepted so in-flight workflows do not 401 (spec 05 §4).
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)

    issued_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rotate_after: Mapped[datetime] = mapped_column(DateTime)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: When a superseded token stops being accepted. Null unless superseded.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    #: Whether this token's plaintext is known to have reached whatever
    #: scans with it. False means nothing has confirmed delivery yet.
    #:
    #: Without this, a rotation that succeeded locally but failed to write the
    #: secret would look complete: the new token is active with a fresh
    #: 90-day clock, so it is not due for rotation, nothing retries — and the
    #: repo's CI breaks silently when the superseded token's overlap expires.
    #: The rotation job retries any active token that is not yet synced.
    #:
    #: It used to be set by exactly one event — a successful GitHub Actions
    #: secret write — which made it a tripwire a Concourse-scanned repository
    #: could never reset (#263). `ToddGBenson/TheHub` carried it permanently
    #: while uploading successfully several times a day. Delivery is now also
    #: recorded from ingestion, so the flag has a path back to true for a repo
    #: this platform cannot write a secret to.
    secret_synced: Mapped[bool] = mapped_column(Boolean, default=False)

    #: When delivery was last confirmed, and nothing about *how*: both writers
    #: set it, and the distinction that matters to a reader is confirmed
    #: versus not (#263).
    #:
    #: Recorded separately from the flag because a bare `True` asserts more
    #: than it measured — "delivered" with no moment attached cannot be aged,
    #: cannot be told apart from a value set at onboarding, and gives a
    #: briefing nothing to print. Null for a token confirmed before this
    #: column existed, which is why the flag remains the thing queried.
    delivery_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    label: Mapped[str] = mapped_column(String(255), default="")


class AgentCredential(Base):
    """One per agent instance: how an agent is told apart from the operator (spec 34 §1).

    Before this, every agent used the operator's admin token and the audit log
    recorded both under one name, so "who decided this?" had no answer. Only
    the SHA-256 is stored, as for ingestion tokens; the plaintext exists once,
    at minting.

    `lineage` is the chain of instances that minted this one, root first. An
    agent may mint a credential for a sub-agent, and the child inherits the
    parent's lineage plus the parent - which is what lets spec 34's
    `outside_lineage` rule refuse a sub-agent approving its parent's work.
    """

    __tablename__ = "agent_credentials"

    token_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Stable, human-readable principal name, e.g. `agent:claude-opus-5.5:3f9a1c`.
    actor: Mapped[str] = mapped_column(String(255), index=True, default="")
    #: The model family the credential was issued for (spec 34 §1.3: recorded,
    #: not attested).
    family: Mapped[str] = mapped_column(String(128), default="")
    #: One instance per credential; two runs of one model are two instances.
    instance: Mapped[str] = mapped_column(String(36), index=True, default=new_id)
    lineage: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: The human this agent acts for. An agent never acts on its own authority.
    on_behalf_of: Mapped[str] = mapped_column(String(255), default="")
    #: Free text naming why the agent exists (`author`, `independent-reviewer`).
    purpose: Mapped[str] = mapped_column(String(128), default="")
    minted_by: Mapped[str] = mapped_column(String(255), default="")
    minted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    #: Defaults to the moment of creation, so a row written without an
    #: expiry is already expired: it fails closed rather than living forever.
    expires_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(255), default=None)
    #: Minted by the platform itself for a reviewer run it started (spec 34
    #: §4.3). The only credentials that can attest `fresh_context`: the
    #: platform built the run's input, so it knows the run saw nothing else.
    #: No API path sets it.
    platform_started: Mapped[bool] = mapped_column(Boolean, default=False)


class RepoReadToken(Base):
    """A read-only credential that answers for one repository's posture.

    A service that wants to know how its own repository stands - "how many
    open dependency findings do I have?" - had two credentials to choose from,
    and both were wrong. Its ingestion token can *write* findings, and the
    viewer token reads every repository. This one does neither: it is
    accepted by exactly one route, which returns counts for the repository
    the token was minted for and nothing else.

    It does not resolve to a `Principal`. That is the scope, not a detail: a
    principal of any role passes every `PrincipalDep` route, and no route
    checks a repo-scoped role per repository, so a token that became a
    principal would read the whole estate.

    Only the SHA-256 is stored; the plaintext exists once, at minting.
    """

    __tablename__ = "repo_read_tokens"

    token_sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Stable handle for revocation and listing; the hash is never shown.
    token_id: Mapped[str] = mapped_column(String(36), index=True, default=new_id)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    label: Mapped[str] = mapped_column(String(255), default="")
    minted_by: Mapped[str] = mapped_column(String(255), default="")
    minted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    #: Defaults to the moment of creation, so a row written without an expiry
    #: is already expired: it fails closed, as `AgentCredential` does.
    expires_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(255), default=None)


class ApprovalRequest(Base):
    """One governed action awaiting a second party (spec 34 §4).

    An approval is of `evidence_digest`, not of `subject_ref`: the bundle the
    approver saw is frozen and hashed, and a changed subject is a new request.
    The requester is snapshotted rather than joined, so a later revocation of
    their credential cannot rewrite who asked.
    """

    __tablename__ = "approval_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    duty: Mapped[str] = mapped_column(String(64), index=True, default="")
    tier: Mapped[str] = mapped_column(String(64), default="")
    subject_ref: Mapped[str] = mapped_column(String(255), index=True, default="")
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence_digest: Mapped[str] = mapped_column(String(64), default="")
    requester_statement: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(255), index=True, default="")
    requester_kind: Mapped[str] = mapped_column(String(16), default="")
    requester_provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: pending | approved | rejected | expired | withdrawn
    state: Mapped[str] = mapped_column(String(16), index=True, default="pending")
    policy_version: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)


class ApprovalDecision(Base):
    """One approver's verdict on one request, bound to the digest they saw."""

    __tablename__ = "approval_decisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    approver: Mapped[str] = mapped_column(String(255), default="")
    approver_kind: Mapped[str] = mapped_column(String(16), default="")
    approver_provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: approve | reject | needs_info
    verdict: Mapped[str] = mapped_column(String(16), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_digest: Mapped[str] = mapped_column(String(64), default="")
    #: The delegation that made an agent eligible, if one did.
    delegation_id: Mapped[str | None] = mapped_column(String(36), default=None)
    #: One person on both sides, allowed only under `single_operator` after
    #: the tier's cooling-off - the documented AC-5 deviation (spec 33 §2.3).
    same_person: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Chosen for after-the-fact human review (spec 34 §5.2).
    sampled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: The human's verdict on a sampled agent decision: agree | disagree.
    sample_verdict: Mapped[str | None] = mapped_column(String(16), default=None)
    sample_reviewed_by: Mapped[str | None] = mapped_column(String(255), default=None)
    sample_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ApprovalEvent(Base):
    """Hash-chained history of one request (spec 33 §7, spec 34 §4.1).

    Each event carries the hash of the previous event for the same request, so
    an edited or deleted event breaks verification of every event after it.
    """

    __tablename__ = "approval_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    seq: Mapped[int] = mapped_column(Integer, default=0)
    event: Mapped[str] = mapped_column(String(64), default="")
    actor: Mapped[str] = mapped_column(String(255), default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RiskAcceptance(Base):
    """A risk acceptance as a decision, not a status on a row (spec 33 §1).

    One record covers the findings its scope matched when it was requested -
    3,647 ZAP findings are one decision - and it is reviewed, renewed, revoked
    and expired as that one thing. Findings still carry `accepted_risk`,
    `accepted_until` and `accepted_reason_code` in the lake, stamped from this
    record on approval, so the Oracle and the existing sweep keep working.
    """

    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    #: The predicate that chose the findings (spec 33 §1.2).
    scope: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: The findings it covers, fixed at request time and bound into the
    #: approval's evidence digest. A later match is drift, not coverage.
    covered_finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    drift_finding_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    response: Mapped[str] = mapped_column(String(16), default="accept")
    #: vendor_dependency | risk_adjustment | operational_requirement
    deviation_type: Mapped[str] = mapped_column(String(32), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    residual_likelihood: Mapped[str] = mapped_column(String(16), default="")
    residual_impact: Mapped[str] = mapped_column(String(16), default="")
    residual_severity: Mapped[str] = mapped_column(String(16), index=True, default="")
    premises: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    compensating_controls: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    milestones: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    risk_owner: Mapped[str] = mapped_column(String(255), default="")
    requested_by: Mapped[str] = mapped_column(String(255), default="")
    approved_by: Mapped[str | None] = mapped_column(String(255), default=None)
    approval_request_id: Mapped[str | None] = mapped_column(String(36), default=None)
    #: pending_approval | active | review_due | expired | rejected | revoked |
    #: premise_failed | closed
    status: Mapped[str] = mapped_column(String(24), index=True, default="pending_approval")
    #: Migrated from row-level acceptances (spec 33 §10): the findings already
    #: carry the old acceptance, and approval confirms rather than creates it.
    legacy: Mapped[bool] = mapped_column(Boolean, default=False)
    renews_id: Mapped[str | None] = mapped_column(String(36), default=None)
    renewal_count: Mapped[int] = mapped_column(Integer, default=0)
    requested_until: Mapped[date | None] = mapped_column(Date, default=None)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    first_effective_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    review_by: Mapped[date | None] = mapped_column(Date, default=None)
    expires_at: Mapped[date | None] = mapped_column(Date, default=None)
    tracking_ref: Mapped[str | None] = mapped_column(String(255), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    closed_reason: Mapped[str | None] = mapped_column(String(255), default=None)


class ApprovalStamp(Base):
    """One thing the platform posted outside itself about a request (spec 34 §1.2).

    GitHub actions all read as one shared account, so the stamp - here, the
    `independent-review` check run - is where the duty-holders are named.
    One row per post: the check's history is every state it was put in.
    """

    __tablename__ = "approval_stamps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    request_id: Mapped[str] = mapped_column(String(36), index=True, default="")
    #: e.g. `github_check:owner/repo@sha`
    target: Mapped[str] = mapped_column(String(255), default="")
    #: The request state this post reflected.
    state: Mapped[str] = mapped_column(String(16), default="")
    #: What was posted: in_progress | success | failure
    conclusion: Mapped[str] = mapped_column(String(16), default="")
    external_id: Mapped[str | None] = mapped_column(String(64), default=None)
    #: Set when the post failed; the job retries until one succeeds.
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Delegation(Base):
    """The operator's trust in an agent approver, made explicit (spec 34 §5).

    Lets agents satisfy the tiers that list `{kind: agent, delegation:
    required}`. Created only by an approved `delegation_grant` request, so a
    person asked for it and a person approved it.
    """

    __tablename__ = "delegations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    granted_by: Mapped[str] = mapped_column(String(255), default="")
    grant_request_id: Mapped[str] = mapped_column(String(36), default="")
    duty: Mapped[str] = mapped_column(String(64), index=True, default="")
    tiers: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: Model families whose agents may use it; empty means none.
    approver_families: Mapped[list[str]] = mapped_column(JSON, default=list)
    constraints: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    sampling: Mapped[float] = mapped_column(Float, default=0.2)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(255), default=None)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    suspended_reason: Mapped[str | None] = mapped_column(String(255), default=None)


class CapabilityGrant(Base):
    """What a repo's token is currently allowed to write (spec 05 §4).

    Presence is the grant. Revoking deletes the row — immediate, local, and
    incapable of partially applying, which is the property that makes it a
    better revocation path than deleting a GitHub secret. History lives in the
    audit log, which is append-only.
    """

    __tablename__ = "capability_grants"
    __table_args__ = (
        UniqueConstraint("repo_full_name", "capability", name="uq_grant"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)
    capability: Mapped[str] = mapped_column(String(32))
    granted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WorkflowInstallEvent(Base):
    """Audit of every install/update PR the Workflow Installer opens (spec 03 §3.6)."""

    __tablename__ = "workflow_install_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_onboarding_id: Mapped[str] = mapped_column(
        ForeignKey("repo_onboardings.id"), index=True
    )
    pr_number: Mapped[int | None] = mapped_column(Integer, default=None)
    pr_url: Mapped[str] = mapped_column(String(512), default="")
    branch: Mapped[str] = mapped_column(String(255), default="")
    capabilities_added: Mapped[list[str]] = mapped_column(JSON, default=list)
    capabilities_removed: Mapped[list[str]] = mapped_column(JSON, default=list)
    #: opened | updated | merged | closed_unmerged | failed
    status: Mapped[str] = mapped_column(String(32), default="opened")
    detail: Mapped[str] = mapped_column(String(2000), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    merged_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)


class ThreatIntelMatch(Base):
    """Public exploitation data for one CVE (spec 17 §4.2).

    Operational, not lake: this is a *current-value* table — one row per CVE,
    overwritten on every refresh — not an append-only record of scan results.
    A revised EPSS score is a correction to a fact this row states, not an
    event to append, which is why it lives alongside `CapabilityGrant` rather
    than as a `findings`-style Parquet table (spec 05 §5a's append-only rule
    is about *scan* history; this isn't one).

    Written only for CVEs an open finding in the portfolio actually names
    (`threat_intel.py::refresh`) — not the full public catalogs, which are
    orders of magnitude larger than anything this platform's findings
    reference.
    """

    __tablename__ = "threat_intel_matches"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_added_at: Mapped[date | None] = mapped_column(Date, default=None)
    kev_due_date: Mapped[date | None] = mapped_column(Date, default=None)
    epss_score: Mapped[float | None] = mapped_column(Float, default=None)
    epss_percentile: Mapped[float | None] = mapped_column(Float, default=None)
    #: The published CVSS v3.x base vector, from NVD. Null until looked up, and
    #: null forever for a CVE NVD has not scored — which is a real state and
    #: not a zero. Stored as the vector rather than the score because the score
    #: cannot be re-read for an environment and the vector can: that is the
    #: entire difference between "7.5 everywhere" and "7.5 there, 5.9 here".
    cvss_vector: Mapped[str | None] = mapped_column(String(128), default=None)
    #: When the vector lookup last ran for this CVE, successful or not. Without
    #: it a CVE NVD has no record of would be retried on every sweep forever.
    vector_checked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: NVD's CVSS v4.0 base vector (TheHub #60824). Stored and shown, never
    #: rescored: the environmental formula here is v3's (D1). Null when NVD
    #: published none. Longer than the v3 column because v4 vectors are.
    cvss_v4_vector: Mapped[str | None] = mapped_column(String(255), default=None)
    #: The base score NVD published beside the v4.0 vector. Copied rather than
    #: computed -- v4 scoring is not implemented here -- so it is shown as
    #: NVD's figure, never as this platform's.
    cvss_v4_base_score: Mapped[float | None] = mapped_column(Float, default=None)
    #: When a lookup that reads v4.0 last ran. Null on every row stamped by the
    #: v3-only lookup, which may have dropped a v4 vector: those are eligible
    #: for exactly one more lookup, then a miss is a miss.
    v4_checked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class GroomedStory(Base):
    """The i2i process's record of what it opened (spec 17 §7.2).

    Operational, not lake: this is what makes "grooming the same finding
    twice updates the issue" possible at all — without a stored pointer from
    the derived story id to a GitHub issue number, a second groom would have
    no way to find the first issue and would open a duplicate. `id` is
    `triage_story.story_id()`, so this table's primary key *is* the lookup.
    """

    __tablename__ = "groomed_stories"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)
    subject_type: Mapped[str] = mapped_column(String(16))  # finding | combination
    subject_id: Mapped[str] = mapped_column(String(255))
    github_issue_number: Mapped[int] = mapped_column(Integer)
    github_issue_url: Mapped[str] = mapped_column(String(512))
    dev_ready: Mapped[bool] = mapped_column(Boolean)
    #: The finding disposition this issue has already been told about
    #: (`groom.sync_story_dispositions`, #432). Null until the finding leaves
    #: `open`, and reset to null by a re-groom.
    #:
    #: Recorded rather than inferred from the issue's state because an
    #: `accepted_risk` issue is deliberately left open — so "the issue is
    #: still open" cannot distinguish an acceptance nobody has commented on
    #: from one commented on every night since. What must not repeat is the
    #: statement, so the statement is what gets stored.
    synced_disposition: Mapped[str | None] = mapped_column(String(32), default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class AuditLogEntry(Base):
    """Append-only actor log (spec 12 §7).

    Deliberately separate from the operational tables it describes, and with
    no update or delete path anywhere in the codebase: corrections are a new
    entry, never an edit to history.
    """

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(64))
    entity_id: Mapped[str] = mapped_column(String(255), index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    #: human | agent | automation | unattributed (spec 34 §1). Empty on entries
    #: written before the column existed: those were never attributed, and
    #: backfilling a guess would be the audit log inventing history.
    actor_kind: Mapped[str] = mapped_column(String(16), default="")
    #: For an agent: family, instance, lineage and on_behalf_of at the moment
    #: of the action, copied rather than joined so a revoked or expired
    #: credential cannot change what the log says happened.
    actor_provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    def __repr__(self) -> str:
        return (
            f"<AuditLogEntry {self.created_at.isoformat()} {self.actor} "
            f"{self.action} {self.entity_type}:{self.entity_id} "
            f"{json.dumps(self.detail, default=str)}>"
        )


class TriageState(Base):
    """Who is working on a finding, and what they have put off (spec 27 §3).

    **Operational, not lake, and the distinction is the design.** Every other
    observation in this platform is append-only in the lake because its history
    is evidence. A claim is not evidence about a finding — it is a fact about
    who is working on it this week, it changes many times a day, and the lake's
    compaction and partitioning model is built for scan results (spec 05 §2).
    The same reasoning `RiskProfile` and `ReachabilityReport` already follow.

    **A snooze is not a disposition, and must never become one.** It hides a
    row from the default queue until its date; it does not touch
    `Finding.status`. A snoozed finding is still open, still scores in Oracle,
    still goes overdue if it goes overdue (spec 24 §2). `accepted_risk` is a
    decision about the vulnerability; this is a decision about the week, and
    collapsing the two would let "not now" quietly become "not ever" — which
    is precisely the state spec 24 §3 exists to stop acceptances drifting into.

    One row per finding, created on first claim or snooze. Absence means
    nobody has touched it, which is the common case and costs nothing to
    store.
    """

    __tablename__ = "triage_state"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    #: Denormalised from the finding so the queue can scope without a lake
    #: read, and so a repository being offboarded can purge its rows.
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)

    #: A handle, matching `Finding.owner`'s vocabulary. Null once released or
    #: expired — the row stays, because a snooze may still be live on it.
    claimed_by: Mapped[str | None] = mapped_column(String(255), default=None)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: When an unreleased claim lapses. Visible in the UI as it approaches
    #: rather than released silently: an abandoned claim that vanishes without
    #: a trace is indistinguishable from work nobody ever started.
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    #: A date, not a timestamp. "Come back to this on Tuesday" is the actual
    #: intent, and an hour-precise snooze invites arguments about timezones
    #: that nobody wants to have about a queue.
    snoozed_until: Mapped[date | None] = mapped_column(Date, default=None)
    #: Required when snoozing. A row that reappears with no reason recorded is
    #: one whose deferral nobody can review, which is the failure mode spec 11
    #: §4 keeps naming.
    snooze_reason: Mapped[str | None] = mapped_column(Text, default=None)
    #: When the current snooze was set. A snooze breaks when its finding joins
    #: CISA KEV *after* this (spec 27 §3, #728): one set knowingly on an
    #: already-listed finding is a decision, and waking it daily overrides it.
    snoozed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<TriageState {self.finding_id[:12]} claimed_by={self.claimed_by} "
            f"snoozed_until={self.snoozed_until}>"
        )


class VexStatement(Base):
    """A vendor's or a VEX document's word that a product is not affected
    (TheHub #60888, D-169).

    Recorded by a person, with its source, and only then evidence: the
    `vex_not_affected` auto-triage lane reads `not_affected` statements and
    nothing else, and never infers one. A statement names an advisory and a
    package; a version or repository narrows it, and absent they mean every
    version and every repository - which is how vendors write them.

    Revoked rather than deleted, so an action that cited a statement can
    still show what it cited.
    """

    __tablename__ = "vex_statements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    #: The advisory as findings carry it: a CVE id, or the rule id for an
    #: advisory with none.
    vulnerability_id: Mapped[str] = mapped_column(String(128), index=True)
    package_name: Mapped[str] = mapped_column(String(255))
    package_version: Mapped[str | None] = mapped_column(String(128), default=None)
    repo_full_name: Mapped[str | None] = mapped_column(String(255), default=None)
    #: OpenVEX's four: not_affected | affected | fixed | under_investigation.
    #: Only `not_affected` is acted on; the others are kept because a vendor
    #: saying `affected` is worth knowing too.
    status: Mapped[str] = mapped_column(String(32), default="not_affected")
    #: OpenVEX's justification for `not_affected`.
    justification: Mapped[str] = mapped_column(String(64), default="")
    impact_statement: Mapped[str] = mapped_column(Text, default="")
    #: vendor | vex: an advisory page, or a VEX document.
    source_kind: Mapped[str] = mapped_column(String(16), default="vendor")
    #: Where it was said: a URL or a document reference. Required - a
    #: statement nobody can go and read is not evidence.
    source: Mapped[str] = mapped_column(String(1000))
    recorded_by: Mapped[str] = mapped_column(String(255), default="")
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    revoked_by: Mapped[str | None] = mapped_column(String(255), default=None)


class AutoTriageAction(Base):
    """One thing the platform closed by itself, and how to put it back
    (TheHub #60888, D-169).

    `prior_state` is the finding's status, `resolved_at`, `accepted_until`
    and `accepted_reason_code` as the action found them; an undo writes them
    back exactly. `evidence` names the record the rule rested on - a
    remediation event, a VEX statement, a precedent finding, a reachability
    report - by id.

    Never deleted. An undone action stays, with who undid it and why, and it
    stops its rule ever being applied to that finding again.
    """

    __tablename__ = "auto_triage_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    capability: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="")
    #: exact_duplicate | vex_not_affected | fix_verified | unreachable
    rule: Mapped[str] = mapped_column(String(32), index=True)
    new_status: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    summary: Mapped[str] = mapped_column(Text, default="")
    prior_state: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    undone_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    undone_by: Mapped[str | None] = mapped_column(String(255), default=None)
    undo_reason: Mapped[str | None] = mapped_column(Text, default=None)


class PublicEndpoint(Base):
    """A URL the operator says is reachable from the internet (mykronos.exposure).

    Declared, then observed: the row is the operator's claim that this URL is
    public; `observations` is what an anonymous GET actually got back the last
    time the exposure job asked.
    """

    __tablename__ = "public_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    url: Mapped[str] = mapped_column(String(512), unique=True, index=True, default="")
    repo_full_name: Mapped[str] = mapped_column(String(255), default="", index=True)
    label: Mapped[str] = mapped_column(String(255), default="")
    declared_by: Mapped[str] = mapped_column(String(255), default="")
    declared_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_status: Mapped[str] = mapped_column(String(32), default="not_probed")
    last_probed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    last_detail: Mapped[str] = mapped_column(Text, default="")
    observations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    #: The `RepoSurface` (usually an entry point) this URL is the public face
    #: of (TheHub #60825). Nullable and not a database foreign key, for the
    #: reason `RepoControl.applies_to_surface_id` gives: a surface withdrawn
    #: while an endpoint still points at it nulls the link
    #: (`surfaces.remove`) rather than refusing the withdrawal.
    surface_id: Mapped[str | None] = mapped_column(String(36), default=None)


class RepoSurface(Base):
    """An asset, an entry point, or a trust boundary this repository has
    (B-029).

    **The three quarters of a threat model the platform did not hold.**
    `RepoControl`'s own docstring says a threat model is made of assets, entry
    points, trust boundaries and mitigations, and that the tab had one of the
    four. It has had mitigations since spec 28 §3. This is the other three.

    Why it matters is the same argument that produced controls, one step
    earlier: a tab built only from findings can say what was found and never
    what is *at stake*. "Twelve mediums in the payments service" and "twelve
    mediums in the internal changelog renderer" are the same row today, and
    they are not the same risk.

    **Declared, never verified, and the wording never blurs the two.** The same
    rule `RepoControl` follows. A row here is a person asserting something,
    which is weaker and clearer than a machine implying it, and it is useful
    the day somebody types it. Nothing in this platform can currently confirm
    that a database holds customer records; pretending otherwise would make
    the tab confidently wrong about the thing it exists to be right about.

    Operational rather than lake, for the reason `RepoControl` gives: this is
    an editable statement about the present, corrected in place when it turns
    out to be wrong, not an append-only observation whose history is evidence.
    """

    __tablename__ = "repo_surfaces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    #: Denormalised for the same two reasons as `RepoControl.repo_full_name`.
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)
    #: asset | entry_point | trust_boundary. One row is one of them: a thing
    #: that is both an asset and an entry point is two facts about the same
    #: subsystem, and declaring it twice is honest and separately reviewable —
    #: the same argument `RepoControl.stride` makes for not taking a list.
    kind: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    #: How exposed this is: internet | internal | local | unknown. `unknown` is
    #: the default and is a real answer — a platform that guessed "internal"
    #: would be understating risk by default, which is the wrong direction to
    #: be wrong in.
    exposure: Mapped[str] = mapped_column(String(32), default="unknown")
    #: What is at stake: pii | financial | credentials | source | public |
    #: unknown. Only meaningful for an asset, and empty elsewhere rather than
    #: defaulted to something that reads as a claim.
    sensitivity: Mapped[str] = mapped_column(String(32), default="unknown")
    #: A route, a file, an ADR, a diagram. Optional for the reason
    #: `RepoControl.evidence_ref` is: requiring it means the register only ever
    #: holds what somebody had time to document.
    evidence_ref: Mapped[str] = mapped_column(String(512), default="")
    #: What a finding has to look like to be *in* this surface (TheHub
    #: #60825): `{"paths": [...], "images": [...], "addresses": [...],
    #: "hostnames": [...]}`, validated and normalised by
    #: `surface_match.normalize_selectors`. Empty matches nothing, which is
    #: the honest default: a surface nobody has located is not a surface every
    #: finding is in.
    selectors: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: CVSS 3.1 Security Requirements, per asset: H | M | L, or null for "not
    #: overridden" (the environmental resolver then derives one from
    #: sensitivity or the repository's RiskProfile). Only an asset carries
    #: them; a requirement on a way in is not a property anybody can act on.
    cr: Mapped[str | None] = mapped_column(String(1), default=None)
    ir: Mapped[str | None] = mapped_column(String(1), default=None)
    ar: Mapped[str | None] = mapped_column(String(1), default=None)
    #: The `id` this row has in `.sdlc/threat-model.yaml`, when the manifest
    #: declared it (`declared_by == "manifest"`). The sync's upsert key, and
    #: null for a row declared through the API.
    manifest_key: Mapped[str | None] = mapped_column(String(128), default=None)
    declared_by: Mapped[str] = mapped_column(String(255), default="")
    declared_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )


class RepoControl(Base):
    """A mitigation somebody declared for this repository (spec 28 §3).

    **A threat model is made of four things and this platform had one.**
    Assets, entry points, trust boundaries, mitigations. The Threat Model tab
    had findings, grouped six ways: it could say what was found and not what
    stops it. As scanning improves that tab can only ever grow more red, and a
    team that spends a quarter adding controls sees no change at all. This is
    the row that changes it.

    **Operational, not lake, and for the reason `TriageState` gives.** Every
    observation in the lake is append-only because its history is evidence —
    you have to be able to say what a finding looked like in March. A declared
    control is not an observation: it is an editable statement about the
    present, corrected in place when it turns out to be wrong, and the lake's
    compaction and partitioning model is built for scan results (spec 05 §2).
    Spec 28 §3.2 named a lake table; that was written before the distinction
    `RiskProfile`, `ReachabilityReport` and `TriageState` all already follow,
    and D-089 records the deviation rather than leaving the spec and the code
    disagreeing.

    **A declared control says "a person asserted this", which is a weaker and
    clearer claim than a machine implying it.** Admin-authored first,
    discovered later: spec 23 §2's entry-point inventory is what eventually
    populates this from the codebase, and a register that waits for it stays
    unbuilt for a year. `verified_by_capability` is where it stops being a
    wiki — a control claiming `authentication` on a route DAST reports as
    unauthenticated is a contradiction the platform can detect, and the tab
    renders it as one rather than resolving it.
    """

    __tablename__ = "repo_controls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    #: Denormalised rather than a foreign key to `repo_onboardings`, so the
    #: threat-model query can scope without a join and an offboarded
    #: repository's rows can be purged by name — the same call `TriageState`
    #: makes, for the same two reasons.
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True)
    #: Which STRIDE category this mitigates. One, not a list: a control that
    #: claims to mitigate four categories is a description of a subsystem
    #: rather than a control, and declaring it four times is both honest and
    #: individually verifiable.
    stride: Mapped[str] = mapped_column(String(32), index=True)
    #: One of `controls.CONTROL_KINDS`.
    kind: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text, default="")
    #: A file path, a route, a policy document, a test id. Optional on
    #: purpose: refusing a control without one would mean the register only
    #: ever holds the controls somebody had time to document, and the tab
    #: renders an evidence-free control as the weaker claim it is.
    evidence_ref: Mapped[str] = mapped_column(String(512), default="")
    #: The capability that could contradict this control if it found something
    #: — `dast` for an authentication claim, `secrets` for a secrets-management
    #: one. Empty means nothing in the platform can check it, which the tab
    #: says rather than implying the control is verified.
    verified_by_capability: Mapped[str] = mapped_column(String(32), default="")
    #: The surface this control guards, when it guards one rather than the
    #: whole repository (TheHub #60825) — a perimeter gate in front of one
    #: entry point, not every port the repository has. Nullable and not a
    #: database foreign key: withdrawing the surface nulls this
    #: (`surfaces.remove`), so the control falls back to repository scope
    #: rather than blocking the withdrawal or vanishing with it.
    applies_to_surface_id: Mapped[str | None] = mapped_column(String(36), default=None)
    #: The control's `id` in `.sdlc/threat-model.yaml`, for a manifest row.
    manifest_key: Mapped[str | None] = mapped_column(String(128), default=None)
    #: When a person last confirmed this is still true. A mitigation nobody has
    #: checked since last year is a belief, and the tab should say which of the
    #: two it is showing.
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    declared_by: Mapped[str] = mapped_column(String(255), default="")
    declared_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RepoControl {self.repo_full_name} {self.stride}/{self.kind}>"


class ScoringContext(Base):
    """Everything known about one repository that a score could rest on,
    at one moment (TheHub #60827).

    **Append-only.** A new row only when the resolved facts change, so the
    table is the history of what the platform believed about this repository's
    environment: "the gate was observed answering 401" appearing, then lapsing
    fifteen days later, is two rows and the dates between them. An
    `EnvironmentalScore` names the context it was computed in, so a score can
    always be traced to the exact facts behind it, even after they changed.

    `context_id` is a hash of the resolved facts and the repository, and is
    the skip rule: a rescore that resolves the same facts writes nothing.
    Not unique on its own: facts can lapse and come back, and the second time
    is a second row.
    """

    __tablename__ = "scoring_contexts"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    context_id: Mapped[str] = mapped_column(String(64), index=True, default="")
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    #: The resolved facts as `environment.Fact` dicts, applied or not.
    facts_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class EnvironmentalScore(Base):
    """This finding's CVSS score re-read for its environment, as last computed
    (TheHub #60827).

    **Current value, not history.** One row per finding, overwritten by each
    rescore; the history of *why* lives in `ScoringContext`. Operational, not
    a lake column, for the reason `TriageState` is: it is derived from
    operational facts that change without any scan running, and rewriting
    Parquet partitions every time a gate observation lapsed would be the
    wrong storage for it.

    Absent is a real state: the finding has no vector (no CVE, or NVD never
    scored it), or no rescore has reached it yet. `_severity_here` then
    computes on read.
    """

    __tablename__ = "environmental_scores"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    vector: Mapped[str] = mapped_column(String(256), default="")
    #: `3.1` or `3.0`: the CVSS version the vector states.
    vector_version: Mapped[str] = mapped_column(String(8), default="")
    #: nvd | advisory | analyst.
    vector_source: Mapped[str] = mapped_column(String(16), default="")
    #: For `analyst`: the confirmed `RuleVector` the vector came from, so the
    #: score traces to who confirmed it, when, and from which template
    #: (TheHub #60832). Empty for a published vector.
    vector_ref: Mapped[str] = mapped_column(String(36), default="")
    base: Mapped[float] = mapped_column(Float, default=0.0)
    environmental: Mapped[float] = mapped_column(Float, default=0.0)
    #: none | low | medium | high | critical (CVSS 3.1 qualitative bands).
    base_band: Mapped[str] = mapped_column(String(16), default="")
    env_band: Mapped[str] = mapped_column(String(16), default="")
    #: The scanner's own severity word, as last scored. Kept so a re-ingest
    #: that changes it is noticed by the skip rule.
    scanner_severity: Mapped[str] = mapped_column(String(16), default="")
    #: The scanner's severity shifted by (env_band - base_band), clamped to
    #: low..critical.
    effective_severity: Mapped[str] = mapped_column(String(16), default="")
    #: This finding's facts, applied or not, each with its reason.
    facts_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    context_id: Mapped[str] = mapped_column(String(64), default="")
    computed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RuleVector(Base):
    """A CVSS 3.1 base vector a person recorded for one scanner rule
    (TheHub #60832, decision D3 of epic #60822).

    SAST, DAST and secrets findings name a rule, not a CVE, so nothing
    publishes a vector for them and D-106 left them unscored rather than
    invent one from a severity word. This row is the way out D3 chose: an
    analyst-asserted vector for (repository or estate, capability, tool,
    rule), pre-filled from a reviewed CWE-class template
    (`cwe-vector-templates-v1.yaml`).

    **Nothing applies until a person confirms it.** `proposed` and `retired`
    rows are read by nobody that scores; `environment.choose_vectors` reads
    only `confirmed`, and only after every published vector (NVD, advisory,
    v4.0) has been passed over. Confirming needs an authenticated human
    principal, never an agent or automation one, and is audited.

    Operational rather than lake, for the reason `RepoControl` is: an editable
    statement about the present, corrected in place, with the audit log as its
    history. At most one `proposed` and one `confirmed` row per key: a
    proposal can sit beside the vector in force as a suggested change, and
    confirming it retires the one it replaces.
    """

    __tablename__ = "rule_vectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    #: Null for an estate-wide vector, which applies to every repository that
    #: has no confirmed vector of its own for the rule.
    repo_full_name: Mapped[str | None] = mapped_column(String(255), index=True, default=None)
    capability: Mapped[str] = mapped_column(String(32), default="")
    #: The scan run's `tool_name`: the same rule id means different things in
    #: different tools.
    tool: Mapped[str] = mapped_column(String(64), default="")
    rule_id: Mapped[str] = mapped_column(String(512), index=True, default="")
    #: CVSS 3.1, the eight base metrics only, in canonical order.
    vector: Mapped[str] = mapped_column(String(256), default="")
    #: proposed | confirmed | retired.
    status: Mapped[str] = mapped_column(String(16), index=True, default="proposed")
    #: Always `analyst`: kept so a stored score's provenance reads the same
    #: word as `EnvironmentalScore.vector_source`.
    vector_source: Mapped[str] = mapped_column(String(16), default="analyst")
    #: The template the proposal was pre-filled from, e.g.
    #: `cwe-vector-templates-v1:CWE-79`; empty when typed by hand.
    proposed_from: Mapped[str] = mapped_column(String(128), default="")
    asserted_by: Mapped[str] = mapped_column(String(255), default="")
    asserted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    confirmed_by: Mapped[str | None] = mapped_column(String(255), default=None)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    retired_by: Mapped[str | None] = mapped_column(String(255), default=None)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    note: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )


class NetassessRun(Base):
    """The last network-assessment run this platform accepted (spec 32 §4.4).

    **One row, superseded outright by the next run**, like `RepoGovernance` and
    for the same reason: what matters is the current inventory and when it
    arrived, not a time series. The zip archive in MinIO is the history, and it
    is written by the publisher rather than by this platform.

    **`inventory_csv` is kept because the next run needs something to diff
    against.** The Concourse task fetched the previous archive from MinIO to
    get it, which is the one thing that made the job need an object store at
    all; keeping the inventory here is what lets the judgement run without one.
    It is a few dozen rows of MAC, address and label for hosts on a home LAN.

    Operational rather than lake: a host inventory is configuration this
    platform reads, not a finding it produced. Nothing here reaches a risk
    score, exactly as spec 14 §5 requires — a network finding carries an asset,
    and this is not a finding.
    """

    __tablename__ = "netassess_runs"

    #: `personal-soc`, or whichever repository owns the scan. Scoped by
    #: repository rather than global because nothing else in this schema is
    #: global, and a second network under a second repository should not need
    #: a migration.
    repo_full_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: `netassess-2026.8.9.zip` — the publisher's key, kept verbatim so a
    #: person can find the archive this row was derived from.
    run_key: Mapped[str] = mapped_column(String(255), default="")
    #: The scan's own date, parsed from the key. Distinct from `received_at`:
    #: a run published late is stale by the first and fresh by the second, and
    #: the freshness check is about the scan rather than the upload.
    run_date: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    inventory_csv: Mapped[str] = mapped_column(Text, default="")
    #: Whether the run was believable. A run that failed verification is still
    #: recorded — "the last scan was bad" is the fact the freshness check needs,
    #: and discarding it would make a degraded scanner look like a silent one.
    believable: Mapped[bool] = mapped_column(Boolean, default=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<NetassessRun {self.repo_full_name} {self.run_key}>"


class ControlObservation(Base):
    """One machine-collected fact about whether a control holds (TheHub #60826).

    **Observed, not declared.** `RepoSurface` and `RepoControl` are a person's
    claims; a row here is what a collector saw from a named vantage point at a
    named time: "anonymous GETs to mykronos-app.toddbenson.net answered 401",
    "docker publishes 0.0.0.0:8002", "cloudflared routes demo.toddbenson.net to
    localhost:8002". It is the evidence the environmental CVSS resolver (S5) is
    allowed to lower a score on, and the evidence that can contradict a
    declaration (`surfaces.CONTRADICTED_BY`).

    **Append-only.** Unlike the declarations, the history is the evidence: a
    port published last week and gone today is two rows, and "latest per
    (subject, assertion)" is a read, not an overwrite.

    `state` uses `host_controls`' five states, and only `pass` / `fail` are
    evidence. `pass` means *the assertion is true* - `port_published` passing
    means the port IS published - not that the result is good.
    """

    __tablename__ = "control_observations"
    __table_args__ = (
        Index(
            "ix_control_observations_latest",
            "repo_full_name",
            "subject",
            "assertion",
            "collected_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    #: From the ingestion token (spec 05 §4) or the exposure endpoint's
    #: registration - never from the payload.
    repo_full_name: Mapped[str] = mapped_column(String(255), default="", index=True)
    #: `surface:<id>` | `control:<id>` | `host:port` | `hostname`.
    subject: Mapped[str] = mapped_column(String(512), default="")
    #: Set when the subject names a declared surface or control directly, or
    #: when a surface's `selectors` cover the subject (`control_observations.
    #: record`). Null when nothing does.
    surface_id: Mapped[str | None] = mapped_column(String(36), default=None, index=True)
    control_id: Mapped[str | None] = mapped_column(String(36), default=None, index=True)
    #: control_observations.ASSERTIONS - a closed vocabulary.
    assertion: Mapped[str] = mapped_column(String(32), default="")
    #: pass | fail | unknown | not_evidence | not_measured (host_controls).
    state: Mapped[str] = mapped_column(String(16), default="unknown")
    #: internet | lan | host - where the collector stood.
    vantage: Mapped[str] = mapped_column(String(16), default="")
    tool: Mapped[str] = mapped_column(String(64), default="")
    tool_version: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    #: An `/api/ingest/raw` reference, or another pointer to what the tool said.
    raw_ref: Mapped[str] = mapped_column(String(512), default="")
    #: Who collected it: `job:exposure`, `Publish-ControlObservations.ps1@HOST`.
    collector: Mapped[str] = mapped_column(String(255), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    #: Structured extras a matcher needs: the service a tunnel routes to, the
    #: container behind a binding.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ControlObservation {self.subject} {self.assertion}={self.state}>"


class RepoGovernance(Base):
    """The last read of this repository's change controls (spec 30 §1.2).

    **Operational, not lake, and current state rather than history.** This is
    configuration: branch protection either requires two reviews right now or
    it does not, and a time series of a setting is not evidence of anything the
    way a scan result is. The same call `ReachabilityReport` makes, one row per
    repository, superseded outright by the next read.

    **Stored at all only because Oracle cannot make an HTTP call.** The panel
    reads GitHub live — a setting somebody changed in the UI ten seconds ago
    must not still be reported as it was — and this row is the copy the risk
    engine reads when it scores. `read_at` is therefore load-bearing rather
    than decorative: a score resting on a six-week-old reading of a setting is
    exactly the failure this platform keeps refusing to ship, so the term goes
    `available: False` once the reading is stale.

    Not a `RiskProfile` column, though spec 30 §4 puts governance "into the
    profile". A profile is admin-authored — every field of it is somebody's
    stated belief about what the application is — and a machine-read setting
    sitting in the same row would be indistinguishable from one, which is
    exactly the distinction spec 21 §1 built that table around.
    """

    __tablename__ = "repo_governance"

    repo_full_name: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: 0-100, or null where too little could be read to say. Null is not zero:
    #: a repository whose settings the App may not read has no posture, not a
    #: bad one.
    governance_score: Mapped[int | None] = mapped_column(Integer, default=None)
    #: `branch_protection` | `ruleset` | `both` | `none`.
    source: Mapped[str] = mapped_column(String(32), default="none")
    #: How many of the nine controls the read actually resolved. A score of 80
    #: over two controls is not the same claim as 80 over nine.
    controls_read: Mapped[int] = mapped_column(Integer, default=0)
    #: The per-control states as last read, keyed by control key. Still current
    #: state and still not a time series — it is the same reading the columns
    #: above summarise, kept in full so the *next* read can tell what changed.
    #: A score dropping from 80 to 60 says something moved; this says which
    #: control, which is the difference between a number and an action.
    control_states: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    read_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RepoGovernance {self.repo_full_name} score={self.governance_score}>"


class JobRun(Base):
    """Whether the platform's own scheduled work is still running.

    **The platform tells four repositories what is wrong with them and had no
    record of whether it was itself working.** `_every` catches every failure,
    logs it, and retries on the next tick — which is the right behaviour and
    means a job that has thrown on every run for a fortnight looks exactly like
    one that has never had a problem. The evidence was one line in a log file
    nobody tails.

    That matters most for the jobs whose silence is invisible. If
    `reconcile-absences` stops, findings never close and every count on every
    page slowly becomes wrong in the safe-looking direction. If `acceptances`
    stops, an acceptance past its review date stays accepted. Neither raises
    anything anywhere.

    One row per job, current state rather than history — the same rule
    `RepoGovernance` follows, and for the same reason. What matters is whether
    it is running now and when it last actually worked, not a log of every
    tick.

    `last_succeeded_at` is separate from `last_run_at` on purpose: a job that
    runs every six hours and fails every time has a recent `last_run_at`, and
    reading only that would report a dead job as healthy.
    """

    __tablename__ = "job_runs"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: The last time it finished without raising. A job whose failures are
    #: caught and retried has a fresh `last_run_at` for ever.
    last_succeeded_at: Mapped[datetime | None] = mapped_column(DateTime, default=None)
    #: Since the last success. One failure is a bad day; twenty is a job that
    #: is not going to fix itself.
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    #: Scrubbed, and only the most recent. The full history is in the log; this
    #: is here so a surface can say what went wrong without asking anyone to
    #: open one.
    last_error: Mapped[str] = mapped_column(Text, default="")
    #: How often it is meant to run, so a reader can tell a job that is late
    #: from one that simply has a long interval.
    interval_seconds: Mapped[int] = mapped_column(Integer, default=0)
    #: Whether this deployment schedules the job at all. Written at start-up.
    #: A row outlives its job: `routing` was switched off on purpose and its
    #: last success, nine days old, read as "late" on every briefing - an
    #: alarm about a decision, which is how alarms stop being read.
    scheduled: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Why the latest due run did nothing, when it was skipped rather than run
    #: (`jobs.JobSkipped`): the briefing DM with no Slack configured for it
    #: (TheHub #60864). Empty after any run that was not skipped. Its own
    #: column because a skip is neither of the other two outcomes: nothing
    #: failed, and nothing was done.
    skipped_reason: Mapped[str] = mapped_column(Text, default="")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<JobRun {self.name} failures={self.consecutive_failures}>"


class ControlDrift(Base):
    """One control changing state, recorded when it happens (spec 30).

    **A transition is not a time series, which is why this exists alongside
    `RepoGovernance` rather than replacing its single row.** That row is
    right: storing every reading of a setting would be noise, and the current
    state is what scores. But a control that was enforced on Monday and is not
    on Thursday is an *event* — somebody did that — and the platform read both
    states and told nobody.

    That is the gap this closes. Governance is read live on every panel render,
    so the console has always shown the truth; nothing compared today's truth
    to yesterday's. A repository could quietly drop its review requirement and
    the only trace would be a score nobody was watching.

    **Recorded on the sweep, not on the render.** Detection that depends on
    somebody opening a page is not monitoring. The scheduled sweep reads every
    onboarded repository whether or not anyone is looking, which is the whole
    difference between a dashboard and a control.
    """

    __tablename__ = "control_drift"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    # Every required column here carries a default it will never actually
    # write: the constructor always supplies one. They are declared because
    # `add_missing_columns` has to be able to add any of them to a table that
    # already has rows, and a column with no default has no value for those —
    # which a drift guard in the schema tests checks rather than trusts.
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    control_key: Mapped[str] = mapped_column(String(64), default="")
    #: `on` | `off` | `partial` — three of the control's four states, never
    #: `unknown`. A transition crossing `unknown` is a read that failed or a
    #: read that recovered, not a control that moved, and the two must never be
    #: conflated: one is a permissions problem and the other is a security
    #: regression. No such row is written since #264; rows written before it
    #: are filtered out by `governance.recent_drift`. The column default stays
    #: `unknown` because `add_missing_columns` needs one and no constructor
    #: ever uses it.
    from_state: Mapped[str] = mapped_column(String(16), default="unknown")
    to_state: Mapped[str] = mapped_column(String(16), default="unknown")
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<ControlDrift {self.repo_full_name} {self.control_key} "
            f"{self.from_state}->{self.to_state}>"
        )


class CiCheckRun(Base):
    """The check run a CI pipeline's verdict on one commit is shown as (D-136).

    One row per (repository, commit, check name), so every report about a
    commit updates the same GitHub check run instead of adding another. An
    editable statement about the present, which is why it is operational
    rather than in the append-only lake; its history is in the audit log.
    """

    __tablename__ = "ci_check_runs"
    __table_args__ = (
        UniqueConstraint("repo_full_name", "head_sha", "name", name="uq_ci_check_run"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    repo_full_name: Mapped[str] = mapped_column(String(255), index=True, default="")
    head_sha: Mapped[str] = mapped_column(String(40), default="")
    name: Mapped[str] = mapped_column(String(100), default="")
    #: GitHub's id for the check run.
    external_id: Mapped[str] = mapped_column(String(64), default="")
    #: in_progress | completed
    status: Mapped[str] = mapped_column(String(16), default="")
    #: success | failure, or None while in progress.
    conclusion: Mapped[str | None] = mapped_column(String(16), default=None)
    #: The job whose report last changed it.
    last_job: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
