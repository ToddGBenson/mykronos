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

    #: Capabilities whose workflow-install PR has actually merged. This is the
    #: live set; `pending_capabilities` is what has been requested but not yet
    #: merged (spec 03 §4). Keeping them apart is what makes the installer
    #: idempotent — the diff is always requested-minus-active.
    enabled_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    pending_capabilities: Mapped[list[str] | None] = mapped_column(JSON, default=None)
    pending_pr_number: Mapped[int | None] = mapped_column(Integer, default=None)

    default_branch: Mapped[str] = mapped_column(String(255), default="main")
    auto_merge_workflow_prs: Mapped[bool] = mapped_column(Boolean, default=False)

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

    #: Whether this token's plaintext actually reached the repo's Actions
    #: secret. False means the repo does not have it yet.
    #:
    #: Without this, a rotation that succeeded locally but failed to write the
    #: secret would look complete: the new token is active with a fresh
    #: 90-day clock, so it is not due for rotation, nothing retries — and the
    #: repo's CI breaks silently when the superseded token's overlap expires.
    #: The rotation job retries any active token that is not yet synced.
    secret_synced: Mapped[bool] = mapped_column(Boolean, default=False)

    label: Mapped[str] = mapped_column(String(255), default="")


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

    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<TriageState {self.finding_id[:12]} claimed_by={self.claimed_by} "
            f"snoozed_until={self.snoozed_until}>"
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
    #: authentication | authorization | input_validation | output_encoding |
    #: secrets_management | logging | rate_limiting | encryption
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
    read_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<RepoGovernance {self.repo_full_name} score={self.governance_score}>"
