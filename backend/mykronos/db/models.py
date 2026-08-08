"""Operational tables — specs 02 §3, 03 §3, 05 §4, 12 §7."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
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
