"""The ledger and the grant table, read side by side (B-062, D-119).

Two tables answer "what may this repository report". `RepoOnboarding.
enabled_capabilities` is the installer's ledger and drives the dashboard;
`capability_grants` is what ingestion enforces. They are written by different
paths -- a merged install PR moves the ledger, `mykronos grant` moves the
table, a Concourse-scanned PATCH moves both -- and when they disagree, each
half of the platform believes a different thing about the same repository.

What that looks like from outside is B-062: on 2026-09-05 an admin sent
TheHub the six capabilities the dashboard showed, the grant table held
eleven, and five lanes lost their grants while the audit recorded
`removed: []`. The same shape sprang again two days later on binnacle.

D-119 settles which side is authoritative: **the ledger, plus whatever is
pending an install merge**. Grants are derived from it. Two consequences
live here. `drift()` reads both sides for every repository and says where
they differ. `reconcile()` widens each side to the union -- a grant with no
ledger entry is added to the ledger, a ledger entry with no grant is
granted -- and never revokes: narrowing a repository's ingestion is a
decision, made through the capabilities PATCH with `revoke_unlisted`, not a
side effect of a tidy-up.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.db.models import RepoOnboarding


@dataclass(frozen=True)
class GrantDrift:
    """One repository, both sides."""

    repo_full_name: str
    #: The ledger, plus what an open install PR will add when it merges.
    enabled: frozenset[str]
    #: What ingestion enforces today.
    granted: frozenset[str]

    @property
    def grant_only(self) -> frozenset[str]:
        """Granted, and the dashboard does not show it. The B-062 trap."""
        return self.granted - self.enabled

    @property
    def ledger_only(self) -> frozenset[str]:
        """Shown as enabled, and every upload for it is refused."""
        return self.enabled - self.granted

    @property
    def drifted(self) -> bool:
        return bool(self.grant_only or self.ledger_only)


def drift(session: Session, registry: TokenRegistry) -> list[GrantDrift]:
    """Every onboarded repository, drifted or not, in name order."""
    rows = (
        session.execute(
            select(RepoOnboarding)
            .where(RepoOnboarding.status != "removed")
            .order_by(RepoOnboarding.github_repo_full_name)
        )
        .scalars()
        .all()
    )
    out: list[GrantDrift] = []
    for row in rows:
        enabled = set(row.enabled_capabilities or []) | set(row.pending_capabilities or [])
        out.append(
            GrantDrift(
                repo_full_name=row.github_repo_full_name,
                enabled=frozenset(enabled),
                granted=frozenset(registry.granted_capabilities(row.github_repo_full_name)),
            )
        )
    return out


def reconcile(session: Session, registry: TokenRegistry) -> list[GrantDrift]:
    """Widen both sides to their union for every drifted repository.

    Returns the drift as it was *before* the change, so the caller can say
    what moved. Nothing is revoked (D-119); a capability that should stop
    reporting is a PATCH, not a reconcile.
    """
    before = [d for d in drift(session, registry) if d.drifted]
    for item in before:
        row = session.execute(
            select(RepoOnboarding).where(
                RepoOnboarding.github_repo_full_name == item.repo_full_name
            )
        ).scalar_one()
        for capability in sorted(item.ledger_only):
            registry.grant(item.repo_full_name, capability)
        if item.grant_only:
            # Into the ledger rather than into `pending`: the grant is live and
            # uploads are arriving, so the honest dashboard reading is
            # "enabled" -- and if no job produces it, the coverage cross-check
            # says `no_job`, which is also honest.
            row.enabled_capabilities = sorted(
                set(row.enabled_capabilities or []) | set(item.grant_only)
            )
    return before
