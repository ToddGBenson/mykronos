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
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import FindingStatus, utcnow


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


def _open_finding_ids(catalog: Catalog, repo_full_name: str, capabilities: set[str],
                      status: str) -> list[str]:
    if not capabilities or not catalog.all_files("findings"):
        return []
    placeholders = ", ".join(["?"] * len(capabilities))
    rows = catalog.query(
        f"SELECT finding_id FROM findings WHERE repo_full_name = ? "
        f"AND capability IN ({placeholders}) AND status = ?",
        [repo_full_name, *sorted(capabilities), status],
    )
    return [str(row[0]) for row in rows]


def _open_ids_by_tool(
    catalog: Catalog,
    repo_full_name: str,
    capability: str,
    tools: set[str],
    status: str,
) -> list[str]:
    """Open findings of one capability that a named tool last observed.

    The tool is not on the finding — it is a property of the observation, so
    it comes through `last_seen_scan_run_id` exactly as absence reconciliation
    reads it. `asset_id` rather than `repo_full_name`, which spec 14 §5 keeps
    only for one migration step.

    A finding whose last scan run has been compacted away joins nothing and is
    left alone, which is the safe direction: it stays `open` rather than being
    stranded on the strength of a row nobody can read.
    """
    if not tools or not catalog.all_files("findings"):
        return []
    placeholders = ", ".join(["?"] * len(tools))
    rows = catalog.query(
        f"""
        SELECT f.finding_id
        FROM findings f
        JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id
        WHERE f.asset_id = ?
          AND f.capability = ?
          AND f.status = ?
          AND coalesce(s.tool_name, '') IN ({placeholders})
        """,
        [repo_full_name, capability, status, *sorted(tools)],
    )
    return [str(row[0]) for row in rows]


def strand_tool_findings(
    catalog: Catalog, repo_full_name: str, capability: str, tools: set[str]
) -> int:
    """Record what dropping an analyser did to the findings only it could see.

    B-047 one level down. Removing a *capability* strands its findings because
    closure needs two consecutive successful scans that no longer observe the
    finding, and a capability that cannot upload will never produce one.
    Removing a *tool* from a capability that still runs is the same dead end:
    ShellCheck's findings need ShellCheck's silence, and CodeQL's silence
    about a shell script has never been evidence of anything.

    Before absence reconciliation read `tool_name` those findings closed on
    the other tool's silence — tidily, and wrongly. They now stay open with no
    exit, which is honest and useless on its own. This makes the removal say
    what it did.

    `restore_stranded_tool` puts them back the moment the analyser is added
    again, because nothing about the finding changed; only whether anything
    was still looking.

    Returns how many were stranded.
    """
    ids = _open_ids_by_tool(
        catalog, repo_full_name, capability, tools, FindingStatus.OPEN.value
    )
    if not ids:
        return 0
    outcome = update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = ?, resolved_at = ?",
        [FindingStatus.STRANDED.value, utcnow()],
        only_if_status=FindingStatus.OPEN.value,
    )
    return outcome.count


def restore_stranded_tool(
    catalog: Catalog, repo_full_name: str, capability: str, tools: set[str]
) -> int:
    """Put back what adding the analyser again made decidable.

    The mirror of `strand_tool_findings`, and it must exist for the same
    reason `restore_stranded` does: a repository that turns an analyser off
    and on again would otherwise accumulate a permanent shadow of findings
    nothing will ever look at, and the platform would be quieter for it while
    being no safer.
    """
    ids = _open_ids_by_tool(
        catalog, repo_full_name, capability, tools, FindingStatus.STRANDED.value
    )
    if not ids:
        return 0
    outcome = update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = ?, resolved_at = NULL",
        [FindingStatus.OPEN.value],
        only_if_status=FindingStatus.STRANDED.value,
    )
    return outcome.count


def strand_findings(catalog: Catalog, repo_full_name: str, capabilities: set[str]) -> int:
    """Record what disabling a capability did to its open findings (B-047).

    TheHub held 32 open `dast` findings with `dast` switched off, and the
    briefing reported that lane silent for fifteen days. Not one of them could
    close by any path the platform offered: closure needs two consecutive
    successful scans that no longer observe the finding, and a capability that
    cannot upload will never produce one.

    That is the closure rule working exactly as designed and arriving
    somewhere it has no exit from. The rule is right, so this does not relax
    it — it makes the removal say what it did. `stranded` is a statement
    about the pipeline, not a judgement about the risk, and `restore_stranded`
    puts them back the moment a scan can decide again.

    Returns how many were stranded.
    """
    ids = _open_finding_ids(catalog, repo_full_name, capabilities, FindingStatus.OPEN.value)
    if not ids:
        return 0
    outcome = update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = ?, resolved_at = ?",
        [FindingStatus.STRANDED.value, utcnow()],
        only_if_status=FindingStatus.OPEN.value,
    )
    return outcome.count


def restore_stranded(catalog: Catalog, repo_full_name: str, capabilities: set[str]) -> int:
    """Put stranded findings back to `open` when the grant returns.

    Without this, re-enabling a capability would leave its history in a state
    no scan can revisit — which is the same defect as stranding them, one
    step later. Back to `open` rather than to `fixed`: nothing has observed
    their absence, and the next two successful scans are what decide.

    Returns how many were restored.
    """
    ids = _open_finding_ids(catalog, repo_full_name, capabilities, FindingStatus.STRANDED.value)
    if not ids:
        return 0
    outcome = update_findings(
        catalog,
        locate_findings(catalog, ids),
        "status = ?, resolved_at = ?",
        [FindingStatus.OPEN.value, None],
        only_if_status=FindingStatus.STRANDED.value,
    )
    return outcome.count
