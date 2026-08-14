"""Populate `asset_type` and `asset_id` on findings written before they existed.

Spec 14 §5 generalises a finding's subject from a repository to an **asset**,
so a host on a network has somewhere to live. A repository is an asset whose
`asset_id` is `owner/repo` — the same string `repo_full_name` already holds.

That identity is the whole reason this is safe to run on a live lake:
`finding_id` is derived from the subject (spec 05 §5), and the subject's
*value* is unchanged. Nothing re-identifies, nothing reopens, and mean time to
fix does not acquire a few hundred phantom resolutions — which is exactly what
a careless re-derivation in this repository did once already.

**Not written through the buffer.** Compaction's findings upsert reopens any
row whose stored status is `fixed` (spec 05 §5 — a finding that comes back is
open again), and a backfill is not a rescan. Routing 700 rows through it would
have reported every previously-fixed finding as freshly reopened, including
the 92 closed this morning. It uses `update_findings` instead, which rewrites
named columns in place and leaves status, dispositions and `first_seen_at`
untouched.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings

logger = logging.getLogger(__name__)


@dataclass
class MigrationResult:
    examined: int = 0
    migrated: int = 0
    already_done: int = 0
    #: Findings with neither an asset_id nor a repo_full_name to derive one
    #: from. Reported rather than guessed at: a finding whose subject cannot
    #: be established is not one to invent a subject for.
    unattributable: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.examined} examined, {self.migrated} migrated, "
            f"{self.already_done} already had an asset, "
            f"{len(self.unattributable)} unattributable"
        )


def migrate_assets(
    catalog: Catalog,
    *,
    dry_run: bool = False,
) -> MigrationResult:
    """Give every finding an `asset_type` and `asset_id` (spec 14 §5)."""
    result = MigrationResult()

    rows = catalog.query(
        "SELECT finding_id, repo_full_name, asset_id FROM findings"
    )

    by_repo: dict[str, list[str]] = {}
    for finding_id, repo_full_name, asset_id in rows:
        result.examined += 1
        if asset_id:
            result.already_done += 1
            continue
        if not repo_full_name:
            result.unattributable.append(str(finding_id))
            continue
        by_repo.setdefault(str(repo_full_name), []).append(str(finding_id))

    result.migrated = sum(len(ids) for ids in by_repo.values())
    if dry_run:
        return result

    for repo_full_name, finding_ids in sorted(by_repo.items()):
        # One update per repository, so the literal is a single bound
        # parameter rather than a value per row.
        update_findings(
            catalog,
            locate_findings(catalog, finding_ids),
            "asset_type = 'repo', asset_id = ?",
            [repo_full_name],
        )
        logger.info(
            "migrate_assets: %d finding(s) attributed to %s",
            len(finding_ids),
            repo_full_name,
        )

    return result
