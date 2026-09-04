"""Backfilling ownership onto findings that predate it (B-034).

Ownership resolves at ingest, which means a finding written before that code
existed — or before a repository grew a CODEOWNERS file — carries whatever was
true on the day it was first seen and never revisits it. On this deployment
that was 1001 findings with a null `owner_source`: not `unresolved`, which at
least says somebody asked, but nothing at all.

**Why a re-derive rather than a migration.** The answer is not a constant. It
depends on the repository's CODEOWNERS file *now*, its risk profile *now*, and
the finding's own path — so the only correct backfill is to ask the same
function ingest asks and write what it says. A SQL UPDATE would encode today's
answer as though it had always been the answer.

**Idempotent, and honest about `manual`.** A finding somebody assigned by hand
is never overwritten: compaction already treats `owner_source = 'manual'` as
authoritative, and a backfill that ignored that would quietly undo the one kind
of ownership a human actually decided.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from mykronos.ownership import owner_for_finding

logger = logging.getLogger(__name__)

#: Never re-derived. A person said so, and that outranks anything inferred.
PROTECTED_SOURCES = frozenset({"manual"})


@dataclass
class ReownReport:
    """What changed, per repository."""

    scanned: int = 0
    changed: int = 0
    protected: int = 0
    by_source: dict[str, int] = field(default_factory=dict)
    repos: list[str] = field(default_factory=list)

    def record(self, source: str) -> None:
        self.by_source[source] = self.by_source.get(source, 0) + 1


def plan(
    catalog: Any,
    *,
    rules_by_repo: dict[str, tuple[list[Any], bool]],
    profile_owner_by_repo: dict[str, str | None],
    repo_full_name: str | None = None,
) -> tuple[list[dict[str, Any]], ReownReport]:
    """The rows whose ownership would change, and a summary.

    Pure: it reads and decides, and writes nothing. The caller applies the
    result, which is what makes `--dry-run` the same code path as the real run
    rather than a second implementation of it.
    """
    report = ReownReport()
    where = "WHERE status = 'open'"
    params: list[Any] = []
    if repo_full_name:
        where += " AND asset_id = ?"
        params.append(repo_full_name)

    rows = catalog.query(
        f"""
        SELECT finding_id, asset_id, file_path, owner, owner_source
        FROM findings {where}
        """,
        params,
    )

    changes: list[dict[str, Any]] = []
    seen_repos: set[str] = set()
    for finding_id, asset_id, file_path, owner, owner_source in rows:
        report.scanned += 1
        repo = str(asset_id)
        seen_repos.add(repo)

        if owner_source in PROTECTED_SOURCES:
            report.protected += 1
            continue

        rules, readable = rules_by_repo.get(repo, ([], True))
        new_owner, new_source = owner_for_finding(
            file_path=None if file_path is None else str(file_path),
            rules=rules,
            profile_owner=profile_owner_by_repo.get(repo),
            repo_owner=repo.split("/")[0] or None,
            codeowners_readable=readable,
        )
        if new_owner == owner and new_source == owner_source:
            continue

        report.changed += 1
        report.record(new_source)
        changes.append(
            {
                "finding_id": str(finding_id),
                "owner": new_owner,
                "owner_source": new_source,
            }
        )

    report.repos = sorted(seen_repos)
    return changes, report
