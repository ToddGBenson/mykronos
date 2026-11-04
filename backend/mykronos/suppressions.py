"""In-repo scanner suppressions: recorded from a lane's raw SARIF, listed with
their expiry (TheHub #60963, decision #60815 option B).

`adapters.sarif` reads them, and keeps them out of the findings, as spec 05
s7 requires. This module keeps the record: one `ScannerSuppression` row per
silenced result, replaced whenever a newer scan run of the same tool reports
in, so the list is what the repository silences now.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Literal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from mykronos.adapters.sarif import SuppressionRecord
from mykronos.db.models import ScannerSuppression

Status = Literal["expired", "no_expiry", "active"]
#: Rows kept from one archived SARIF. The archive is size-capped already; this
#: stops one document of generated suppressions from filling the table.
MAX_PER_ARCHIVE = 5_000
STATUSES: tuple[Status, ...] = ("expired", "no_expiry", "active")


def status_of(expires_at: date | None, today: date) -> Status:
    """`expired` once the date has passed; `no_expiry` when none was given."""
    if expires_at is None:
        return "no_expiry"
    return "expired" if expires_at < today else "active"


def record(
    session: Session,
    *,
    repo_full_name: str,
    capability: str,
    scan_run_id: str,
    tools: Iterable[str],
    records: Iterable[SuppressionRecord],
    now: datetime,
) -> int:
    """Store what one archived SARIF reports. Returns the rows written.

    For each tool the document ran, rows from any *other* scan run are
    replaced: a pragma removed since then is no longer listed. Rows from this
    same scan run are kept, because one scan can archive several SARIF files
    (CodeQL writes one per language), and a file archived twice is not
    counted twice. When a row is replaced, its first-seen time carries over.
    """
    tools = sorted(set(tools))
    by_identity: dict[tuple[str, str, str, int | None], SuppressionRecord] = {}
    for item in records:
        if len(by_identity) >= MAX_PER_ARCHIVE:
            break
        by_identity.setdefault(item.identity, item)
    first_seen: dict[tuple[str, str, str, int | None], datetime] = {}
    current: dict[tuple[str, str, str, int | None], ScannerSuppression] = {}

    if tools:
        rows = session.scalars(
            select(ScannerSuppression).where(
                ScannerSuppression.repo_full_name == repo_full_name,
                ScannerSuppression.tool.in_(tools),
            )
        )
        for existing in rows:
            key = (existing.tool, existing.rule_id, existing.file_path, existing.line)
            if existing.scan_run_id == scan_run_id:
                current[key] = existing
            else:
                seen = existing.first_seen_at
                first_seen[key] = min(first_seen.get(key, seen), seen)
        session.execute(
            delete(ScannerSuppression).where(
                ScannerSuppression.repo_full_name == repo_full_name,
                ScannerSuppression.tool.in_(tools),
                ScannerSuppression.scan_run_id != scan_run_id,
            )
        )

    for key, item in by_identity.items():
        row = current.get(key)
        if row is None:
            row = ScannerSuppression(
                repo_full_name=repo_full_name,
                tool=item.tool,
                rule_id=item.rule_id,
                file_path=item.file_path,
                line=item.line,
                scan_run_id=scan_run_id,
                first_seen_at=first_seen.get(key, now),
            )
            session.add(row)
        row.capability = capability
        row.kind = item.kind
        row.justification = item.justification
        row.expires_at = item.expires_at
        row.last_seen_at = now
    return len(by_identity)


@dataclass(frozen=True)
class Listed:
    row: ScannerSuppression
    status: Status


def listing(session: Session, repo_full_name: str, today: date) -> list[Listed]:
    """Expired first, then undated, then live; within each, by file and line."""
    rows = session.scalars(
        select(ScannerSuppression).where(ScannerSuppression.repo_full_name == repo_full_name)
    )
    listed = [Listed(row, status_of(row.expires_at, today)) for row in rows]
    order = {status: index for index, status in enumerate(STATUSES)}
    listed.sort(
        key=lambda item: (
            order[item.status],
            item.row.file_path,
            item.row.line if item.row.line is not None else -1,
            item.row.rule_id,
        )
    )
    return listed
