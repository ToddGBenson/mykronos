"""In-repository scanner suppressions, kept and listed (TheHub #60963).

Decision 60815, option B. A result the scanned repository silenced at the
source -- `# nosemgrep`, `# checkov:skip=`, any SARIF `suppressions` entry --
is not ingested as a finding (spec 05 §7: the author answering a result is not
the platform accepting a risk, and a rescan must not rewrite a platform
disposition). Until this module the answer was only a warning on the scan run,
so a repository could silence a check for ever and nothing listed it.

Two operations:

- `record` replaces the set for one (repository, capability, tool, branch)
  with what a clean scan reported, so a pragma the repository removed stops
  being listed;
- `listing` reads a repository's suppressions with each one's expiry state,
  and the lane-health facts for the ones whose declared expiry has passed.

Nothing here touches `findings`, and nothing here is read by scoring.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from mykronos.adapters.sarif import expired_suppression_facts, expiry_state
from mykronos.db.models import ScannerSuppression
from mykronos.schemas import SuppressionSubmission, utcnow

EXPIRY_STATES = ("expired", "no_expiry", "active")


def record(
    session: Session,
    *,
    repo_full_name: str,
    capability: str,
    tool: str,
    branch: str,
    scan_run_id: str,
    commit_sha: str,
    suppressions: Sequence[SuppressionSubmission],
) -> list[ScannerSuppression]:
    """Replace the recorded set for this tool and branch. Does not commit."""
    session.execute(
        delete(ScannerSuppression).where(
            ScannerSuppression.repo_full_name == repo_full_name,
            ScannerSuppression.capability == capability,
            ScannerSuppression.tool == tool,
            ScannerSuppression.branch == branch,
        )
    )
    now = utcnow()
    rows = [
        ScannerSuppression(
            repo_full_name=repo_full_name,
            capability=capability,
            tool=tool,
            branch=branch,
            rule_id=s.rule_id,
            file_path=s.file_path,
            line=s.line,
            justification=s.justification,
            expires_at=s.expires_at,
            kind=s.kind,
            status=s.status,
            scan_run_id=scan_run_id,
            commit_sha=commit_sha,
            recorded_at=now,
        )
        for s in suppressions
    ]
    session.add_all(rows)
    session.flush()
    return rows


@dataclass(frozen=True)
class Listing:
    rows: list[tuple[ScannerSuppression, str]]
    lane_health: list[str]
    counts: dict[str, int]


def listing(session: Session, repo_full_name: str, today: date | None = None) -> Listing:
    """A repository's suppressions, each with its expiry state, as of `today`.

    Computed at read time, not at ingest: a suppression expires on a date,
    not on a scan, and a repository that is not rescanned still owes the
    reader the truth about it.
    """
    day = today or utcnow().date()
    found = list(
        session.execute(
            select(ScannerSuppression)
            .where(ScannerSuppression.repo_full_name == repo_full_name)
            .order_by(
                ScannerSuppression.tool,
                ScannerSuppression.branch,
                ScannerSuppression.file_path,
                ScannerSuppression.line,
                ScannerSuppression.rule_id,
            )
        ).scalars()
    )
    rows = [(row, expiry_state(row.expires_at, day)) for row in found]
    counts = {state: 0 for state in EXPIRY_STATES}
    for _, state in rows:
        counts[state] += 1

    facts: list[str] = []
    for tool in sorted({row.tool for row in found}):
        facts.extend(expired_suppression_facts([r for r in found if r.tool == tool], tool, day))
    return Listing(rows=rows, lane_health=facts, counts=counts)
