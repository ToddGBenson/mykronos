"""Re-score archived supply-chain evidence with the current scorer (spec 07 §5a).

Sibling of `reprocess`, and for the same class of reason: the derivation was
wrong, and the rows it produced are still on disk asserting it. There the
adapters mis-shaped findings; here `score()` returned 100 for a scan that
resolved no dependencies, because zero vulnerabilities out of zero packages
takes every penalty term to zero.

Unlike a finding, an evidence row's identity does not depend on the thing that
changed: `evidence_id` derives from repo and commit, so a re-score updates the
row in place rather than orphaning it. Nothing is superseded and no history is
retired — the same scan, scored correctly.

The per-ecosystem counts the score was computed from are kept on the row
(spec 07 §8), so this does not need the archived tool output at all. It reads
`ecosystems_json`, re-runs the scorer, and writes back only where the answer
moved. A row whose counts are missing is left alone and reported: guessing at
inputs would be a worse error than the one being fixed.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from mykronos.atlas import score
from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.tables import column_names
from mykronos.schemas import EcosystemEvidence

logger = logging.getLogger(__name__)


@dataclass
class Rescored:
    evidence_id: str
    repo_full_name: str
    commit_sha: str
    was: int | None
    now: int | None
    dependency_count: int


@dataclass
class RescoreResult:
    examined: int = 0
    changed: list[Rescored] = field(default_factory=list)
    unscoreable: list[str] = field(default_factory=list)

    @property
    def wrote(self) -> int:
        return len(self.changed)


def _ecosystems(raw: Any) -> list[EcosystemEvidence] | None:
    """Parse the stored per-ecosystem counts, or None if they are unusable.

    An empty list is a valid answer, not a missing one — it is what a scan
    that resolved nothing recorded, and those rows are the entire reason this
    command exists. Only an absent or unparseable field is unscoreable.
    """
    if not raw:
        return None
    try:
        detail = json.loads(raw) if isinstance(raw, str) else raw
        rows = detail.get("ecosystems") if isinstance(detail, dict) else None
        if not isinstance(rows, list):
            return None
        return [EcosystemEvidence(**row) for row in rows]
    except Exception:  # noqa: BLE001 - a malformed row is data, not a crash
        return None


def rescore_sscs(
    catalog: Catalog,
    buffer: WriteAheadBuffer,
    *,
    repo_full_name: str | None = None,
    dry_run: bool = False,
) -> RescoreResult:
    """Recompute every evidence row's trust score and write back the changes."""
    result = RescoreResult()

    names = column_names("sscs_evidence")
    where = "WHERE repo_full_name = ?" if repo_full_name else ""
    params = [repo_full_name] if repo_full_name else []
    rows = catalog.query(f"SELECT {', '.join(names)} FROM sscs_evidence {where}", params)

    updates: list[dict[str, Any]] = []
    for values in rows:
        row = dict(zip(names, values, strict=True))
        result.examined += 1

        ecosystems = _ecosystems(row.get("ecosystems_json"))
        if ecosystems is None:
            # The field is absent or unparseable, so the inputs the score was
            # computed from are gone. Not the same as an empty ecosystems
            # list, which scores to null and is handled above; here there is
            # nothing to recompute from and only a rescan can settle it.
            result.unscoreable.append(str(row["evidence_id"]))
            continue

        assessment = score(ecosystems)
        if assessment.trust_score == row["trust_score"]:
            continue

        result.changed.append(
            Rescored(
                evidence_id=str(row["evidence_id"]),
                repo_full_name=str(row["repo_full_name"]),
                commit_sha=str(row["commit_sha"]),
                was=None if row["trust_score"] is None else int(row["trust_score"]),
                now=assessment.trust_score,
                dependency_count=assessment.dependency_count,
            )
        )

        # The whole row, with the score replaced and `evaluated_at` untouched.
        # Compaction upserts on evidence_id and finds the row's partition from
        # the existing table, so keeping the timestamp keeps the row where it
        # is; bumping it would claim the assessment happened today, which is
        # the sort of quiet falsification this command exists to undo.
        detail = row.get("ecosystems_json")
        parsed = json.loads(detail) if isinstance(detail, str) else (detail or {})
        parsed["score_terms"] = assessment.terms
        parsed["floored"] = assessment.floored
        updates.append(
            {
                **row,
                "trust_score": assessment.trust_score,
                "raw_trust_score": assessment.raw_trust_score,
                "ecosystems_json": json.dumps(parsed),
            }
        )

    if updates and not dry_run:
        buffer.append("sscs_evidence", updates)
        logger.info("rescore_sscs staged %d corrected rows", len(updates))

    return result
