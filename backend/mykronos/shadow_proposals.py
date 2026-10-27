"""Model triage proposals in shadow, graded against human verdicts
(TheHub #60893, Triage T6; absorbs #60748).

Epic #60879 decided that model verdicts *propose* and stay in shadow until
measured. This is the measuring half:

- `record` stores what a model proposed for a finding, under the
  `finding_disposition` duty, with the exact model id, its rationale and what
  it read. It writes one row and one audit entry. **It never changes a
  finding, never raises an approval request, and nothing reads the table to
  act on it.** `tests/test_dossier.py` pins that.
- `grade` compares each proposal with the verdict a *person* recorded on
  the same finding **after** the proposal was made. A proposal made after
  the verdict could have read it, so it is counted as ineligible rather than
  as agreement. A finding the scanners later observed fixed counts as a
  human-grade `true_positive`: the code was changed, so it was real.

Grades are per model id, because "the model" is not one thing over time.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import AuditLogEntry, ModelTriageProposal

DUTY = "finding_disposition"
MODE = "shadow"

#: What a model may propose. `true_positive` is "real, keep it open": the
#: verdict a rule classifier cannot give and a model reading the code can.
PROPOSALS = ("true_positive", "false_positive", "suppressed", "accepted_risk")

#: Human outcomes that confirm a finding was real. A person reopening it
#: says so too (operator decision on #1006, first review item 4).
_REAL = ("accepted_risk", "fixed", "open")


def record(
    session: Session,
    *,
    finding: Mapping[str, Any],
    proposed_status: str,
    rationale: str,
    model: str,
    confidence: float | None,
    evidence: Mapping[str, Any] | None,
    proposed_by: str,
    actor_kind: str,
    cluster_id: str = "",
) -> ModelTriageProposal:
    if proposed_status not in PROPOSALS:
        raise ValueError(f"{proposed_status!r} is not a proposal ({', '.join(PROPOSALS)}).")
    row = ModelTriageProposal(
        finding_id=str(finding.get("finding_id") or ""),
        repo_full_name=str(finding.get("repo_full_name") or ""),
        cluster_id=cluster_id,
        duty=DUTY,
        proposed_status=proposed_status,
        confidence=confidence,
        rationale=rationale,
        model=model,
        evidence=dict(evidence or {}),
        proposed_by=proposed_by,
        actor_kind=actor_kind,
    )
    session.add(row)
    session.flush()
    return row


def human_verdicts(
    session: Session, finding_ids: Iterable[str]
) -> dict[str, list[tuple[datetime, str, str]]]:
    """finding_id -> [(when, status, actor)] for every disposition a person
    recorded, oldest first. Agents and automation are not graders."""
    ids = sorted({str(f) for f in finding_ids})
    if not ids:
        return {}
    out: dict[str, list[tuple[datetime, str, str]]] = {}
    for entry in session.scalars(
        select(AuditLogEntry)
        .where(
            AuditLogEntry.action == "finding.status",
            AuditLogEntry.entity_id.in_(ids),
            AuditLogEntry.actor_kind == "human",
        )
        .order_by(AuditLogEntry.created_at)
    ):
        status = str((entry.detail or {}).get("new_status") or "")
        if status:
            out.setdefault(entry.entity_id, []).append(
                (entry.created_at, status, entry.actor)
            )
    return out


def _agrees(proposed: str, human: str) -> bool:
    if proposed == "true_positive":
        return human in _REAL
    return proposed == human


def grade_one(
    proposal: Any,
    verdicts: list[tuple[datetime, str, str]],
    fixed_at: datetime | None,
) -> dict[str, Any]:
    """`pending`, `ineligible`, `agree` or `disagree`, with the verdict used."""
    before = [v for v in verdicts if v[0] <= proposal.created_at]
    after = [v for v in verdicts if v[0] > proposal.created_at]
    if fixed_at is not None and fixed_at > proposal.created_at:
        after.append((fixed_at, "fixed", "scanner"))
        after.sort(key=lambda v: v[0])
    if after:
        when, status, actor = after[0]
        return {
            "grade": "agree" if _agrees(proposal.proposed_status, status) else "disagree",
            "human_verdict": status,
            "human_actor": actor,
            "verdict_at": when,
        }
    if before:
        when, status, actor = before[-1]
        return {
            "grade": "ineligible",
            "human_verdict": status,
            "human_actor": actor,
            "verdict_at": when,
        }
    return {"grade": "pending", "human_verdict": None, "human_actor": None, "verdict_at": None}


def latest(proposals: Iterable[Any]) -> list[Any]:
    """The newest proposal per (finding, model): a model that changed its mind
    is graded on its last word, not twice."""
    newest: dict[tuple[str, str], Any] = {}
    for p in proposals:
        key = (p.finding_id, p.model)
        if key not in newest or p.created_at > newest[key].created_at:
            newest[key] = p
    return sorted(newest.values(), key=lambda p: (p.created_at, p.id))


def fixed_times(catalog: Any, finding_ids: Iterable[str]) -> dict[str, datetime]:
    ids = sorted({str(f) for f in finding_ids})
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    rows = catalog.query(
        f"SELECT finding_id, resolved_at FROM findings "
        f"WHERE status = 'fixed' AND finding_id IN ({placeholders})",
        ids,
    )
    return {str(fid): at for fid, at in rows if isinstance(at, datetime)}


def grade(session: Session, catalog: Any) -> dict[str, Any]:
    """Every model's agreement with human verdicts, by model."""
    proposals = latest(session.scalars(select(ModelTriageProposal)))
    ids = [p.finding_id for p in proposals]
    verdicts = human_verdicts(session, ids)
    fixed = fixed_times(catalog, ids)

    by_model: dict[str, Counter[str]] = {}
    pairs: dict[str, Counter[str]] = {}
    for p in proposals:
        g = grade_one(p, verdicts.get(p.finding_id, []), fixed.get(p.finding_id))
        by_model.setdefault(p.model or "unknown", Counter())[g["grade"]] += 1
        if g["grade"] in ("agree", "disagree"):
            pairs.setdefault(p.model or "unknown", Counter())[
                f"{p.proposed_status} -> {g['human_verdict']}"
            ] += 1

    models = []
    for model, counts in sorted(by_model.items()):
        graded = counts["agree"] + counts["disagree"]
        models.append(
            {
                "model": model,
                "proposals": sum(counts.values()),
                "graded": graded,
                "agree": counts["agree"],
                "disagree": counts["disagree"],
                "pending": counts["pending"],
                "ineligible": counts["ineligible"],
                "agreement_rate": round(counts["agree"] / graded, 3) if graded else None,
                "pairs": dict(sorted(pairs.get(model, Counter()).items())),
            }
        )
    return {
        "duty": DUTY,
        "mode": MODE,
        "applied": 0,
        "models": models,
        "interpretation": (
            "Proposals are measured, never applied. A grade compares a model's "
            "latest proposal on a finding with the first human verdict recorded "
            "after it (or a scanner observing it fixed, which confirms it was "
            "real). A proposal made after a verdict could have read it and is "
            "ineligible. Going live is an operator decision on these numbers."
        ),
    }
