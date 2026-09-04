"""What stops the things that could happen here (spec 28 §3, §4).

A threat model is made of four things — assets, entry points, trust boundaries,
mitigations — and the Threat Model tab had one. It could say what was found and
not what stops it. Two consequences, both of which get worse as the platform
gets better: as scanning improves the tab can only ever grow more red, and a
team that spends a quarter adding controls sees no change at all.

**An empty category reads as safe, and that is the bug this closes.** A STRIDE
category with no findings because DAST has never run in this repository
rendered identically to one with no findings because the code is clean. The
scan-health data that separates them was already fetched on the same page, one
tab away. Four states now, and `unscanned` is the one that matters most,
because it is the one that has been rendering as good news.

**A declared control is somebody's assertion, and the tab never upgrades it to
a fact.** An admin-authored register is useful the day it ships, where one that
waits for spec 23 §2's entry-point inventory stays unbuilt for a year. What
keeps it from becoming a wiki is `verified_by_capability`: a control claiming
`authentication` on a repository where DAST is reporting an open authentication
finding is a contradiction, and the tab shows it as one rather than resolving
it. A control that exists while findings accumulate underneath it is either
wrong, bypassed, or narrower than its description, and every one of those is
worth somebody's attention.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import RepoControl
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: What a control can be. Deliberately a closed list: a free-text `kind` would
#: make two teams' registers incomparable within a quarter, and the value of
#: this table is that "how many repositories declare an authentication control"
#: is a question somebody can ask.
CONTROL_KINDS = (
    "authentication",
    "authorization",
    "input_validation",
    "output_encoding",
    "secrets_management",
    "logging",
    "rate_limiting",
    "encryption",
)

#: The capability that could contradict a control of each kind. Empty for the
#: kinds nothing in the platform can check — stated rather than left implied,
#: because a control the platform cannot contradict is not a verified control
#: and the tab must not let it look like one.
CONTRADICTED_BY: dict[str, str] = {
    "authentication": "dast",
    "authorization": "dast",
    "input_validation": "sast",
    "output_encoding": "sast",
    "secrets_management": "secrets",
    "encryption": "sast",
    "logging": "",
    "rate_limiting": "",
}

#: After this, a declared control is shown as stale. Ninety days rather than
#: the thirty `regression.STALE_AFTER_DAYS` uses, because these are different
#: claims: a test lane either ran or it did not, while a person re-reading a
#: control declaration is a quarterly review task and calling it stale after a
#: month would mean every control is permanently stale.
STALE_AFTER_DAYS = 90


class ControlError(ValueError):
    """Something a person needs to correct."""


@dataclass(frozen=True)
class CategoryState:
    """One STRIDE category's state (spec 28 §4)."""

    stride: str
    findings: int
    controls: list[dict[str, Any]]
    scanned: bool

    @property
    def state(self) -> str:
        """Exactly one of four, and the order of these tests is the design.

        `unscanned` is checked before anything else because it is the state
        currently rendering as good news: a category nothing has ever looked
        at must never be reported as clean, whatever else is true of it.
        """
        if not self.scanned:
            return "unscanned"
        if self.findings:
            return "findings_open"
        if self.controls:
            return "mitigated"
        return "unmitigated"

    @property
    def contradicted(self) -> bool:
        """Findings open *and* a control declared for the same category.

        Shown prominently rather than resolved: the platform has no basis to
        decide which of the two is wrong, and both being true at once is the
        finding.
        """
        return bool(self.findings and self.controls)


def declare(
    session: Session,
    *,
    repo_full_name: str,
    stride: str,
    kind: str,
    description: str = "",
    evidence_ref: str = "",
    declared_by: str = "",
    known_categories: tuple[str, ...] = (),
    now: datetime | None = None,
) -> RepoControl:
    """Record a control. Returns the row."""
    if known_categories and stride not in known_categories:
        raise ControlError(
            f"{stride!r} is not a STRIDE category. Expected one of: "
            f"{', '.join(known_categories)}."
        )
    if kind not in CONTROL_KINDS:
        raise ControlError(
            f"{kind!r} is not a control kind. Expected one of: "
            f"{', '.join(CONTROL_KINDS)}."
        )

    stamp = now or utcnow()
    control = RepoControl(
        repo_full_name=repo_full_name,
        stride=stride,
        kind=kind,
        description=description.strip(),
        evidence_ref=evidence_ref.strip(),
        # Derived, never accepted from the caller: it says which capability
        # *could contradict* this control, which is a property of the kind and
        # not something a declarer gets to choose. Letting it be set would let
        # a control name a capability that cannot see it and look checked.
        verified_by_capability=CONTRADICTED_BY.get(kind, ""),
        declared_by=declared_by,
        declared_at=stamp,
        # Declaring is confirming. Left null the row would read as stale from
        # the moment it was written, which is the opposite of what happened.
        last_verified_at=stamp,
    )
    session.add(control)
    session.flush()
    return control


def confirm(
    session: Session, control_id: str, *, now: datetime | None = None
) -> RepoControl:
    """Somebody re-read this and it is still true."""
    control = session.get(RepoControl, control_id)
    if control is None:
        raise ControlError("No such control.")
    control.last_verified_at = now or utcnow()
    session.flush()
    return control


def withdraw(session: Session, control_id: str) -> None:
    """Delete it.

    Deleted rather than flagged withdrawn, unlike almost everything else here.
    A control is a *claim about the present*, and a withdrawn one is not
    evidence of anything — nobody needs to know that somebody once believed
    authentication was enforced. The audit log records who removed it, which
    is the part that matters.
    """
    control = session.get(RepoControl, control_id)
    if control is None:
        raise ControlError("No such control.")
    session.delete(control)
    session.flush()


def for_repo(session: Session, repo_full_name: str) -> list[RepoControl]:
    return list(
        session.scalars(
            select(RepoControl)
            .where(RepoControl.repo_full_name == repo_full_name)
            .order_by(RepoControl.stride, RepoControl.kind)
        )
    )


def purge_for_repo(session: Session, repo_full_name: str) -> int:
    """Everything declared for a repository being offboarded."""
    rows = for_repo(session, repo_full_name)
    for row in rows:
        session.delete(row)
    return len(rows)


def as_dict(control: RepoControl, *, now: datetime | None = None) -> dict[str, Any]:
    moment = now or utcnow()
    verified = control.last_verified_at
    stale = verified is None or verified < moment - timedelta(days=STALE_AFTER_DAYS)
    return {
        "control_id": control.id,
        "stride": control.stride,
        "kind": control.kind,
        "description": control.description,
        "evidence_ref": control.evidence_ref,
        # A control with no evidence reference is allowed and is the weaker
        # claim; refusing it would mean the register only ever holds the
        # controls somebody had time to document.
        "evidence": "referenced" if control.evidence_ref else "asserted",
        "verified_by_capability": control.verified_by_capability,
        "checkable": bool(control.verified_by_capability),
        "last_verified_at": control.last_verified_at,
        "stale": stale,
        "declared_by": control.declared_by,
        "declared_at": control.declared_at,
    }


def category_states(
    *,
    categories: tuple[str, ...],
    findings_by_category: dict[str, int],
    controls: list[RepoControl],
    scanned_capabilities: set[str],
    stride_by_capability: dict[str, tuple[str, ...]],
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """One state per STRIDE category (spec 28 §4).

    `scanned` is computed from capabilities that have actually reported, not
    from capabilities that are enabled. A lane switched on last week and never
    run is exactly the gap this is for: the repository believes it is covered,
    and no failing run disagrees, because there is no run.
    """
    by_category: dict[str, list[RepoControl]] = {c: [] for c in categories}
    for control in controls:
        by_category.setdefault(control.stride, []).append(control)

    reachable: set[str] = set()
    for capability in scanned_capabilities:
        reachable.update(stride_by_capability.get(capability, ()))

    states: list[dict[str, Any]] = []
    for category in categories:
        state = CategoryState(
            stride=category,
            findings=findings_by_category.get(category, 0),
            controls=[as_dict(c, now=now) for c in by_category.get(category, [])],
            scanned=category in reachable,
        )
        states.append(
            {
                "stride": category,
                "state": state.state,
                "controls": state.controls,
                "contradicted": state.contradicted,
                "reason": _reason(state, stride_by_capability),
            }
        )
    return states


def _reason(
    state: CategoryState, stride_by_capability: dict[str, tuple[str, ...]]
) -> str:
    """Why this category is in the state it is, in one sentence."""
    if state.state == "unscanned":
        feeders = sorted(
            capability
            for capability, categories in stride_by_capability.items()
            if state.stride in categories
        )
        return (
            "Nothing that reports into this category has ever run here"
            + (f" — it needs {' or '.join(feeders)}." if feeders else ".")
        )
    if state.contradicted:
        return (
            f"{state.findings} open finding(s) beneath {len(state.controls)} "
            "declared control(s). A control that exists while findings "
            "accumulate under it is either wrong, bypassed, or narrower than "
            "its description."
        )
    if state.state == "findings_open":
        return f"{state.findings} open finding(s), and no control declared here."
    if state.state == "mitigated":
        return (
            f"No open findings, and {len(state.controls)} declared control(s). "
            "Declared means somebody asserted it, not that the platform "
            "verified it."
        )
    return "Scanned, nothing found, and nothing declared that would stop it."
