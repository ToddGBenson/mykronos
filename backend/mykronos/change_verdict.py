"""What THIS change did, named apart from the standing posture (TheHub #60914).

The Oracle recommendation and score describe the whole open backlog (D-048,
S60732). That is the right answer to "how much risk does this repository
carry" and the wrong headline for one commit: on a repository with a large
accepted backlog every commit reads `no_go 100/100`, whatever it changed,
and a developer learns to ignore the gate.

What a developer acts on is what the commit introduced, which is also what
the gate job and deploy.ps1 refuse on (`introduced_blocking`, #735, D-159).
So a decision is shown as two things:

- `change`: "change: clean" or "change: introduces N blocking", by the
  same rule as `introduced_blocking`: an open critical or high finding this
  commit introduced. A count that could not be read is `unknown`, never
  clean.
- `posture`: the recommendation and score as recorded, labelled as posture.

Presentation only. Nothing here decides anything: the policy, the recorded
recommendation and deploy.ps1's rule are unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel, Field

#: The severities that block, as `introduced_blocking` counts them.
BLOCKING_SEVERITIES = ("critical", "high")


class ChangeVerdict(BaseModel):
    """What this commit introduced, as the verdict a developer acts on."""

    verdict: Literal["clean", "introduces_blocking", "unknown"] = Field(
        description=(
            "`introduces_blocking` when the commit introduced an open critical or "
            "high finding (the same rule as `introduced_blocking`), `clean` when "
            "it did not, and `unknown` when the count could not be read. Unknown "
            "is never clean."
        )
    )
    blocking: int | None = Field(
        description="Open critical and high findings this commit introduced. Null when unread."
    )
    non_blocking: int | None = Field(
        description="Other open findings it introduced (medium, low, info). Null when unread."
    )
    overridden: bool = Field(
        default=False, description="A person recorded an override on this decision."
    )
    text: str = Field(
        description='The headline: "change: clean" or "change: introduces N blocking".'
    )


class Posture(BaseModel):
    """The standing posture: the Oracle recommendation and score, as recorded."""

    recommendation: str | None
    score: float | None
    text: str = Field(description='"posture: <recommendation> <score>/100", labelled as posture.')


def change_of(introduced: Mapping[str, int] | None, *, overridden: bool = False) -> ChangeVerdict:
    """The change verdict for one commit's `introduced` counts (None: unread)."""
    if introduced is None:
        return ChangeVerdict(
            verdict="unknown",
            blocking=None,
            non_blocking=None,
            overridden=overridden,
            text="change: unknown (what this commit introduced could not be read)",
        )
    blocking = sum(int(introduced.get(s) or 0) for s in BLOCKING_SEVERITIES)
    other = sum(int(n or 0) for s, n in introduced.items() if s not in BLOCKING_SEVERITIES)
    if blocking:
        text = f"change: introduces {blocking} blocking"
        if overridden:
            text += " (overridden by a person)"
        return ChangeVerdict(
            verdict="introduces_blocking",
            blocking=blocking,
            non_blocking=other,
            overridden=overridden,
            text=text,
        )
    return ChangeVerdict(
        verdict="clean",
        blocking=0,
        non_blocking=other,
        overridden=overridden,
        text="change: clean",
    )


def posture_of(recommendation: str | None, score: float | None) -> Posture:
    """The recorded recommendation and score, labelled as posture."""
    if not recommendation:
        return Posture(recommendation=None, score=score, text="posture: not recorded")
    shown = "" if score is None else f" {score:g}/100"
    return Posture(
        recommendation=recommendation, score=score, text=f"posture: {recommendation}{shown}"
    )
