"""The Today run sheet's actions: Merge in order and Deploy (TheHub #61142).

Operator decision 2026-11-04: built now, shipped switched off. The routes in
`mykronos.api.today` refuse while `runsheet_actions_enabled` is off.

The server never merges and never deploys. "Patchwork never merges anything"
(spec 08 §3) is held by the GitHub client having no merge method, which
`tests/test_patchwork.py` enforces, and spec 10 §2 says the platform offers no
merge of its own. So pressing a button re-checks, at request time, everything
the server can read, and records a `RunsheetRequest`. A runner on the host,
holding the operator's own GitHub credential and able to read the deploy lock
and the Delivery hold, carries it out with Start-Here's rules: one batch,
TheHub first, each merged with `--match-head-commit` at the head recorded
here, stop at the first failure, and never move an approved head. That runner
is a follow-up; until it exists, a queued request waits.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from mykronos import runsheet as rs

#: Start-Here's batch limit (operator decision 2026-11-03).
MAX_BATCH = 5
#: Base branches a pull request merges into directly. Any other base is a
#: branch of another pull request: a stack, which loses its content when the
#: base merges first.
TRUNKS = frozenset({"main", "master", "develop"})

MERGE = "merge"
DEPLOY = "deploy"
#: Request states that still occupy the queue.
OPEN_STATES = ("queued", "taken")

HOST_NOTE = (
    "The host runner checks the deploy lock and the Delivery hold before it acts; "
    "the server cannot read either. Until the runner exists, a queued request waits."
)


class _Reader(Protocol):
    async def get_pull_request(self, repo_full_name: str, number: int) -> Any: ...


ClientFor = Callable[[str], "_Reader | None"]


@dataclass(frozen=True)
class MergeAsk:
    repo_full_name: str
    number: int
    #: The head the run sheet showed, which the merge must match exactly.
    head_sha: str

    @property
    def ref(self) -> str:
        return f"{self.repo_full_name}#{self.number}"


@dataclass
class Outcome:
    repo_full_name: str
    number: int
    head_sha: str
    #: accepted | refused | not_queued
    result: str
    reason: str = ""


@dataclass
class BatchCheck:
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return bool(self.outcomes) and all(o.result == "accepted" for o in self.outcomes)


def order_batch(asks: Iterable[MergeAsk]) -> list[MergeAsk]:
    """TheHub first (Start-Here section 2), then by repository and oldest number."""
    return sorted(
        asks,
        key=lambda a: (a.repo_full_name not in rs.APPROVAL_REPOS, a.repo_full_name, a.number),
    )


def _short(sha: str) -> str:
    return sha[:12] or "(none)"


async def _refusal(ask: MergeAsk, item: rs.Item | None, client_for: ClientFor) -> str:
    if item is None:
        return "not on the run sheet's Merge step now"
    if item.state != rs.READY:
        return f"not ready on the run sheet now: {item.reason}"
    if not rs.same_sha(item.sha, ask.head_sha):
        return (
            f"{_short(ask.head_sha)} is not the head the run sheet showed "
            f"({_short(item.sha)}); reload the sheet"
        )
    client = client_for(ask.repo_full_name)
    if client is None:
        return "could not be read: the repository is not onboarded"
    try:
        live = await client.get_pull_request(ask.repo_full_name, ask.number)
    except Exception as exc:  # noqa: BLE001 - refuse rather than trust the sheet
        return f"could not be read from GitHub ({type(exc).__name__}), so it was not queued"
    if live is None:
        return "could not be read: GitHub has no such pull request"
    if live.state != "open" or live.merged:
        return "not open any more"
    if not rs.same_sha(live.head_sha, ask.head_sha):
        return (
            f"head moved: GitHub has {_short(live.head_sha)}, the sheet showed "
            f"{_short(ask.head_sha)}. Never move an approved head; it needs a review at the new one"
        )
    if live.base_branch and live.base_branch not in TRUNKS:
        return f"stacked on {live.base_branch}: merge its base first, or rebase it onto the trunk"
    return ""


async def check_batch(
    asks: Iterable[MergeAsk], *, step: rs.Step, client_for: ClientFor
) -> BatchCheck:
    """Re-check a batch against a freshly computed Merge step and GitHub's live heads.

    All or nothing: one refusal refuses the batch, and the rest are reported
    `not_queued`, so a partial batch is never queued behind the operator's back.
    """
    items = {i.ref: i for i in step.items}
    outcomes: list[Outcome] = []
    for ask in order_batch(asks):
        why = await _refusal(ask, items.get(ask.ref), client_for)
        outcomes.append(
            Outcome(
                ask.repo_full_name,
                ask.number,
                ask.head_sha,
                "refused" if why else "accepted",
                why,
            )
        )
    if any(o.result == "refused" for o in outcomes):
        for o in outcomes:
            if o.result == "accepted":
                o.result = "not_queued"
                o.reason = "another pull request in the batch was refused"
    return BatchCheck(outcomes)


def deploy_refusal(
    step: rs.Step, facts: rs.DeployFacts, sha: str, *, open_requests: int
) -> str | None:
    """Why a deploy of `sha` may not be queued now, or None.

    Re-checked at request time from fresh reads: the Deploy step is ready,
    `sha` is main's head, Delivery on main succeeded, every deploy lane is
    green, the risk gate decided, and the backup window is clear. The deploy
    lock and the Delivery hold are the host runner's to check.
    """
    if open_requests:
        return "A deploy is already queued; one at a time."
    if step.state != rs.READY:
        return f"The Deploy step is not ready: {step.reason or step.summary}"
    if not rs.same_sha(facts.main_sha, sha):
        return (
            f"main is {_short(facts.main_sha)} now, not {_short(sha)}; reload the sheet."
        )
    if facts.delivery != ("completed", "success"):
        word = " ".join(x for x in (facts.delivery or ("not found", None)) if x)
        return f"main's Delivery is {word}: no image to deploy."
    red = [f"{n} {s or 'unread'}" for n, s in facts.lanes.items() if s != "succeeded"]
    if red:
        return "Lanes not green: " + ", ".join(red) + "."
    if rs.in_backup_window(facts.now):
        return "02:40-04:15Z is the backup window. Deploy after it."
    gate = next((i for i in step.items if i.text == "risk gate"), None)
    if gate is None or gate.state != rs.READY:
        return f"The risk gate has not said go: {gate.reason if gate else 'not read'}."
    return None


# -- Reads, patched in tests ---------------------------------------------------


async def merge_view(state: Any, now: datetime) -> rs.Step:
    """The Merge step, computed now, exactly as `GET /today` would show it."""
    steps = await rs.gather(state, now)
    return next(s for s in steps if s.key == MERGE)


async def deploy_view(state: Any, now: datetime) -> tuple[rs.Step, rs.DeployFacts]:
    facts = await rs._deploy_facts(state, now)
    return rs.deploy_step(facts), facts


def reader_for(state: Any) -> ClientFor:
    from mykronos.approvals.pull_requests import client_for

    def read(repo: str) -> _Reader | None:
        return client_for(state.db, state.github_factory, repo)

    return read


__all__ = [
    "MAX_BATCH",
    "BatchCheck",
    "MergeAsk",
    "Outcome",
    "check_batch",
    "deploy_refusal",
    "deploy_view",
    "merge_view",
    "order_batch",
    "reader_for",
]
