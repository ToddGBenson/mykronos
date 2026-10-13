"""Linking before closing: carry-forward and absence reconciliation, in order (TheHub #60734).

Both jobs decide what happens to a finding its lane has stopped reporting.
`carry_forward` asks whether a new finding *is* it, under another id, and
withdraws it as `superseded`. `reconcile_absences` asks whether it has been
gone for two scans, and closes it as `fixed`. For a re-keyed finding both
answers are yes, and only the first is true.

They ran on two independent hourly timers, each in its own thread. Measured
in production on 2026-10-13: after #795 re-keyed every PowerShell finding,
the next passes were due at 01:55:50Z (carry-forward) and 01:55:53Z
(absences) -- overlapping runs, with 38 old rows already two scans absent.
Whichever read first decided whether they ended `superseded` or `fixed`, and
`fixed` is the number this platform is most careful about: it feeds
mean-time-to-fix and the Oracle's posture credits. The two could also rewrite
the same partitions at once, which `mutate.atomic_write` detects but does not
prevent (#443).

So absence reconciliation always runs carry-forward first, in the same
thread, and both hold one lock: an exact link always wins, and the two never
overlap. The lock is per process; the backend runs one (`uvicorn` without
`--workers`), and the CLI's `reconcile-absences` takes the same order.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from mykronos.lake.carry_forward import CarryForwardResult, carry_forward
from mykronos.lake.catalog import Catalog
from mykronos.lake.reconcile import ReconcileResult, reconcile_absences

#: Held by every pass that withdraws or closes findings a lane stopped
#: reporting, so no two of them read-modify-write the partitions at once.
LANE_CLOSURE_LOCK = threading.Lock()


@dataclass
class LinkThenClose:
    carried: CarryForwardResult
    closed: ReconcileResult


def carry_forward_exclusively(catalog: Catalog) -> CarryForwardResult:
    """The hourly carry-forward job, never alongside absence reconciliation."""
    with LANE_CLOSURE_LOCK:
        return carry_forward(catalog)


def reconcile_after_linking(catalog: Catalog) -> LinkThenClose:
    """Absence reconciliation, with every exact link applied first.

    A finding carry-forward withdraws is `superseded`, which absence never
    closes, so nothing it can link is left for absence to call fixed.
    """
    with LANE_CLOSURE_LOCK:
        carried = carry_forward(catalog)
        closed = reconcile_absences(catalog)
    return LinkThenClose(carried=carried, closed=closed)
