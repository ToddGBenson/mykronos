"""DORA metrics per repository, from data MyKronos already holds (TheHub #60912).

The goals "accelerate delivery" and "improve reliability" could not be
measured here: `/api/dashboard/trends` reports mean time to fix findings and
nothing about delivery. The four DORA metrics are computed from two inputs:

- **TheHub's deploy record** (`GET /api/devops/deploys`). A production deploy
  is a run TheHub's deploy.sh made (`trigger_source: deploy_sh`) whose
  `deploy` stage, the one that ships to production, succeeded. Its
  `deploy_target` stage is only target selection, before anything is built,
  so it decides nothing here (review of #1117). Concourse test runs, runs
  that died before `deploy`, and a skipped `deploy` are not deploys. A
  successful run with no `deploy` stage at all predates deploy.sh recording
  it, and cannot be told apart from a deploy: the record is judged only from
  after the newest such run. Only TheHub records its own deploys.
  MyKronos keeps only the running revision (D-145), so every other repository
  lacks a deploy record. That gap is named, never counted as zero deploys.
- **The lake's first-seen time of each commit**: the earliest scan of the sha
  (the delivery ledger's `first_seen`). For a squash-merged commit that is
  when its merge was first scanned.

The metrics, over 30 and 90 days:

- *Deploy frequency*: production deploys per week.
- *Lead time for changes*: median hours from the deployed commit's first-seen
  time to the deploy finishing.
- *Change failure rate*: % of production deploys that reached `deploy` and
  then failed (or were aborted), or whose `rollback` stage ran.
- *Time to restore*: DORA's "failed deployment recovery time", the median
  hours from a change failure to the next production deploy that did not
  fail. Hub incidents are not used: they carry no repository, and most are
  pipeline signals, not production outages.

A metric that cannot be computed has `value: null` and a `lacks` sentence
naming the input it is missing. It is never 0: a 0 that means "not measured"
reads as "perfect" or as "dead", and both are claims the data does not make.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field

from mykronos.schemas import utcnow

WINDOWS = (30, 90)

#: Stage states that mean a stage did not run.
_NOT_RUN = {"", "skipped", "not_run", "pending", "none"}

NO_DEPLOY_RECORD = (
    "no deploy record for this repository: MyKronos keeps only the running revision "
    "(D-145), and TheHub records deploys of itself only"
)
HUB_NOT_CONNECTED = (
    "TheHub is not connected (MYKRONOS_HUB_API_URL and MYKRONOS_HUB_API_TOKEN), so its "
    "deploy record cannot be read"
)


class Metric(BaseModel):
    value: float | None = Field(description="Null when it cannot be computed. Never 0 for that.")
    unit: str
    sample: int = Field(description="How many deploys, commits or failures it is computed from.")
    lacks: str | None = Field(
        default=None, description="The input it lacks, when `value` is null."
    )
    detail: str | None = None


class Window(BaseModel):
    days: int
    deploy_frequency: Metric
    lead_time: Metric
    change_failure_rate: Metric
    recovery_time: Metric


DEFINITIONS = {
    "deploy_frequency": (
        "Production deploys per week: TheHub deploy.sh runs whose deploy stage succeeded."
    ),
    "lead_time": (
        "Median hours from the deployed commit's first scan in the lake to the deploy finishing."
    ),
    "change_failure_rate": (
        "% of production deploys that failed after the deploy stage, or rolled back."
    ),
    "recovery_time": (
        "Median hours from a change failure to the next production deploy that did not fail."
    ),
}


@dataclass(frozen=True)
class DeployRun:
    sha: str
    started_at: datetime
    finished_at: datetime | None
    reached_production: bool
    failed: bool
    #: False for a successful run with no `deploy` stage: it predates the
    #: stage being recorded, so whether it shipped is not known.
    judged: bool = True


@dataclass
class DeploySource:
    #: None when there is no record to read, with `lacks` saying why.
    runs: list[DeployRun] | None
    lacks: str | None = None
    #: The oldest run read, when the read stopped before the oldest window's
    #: start: the record does not cover any earlier time.
    covers_from: datetime | None = None


def _time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value:
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment


def parse_runs(items: Iterable[Any]) -> list[DeployRun]:
    """TheHub's deploy runs, as production deploys. Anything that is not a
    deploy.sh run, or has no start time, is left out."""
    out: list[DeployRun] = []
    for item in items:
        if not isinstance(item, dict) or item.get("trigger_source") != "deploy_sh":
            continue
        started = _time(item.get("started_at"))
        if started is None:
            continue
        stages = item.get("stage_summary")
        stages = stages if isinstance(stages, dict) else {}
        reached = str(stages.get("deploy") or "") == "success"
        rollback = str(stages.get("rollback") or "").lower()
        status = str(item.get("final_status") or "")
        judged = not (status == "success" and "deploy" not in stages)
        out.append(
            DeployRun(
                sha=str(item.get("sha") or item.get("deploy_id") or "").lower(),
                started_at=started,
                finished_at=_time(item.get("finished_at")),
                reached_production=reached,
                failed=reached
                and (status in ("failed", "aborted") or rollback not in _NOT_RUN),
                judged=judged,
            )
        )
    return out


def _hours(delta: timedelta) -> float:
    return delta.total_seconds() / 3600


def _none(unit: str, lacks: str) -> Metric:
    return Metric(value=None, unit=unit, sample=0, lacks=lacks)


def _first_seen(first_seen: Mapping[str, datetime], sha: str) -> datetime | None:
    if not sha:
        return None
    if sha in first_seen:
        return first_seen[sha]
    for known, at in first_seen.items():
        if known and len(known) >= 7 and (known.startswith(sha) or sha.startswith(known)):
            return at
    return None


def window(
    days: int,
    *,
    now: datetime,
    deploys: DeploySource,
    first_seen: Mapping[str, datetime] | None,
) -> Window:
    since = now - timedelta(days=days)
    units = ("per week", "hours", "percent", "hours")

    def lacking(sentence: str) -> Window:
        f, lt, c, r = (_none(u, sentence) for u in units)
        return Window(
            days=days, deploy_frequency=f, lead_time=lt, change_failure_rate=c, recovery_time=r
        )

    if deploys.runs is None:
        return lacking(deploys.lacks or NO_DEPLOY_RECORD)
    if deploys.covers_from is not None and deploys.covers_from > since:
        return lacking(
            "TheHub's deploy record reaches back only to "
            f"{deploys.covers_from.date().isoformat()}, "
            f"not to the start of this {days}-day window"
        )

    unjudged = [r.started_at for r in deploys.runs if not r.judged]
    if unjudged and max(unjudged) >= since:
        return lacking(
            "TheHub's deploy record names the deploy stage only after "
            f"{max(unjudged).date().isoformat()}: an earlier successful run cannot be "
            "told apart from a production deploy"
        )

    every = sorted((r for r in deploys.runs if r.reached_production), key=lambda r: r.started_at)
    runs = [r for r in every if since <= r.started_at <= now]
    frequency = Metric(value=round(len(runs) / (days / 7), 2), unit="per week", sample=len(runs))
    if not runs:
        nothing = "no production deploy in this window"
        return Window(
            days=days,
            deploy_frequency=frequency,
            lead_time=_none("hours", nothing),
            change_failure_rate=_none("percent", nothing),
            recovery_time=_none("hours", nothing),
        )

    leads = []
    for r in runs if first_seen is not None else []:
        seen = _first_seen(first_seen, r.sha)
        if seen is not None and r.finished_at is not None and r.finished_at >= seen:
            leads.append(_hours(r.finished_at - seen))
    lead = (
        Metric(
            value=round(statistics.median(leads), 2),
            unit="hours",
            sample=len(leads),
            detail=f"{len(runs) - len(leads)} deployed commit(s) had no first-seen time"
            if len(leads) < len(runs)
            else None,
        )
        if leads
        else _none(
            "hours",
            "the lake's first-seen times could not be read"
            if first_seen is None
            else "no deployed commit in this window has a first-seen time in the lake "
            "(none of them was ever scanned)",
        )
    )

    failures = [r for r in runs if r.failed]
    rate = Metric(
        value=round(100 * len(failures) / len(runs), 1), unit="percent", sample=len(runs)
    )

    recoveries = []
    unrecovered = 0
    for f in failures:
        ended = f.finished_at or f.started_at
        good = next((r for r in every if r.started_at > f.started_at and not r.failed), None)
        if good is None or good.finished_at is None:
            unrecovered += 1
            continue
        recoveries.append(_hours(good.finished_at - ended))
    if not failures:
        recovery = _none("hours", "no change failure in this window, so nothing to recover from")
    elif not recoveries:
        recovery = _none(
            "hours", f"{unrecovered} change failure(s) not yet followed by a good deploy"
        )
    else:
        recovery = Metric(
            value=round(statistics.median(recoveries), 2),
            unit="hours",
            sample=len(recoveries),
            detail=f"{unrecovered} not yet recovered" if unrecovered else None,
        )

    return Window(
        days=days,
        deploy_frequency=frequency,
        lead_time=lead,
        change_failure_rate=rate,
        recovery_time=recovery,
    )


def compute(
    *,
    now: datetime | None = None,
    deploys: DeploySource,
    first_seen: Mapping[str, datetime] | None,
    windows: Iterable[int] = WINDOWS,
) -> list[Window]:
    moment = now or utcnow()
    return [window(d, now=moment, deploys=deploys, first_seen=first_seen) for d in windows]


async def hub_deploy_source(
    hub: Any, since: datetime, *, page: int = 200, max_pages: int = 10
) -> DeploySource:
    """TheHub's deploy record back to `since`, newest first, a page at a time.
    Unreadable is `lacks`, never an empty record."""
    from mykronos.product_owner import HubUnavailableError

    if hub is None:
        return DeploySource(runs=None, lacks=HUB_NOT_CONNECTED)
    items: list[dict[str, Any]] = []
    oldest: datetime | None = None
    reached = False
    for n in range(max_pages):
        try:
            body = await hub.get_json("/api/devops/deploys", {"limit": page, "offset": n * page})
        except HubUnavailableError:
            return DeploySource(
                runs=None, lacks="TheHub's deploy record could not be read (TheHub unavailable)"
            )
        batch = body.get("items") if isinstance(body, dict) else None
        if not isinstance(batch, list):
            return DeploySource(
                runs=None, lacks="TheHub's deploy record could not be read (unexpected shape)"
            )
        items.extend(x for x in batch if isinstance(x, dict))
        times = [t for t in (_time(x.get("started_at")) for x in batch if isinstance(x, dict)) if t]
        if times:
            oldest = min([*times, oldest] if oldest else times)
        if oldest is not None and oldest <= since:
            reached = True
            break
        if len(batch) < page:
            break
    if not items:
        return DeploySource(runs=None, lacks="no deploys recorded in TheHub's deploy record")
    covers_from = None if reached else (oldest or utcnow())
    return DeploySource(runs=parse_runs(items), covers_from=covers_from)


def first_seen_of(catalog: Any, repo_full_name: str, shas: Iterable[str]) -> dict[str, datetime]:
    """The earliest scan of each sha in the lake: the delivery ledger's first_seen.

    Matched by prefix: deploy.sh records 12 characters and the lake stores
    40, so an exact match never finds one (review of #1117). Keyed by the
    sha as asked. A prefix shorter than 7 characters matches nothing.
    """
    wanted = sorted({s.lower() for s in shas if s and len(s) >= 7})
    if not wanted:
        return {}
    clauses = " OR ".join("starts_with(lower(commit_sha), ?)" for _ in wanted)
    rows = catalog.query(
        f"""
        SELECT lower(commit_sha), MIN(started_at)
        FROM scan_runs
        WHERE repo_full_name = ? AND ({clauses})
        GROUP BY lower(commit_sha)
        """,
        [repo_full_name, *wanted],
    )
    out: dict[str, datetime] = {}
    for full, at in rows:
        moment = _time(at)
        if moment is None:
            continue
        for sha in wanted:
            if str(full).startswith(sha) and (sha not in out or moment < out[sha]):
                out[sha] = moment
    return out
