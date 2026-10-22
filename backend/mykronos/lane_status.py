"""Whether a scan lane is current, stale or retired (TheHub #60816).

A capability can be served by several lanes - `atlas` by osv-scanner and by
grype, `dast` by `dast-demo` and `dast-staging`, `sast` by CodeQL and by
ShellCheck beside it. The capability reads fresh as long as *any* of them
reports, so when one stops nothing distinguishes a lane somebody switched off
from a lane that broke: both are a row in the lane list with an old date.

Each lane (a `tool_name` and `job` pair under one capability, as
`ScanRunReport.lanes` lists them; `job` is recorded since #449) is read as:

* **retired** - nobody expects it to report any more, for one of two reasons:

  - **inferred from configuration.** The configuration that says which tools
    serve a capability no longer lists it. For a Concourse lane that is the
    pipeline's job list `ci.CAPABILITY_BY_JOB` holds (and `test_ci_job_audit`
    keeps in step with `deploy/concourse/pipelines/*.yml`): the job is no
    longer declared for this repository's pipeline under this capability.
    For a GitHub Actions lane it is the repository's capability config, from
    which the installer renders its workflows: the tool is neither the
    primary (`enabled_tool`, or the capability's default) nor one of its
    `extra_analysers`.
  - **retired by an operator** (`RetiredLane`): still configured, and
    deliberately unused. Audited, and reversible.

* **stale** - not retired, and its last run is more than
  `LANE_STALE_DAYS` old, or it never finished one. A lane that stopped and
  that nobody has said is retired is a broken lane until somebody says so.

* **current** - neither.

A stopped lane therefore reads retired or stale; it never reads current.

**Inference only where the configuration is known.** A job on a pipeline this
platform has no job list for (one with no entry in `CAPABILITY_BY_JOB`) is not
inferred retired - "the table does not know it" is not "the table dropped it"
- and a run recorded before #449 has no job to look up. Both fall through to
the staleness test, which is the safe direction: such a lane can read stale,
never current, once it stops.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from mykronos import ci
from mykronos.adapters.registry import default_tool
from mykronos.installer.extra_lanes import EXTRA_LANES

#: A lane whose last run is older than this, and which nobody retired, reads
#: stale. Eight days rather than the portfolio's seven (`dashboard.
#: STALE_AFTER_DAYS`) so a weekly lane - `coverage` - has a day of slack
#: rather than reading stale for the hours between one run and the next.
LANE_STALE_DAYS = 8

CURRENT = "current"
STALE = "stale"
RETIRED = "retired"
STATES = (CURRENT, STALE, RETIRED)


@dataclass(frozen=True)
class Retirement:
    """An operator's record that a lane is deliberately unused."""

    id: str
    reason: str
    retired_by: str
    retired_at: datetime


@dataclass(frozen=True)
class LaneVerdict:
    state: str
    #: `config` | `operator` for a retired lane; `age` | `never_finished` for
    #: a stale one; empty for a current one.
    basis: str
    #: One sentence a person reads beside the lane.
    reason: str
    retirement: Retirement | None = None
    #: A run arrived after an operator retired the lane: it is being used
    #: after all, and the retirement probably wants withdrawing.
    reported_since_retired: bool = False


def _capabilities(mapped: str | tuple[str, ...] | None) -> tuple[str, ...]:
    if mapped is None:
        return ()
    return (mapped,) if isinstance(mapped, str) else tuple(mapped)


def _known_pipeline(pipeline: str) -> bool:
    return any(p == pipeline for p, _ in ci.CAPABILITY_BY_JOB)


def configured_actions_tools(capability: str, config: dict[str, Any] | None) -> frozenset[str]:
    """The tools the repository's capability config asks Actions to run."""
    config = config or {}
    primary = str(config.get("enabled_tool") or default_tool(capability))
    extras = config.get("extra_analysers") or []
    tools = {primary}
    if isinstance(extras, list):
        tools.update(
            str(tool) for tool in extras if EXTRA_LANES.get(str(tool), ("", ""))[0] == capability
        )
    return frozenset(tools)


def config_retirement(
    *,
    pipeline: str,
    capability: str,
    tool_name: str | None,
    job: str | None,
    config: dict[str, Any] | None,
) -> str | None:
    """Why the configuration says this lane no longer serves the capability,
    or None when it still does - or when there is no configuration to ask."""
    if not job:
        return None
    if capability in _capabilities(ci.CAPABILITY_BY_JOB.get((pipeline, job))):
        return None  # a Concourse job this pipeline still declares
    if capability in _capabilities(ci.CAPABILITY_BY_JOB.get((ci.ACTIONS, job))):
        if not tool_name:
            return None
        tools = configured_actions_tools(capability, config)
        if tool_name in tools:
            return None
        return (
            f"The repository's {capability} config no longer runs {tool_name} "
            f"(it runs {', '.join(sorted(tools))})."
        )
    if _known_pipeline(pipeline):
        return (
            f"Job {job} is no longer in the {pipeline} pipeline's job list for {capability}."
        )
    return None


def classify(
    *,
    pipeline: str,
    capability: str,
    tool_name: str | None,
    job: str | None,
    last_run_at: datetime | None,
    config: dict[str, Any] | None,
    retirement: Retirement | None,
    now: datetime,
    stale_days: int = LANE_STALE_DAYS,
) -> LaneVerdict:
    if retirement is not None:
        return LaneVerdict(
            state=RETIRED,
            basis="operator",
            reason=f"Retired by {retirement.retired_by}: {retirement.reason}",
            retirement=retirement,
            reported_since_retired=last_run_at is not None
            and last_run_at > retirement.retired_at,
        )
    inferred = config_retirement(
        pipeline=pipeline, capability=capability, tool_name=tool_name, job=job, config=config
    )
    if inferred is not None:
        return LaneVerdict(state=RETIRED, basis="config", reason=inferred)
    if last_run_at is None:
        return LaneVerdict(
            state=STALE, basis="never_finished", reason="It has never finished a run."
        )
    age = now - last_run_at
    if age > timedelta(days=stale_days):
        return LaneVerdict(
            state=STALE,
            basis="age",
            reason=(
                f"No run for {age.days} days, and nothing says it was retired: "
                "a lane that stopped is broken until somebody says otherwise."
            ),
        )
    return LaneVerdict(state=CURRENT, basis="", reason="")


def lane_key(tool_name: str | None, job: str | None) -> tuple[str, str]:
    """How a lane is matched to its retirement: absent parts are empty."""
    return (tool_name or "", job or "")


def with_states(
    lanes: Iterable[dict[str, Any]],
    *,
    repo_full_name: str,
    capability: str,
    config: dict[str, Any] | None,
    retirements: dict[tuple[str, str], Retirement],
    now: datetime,
) -> list[dict[str, Any]]:
    """`ScanRunReport.lanes` rows, each with its state, basis and reason."""
    pipeline = ci.pipeline_name_for(repo_full_name)
    out: list[dict[str, Any]] = []
    for lane in lanes:
        last = lane.get("last_run_at")
        if isinstance(last, datetime) and last.tzinfo is not None:
            last = last.replace(tzinfo=None)
        retirement = retirements.get(lane_key(lane.get("tool_name"), lane.get("job")))
        verdict = classify(
            pipeline=pipeline,
            capability=capability,
            tool_name=lane.get("tool_name"),
            job=lane.get("job"),
            last_run_at=last if isinstance(last, datetime) else None,
            config=config,
            retirement=retirement,
            now=now,
        )
        out.append(
            {
                **lane,
                "state": verdict.state,
                "state_basis": verdict.basis,
                "state_reason": verdict.reason,
                "retired_by": retirement.retired_by if retirement else None,
                "retired_at": retirement.retired_at if retirement else None,
                "reported_since_retired": verdict.reported_since_retired,
            }
        )
    return out
