"""Next-sprint candidates, ranked and filed to TheHub's backlog (TheHub #60862,
epic #60858).

The daily briefing already lists what would close the most of a product's
open findings (`daily_briefing.next_sprint_candidates`). This ranks those
candidates across the estate by one score, files the ones that are not on the
board yet to TheHub's backlog, and measures whether that changed anything.

**The score, and every factor of it, is on the page.**

    score = risk removed x exposure / effort

- *risk removed*: the findings the change would close, each weighted by its
  *contextual* band (`SEVERITY_WEIGHT`): the effective severity of a stored
  environmental score in force for it, else the scanner's own band, and the
  line says which (TheHub #61348). The scanner's bands stay in `risk_basis`
  beside the contextual ones in `contextual_basis`. A lane repair removes the
  risk of the open findings it holds: they cannot close until it scans.
- *exposure*: where *these findings* run (`exposure_for`), not where the
  repository does. Internet only when a finding sits in a surface the internet
  was observed to reach: a public endpoint the exposure probe reached, or a
  fresh `port_published` observation from the internet vantage. A surface only
  *declared* internet-facing is shown as declared and does not raise it. Then
  deployed (the deployment probe, or a public endpoint elsewhere in the
  repository), or neither. Until TheHub #61348 one public endpoint gave every
  finding in its repository the internet factor.
- *effort*: what kind of change it is (`EFFORT_WEIGHT`, from the scanner's
  own fix text through `guidance`), or a lane repair.

**A group with no fix is not a fix candidate.** When the scanner says no fixed
version is published (`guidance` effort `no_fix`), nothing can be changed, so
it is an *acceptance* candidate (`kind="acceptance"`): accept with
`no_vendor_fix` and a review date, or mitigate. It is listed apart and never
filed as a story (TheHub #61348; #61335 was one).

Each candidate carries the three numbers and what each was read from, and its
line says them, so a ranking can be argued with item by item.

**Filing is idempotent.** Every candidate has a `signal_key`, a hash of the
repository and the fix (or lane) it is about, so the same candidate keeps its
key from day to day. A filed story carries the key in its tags, `source_ref`
and detail. The daily `briefing-signal-filing` job reads the whole board
first and files nothing whose key is on a story already, in any bucket, nor
anything the briefing's own matcher (`daily_briefing.on_board`, B3) says is a
story already. It files to the backlog only, tagged `briefing-signal`: the
backlog is where Todd decides (three options and a recommendation in each
story); nothing here moves a story into a sprint (D-170).

**The weekly success metric** is the share of a week's sprint stories that are
tagged `briefing-signal`, the risk those stories claimed when they were filed,
and beside it the risk MyKronos verified removed: the findings of each done
story's fix that have since closed by absence (`weekly_metric`).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from sqlalchemy import select

from mykronos.jobs import SIGNAL_FILING_JOB, JobNotDue, JobSkipped, _succeeded_today
from mykronos.schemas import utcnow

if TYPE_CHECKING:  # pragma: no cover - import-cycle guard
    from mykronos.api.briefing_daily import DailyBriefingOut
    from mykronos.briefing import Briefing
    from mykronos.lake.catalog import Catalog

logger = logging.getLogger(__name__)

# The `job_runs` row, and the name MyKronos Health shows, is
# `jobs.SIGNAL_FILING_JOB` ("briefing-signal-filing"), imported above.

#: How often the scheduler asks whether today's filing is owed. The job acts
#: once a UTC day (its own `job_runs` row says whether it has), so a restart
#: does not file twice.
TICK_SECONDS = 3600

#: The tag every story this files carries, and the metric counts.
SIGNAL_TAG = "briefing-signal"
#: The tag that carries a story's signal key: `briefing-signal:<key>`.
KEY_TAG_PREFIX = f"{SIGNAL_TAG}:"
SOURCE_KIND = "mykronos-briefing"

#: How many candidates one day's run files, at most, highest score first. The
#: backlog is somebody's reading list: a day's ranking is not dumped into it.
FILE_LIMIT = 3

#: How many ranked candidates the briefing's suggested focus carries.
FOCUS_TOP = 3

#: Risk per finding by the scanner's severity. A severity nobody recorded is
#: counted at `UNKNOWN_WEIGHT`, never as nothing.
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.0,
}
UNKNOWN_WEIGHT = 1.0

#: Where the code runs. Read from the briefing's own inputs: the public
#: endpoint probes (`exposure`) and the deployment probe sweep.
INTERNET = 3.0
DEPLOYED = 2.0
NOT_DEPLOYED = 1.0

#: Effort by the kind of change `guidance` says it is.
EFFORT_WEIGHT: dict[str, float] = {
    "config": 1.0,
    "upgrade": 2.0,
    "rotate": 2.0,
    "judgement": 3.0,
    "no_fix": 5.0,
}
LANE_REPAIR_EFFORT = 2.0

FORMULA = "score = risk removed x exposure / effort"

#: TheHub's title column. A longer title is cut at a word (`story_title`).
TITLE_LIMIT = 255

#: Where a candidate's findings run, as `Candidate.exposure_state`.
EXPOSURE_STATES = (
    "internet_observed",
    "declared_internet",
    "deployed",
    "not_deployed",
    "not_measured",
)


@dataclass
class Candidate:
    """One change worth a sprint, and why it ranks where it does."""

    signal_key: str
    #: fix | lane
    kind: str
    repo_full_name: str
    capability: str
    #: The change itself, as the line's `what`.
    title: str
    #: The fix id (`guidance`), so B3's matcher can find a story that names
    #: it. Empty for a lane repair.
    ref: str
    findings: int
    risk_removed: float
    #: severity -> findings, what the risk was weighed from.
    risk_basis: dict[str, int]
    exposure: float
    exposure_basis: str
    effort: float
    effort_basis: str
    score: float
    #: Ordered steps from `guidance`, when it has them.
    steps: list[str] = field(default_factory=list)
    #: One of `EXPOSURE_STATES` (TheHub #61348). Empty on a candidate built
    #: before it existed.
    exposure_state: str = ""
    #: severity -> findings at the *contextual* band, what `risk_removed` is
    #: weighed from. Equal to `risk_basis` where no environmental score is in
    #: force.
    contextual_basis: dict[str, int] = field(default_factory=dict)
    #: How many of `findings` had an environmental score in force.
    contextual_scored: int = 0

    def explain(self) -> str:
        risk = ", ".join(f"{n} {sev}" for sev, n in self.risk_basis.items()) or "none"
        return (
            f"Score {self.score:g} = risk removed {self.risk_removed:g} x exposure "
            f"{self.exposure:g} / effort {self.effort:g}. Risk: {self.findings} finding(s) "
            f"(scanner: {risk}; {self._contextual()}); exposure: {self.exposure_basis}; "
            f"effort: {self.effort_basis}."
        )

    def _contextual(self) -> str:
        if not self.contextual_basis or self.kind == "lane":
            return "contextual: not assessed for a lane repair"
        if not self.contextual_scored:
            return "contextual: the scanner's bands, no environmental score in force"
        bands = ", ".join(f"{n} {sev}" for sev, n in self.contextual_basis.items())
        return (
            f"contextual: {bands}, from the environmental score in force for "
            f"{self.contextual_scored} of {self.findings}"
        )

    def factors(self) -> dict[str, Any]:
        return asdict(self)


def weights() -> dict[str, Any]:
    """Every weight the score uses, for the page to show beside it."""
    return {
        "severity": dict(SEVERITY_WEIGHT),
        "unknown_severity": UNKNOWN_WEIGHT,
        "exposure": {"internet": INTERNET, "deployed": DEPLOYED, "not_deployed": NOT_DEPLOYED},
        "effort": {**EFFORT_WEIGHT, "lane_repair": LANE_REPAIR_EFFORT},
    }


def repos(db: Any) -> list[str]:
    """Every product the portfolio shows: not removed, not the synthetic
    benchmark corpus."""
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        rows = session.execute(
            select(RepoOnboarding.github_repo_full_name)
            .where(RepoOnboarding.status != "removed")
            .where(RepoOnboarding.synthetic.is_(False))
            .order_by(RepoOnboarding.github_repo_full_name)
        ).scalars()
        return [str(name) for name in rows]


def signal_key(repo_full_name: str, kind: str, ident: str) -> str:
    """Stable across days: the same change in the same repository keeps it."""
    digest = hashlib.sha256(f"{repo_full_name}|{kind}|{ident}".encode()).hexdigest()
    return digest[:16]


def risk(severities: dict[str, int]) -> float:
    return round(
        sum(SEVERITY_WEIGHT.get(sev, UNKNOWN_WEIGHT) * n for sev, n in severities.items()), 2
    )


def _ordered(severities: dict[str, int]) -> dict[str, int]:
    order = [*SEVERITY_WEIGHT, "unknown"]
    known = {s: severities[s] for s in order if severities.get(s)}
    known.update(sorted((s, n) for s, n in severities.items() if s not in known and n))
    return known


def deployment_of(report: Briefing | None, repo: str) -> tuple[float, str, str]:
    """(factor, what it was read from, state) for one repository as a whole.

    Never `INTERNET`: whether the internet reaches a finding is a fact about the
    finding (`exposure_for`), and a public endpoint somewhere in the repository
    says the repository is deployed, not that every finding in it sits behind
    that endpoint (TheHub #61348).
    """
    unread = "not measured: the deployment record could not be read"
    if report is None:
        return NOT_DEPLOYED, unread, "not_measured"
    if any(str(e.get("repo_full_name") or "") == repo for e in report.exposure or []):
        return (
            DEPLOYED,
            "deployed with a public endpoint, but these findings are not placed behind "
            "it and no internet observation covers them",
            "deployed",
        )
    if any(lag.repo_full_name == repo for lag in report.production_lag or []):
        return (
            DEPLOYED,
            "deployed (the deployment probe tracks it), no public endpoint probed",
            "deployed",
        )
    if report.production_lag_unknown and report.exposure_unknown:
        return NOT_DEPLOYED, unread, "not_measured"
    return NOT_DEPLOYED, "no deployment or public endpoint on record", "not_deployed"


def exposure_of(report: Briefing | None, repo: str) -> tuple[float, str]:
    """(factor, what it was read from) for one repository: `deployment_of`."""
    factor, basis, _state = deployment_of(report, repo)
    return factor, basis


@dataclass
class _Placement:
    """What one repository's surfaces say about where its findings run."""

    surfaces: list[Any] = field(default_factory=list)
    #: surface id -> how the internet was observed to reach it.
    internet: dict[str, str] = field(default_factory=dict)
    #: host -> the public endpoint's label, for DAST findings by target host.
    probed_hosts: dict[str, str] = field(default_factory=dict)
    #: False when there is no database to read: nothing is placed.
    read: bool = True


def _placement(db: Any, repo: str, now: datetime) -> _Placement:
    """Surfaces, and which of them the internet was *observed* to reach.

    Two observations count, both fresh (`control_observations.FRESH_DAYS`): a
    public endpoint the exposure probe reached (`last_status == probed`) linked
    to the surface, and a `port_published` observation that passed from the
    `internet` vantage. A declared exposure is read from the surface itself
    and never counts here.
    """
    from types import SimpleNamespace

    from mykronos import control_observations, exposure
    from mykronos.db.models import ControlObservation, PublicEndpoint, RepoSurface

    if db is None:
        return _Placement(read=False)
    fresh_after = now - timedelta(days=control_observations.FRESH_DAYS)
    out = _Placement()
    with db.session() as session:
        for row in session.scalars(
            select(RepoSurface).where(RepoSurface.repo_full_name == repo)
        ):
            out.surfaces.append(
                SimpleNamespace(
                    id=str(row.id),
                    kind=str(row.kind),
                    name=str(row.name),
                    exposure=str(row.exposure or "unknown"),
                    selectors=dict(row.selectors or {}),
                )
            )
        for endpoint in session.scalars(
            select(PublicEndpoint).where(PublicEndpoint.repo_full_name == repo)
        ):
            probed = endpoint.last_probed_at
            if endpoint.last_status != exposure.PROBED or probed is None:
                continue
            if probed.replace(tzinfo=None) < fresh_after:
                continue
            label = str(endpoint.label or "its public endpoint")
            if endpoint.surface_id:
                out.internet.setdefault(
                    str(endpoint.surface_id), f"the exposure probe reached {label}"
                )
            host = urlsplit(str(endpoint.url or "")).hostname
            if host:
                out.probed_hosts[host.lower()] = label
        for observed in session.scalars(
            select(ControlObservation).where(
                ControlObservation.repo_full_name == repo,
                ControlObservation.vantage == "internet",
                ControlObservation.assertion == "port_published",
                ControlObservation.state == "pass",
            )
        ):
            collected = observed.collected_at
            if observed.surface_id is None or collected is None:
                continue
            if collected.replace(tzinfo=None) < fresh_after:
                continue
            out.internet.setdefault(
                str(observed.surface_id), "a port observed published from the internet"
            )
    return out


def _dast_host(finding: dict[str, Any]) -> str | None:
    """The host a DAST finding's request went to, lower-cased."""
    raw = finding.get("raw_finding_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, dict):
        return None
    instance = raw.get("instance")
    uri = instance.get("uri") if isinstance(instance, dict) else None
    host = urlsplit(str(uri or "")).hostname
    return host.lower() if host else None


def exposure_for(
    findings: list[dict[str, Any]],
    placement: _Placement,
    report: Briefing | None,
    repo: str,
) -> tuple[float, str, str]:
    """(factor, what it was read from, state) for the findings one change closes.

    Internet only when at least one of *these* findings sits in a surface the
    internet was observed to reach, or is a DAST finding against a host the
    exposure probe reached. Otherwise the repository's deployment, with a
    surface that is only *declared* internet-facing named as declared.
    """
    from mykronos import surface_match

    deployed, deployed_basis, deployed_state = deployment_of(report, repo)
    if not placement.read:
        return deployed, f"{deployed_basis} (per-finding exposure not read)", deployed_state

    observed: dict[str, int] = {}
    declared: dict[str, int] = {}
    for finding in findings:
        host = _dast_host(finding) if finding.get("capability") == "dast" else None
        if host and host in placement.probed_hosts:
            key = f"{placement.probed_hosts[host]} (the exposure probe reached it)"
            observed[key] = observed.get(key, 0) + 1
            continue
        surface = surface_match.surface_for(finding, placement.surfaces)
        if surface is None:
            continue
        how = placement.internet.get(str(surface.id))
        if how:
            key = f"{surface.name} ({how})"
            observed[key] = observed.get(key, 0) + 1
        elif getattr(surface, "exposure", "") == "internet":
            declared[surface.name] = declared.get(surface.name, 0) + 1

    if observed:
        where = "; ".join(f"{n} in {name}" for name, n in sorted(observed.items()))
        return (
            INTERNET,
            f"observed reachable from the internet: {sum(observed.values())} of "
            f"{len(findings)} finding(s): {where}",
            "internet_observed",
        )
    if declared:
        names = ", ".join(sorted(declared))
        counted = "deployed" if deployed == DEPLOYED else "not deployed"
        return (
            deployed,
            f"declared internet-facing ({names}), not observed: counted as {counted}",
            "declared_internet",
        )
    return deployed, deployed_basis, deployed_state


def _score(risk_removed: float, exposure: float, effort: float) -> float:
    return round(risk_removed * exposure / effort, 2) if effort else 0.0


def open_severities(catalog: Catalog, repos: list[str]) -> dict[tuple[str, str], dict[str, int]]:
    """(repo, capability) -> severity -> open findings: what a stalled lane holds."""
    if not repos or not catalog.all_files("findings"):
        return {}
    placeholders = ", ".join("?" for _ in repos)
    rows = catalog.query(
        f"""
        SELECT asset_id, capability, lower(coalesce(severity, '')), count(*)
        FROM findings WHERE status = 'open' AND asset_id IN ({placeholders})
        GROUP BY 1, 2, 3
        """,
        repos,
    )
    out: dict[tuple[str, str], dict[str, int]] = {}
    for repo, capability, severity, count in rows:
        bucket = out.setdefault((str(repo), str(capability)), {})
        bucket[str(severity or "unknown")] = int(count)
    return out


def _open_findings(catalog: Catalog, repo: str) -> dict[str, dict[str, Any]]:
    """finding id -> the fields placement and the contextual band read."""
    if not catalog.all_files("findings"):
        return {}
    rows = catalog.query(
        """
        SELECT finding_id, capability, file_path, raw_finding_json, address, port,
               lower(coalesce(severity, ''))
        FROM findings WHERE status = 'open' AND asset_id = ?
        """,
        [repo],
    )
    return {
        str(fid): {
            "finding_id": str(fid),
            "capability": str(capability or ""),
            "file_path": file_path,
            "raw_finding_json": raw,
            "address": address,
            "port": port,
            "severity": str(severity or "unknown"),
        }
        for fid, capability, file_path, raw, address, port, severity in rows
    }


def _contextual_bands(db: Any, finding_ids: list[str], now: datetime) -> dict[str, str]:
    """finding id -> the effective severity of an environmental score in force.

    In force means `environment_view.rank_reading` reads it as `scored`: not
    lapsed on an expired lowering fact. A finding with no such score is absent,
    and its contextual band is the scanner's.
    """
    if db is None or not finding_ids:
        return {}
    from mykronos import environment_view
    from mykronos.db.models import EnvironmentalScore

    out: dict[str, str] = {}
    ids = list(dict.fromkeys(finding_ids))
    with db.session() as session:
        for start in range(0, len(ids), 500):
            for row in session.scalars(
                select(EnvironmentalScore).where(
                    EnvironmentalScore.finding_id.in_(ids[start : start + 500])
                )
            ):
                reading = environment_view.rank_reading(row, now)
                if reading is not None and reading.state == "scored":
                    out[str(row.finding_id)] = str(row.effective_severity).lower()
    return out


def rank(
    catalog: Catalog,
    report: Briefing | None,
    repos: list[str],
    *,
    db: Any = None,
    now: datetime | None = None,
) -> list[Candidate]:
    """Every candidate on these repositories, highest score first.

    `db` is the operational database. Without it findings cannot be placed in
    a surface or read for an environmental score, so exposure falls back to
    the repository's deployment and the contextual band to the scanner's, and
    each line says so.

    Raises when the lake cannot be read; a section built from it says so.
    """
    from mykronos import guidance

    moment = (now or utcnow()).replace(tzinfo=None)
    candidates: list[Candidate] = []
    held = open_severities(catalog, repos)
    for lane in report.stalled if report else []:
        if lane.repo_full_name not in repos:
            continue
        basis = held.get((lane.repo_full_name, lane.capability)) or (
            {"unknown": lane.open_findings} if lane.open_findings else {}
        )
        exposure, exposure_basis, exposure_state = deployment_of(report, lane.repo_full_name)
        removed = risk(basis)
        candidates.append(
            Candidate(
                signal_key=signal_key(lane.repo_full_name, "lane", lane.capability),
                kind="lane",
                repo_full_name=lane.repo_full_name,
                capability=lane.capability,
                title=f"Repair the {lane.capability} lane ({lane.reason}) in "
                f"{lane.repo_full_name}.",
                ref="",
                findings=sum(basis.values()),
                risk_removed=removed,
                risk_basis=_ordered(basis),
                exposure=exposure,
                exposure_basis=exposure_basis,
                effort=LANE_REPAIR_EFFORT,
                effort_basis="a lane repair: its open findings cannot close until it "
                "scans successfully twice",
                score=_score(removed, exposure, LANE_REPAIR_EFFORT),
                exposure_state=exposure_state,
            )
        )
    for repo in repos:
        groups = guidance.fix_groups(catalog, asset_id=repo)
        if not groups:
            continue
        rows = _open_findings(catalog, repo)
        placement = _placement(db, repo, moment)
        contextual = _contextual_bands(
            db, [fid for g in groups for fid in g.finding_ids], moment
        )
        for group in groups:
            basis = group.severities or {"unknown": group.findings}
            members = [rows[fid] for fid in group.finding_ids if fid in rows]
            context_counts: dict[str, int] = {}
            for member in members:
                band = contextual.get(member["finding_id"], member["severity"])
                context_counts[band] = context_counts.get(band, 0) + 1
            if not context_counts:
                context_counts = dict(basis)
            scored = sum(1 for m in members if m["finding_id"] in contextual)
            exposure, exposure_basis, exposure_state = exposure_for(
                members, placement, report, repo
            )
            no_fix = group.effort == "no_fix"
            effort = EFFORT_WEIGHT.get(group.effort, EFFORT_WEIGHT["judgement"])
            removed = risk(context_counts)
            title = group.full_action or group.action
            candidates.append(
                Candidate(
                    signal_key=signal_key(repo, "fix", group.fix_id),
                    kind="acceptance" if no_fix else "fix",
                    repo_full_name=repo,
                    capability=group.capability,
                    title=(
                        f"Accept with no_vendor_fix and a review date, or mitigate: {title}"
                        if no_fix
                        else title
                    ),
                    ref=group.fix_id,
                    findings=group.findings,
                    risk_removed=removed,
                    risk_basis=_ordered(basis),
                    exposure=exposure,
                    exposure_basis=exposure_basis,
                    effort=effort,
                    effort_basis=(
                        "no_fix: the scanner reports no fixed version published, so "
                        "there is no change to make"
                        if no_fix
                        else f"{group.effort} ({len(group.rules)} rule(s), per the "
                        "scanner's fix text)"
                    ),
                    score=_score(removed, exposure, effort),
                    steps=[] if no_fix else list(group.steps),
                    exposure_state=exposure_state,
                    contextual_basis=_ordered(context_counts),
                    contextual_scored=scored,
                )
            )
    candidates.sort(key=lambda c: (-c.score, -c.risk_removed, c.repo_full_name, c.title))
    return candidates


def story_title(text: str, limit: int = TITLE_LIMIT) -> str:
    """`text` as a story title: whole when it fits, else cut at a word with an
    ellipsis. Never mid-word (TheHub #61348: "gcc: Integer wrap in `std")."""
    clean = " ".join(str(text or "").split())
    if len(clean) <= limit:
        return clean
    head = clean[: limit - 1]
    cut = head.rfind(" ")
    if cut > 0:
        head = head[:cut]
    return head.rstrip(" ,;:-") + "…"


# ---------------------------------------------------------------------------
# On the board already
# ---------------------------------------------------------------------------


def key_tag(key: str) -> str:
    return f"{KEY_TAG_PREFIX}{key}"


def story_key(story: dict[str, Any]) -> str | None:
    """The signal key a filed story carries, wherever it carries it."""
    for tag in story.get("tags") or []:
        if isinstance(tag, str) and tag.startswith(KEY_TAG_PREFIX):
            return tag[len(KEY_TAG_PREFIX):]
    ref = str(story.get("source_ref") or "")
    if ref.startswith(KEY_TAG_PREFIX):
        return ref[len(KEY_TAG_PREFIX):]
    match = _KEY_IN_DETAIL.search(str(story.get("detail") or ""))
    return match.group(1) if match else None


_KEY_IN_DETAIL = re.compile(r"MyKronos signal `([0-9a-f]{16})`")
_RISK_IN_DETAIL = re.compile(r"risk removed ([0-9]+(?:\.[0-9]+)?)")


def is_signal(story: dict[str, Any]) -> bool:
    return SIGNAL_TAG in (story.get("tags") or []) or story_key(story) is not None


def already_filed(
    candidate: Candidate, stories: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The story this candidate already is: by its key in any bucket, or by
    the briefing's own matcher (fix id or title) among open stories."""
    from mykronos.daily_briefing import STORY, Line, on_board

    for story in stories:
        if story_key(story) == candidate.signal_key:
            return story
    open_stories = [s for s in stories if s.get("bucket") != "done"]
    return on_board(
        Line(what=candidate.title, so_what="", work=STORY, ref=candidate.ref), open_stories
    )


# ---------------------------------------------------------------------------
# The story
# ---------------------------------------------------------------------------


def story_payload(candidate: Candidate, *, rank_at: int) -> dict[str, Any]:
    """A backlog story: what, why it ranks, three options and a recommendation.

    Refuses an acceptance candidate: a group with no fix has no change to make,
    and a story recommending one cannot be done (TheHub #61348, #61335).
    """
    if candidate.kind == "acceptance":
        raise ValueError(
            "an acceptance candidate is not a story: no fix exists, so it is an "
            "operator decision (accept with no_vendor_fix, or mitigate)"
        )
    steps = "".join(f"\n   - {step}" for step in candidate.steps)
    accept = (
        "Record a risk acceptance for these findings in MyKronos, with a premise and "
        "an end date, and close this story."
        if candidate.kind == "fix"
        else "Retire the lane on purpose (remove the capability from the repository's "
        "onboarding) and close this story; its findings then need an owner."
    )
    detail = "\n".join(
        [
            f"**{candidate.title}** ({candidate.repo_full_name}, {candidate.capability})",
            "",
            f"Ranked #{rank_at} of the daily briefing's next-sprint candidates.",
            "",
            f"{candidate.explain()}",
            "",
            "**Options**",
            "",
            f"1. **Pull it into the next sprint** and make the change.{steps}",
            "2. **Leave it in the backlog** and revisit when its score changes; the "
            "briefing re-ranks it every morning.",
            f"3. **Accept the risk.** {accept}",
            "",
            "**Recommendation:** option 1"
            + (
                ": it is the top-ranked candidate on the estate today."
                if rank_at == 1
                else f": it ranks #{rank_at} by risk removed per unit of effort."
            ),
            "",
            f"MyKronos signal `{candidate.signal_key}`; risk removed "
            f"{candidate.risk_removed:g}. Filed by the `{SIGNAL_FILING_JOB}` job "
            "(TheHub #60862). The signal key is how the job knows not to file it again.",
        ]
    )
    if candidate.kind == "fix":
        criteria = [
            f"A re-scan of {candidate.repo_full_name} no longer reports the "
            f"{candidate.findings} {candidate.capability} finding(s) this change covers "
            f"({candidate.ref}).",
        ]
    else:
        criteria = [
            f"The {candidate.capability} lane on {candidate.repo_full_name} completes "
            "two successful scans in a row.",
        ]
    return {
        "title": story_title(candidate.title),
        "detail": detail,
        "bucket": "backlog",
        "tags": [SIGNAL_TAG, key_tag(candidate.signal_key), f"repo:{candidate.repo_full_name}"],
        "source_kind": SOURCE_KIND,
        "source_ref": key_tag(candidate.signal_key),
        "acceptance_criteria": criteria,
    }


# ---------------------------------------------------------------------------
# The weekly success metric
# ---------------------------------------------------------------------------


def _week_start(now: datetime) -> datetime:
    day = now.astimezone(UTC).replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
    return day - timedelta(days=day.weekday())


def _risk_of(story: dict[str, Any]) -> float:
    match = _RISK_IN_DETAIL.search(str(story.get("detail") or ""))
    return float(match.group(1)) if match else 0.0


#: The fix id a filed story's acceptance criterion names: "... ({ref})."
_REF_IN_CRITERION = re.compile(r"\(([a-z_]+:[^()]+)\)\.?\s*$")


def _target(story: dict[str, Any]) -> tuple[str, str] | None:
    """(repository, fix id) a filed fix story is about, or None (a lane)."""
    repo = next(
        (
            tag[len("repo:"):]
            for tag in story.get("tags") or []
            if isinstance(tag, str) and tag.startswith("repo:")
        ),
        None,
    )
    for criterion in story.get("acceptance_criteria") or []:
        match = _REF_IN_CRITERION.search(str(criterion))
        if match and repo:
            return repo, match.group(1)
    return None


def _verified(
    catalog: Catalog, story: dict[str, Any], since: datetime | None
) -> tuple[float, int]:
    """(risk, findings) of the story's fix that MyKronos has closed since it
    was filed. `fixed` is only ever set by absence or a verification scan;
    nobody may hand-set it, so it is what "verified removed" means here."""
    from mykronos import guidance

    target = _target(story)
    if target is None:
        return 0.0, 0
    repo, ref = target
    for group in guidance.fix_groups(
        catalog, asset_id=repo, status="fixed", resolved_since=since
    ):
        if group.fix_id == ref:
            return risk(group.severities), group.findings
    return 0.0, 0


def weekly_metric(
    board: Any, *, now: datetime, catalog: Catalog | None = None
) -> dict[str, Any]:
    """This week's and last week's share of sprint stories tagged
    `briefing-signal`, the risk those stories claimed, and the risk MyKronos
    verified removed.

    A week starts Monday 00:00 UTC. Its sprint stories are those done in it
    (by `closed_at`) and, for the current week, those in the sprint bucket now:
    the board keeps no history of who was in a past sprint, so a past week is
    measured by what it finished.

    *Claimed* (`risk_claimed`, and `risk_removed` as it was always called) is
    the `risk removed` each tagged story recorded when it was filed, summed
    over the ones done in the week. *Verified* (`risk_verified_removed`,
    TheHub #61348) is, for the same stories, the scanner-weighted risk of the
    findings of their fix that MyKronos has closed (`fixed`) since the story
    was created; null when the lake was not given, which is not zero.
    """
    from mykronos.po_console import parse_time

    def naive(value: Any) -> datetime | None:
        moment = parse_time(value)
        if moment is None:
            return None
        return moment.astimezone(UTC).replace(tzinfo=None) if moment.tzinfo else moment

    start = _week_start(now)
    weeks = []
    for begin, end, current in (
        (start, start + timedelta(days=7), True),
        (start - timedelta(days=7), start, False),
    ):
        done = [
            s for s in board.stories.get("done", [])
            if (closed := naive(s.get("closed_at"))) is not None and begin <= closed < end
        ]
        stories = done + (list(board.stories.get("sprint", [])) if current else [])
        tagged = [s for s in stories if is_signal(s)]
        claimed = round(sum(_risk_of(s) for s in done if is_signal(s)), 2)
        verified: float | None = None
        closed_count: int | None = None
        if catalog is not None:
            total, count = 0.0, 0
            for s in done:
                if is_signal(s):
                    weight, found = _verified(catalog, s, naive(s.get("created_at")))
                    total += weight
                    count += found
            verified, closed_count = round(total, 2), count
        weeks.append(
            {
                "week_start": begin.date().isoformat(),
                "current": current,
                "sprint_stories": len(stories),
                "briefing_signal_stories": len(tagged),
                "share": round(len(tagged) / len(stories), 3) if stories else None,
                "done_briefing_signal_stories": sum(1 for s in done if is_signal(s)),
                "risk_removed": claimed,
                "risk_claimed": claimed,
                "risk_verified_removed": verified,
                "findings_verified_closed": closed_count,
            }
        )
    return {
        "measured_by": "TheHub board: sprint bucket now plus stories closed in the "
        "week; risk claimed as recorded on each tagged story when it was filed; "
        "risk verified removed from the lake: the findings of each done story's fix "
        "that MyKronos closed after the story was created, at the scanner's weights",
        "tag": SIGNAL_TAG,
        "weeks": weeks,
    }


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------


#: How the overall briefing is read: through its own route, like the DM.
BriefingReader = Callable[[str | None], Awaitable["DailyBriefingOut"]]


@dataclass
class FilingResult:
    filed: list[dict[str, Any]] = field(default_factory=list)
    #: (signal key, why) for candidates left alone.
    skipped: list[tuple[str, str]] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"filed {len(self.filed)}, already stories {len(self.skipped)}, "
            f"failed {len(self.failed)}"
        )


class SignalFilingError(RuntimeError):
    """A story TheHub would not take. Raised after the rest are tried, so the
    run reads `failing` and tomorrow's retries; the message is ours."""


def _candidate(row: dict[str, Any]) -> Candidate:
    return Candidate(**{k: row[k] for k in Candidate.__dataclass_fields__ if k in row})


async def _whole_board(hub: Any) -> list[dict[str, Any]]:
    """Every bucket, fresh: the cache that serves the page is not enough to
    decide that something is not a story yet."""
    from mykronos.delivery_sources import BOARD_BUCKETS

    lists = await asyncio.gather(*(hub.list_stories(bucket) for bucket in BOARD_BUCKETS))
    return [
        {**story, "bucket": story.get("bucket") or bucket}
        for bucket, stories in zip(BOARD_BUCKETS, lists, strict=True)
        for story in stories
    ]


async def file_signals(
    *,
    db: Any,
    hub: Any,
    read: BriefingReader,
    now: datetime | None = None,
    job_name: str = SIGNAL_FILING_JOB,
    limit: int = FILE_LIMIT,
) -> FilingResult:
    """File today's top candidates that are not stories yet.

    Raises `JobNotDue` once today's run has succeeded, `JobSkipped` when TheHub
    is not connected, and `SignalFilingError` when TheHub refused a story.
    """
    from mykronos.delivery_sources import HUB_NOT_CONNECTED

    moment = now or datetime.now(UTC)
    if _succeeded_today(db, job_name, moment):
        raise JobNotDue
    if hub is None:
        raise JobSkipped(HUB_NOT_CONNECTED)

    overall = await read(None)
    section = next((s for s in overall.sections if s.key == NEXT_SPRINT_KEY), None)
    if section is None or section.status not in ("ok", "partial"):
        why = section.reason if section is not None else "the section is missing"
        raise RuntimeError(f"Next-sprint candidates could not be ranked: {why}")

    stories = await _whole_board(hub)
    result = FilingResult()
    # An acceptance candidate is never filed, wherever it came from (#61348).
    ranked = [
        c
        for c in (_candidate(row) for row in section.data.get("candidates") or [])
        if c.kind != "acceptance"
    ]
    for position, candidate in enumerate(ranked, start=1):
        if len(result.filed) >= limit:
            break
        story = already_filed(candidate, stories)
        if story is not None:
            result.skipped.append((candidate.signal_key, f"TheHub #{story.get('id')}"))
            continue
        payload = story_payload(candidate, rank_at=position)
        outcome = await hub.create_story(payload)
        if not outcome.ok:
            result.failed.append((candidate.signal_key, outcome.detail or "refused"))
            continue
        body = outcome.body if isinstance(outcome.body, dict) else {}
        filed = {**payload, "id": body.get("id"), "bucket": "backlog"}
        result.filed.append(filed)
        # A second candidate the same story covers is not filed twice.
        stories.append(filed)
    logger.info("Briefing signal filing: %s", result.summary())
    if result.failed:
        raise SignalFilingError(
            f"TheHub refused {len(result.failed)} story(ies): "
            + "; ".join(why for _, why in result.failed)
            + f" ({result.summary()})"
        )
    return result


#: The overall briefing section this ranks into (`daily_briefing`).
NEXT_SPRINT_KEY = "next_sprint"
