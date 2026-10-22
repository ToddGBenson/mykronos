"""Next-sprint candidates, ranked and filed to TheHub's backlog (TheHub #60862,
epic #60858).

The daily briefing already lists what would close the most of a product's
open findings (`daily_briefing.next_sprint_candidates`). This ranks those
candidates across the estate by one score, files the ones that are not on the
board yet to TheHub's backlog, and measures whether that changed anything.

**The score, and every factor of it, is on the page.**

    score = risk removed x exposure / effort

- *risk removed*: the findings the change would close, each weighted by the
  severity the scanner gave it (`SEVERITY_WEIGHT`). A lane repair removes the
  risk of the open findings it holds: they cannot close until it scans.
- *exposure*: where the code runs (`EXPOSURE`): an endpoint the public probes
  reach, a deployment the probe sweep knows, or neither.
- *effort*: what kind of change it is (`EFFORT_WEIGHT`, from the scanner's
  own fix text through `guidance`), or a lane repair.

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
tagged `briefing-signal`, and the risk those stories removed, read from the
board (`weekly_metric`).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from mykronos.jobs import SIGNAL_FILING_JOB, JobNotDue, JobSkipped, _succeeded_today

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

    def explain(self) -> str:
        risk = ", ".join(f"{n} {sev}" for sev, n in self.risk_basis.items()) or "none"
        return (
            f"Score {self.score:g} = risk removed {self.risk_removed:g} x exposure "
            f"{self.exposure:g} / effort {self.effort:g}. Risk: {self.findings} finding(s) "
            f"({risk}); exposure: {self.exposure_basis}; effort: {self.effort_basis}."
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


def exposure_of(report: Briefing | None, repo: str) -> tuple[float, str]:
    """(factor, what it was read from) for one repository."""
    if report is None:
        return NOT_DEPLOYED, "not measured: the deployment record could not be read"
    if any(str(e.get("repo_full_name") or "") == repo for e in report.exposure or []):
        return INTERNET, "a public endpoint the exposure probes reach"
    if any(lag.repo_full_name == repo for lag in report.production_lag or []):
        return DEPLOYED, "deployed (the deployment probe tracks it), no public endpoint probed"
    if report.production_lag_unknown and report.exposure_unknown:
        return NOT_DEPLOYED, "not measured: the deployment record could not be read"
    return NOT_DEPLOYED, "no deployment or public endpoint on record"


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


def rank(catalog: Catalog, report: Briefing | None, repos: list[str]) -> list[Candidate]:
    """Every candidate on these repositories, highest score first.

    Raises when the lake cannot be read; a section built from it says so.
    """
    from mykronos import guidance

    candidates: list[Candidate] = []
    held = open_severities(catalog, repos)
    for lane in report.stalled if report else []:
        if lane.repo_full_name not in repos:
            continue
        basis = held.get((lane.repo_full_name, lane.capability)) or (
            {"unknown": lane.open_findings} if lane.open_findings else {}
        )
        exposure, exposure_basis = exposure_of(report, lane.repo_full_name)
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
            )
        )
    for repo in repos:
        exposure, exposure_basis = exposure_of(report, repo)
        for group in guidance.fix_groups(catalog, asset_id=repo):
            basis = group.severities or {"unknown": group.findings}
            effort = EFFORT_WEIGHT.get(group.effort, EFFORT_WEIGHT["judgement"])
            removed = risk(basis)
            candidates.append(
                Candidate(
                    signal_key=signal_key(repo, "fix", group.fix_id),
                    kind="fix",
                    repo_full_name=repo,
                    capability=group.capability,
                    title=group.action,
                    ref=group.fix_id,
                    findings=group.findings,
                    risk_removed=removed,
                    risk_basis=_ordered(basis),
                    exposure=exposure,
                    exposure_basis=exposure_basis,
                    effort=effort,
                    effort_basis=f"{group.effort} ({len(group.rules)} rule(s), per the "
                    "scanner's fix text)",
                    score=_score(removed, exposure, effort),
                    steps=list(group.steps),
                )
            )
    candidates.sort(key=lambda c: (-c.score, -c.risk_removed, c.repo_full_name, c.title))
    return candidates


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
    """A backlog story: what, why it ranks, three options and a recommendation."""
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
        "title": candidate.title[:255],
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


def weekly_metric(board: Any, *, now: datetime) -> dict[str, Any]:
    """This week's and last week's share of sprint stories tagged
    `briefing-signal`, and the risk those stories removed.

    A week starts Monday 00:00 UTC. Its sprint stories are those done in it
    (by `closed_at`) and, for the current week, those in the sprint bucket now:
    the board keeps no history of who was in a past sprint, so a past week is
    measured by what it finished. Risk removed is the `risk removed` each
    tagged story recorded when it was filed, summed over the ones done in the
    week.
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
        weeks.append(
            {
                "week_start": begin.date().isoformat(),
                "current": current,
                "sprint_stories": len(stories),
                "briefing_signal_stories": len(tagged),
                "share": round(len(tagged) / len(stories), 3) if stories else None,
                "done_briefing_signal_stories": sum(1 for s in done if is_signal(s)),
                "risk_removed": round(sum(_risk_of(s) for s in done if is_signal(s)), 2),
            }
        )
    return {
        "measured_by": "TheHub board: sprint bucket now plus stories closed in the "
        "week; risk removed as recorded on each tagged story when it was filed",
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
    ranked = [_candidate(row) for row in section.data.get("candidates") or []]
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
