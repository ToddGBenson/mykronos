"""What to do next about the open backlog, measured rather than guessed.

The portfolio says which repository is worst. The worklist says which finding
is most urgent. Neither answers the question somebody actually asks after a
deploy: *given four hundred open findings, what single thing would close the
most of them?*

That question has a different answer per class, and almost none of the answers
are "let auto-remediation handle it":

- A DAST header finding is fixed once in a config and closes across every
  route it was reported on.
- A SAST finding is usually a judgement, and sometimes a false positive that
  needs dispositioning rather than fixing.
- A container CVE frequently has **no fix to take at all**, and the honest
  answer is an acceptance with a review date rather than any edit.

That last one was written here as "rebuild on a current base image and one
rebuild closes them together" until 2026-09-01, when `guidance` read what Trivy
had been reporting all along: 231 of 234 with no published fix. This module now
takes the count from the scan rather than the category, because advice invented
from a class of finding is how a page confidently sends somebody to do a day of
work that cannot close anything (B-026).

**The first section is the one that earns this module.** A finding closes only
after two consecutive *successful* scans observe its absence
(`reconcile.REQUIRED_ABSENCES`). So a capability whose lane is failing cannot
close anything, however thoroughly the underlying defect was fixed — the
backlog simply stops moving, and nothing in the dashboard says why.

That is not hypothetical. On 2026-09-01 this repository carried 115 open DAST
findings against an application whose security headers had already been added
and were verifiably being served. The DAST lane had failed seventeen
consecutive times since 2026-08-30, so no scan had ever observed the fix. The
findings were closed in reality and open for ever in the record.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, TypeVar

from mykronos import guidance
from mykronos.lake.catalog import Catalog

#: How many recent runs to read per (repo, capability) when deciding whether a
#: lane is healthy. Enough to distinguish a flake from a lane that stopped
#: working, without reading a year of history.
RECENT_RUNS = 10

#: What to do about each capability's findings, and why auto-remediation is
#: not the answer for most of them. Keyed to the same classes
#: `fixers.NOT_COVERED` names, so the two cannot describe different worlds.
ROUTES: dict[str, str] = {
    # This said "rebuild on a current base image and one rebuild closes them
    # together" until 2026-09-01, when reading what Trivy actually reported
    # showed 231 of 234 with no published fix at all — and a freshly pulled
    # `python:3.13-slim` shipping byte-identical package versions to the
    # deployed one. The advice was confidently sending somebody to do a day of
    # work that could not close a single finding (B-026).
    "containers": (
        "Check whether a fix exists before rebuilding. Most of these are OS "
        "packages with no patched version published, so a rebuild closes "
        "nothing — accept those with `no_vendor_fix` and a review date, which "
        "re-opens automatically when a vendor ships. /remediate names the few "
        "that do have a fixed version."
    ),
    "dast": (
        "Usually one response header or config value, fixed once and closing "
        "every route it was reported on."
    ),
    "sast": (
        "Case by case. Expect a share to be false positives — disposition "
        "those through the classification review rather than fixing them."
    ),
    "iac": (
        "A deliberate default is frequently the reason. Read the finding "
        "before changing infrastructure that works."
    ),
    "secrets": (
        "Rotate first, then remove. A committed credential stays compromised "
        "after the commit that removes it."
    ),
    "atlas": (
        "Auto-remediation can pin these: the deterministic fixers cover "
        "Python, npm and Go dependencies with a known fixed version."
    ),
    "cloud": (
        "Fixed in the cloud account, which this platform deliberately cannot "
        "reach. It reports the posture; changing it is somebody with the "
        "console."
    ),
}


@dataclass
class Action:
    """One request that acts on a whole group of findings.

    Every field names something that already exists. A briefing that offered
    a button for each group regardless would be the Remediation tab's problem
    again in a new place: an affordance that looks like capability and is not.
    Where no route exists, `ClassSummary.action` is None and the reason is in
    `route`.
    """

    label: str
    method: str
    path: str
    #: What the person should expect afterwards. None of these close a finding
    #: on their own — closure still needs two consecutive successful scans.
    effect: str


#: The single request that acts on a whole class, where one exists. Only two
#: of the six classes have one, and that is the accurate picture rather than a
#: gap: a base-image rebuild is a Dockerfile change and a committed secret
#: needs rotating first, neither of which is an API call.
CLASS_ACTIONS: dict[str, Action] = {
    # Every finding the classifier already judged, worked in one pass. This
    # is the highest-leverage honest button in the platform: 22
    # `likely_false_positive` findings sit at stage `triaged` waiting for
    # exactly this, and each disposition also feeds dampening.
    "sast": Action(
        label="Work the classifier queue for this class",
        method="GET",
        path="/api/dashboard/triage?capability=sast&triage=likely_false_positive",
        effect=(
            "Opens the findings the classifier already judged, each with its "
            "rationale. Confirming or rejecting one is a single request; no "
            "machine may disposition on its own."
        ),
    ),
    # The deterministic fixers cover dependency pinning, so this is the one
    # class where fix generation has anything to generate.
    "atlas": Action(
        label="Generate fixes for pinnable dependencies",
        method="POST",
        path="/api/patchwork/findings/{finding_id}/fix",
        effect=(
            "Opens a draft pull request per finding. Always a draft — "
            "GitHubClient has no merge method, and a test enforces it."
        ),
    ),
}


#: A lane is silent when it has not run for this many times its own usual gap
#: between runs. Self-calibrating on purpose: the schedules in this estate are
#: a mix of daily and weekly, so any fixed threshold either misses a daily lane
#: that stopped or cries wolf at every weekly one.
SILENCE_MULTIPLE = 3.0

#: ...but never sooner than this, so a lane that runs on every push does not
#: report as silent an hour after a quiet afternoon.
SILENCE_FLOOR_DAYS = 2.0

#: Lanes that every scan lane on a Concourse-scanned repository gates on
#: (`passed: [unit, ...]`). When the newest run of one of these failed, the
#: lanes behind it are not silent -- they were never allowed to start -- and
#: telling somebody to re-run a lane that Concourse will not schedule is a
#: button that does nothing. B-055 named this: TheHub's `develop` received
#: zero security scanning for as long as its unit suite was red, and the
#: briefing read every one of those lanes as merely quiet.
BLOCKING_UPSTREAM: tuple[str, ...] = ("unit",)

#: How long a newer commit must have been visible to this platform before a
#: lane still scanning an older one is called pinned. Guards the one false
#: positive this check can produce: two lanes triggered by the same push race,
#: and a slow lane on commit N can finish after a fast lane on N+1 started.
#:
#: Deliberately NOT scaled by the lane's own cadence, which the first version
#: of this did. Cadence is the right guard for silence -- a weekly lane that
#: has not run for five days is fine -- and the wrong one here: once a lane
#: has actually *run*, how often it usually runs says nothing about whether it
#: should have picked up the newer commit. Scaling by it made a lane that runs
#: every nine days unreportable until the new commit was nine days old, which
#: is exactly the lane most worth reporting.
STALE_FLOOR_DAYS = 1.0


@dataclass
class StalledLane:
    """A capability that cannot close findings, and what it is holding open.

    Three shapes, one consequence. A lane can be **failing** — running and
    erroring, which is what mykronos DAST did seventeen times. It can be
    **silent** — succeeding, and then simply never running again, which is
    what every one of TheHub's lanes did after 2026-08-27. Or it can be
    **blocked** — quiet because an upstream lane it gates on is red, so
    Concourse never schedules it; the fix is upstream, and re-running this
    lane does nothing at all.

    Silence is the worse of the two and was nearly missed here, because a
    check that reads `scan_status` sees nothing wrong with a lane whose last
    run succeeded. There is no error to notice. The findings are frozen just
    the same: no scan, no observed absence, no closure.
    """

    repo_full_name: str
    capability: str
    #: "failing", "silent" or "blocked" — see the class docstring. All three
    #: freeze findings; they need different fixes, so the briefing must not
    #: conflate them.
    reason: str
    consecutive_failures: int
    #: True when the streak filled the whole read window, so the real streak
    #: is at least `consecutive_failures` and possibly longer. The lake held
    #: ten mykronos DAST failures inside the window and seventeen in total;
    #: printing a bare "10" would have understated a two-day outage.
    streak_capped: bool
    last_success: datetime | None
    detail: str
    open_findings: int
    #: How long since this lane ran at all, and the gap it usually runs at.
    #: Both are needed to read the first: five days is an outage for a daily
    #: lane and unremarkable for a weekly one.
    days_since_run: float = 0.0
    usual_gap_days: float = 0.0
    #: For a **blocked** lane, the upstream capability whose failure is
    #: holding it; empty otherwise.
    blocked_by: str = ""
    #: Set in `__post_init__` rather than exposed as a property, because
    #: `--json` serialises with `dataclasses.asdict` and a property is
    #: silently absent from it. The action is the part a pipeline step wants.
    action: Action = field(init=False)

    def __post_init__(self) -> None:
        """Re-run the lane. This is the button, and it already exists.

        A stalled lane is the one group in the whole briefing where a single
        request genuinely does the work: dispatching the capability produces
        the successful scan the findings have been waiting on, and two of them
        close the lot.

        The caveat differs by reason, and flattening the two would make this
        button a lie half the time. A **silent** lane was working when it
        stopped, so dispatching it is the whole fix. A **failing** lane will
        fail again — re-running it closes nothing and looks like action.
        """
        if self.reason == "blocked":
            # The button is the upstream lane's, not this one's: Concourse
            # will not schedule a job whose `passed:` constraint is unmet, so
            # dispatching this lane produces nothing to wait on.
            self.action = Action(
                label=f"Fix {self.blocked_by} for {self.repo_full_name}",
                method="POST",
                path=f"/api/repos/{self.repo_full_name}/scan?capabilities={self.blocked_by}",
                effect=(
                    f"Re-runs the upstream lane this one gates on. Nothing here "
                    f"can start until {self.blocked_by} is green; once it is, two "
                    f"successful runs of {self.capability} close up to "
                    f"{self.open_findings} finding(s)."
                ),
            )
            return
        caveat = (
            "The lane was working when it stopped, so this is the fix."
            if self.reason == "silent"
            else "Repair the job first — a re-run of a broken workflow fails "
            "again and closes nothing."
        )
        self.action = Action(
            label=f"Re-run {self.capability} for {self.repo_full_name}",
            method="POST",
            path=f"/api/repos/{self.repo_full_name}/scan?capabilities={self.capability}",
            effect=(
                f"Dispatches the lane. {caveat} Two successful runs then "
                f"close up to {self.open_findings} finding(s)."
            ),
        )


@dataclass
class StaleLane:
    """A lane that is reporting, and not covering (B-046).

    `stalled_lanes` measures wall-clock silence: how long since this
    capability last reported. That is the right question and it is not the
    only one. A pipeline pinned to a branch that has stopped moving, or to a
    cached checkout, produces a successful run on schedule forever against an
    unchanging tree -- and never appears in that section at all. TheHub's
    lanes surfaced only because they *also* went quiet for two days; had the
    pipeline held its ten-hour cadence, 330 findings would have been frozen
    against a stale tree with every indicator green.

    Two shapes, both "the repository moved and this lane did not":

    **`same_commit`** -- the lane's newest successful run carries a commit the
    repository has already moved off, and it ran well after the newer commit
    was visible here. Not simply "two runs share a commit": a lane scanning a
    repository nobody has pushed to is covering it correctly, and calling that
    a fault would flag every quiet repository in the estate.

    **`wrong_branch`** -- the lane scans a branch that is not the
    repository's default. B-045's instance, which cost TheHub sixteen days of
    scanning `main` while every commit landed on `develop`.
    """

    repo_full_name: str
    capability: str
    #: "same_commit" or "wrong_branch". Both mean the lane is not watching
    #: what it is supposed to watch; they need different fixes.
    reason: str
    #: The commit this lane keeps scanning, short form.
    commit_sha: str
    #: The branch it scanned, and what the repository says is default.
    branch: str
    default_branch: str
    #: When this lane's coverage stopped moving -- the first of its runs to
    #: carry this commit -- and how many successful runs have carried it.
    since: datetime | None
    runs: int
    #: What is frozen behind it. A lane covering a stale tree cannot close a
    #: finding fixed on the tree it is not reading.
    open_findings: int
    action: Action = field(init=False)

    def __post_init__(self) -> None:
        """Re-running is not the fix here, and saying so is the point.

        A stalled lane's button dispatches it and the findings close. This
        lane is already running and already succeeding: dispatching it again
        produces one more successful scan of the same stale tree. The fix is
        in the pipeline definition, so the action names the file rather than
        offering a request that would change nothing.
        """
        if self.reason == "wrong_branch":
            effect = (
                f"This lane scans `{self.branch}` and the repository's default is "
                f"`{self.default_branch}`. Nothing on the default branch has been "
                f"scanned by it. Point the resource at `{self.default_branch}` and "
                "re-apply; a re-run changes nothing."
            )
        else:
            effect = (
                f"This lane has scanned `{self.commit_sha}` for its last "
                f"{self.runs} successful run(s) while the repository moved on. "
                "A pinned ref or a cached checkout is the usual cause. A re-run "
                f"produces one more clean scan of the same tree and closes none "
                f"of the {self.open_findings} finding(s) behind it."
            )
        self.action = Action(
            label=f"Repair the {self.capability} lane for {self.repo_full_name}",
            method="GET",
            path=f"/api/dashboard/repos/{self.repo_full_name}/ci",
            effect=effect,
        )


@dataclass
class UnreadCode:
    """Source in a repository that no configured analyser implements (B-051).

    `keel` recorded 47 successful SAST runs and zero findings, ever, which
    reads as a well-kept repository. Its analyser is CodeQL, CodeQL implements
    no shell language at all, and 69% of keel is shell -- so 219 KB has never
    been read by anything and every run over it reported success.

    That is the section above's failure with the alarm removed. A stalled lane
    at least stops reporting; this one reports `success` while reading nothing,
    so it appears in no gap anywhere and looks exactly like a clean
    repository.
    """

    repo_full_name: str
    tool: str
    #: 0.0 to 1.0 of application source the analyser cannot read.
    share_unread: float
    #: The languages it cannot read, largest first, as (name, bytes).
    unread: list[tuple[str, int]]
    action: Action = field(init=False)

    def __post_init__(self) -> None:
        """No dispatch button, and that is the point.

        Every other lane row on this page offers a re-run because for those
        the lane can produce the missing answer. Running this one again reads
        the same bytes with the same tool and reports success again. The fix
        is a second analyser, which is a decision about the repository rather
        than a request this platform can make.
        """
        languages = ", ".join(name for name, _ in self.unread[:3])
        self.action = Action(
            label=f"Choose an analyser for {languages} on {self.repo_full_name}",
            method="GET",
            path=f"/api/dashboard/repos/{self.repo_full_name}/ci",
            effect=(
                f"{self.share_unread:.0%} of this repository is {languages}, which "
                f"{self.tool} does not implement. Re-running the lane reads the same "
                "bytes and reports success again; the gap closes when a tool that "
                "reads those languages runs beside it."
            ),
        )


@dataclass
class AwaitingClosure:
    """Findings already gone, waiting only for scans to say so.

    The single most useful thing to separate out of an open count. These need
    **no work at all** — the defect is fixed and absent from the newest
    successful scan; closure is arithmetic from here
    (`reconcile.REQUIRED_ABSENCES`). Presenting them beside findings that need
    a person is what makes a backlog look larger than the work in it.
    """

    repo_full_name: str
    capability: str
    findings: int
    #: How many more successful scans of this lane before they close. Zero
    #: means the next `reconcile_absences` sweep takes them.
    scans_needed: int


@dataclass
class ClassSummary:
    capability: str
    open_findings: int
    route: str
    #: The handful of packages or rules the class is concentrated in — what
    #: makes "234 findings" into "one base image".
    concentrated_in: list[tuple[str, int]] = field(default_factory=list)
    #: None where no single request acts on the group — a base-image rebuild
    #: is a Dockerfile change, not an API call, and pretending otherwise
    #: would be a dead button.
    action: Action | None = None
    #: How many of these the scanner says have no published fix. Advice is
    #: cheap and a count is not: 231 of 234 container findings had nothing to
    #: upgrade to, which is the difference between a day of work and a
    #: dispositioning pass (B-026).
    no_fix_available: int = 0


@dataclass
class Briefing:
    generated_at: datetime
    total_open: int
    stalled: list[StalledLane] = field(default_factory=list)
    #: Lanes that are reporting and not covering (B-046). Deliberately its own
    #: list rather than another `reason` on `StalledLane`: those lanes are not
    #: producing successful scans and these are, so the sentence, the number
    #: and the fix are all different.
    stale: list[StaleLane] = field(default_factory=list)
    #: Repositories whose analyser cannot read part of them (B-051). Its own
    #: list because the fix is a tool choice rather than a lane repair, and
    #: because these lanes are green everywhere else in the platform.
    unread: list[UnreadCode] = field(default_factory=list)
    classes: list[ClassSummary] = field(default_factory=list)
    auto_fixable: int = 0
    #: Already fixed, waiting only for scans to confirm. Needs no work.
    awaiting: list[AwaitingClosure] = field(default_factory=list)

    @property
    def closing_soon(self) -> int:
        """Findings that will close with no work at all."""
        return sum(a.findings for a in self.awaiting)

    @property
    def blocked_findings(self) -> int:
        """Open findings that cannot close until a lane is repaired."""
        return sum(lane.open_findings for lane in self.stalled)


def awaiting_closure(catalog: Catalog) -> list[AwaitingClosure]:
    """Open findings absent from their lane's most recent successful scan.

    Deliberately mirrors `reconcile_absences` rather than approximating it: the
    same `CONFIRMING_STATUSES`, the same "not among the most recent runs" test,
    the same `asset_id`/`repo_full_name` join. A page that promised something
    would close on a different rule from the one that closes it would be worse
    than not saying anything.

    The difference is only that this counts what is *on its way* out, where
    reconcile acts on what has already arrived.
    """
    from mykronos.lake.reconcile import CONFIRMING_STATUSES, REQUIRED_ABSENCES

    if not catalog.all_files("findings") or not catalog.all_files("scan_runs"):
        return []

    statuses = ", ".join(f"'{s}'" for s in CONFIRMING_STATUSES)
    rows = catalog.query(
        f"""
        WITH recent AS (
            SELECT repo_full_name, capability, scan_run_id, rn FROM (
                SELECT repo_full_name, capability, scan_run_id,
                       row_number() OVER (
                           PARTITION BY repo_full_name, capability
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs WHERE scan_status IN ({statuses})
            ) WHERE rn <= {REQUIRED_ABSENCES}
        ),
        depth AS (
            SELECT repo_full_name, capability, count(*) AS runs
            FROM recent GROUP BY 1, 2
        )
        SELECT f.asset_id, f.capability, d.runs, count(*)
        FROM findings f
        JOIN depth d
          ON d.repo_full_name = f.asset_id AND d.capability = f.capability
        WHERE f.status = 'open'
          AND f.last_seen_scan_run_id NOT IN (
              SELECT r.scan_run_id FROM recent r
              WHERE r.repo_full_name = f.asset_id AND r.capability = f.capability
          )
        GROUP BY 1, 2, 3
        """
    )

    out = [
        AwaitingClosure(
            repo_full_name=str(repo),
            capability=str(capability),
            findings=int(count),
            # A lane with fewer than the required runs on record cannot confirm
            # yet, however long the finding has been absent.
            scans_needed=max(0, REQUIRED_ABSENCES - int(runs)),
        )
        for repo, capability, runs, count in rows
    ]
    out.sort(key=lambda a: -a.findings)
    return out


def _open_by_capability(catalog: Catalog) -> dict[tuple[str, str], int]:
    if not catalog.all_files("findings"):
        return {}
    rows = catalog.query(
        """
        SELECT asset_id, capability, count(*)
        FROM findings WHERE status = 'open' GROUP BY 1, 2
        """
    )
    return {(str(repo), str(capability)): int(n) for repo, capability, n in rows}


def stalled_lanes(catalog: Catalog, *, now: datetime | None = None) -> list[StalledLane]:
    """Lanes that cannot close findings, failing or silent.

    **Failing** is counted consecutively from the newest run backwards, so a
    lane that failed twice and then recovered is not reported — it is working,
    and reporting it would make this section the thing people stop reading.

    **Silent** is measured against the lane's own cadence rather than a fixed
    threshold, because this estate mixes daily and weekly schedules and any
    single number would either miss a stopped daily lane or cry wolf at every
    weekly one. Five days of silence is an outage for one and a Tuesday for
    the other.
    """
    from mykronos.schemas import utcnow

    if not catalog.all_files("scan_runs"):
        return []

    stamp = now or utcnow()

    rows = catalog.query(
        f"""
        SELECT repo_full_name, capability, scan_status, detail, ran_at FROM (
            SELECT repo_full_name, capability, scan_status,
                   coalesce(detail, '') AS detail,
                   coalesce(completed_at, started_at) AS ran_at,
                   row_number() OVER (
                       PARTITION BY repo_full_name, capability
                       ORDER BY coalesce(completed_at, started_at) DESC
                   ) AS rn
            FROM scan_runs
        ) WHERE rn <= {RECENT_RUNS}
        ORDER BY repo_full_name, capability, ran_at DESC
        """
    )

    by_lane: dict[tuple[str, str], list[tuple[str, str, Any]]] = {}
    for repo, capability, scan_status, detail, at in rows:
        by_lane.setdefault((str(repo), str(capability)), []).append(
            (str(scan_status), str(detail), at)
        )

    open_counts = _open_by_capability(catalog)
    stalled: list[StalledLane] = []
    for (repo, capability), runs in by_lane.items():
        failures = 0
        detail = ""
        for scan_status, run_detail, _ in runs:
            if scan_status == "success":
                break
            failures += 1
            detail = detail or run_detail

        # `runs` is newest-first, so this is the most recent run of any kind.
        since = (stamp - runs[0][2]).total_seconds() / 86400
        gap = _usual_gap_days(runs)
        silent = since > max(SILENCE_MULTIPLE * gap, SILENCE_FLOOR_DAYS)

        if failures == 0 and not silent:
            continue

        # Quiet because it cannot start, or quiet because it stopped? A lane
        # that is silent while an upstream it gates on has failed *since* this
        # lane last ran was never scheduled, and the honest word for that is
        # blocked (B-055). Failing wins over both: a lane that ran and failed
        # has its own job for somebody to go and read.
        blocked_by = ""
        if not failures:
            for upstream in BLOCKING_UPSTREAM:
                if upstream == capability:
                    continue
                upstream_runs = by_lane.get((repo, upstream))
                if not upstream_runs:
                    continue
                newest_status, _, newest_at = upstream_runs[0]
                if newest_status != "success" and newest_at >= runs[0][2]:
                    blocked_by = upstream
                    break

        stalled.append(
            StalledLane(
                repo_full_name=repo,
                capability=capability,
                # A lane can be both; failing is the more actionable label,
                # because it names a job somebody has to go and read.
                reason="failing" if failures else ("blocked" if blocked_by else "silent"),
                blocked_by=blocked_by,
                consecutive_failures=failures,
                streak_capped=bool(failures) and failures >= min(RECENT_RUNS, len(runs)),
                last_success=_last_success(catalog, repo, capability),
                detail=detail,
                open_findings=open_counts.get((repo, capability), 0),
                days_since_run=round(since, 1),
                usual_gap_days=round(gap, 1),
            )
        )

    # Worst first: what is holding the most open, then how long it has been
    # stuck. A lane blocking nothing is real but not urgent.
    stalled.sort(key=lambda lane: (-lane.open_findings, -lane.days_since_run))
    return stalled


def stale_lanes(
    catalog: Catalog,
    *,
    now: datetime | None = None,
    default_branches: dict[str, str] | None = None,
) -> list[StaleLane]:
    """Lanes that are succeeding without covering anything new (B-046).

    Mykronos already held both halves of this -- `repo_onboarding.
    default_branch` and `scan_runs.branch` / `scan_runs.commit_sha` -- and
    nothing compared them.

    **The check is not "consecutive runs share a commit".** A lane scanning a
    repository nobody has pushed to shares a commit with itself forever and is
    covering it correctly; flagging that would light up every quiet repository
    in the estate and the section would stop being read. What is wrong is a
    lane whose commit the *repository has already moved off* -- established
    from the lake itself, by the newest commit any lane on that repository has
    reported -- while the lane kept succeeding.

    So a repository with one lane is never reported: there is nothing to
    establish movement from, and guessing would be worse than the gap.
    """
    from mykronos.schemas import utcnow

    if not catalog.all_files("scan_runs"):
        return []

    stamp = now or utcnow()
    branches = default_branches or {}

    rows = catalog.query(
        """
        SELECT repo_full_name, capability, scan_status,
               coalesce(branch, '') AS branch,
               coalesce(commit_sha, '') AS commit_sha,
               coalesce(completed_at, started_at) AS ran_at
        FROM scan_runs
        WHERE commit_sha IS NOT NULL AND commit_sha <> ''
        ORDER BY repo_full_name, ran_at DESC
        """
    )

    #: Every run of a repository, newest first, and the same rows grouped by
    #: lane. One pass, because the two questions are asked of the same rows.
    by_repo: dict[str, list[tuple[str, str, str, Any]]] = {}
    by_lane: dict[tuple[str, str], list[tuple[str, str, str, Any]]] = {}
    for repo, capability, scan_status, branch, commit_sha, ran_at in rows:
        record = (str(scan_status), str(branch), str(commit_sha), ran_at)
        by_repo.setdefault(str(repo), []).append(record)
        by_lane.setdefault((str(repo), str(capability)), []).append(record)

    open_counts = _open_by_capability(catalog)
    stale: list[StaleLane] = []

    for (repo, capability), runs in by_lane.items():
        successes = [run for run in runs if run[0] == "success"]
        if not successes:
            continue
        _, branch, commit_sha, last_ran = successes[0]

        # How long this lane has been on this commit, and over how many runs.
        # The leading block only: an older run of the same commit with a
        # different one in between is not a lane that stopped moving.
        block = []
        for run in successes:
            if run[2] != commit_sha:
                break
            block.append(run)
        since = block[-1][3]

        default_branch = branches.get(repo, "")
        if default_branch and branch and branch != default_branch:
            stale.append(
                StaleLane(
                    repo_full_name=repo,
                    capability=capability,
                    reason="wrong_branch",
                    commit_sha=_short(commit_sha),
                    branch=branch,
                    default_branch=default_branch,
                    since=since,
                    runs=len(block),
                    open_findings=open_counts.get((repo, capability), 0),
                )
            )
            continue

        # Did the repository move, and had it moved long enough before this
        # lane last ran that a race cannot explain it?
        #
        # "Newest" is the commit that APPEARED most recently, not the commit
        # on the most recent run. Those differ precisely in the case being
        # looked for: a pinned lane re-scanning an old tree today is the most
        # recent run, so reading the head off it would let the stale lane
        # define itself as current and this check would never fire.
        first_seen: dict[str, Any] = {}
        for _, _, sha, ran in by_repo.get(repo, []):
            if sha not in first_seen or ran < first_seen[sha]:
                first_seen[sha] = ran
        if len(first_seen) < 2:
            continue
        newest_commit = max(first_seen, key=lambda sha: first_seen[sha])
        if newest_commit == commit_sha:
            continue
        known_for = (last_ran - first_seen[newest_commit]).total_seconds() / 86400
        if known_for <= STALE_FLOOR_DAYS:
            continue

        stale.append(
            StaleLane(
                repo_full_name=repo,
                capability=capability,
                reason="same_commit",
                commit_sha=_short(commit_sha),
                branch=branch,
                default_branch=default_branch,
                since=since,
                runs=len(block),
                open_findings=open_counts.get((repo, capability), 0),
            )
        )

    # Worst first, the same ordering rule the stalled section uses: what is
    # holding the most, then how long it has been stuck.
    stale.sort(key=lambda lane: (-lane.open_findings, lane.since or stamp))
    return stale


def unread_code(
    languages: dict[str, dict[str, int]] | None,
    sast_tools: dict[str, str | list[str]] | None = None,
) -> list[UnreadCode]:
    """Repositories with source no configured analyser implements (B-051).

    `languages` is GitHub's byte count per language per repository, and
    `sast_tools` the analyser each one runs. Both are read from outside the
    lake, so a caller with no GitHub client passes nothing and this reports
    nothing -- which is the honest degradation: not knowing what a repository
    is made of is different from knowing it is fully analysed.
    """
    from mykronos.analysers import readability

    if not languages:
        return []

    tools = sast_tools or {}
    out: list[UnreadCode] = []
    for repo, byte_counts in languages.items():
        reading = readability(repo, byte_counts, tools.get(repo) or "codeql")
        if not reading.blind:
            continue
        out.append(
            UnreadCode(
                repo_full_name=repo,
                tool=reading.tool,
                share_unread=reading.share_unread,
                unread=reading.unread,
            )
        )

    # Most unread first. A repository that is 4% unread and one that is 100%
    # are the same defect and very much not the same problem.
    out.sort(key=lambda row: -row.share_unread)
    return out


def _usual_gap_days(runs: list[tuple[str, str, Any]]) -> float:
    """How often this lane normally runs, from its own history.

    The median gap rather than the mean: a lane that runs on every push has a
    handful of enormous gaps around holidays, and a mean would let it go dark
    for a fortnight before anybody was told.

    A lane with only one run on record has no cadence to measure. It gets 1.0,
    which combined with `SILENCE_FLOOR_DAYS` means it must be quiet for two
    days before it is called silent — cautious, and the right way round.
    """
    # The timestamps arrive from DuckDB as `Any`; naming the type here is what
    # keeps the median a float rather than propagating Any to the caller.
    times: list[datetime] = sorted((run[2] for run in runs), reverse=True)
    gaps: list[float] = sorted(
        (times[i] - times[i + 1]).total_seconds() / 86400 for i in range(len(times) - 1)
    )
    if not gaps:
        return 1.0
    middle = len(gaps) // 2
    return gaps[middle] if len(gaps) % 2 else (gaps[middle - 1] + gaps[middle]) / 2


def _last_success(catalog: Catalog, repo: str, capability: str) -> datetime | None:
    """When this lane last worked, over all history rather than the window.

    `stalled_lanes` only reads `RECENT_RUNS` rows, which is right for counting
    a failure streak and wrong for this: a lane that has failed more times than
    the window is wide would otherwise be reported as never having succeeded,
    which is a much stronger claim than was checked. Mykronos DAST last
    succeeded on 2026-08-30 and had failed seventeen times since.
    """
    rows = catalog.query(
        """
        SELECT max(coalesce(completed_at, started_at)) FROM scan_runs
        WHERE repo_full_name = ? AND capability = ? AND scan_status = 'success'
        """,
        [repo, capability],
    )
    return rows[0][0] if rows and rows[0][0] is not None else None


def _concentration(
    catalog: Catalog, capability: str, limit: int = 5, *, asset_id: str | None = None
) -> list[tuple[str, int]]:
    """Where a class's findings pile up — package for dependency-shaped
    capabilities, rule for the rest.

    This is what turns a count into an action: "234 container findings" is a
    backlog, "twenty of them are libc6" is a base image.
    """
    column = "package_name" if capability in ("containers", "atlas") else "rule_id"
    scope = "" if asset_id is None else " AND asset_id = ?"
    params: list[Any] = [capability]
    if asset_id is not None:
        params.append(asset_id)
    params.append(limit)
    rows = catalog.query(
        f"""
        SELECT coalesce({column}, '(unattributed)'), count(*)
        FROM findings
        WHERE status = 'open' AND capability = ?{scope}
        GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """,
        params,
    )
    return [(_short(str(name)), int(count)) for name, count in rows]


def _short(identifier: str) -> str:
    """The part of a rule id a person would say out loud.

    Semgrep ids are namespaced to the point of unreadability —
    `python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text`
    is eighty characters to say `avoid-sqlalchemy-text`. The namespace is
    recoverable from the finding itself; this line exists to be skimmed.
    Package names and ZAP ids have no dots and pass through untouched.
    """
    tail = identifier.rsplit(".", 1)[-1]
    return tail if len(tail) > 3 else identifier


class _RepoScoped(Protocol):
    """Anything the briefing lists that belongs to one repository."""

    repo_full_name: str


_T = TypeVar("_T", bound=_RepoScoped)


def _only(rows: list[_T], asset_id: str | None) -> list[_T]:
    """Keep the rows belonging to one repository, or all of them."""
    if asset_id is None:
        return rows
    return [row for row in rows if row.repo_full_name == asset_id]


def build(
    catalog: Catalog,
    *,
    now: datetime | None = None,
    asset_id: str | None = None,
    default_branches: dict[str, str] | None = None,
    languages: dict[str, dict[str, int]] | None = None,
    sast_tools: dict[str, str | list[str]] | None = None,
) -> Briefing:
    """The whole briefing, from the lake.

    `asset_id` narrows every section to one repository. The estate-wide view
    answers "where is the worst of it"; the scoped one answers "what do I do
    about *this* repository today", which is the question somebody who owns one
    service actually has. Both are the same reasoning — cheapest first, lanes
    that cannot close ahead of findings that can — applied to a different
    denominator.

    Scoped by filtering rather than by re-querying wherever the underlying
    structure is already keyed by repository, so the two views cannot drift
    apart: a difference between them would be a bug in one query, and there is
    only one query.
    """
    from mykronos.schemas import utcnow

    stamp = now or utcnow()
    open_counts = _open_by_capability(catalog)
    if asset_id is not None:
        open_counts = {
            key: count for key, count in open_counts.items() if key[0] == asset_id
        }

    # From the scan rather than from a category. `guidance` reads what each
    # tool actually said; this is the one number out of it the terminal
    # briefing needs.
    no_fix = {
        summary.capability: summary.unactionable
        for summary in guidance.by_rule(catalog, asset_id=asset_id)
        if summary.unactionable
    }

    totals: dict[str, int] = {}
    for (_, capability), count in open_counts.items():
        totals[capability] = totals.get(capability, 0) + count

    classes = [
        ClassSummary(
            capability=capability,
            open_findings=count,
            route=ROUTES.get(capability, "No standing route recorded for this class."),
            concentrated_in=_concentration(catalog, capability, asset_id=asset_id),
            action=CLASS_ACTIONS.get(capability),
            no_fix_available=no_fix.get(capability, 0),
        )
        for capability, count in sorted(totals.items(), key=lambda kv: -kv[1])
    ]

    return Briefing(
        generated_at=stamp,
        total_open=sum(totals.values()),
        stalled=_only(stalled_lanes(catalog, now=stamp), asset_id),
        stale=_only(
            stale_lanes(catalog, now=stamp, default_branches=default_branches), asset_id
        ),
        unread=_only(unread_code(languages, sast_tools), asset_id),
        awaiting=_only(awaiting_closure(catalog), asset_id),
        classes=classes,
        # Only `atlas` has deterministic fixers with anything to act on; the
        # secrets fixer needs a credential in source rather than a reference.
        auto_fixable=totals.get("atlas", 0),
    )


def _cadence(days: float) -> str:
    """A gap in the unit a person would say it in.

    Push-triggered lanes run several times an hour, and "every 0.2 days" is
    a number nobody converts in their head — the cadence is only in the line
    to make the silence beside it mean something.
    """
    if days >= 1:
        return f"{days:.0f} day" + ("s" if days >= 2 else "")
    hours = days * 24
    return f"{hours:.0f} hours" if hours >= 1 else "few minutes"


def render(briefing: Briefing) -> str:
    """The briefing as a person reads it after a deploy."""
    lines = [
        f"Mykronos briefing — {briefing.generated_at:%Y-%m-%d %H:%M} UTC",
        f"{briefing.total_open} open findings.",
        "",
    ]

    if briefing.stalled:
        lines += [
            "LANES THAT CANNOT CLOSE FINDINGS",
            "  A finding closes only after two consecutive successful scans see",
            "  it gone. These lanes are not producing them, so their findings",
            "  cannot close however thoroughly the defect was fixed.",
            "",
        ]
        # A lane holding nothing open is still broken and still worth knowing
        # about, but it must not push a lane holding 213 findings down the
        # page. One line for all of them, at the bottom.
        holding = [lane for lane in briefing.stalled if lane.open_findings]
        idle = [lane for lane in briefing.stalled if not lane.open_findings]

        for lane in holding:
            if lane.reason == "failing":
                since = (
                    f"last success {lane.last_success:%Y-%m-%d}"
                    if lane.last_success
                    else "no successful run on record"
                )
                streak = ("at least " if lane.streak_capped else "") + str(
                    lane.consecutive_failures
                )
                state = f"{streak} consecutive failures, {since}"
            elif lane.reason == "blocked":
                state = (
                    f"blocked for {lane.days_since_run:.0f} days — "
                    f"{lane.blocked_by} is red, so this lane cannot start"
                )
            else:
                # Silence needs the cadence beside it or the number means
                # nothing: five days is an outage for a daily lane and
                # unremarkable for a weekly one.
                state = (
                    f"silent for {lane.days_since_run:.0f} days "
                    f"(usually every {_cadence(lane.usual_gap_days)})"
                )
            lines.append(f"  {lane.capability:<11} {lane.repo_full_name}  — {state}")
            lines.append(f"      holding {lane.open_findings} finding(s) open")
            if lane.detail:
                lines.append(f"      {lane.detail[:110]}")
            lines.append(f"      → {lane.action.method} {lane.action.path}")

        if idle:
            names = ", ".join(f"{lane.repo_full_name} {lane.capability}" for lane in idle)
            lines.append("")
            lines += textwrap.wrap(
                f"  Also stalled, holding nothing open: {names}. Nothing is "
                f"stuck behind these, but they are not watching either.",
                72,
                subsequent_indent="  ",
            )
        lines.append("")
    else:
        lines += ["Every lane is reporting. Findings can close.", ""]

    if briefing.stale:
        lines += [
            "LANES THAT ARE REPORTING AND NOT COVERING",
            "  These succeed on schedule against a tree that is not moving, so",
            "  they never appear above. A green lane over a stale checkout",
            "  closes nothing and looks exactly like one that is working.",
            "",
        ]
        # `uncovered`, not `lane`: the stalled loop above binds that name to a
        # StalledLane in the same scope, and reusing it makes every attribute
        # here read as an error against the wrong type.
        for uncovered in briefing.stale:
            if uncovered.reason == "wrong_branch":
                state = (
                    f"scanning {uncovered.branch}, and the default branch is "
                    f"{uncovered.default_branch}"
                )
            else:
                stuck = (
                    f"{uncovered.since:%Y-%m-%d}" if uncovered.since else "an unknown date"
                )
                state = (
                    f"{uncovered.runs} successful run(s) all on "
                    f"{uncovered.commit_sha}, since {stuck}"
                )
            lines.append(
                f"  {uncovered.capability:<11} {uncovered.repo_full_name}  — {state}"
            )
            if uncovered.open_findings:
                lines.append(f"      holding {uncovered.open_findings} finding(s) open")
            lines.append(f"      → {uncovered.action.effect}")
        lines.append("")

    if briefing.unread:
        lines += [
            "CODE NO ANALYSER HERE CAN READ",
            "  These lanes report success over source their tool does not",
            "  implement. They are not silent and not failing, so nothing else",
            "  on this page marks them.",
            "",
        ]
        for blind in briefing.unread:
            languages = ", ".join(f"{name}" for name, _ in blind.unread[:3])
            lines.append(
                f"  {blind.repo_full_name}  — {blind.share_unread:.0%} unread "
                f"({languages}), analyser {blind.tool}"
            )
            lines.append(f"      → {blind.action.effect}")
        lines.append("")

    lines += ["OPEN FINDINGS, BY WHAT WOULD FIX THEM", ""]
    for entry in briefing.classes:
        lines.append(f"  {entry.open_findings:>4}  {entry.capability}")
        lines += textwrap.wrap(entry.route, 72, initial_indent="        ",
                               subsequent_indent="        ")
        if entry.concentrated_in:
            top = ", ".join(f"{name} ({n})" for name, n in entry.concentrated_in)
            lines += textwrap.wrap(
                f"concentrated in: {top}",
                72,
                initial_indent="        ",
                subsequent_indent="          ",
                # A rule id split across lines cannot be copied or searched
                # for, which is the only reason anyone reads this line.
                break_long_words=False,
                break_on_hyphens=False,
            )
        if entry.no_fix_available:
            lines.append(
                f"        {entry.no_fix_available} of these have no published fix — "
                "nothing to upgrade to."
            )
        if entry.action:
            lines.append(f"        → {entry.action.method} {entry.action.path}")
        lines.append("")

    lines += [
        "WHAT AUTO-REMEDIATION CAN TAKE",
        f"  {briefing.auto_fixable} of {briefing.total_open}. The deterministic "
        "fixers cover dependency",
        "  pinning and committed secrets; everything outside those classes",
        "  needs a person. Saying so beats a Remediation tab that reads as",
        "  broken.",
    ]
    if briefing.blocked_findings:
        lines += [
            "",
            f"  {briefing.blocked_findings} of those findings cannot close at all",
            "  until the lanes above are repaired. Fix the lane before the finding.",
        ]
    return "\n".join(lines)
