"""What to do next about the open backlog, measured rather than guessed.

The portfolio says which repository is worst. The worklist says which finding
is most urgent. Neither answers the question somebody actually asks after a
deploy: *given four hundred open findings, what single thing would close the
most of them?*

That question has a different answer per class, and almost none of the answers
are "let auto-remediation handle it":

- A container CVE is fixed by moving base image, which is one action closing
  scores of findings and is not an edit to any file.
- A DAST header finding is fixed once in a config and closes across every
  route it was reported on.
- A SAST finding is usually a judgement, and sometimes a false positive that
  needs dispositioning rather than fixing.

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
from typing import Any

from mykronos.lake.catalog import Catalog

#: How many recent runs to read per (repo, capability) when deciding whether a
#: lane is healthy. Enough to distinguish a flake from a lane that stopped
#: working, without reading a year of history.
RECENT_RUNS = 10

#: What to do about each capability's findings, and why auto-remediation is
#: not the answer for most of them. Keyed to the same classes
#: `fixers.NOT_COVERED` names, so the two cannot describe different worlds.
ROUTES: dict[str, str] = {
    "containers": (
        "Rebuild on a current base image. These are OS packages in the image, "
        "not edits to any file, and one rebuild closes them together."
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


@dataclass
class StalledLane:
    """A capability that cannot close findings, and what it is holding open."""

    repo_full_name: str
    capability: str
    consecutive_failures: int
    #: True when the streak filled the whole read window, so the real streak
    #: is at least `consecutive_failures` and possibly longer. The lake held
    #: ten mykronos DAST failures inside the window and seventeen in total;
    #: printing a bare "10" would have understated a two-day outage.
    streak_capped: bool
    last_success: datetime | None
    detail: str
    open_findings: int
    #: Set in `__post_init__` rather than exposed as a property, because
    #: `--json` serialises with `dataclasses.asdict` and a property is
    #: silently absent from it. The action is the part a pipeline step wants.
    action: Action = field(init=False)

    def __post_init__(self) -> None:
        """Re-run the lane. This is the button, and it already exists.

        A stalled lane is the one group in the whole briefing where a single
        request genuinely does the work: once the underlying job is repaired,
        dispatching the capability produces the successful scan the findings
        have been waiting on, and two of them close the lot.
        """
        self.action = Action(
            label=f"Re-run {self.capability} for {self.repo_full_name}",
            method="POST",
            path=f"/api/repos/{self.repo_full_name}/scan?capabilities={self.capability}",
            effect=(
                f"Dispatches the lane. Repair the job first — a re-run of a "
                f"broken workflow fails again and closes nothing. Two "
                f"successful runs then close up to {self.open_findings} finding(s)."
            ),
        )


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


@dataclass
class Briefing:
    generated_at: datetime
    total_open: int
    stalled: list[StalledLane] = field(default_factory=list)
    classes: list[ClassSummary] = field(default_factory=list)
    auto_fixable: int = 0

    @property
    def blocked_findings(self) -> int:
        """Open findings that cannot close until a lane is repaired."""
        return sum(lane.open_findings for lane in self.stalled)


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


def stalled_lanes(catalog: Catalog) -> list[StalledLane]:
    """Lanes whose most recent runs all failed.

    Consecutive from the newest run backwards, so a lane that failed twice and
    then recovered is not reported — it is working, and reporting it would
    make this section the thing people stop reading.
    """
    if not catalog.all_files("scan_runs"):
        return []

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
        if failures == 0:
            continue

        last_success = _last_success(catalog, repo, capability)
        stalled.append(
            StalledLane(
                repo_full_name=repo,
                capability=capability,
                consecutive_failures=failures,
                streak_capped=failures >= min(RECENT_RUNS, len(runs)),
                last_success=last_success,
                detail=detail,
                open_findings=open_counts.get((repo, capability), 0),
            )
        )

    # Worst first: what is holding the most open, then the longest run of
    # failures. A lane blocking nothing is real but not urgent.
    stalled.sort(key=lambda lane: (-lane.open_findings, -lane.consecutive_failures))
    return stalled


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


def _concentration(catalog: Catalog, capability: str, limit: int = 5) -> list[tuple[str, int]]:
    """Where a class's findings pile up — package for dependency-shaped
    capabilities, rule for the rest.

    This is what turns a count into an action: "234 container findings" is a
    backlog, "twenty of them are libc6" is a base image.
    """
    column = "package_name" if capability in ("containers", "atlas") else "rule_id"
    rows = catalog.query(
        f"""
        SELECT coalesce({column}, '(unattributed)'), count(*)
        FROM findings
        WHERE status = 'open' AND capability = ?
        GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """,
        [capability, limit],
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


def build(catalog: Catalog, *, now: datetime | None = None) -> Briefing:
    """The whole briefing, from the lake."""
    from mykronos.schemas import utcnow

    stamp = now or utcnow()
    open_counts = _open_by_capability(catalog)

    totals: dict[str, int] = {}
    for (_, capability), count in open_counts.items():
        totals[capability] = totals.get(capability, 0) + count

    classes = [
        ClassSummary(
            capability=capability,
            open_findings=count,
            route=ROUTES.get(capability, "No standing route recorded for this class."),
            concentrated_in=_concentration(catalog, capability),
            action=CLASS_ACTIONS.get(capability),
        )
        for capability, count in sorted(totals.items(), key=lambda kv: -kv[1])
    ]

    return Briefing(
        generated_at=stamp,
        total_open=sum(totals.values()),
        stalled=stalled_lanes(catalog),
        classes=classes,
        # Only `atlas` has deterministic fixers with anything to act on; the
        # secrets fixer needs a credential in source rather than a reference.
        auto_fixable=totals.get("atlas", 0),
    )


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
            "  it gone. These lanes are failing, so their findings cannot close",
            "  however thoroughly the defect was fixed.",
            "",
        ]
        for lane in briefing.stalled:
            since = (
                f"last success {lane.last_success:%Y-%m-%d}"
                if lane.last_success
                else "no successful run on record"
            )
            streak = ("at least " if lane.streak_capped else "") + str(
                lane.consecutive_failures
            )
            lines.append(
                f"  {lane.capability:<11} {lane.repo_full_name}"
                f"  — {streak} consecutive failures, {since}"
            )
            lines.append(f"      holding {lane.open_findings} finding(s) open")
            if lane.detail:
                lines.append(f"      {lane.detail[:110]}")
            lines.append(f"      → {lane.action.method} {lane.action.path}")
        lines.append("")
    else:
        lines += ["Every lane is reporting. Findings can close.", ""]

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
