"""Absence reconciliation — closing findings that stopped being reported.

spec 05 §5: a finding absent from the latest scan is marked `fixed`, but only
after **two consecutive scans** confirm its absence, so a flaky scanner that
misses something once does not close it and then reopen it next run. That
flapping would be worse than leaving it open: it destroys `resolved_at`,
corrupts mean-time-to-fix, and generates a reopened event every cycle.

Rather than tracking an absence counter on each finding, absence is derived:
if a finding's `last_seen_scan_run_id` is not among the two most recent
qualifying scans for its (repo, capability, **branch**), it has missed both.

**The branch is part of the lane, and leaving it out closed findings on
evidence from a tree they were never in (B-056).** `scan_runs` has always
carried a branch and this never read it, so every branch of a repository wrote
to one lane: TheHub is scanned on `develop` and on `main` at once, and each
repository also collects runs from the install pull requests Mykronos itself
opens. Two consecutive `main` scans could therefore confirm the absence of a
finding that only ever existed on `develop` — 61 of TheHub's `dast` findings
were last seen on `main` while the lane's live work is on `develop` — and the
next `develop` scan reopened it. That flapping is the exact outcome the
two-scan rule exists to prevent, arriving through the dimension the rule did
not have.

A finding's branch is the branch of the run that last saw it, which is the
only honest answer: it is where the platform actually observed the finding,
rather than where somebody expected it to be.

**On spec 05 §9's "no component other than the Ingestion API writes to the
Parquet partitions".** This job does write. The rule exists so that all
*ingestion* goes through one validating, deduplicating path — and this is not
ingestion. It is a derived state transition that belongs to the lake itself,
which is why it lives here beside compaction rather than in a service that
merely reads. Routing it through the findings endpoint would be actively
wrong: that path means "I observed this again", and its upsert would flip a
`fixed` finding straight back to `open`. See docs/DECISIONS.md D-014.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import update_findings
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: Scan outcomes that count as a real observation. A failed or partially
#: failed scan reporting nothing is not evidence a finding is gone — treating
#: it as such would close findings every time CI had a bad day.
CONFIRMING_STATUSES = ("success", "no_applicable_targets")

#: spec 05 §5. Two consecutive absences, not one.
REQUIRED_ABSENCES = 2


@dataclass
class ReconcileResult:
    fixed: list[str] = field(default_factory=list)
    partitions_written: int = 0
    #: (repo, capability) pairs skipped for lack of enough qualifying scans.
    #: Reported per pair rather than per branch: a caller asking "what could
    #: not be closed" wants the lane, and a repository scanned on four
    #: short-lived pull-request branches would otherwise report four rows
    #: about the same waiting.
    insufficient_history: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_fixed(self) -> int:
        return len(self.fixed)


def reconcile_absences(catalog: Catalog, required: int = REQUIRED_ABSENCES) -> ReconcileResult:
    """Close findings that have been absent from `required` consecutive scans."""
    result = ReconcileResult()
    if not catalog.all_files("findings"):
        return result

    with catalog.connect() as con:
        statuses = ", ".join(f"'{s}'" for s in CONFIRMING_STATUSES)

        # The most recent qualifying scan runs per
        # (repo, capability, branch, **tool**).
        #
        # `coalesce(branch, '')` rather than dropping the null ones: a run
        # that recorded no branch is its own lane and must not silently join
        # whichever lane happens to be first. Nothing in the estate produces
        # one today, and a scanner that starts to must not close findings on
        # another branch's behalf.
        #
        # `tool_name` for the same reason, one dimension over, and it became
        # load-bearing on 2026-09-09. `extra_analysers` puts two tools on one
        # capability on purpose: CodeQL implements no shell language, so
        # ShellCheck runs *alongside* it rather than instead of it (B-051).
        # Partitioning on capability alone made two CodeQL runs into two
        # qualifying `sast` scans, and every ShellCheck finding was absent
        # from both — because CodeQL cannot see shell and never could. They
        # closed as fixed, which is the reassuring direction and therefore the
        # worse one.
        #
        # It also quietly halved the guarantee. With both lanes reporting on
        # every push, the two most recent `sast` runs were one of each, so a
        # finding one push old counted as absent from "two consecutive scans"
        # after a single push.
        con.execute("DROP TABLE IF EXISTS recent_runs")
        con.execute(
            f"""
            CREATE TEMP TABLE recent_runs AS
            SELECT repo_full_name, capability, branch, tool_name, scan_run_id, rn
            FROM (
                SELECT repo_full_name, capability,
                       coalesce(branch, '') AS branch,
                       coalesce(tool_name, '') AS tool_name, scan_run_id,
                       row_number() OVER (
                           PARTITION BY repo_full_name, capability,
                                        coalesce(branch, ''),
                                        coalesce(tool_name, '')
                           ORDER BY coalesce(completed_at, started_at) DESC
                       ) AS rn
                FROM scan_runs
                WHERE scan_status IN ({statuses})
            ) WHERE rn <= {required}
            """
        )

        # Which branch — and which tool — each open finding was last observed
        # by. Joined here rather than stored on the finding: both are
        # properties of the observation, and a finding seen again on a
        # different branch has genuinely moved lane.
        #
        # The tool is the one whose silence is allowed to close this finding.
        # A scanner that cannot read the language a finding is written in has
        # said nothing about it, and nothing is not evidence.
        con.execute("DROP TABLE IF EXISTS finding_branch")
        con.execute(
            """
            CREATE TEMP TABLE finding_branch AS
            SELECT f.finding_id, f.dt, f.asset_id, f.capability,
                   coalesce(s.branch, '') AS branch,
                   coalesce(s.tool_name, '') AS tool_name
            FROM findings f
            JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id
            WHERE f.status = 'open'
            """
        )

        # A lane with fewer than `required` qualifying scans cannot yet confirm
        # anything. Recorded rather than silently skipped: "we have not looked
        # enough times" is different from "nothing to close". Reported per
        # (repo, capability) because that is the lane a person acts on, even
        # though the count that decided it is per branch.
        # Reported when NO branch of the lane has looked enough times. A lane
        # that is closing findings on `develop` is working, and saying it is
        # short of history because a pull-request branch was scanned once is
        # the kind of true-but-useless line that gets a report skipped.
        for repo, capability, branches, best in con.execute(
            """
            SELECT repo_full_name, capability, count(*) AS branches, max(runs) AS best
            FROM (
                SELECT repo_full_name, capability, branch, count(*) AS runs
                FROM recent_runs GROUP BY 1, 2, 3
            ) GROUP BY 1, 2 HAVING max(runs) < ?
            """,
            [required],
        ).fetchall():
            result.insufficient_history.append((str(repo), str(capability)))
            logger.debug(
                "Skipping %s/%s: %s branch(es), the best with %s qualifying scan(s)",
                repo,
                capability,
                branches,
                best,
            )

        # Open findings whose last sighting predates all of the recent runs
        # ON THEIR OWN BRANCH. Every clause below is scoped to that branch:
        # a finding is closed on evidence from the tree it was found in, and
        # from no other.
        candidates = con.execute(
            f"""
            SELECT b.finding_id, b.dt
            FROM finding_branch b
            JOIN findings f ON f.finding_id = b.finding_id
            WHERE EXISTS (
                  SELECT 1 FROM recent_runs r
                  -- scan_runs is about a repository and keeps
                  -- repo_full_name; findings are about an asset (spec 14 §5).
                  -- For a repository asset the two hold the same string.
                  WHERE r.repo_full_name = b.asset_id
                    AND r.capability = b.capability
                    AND r.branch = b.branch
                    AND r.tool_name = b.tool_name
                  GROUP BY r.repo_full_name, r.capability, r.branch, r.tool_name
                  HAVING count(*) >= {required}
              )
              AND f.last_seen_scan_run_id NOT IN (
                  SELECT r.scan_run_id FROM recent_runs r
                  WHERE r.repo_full_name = b.asset_id
                    AND r.capability = b.capability
                    AND r.branch = b.branch
                    AND r.tool_name = b.tool_name
              )
            """
        ).fetchall()

        if not candidates:
            con.execute("DROP TABLE IF EXISTS recent_runs")
            con.execute("DROP TABLE IF EXISTS finding_branch")
            return result

        by_partition: dict[str, list[str]] = {}
        for finding_id, dt in candidates:
            by_partition.setdefault(str(dt), []).append(str(finding_id))

        con.execute("DROP TABLE IF EXISTS recent_runs")
        con.execute("DROP TABLE IF EXISTS finding_branch")

    # Outside the connection: the shared helper opens its own, and holding two
    # writable handles to the same catalog is asking for a lock fight.
    outcome = update_findings(
        catalog,
        by_partition,
        "status = 'fixed', resolved_at = ?",
        [utcnow()],
        # A human disposition set between the read and the write wins. Absence
        # is an observation; false_positive is a decision.
        only_if_status="open",
    )
    result.fixed.extend(outcome.updated)
    result.partitions_written += outcome.partitions_written
    if result.fixed:
        logger.info("Reconciliation closed %s absent finding(s)", result.total_fixed)
    return result




__all__ = ["REQUIRED_ABSENCES", "ReconcileResult", "reconcile_absences"]
