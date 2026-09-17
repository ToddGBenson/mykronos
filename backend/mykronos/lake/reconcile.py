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

**Absence retires an acceptance too (B-071).** This read `status = 'open'`
only, so a finding somebody had accepted could never stop being accepted
however many scans no longer saw it — TheHub carried 12 `critical` acceptances
for perl CVEs that had been patched twelve scans earlier, and nothing but the
October review date could have ended them. An acceptance is a judgement about
the risk a live vulnerability poses; absence removes the vulnerability, not the
judgement, and the judgement stays on the closed record. Which statuses this
does and does not extend to, and why they are not all alike, is
`CLOSEABLE_STATUSES` below.

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

#: The statuses absence is allowed to close, and the whole of the judgement in
#: this module about whose disposition a machine observation may end (B-071).
#:
#: `open` is the original rule: nobody has said anything, the scanner stopped
#: reporting it, it is fixed.
#:
#: `accepted_risk` is here because an acceptance is a judgement about **the
#: risk a live vulnerability poses**, and absence removes the vulnerability the
#: judgement was about. TheHub carried 12 `critical` acceptances for three perl
#: CVEs that twelve consecutive successful scans no longer saw: perl was
#: patched on 2026-09-12 and the register went on reporting accepted critical
#: risk for something that did not exist, with nothing able to end it before a
#: person arrived on the review date. `sweep_acceptances` already lets machine
#: evidence end an acceptance — it re-opens a `no_vendor_fix` acceptance the
#: day a `fixed_version` appears — so "a scan may contradict an acceptance's
#: premise" is established policy here, and the fix having actually been
#: *applied* is stronger evidence than the fix merely existing.
#:
#: Every other status is deliberately absent, and the reasons differ:
#:
#: - `false_positive` and `suppressed` are judgements about **the finding**,
#:   not about the risk. A report somebody declared bogus going quiet is not
#:   news; it is the scanner agreeing. Closing it `fixed` would assert a
#:   remediation that never happened and feed that lie to mean-time-to-fix.
#:   Worse, it would make the decision *impermanent*: compaction reopens a
#:   `fixed` finding the moment a scan sees it again, so a false positive
#:   auto-closed here comes back as `open` on the next sighting and the human
#:   judgement is gone. `accepted_risk` reopening that way is correct — the
#:   vulnerability returned and the acceptance's review date has lapsed — and
#:   for a false positive it is simply wrong.
#: - `superseded` is a withdrawn record (spec 05 §5a); closing those `fixed`
#:   reports a mass remediation every time an adapter is corrected.
#: - `stranded` is a finding whose capability cannot scan (B-047), so no
#:   confirming run can exist for it in the first place. Restoring the grant
#:   returns it to `open`, and then this rule decides on real evidence.
#: - `fixed` is already closed.
CLOSEABLE_STATUSES = ("open", "accepted_risk")


@dataclass
class ReconcileResult:
    fixed: list[str] = field(default_factory=list)
    partitions_written: int = 0
    #: How many of `fixed` were `accepted_risk` when absence closed them.
    #: Counted separately because it is the one number a person may want to
    #: audit: it is the platform ending decisions somebody made by hand.
    fixed_acceptances: int = 0
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

        # Which branch — and which tool — each closeable finding was last
        # observed by. Joined here rather than stored on the finding: both are
        # properties of the observation, and a finding seen again on a
        # different branch has genuinely moved lane.
        #
        # The tool is the one whose silence is allowed to close this finding.
        # A scanner that cannot read the language a finding is written in has
        # said nothing about it, and nothing is not evidence.
        #
        # `last_seen_scan_run_id` is what makes this sound for a finding a
        # person has dispositioned: ingest reports every finding the scanner
        # still sees regardless of its status, and compaction refreshes
        # `last_seen_scan_run_id` on every one of them — the human disposition
        # is preserved by the upsert, the observation underneath it is not
        # frozen. So an acceptance the scanner still reports carries a current
        # run id and is never a candidate here; only one nothing has reported
        # for two qualifying runs is.
        closeable = ", ".join(f"'{s}'" for s in CLOSEABLE_STATUSES)
        con.execute("DROP TABLE IF EXISTS finding_branch")
        con.execute(
            f"""
            CREATE TEMP TABLE finding_branch AS
            SELECT f.finding_id, f.dt, f.asset_id, f.capability, f.status,
                   coalesce(s.branch, '') AS branch,
                   coalesce(s.tool_name, '') AS tool_name
            FROM findings f
            JOIN scan_runs s ON s.scan_run_id = f.last_seen_scan_run_id
            WHERE f.status IN ({closeable})
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

        # Findings whose last sighting predates all of the recent runs
        # ON THEIR OWN BRANCH. Every clause below is scoped to that branch:
        # a finding is closed on evidence from the tree it was found in, and
        # from no other.
        candidates = con.execute(
            f"""
            SELECT b.finding_id, b.dt, b.status
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

        # Bucketed by the status we read, because that status is also the
        # guard we write under: `update_findings` re-checks it inside the
        # partition rewrite, so a disposition a person changed between this
        # read and that write wins. Splitting the buckets is what keeps that
        # guard exact — one call per status rather than one unguarded call
        # covering both.
        by_status: dict[str, dict[str, list[str]]] = {}
        for finding_id, dt, status in candidates:
            by_status.setdefault(str(status), {}).setdefault(str(dt), []).append(
                str(finding_id)
            )

        con.execute("DROP TABLE IF EXISTS recent_runs")
        con.execute("DROP TABLE IF EXISTS finding_branch")

    # Outside the connection: the shared helper opens its own, and holding two
    # writable handles to the same catalog is asking for a lock fight.
    for status in CLOSEABLE_STATUSES:
        by_partition = by_status.get(status)
        if not by_partition:
            continue
        outcome = update_findings(
            catalog,
            by_partition,
            # `accepted_until` and `accepted_reason_code` are deliberately left
            # standing on a closed acceptance. The decision is evidence about
            # how this estate reasons and it is worth keeping; what ends is its
            # status as a live claim about a vulnerability that is gone. It is
            # superseded, not discarded.
            "status = 'fixed', resolved_at = ?",
            [utcnow()],
            # A human disposition set between the read and the write wins.
            # Absence is an observation; false_positive is a decision, and a
            # finding a person has just marked one is no longer in this bucket.
            only_if_status=status,
        )
        result.fixed.extend(outcome.updated)
        result.partitions_written += outcome.partitions_written
        if status == "accepted_risk":
            result.fixed_acceptances += outcome.count

    if result.fixed:
        logger.info(
            "Reconciliation closed %s absent finding(s), %s of them accepted risks",
            result.total_fixed,
            result.fixed_acceptances,
        )
    return result




__all__ = [
    "CLOSEABLE_STATUSES",
    "REQUIRED_ABSENCES",
    "ReconcileResult",
    "reconcile_absences",
]
