"""The deploy ratchet: a deploy may not raise a repository's risk (D-182).

Operator decision 2026-11-15. A deploy of commit C for repository R is judged
against the commit R is running now (the *baseline*, D):

(a) REFUSED if C raises R's risk relative to D: its score is higher than D's
    by more than `TOLERANCE` (accumulated across deploys, see THE CREEP
    LEDGER), or C carries an open critical or high finding that D did not -
    by its own severity, by a KEV boost to high or critical, or as a member of
    a high or critical toxic combination;
(b) once R's score has been below the No-Go threshold (`policy.no_go`), a
    No-Go is a hard refusal. The first crossing is recorded per repository in
    `oracle_ratchet_latches` and never cleared by code. Operator decision
    2026-11-15, which replaces (b) as literally applied: while latched and the
    candidate is still No-Go, a deploy is ALLOWED only when it lowers the
    score by more than the tolerance and introduces no critical or high
    (`lowered_while_latched`); everything else is refused, with no repair
    exemption;
(c) the gate FAILS CLOSED: no decision for C, an unknown baseline, or an
    evaluation that could not be completed is a refusal with a named reason;
(d) a fix that lowers the score is allowed while R is still No-Go (unlatched).

WHICH REPOSITORIES. For now only this platform's own, and only while the
backend knows its own build (`enforceable`). Every other repository is
refused `not_enforceable`: its baseline would be the caller's word, and a
finding first seen on a feature-branch push, or on a pull request scanned
only before D, cannot be placed without a per-branch first-sighting record
(re-review of 6a448dfc). MyKronos's scans are push scans of main only.

THE TWO SCORES ARE MEASURED OVER ONE SNAPSHOT. Oracle's score describes the
whole open backlog, so two decisions recorded a day apart differ by every CVE
published in between, whatever the commits did. On 2026-11-14 MyKronos main
scored 166.3 against the deployed commit's 165.2, and all of the 1.1 was three
otel-sdk mediums and a dpkg low first seen that morning in images neither
commit changed. Comparing stored decisions would have refused every deploy
until the next CVE-free day. So nothing stored is compared. The backlog is
scored once, now, and BOTH scores are that score with the lake's current
state turned back into the state each commit carried: the findings a commit
did not have are taken out and the closed findings it did have are put back.
Every term a finding moves is re-scored, not only the severity bands: the
bands (with their dampened, in-flight and no-upstream-fix tallies), the age
terms, the KEV boost (`exploitability.<id>`), toxic combinations and the
No-Go they force, blast radius, and overdue findings. What the vulnerability
database did since D was scanned is in both states equally, so it cancels.

Reconstructing C as well as D, rather than taking C to be "now", is what
keeps a candidate older than the branch head honest: a high C introduced and
a later commit fixed is closed now, but C still carries it, so it is put back
on C's side and refuses.

WHICH COMMIT CARRIES A FINDING. There is no occurrence table: a finding
records only its first and its last sighting, and `last_seen_scan_run_id` is
overwritten by any scan, pull-request scans included. So:

* an open finding is carried by commit X unless it was *introduced after X*:
  first seen after X's first push scan on the branch, by a scan that is not
  of X or of a commit pushed before X (whatever kind of scan saw it first or
  last); or first seen on a pull request scanned before X whose pull request
  was scanned again after X existed (it was still open, so it merged after X);
* minus what `split_disclosed` calls newly disclosed (a CVE in an image whose
  bytes did not change, or on a dependency version the baseline already
  carried), which every commit carries;
* a finding that only its own pull request ever saw (first and last sighting
  the same pull request) is on no branch, so it is the same on both sides;
* a closed (`fixed`) finding is carried by X when it was not introduced after
  X and its last sighting is no earlier than X's last push scan of the same
  capability (so X's own scans never missed it);
* the same test applies to an open finding introduced inside the range: when
  X's own last scan of its capability no longer reports it, X fixed it, and
  does not carry it although reconciliation has not closed it yet.

Where a finding cannot be placed precisely it counts against C, because the
gate fails closed, with two exceptions, which are why only this platform's
own repository is judged: a finding first seen on a push of another branch
before D, and a pull request whose every scan predates D and that merged
after D without being scanned again. Both are on neither side.

Not re-scored, and held at their current value in both states: the
`posture.*` terms (including the critical-open credit cap),
`reachability.orphaned` and `accepted.residual`. The error mostly runs
against C.

A rollback (C scanned before D) needs nothing special: both states are
reconstructed the same way, so C lacks what the commits after it introduced
and carries again what they fixed, and a rollback past a security fix is
refused as introducing it.

THE CREEP LEDGER. The tolerance absorbs one small rise, not a series: ten
deploys at +0.4 each are +4.0, and a change could be split on purpose to stay
under 0.5. `oracle_ratchet_creep` keeps each repository's accumulated rise.
A deploy is refused `score_raised` when that plus its own rise passes the
tolerance. The gate learns that a deploy went through from the next question:
an allow records its delta as pending against the candidate sha, and the next
check that names that sha as the running baseline adds it (a lowering
subtracts, never below zero). A running sha that is not pending (a `-Force`
deploy, a deploy by hand, or an entry the 50-entry cap evicted) is measured
from the last confirmed sha over the current snapshot, and that rise is
added, so no deploy path ships a rise the ledger does not count.

THE BASELINE SOURCE. The caller names D from what is running (the deploy host
reads the running container's build stamp). For this platform's own
repository the backend answering is the deployment, so its `build_sha` is
authoritative: a caller that names anything else is refused. `baseline_for`
still reads another repository's baseline from the caller, with the
deployment probe's last reading (#361) beside it, but `evaluate` refuses
such a repository `not_enforceable` before using it (WHICH REPOSITORIES).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from mykronos import blast_radius, risk_evidence
from mykronos.db.models import OracleRatchetCreep, OracleRatchetLatch, RepoOnboarding
from mykronos.db.session import Database
from mykronos.deployments import OK as PROBE_OK
from mykronos.lake.reconcile import CONFIRMING_STATUSES
from mykronos.logsafe import scrub
from mykronos.oracle.engine import (
    AGE_DAYS,
    TOOL_IMAGE_SQL,
    OracleEngine,
    _overdue_snapshot,
    age_terms,
    finding_band_terms,
    kev_boost,
)
from mykronos.oracle.policy import Policy
from mykronos.schemas import utcnow
from mykronos.threat_intel import extract_cve

logger = logging.getLogger(__name__)

#: How far C's score may sit above the baseline's and still not "raise" it.
#:
#: Half a point of the published integer score. Because both scores are
#: measured over one snapshot, nothing here is noise in the drift sense; what
#: the tolerance absorbs is the smallest real changes, which the log curve
#: (D-018) makes tiny in a large band: one more medium on top of 13 adds
#: 5 x log2(15/14) = 0.497. A critical or high is never let through by it,
#: because rule (a)'s second clause refuses any introduced critical or high
#: outright. It is a budget across deploys, not per deploy (the creep
#: ledger). A constant rather than policy for the reason the floor is one: a
#: tolerance an operator can raise under pressure is one that reaches 100.
TOLERANCE = 0.5

#: Severities whose introduction refuses a deploy whatever the score does.
BLOCKING_SEVERITIES = ("critical", "high")

#: Recommendations that are measurements. Anything else (`not_assessed`,
#: `insufficient_evidence`, a word a later policy adds) is not one.
BANDS = ("go", "review_recommended", "no_go")

ALLOW = "allow"
REFUSE = "refuse"

# Refusal codes. Stable: deploy.ps1 and TheHub's risk_gate.py key on them.
NO_DECISION = "no_decision"
NOT_ASSESSED = "not_assessed"
BASELINE_UNKNOWN = "baseline_unknown"
BASELINE_DISAGREES = "baseline_disagrees"
EVALUATION_FAILED = "evaluation_failed"
SCORE_RAISED = "score_raised"
INTRODUCED_BLOCKING = "introduced_blocking"
LATCHED_NO_GO = "latched_no_go"
NOT_ENFORCEABLE = "not_enforceable"

# Allow codes, so an allow says which rule let it through.
NOT_RAISED = "not_raised"
LOWERED = "lowered"
LOWERED_WHILE_NO_GO = "lowered_while_no_go"
UNCHANGED_WHILE_NO_GO = "unchanged_while_no_go"
LOWERED_WHILE_LATCHED = "lowered_while_latched"

_SHA = re.compile(r"^[0-9a-f]{7,40}$")

#: How many not-yet-confirmed candidates the creep ledger remembers. An
#: evicted one is not lost: a running sha that is not pending is measured
#: from the last confirmed one instead (see `settle_creep`).
_PENDING_CAP = 50

#: Repositories the tests drive the comparison for although they are not this
#: platform's own. Never set outside the test suite.
_TEST_ENFORCEABLE: frozenset[str] = frozenset()


#: This platform's own repository, in full: the one whose deployment the
#: answering backend is. Any other owner's `.../mykronos` is not it.
SELF_REPO_FULL_NAME = "ToddGBenson/mykronos"


def _is_self(repo_full_name: str) -> bool:
    return repo_full_name.strip().lower() == SELF_REPO_FULL_NAME.lower()


def _confirming_sql() -> str:
    """Scan statuses that are evidence of what a commit carries: the ones
    absence reconciliation trusts. A failed or partial scan reporting nothing
    is not evidence a finding is gone (re-review of ab9a17d7, R-B1)."""
    return ", ".join(f"'{s}'" for s in CONFIRMING_STATUSES)


def enforceable(repo_full_name: str, self_build_sha: str) -> bool:
    """Whether the ratchet can judge this repository at all.

    Only this platform's own, and only while it knows its own build: there the
    baseline is the backend's `build_sha`, not the caller's word, and every
    scan is a push scan of main, so each finding's first sighting is on the
    branch being compared. For any other repository neither holds: the caller
    names the baseline (and so settles the creep ledger), and a high first
    seen on a feature-branch push or on a pull request scanned only before D
    is on neither side (re-review of 6a448dfc, N-B1). Until there is a
    per-branch first-sighting record and a trusted baseline, those answer
    `not_enforceable`, never allow.
    """
    if repo_full_name in _TEST_ENFORCEABLE:
        return True
    return _is_self(repo_full_name) and bool(_SHA.match((self_build_sha or "").strip().lower()))


@dataclass(frozen=True)
class Reason:
    code: str
    message: str

    def to_json(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class Judgement:
    allow: bool
    reasons: list[Reason]


def _pending_note(fix_credit_pending: int) -> str:
    if not fix_credit_pending:
        return ""
    return (
        f" Fix credit pending: {fix_credit_pending} finding(s) this commit's latest scan "
        "did not report stay open until a second scan closes them, and are not yet "
        "credited to it; there is no need to re-deploy to collect the credit."
    )


def judge(
    *,
    candidate_found: bool,
    candidate_recommendation: str | None,
    baseline_problem: Reason | None,
    evaluation_error: str | None,
    candidate_score: float | None,
    baseline_score: float | None,
    blocking_ids: list[str],
    latched: bool,
    no_go: float,
    tolerance: float = TOLERANCE,
    creep: float = 0.0,
    fix_credit_pending: int = 0,
) -> Judgement:
    """The ratchet's rule, as a pure function of what was measured.

    Every refusal that applies is listed, not only the first, so a caller
    fixing one does not discover the next on the following run. The
    fail-closed refusals come first and stop the comparison: without a
    decision or a baseline there is nothing to compare.

    `creep` is the rise earlier deploys already spent of the tolerance.
    """
    closed: list[Reason] = []
    if not candidate_found:
        closed.append(Reason(
            NO_DECISION,
            "The risk gate has never scored this commit. Concourse scores only a commit "
            "that passed every lane; wait for the gate or deploy the newest commit it scored.",
        ))
    elif candidate_recommendation not in BANDS:
        closed.append(Reason(
            NOT_ASSESSED,
            f"The decision for this commit is {candidate_recommendation!r}, which is not a "
            "measurement of risk (a required lane did not report on it).",
        ))
    if baseline_problem is not None:
        closed.append(baseline_problem)
    if evaluation_error is not None:
        closed.append(Reason(EVALUATION_FAILED, evaluation_error))
    if closed or candidate_score is None or baseline_score is None:
        if not closed:
            closed.append(Reason(EVALUATION_FAILED, "No score could be computed."))
        return Judgement(False, closed)

    creep = max(0.0, float(creep))
    delta = candidate_score - baseline_score
    pending = _pending_note(fix_credit_pending)
    refusals: list[Reason] = []
    if blocking_ids:
        refusals.append(Reason(
            INTRODUCED_BLOCKING,
            f"This deploy brings {len(blocking_ids)} open critical or high finding(s) the "
            "running commit does not have (by severity, a KEV boost, or a high or critical "
            f"toxic combination): {', '.join(blocking_ids[:10])}"
            + (" ..." if len(blocking_ids) > 10 else "") + "." + pending,
        ))
    if delta > 0 and delta + creep > tolerance:
        refusals.append(Reason(
            SCORE_RAISED,
            f"This deploy raises the risk score from {baseline_score:.2f} to "
            f"{candidate_score:.2f} (+{delta:.2f}"
            + (f", on top of +{creep:.2f} earlier deploys already added" if creep else "")
            + f"; tolerance {tolerance:g} in total).",
        ))
    lowered = delta < -tolerance
    if latched and candidate_score >= no_go and not (lowered and not blocking_ids):
        refusals.append(Reason(
            LATCHED_NO_GO,
            f"The repository has been below No-Go ({no_go:g}) before, so a No-Go deploy is "
            f"refused unless it lowers the score by more than {tolerance:g} and introduces "
            f"no critical or high (D-182 (b), operator decision 2026-11-15). This deploy "
            f"scores {candidate_score:.2f} ({delta:+.2f})"
            + (
                "; the change itself does not raise it, so the No-Go is the backlog: "
                "lower it below the threshold, or override with a recorded reason."
                if delta <= tolerance else "."
            ),
        ))
    if refusals:
        return Judgement(False, refusals)

    if candidate_score >= no_go:
        if latched:
            return Judgement(True, [Reason(
                LOWERED_WHILE_LATCHED,
                f"Still No-Go at {candidate_score:.2f} on a repository that has been below "
                f"{no_go:g}, but this deploy lowers the score by {-delta:.2f} (more than "
                f"{tolerance:g}) and introduces no critical or high, so it is allowed "
                "(D-182 (b), operator decision 2026-11-15)." + pending,
            )])
        code = LOWERED_WHILE_NO_GO if lowered else UNCHANGED_WHILE_NO_GO
        return Judgement(True, [Reason(
            code,
            f"Still No-Go at {candidate_score:.2f}, but the repository has never been below "
            f"{no_go:g}, and this deploy does not raise the score ({delta:+.2f}), so it is "
            "allowed (D-182 (d))." + pending,
        )])
    code = LOWERED if lowered else NOT_RAISED
    return Judgement(True, [Reason(
        code,
        f"The score moves from {baseline_score:.2f} to {candidate_score:.2f} ({delta:+.2f}"
        + (f"; +{creep:.2f} of the {tolerance:g} tolerance already spent" if creep else "")
        + ") and nothing critical or high is introduced." + pending,
    )])


# -- the latch ----------------------------------------------------------------


@dataclass(frozen=True)
class Latch:
    latched: bool
    latched_at: datetime | None = None
    commit_sha: str = ""
    raw_score: float | None = None
    source: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "latched": self.latched,
            "latched_at": self.latched_at.isoformat() if self.latched_at else None,
            "commit_sha": self.commit_sha or None,
            "raw_score": self.raw_score,
            "source": self.source or None,
        }


def read_latch(db: Database, repo_full_name: str) -> Latch:
    """The repository's latch. Raises if the store cannot be read: the caller
    refuses, because an unreadable latch must not read as "not latched"."""
    with db.session() as session:
        row = session.get(OracleRatchetLatch, repo_full_name)
        if row is None:
            return Latch(latched=False)
        return Latch(
            latched=True,
            latched_at=row.latched_at,
            commit_sha=row.commit_sha,
            raw_score=row.raw_score,
            source=row.source,
        )


def note_score(
    db: Database,
    repo_full_name: str,
    *,
    raw_score: float,
    recommendation: str,
    policy: Policy,
    commit_sha: str,
    source: str,
) -> bool:
    """Latch the repository if this score is the first below No-Go.

    Only a measurement latches (`go` or `review_recommended`): a repository
    nothing has looked at scores 0, and the absence of evidence must not set
    a latch any more than it may read as safety (#341). Returns True when
    this call set the latch. Idempotent; a latch is never moved or cleared.
    """
    if recommendation not in ("go", "review_recommended") or raw_score >= policy.no_go:
        return False
    with db.session() as session:
        if session.get(OracleRatchetLatch, repo_full_name) is not None:
            return False
        session.add(OracleRatchetLatch(
            repo_full_name=repo_full_name,
            latched_at=utcnow(),
            commit_sha=commit_sha,
            raw_score=float(raw_score),
            no_go_threshold=float(policy.no_go),
            policy_version=policy.version,
            source=source,
        ))
    logger.warning(
        "Deploy ratchet latched for %s at %s (raw %.2f < no_go %s): a No-Go deploy is "
        "now a hard refusal (D-182).",
        scrub(repo_full_name), scrub(commit_sha), raw_score, policy.no_go,
    )
    return True


# -- the creep ledger -----------------------------------------------------------


def _pending(row: OracleRatchetCreep) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(row.pending_json or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def settle_creep(
    db: Database,
    repo_full_name: str,
    deployed_sha: str,
    *,
    measure: Callable[[str, str], float],
) -> float:
    """The repository's accumulated rise, after accounting for what now runs.

    When the running sha is not the last confirmed one, something shipped:
    * if the gate allowed it (it is pending), its recorded delta is added;
    * otherwise (a `-Force` deploy, a deploy by hand, or a pending entry the
      cap evicted) the change is measured, `measure(confirmed, running)` over
      the current snapshot, and that delta is added, so no deploy path can
      ship a rise the ledger never sees.
    A lowering subtracts, never below zero. Either way every pending entry is
    cleared, because they were all measured over a baseline that no longer
    runs. The first sha ever seen is taken as the starting point. Raises if
    the store cannot be read or written, or the change cannot be measured;
    the caller refuses, because an unreadable ledger must not read as "no
    creep".
    """
    deployed = (deployed_sha or "").strip().lower()
    with db.session() as session:
        row = session.get(OracleRatchetCreep, repo_full_name)
        if row is None:
            if not deployed:
                return 0.0
            row = OracleRatchetCreep(
                repo_full_name=repo_full_name, accepted_creep=0.0, confirmed_sha=deployed,
                pending_json="{}", updated_at=utcnow(),
            )
            session.add(row)
            return 0.0
        confirmed = (row.confirmed_sha or "").strip().lower()
        if deployed and not _same(deployed, confirmed):
            pending = _pending(row)
            match = next((sha for sha in pending if _same(sha, deployed)), None)
            if match is not None:
                delta = float(pending[match].get("delta") or 0.0)
            elif confirmed:
                delta = float(measure(confirmed, deployed))
            else:
                delta = 0.0  # the starting point: nothing earlier to measure from
            row.accepted_creep = max(0.0, float(row.accepted_creep or 0.0) + delta)
            row.confirmed_sha = deployed
            row.pending_json = "{}"
            row.updated_at = utcnow()
        return float(row.accepted_creep or 0.0)


def record_pending(
    db: Database, repo_full_name: str, *, candidate: str, baseline: str, delta: float
) -> None:
    """Remember an allowed deploy's delta until the candidate is seen running."""
    with db.session() as session:
        row = session.get(OracleRatchetCreep, repo_full_name)
        if row is None:
            row = OracleRatchetCreep(
                repo_full_name=repo_full_name, accepted_creep=0.0, confirmed_sha="",
                pending_json="{}",
            )
            session.add(row)
        pending = _pending(row)
        pending.pop(candidate, None)
        pending[candidate] = {
            "delta": round(float(delta), 4), "baseline": baseline, "at": utcnow().isoformat(),
        }
        while len(pending) > _PENDING_CAP:
            pending.pop(next(iter(pending)))
        row.pending_json = json.dumps(pending)
        row.updated_at = utcnow()


def ratchet_state(db: Database, repo_full_name: str) -> tuple[bool, tuple[Any, ...] | None]:
    """The latch and creep rows as a comparable value, for the route's cache."""
    with db.session() as session:
        latch = session.get(OracleRatchetLatch, repo_full_name)
        creep = session.get(OracleRatchetCreep, repo_full_name)
        return (
            latch is not None,
            None if creep is None
            else (creep.accepted_creep, creep.confirmed_sha, creep.pending_json),
        )


# -- the lake reads -----------------------------------------------------------


def _resolve(catalog: Any, repo_full_name: str, sha: str) -> list[str]:
    """Full shas this repository's scans carry that `sha` names (prefix either way)."""
    rows = catalog.query(
        """
        SELECT DISTINCT lower(commit_sha) FROM scan_runs
        WHERE repo_full_name = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
          AND (starts_with(lower(commit_sha), ?) OR starts_with(?, lower(commit_sha)))
        """,
        [repo_full_name, sha, sha],
    )
    return sorted({str(r[0]) for r in rows})


def _push_scans(catalog: Any, repo_full_name: str, sha: str) -> dict[str, tuple[Any, Any]]:
    """Branch -> (first, last) push-scan start for one commit. Pull-request
    scans are not on a branch's line of history and are left out."""
    rows = catalog.query(
        """
        SELECT coalesce(branch, ''), min(started_at), max(started_at)
        FROM scan_runs
        WHERE repo_full_name = ? AND lower(commit_sha) = ? AND coalesce(pr_number, 0) = 0
        GROUP BY 1
        """,
        [repo_full_name, sha],
    )
    return {str(r[0]): (r[1], r[2]) for r in rows if r[1] is not None}


def _capability_last(
    catalog: Any, repo_full_name: str, branch: str, sha: str
) -> dict[str, Any]:
    """Capability -> the commit's last confirming push scan of it on the
    branch. Only a scan that completed counts: it is what says a finding the
    commit had is gone (`_missed`, and the closed-row rule in `_carries`)."""
    rows = catalog.query(
        f"""
        SELECT capability, max(started_at) FROM scan_runs
        WHERE repo_full_name = ? AND lower(commit_sha) = ? AND coalesce(pr_number, 0) = 0
          AND coalesce(branch, '') = ? AND scan_status IN ({_confirming_sql()})
        GROUP BY 1
        """,
        [repo_full_name, sha, branch],
    )
    return {str(r[0]): r[1] for r in rows if r[1] is not None}


def _range(
    catalog: Any, repo_full_name: str, branch: str, after: Any, upto: Any
) -> list[str]:
    """Commits whose first push scan on `branch` is in (after, upto]."""
    rows = catalog.query(
        """
        SELECT lower(commit_sha), min(started_at) AS first_at
        FROM scan_runs
        WHERE repo_full_name = ? AND coalesce(branch, '') = ? AND coalesce(pr_number, 0) = 0
          AND commit_sha IS NOT NULL AND commit_sha <> ''
        GROUP BY 1
        HAVING min(started_at) > ? AND min(started_at) <= ?
        ORDER BY first_at
        """,
        [repo_full_name, branch, after, upto],
    )
    return [str(r[0]) for r in rows]


def _in_scope_sql(policy: Policy) -> str:
    """The engine's scoring scope for a gate, as one boolean expression."""
    severities = ", ".join(f"'{s}'" for s in policy.severities_in_scope())
    parts = [f"f.severity IN ({severities})"]
    if policy.capabilities_excluded_from_gates:
        names = ", ".join(f"'{c}'" for c in policy.capabilities_excluded_from_gates)
        parts.append(f"f.capability NOT IN ({names})")
    if policy.exclude_tool_images:
        parts.append(f"NOT ({TOOL_IMAGE_SQL})")
    return "(" + " AND ".join(parts) + ")"


@dataclass
class _Row:
    """One finding, with what is known about where it was seen."""

    finding_id: str
    severity: str
    capability: str
    rule_id: str
    title: str
    status: str
    in_scope: bool
    is_tool: bool
    package: str
    version: str
    fixed_version: str
    first_seen_at: Any
    due_at: Any
    fs_scan: str
    fs_at: Any
    fs_pr: int
    fs_commit: str
    fs_commit_first: Any
    ls_at: Any
    ls_pr: int
    pr_last: Any
    image: str | None
    baseline: Any
    remedy: Any
    disclosed: bool = False

    @property
    def pr_only(self) -> bool:
        """Seen by its own pull request and nothing else: on no branch."""
        return self.fs_pr != 0 and self.ls_pr == self.fs_pr

    def split_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "severity": self.severity,
            "capability": self.capability, "rule_id": self.rule_id, "_scan": self.fs_scan,
            "_image": self.image, "_package": self.package, "_version": self.version,
            "_baseline": self.baseline, "_remedy": self.remedy,
        }


def _rows(
    catalog: Any, policy: Policy, repo_full_name: str, branch: str, since: Any
) -> list[_Row]:
    """The findings whose place relative to two commits first scanned no earlier
    than `since` can differ: open ones first seen after it (or on a pull request
    scanned after it), and closed ones last seen at or after it. Everything else
    is the same on both sides."""
    open_statuses = ", ".join(f"'{s}'" for s in policy.statuses_considered)
    tool = TOOL_IMAGE_SQL if policy.exclude_tool_images else "false"
    rows = catalog.query(
        f"""
        WITH cp AS (
            SELECT lower(commit_sha) AS sha, min(started_at) AS first_at
            FROM scan_runs
            WHERE repo_full_name = ? AND coalesce(pr_number, 0) = 0
              AND coalesce(branch, '') = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
            GROUP BY 1
        ), pl AS (
            SELECT pr_number, max(started_at) AS last_at
            FROM scan_runs
            WHERE repo_full_name = ? AND coalesce(pr_number, 0) <> 0
            GROUP BY 1
        )
        SELECT f.finding_id, lower(f.severity), f.capability, f.rule_id, coalesce(f.title, ''),
               f.status, {_in_scope_sql(policy)} AS in_scope, ({tool}) AS is_tool,
               lower(trim(coalesce(f.package_name, ''))), coalesce(f.package_version, ''),
               coalesce(json_extract_string(f.raw_finding_json, '$.fixed_version'), ''),
               f.first_seen_at, f.due_at, f.first_seen_scan_run_id,
               fs.started_at, coalesce(fs.pr_number, 0), lower(coalesce(fs.commit_sha, '')),
               fcp.first_at,
               coalesce(ls.started_at, f.last_seen_at), coalesce(ls.pr_number, 0), pl.last_at,
               json_extract_string(f.raw_finding_json, '$.image'),
               json_extract(f.raw_finding_json, '$.baseline_commits'),
               json_extract(f.raw_finding_json, '$.remediated_by'),
               f.package_name
        FROM findings f
        JOIN scan_runs fs ON fs.scan_run_id = f.first_seen_scan_run_id
        LEFT JOIN scan_runs ls ON ls.scan_run_id = f.last_seen_scan_run_id
        LEFT JOIN cp fcp ON fcp.sha = lower(fs.commit_sha)
        LEFT JOIN pl ON pl.pr_number = fs.pr_number AND coalesce(fs.pr_number, 0) <> 0
        WHERE f.asset_id = ? AND fs.repo_full_name = ?
          AND (
                (f.status IN ({open_statuses})
                 AND (fs.started_at > ? OR (coalesce(fs.pr_number, 0) <> 0 AND pl.last_at > ?)))
             OR (f.status = 'fixed' AND coalesce(ls.started_at, f.last_seen_at) >= ?)
          )
        """,
        [repo_full_name, branch, repo_full_name, repo_full_name, repo_full_name,
         since, since, since],
    )
    out: list[_Row] = []
    for (fid, severity, capability, rule_id, title, status, scoped, is_tool, package,
         version, fixed_version, first_seen_at, due_at, fs_scan, fs_at, fs_pr, fs_commit,
         fs_commit_first, ls_at, ls_pr, pr_last, image, baseline, remedy, raw_package) in rows:
        out.append(_Row(
            finding_id=str(fid), severity=str(severity), capability=str(capability),
            rule_id=str(rule_id), title=str(title), status=str(status),
            in_scope=bool(scoped), is_tool=bool(is_tool), package=str(package or ""),
            version=str(version or ""), fixed_version=str(fixed_version or ""),
            first_seen_at=first_seen_at, due_at=due_at, fs_scan=str(fs_scan), fs_at=fs_at,
            fs_pr=int(fs_pr or 0), fs_commit=str(fs_commit or ""),
            fs_commit_first=fs_commit_first, ls_at=ls_at, ls_pr=int(ls_pr or 0),
            pr_last=pr_last, image=None if image is None else str(image),
            baseline=baseline, remedy=remedy,
        ))
        # `split_disclosed` compares the package as the scanner named it.
        out[-1].package = str(raw_package or "")
    return out


@dataclass(frozen=True)
class _Commit:
    sha: str
    first: Any  # first push scan on the branch, any capability
    last_by_capability: dict[str, Any]


def _after(row: _Row, commit: _Commit) -> bool:
    """Whether the finding was (or may have been) introduced after `commit`."""
    if row.disclosed or row.pr_only:
        return False
    if row.fs_at is not None and row.fs_at > commit.first:
        if row.fs_commit == commit.sha:
            return False  # a rescan of the commit itself found it
        # Not when a rescan of an older commit on the branch found it.
        return row.fs_commit_first is None or row.fs_commit_first > commit.first
    # First seen on a pull request before the commit existed, and that pull
    # request was still being scanned after: it merged after the commit.
    return row.fs_pr != 0 and row.pr_last is not None and row.pr_last > commit.first


def _carries(row: _Row, commit: _Commit) -> bool:
    """Whether `commit` carries the finding (open now, or closed since)."""
    if row.pr_only:
        return row.status != "fixed"
    if _after(row, commit):
        return False
    if row.status != "fixed":
        return True
    # Closed: the commit carried it if its own scans of that capability never
    # missed it, i.e. the last sighting is no earlier than its last such scan.
    if row.ls_at is None:
        return False
    last = commit.last_by_capability.get(row.capability)
    return bool(row.ls_at >= (last if last is not None else commit.first))


def _missed(row: _Row, commit: _Commit) -> bool:
    """Whether `commit`'s own last push scan of the finding's capability ran
    after the finding's last sighting: that scan did not report it."""
    last = commit.last_by_capability.get(row.capability)
    return row.ls_at is not None and last is not None and bool(row.ls_at < last)


# -- re-scoring a state -------------------------------------------------------


def _terms_by_key(snapshot: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for term in snapshot.get("terms") or []:
        key = str(term.get("key") or "")
        out[key] = out.get(key, 0.0) + float(term.get("contribution") or 0.0)
    return out


def _sum_prefix(terms: dict[str, float], prefix: str) -> float:
    return sum(v for k, v in terms.items() if k.startswith(prefix))


def _band_inputs(
    snapshot: dict[str, Any],
) -> tuple[dict[str, int], dict[str, int], dict[str, int], dict[str, int]]:
    """The tallies the engine scored its finding bands on, from its snapshot."""
    counts: dict[str, int] = {}
    dampened: dict[str, int] = {}
    covered: dict[str, int] = {}
    unfixable: dict[str, int] = {}
    for term in snapshot.get("terms") or []:
        key = str(term.get("key") or "")
        if not key.startswith("findings."):
            continue
        severity = key.split(".", 1)[1]
        inputs = term.get("inputs") or {}
        counts[severity] = int(inputs.get("count") or 0)
        dampened[severity] = int(inputs.get("dampened") or 0)
        covered[severity] = int(inputs.get("remediation_in_flight") or 0)
        unfixable[severity] = int(inputs.get("no_upstream_fix") or 0)
    return counts, dampened, covered, unfixable


@dataclass(frozen=True)
class _Combination:
    severity: str
    finding_ids: frozenset[str]


@dataclass
class _Scorer:
    """Turns the current snapshot into the score of another state of the findings."""

    engine: OracleEngine
    repo_full_name: str
    snapshot: dict[str, Any]
    current_raw: float
    as_of: datetime
    covered: set[str]
    kev: dict[str, tuple[str, float]]
    terms: dict[str, float] = field(default_factory=dict)
    dampened_rules: set[str] = field(default_factory=set)
    _packages: dict[str, int] | None = None
    _dependents: dict[str, int] | None = None
    _dependents_read: bool = False

    def __post_init__(self) -> None:
        self.terms = _terms_by_key(self.snapshot)
        damp = (self.snapshot.get("false_positive_dampening") or {}).get("dampened_rules")
        self.dampened_rules = {
            str(r.get("rule_id")) for r in (damp or []) if isinstance(r, dict)
        }

    @property
    def policy(self) -> Policy:
        return self.engine.policy

    def combinations_now(self) -> list[_Combination]:
        block = self.snapshot.get("toxic_combinations") or {}
        return [
            _Combination(
                str(c.get("severity")), frozenset(str(i) for i in c.get("finding_ids") or [])
            )
            for c in block.get("combinations") or []
        ]

    def _combinations(self, drop: list[_Row], add: list[_Row]) -> list[_Combination]:
        pol = self.policy.toxic_combinations
        kwargs: dict[str, Any] = {
            "escalate_steps": pol.escalate_steps,
            "drop_ids": frozenset(r.finding_id for r in drop),
            "add_ids": tuple(sorted(r.finding_id for r in add)),
        }
        if self.engine.db is not None:
            with self.engine.db.session() as session:
                combos = risk_evidence.toxic_combinations(
                    self.engine.catalog, session, self.repo_full_name, **kwargs
                )
        else:
            combos = risk_evidence.toxic_combinations(
                self.engine.catalog, None, self.repo_full_name, **kwargs
            )
        return [
            _Combination(str(c.severity), frozenset(str(m["finding_id"]) for m in c.members))
            for c in combos
        ]

    def _radius(self, drop: list[_Row], add: list[_Row], lenient: bool) -> float | None:
        """Blast radius for the edited state, or None when it is not scored."""
        if not self._dependents_read:
            self._dependents_read = True
            self._dependents = blast_radius.build(self.engine.catalog)
            not_tool = f"AND NOT ({TOOL_IMAGE_SQL})" if self.policy.exclude_tool_images else ""
            self._packages = {
                str(name): int(n)
                for name, n in self.engine.catalog.query(
                    f"""
                    SELECT lower(trim(package_name)), count(*) FROM findings
                    WHERE asset_id = ? AND status = 'open'
                      AND package_name IS NOT NULL AND trim(package_name) <> ''
                      {not_tool}
                    GROUP BY 1
                    """,
                    [self.repo_full_name],
                )
            }
        if self._dependents is None or self._packages is None:
            return None
        packages = dict(self._packages)
        for row in drop:
            name = row.package.strip().lower()
            if name and not row.is_tool and row.status != "fixed":
                packages[name] = packages.get(name, 0) - 1
        for row in add:
            name = row.package.strip().lower()
            if name and not row.is_tool:
                packages[name] = packages.get(name, 0) + 1
        pol = self.policy.blast_radius
        concentrated = 0
        for name, n in packages.items():
            if n <= 0:
                continue
            dependents = self._dependents.get(name, 0)
            # A package this repository does not carry now is not in the
            # finding-derived count for it; the candidate's side assumes it
            # would be, the baseline's that it would not.
            if lenient and self._packages.get(name, 0) <= 0:
                dependents += 1
            if dependents >= pol.min_dependents:
                concentrated += 1
        return min(pol.points_per_package * concentrated, pol.cap)

    def score(
        self, drop: list[_Row], add: list[_Row], *, lenient: bool
    ) -> tuple[float, list[_Combination]]:
        """The raw score with `drop` taken out and `add` put back.

        `lenient` is the candidate's side: where a term can only be estimated,
        the candidate is estimated high and the baseline low, so an estimate
        never lets a rise through.
        """
        if not drop and not add:
            return self.current_raw, self.combinations_now()
        policy = self.policy
        terms = self.terms
        lift_now = terms.get("toxic_combination_no_go", 0.0)
        moved_now = (
            _sum_prefix(terms, "findings.")
            + _sum_prefix(terms, "age.")
            + _sum_prefix(terms, "exploitability.")
            + terms.get("toxic_combinations", 0.0)
            + terms.get("blast_radius", 0.0)
            + terms.get("overdue_findings", 0.0)
        )
        other = self.current_raw - lift_now - moved_now

        # 1. The bands, with all four tallies moved together.
        counts, dampened, covered, unfixable = _band_inputs(self.snapshot)
        counts, dampened = dict(counts), dict(dampened)
        covered, unfixable = dict(covered), dict(unfixable)
        aged = {str(k): int(v) for k, v in ((self.snapshot.get("findings") or {})
                                             .get("aged") or {}).items()}
        overdue_block = self.snapshot.get("overdue_findings") or {}
        overdue = int(overdue_block.get("overdue_findings") or 0)
        with_target = int(overdue_block.get("findings_with_a_target") or 0)
        kev_total = _sum_prefix(terms, "exploitability.")
        for sign, rows in ((-1, drop), (1, add)):
            for row in rows:
                if not row.in_scope:
                    continue
                s = row.severity
                counts[s] = counts.get(s, 0) + sign
                if row.rule_id in self.dampened_rules:
                    dampened[s] = dampened.get(s, 0) + sign
                if row.finding_id in self.covered:
                    covered[s] = covered.get(s, 0) + sign
                if row.package.strip() and not row.fixed_version:
                    unfixable[s] = unfixable.get(s, 0) + sign
                days = AGE_DAYS.get(s)
                if days is not None and row.first_seen_at is not None and (
                    row.first_seen_at <= self.as_of - timedelta(days=days)
                ):
                    aged[s] = aged.get(s, 0) + sign
                if row.due_at is not None:
                    with_target += sign
                    if row.due_at <= self.as_of:
                        overdue += sign
                kev_total += sign * self.kev.get(row.finding_id, ("", 0.0))[1]
        for tally in (counts, dampened, covered, unfixable, aged):
            for s in list(tally):
                tally[s] = max(0, tally[s])
        band_terms, _ = finding_band_terms(counts, dampened, covered, unfixable, policy)
        bands = sum(t.contribution for t in band_terms)
        age = sum(t.contribution for t in age_terms(aged, policy))
        kev_total = max(0.0, kev_total)

        # 2. Overdue, when the policy sets deadlines at all.
        if overdue_block.get("available"):
            overdue_points = sum(
                t.contribution
                for t in _overdue_snapshot(max(0, overdue), max(0, with_target), policy)[1]
            )
        else:
            overdue_points = terms.get("overdue_findings", 0.0)

        # 3. Toxic combinations, detected again over the edited pool.
        combos = self._combinations(drop, add)
        pol = policy.toxic_combinations
        forces = pol.critical_forces_no_go and any(c.severity == "critical" for c in combos)
        toxic_points = min(
            sum(
                pol.points.get(c.severity, 0.0)
                for c in combos
                if not (forces and c.severity == "critical")
            ),
            pol.cap,
        )

        # 4. Blast radius.
        radius = self._radius(drop, add, lenient)
        if radius is None:
            radius = terms.get("blast_radius", 0.0)

        raw = other + bands + age + kev_total + overdue_points + toxic_points + radius
        if forces and raw < policy.no_go:
            raw = float(policy.no_go)
        return raw, combos


def _kev(engine: OracleEngine, rows: list[_Row]) -> dict[str, tuple[str, float]]:
    """finding id -> (boosted_to, boost) for KEV-listed in-scope findings, the
    engine's own rule (spec 17 §5.4). Empty without the operational database,
    as the engine's exploitability category is."""
    if engine.db is None:
        return {}
    by_cve: dict[str, list[_Row]] = {}
    for row in rows:
        if not row.in_scope:
            continue
        cve = extract_cve(row.rule_id, row.title)
        if cve is not None:
            by_cve.setdefault(cve, []).append(row)
    if not by_cve:
        return {}
    with engine.db.session() as session:
        matches = risk_evidence.threat_signals(session, by_cve)
    out: dict[str, tuple[str, float]] = {}
    for cve, members in by_cve.items():
        match = matches.get(cve) or matches.get(cve.upper())
        if not (match and match.in_kev):
            continue
        for row in members:
            boosted_to, boost = kev_boost(row.severity, engine.policy.severity_weights)
            if boost > 0:
                out[row.finding_id] = (boosted_to, boost)
    return out


def _stored_decision(
    catalog: Any, repo_full_name: str, sha: str, *, exact: bool = False
) -> dict[str, Any] | None:
    """The newest decision recorded for this repository at this commit.

    `exact` once the sha is resolved to the full one, so a short prefix
    cannot pick up another commit's decision."""
    match = (
        "lower(commit_sha) = ?"
        if exact
        else "(starts_with(lower(commit_sha), ?) OR starts_with(?, lower(commit_sha)))"
    )
    rows = catalog.query(
        f"""
        SELECT decision_id, decision_type, commit_sha, overall_risk_score, recommendation,
               policy_version, evaluated_at, inputs_snapshot, human_override
        FROM risk_decisions
        WHERE repo_full_name = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
          AND {match}
        ORDER BY evaluated_at DESC
        LIMIT 1
        """,
        [repo_full_name, sha] if exact else [repo_full_name, sha, sha],
    )
    if not rows:
        return None
    (decision_id, decision_type, commit_sha, score, recommendation, policy_version,
     evaluated_at, snapshot, override) = rows[0]
    raw: float | None = None
    try:
        totals = json.loads(snapshot or "{}").get("totals") or {}
        raw = float(totals["raw_score"]) if "raw_score" in totals else None
    except (TypeError, ValueError, json.JSONDecodeError):
        raw = None
    return {
        "decision_id": str(decision_id),
        "decision_type": str(decision_type),
        "commit_sha": str(commit_sha),
        "overall_risk_score": None if score is None else int(score),
        "raw_score": raw,
        "recommendation": str(recommendation),
        "policy_version": str(policy_version or ""),
        "evaluated_at": evaluated_at.isoformat()
        if isinstance(evaluated_at, datetime) else (None if evaluated_at is None
                                                    else str(evaluated_at)),
        "overridden": override not in (None, "", "null"),
    }


def _fix_credit_pending(
    catalog: Any, policy: Policy, repo_full_name: str, branch: str, candidate: str
) -> set[str]:
    """Open in-scope findings whose last sighting is a push scan older than the
    candidate's last push scan of their capability: its scan no longer reports
    them, and absence reconciliation has not yet closed them."""
    statuses = ", ".join(f"'{s}'" for s in policy.statuses_considered)
    rows = catalog.query(
        f"""
        WITH cq AS (
            SELECT capability, max(started_at) AS last_at FROM scan_runs
            WHERE repo_full_name = ? AND lower(commit_sha) = ? AND coalesce(pr_number, 0) = 0
              AND coalesce(branch, '') = ? AND scan_status IN ({_confirming_sql()})
            GROUP BY 1
        )
        SELECT f.finding_id FROM findings f
        JOIN scan_runs ls ON ls.scan_run_id = f.last_seen_scan_run_id
        JOIN cq ON cq.capability = f.capability
        WHERE f.asset_id = ? AND f.status IN ({statuses}) AND {_in_scope_sql(policy)}
          AND coalesce(ls.pr_number, 0) = 0 AND ls.started_at < cq.last_at
        """,
        [repo_full_name, candidate, branch, repo_full_name],
    )
    return {str(r[0]) for r in rows}


# -- the baseline -------------------------------------------------------------


@dataclass
class Baseline:
    sha: str | None
    source: str
    probe_revision: str | None = None
    problem: Reason | None = None


def _same(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    if not a or not b:
        return False
    return a.startswith(b) or b.startswith(a)


def baseline_for(
    db: Database, repo_full_name: str, claimed: str | None, self_build_sha: str
) -> Baseline:
    """Which commit R is running, and where that answer came from."""
    claimed = (claimed or "").strip().lower() or None
    if claimed is not None and not _SHA.match(claimed):
        return Baseline(None, "caller", problem=Reason(
            BASELINE_UNKNOWN, f"deployed={claimed!r} is not a commit sha (7-40 hex)."))
    is_self = _is_self(repo_full_name)
    own = (self_build_sha or "").strip().lower()
    if is_self and _SHA.match(own):
        if claimed is not None and not _same(claimed, own):
            return Baseline(own, "this process (MYKRONOS_BUILD_SHA)", problem=Reason(
                BASELINE_DISAGREES,
                f"The caller says {claimed[:12]} is deployed, but the backend answering "
                f"is running {own[:12]}. Ask the production backend, or find out what runs.",
            ))
        return Baseline(own, "this process (MYKRONOS_BUILD_SHA)")

    probe: str | None = None
    with db.session() as session:
        row = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo_full_name)
        ).first()
        if row is not None and row.deployment_probe_status == PROBE_OK and row.deployed_revision:
            probe = str(row.deployed_revision).strip().lower()
    if claimed is not None:
        return Baseline(claimed, "caller", probe_revision=probe)
    if probe is not None and _SHA.match(probe):
        return Baseline(probe, "deployment probe", probe_revision=probe)
    return Baseline(None, "none", probe_revision=probe, problem=Reason(
        BASELINE_UNKNOWN,
        "No deployed commit was named, and the platform has no reading of what this "
        "repository runs. Pass deployed=<the running build stamp>.",
    ))


# -- the whole check ----------------------------------------------------------


@dataclass
class DeployGate:
    repo_full_name: str
    commit_sha: str
    deployed_sha: str | None
    baseline_source: str
    probe_revision: str | None
    verdict: str
    allow: bool
    reasons: list[Reason]
    candidate_score: float | None = None
    baseline_score: float | None = None
    score_delta: float | None = None
    tolerance: float = TOLERANCE
    accepted_creep: float | None = None
    fix_credit_pending: int = 0
    no_go_threshold: float = 0.0
    policy_version: str = ""
    direction: str = "forward"
    branch: str | None = None
    range_commits: list[str] = field(default_factory=list)
    introduced: dict[str, int] = field(default_factory=dict)
    fixed: dict[str, int] = field(default_factory=dict)
    introduced_blocking_ids: list[str] = field(default_factory=list)
    candidate_decision: dict[str, Any] | None = None
    baseline_decision: dict[str, Any] | None = None
    latch: Latch = field(default_factory=lambda: Latch(latched=False))
    error_id: str | None = None
    evaluated_at: datetime = field(default_factory=utcnow)


def _decision(catalog: Any, repo_full_name: str, sha: str, full: list[str]) -> Any:
    if len(full) == 1:
        return _stored_decision(catalog, repo_full_name, full[0], exact=True)
    return _stored_decision(catalog, repo_full_name, sha)


def evaluate(
    engine: OracleEngine,
    queries: Any,
    db: Database,
    repo_full_name: str,
    commit: str,
    deployed: str | None,
    *,
    self_build_sha: str = "",
) -> DeployGate:
    """Judge a deploy of `commit` over the running baseline. Never raises:
    anything that goes wrong is a refusal that names it (rule (c))."""
    catalog = engine.catalog
    policy = engine.policy
    commit = commit.strip().lower()
    gate = DeployGate(
        repo_full_name=repo_full_name, commit_sha=commit, deployed_sha=None,
        baseline_source="none", probe_revision=None, verdict=REFUSE, allow=False,
        reasons=[], no_go_threshold=float(policy.no_go), policy_version=policy.version,
    )
    baseline_problem: Reason | None = None
    error: str | None = None
    candidate_recommendation: str | None = None
    blocking: list[str] = []
    creep = 0.0
    if not enforceable(repo_full_name, self_build_sha):
        gate.reasons = [Reason(
            NOT_ENFORCEABLE,
            f"The ratchet cannot judge {repo_full_name} yet: its scan history cannot be "
            "placed (a finding first seen on a feature-branch push or on a pull request "
            "scanned before the running commit is on neither side), and its baseline is "
            "the caller's word. It covers this platform's own deploys only, and only "
            "while the backend knows its own build (D-182).",
        )]
        return gate
    try:
        gate.latch = read_latch(db, repo_full_name)
        baseline = baseline_for(db, repo_full_name, deployed, self_build_sha)
        gate.deployed_sha = baseline.sha
        gate.baseline_source = baseline.source
        gate.probe_revision = baseline.probe_revision
        baseline_problem = baseline.problem

        full_c = _resolve(catalog, repo_full_name, commit)
        gate.candidate_decision = _decision(catalog, repo_full_name, commit, full_c)
        if gate.candidate_decision is not None:
            candidate_recommendation = gate.candidate_decision["recommendation"]
        # Without a decision the answer is `no_decision` alone, which is the
        # one refusal a deploy host waits on; an unscanned commit is the
        # same state seen earlier, not a second fault.
        if gate.candidate_decision is not None and len(full_c) != 1:
            error = (
                f"{commit[:12]} names {len(full_c)} scanned commits of {repo_full_name}; "
                "it must name exactly one."
            )
        full_d: list[str] = []
        if baseline.sha:
            full_d = _resolve(catalog, repo_full_name, baseline.sha)
            gate.baseline_decision = _decision(catalog, repo_full_name, baseline.sha, full_d)
        if baseline_problem is None and baseline.sha and len(full_d) != 1:
            baseline_problem = Reason(
                BASELINE_UNKNOWN,
                f"The deployed commit {baseline.sha[:12]} names {len(full_d)} scanned "
                f"commits of {repo_full_name}, so what it carries is unknown.",
            )
        if error is None and baseline_problem is None and gate.candidate_decision is not None:
            c, d = full_c[0], full_d[0]
            gate.commit_sha, gate.deployed_sha = c, d
            if policy.environmental.live_for(repo_full_name) is not None:
                raise ValueError(
                    "environmental scoring is live for this repository, and the ratchet "
                    "does not re-score the environmental recount"
                )
            fresh = engine.evaluate(repo_full_name, decision_type="commit_gate", commit_sha=c)
            snapshot = fresh.inputs_snapshot
            raw_value = (snapshot.get("totals") or {}).get("raw_score")
            if raw_value is None:
                raise ValueError("the evaluation carries no totals.raw_score")
            current_raw = float(raw_value)

            def measure(frm: str, to: str) -> float:
                """The rise from the last confirmed sha to what runs now, over
                this snapshot: a deploy the ledger was never told about."""
                full = _resolve(catalog, repo_full_name, frm)
                if len(full) != 1:
                    raise ValueError(
                        f"the creep since {frm[:12]} cannot be measured: it names "
                        f"{len(full)} scanned commits"
                    )
                scratch = DeployGate(
                    repo_full_name=repo_full_name, commit_sha=to, deployed_sha=full[0],
                    baseline_source="creep ledger", probe_revision=None, verdict=REFUSE,
                    allow=False, reasons=[],
                )
                problem = _compare(
                    engine, queries, scratch, to, full[0], snapshot, current_raw,
                    fresh.evaluated_at, [],
                )
                if problem is not None or scratch.candidate_score is None:
                    raise ValueError(
                        f"the creep from {frm[:12]} to {to[:12]} cannot be measured"
                        + (f": {problem.message}" if problem is not None else "")
                    )
                return float(scratch.candidate_score) - float(scratch.baseline_score or 0.0)

            creep = settle_creep(db, repo_full_name, d, measure=measure)
            gate.accepted_creep = round(creep, 2)
            if fresh.recommendation not in BANDS:
                candidate_recommendation = fresh.recommendation
            if c == d:
                gate.candidate_score = gate.baseline_score = round(current_raw, 2)
                gate.direction = "same"
            else:
                baseline_problem = _compare(
                    engine, queries, gate, c, d, snapshot, current_raw, fresh.evaluated_at,
                    blocking,
                )
            if gate.candidate_score is not None and gate.baseline_score is not None:
                gate.score_delta = round(gate.candidate_score - gate.baseline_score, 2)
            # The backlog as it stands now is R's score: latch on it, from the
            # fresh evaluation and its own recommendation, before judging. A
            # latch set here is read back and judged on in this same call: the
            # backlog now is below No-Go, but the candidate (an older commit,
            # or a rollback) can still be No-Go, and (b) then refuses it.
            if note_score(
                db, repo_full_name, raw_score=current_raw,
                recommendation=fresh.recommendation, policy=policy,
                commit_sha=d if gate.direction == "rollback" else c, source="deploy_gate",
            ):
                gate.latch = read_latch(db, repo_full_name)
    except Exception:  # rule (c): any failure is a refusal, never a pass
        gate.error_id = uuid.uuid4().hex[:12]
        logger.exception(
            "Deploy ratchet could not evaluate %s (error id %s)",
            scrub(repo_full_name), gate.error_id,
        )
        error = (
            "The ratchet could not be evaluated; the detail is in the backend log under "
            f"error id {gate.error_id}."
        )
        gate.candidate_score = gate.baseline_score = gate.score_delta = None

    gate.introduced_blocking_ids = blocking
    outcome = judge(
        candidate_found=gate.candidate_decision is not None,
        candidate_recommendation=candidate_recommendation,
        baseline_problem=baseline_problem,
        evaluation_error=error,
        candidate_score=gate.candidate_score,
        baseline_score=gate.baseline_score,
        blocking_ids=blocking,
        latched=gate.latch.latched,
        no_go=float(policy.no_go),
        creep=creep,
        fix_credit_pending=gate.fix_credit_pending,
    )
    if outcome.allow and gate.score_delta is not None and gate.direction != "same":
        try:
            record_pending(
                db, repo_full_name, candidate=gate.commit_sha,
                baseline=gate.deployed_sha or "",
                delta=float(gate.candidate_score or 0.0) - float(gate.baseline_score or 0.0),
            )
        except Exception:  # an allow whose rise cannot be remembered is refused
            gate.error_id = uuid.uuid4().hex[:12]
            logger.exception(
                "Deploy ratchet could not record the creep for %s (error id %s)",
                scrub(repo_full_name), gate.error_id,
            )
            outcome = Judgement(False, [Reason(
                EVALUATION_FAILED,
                "The ratchet could not record this deploy's rise in the creep ledger; the "
                f"detail is in the backend log under error id {gate.error_id}.",
            )])
    gate.allow = outcome.allow
    gate.verdict = ALLOW if outcome.allow else REFUSE
    gate.reasons = outcome.reasons
    return gate


def _compare(
    engine: OracleEngine,
    queries: Any,
    gate: DeployGate,
    c: str,
    d: str,
    snapshot: dict[str, Any],
    current_raw: float,
    as_of: datetime,
    blocking: list[str],
) -> Reason | None:
    """Score the states C and D carried over this snapshot. Fills `gate` and
    `blocking`; returns a baseline problem, or None."""
    catalog = engine.catalog
    policy = engine.policy
    repo = gate.repo_full_name
    c_scans = _push_scans(catalog, repo, c)
    d_scans = _push_scans(catalog, repo, d)
    shared = set(c_scans) & set(d_scans)
    common = sorted(b for b in shared if b)
    if not common:
        return Reason(
            BASELINE_UNKNOWN,
            f"{c[:12]} and the deployed {d[:12]} have no push scan on a common named "
            "branch, so the commits between them cannot be read"
            + (" (a scan with no branch is no line of history)." if "" in shared else "."),
        )
    # The branch the candidate was scanned on most recently.
    branch = max(common, key=lambda b: c_scans[b][1])
    gate.branch = branch
    cand = _Commit(c, c_scans[branch][0], _capability_last(catalog, repo, branch, c))
    base = _Commit(d, d_scans[branch][0], _capability_last(catalog, repo, branch, d))
    forward = base.first <= cand.first
    older, newer = (base, cand) if forward else (cand, base)
    if not forward:
        gate.direction = "rollback"
    commits = _range(catalog, repo, branch, older.first, newer.first)
    if newer.sha not in commits:
        commits.append(newer.sha)
    gate.range_commits = commits

    rows = _rows(catalog, policy, repo, branch, older.first)
    # Newly disclosed findings are carried by every commit (D-048, #734).
    maybe = [r for r in rows if _after(r, cand) or _after(r, base)]
    _, disclosed = queries.split_disclosed([r.split_row() for r in maybe])
    disclosed_ids = {str(r["finding_id"]) for r in disclosed}
    # A renamed image's old-name findings close by absence while its new-name
    # ones read as disclosed: the same CVE, so neither side gets it back.
    renamed = {
        (str(r["rule_id"]), str(r.get("_package") or ""), str(r.get("_version") or ""))
        for r in disclosed
    }
    kept: list[_Row] = []
    for row in rows:
        if row.finding_id in disclosed_ids:
            row.disclosed = True
        if row.status == "fixed" and (row.rule_id, row.package, row.version) in renamed:
            continue
        kept.append(row)

    open_rows = [r for r in kept if r.status != "fixed"]
    fixed_rows = [r for r in kept if r.status == "fixed"]
    # An open finding introduced inside the range that a later commit's own
    # last scan of its capability no longer reports was fixed in the range:
    # that commit does not carry it, though reconciliation has not closed it
    # yet (a hotfix is not refused as introducing what it removes).
    in_range_missed = {
        (r.finding_id, side.sha)
        for r in open_rows
        if _after(r, older)
        for side in (cand, base)
        if _missed(r, side)
    }
    c_drop = [
        r for r in open_rows
        if not _carries(r, cand) or (r.finding_id, cand.sha) in in_range_missed
    ]
    d_drop = [
        r for r in open_rows
        if not _carries(r, base) or (r.finding_id, base.sha) in in_range_missed
    ]
    c_add = [r for r in fixed_rows if _carries(r, cand)]
    d_add = [r for r in fixed_rows if _carries(r, base)]
    c_gone = {r.finding_id for r in c_drop}
    d_gone = {r.finding_id for r in d_drop}
    in_c = {r.finding_id for r in open_rows if r.finding_id not in c_gone}
    in_c |= {r.finding_id for r in c_add}
    in_d = {r.finding_id for r in open_rows if r.finding_id not in d_gone}
    in_d |= {r.finding_id for r in d_add}
    brought = [r for r in kept if r.finding_id in in_c and r.finding_id not in in_d]
    removed = [r for r in kept if r.finding_id in in_d and r.finding_id not in in_c]

    scorer = _Scorer(
        engine=engine, repo_full_name=repo, snapshot=snapshot, current_raw=current_raw,
        as_of=as_of, covered=_covered(engine, repo),
        kev=_kev(engine, c_drop + d_drop + c_add + d_add),
    )
    cand_raw, cand_combos = scorer.score(c_drop, c_add, lenient=True)
    base_raw, _ = scorer.score(d_drop, d_add, lenient=False)
    gate.candidate_score = round(cand_raw, 2)
    gate.baseline_score = round(base_raw, 2)
    gate.introduced = _by_severity([r for r in brought if r.in_scope])
    gate.fixed = _by_severity([r for r in removed if r.in_scope])
    if forward:
        credited = {fid for fid, sha in in_range_missed if sha == cand.sha}
        gate.fix_credit_pending = len(
            _fix_credit_pending(catalog, policy, repo, branch, c) - credited
        )

    chained = {
        fid
        for combo in cand_combos
        if combo.severity in BLOCKING_SEVERITIES
        for fid in combo.finding_ids
    }
    blocking.extend(sorted(
        r.finding_id
        for r in brought
        if r.in_scope
        and (
            r.severity in BLOCKING_SEVERITIES
        or scorer.kev.get(r.finding_id, ("", 0.0))[0] in BLOCKING_SEVERITIES
        or r.finding_id in chained
        )
    ))
    return None


def _covered(engine: OracleEngine, repo_full_name: str) -> set[str]:
    """Findings with a fix in flight, as the engine reads them."""
    return set(engine._remediation_in_flight(repo_full_name))


def _by_severity(rows: list[_Row]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[row.severity] = out.get(row.severity, 0) + 1
    return out
