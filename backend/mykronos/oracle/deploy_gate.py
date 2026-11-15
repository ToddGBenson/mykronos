"""The deploy ratchet: a deploy may not raise a repository's risk (D-182).

Operator decision 2026-11-15. A deploy of commit C for repository R is judged
against the commit R is running now (the *baseline*, D):

(a) REFUSED if C raises R's risk relative to D: its score is higher than D's
    by more than `TOLERANCE`, or C carries an open critical or high finding
    that D did not;
(b) once R's score has been below the No-Go threshold (`policy.no_go`), a
    No-Go is a hard refusal. The first crossing is recorded per repository in
    `oracle_ratchet_latches` and never cleared by code;
(c) the gate FAILS CLOSED: no decision for C, an unknown baseline, or an
    evaluation that could not be completed is a refusal with a named reason;
(d) a fix that lowers the score is allowed while R is still No-Go (unlatched).

THE TWO SCORES ARE MEASURED OVER ONE SNAPSHOT. Oracle's score describes the
whole open backlog, so two decisions recorded a day apart differ by every CVE
published in between, whatever the commits did. On 2026-11-14 MyKronos main
scored 166.3 against the deployed commit's 165.2, and all of the 1.1 was three
otel-sdk mediums and a dpkg low first seen that morning in images neither
commit changed. Comparing stored decisions would have refused every deploy
until the next CVE-free day. So nothing stored is compared. The backlog is
scored once, now, and the baseline is that same score with the change taken
out of it: the findings attributable to the commits between D and C are
removed and the findings they fixed are put back, and only the severity bands
are re-scored. Whatever the vulnerability database did since D was scanned is
in both scores equally, so it cancels.

"Attributable" is the commit gate's own rule (D-048, #734, TheHub #61063):
first seen by a scan of a commit in the range, minus what `split_disclosed`
calls newly disclosed (a CVE in an image whose bytes did not change, or on a
dependency version the baseline already carried). A finding that also
affects the deployed commit is therefore never introduced by C.

THE RANGE is read from the lake, never taken from the caller: the commits
with push scans (no pull request) on the branch both commits were scanned on,
whose first scan falls after D's first scan and no later than C's. A finding
first seen by a pull-request scan counts when a push scan on that branch has
seen it since D: a squash merge's commit never "first sees" what its pull
request already reported. Where that cannot be placed precisely it counts
against C, because the gate fails closed. A rollback (C scanned before D) is
the same range read the other way: C lacks what the range introduced and
carries again what the range fixed, so a rollback past a security fix is
refused as introducing it.

THE BASELINE SOURCE. The caller names D from what is running (the deploy host
reads the running container's build stamp). For this platform's own
repository the backend answering is the deployment, so its `build_sha` is
authoritative: a caller that names anything else is refused. For any other
repository the deployment probe's last reading (#361) is reported beside the
caller's claim and used when the caller names nothing; it is not a refusal on
its own, because the probe runs half-hourly and lags every deploy.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select

from mykronos.db.models import OracleRatchetLatch, RepoOnboarding
from mykronos.db.session import Database
from mykronos.deployments import OK as PROBE_OK
from mykronos.deployments import SELF_REPO_NAME
from mykronos.logsafe import scrub
from mykronos.oracle.engine import TOOL_IMAGE_SQL, OracleEngine, finding_band_terms
from mykronos.oracle.policy import Policy
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How far C's score may sit above the baseline's and still not "raise" it.
#:
#: Half a point of the published integer score. Because both scores are
#: measured over one snapshot, nothing here is noise in the drift sense; what
#: the tolerance absorbs is the smallest real changes, which the log curve
#: (D-018) makes tiny in a large band: one more medium on top of 13 adds
#: 5 x log2(15/14) = 0.497. A critical or high is never let through by it,
#: because rule (a)'s second clause refuses any introduced critical or high
#: outright. A constant rather than policy for the reason the floor is one: a
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

# Allow codes, so an allow says which rule let it through.
NOT_RAISED = "not_raised"
LOWERED = "lowered"
LOWERED_WHILE_NO_GO = "lowered_while_no_go"
UNCHANGED_WHILE_NO_GO = "unchanged_while_no_go"

_SHA = re.compile(r"^[0-9a-f]{7,40}$")


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
) -> Judgement:
    """The ratchet's rule, as a pure function of what was measured.

    Every refusal that applies is listed, not only the first, so a caller
    fixing one does not discover the next on the following run. The
    fail-closed refusals come first and stop the comparison: without a
    decision or a baseline there is nothing to compare.
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

    delta = candidate_score - baseline_score
    refusals: list[Reason] = []
    if blocking_ids:
        refusals.append(Reason(
            INTRODUCED_BLOCKING,
            f"This deploy brings {len(blocking_ids)} open critical or high finding(s) the "
            f"running commit does not have: {', '.join(blocking_ids[:10])}"
            + (" ..." if len(blocking_ids) > 10 else "") + ".",
        ))
    if delta > tolerance:
        refusals.append(Reason(
            SCORE_RAISED,
            f"This deploy raises the risk score from {baseline_score:.2f} to "
            f"{candidate_score:.2f} (+{delta:.2f}, tolerance {tolerance:g}).",
        ))
    if latched and candidate_score >= no_go:
        refusals.append(Reason(
            LATCHED_NO_GO,
            f"The repository has been below No-Go ({no_go:g}) before, so a No-Go is a hard "
            f"refusal (D-182 (b)). This deploy scores {candidate_score:.2f}"
            + (
                "; the change itself does not raise it, so the No-Go is the backlog: "
                "lower it below the threshold, or override with a recorded reason."
                if delta <= tolerance else "."
            ),
        ))
    if refusals:
        return Judgement(False, refusals)

    if candidate_score >= no_go:
        code = LOWERED_WHILE_NO_GO if delta < -tolerance else UNCHANGED_WHILE_NO_GO
        return Judgement(True, [Reason(
            code,
            f"Still No-Go at {candidate_score:.2f}, but the repository has never been below "
            f"{no_go:g}, and this deploy does not raise the score ({delta:+.2f}), so it is "
            "allowed (D-182 (d)).",
        )])
    code = LOWERED if delta < -tolerance else NOT_RAISED
    return Judgement(True, [Reason(
        code,
        f"The score moves from {baseline_score:.2f} to {candidate_score:.2f} ({delta:+.2f}) "
        "and nothing critical or high is introduced.",
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


def _marks(values: list[str]) -> str:
    return ", ".join("?" for _ in values) or "NULL"


def _introduced_in_range(
    catalog: Any,
    queries: Any,
    policy: Policy,
    repo_full_name: str,
    branch: str,
    commits: list[str],
    after: Any,
) -> list[dict[str, Any]]:
    """Open findings the range introduced, newly disclosed ones removed."""
    if not commits:
        return []
    in_scope = _in_scope_sql(policy)
    rows = catalog.query(
        f"""
        SELECT DISTINCT f.finding_id, f.severity, f.capability, f.rule_id,
               f.first_seen_scan_run_id,
               json_extract_string(f.raw_finding_json, '$.image'),
               f.package_name, f.package_version,
               json_extract(f.raw_finding_json, '$.baseline_commits'),
               json_extract(f.raw_finding_json, '$.remediated_by'),
               {in_scope} AS in_scope
        FROM findings f
        JOIN scan_runs fs ON fs.scan_run_id = f.first_seen_scan_run_id
        LEFT JOIN scan_runs ls ON ls.scan_run_id = f.last_seen_scan_run_id
        WHERE f.asset_id = ? AND f.status = 'open'
          AND fs.repo_full_name = ?
          AND fs.started_at > ?
          AND (
                (coalesce(fs.pr_number, 0) = 0 AND coalesce(fs.branch, '') = ?
                 AND lower(fs.commit_sha) IN ({_marks(commits)}))
             OR (coalesce(fs.pr_number, 0) <> 0
                 AND coalesce(ls.pr_number, 0) = 0 AND coalesce(ls.branch, '') = ?
                 AND ls.started_at > ?)
          )
        """,
        [repo_full_name, repo_full_name, after, branch, *commits, branch, after],
    )
    found = [
        {
            "finding_id": str(fid),
            "severity": str(severity),
            "capability": str(capability),
            "rule_id": str(rule_id),
            "_scan": str(scan),
            "_image": None if image is None else str(image),
            "_package": str(package or ""),
            "_version": str(version or ""),
            "_baseline": baseline,
            "_remedy": remedy,
            "_in_scope": bool(scoped),
        }
        for (fid, severity, capability, rule_id, scan, image, package, version,
             baseline, remedy, scoped) in rows
    ]
    introduced, _ = queries.split_disclosed(found)
    return list(introduced)


def _fixed_in_range(
    catalog: Any,
    policy: Policy,
    repo_full_name: str,
    branch: str,
    older: str,
    commits: list[str],
    older_last: Any,
) -> list[dict[str, Any]]:
    """Findings the older commit carried that the range closed by absence:
    first seen no later than the older commit's last scan and not by a commit
    in the range, last seen on the branch at the older commit or a range
    commit other than the newest (which did not see it)."""
    seen_at = [older, *commits[:-1]]
    in_scope = _in_scope_sql(policy)
    rows = catalog.query(
        f"""
        SELECT DISTINCT f.finding_id, f.severity, {in_scope} AS in_scope
        FROM findings f
        JOIN scan_runs fs ON fs.scan_run_id = f.first_seen_scan_run_id
        JOIN scan_runs ls ON ls.scan_run_id = f.last_seen_scan_run_id
        WHERE f.asset_id = ? AND f.status = 'fixed'
          AND fs.repo_full_name = ? AND ls.repo_full_name = ?
          AND fs.started_at <= ?
          AND lower(coalesce(fs.commit_sha, '')) NOT IN ({_marks(commits)})
          AND coalesce(ls.pr_number, 0) = 0 AND coalesce(ls.branch, '') = ?
          AND lower(ls.commit_sha) IN ({_marks(seen_at)})
        """,
        [repo_full_name, repo_full_name, repo_full_name, older_last, *commits, branch,
         *seen_at],
    )
    return [
        {"finding_id": str(fid), "severity": str(sev), "_in_scope": bool(scoped)}
        for fid, sev, scoped in rows
    ]


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


def _band_total(
    counts: dict[str, int],
    dampened: dict[str, int],
    covered: dict[str, int],
    unfixable: dict[str, int],
    policy: Policy,
) -> float:
    terms, _ = finding_band_terms(counts, dampened, covered, unfixable, policy)
    return sum(term.contribution for term in terms)


def _tally(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        if row.get("_in_scope"):
            out[row["severity"]] = out.get(row["severity"], 0) + 1
    return out


def _stored_decision(catalog: Any, repo_full_name: str, sha: str) -> dict[str, Any] | None:
    """The newest decision recorded for this repository at this commit."""
    rows = catalog.query(
        """
        SELECT decision_id, decision_type, commit_sha, overall_risk_score, recommendation,
               policy_version, evaluated_at, inputs_snapshot, human_override
        FROM risk_decisions
        WHERE repo_full_name = ? AND commit_sha IS NOT NULL AND commit_sha <> ''
          AND (starts_with(lower(commit_sha), ?) OR starts_with(?, lower(commit_sha)))
        ORDER BY evaluated_at DESC
        LIMIT 1
        """,
        [repo_full_name, sha, sha],
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


# -- the baseline -------------------------------------------------------------


@dataclass
class Baseline:
    sha: str | None
    source: str
    probe_revision: str | None = None
    problem: Reason | None = None


def _same(a: str, b: str) -> bool:
    a, b = a.lower(), b.lower()
    return a.startswith(b) or b.startswith(a)


def baseline_for(
    db: Database, repo_full_name: str, claimed: str | None, self_build_sha: str
) -> Baseline:
    """Which commit R is running, and where that answer came from."""
    claimed = (claimed or "").strip().lower() or None
    if claimed is not None and not _SHA.match(claimed):
        return Baseline(None, "caller", problem=Reason(
            BASELINE_UNKNOWN, f"deployed={claimed!r} is not a commit sha (7-40 hex)."))
    is_self = repo_full_name.split("/")[-1].lower() == SELF_REPO_NAME
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
    evaluated_at: datetime = field(default_factory=utcnow)


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
    try:
        gate.latch = read_latch(db, repo_full_name)
        baseline = baseline_for(db, repo_full_name, deployed, self_build_sha)
        gate.deployed_sha = baseline.sha
        gate.baseline_source = baseline.source
        gate.probe_revision = baseline.probe_revision
        baseline_problem = baseline.problem

        gate.candidate_decision = _stored_decision(catalog, repo_full_name, commit)
        if gate.candidate_decision is not None:
            candidate_recommendation = gate.candidate_decision["recommendation"]
        if baseline.sha:
            gate.baseline_decision = _stored_decision(catalog, repo_full_name, baseline.sha)

        full_c = _resolve(catalog, repo_full_name, commit)
        # Without a decision the answer is `no_decision` alone, which is the
        # one refusal a deploy host waits on; an unscanned commit is the
        # same state seen earlier, not a second fault.
        if gate.candidate_decision is not None and len(full_c) != 1:
            error = (
                f"{commit[:12]} names {len(full_c)} scanned commits of {repo_full_name}; "
                "it must name exactly one."
            )
        full_d: list[str] = []
        if baseline_problem is None and baseline.sha:
            full_d = _resolve(catalog, repo_full_name, baseline.sha)
            if len(full_d) != 1:
                baseline_problem = Reason(
                    BASELINE_UNKNOWN,
                    f"The deployed commit {baseline.sha[:12]} names {len(full_d)} scanned "
                    f"commits of {repo_full_name}, so what it carries is unknown.",
                )
        if error is None and baseline_problem is None and gate.candidate_decision is not None:
            c, d = full_c[0], full_d[0]
            gate.commit_sha, gate.deployed_sha = c, d
            fresh = engine.evaluate(repo_full_name, decision_type="commit_gate", commit_sha=c)
            snapshot = fresh.inputs_snapshot
            raw_value = (snapshot.get("totals") or {}).get("raw_score")
            if raw_value is None:
                raise ValueError("the evaluation carries no totals.raw_score")
            current_raw = float(raw_value)
            if fresh.recommendation not in BANDS:
                candidate_recommendation = fresh.recommendation
            if c == d:
                gate.candidate_score = gate.baseline_score = round(current_raw, 2)
                gate.direction = "same"
            else:
                c_scans = _push_scans(catalog, repo_full_name, c)
                d_scans = _push_scans(catalog, repo_full_name, d)
                common = sorted(set(c_scans) & set(d_scans))
                if not common:
                    baseline_problem = Reason(
                        BASELINE_UNKNOWN,
                        f"{c[:12]} and the deployed {d[:12]} have no push scan on a common "
                        "branch, so the commits between them cannot be read.",
                    )
                else:
                    # The branch the candidate was scanned on most recently.
                    branch = max(common, key=lambda b: c_scans[b][1])
                    gate.branch = branch
                    forward = d_scans[branch][0] <= c_scans[branch][0]
                    newer, older = (c, d) if forward else (d, c)
                    older_scans = d_scans if forward else c_scans
                    newer_scans = c_scans if forward else d_scans
                    commits = _range(
                        catalog, repo_full_name, branch,
                        older_scans[branch][0], newer_scans[branch][0],
                    )
                    if newer not in commits:
                        commits.append(newer)
                    gate.range_commits = commits
                    intro = _introduced_in_range(
                        catalog, queries, policy, repo_full_name, branch, commits,
                        older_scans[branch][0],
                    )
                    fixed = _fixed_in_range(
                        catalog, policy, repo_full_name, branch, older, commits,
                        older_scans[branch][1],
                    )
                    counts, dampened, covered, unfixable = _band_inputs(snapshot)
                    intro_n, fixed_n = _tally(intro), _tally(fixed)
                    older_counts = {
                        s: max(0, counts.get(s, 0) - intro_n.get(s, 0) + fixed_n.get(s, 0))
                        for s in set(counts) | set(intro_n) | set(fixed_n)
                    }
                    delta = _band_total(counts, dampened, covered, unfixable, policy) - (
                        _band_total(older_counts, dampened, covered, unfixable, policy)
                    )
                    if forward:
                        gate.candidate_score = round(current_raw, 2)
                        gate.baseline_score = round(current_raw - delta, 2)
                        brought, removed = intro, fixed
                    else:
                        gate.direction = "rollback"
                        gate.baseline_score = round(current_raw, 2)
                        gate.candidate_score = round(current_raw - delta, 2)
                        brought, removed = fixed, intro
                    gate.introduced = _by_severity(brought)
                    gate.fixed = _by_severity(removed)
                    blocking = sorted(
                        r["finding_id"] for r in brought if r["severity"] in BLOCKING_SEVERITIES
                    )
            if gate.candidate_score is not None and gate.baseline_score is not None:
                gate.score_delta = round(gate.candidate_score - gate.baseline_score, 2)
            # The backlog as it stands now is R's score: latch on it, from the
            # fresh evaluation and its own recommendation, before judging.
            # Judged on the latch as read above, which is the same answer:
            # a score that latches here is below No-Go, so (b) cannot apply.
            if note_score(
                db, repo_full_name, raw_score=current_raw,
                recommendation=fresh.recommendation, policy=policy,
                commit_sha=c if gate.direction != "rollback" else d, source="deploy_gate",
            ):
                gate.latch = read_latch(db, repo_full_name)
    except Exception as exc:  # rule (c): any failure is a refusal, never a pass
        logger.exception("Deploy ratchet could not evaluate %s", scrub(repo_full_name))
        error = f"The ratchet could not be evaluated: {type(exc).__name__}: {scrub(str(exc))}"
        gate.candidate_score = gate.baseline_score = None

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
    )
    gate.allow = outcome.allow
    gate.verdict = ALLOW if outcome.allow else REFUSE
    gate.reasons = outcome.reasons
    return gate


def _by_severity(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        out[row["severity"]] = out.get(row["severity"], 0) + 1
    return out
