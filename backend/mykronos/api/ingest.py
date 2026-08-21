"""Ingestion API — the single write path into the data lake (spec 05 §4).

Three properties this module is responsible for:

1. **A 200 is a durability guarantee.** Every write goes to the fsync'd
   write-ahead buffer before the response is returned, so a workflow that saw
   a 200 can be certain its findings survive a crash. Nothing is acknowledged
   from memory.

2. **Attribution comes from the token, not the payload.** `repo_full_name` is
   stamped from the authenticated token's scope and is not accepted as client
   input. A workflow cannot file findings against another repo because there
   is no field in which to say so.

3. **Capability is declared but verified.** Since D-009 a repo has one token
   spanning several capabilities, so the caller must say which one it is
   writing as — and the server rejects anything outside the current grant set.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select

from mykronos.aegis import AEGIS_CHECK_RUN_NAME, assess, render_check_run_summary
from mykronos.aegis import to_row as aegis_row
from mykronos.atlas import evidence_id as atlas_evidence_id
from mykronos.atlas import score as trust_score
from mykronos.atlas import to_row as atlas_row
from mykronos.auth import Resolution, TokenRegistry
from mykronos.db.models import (
    ReachabilityReport,
    RepoOnboarding,
    RiskProfile,
    capability_config_for,
)
from mykronos.fingerprint import compute_finding_id
from mykronos.github.client import GitHubError
from mykronos.logsafe import scrub
from mykronos.notify import Notification
from mykronos.ownership import owner_for_finding
from mykronos.schemas import (
    AegisAccepted,
    AtlasAccepted,
    Capability,
    FindingBatch,
    FindingStatus,
    HealthResponse,
    IngestAccepted,
    InsiderRiskSubmission,
    RawAccepted,
    ReachabilityAccepted,
    ReachabilitySubmission,
    ScanRunSubmission,
    ScanStatus,
    SscsEvidenceSubmission,
    utcnow,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])

#: How long an ingest request may spend posting a GitHub Check Run before it
#: gives up and records the row anyway.
#:
#: The pipelines allow this POST 60 seconds end to end. The GitHub client's own
#: timeout is 30s per call and minting an installation token is a second call,
#: so without a bound here a slow api.github.com consumes the caller's entire
#: budget and the row is lost with it — which is what happened to
#: `mykronos/insider/77` on 2026-08-19.
CHECK_RUN_TIMEOUT = 15.0

_bearer = HTTPBearer(auto_error=False, description="Per-repo ingestion token.")

#: Advisory header set when a caller is still presenting a rotated-away token
#: inside its overlap window (spec 05 §4). Lets a repo that never picked up the
#: new secret be spotted from logs, rather than only when it starts failing.
ROTATED_HEADER = "X-Mykronos-Token-Rotated"

#: Scan outcomes worth waking somebody for (spec 16 §14).
#:
#: `no_applicable_targets` is deliberately absent. It is the third state from
#: L0001 — a scanner with nothing to scan — and it is a normal, correct result
#: for a repository that has no Dockerfiles or declares no dependencies.
#: Alerting on it would train people to ignore this channel, which is how the
#: two entries that *are* here stop being read.
_FAILED_SCANS = frozenset({ScanStatus.FAILURE.value, ScanStatus.PARTIAL_FAILURE.value})


async def require_token(
    request: Request,
    response: Response,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Resolution:
    """Resolve and rate-limit the presented ingestion token."""
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing ingestion token. Send 'Authorization: Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    with request.app.state.db.session() as session:
        registry = TokenRegistry(
            session, overlap_hours=request.app.state.settings.token_overlap_hours
        )
        resolution = registry.resolve(credentials.credentials)

    if resolution is None:
        # Unknown, revoked and expired-superseded are deliberately
        # indistinguishable: a caller learns only that this token does not work
        # now, not whether it ever did.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Ingestion token is unknown, revoked, or expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    allowed, retry_after = request.app.state.limiter.check(resolution.token_sha256)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Ingestion rate limit exceeded for this token. Back off and retry — "
                "do not drop findings."
            ),
            headers={"Retry-After": str(retry_after)},
        )

    if resolution.superseded:
        # The deadline, not just the fact. A rotation warning without a time
        # attached reads as optional; this one names the moment every request
        # from this token starts returning 401.
        response.headers[ROTATED_HEADER] = (
            resolution.superseded_expires_at.isoformat()
            if resolution.superseded_expires_at
            else "true"
        )

    return resolution


TokenDep = Annotated[Resolution, Depends(require_token)]


def _require_capability(token: Resolution, capability: str) -> None:
    if not token.permits(capability):
        granted = ", ".join(sorted(token.granted_capabilities)) or "none"
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"'{capability}' is not enabled for {token.repo_full_name}. "
                f"Currently granted: {granted}."
            ),
        )


def _require_repo(token: Resolution, repo_full_name: str) -> None:
    if token.repo_full_name != repo_full_name:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"This token is scoped to {token.repo_full_name} and cannot write {repo_full_name}."
            ),
        )


@router.get("/health", response_model=HealthResponse)
async def health(request: Request, token: TokenDep) -> HealthResponse:
    """Called by a workflow before scanning so it can fail fast (spec 05 §4).

    Reports whether the lake is actually writable rather than merely whether
    the process is up — an unwritable disk is the failure this exists to catch.
    """
    buffer = request.app.state.buffer
    try:
        buffer.root.mkdir(parents=True, exist_ok=True)
        probe = buffer.root / ".health"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        writable = True
        detail = ""
    except OSError as exc:
        writable = False
        detail = f"Data lake is not writable: {exc}"

    return HealthResponse(
        status="ok" if writable else "degraded",
        datalake_writable=writable,
        buffered_segments=buffer.count_sealed(),
        detail=detail,
        repo_full_name=token.repo_full_name,
        granted_capabilities=sorted(token.granted_capabilities),
    )


@router.post("/scan-run", response_model=IngestAccepted)
async def ingest_scan_run(
    request: Request,
    submission: ScanRunSubmission,
    token: TokenDep,
    background: BackgroundTasks,
) -> IngestAccepted:
    """Register or finalise a ScanRun.

    Posted once at workflow start and again at completion with
    `completed_at`/`scan_status`/`finding_count`; the second post upserts onto
    the first by `scan_run_id` (docs/DECISIONS.md D-002).

    Every run is registered — success, no-op and failure alike — so scan
    coverage and freshness are auditable from the lake alone (spec 04 §7).
    """
    _require_repo(token, submission.repo_full_name)
    _require_capability(token, submission.capability.value)

    row = submission.model_dump(mode="python")
    row["capability"] = submission.capability.value
    row["triggered_by"] = submission.triggered_by.value
    row["scan_status"] = submission.scan_status.value
    row["ingested_at"] = utcnow()

    request.app.state.buffer.append("scan_runs", [row])

    # Only on the finalising post. The same scan run is submitted twice
    # (D-002), and the first has no `completed_at` and no meaningful status --
    # alerting on it would fire on every scan that has merely started.
    #
    # This is the alert that matters most and reads as the dullest: a
    # capability whose scan failed reports no findings, which is
    # indistinguishable from a clean repository on every dashboard the platform
    # has. Spec 04 §6 is the requirement; this is how a person hears about it
    # the same day rather than during an audit.
    if submission.completed_at is not None and row["scan_status"] in _FAILED_SCANS:
        background.add_task(
            request.app.state.notifier.send,
            Notification(
                title=f"{row['capability']} scan {row['scan_status']}",
                detail=(
                    f"Scan run `{submission.scan_run_id}` on "
                    f"`{submission.commit_sha or 'unknown commit'}` did not complete "
                    "cleanly. It reported "
                    f"{submission.finding_count or 0} finding(s), and that count "
                    "is not evidence of a clean repository -- a failed scan and "
                    "a clean scan look identical on the dashboard."
                ),
                repo_full_name=token.repo_full_name,
                level="warning",
            ),
        )

    return IngestAccepted(accepted=1, scan_run_id=submission.scan_run_id)


#: Severity ordered loudest-last, so "at or above the configured floor" is a
#: comparison rather than a set membership test that has to be kept in sync.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {name: rank for rank, name in enumerate(reversed(_SEVERITY_ORDER))}


@router.post("/findings", response_model=IngestAccepted)
async def ingest_findings(
    request: Request,
    batch: FindingBatch,
    token: TokenDep,
    background: BackgroundTasks,
) -> IngestAccepted:
    """Submit a batch of normalized findings for a scan run.

    An empty batch is valid and meaningful: it is how a scanner reports
    "I ran and found nothing," which the lake must be able to tell apart from
    "never ran" (spec 04 §6).
    """
    capability = batch.capability.value
    _require_capability(token, capability)

    now = utcnow()
    rows: list[dict[str, Any]] = []

    # One CODEOWNERS read per batch, cached for fifteen minutes across batches
    # (spec 24 §1.2). Never per finding: a four-hundred-finding upload would
    # otherwise be four hundred GitHub requests for one answer.
    ownership = request.app.state.ownership
    rules = await ownership.rules_for(
        _installation_client(request, token.repo_full_name), token.repo_full_name
    )
    profile_owner = _profile_owner(request, token.repo_full_name)

    for finding in batch.findings:
        finding_id, fingerprint_version = compute_finding_id(
            repo_full_name=token.repo_full_name,
            capability=capability,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            symbol=finding.symbol,
            code_snippet=finding.code_snippet,
            line_start=finding.line_start,
            package_name=finding.package_name,
            address=finding.address,
            port=finding.port,
            title=finding.title,
        )
        owner, owner_source = owner_for_finding(
            file_path=finding.file_path, rules=rules, profile_owner=profile_owner
        )
        rows.append(
            {
                "finding_id": finding_id,
                "scan_run_id": batch.scan_run_id,
                # Every finding this endpoint accepts is about a repository:
                # the token is scoped to one (spec 02 §6), and a network scan
                # does not authenticate as a repo. A network finding arrives
                # with asset_type "network" through its own path.
                "asset_type": "repo",
                "asset_id": token.repo_full_name,
                "repo_full_name": token.repo_full_name,
                "capability": capability,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "symbol": finding.symbol,
                "code_snippet": finding.code_snippet,
                "fingerprint_version": fingerprint_version,
                "address": finding.address,
                "port": finding.port,
                "package_name": finding.package_name,
                "package_version": finding.package_version,
                # Provisional: compaction keeps the stored first_seen_* when
                # this finding_id turns out to already exist.
                "status": FindingStatus.OPEN.value,
                "first_seen_scan_run_id": batch.scan_run_id,
                "last_seen_scan_run_id": batch.scan_run_id,
                "first_seen_at": now,
                "last_seen_at": now,
                "resolved_at": None,
                "owner": owner,
                "owner_source": owner_source,
                "raw_finding_json": json.dumps(finding.raw_finding_json, ensure_ascii=False),
            }
        )

    request.app.state.buffer.append("findings", rows)

    # One summary per batch, never one per finding (spec 16 §14). A scan that
    # uploads four hundred criticals is one event a person needs to know about;
    # four hundred messages is a channel somebody mutes, which costs more than
    # the alert was ever worth.
    #
    # These are newly *ingested*, not necessarily newly *discovered* — the
    # compaction upsert decides that, and it has not run yet. The wording says
    # "reported" for exactly that reason.
    settings = request.app.state.settings
    threshold = _SEVERITY_RANK.get(settings.slack_notify_min_severity, 3)
    loud = [r for r in rows if _SEVERITY_RANK.get(r["severity"], 0) >= threshold]
    if loud:
        counts = Counter(r["severity"] for r in loud)
        summary = ", ".join(
            f"{counts[name]} {name}" for name in _SEVERITY_ORDER if counts.get(name)
        )
        worst = max(_SEVERITY_RANK.get(r["severity"], 0) for r in loud)
        background.add_task(
            request.app.state.notifier.send,
            Notification(
                title=f"{capability} reported {summary}",
                detail=(
                    f"Scan run `{batch.scan_run_id}`.\n"
                    + "\n".join(f"- {r['severity']}: {r['title']}" for r in loud[:5])
                    + (f"\n...and {len(loud) - 5} more." if len(loud) > 5 else "")
                ),
                repo_full_name=token.repo_full_name,
                level="critical" if worst >= _SEVERITY_RANK["critical"] else "warning",
            ),
        )

    return IngestAccepted(accepted=len(rows), scan_run_id=batch.scan_run_id)


@router.post("/raw", response_model=RawAccepted)
async def ingest_raw_output(
    request: Request,
    token: TokenDep,
    scan_run_id: str,
    capability: Capability,
    filename: str,
) -> RawAccepted:
    """Archive a scanner's original, unmodified output (spec 05 §7).

    Kept alongside the normalized findings so a disputed result can always be
    traced back to exactly what the tool said, rather than to our
    interpretation of it. Retention is bounded separately; normalized
    `Finding` rows outlive the raw files.
    """
    _require_capability(token, capability.value)

    settings = request.app.state.settings
    safe_name = Path(filename).name  # strip any directory component
    if not safe_name or safe_name.startswith("."):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="filename must be a plain file name.",
        )

    body = await request.body()
    if len(body) > settings.max_raw_output_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"Raw output is {len(body)} bytes; the ceiling is "
                f"{settings.max_raw_output_bytes}. Normalized findings were still "
                "accepted — only the archive copy was rejected."
            ),
        )

    # Repo names contain a slash; keep it as a directory level rather than
    # flattening, so the archive mirrors the repo namespace.
    owner, _, name = token.repo_full_name.partition("/")
    destination = (
        settings.raw_dir
        / _safe_segment(owner)
        / _safe_segment(name)
        / _safe_segment(scan_run_id)
        / safe_name
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(body)

    return RawAccepted(
        raw_output_ref=str(destination.relative_to(settings.datalake_dir).as_posix()),
        bytes_written=len(body),
    )


def _safe_segment(value: str) -> str:
    """One path segment, with no way out of the archive directory."""
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in value)
    return cleaned.strip(".-") or "unknown"


@router.post("/aegis", response_model=AegisAccepted)
async def ingest_aegis(
    request: Request, body: InsiderRiskSubmission, token: TokenDep
) -> AegisAccepted:
    """Score a pull request for insider risk and record it (spec 06 §4).

    The workflow reports *observations* — which signals fired and why — and
    the platform combines them. Scoring here rather than on the runner is what
    makes the recommendation reproducible from the stored breakdown, and it is
    also what stops a repo silently running a forked scorer with its own
    thresholds.

    Read spec 06 §9 before extending this. The row is personal data.
    """
    _require_capability(token, Capability.AEGIS.value)

    with request.app.state.db.session() as session:
        config = capability_config_for(session, token.repo_full_name, "aegis")

    assessment = assess(
        body,
        token.repo_full_name,
        block_threshold=int(config.get("block_threshold", 80)),
        ai_disclosure_required=bool(config.get("ai_disclosure_required", True)),
        ai_classifier_configured=bool(config.get("ai_classifier_url")),
    )

    check_run_id: str | None = None
    check_run_error: str | None = None
    blocking = bool(config.get("blocking", False))
    github = _installation_client(request, token.repo_full_name)
    if github is not None:
        try:
            # Bounded, because this is the only thing between a caller and its
            # row and it is a call to somebody else's API.
            #
            # `mykronos/insider/77` timed out on 2026-08-19 after the full 60
            # seconds the pipeline allows this POST, and the request never
            # reached uvicorn's access log at all — uvicorn logs when a
            # response is sent, so a request the client abandoned mid-flight
            # leaves no trace. Every other ingest endpoint was logging
            # normally. The GitHub client's own timeout is 30s per call, and
            # minting an installation token is a second call, so a slow
            # api.github.com can consume the caller's whole budget here and
            # nowhere else.
            #
            # 15s, well inside the pipeline's 60. The `except` below already
            # says the row is the record and the Check Run is only how it is
            # displayed — that was true for a GitHubError and not for a hang,
            # because a hang took the row with it. Now both land here.
            check_run_id = await asyncio.wait_for(
                github.create_check_run(
                    token.repo_full_name,
                    name=AEGIS_CHECK_RUN_NAME,
                    head_sha=body.commit_sha,
                    # Advisory unless the repo opted in, same as every other
                    # capability (spec 04 §5). A red check on a heuristic about
                    # a person is the fastest way to make this capability
                    # hated.
                    conclusion=(
                        "failure"
                        if blocking and assessment.is_block
                        else "neutral"
                        if assessment.recommendation != "pass"
                        else "success"
                    ),
                    title=(
                        f"{assessment.recommendation.replace('_', ' ')} — "
                        f"{assessment.insider_risk_score}/100"
                    ),
                    summary=render_check_run_summary(assessment, body),
                ),
                timeout=CHECK_RUN_TIMEOUT,
            )
        except (GitHubError, TimeoutError) as exc:
            # Same rule as Oracle: the row is the record, the Check Run is how
            # it is displayed, and losing the display must not lose the row.
            check_run_error = str(exc) or type(exc).__name__
            logger.warning(
                "Could not post the Aegis check run for %s#%s: %s",
                scrub(token.repo_full_name),
                scrub(body.pr_number),
                scrub(check_run_error),
            )

    request.app.state.buffer.append(
        "insider_risk_signals",
        [aegis_row(assessment, body, token.repo_full_name, check_run_id=check_run_id)],
    )

    return AegisAccepted(
        accepted=1,
        signal_id=assessment.signal_id,
        insider_risk_score=assessment.insider_risk_score,
        recommendation=assessment.recommendation,
        blocking=blocking,
        check_run_id=check_run_id,
        check_run_error=check_run_error,
    )


@router.post("/atlas", response_model=AtlasAccepted)
async def ingest_atlas(
    request: Request, body: SscsEvidenceSubmission, token: TokenDep
) -> AtlasAccepted:
    """Record supply-chain evidence for a commit (spec 07 §4).

    The workflow reports dependency counts per ecosystem; the trust score is
    computed here, because spec 07 §7 makes reproducibility an acceptance
    criterion and a score the runner calculates drifts the moment two repos
    are on different versions of the action.

    Per-vulnerability detail goes in as ordinary `Finding` rows through
    `/api/ingest/findings` with `capability = atlas` (spec 07 §3), so
    dependency vulnerabilities appear in the same portfolio views as
    everything else. This endpoint writes only the aggregate.
    """
    _require_capability(token, Capability.ATLAS.value)

    assessment = trust_score(body.ecosystems)

    with request.app.state.db.session() as session:
        config = capability_config_for(session, token.repo_full_name, "atlas")

    minimum = int(config.get("min_trust_score", 50))
    blocking = bool(config.get("blocking", False))

    request.app.state.buffer.append(
        "sscs_evidence", [atlas_row(body, assessment, token.repo_full_name)]
    )

    return AtlasAccepted(
        accepted=1,
        evidence_id=atlas_evidence_id(token.repo_full_name, body.commit_sha),
        trust_score=assessment.trust_score,
        raw_trust_score=assessment.raw_trust_score,
        dependency_count=assessment.dependency_count,
        vulnerable_dependency_count=assessment.vulnerable_dependency_count,
        min_trust_score=minimum,
        blocking=blocking,
        # An unassessed scan is not below the floor: there is no score to
        # compare, and reporting it as below would block a release for a
        # measurement that never happened (spec 07 §5a).
        below_minimum=(assessment.trust_score is not None and assessment.trust_score < minimum),
    )


@router.post("/reachability", response_model=ReachabilityAccepted)
async def ingest_reachability(
    request: Request, body: ReachabilitySubmission, token: TokenDep
) -> ReachabilityAccepted:
    """Record which files nothing imports (spec 19 §2.1).

    Under the `sast` capability's token: reachability is a fact about source
    code, and `sast` is the capability whose findings it prioritises. A
    capability of its own would mean a separate grant for something that has
    no findings, no workflow of its own, and nothing to enable.

    One row per repository, replaced outright. This is current state, not
    evidence — the previous analysis is superseded by this one and nothing
    reads its history (see `ReachabilityReport`).
    """
    _require_capability(token, Capability.SAST.value)

    with request.app.state.db.session() as session:
        onboarding = (
            session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == token.repo_full_name
                )
            )
            .scalars()
            .first()
        )
        if onboarding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{token.repo_full_name} is not onboarded.",
            )
        report = (
            session.execute(
                select(ReachabilityReport).where(
                    ReachabilityReport.repo_onboarding_id == onboarding.id
                )
            )
            .scalars()
            .first()
        )
        if report is None:
            report = ReachabilityReport(repo_onboarding_id=onboarding.id)
            session.add(report)
        report.language = body.language
        report.commit_sha = body.commit_sha
        report.orphaned_paths = list(body.orphaned_paths)
        report.files_analysed = body.files_analysed
        report.files_unparseable = body.files_unparseable

    return ReachabilityAccepted(
        accepted=1,
        orphaned=len(body.orphaned_paths),
        files_analysed=body.files_analysed,
    )


@router.post("/{capability}", response_model=IngestAccepted)
async def ingest_capability_payload(
    capability: Capability,
    token: TokenDep,
) -> IngestAccepted:
    """Capability-specific tables that do not have an endpoint yet.

    Declared here because spec 05 §4 defines the route. Aegis and Atlas have
    their own handlers above — registered first, so this catch-all cannot
    shadow them. Returning 501 rather than 404 keeps the contract visible
    instead of looking like a routing bug.
    """
    _require_capability(token, capability.value)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            f"Ingestion for '{capability.value}' is not implemented yet. "
            "Patchwork arrives in Phase 6 (specs/13-build-roadmap.md §3)."
        ),
    )


def _profile_owner(request: Request, repo_full_name: str) -> str | None:
    """The repository owner recorded on the risk profile (spec 21 §1).

    Used only for findings with no path — a dependency CVE names a package,
    not the file that declares it. Weaker than a CODEOWNERS answer and stored
    under its own `owner_source` so nobody mistakes it for one.
    """
    with request.app.state.db.session() as session:
        profile = (
            session.execute(
                select(RiskProfile)
                .join(RepoOnboarding, RepoOnboarding.id == RiskProfile.repo_onboarding_id)
                .where(RepoOnboarding.github_repo_full_name == repo_full_name)
            )
            .scalars()
            .first()
        )
    return profile.owner if profile is not None else None


def _installation_client(request: Request, repo_full_name: str) -> Any:
    with request.app.state.db.session() as session:
        onboarding = (
            session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo_full_name)
            )
            .scalars()
            .first()
        )
    if onboarding is None:
        return None
    return request.app.state.github_factory.for_installation(onboarding.github_installation_id)
