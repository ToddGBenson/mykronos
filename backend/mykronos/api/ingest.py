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

import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from mykronos.auth import Resolution, TokenRegistry
from mykronos.fingerprint import compute_finding_id
from mykronos.schemas import (
    Capability,
    FindingBatch,
    FindingStatus,
    HealthResponse,
    IngestAccepted,
    RawAccepted,
    ScanRunSubmission,
    utcnow,
)

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])

_bearer = HTTPBearer(auto_error=False, description="Per-repo ingestion token.")

#: Advisory header set when a caller is still presenting a rotated-away token
#: inside its overlap window (spec 05 §4). Lets a repo that never picked up the
#: new secret be spotted from logs, rather than only when it starts failing.
ROTATED_HEADER = "X-Mykronos-Token-Rotated"


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
        response.headers[ROTATED_HEADER] = "true"

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
                f"This token is scoped to {token.repo_full_name} and cannot "
                f"write {repo_full_name}."
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
    return IngestAccepted(accepted=1, scan_run_id=submission.scan_run_id)


@router.post("/findings", response_model=IngestAccepted)
async def ingest_findings(
    request: Request,
    batch: FindingBatch,
    token: TokenDep,
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
            title=finding.title,
        )
        rows.append(
            {
                "finding_id": finding_id,
                "scan_run_id": batch.scan_run_id,
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
                "raw_finding_json": json.dumps(finding.raw_finding_json, ensure_ascii=False),
            }
        )

    request.app.state.buffer.append("findings", rows)
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
        settings.raw_dir / _safe_segment(owner) / _safe_segment(name)
        / _safe_segment(scan_run_id) / safe_name
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


@router.post("/{capability}", response_model=IngestAccepted)
async def ingest_capability_payload(
    capability: Capability,
    token: TokenDep,
) -> IngestAccepted:
    """Capability-specific tables: InsiderRiskSignal, SscsEvidence,
    RemediationEvent, RiskDecision.

    Declared here because spec 05 §4 defines the route, but the target tables
    arrive with their capabilities in Phases 3-6. Returning 501 rather than 404
    keeps the contract visible instead of looking like a routing bug.
    """
    _require_capability(token, capability.value)
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            f"Ingestion for '{capability.value}' is not implemented yet. "
            "Phases 0-1 cover scan_runs and findings only "
            "(specs/13-build-roadmap.md §3)."
        ),
    )
