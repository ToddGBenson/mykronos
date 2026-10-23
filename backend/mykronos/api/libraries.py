"""Libraries: request, vet, approve and manage third-party libraries
(TheHub epic #60880).

- `POST /api/libraries/requests` vets a package version and opens its
  `library_approval` request (L1, L2). The approval is decided through the
  approvals routes like every other duty.
- `GET /api/libraries/managed` is every library in use with its status,
  owner, version policy and flags (L3); `PATCH` records tolerated or banned,
  an owner or a policy, and `POST /baseline` records every unrecorded library
  as tolerated.
- `POST /api/libraries/pr-checks` runs the allowlist check on one pull
  request, and `PUT /api/libraries/repo-mode` switches a repository between
  report and blocking - refused until the allowlist covers it (L4).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import libraries, library_check
from mykronos.adminauth import HumanDep, Principal, PrincipalDep
from mykronos.approvals.engine import ApprovalError, create_request
from mykronos.approvals.policy import cached_policy
from mykronos.approvals.pull_requests import client_for
from mykronos.db.models import LibraryEntry, LibraryRequest, new_id

router = APIRouter(prefix="/api/libraries", tags=["libraries"])


class LibraryRequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The purl ecosystem: npm, pypi, golang, maven, cargo, nuget.
    ecosystem: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    package_name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    #: Why the library is needed. The approver reads it beside the report.
    reason: str = Field(min_length=20, max_length=4_000)
    owner: str = Field(default="", max_length=255)
    #: The policy the allowlist entry gets if approved; read against `version`.
    version_policy: str = Field(default="minimum", max_length=32)


class LibraryRequestOut(BaseModel):
    id: str
    ecosystem: str
    package_name: str
    version: str
    reason: str
    owner: str
    version_policy: str
    requested_by: str
    #: pending_approval | approved | rejected | expired, or banned: approved,
    #: but a ban recorded while it was pending stands.
    state: str
    #: `flagged` needs a person to approve; `clean` may also be approved by a
    #: delegated agent.
    tier: str
    vetting: dict[str, Any]
    approval_request_id: str | None
    #: The approver's rationale - for a rejection, the reason it was refused.
    decision_reason: str
    decided_by: str
    created_at: datetime
    updated_at: datetime


class LibraryRequestList(BaseModel):
    requests: list[LibraryRequestOut]


class LibraryFlagsOut(BaseModel):
    """`null` means the platform holds no data to decide, never "fine"."""

    divergent: bool
    eol: bool | None
    abandoned: bool | None
    license_changed: bool | None
    version_policy_violation: bool | None
    banned_in_use: bool


class ManagedLibraryOut(BaseModel):
    ecosystem: str
    package_name: str
    repos: list[str]
    versions: list[str]
    #: approved | tolerated | banned
    status: str
    #: approval | baseline | manual, or `default` when nothing is recorded.
    status_source: str
    owner: str
    version_policy: str
    version_ref: str
    flags: LibraryFlagsOut
    facts_read_at: datetime | None


class ManagedLibrariesOut(BaseModel):
    libraries: list[ManagedLibraryOut]
    by_status: dict[str, int]
    #: Libraries whose status is the default rather than a recorded one.
    unrecorded: int
    #: Libraries with any flag set to true.
    flagged: int
    without_owner: int


class LibraryEntryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9-]+$")
    package_name: str = Field(min_length=1, max_length=214)
    #: tolerated | banned. `approved` comes only from an approved request.
    status: str | None = Field(default=None, max_length=16)
    owner: str | None = Field(default=None, max_length=255)
    version_policy: str | None = Field(default=None, max_length=32)
    version_ref: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=2_000)


class LibraryEntryOut(BaseModel):
    ecosystem: str
    package_name: str
    status: str
    owner: str
    version_policy: str
    version_ref: str
    source: str
    approval_request_id: str | None
    note: str
    updated_by: str
    updated_at: datetime


class LibraryBaselineOut(BaseModel):
    recorded: int
    libraries: list[str]


class LibraryFactsOut(BaseModel):
    read: int
    failed: int
    libraries: int


class LibraryCoverageOut(BaseModel):
    repo: str
    mode: str
    libraries: int
    #: `ecosystem:name` of each library in use with no approved or tolerated
    #: entry. Empty with libraries > 0 means covered.
    missing: list[str]
    covered: bool


class LibraryModeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(min_length=3, max_length=255)
    mode: str = Field(max_length=16)


class LibraryPrCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(min_length=3, max_length=255)
    number: int = Field(ge=1)


class LibraryPrCheckOut(BaseModel):
    repo: str
    number: int
    head_sha: str
    mode: str
    conclusion: str
    results: list[dict[str, Any]]
    error: str | None


def _require_writer(principal: Principal, verb: str) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{verb} requires the 'admin' role; you have '{principal.role.value}'.",
        )


def _request_out(row: LibraryRequest) -> LibraryRequestOut:
    return LibraryRequestOut(
        id=row.id,
        ecosystem=row.ecosystem,
        package_name=row.package_name,
        version=row.version,
        reason=row.reason,
        owner=row.owner,
        version_policy=row.version_policy,
        requested_by=row.requested_by,
        state=row.state,
        tier=libraries.vetting_tier(row.vetting or {}),
        vetting=dict(row.vetting or {}),
        approval_request_id=row.approval_request_id,
        decision_reason=row.decision_reason,
        decided_by=row.decided_by,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _entry_out(row: LibraryEntry) -> LibraryEntryOut:
    return LibraryEntryOut(
        ecosystem=row.ecosystem,
        package_name=row.package_name,
        status=row.status,
        owner=row.owner,
        version_policy=row.version_policy,
        version_ref=row.version_ref,
        source=row.source,
        approval_request_id=row.approval_request_id,
        note=row.note,
        updated_by=row.updated_by,
        updated_at=row.updated_at,
    )


def _fetch(request: Request) -> libraries.Fetch:
    fetch: libraries.Fetch = getattr(request.app.state, "library_fetch", libraries.http_fetch)
    return fetch


@router.post("/requests", response_model=LibraryRequestOut, status_code=201)
async def request_library(
    request: Request, body: LibraryRequestIn, principal: PrincipalDep
) -> LibraryRequestOut:
    """Request a library: the platform vets it and opens its approval.

    The vetting report reads OSV, deps.dev and OpenSSF Scorecard, and runs
    typosquat and new-package checks; each check names its source, and one
    that could not be read says so. The report is the evidence of a
    `library_approval` request whose tier it decides.
    """
    _require_writer(principal, "Requesting a library")
    if body.version_policy not in libraries.VERSION_POLICIES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"version_policy must be one of {', '.join(libraries.VERSION_POLICIES)}.",
        )
    ecosystem = body.ecosystem
    name = libraries.normalise(ecosystem, body.package_name)
    db = request.app.state.db
    with db.session() as session:
        entry = session.execute(
            select(LibraryEntry).where(
                LibraryEntry.ecosystem == ecosystem, LibraryEntry.package_name == name
            )
        ).scalar_one_or_none()
        if entry is not None and entry.status == "banned":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{ecosystem}:{name} is banned. Lifting a ban is a change to its "
                "entry, made deliberately, not a request.",
            )
        if (
            entry is not None
            and entry.status == "approved"
            and libraries.version_allowed(entry.version_policy, entry.version_ref, body.version)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{ecosystem}:{name}@{body.version} is already approved.",
            )
        duplicate = session.execute(
            select(LibraryRequest).where(
                LibraryRequest.ecosystem == ecosystem,
                LibraryRequest.package_name == name,
                LibraryRequest.version == body.version,
                LibraryRequest.state == "pending_approval",
            )
        ).scalar_one_or_none()
        if duplicate is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Request {duplicate.id} for this version is already pending.",
            )

    report = await libraries.vet(
        ecosystem,
        body.package_name,
        body.version,
        fetch=_fetch(request),
        known=libraries.known_names(request.app.state.catalog, ecosystem),
    )
    request_id = new_id()
    fields = {
        "ecosystem": ecosystem,
        "package_name": name,
        "version": body.version,
        "reason": body.reason.strip(),
        "owner": body.owner.strip(),
        "version_policy": body.version_policy,
        "vetting": report,
    }
    try:
        approval = create_request(
            db,
            cached_policy(request.app.state.settings.approval_policy_path),
            duty=libraries.DUTY,
            subject_ref=request_id,
            requested_by=principal,
            statement=body.reason.strip(),
            context={"library_request": fields},
        )
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    with db.session() as session:
        row = LibraryRequest(
            id=request_id,
            requested_by=principal.actor,
            requester_kind=principal.kind.value,
            state="pending_approval",
            approval_request_id=approval.id,
            **fields,
        )
        session.add(row)
        db.audit(
            session,
            actor=principal.actor,
            action="library.requested",
            entity_type="library",
            entity_id=f"{ecosystem}:{name}",
            version=body.version,
            tier=approval.tier,
            flags=report["flags"],
            approval_request_id=approval.id,
        )
        session.flush()
        return _request_out(row)


@router.get("/requests", response_model=LibraryRequestList)
async def list_requests(
    request: Request,
    principal: PrincipalDep,
    state: Annotated[str | None, Query(max_length=24)] = None,
) -> LibraryRequestList:
    """Library requests, newest first, with decisions copied back."""
    with request.app.state.db.session() as session:
        libraries.sync_decisions(session)
        query = select(LibraryRequest).order_by(LibraryRequest.created_at.desc())
        if state:
            query = query.where(LibraryRequest.state == state)
        return LibraryRequestList(
            requests=[_request_out(r) for r in session.execute(query).scalars()]
        )


@router.get("/requests/{request_id}", response_model=LibraryRequestOut)
async def get_request(
    request: Request, request_id: str, principal: PrincipalDep
) -> LibraryRequestOut:
    """One library request and its vetting report."""
    with request.app.state.db.session() as session:
        libraries.sync_decisions(session)
        row = session.get(LibraryRequest, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"No library request {request_id}.")
        return _request_out(row)


@router.get("/managed", response_model=ManagedLibrariesOut)
async def managed_libraries(
    request: Request,
    principal: PrincipalDep,
    ecosystem: Annotated[str | None, Query(max_length=32)] = None,
) -> ManagedLibrariesOut:
    """Every library in use, with its status, owner, version policy and flags.

    A library nobody has recorded reads `tolerated` with `status_source:
    default`. EOL and abandonment come from registry facts; until the
    `library-facts` job has read a library, those flags are null.
    """
    with request.app.state.db.session() as session:
        rows = libraries.managed(session, request.app.state.catalog, ecosystem=ecosystem)
    by_status: dict[str, int] = {s: 0 for s in libraries.STATUSES}
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    return ManagedLibrariesOut(
        libraries=[ManagedLibraryOut.model_validate(r) for r in rows],
        by_status=by_status,
        unrecorded=sum(1 for r in rows if r["status_source"] == "default"),
        flagged=sum(1 for r in rows if any(v is True for v in r["flags"].values())),
        without_owner=sum(1 for r in rows if not r["owner"]),
    )


@router.patch("/managed", response_model=LibraryEntryOut)
async def update_library(
    request: Request, body: LibraryEntryIn, principal: PrincipalDep
) -> LibraryEntryOut:
    """Record a library as tolerated or banned, or set its owner or policy.

    Approving is refused here: a library is approved through a vetted request.
    Tolerated is refused for a library no repository's SBOM has. Banning,
    lifting a ban and loosening an approved library need a person.
    """
    _require_writer(principal, "Changing a library")
    ecosystem = body.ecosystem.strip().lower()
    name = libraries.normalise(ecosystem, body.package_name)
    in_use = any(
        lib.package_name == name
        for lib in libraries.in_use(request.app.state.catalog, ecosystem=ecosystem)
    )
    with request.app.state.db.session() as session:
        try:
            entry = libraries.set_entry(
                session,
                ecosystem=body.ecosystem,
                package_name=body.package_name,
                actor=principal.actor,
                in_use=in_use,
                by_person=principal.is_human,
                status=body.status,
                owner=body.owner,
                version_policy=body.version_policy,
                version_ref=body.version_ref,
                note=body.note,
            )
        except libraries.LibraryPersonError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except libraries.LibraryError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        return _entry_out(entry)


@router.post("/baseline", response_model=LibraryBaselineOut)
async def baseline(request: Request, principal: PrincipalDep) -> LibraryBaselineOut:
    """Record every in-use library with no entry as tolerated."""
    _require_writer(principal, "Recording the library baseline")
    with request.app.state.db.session() as session:
        added = libraries.baseline(session, request.app.state.catalog, actor=principal.actor)
    return LibraryBaselineOut(recorded=len(added), libraries=added)


@router.post("/facts/refresh", response_model=LibraryFactsOut)
async def refresh_facts(
    request: Request,
    principal: PrincipalDep,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> LibraryFactsOut:
    """Read registry facts (latest release, licenses, deprecations) for the
    libraries in use, least recently read first."""
    _require_writer(principal, "Refreshing library facts")
    result = await libraries.refresh_facts(
        request.app.state.db, request.app.state.catalog, fetch=_fetch(request), limit=limit
    )
    return LibraryFactsOut(**result)


@router.get("/coverage", response_model=LibraryCoverageOut)
async def repo_coverage(
    request: Request,
    principal: PrincipalDep,
    repo: Annotated[str, Query(min_length=3, max_length=255)],
) -> LibraryCoverageOut:
    """Whether the allowlist covers a repository's current dependencies."""
    with request.app.state.db.session() as session:
        total, missing = library_check.coverage(session, request.app.state.catalog, repo)
        mode = library_check.repo_mode(session, repo)
    return LibraryCoverageOut(
        repo=repo, mode=mode, libraries=total, missing=missing, covered=total > 0 and not missing
    )


@router.put("/repo-mode", response_model=LibraryCoverageOut)
async def set_repo_mode(
    request: Request, body: LibraryModeIn, principal: HumanDep
) -> LibraryCoverageOut:
    """Switch a repository's library check between report and blocking.

    A person's decision. Blocking is refused until every library in the
    repository's SBOM has an approved or tolerated entry.
    """
    _require_writer(principal, "Changing a repository's library check")
    with request.app.state.db.session() as session:
        try:
            library_check.set_mode(
                session, request.app.state.catalog, body.repo, body.mode, principal.actor
            )
        except libraries.LibraryError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        session.flush()
        total, missing = library_check.coverage(session, request.app.state.catalog, body.repo)
        mode = library_check.repo_mode(session, body.repo)
    return LibraryCoverageOut(
        repo=body.repo,
        mode=mode,
        libraries=total,
        missing=missing,
        covered=total > 0 and not missing,
    )


@router.post("/pr-checks", response_model=LibraryPrCheckOut)
async def run_pr_check(
    request: Request, body: LibraryPrCheckIn, principal: PrincipalDep
) -> LibraryPrCheckOut:
    """Run the library-allowlist check on one pull request's head now.

    The `library-checks` job does this for every open pull request; this is
    for not waiting."""
    _require_writer(principal, "Running a library check")
    github = client_for(request.app.state.db, request.app.state.github_factory, body.repo)
    if github is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{body.repo} is not onboarded; there is no installation to read it through.",
        )
    try:
        check = await library_check.check_pull_request(
            request.app.state.db,
            request.app.state.catalog,
            github,
            repo=body.repo,
            number=body.number,
            dashboard_url=request.app.state.settings.dashboard_url,
        )
    except libraries.LibraryError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return LibraryPrCheckOut(
        repo=check.repo_full_name,
        number=check.number,
        head_sha=check.head_sha,
        mode=check.mode,
        conclusion=check.conclusion,
        results=list(check.results or []),
        error=check.error,
    )
