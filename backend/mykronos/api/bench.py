"""The detector benchmark lane's run record (spec 23 §1.6, TheHub #60742).

`POST /api/ingest/bench-run` is what the `bench` Concourse job calls on every
mykronos main commit that passes `unit`. The platform grades the corpus's
newest scanned commit against its manifest and stores a `BenchRun`, graded or
not. `GET /api/bench/runs` reads them back, newest first.

**Never an empty success.** A corpus that is not onboarded, is onboarded as a
real repository, has never been scanned, or has no readable manifest is
stored as a run with a status other than `graded` and the reason, and the job
exits non-zero on it. A grade of 0% and a grade that could not be taken are
different answers (#60015), and here they are different statuses.

The ingestion token needs no capability grant, as for `/lane-failure`: the
benchmark is not a capability of the repository that runs it, and it writes
nothing to the lake. The platform repository on the record comes from the
token, never from the body.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import bench
from mykronos.adminauth import PrincipalDep
from mykronos.api.ingest import TokenDep
from mykronos.db.models import BenchRun, RepoOnboarding

logger = logging.getLogger(__name__)

router = APIRouter(tags=["bench"])


class BenchRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The corpus repository, `owner/name`. It must be onboarded with
    #: `synthetic: true`; nothing infers that from the name (spec 23 §1.5).
    bench_repo: str = Field(min_length=3, max_length=255, pattern=r"^[\w.-]+/[\w.-]+$")
    #: The mykronos commit the job ran for.
    platform_commit: str = Field(min_length=7, max_length=64, pattern=r"^[0-9a-fA-F]+$")
    run_url: str | None = Field(default=None, max_length=1000)


class BenchRunOut(BaseModel):
    id: str
    graded_at: datetime
    platform_repo: str
    platform_commit: str
    bench_repo: str
    bench_commit: str | None
    #: `graded`, `not_measured` or `manifest_invalid`. Anything but `graded`
    #: is a red lane.
    status: str
    reason: str
    scan_runs: int
    seeded_total: int
    unmatched_findings: int
    #: Per capability: scanned, seeded_total, seeded_detected, recall (null
    #: when nothing seeded or no scan of it ran), and the missed seed ids.
    capabilities: list[dict[str, Any]]
    #: Per (capability, rule_id): findings, matched, unmatched, seeds_detected,
    #: seeds_in_capability, recall and precision_floor. A floor because the
    #: corpus is seeded, not clean (spec 23 §1.3).
    rules: list[dict[str, Any]]
    run_url: str | None


class BenchRunList(BaseModel):
    runs: list[BenchRunOut]


def _out(row: BenchRun) -> BenchRunOut:
    return BenchRunOut(
        id=row.id,
        graded_at=row.graded_at,
        platform_repo=row.platform_repo,
        platform_commit=row.platform_commit,
        bench_repo=row.bench_repo,
        bench_commit=row.bench_commit,
        status=row.status,
        reason=row.reason,
        scan_runs=row.scan_runs,
        seeded_total=row.seeded_total,
        unmatched_findings=row.unmatched_findings,
        capabilities=list(row.capabilities or []),
        rules=list(row.rules or []),
        run_url=row.run_url,
    )


async def _take(request: Request, body: BenchRunRequest) -> dict[str, Any]:
    """The run's fields: a grade, or the reason there is none."""
    state = request.app.state
    with state.db.session() as session:
        onboarding = (
            session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == body.bench_repo,
                    RepoOnboarding.status != "removed",
                )
            )
            .scalars()
            .first()
        )
        if onboarding is None:
            return {
                "status": bench.NOT_MEASURED,
                "reason": (
                    f"{body.bench_repo} is not onboarded, so there is no corpus to "
                    "grade. Onboard it with synthetic: true (spec 23 §1.5)."
                ),
            }
        if not onboarding.synthetic:
            return {
                "status": bench.NOT_MEASURED,
                "reason": (
                    f"{body.bench_repo} is onboarded but not as synthetic. Its findings "
                    "are real findings, and grading them as seeds would score them as "
                    "detector hits. Re-onboard it with synthetic: true if it is the corpus."
                ),
            }
        installation_id = int(onboarding.github_installation_id)
        branch = onboarding.default_branch or "main"

    scanned = bench.latest_scanned_commit(state.catalog, body.bench_repo, branch)
    if scanned is None:
        return {
            "status": bench.NOT_MEASURED,
            "reason": (
                f"The lake holds no scan run for {body.bench_repo} on {branch}, so "
                "nothing has scanned the corpus and there is no detection to grade. "
                "This is not 0% recall."
            ),
        }
    commit, runs = scanned
    taken: dict[str, Any] = {"bench_commit": commit, "scan_runs": runs}

    factory = getattr(state, "github_factory", None)
    try:
        if factory is None:
            raise RuntimeError("no GitHub App is configured")
        text = await factory.for_installation(installation_id).get_file(
            body.bench_repo, bench.MANIFEST_PATH, commit
        )
        seeds = bench.parse_manifest(text)
    except ValueError as exc:
        return {**taken, "status": bench.MANIFEST_INVALID, "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - any read failure is the same answer here
        logger.warning("Could not read %s from %s", bench.MANIFEST_PATH, body.bench_repo)
        return {
            **taken,
            "status": bench.MANIFEST_INVALID,
            "reason": (
                f"{bench.MANIFEST_PATH} could not be read from {body.bench_repo} at "
                f"{commit}: {type(exc).__name__}."
            ),
        }

    result = bench.grade(
        seeds,
        bench.findings_for(state.catalog, body.bench_repo, commit),
        bench.scanned_capabilities(state.catalog, body.bench_repo, commit),
    )
    return {
        **taken,
        "status": bench.GRADED,
        "reason": f"Graded {len(seeds)} seeded issue(s) against {runs} scan run(s).",
        "seeded_total": len(seeds),
        "unmatched_findings": result.unmatched_findings,
        "capabilities": [c.as_dict() for c in result.capabilities],
        "rules": [r.as_dict() for r in result.rules],
    }


@router.post("/api/ingest/bench-run", response_model=BenchRunOut)
async def ingest_bench_run(
    request: Request, body: BenchRunRequest, token: TokenDep
) -> BenchRunOut:
    """Grade the detector benchmark corpus and store the run, graded or not.

    The answer is 200 whatever the status, because the run was recorded; the
    `status` is the verdict, and the `bench` job exits non-zero on anything
    but `graded`. Nothing is written to the lake.
    """
    fields = await _take(request, body)
    with request.app.state.db.session() as session:
        row = BenchRun(
            platform_repo=token.repo_full_name,
            platform_commit=body.platform_commit,
            bench_repo=body.bench_repo,
            run_url=body.run_url,
            **fields,
        )
        session.add(row)
        session.flush()
        return _out(row)


@router.get("/api/bench/runs", response_model=BenchRunList)
def list_bench_runs(
    request: Request,
    principal: PrincipalDep,
    limit: int = Query(default=50, ge=1, le=500),
) -> BenchRunList:
    """The benchmark lane's runs, newest first, with per-rule figures."""
    with request.app.state.db.session() as session:
        rows = session.scalars(
            select(BenchRun).order_by(BenchRun.graded_at.desc()).limit(limit)
        ).all()
        return BenchRunList(runs=[_out(r) for r in rows])
