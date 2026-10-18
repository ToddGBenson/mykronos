"""Public endpoints: register what is reachable from the internet, see what it shows.

Registering a URL is the operator's claim that it is public; the exposure job
(and `POST /probe`) is the platform checking what an anonymous visitor gets
there. See `mykronos.exposure`.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from mykronos import exposure
from mykronos.adminauth import PrincipalDep

router = APIRouter(prefix="/api/exposure", tags=["Exposure"])


class EndpointIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=512, description="Base URL as the internet reaches it.")
    repo_full_name: str = Field(default="", max_length=255)
    label: str = Field(default="", max_length=255)
    surface_id: str | None = Field(
        default=None,
        max_length=36,
        description=(
            "The declared surface (usually an entry point) this URL is the "
            "public face of (TheHub #60825). Must belong to `repo_full_name`."
        ),
    )


def _require_writer(principal: Any, what: str) -> None:
    if not principal.may_write:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=f"{what} requires write access."
        )


@router.get("")
async def list_endpoints(request: Request, principal: PrincipalDep) -> dict[str, Any]:
    """Every registered public endpoint with its last observations, worst first."""
    rows = exposure.summary(request.app.state.db)
    return {
        "endpoints": rows,
        "exposed": sum(1 for r in rows if r["observations"]),
        "never_probed": sum(1 for r in rows if r["last_status"] == exposure.NOT_PROBED),
    }


@router.post("/endpoints", status_code=status.HTTP_201_CREATED)
async def register_endpoint(
    request: Request, body: EndpointIn, principal: PrincipalDep
) -> dict[str, Any]:
    _require_writer(principal, "Registering a public endpoint")
    from mykronos.db.models import PublicEndpoint, RepoSurface

    try:
        url = exposure.validate_url(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db = request.app.state.db
    with db.session() as session:
        if session.scalars(select(PublicEndpoint).where(PublicEndpoint.url == url)).first():
            raise HTTPException(status_code=409, detail=f"{url} is already registered.")
        if body.surface_id:
            surface = session.get(RepoSurface, body.surface_id)
            if surface is None or surface.repo_full_name != body.repo_full_name.strip():
                raise HTTPException(
                    status_code=422,
                    detail="surface_id names no surface on that repository.",
                )
        row = PublicEndpoint(
            url=url,
            repo_full_name=body.repo_full_name.strip(),
            label=body.label.strip(),
            declared_by=principal.actor,
            surface_id=body.surface_id or None,
        )
        session.add(row)
        session.flush()
        db.audit(
            session,
            actor=principal.actor,
            action="exposure.registered",
            entity_type="public_endpoint",
            entity_id=row.id,
            url=url,
            repo_full_name=row.repo_full_name,
            surface_id=row.surface_id,
        )
        session.commit()
        return {
            "id": row.id,
            "url": url,
            "last_status": row.last_status,
            "surface_id": row.surface_id,
        }


@router.delete("/endpoints/{endpoint_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_endpoint(request: Request, endpoint_id: str, principal: PrincipalDep) -> None:
    _require_writer(principal, "Removing a public endpoint")
    from mykronos.db.models import PublicEndpoint

    db = request.app.state.db
    with db.session() as session:
        row = session.get(PublicEndpoint, endpoint_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"No public endpoint {endpoint_id}.")
        db.audit(
            session,
            actor=principal.actor,
            action="exposure.removed",
            entity_type="public_endpoint",
            entity_id=row.id,
            url=row.url,
        )
        session.delete(row)
        session.commit()


@router.post("/probe")
async def probe_now(request: Request, principal: PrincipalDep) -> dict[str, Any]:
    """Probe every registered endpoint now, instead of waiting for the job."""
    _require_writer(principal, "Probing public endpoints")
    results = await exposure.run_sweep(request.app.state.db)
    return {"probed": len(results), "results": results}
