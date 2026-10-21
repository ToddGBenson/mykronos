"""The routes behind `WriterDep` are a committed list (TheHub #60809).

`WriterDep` admits any principal that `may_write`: the operator's admin token
**and every agent credential** (spec 34 §1.1). It was called `AdminDep`, and
the name read as "a person with the admin role", which it never was. A route
that must be a person's uses `HumanDep`.

Renaming it does not stop the next route from picking it up by default, so
this file pins the set. A route that starts depending on `WriterDep` fails
here until it is added below, which makes widening what an agent may do a
reviewed change rather than a side effect.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.routing import APIRoute

from mykronos import adminauth
from mykronos.adminauth import ActorKind, Principal, Role, require_writer
from mykronos.config import Settings
from mykronos.main import create_app

#: Every `METHOD path` whose dependency graph contains `require_writer`.
#: Adding one is a decision that an agent may call it; say so in the PR.
WRITER_ROUTES: frozenset[str] = frozenset(
    {
        "POST /api/knowledge/notes",
        "POST /api/knowledge/promotion-candidates/{subject}/approve",
        "GET /api/repos/-/capabilities",
        "POST /api/repos",
        "GET /api/repos",
        "GET /api/repos/{repo_id}",
        "PATCH /api/repos/{repo_id}",
        "PUT /api/repos/{repo_id}/deployment-probe",
        "PATCH /api/repos/{repo_id}/capabilities",
        "DELETE /api/repos/{repo_id}",
        "POST /api/repos/{repo_id}/scan",
        "GET /api/repos/{repo_id}/workflows",
        "PUT /api/repos/{repo_id}/workflows/{capability}/enable",
        "PUT /api/repos/{repo_id}/workflows/{capability}/disable",
        "PUT /api/repos/{repo_id}/risk-profile",
        "POST /api/triage/{finding_id}/groom",
        "POST /api/triage/repos/{repo_id}/combinations/{combination_id}/groom",
    }
)


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> FastAPI:
    root: Path = tmp_path_factory.mktemp("writer-routes")
    settings = Settings(
        datalake_dir=root / "datalake",
        database_url=f"sqlite:///{(root / 'mykronos.db').as_posix()}",
        run_compaction_in_background=False,
        run_jobs_in_background=False,
        github_app_id="",
        github_app_private_key_path=None,
    )
    return create_app(settings)


def _routes(app: FastAPI) -> list[Any]:
    """Flattened as in test_route_authz_matrix.py: recent FastAPI keeps an
    included router as one entry and walks it with `iter_route_contexts`."""
    import fastapi.routing

    walk = getattr(fastapi.routing, "iter_route_contexts", None)
    return list(walk(app.routes)) if walk is not None else list(app.routes)


def _depends_on_writer(route: Any) -> bool:
    original = getattr(route, "original_route", route)
    if not isinstance(original, APIRoute):
        return False
    stack = list(original.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is require_writer:
            return True
        stack.extend(dep.dependencies)
    return False


def _writer_routes(app: FastAPI) -> set[str]:
    found: set[str] = set()
    for route in _routes(app):
        if not _depends_on_writer(route):
            continue
        for method in getattr(route, "methods", None) or ():
            if method != "HEAD":
                found.add(f"{method} {route.path}")
    return found


class TestTheWriterRoutesArePinned:
    def test_the_routes_behind_writer_dep_are_the_committed_list(self, app: FastAPI) -> None:
        found = _writer_routes(app)

        added = sorted(found - WRITER_ROUTES)
        removed = sorted(WRITER_ROUTES - found)
        assert not added, (
            "New routes depend on WriterDep, which admits every agent credential. "
            f"If an agent may call them, add them to WRITER_ROUTES on purpose: {added}"
        )
        assert not removed, f"WRITER_ROUTES names routes that no longer use WriterDep: {removed}"

    def test_the_list_is_not_empty(self) -> None:
        """Guards the walk: a traversal that finds nothing would pass anything."""
        assert len(WRITER_ROUTES) > 10


def _principal(role: Role, kind: ActorKind) -> Principal:
    return Principal(actor=f"{kind.value}:{role.value}", role=role, kind=kind)


class TestWhatWriterDepAdmits:
    """The name says what it does: admin or agent, nobody else."""

    @pytest.mark.parametrize(
        ("role", "kind"),
        [(Role.ADMIN, ActorKind.HUMAN), (Role.AGENT, ActorKind.AGENT)],
    )
    def test_admin_and_agent_are_admitted(self, role: Role, kind: ActorKind) -> None:
        principal = _principal(role, kind)

        assert asyncio.run(require_writer(principal)) == principal.actor

    @pytest.mark.parametrize("role", [Role.VIEWER, Role.REPO_SCOPED])
    def test_anyone_else_is_refused(self, role: Role) -> None:
        with pytest.raises(HTTPException) as refused:
            asyncio.run(require_writer(_principal(role, ActorKind.HUMAN)))

        assert refused.value.status_code == 403

    def test_the_old_name_is_gone(self) -> None:
        """An `AdminDep` alias kept for compatibility would bring the
        misreading back with it."""
        assert not hasattr(adminauth, "AdminDep")
        assert not hasattr(adminauth, "require_admin")
