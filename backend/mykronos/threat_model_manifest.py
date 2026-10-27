"""`.sdlc/threat-model.yaml`: a repository's threat model, in the repository
(TheHub #60825, decision D4; spec 28 §8).

The register (`surfaces.py`, `controls.py`) is admin-authored through the API,
which made it a second copy of something the repository's own team knows
best and changes by pull request. D4 makes the file the source of truth, on
the precedent D-132 set for `.sdlc/process.yaml`: read from the default
branch through the GitHub App, parsed strictly, and never replaced by a
default that pretends to be what the repository declared.

**Parsed strictly.** An unknown key is an error, so `sensitivty:` is reported
rather than silently meaning "unknown". An invalid file changes nothing: the
rows the last valid file produced stay, and the sync says why it stopped —
a typo must not delete a threat model.

**Synced, not read on every request.** Unlike the process manifest, these
rows feed scoring (S5) and are joined against findings, so they live in the
operational store. Rows the manifest declared carry `declared_by: manifest`
and a `manifest_key` (the file's `id`), and are read-only through the API and
UI (`surfaces.DeclaredInManifestError`). Rows declared through the API are never
touched by a sync: the two coexist, and only the file's own rows follow it.

**Absent means absent.** A repository that deletes the file has said its
threat model is no longer declared there, so the manifest's rows go. A file
that could not be *read* is different — `unreadable` changes nothing, because
"could not look" is never evidence of absence (B-058).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime, time
from typing import Any, Literal

import httpx2
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos import controls, surfaces
from mykronos.db.models import RepoControl, RepoOnboarding, RepoSurface
from mykronos.db.session import Database
from mykronos.github.client import GitHubClient, GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow
from mykronos.surface_match import SelectorError, normalize_selectors

logger = logging.getLogger(__name__)

MANIFEST_PATH = ".sdlc/threat-model.yaml"

#: Who a sync acts as in the audit log, when no person asked for it.
SYNC_ACTOR = "system:threat-model-sync"

_KEY = r"^[a-z0-9][a-z0-9_.-]{0,127}$"
#: A path inside the repository, as `product_owner._SAFE_PATH` has it: an
#: evidence reference is rendered as a link, so a scheme must never get
#: through. A URL to a policy page is allowed only as https.
_SAFE_REF = re.compile(r"^(?:[A-Za-z0-9_.][A-Za-z0-9_./#:-]*|https://[^\s]+)$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _evidence(value: str) -> str:
    value = value.strip()
    if value and (not _SAFE_REF.match(value) or ".." in value.split("/")):
        raise ValueError("must be a path inside the repository or an https URL")
    return value


class Selectors(_Strict):
    paths: list[str] = Field(default_factory=list)
    images: list[str] = Field(default_factory=list)
    addresses: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _valid(self) -> Selectors:
        try:
            cleaned = normalize_selectors(self.model_dump())
        except SelectorError as exc:
            raise ValueError(str(exc)) from exc
        for key, values in cleaned.items():
            setattr(self, key, values)
        return self


class _Surface(_Strict):
    id: str = Field(pattern=_KEY)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2_000)
    exposure: Literal["internet", "internal", "local", "unknown"] = "unknown"
    evidence_ref: str = Field(default="", max_length=512)
    selectors: Selectors = Field(default_factory=Selectors)

    _ref = field_validator("evidence_ref")(_evidence)


class Asset(_Surface):
    sensitivity: Literal["pii", "financial", "credentials", "source", "public", "unknown"] = (
        "unknown"
    )
    cr: Literal["H", "M", "L"] | None = None
    ir: Literal["H", "M", "L"] | None = None
    ar: Literal["H", "M", "L"] | None = None


class EntryPoint(_Surface):
    pass


class TrustBoundary(_Surface):
    pass


ControlKind = Literal[
    "authentication",
    "authorization",
    "input_validation",
    "output_encoding",
    "secrets_management",
    "logging",
    "rate_limiting",
    "encryption",
    "perimeter_gate",
    "network_segmentation",
    "security_headers",
    "container_hardening",
    "waf",
]
StrideCategory = Literal[
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]


class Control(_Strict):
    id: str = Field(pattern=_KEY)
    kind: ControlKind
    #: Omitted: the kind's first typical category (`controls.TYPICAL_STRIDE`).
    stride: StrideCategory | None = None
    description: str = Field(default="", max_length=2_000)
    #: Required here, unlike the API. A file in the repository can always name
    #: the file, route or test it is talking about; a manifest control with no
    #: evidence is a sentence, not a declaration.
    evidence_ref: str = Field(min_length=1, max_length=512)
    #: The `id` of a surface in this file.
    applies_to: str | None = Field(default=None, pattern=_KEY)
    #: When a person last re-read this and found it true. Becomes the
    #: control's `last_verified_at`; omitted, the time the sync first saw this
    #: version of the control. Re-confirming is editing this line.
    reviewed_at: date | None = None

    _ref = field_validator("evidence_ref")(_evidence)


class ThreatModelManifest(_Strict):
    """`.sdlc/threat-model.yaml`, version 1 (spec 28 §8)."""

    version: Literal[1]
    assets: list[Asset] = Field(default_factory=list, max_length=200)
    entry_points: list[EntryPoint] = Field(default_factory=list, max_length=200)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list, max_length=200)
    controls: list[Control] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def _references(self) -> ThreatModelManifest:
        seen: set[str] = set()
        surface_ids: set[str] = set()
        for group in (self.assets, self.entry_points, self.trust_boundaries):
            for item in group:
                if item.id in seen:
                    raise ValueError(f"id {item.id!r} is used twice")
                seen.add(item.id)
                surface_ids.add(item.id)
        for control in self.controls:
            if control.id in seen:
                raise ValueError(f"id {control.id!r} is used twice")
            seen.add(control.id)
            if control.applies_to is not None and control.applies_to not in surface_ids:
                raise ValueError(
                    f"control {control.id!r} applies_to {control.applies_to!r}, "
                    "which is not an asset, entry point or trust boundary in this file"
                )
        return self

    def surfaces(self) -> list[tuple[str, _Surface]]:
        return [
            *(("asset", a) for a in self.assets),
            *(("entry_point", e) for e in self.entry_points),
            *(("trust_boundary", t) for t in self.trust_boundaries),
        ]


ManifestStateName = Literal["valid", "invalid", "absent", "unreadable"]


@dataclass
class ManifestState:
    """What the default branch says, including that it says nothing."""

    state: ManifestStateName
    manifest: ThreatModelManifest | None = None
    error: str | None = None


def _describe(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(part) for part in error.get("loc", ())) or "(top level)"
        message = str(error.get("msg", "invalid"))
        if error.get("type") == "extra_forbidden":
            message = "unknown key"
        parts.append(f"{location}: {message}")
    more = len(exc.errors()) - 5
    if more > 0:
        parts.append(f"and {more} more")
    return "; ".join(parts)


def parse_manifest(text: str | None) -> ManifestState:
    """Parse a manifest, or report exactly why it cannot be used."""
    if text is None:
        return ManifestState(state="absent")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark is not None else ""
        return ManifestState(state="invalid", error=f"Not valid YAML{where}.")
    if not isinstance(document, dict):
        return ManifestState(state="invalid", error="The manifest must be a YAML mapping.")
    try:
        return ManifestState(
            state="valid", manifest=ThreatModelManifest.model_validate(document)
        )
    except ValidationError as exc:
        return ManifestState(state="invalid", error=_describe(exc))


# --------------------------------------------------------------------------
# Sync
# --------------------------------------------------------------------------


@dataclass
class Counts:
    added: int = 0
    updated: int = 0
    removed: int = 0
    unchanged: int = 0


@dataclass
class SyncReport:
    repo_full_name: str
    state: ManifestStateName
    error: str | None = None
    #: False when the sync deliberately changed nothing (invalid, unreadable).
    applied: bool = False
    surfaces: Counts = field(default_factory=Counts)
    controls: Counts = field(default_factory=Counts)

    def summary(self) -> str:
        if not self.applied:
            return f"{self.repo_full_name}: {self.state} ({self.error or 'nothing applied'})"
        s, c = self.surfaces, self.controls
        return (
            f"{self.repo_full_name}: surfaces +{s.added} ~{s.updated} -{s.removed}, "
            f"controls +{c.added} ~{c.updated} -{c.removed}"
        )


def apply(
    session: Session,
    repo_full_name: str,
    state: ManifestState,
    *,
    now: datetime | None = None,
) -> SyncReport:
    """Make the manifest's rows match the file. Touches only rows with
    `declared_by == manifest` for this repository."""
    report = SyncReport(repo_full_name=repo_full_name, state=state.state, error=state.error)
    if state.state in ("invalid", "unreadable"):
        return report
    report.applied = True
    stamp = now or utcnow()
    manifest = state.manifest if state.state == "valid" else None

    existing_surfaces = {
        row.manifest_key: row
        for row in session.scalars(
            select(RepoSurface).where(
                RepoSurface.repo_full_name == repo_full_name,
                RepoSurface.declared_by == surfaces.MANIFEST_ACTOR,
            )
        )
    }
    existing_controls = {
        row.manifest_key: row
        for row in session.scalars(
            select(RepoControl).where(
                RepoControl.repo_full_name == repo_full_name,
                RepoControl.declared_by == surfaces.MANIFEST_ACTOR,
            )
        )
    }

    surface_ids: dict[str, str] = {}
    wanted_surfaces: set[str] = set()
    for kind, item in manifest.surfaces() if manifest else []:
        wanted_surfaces.add(item.id)
        values = surfaces.validate(
            kind=kind,
            name=item.name,
            exposure=item.exposure,
            sensitivity=getattr(item, "sensitivity", "unknown"),
            selectors=item.selectors.model_dump(),
            cr=getattr(item, "cr", None),
            ir=getattr(item, "ir", None),
            ar=getattr(item, "ar", None),
        )
        values["description"] = item.description.strip()
        values["evidence_ref"] = item.evidence_ref.strip()
        row = existing_surfaces.get(item.id)
        if row is None:
            row = RepoSurface(
                repo_full_name=repo_full_name,
                declared_by=surfaces.MANIFEST_ACTOR,
                manifest_key=item.id,
                declared_at=stamp,
                **values,
            )
            session.add(row)
            session.flush()
            report.surfaces.added += 1
        elif _assign(row, values):
            report.surfaces.updated += 1
        else:
            report.surfaces.unchanged += 1
        surface_ids[item.id] = row.id

    for key, row in existing_surfaces.items():
        if key not in wanted_surfaces:
            surfaces.remove(session, repo_full_name, row.id, by_manifest=True)
            report.surfaces.removed += 1
    session.flush()

    wanted_controls: set[str] = set()
    for declared in manifest.controls if manifest else []:
        wanted_controls.add(declared.id)
        stride = declared.stride or controls.TYPICAL_STRIDE[declared.kind][0]
        control_values: dict[str, Any] = {
            "stride": stride,
            "kind": declared.kind,
            "description": declared.description.strip(),
            "evidence_ref": declared.evidence_ref.strip(),
            "verified_by_capability": controls.CONTRADICTED_BY.get(declared.kind, ""),
            "applies_to_surface_id": surface_ids.get(declared.applies_to or ""),
        }
        reviewed = (
            datetime.combine(declared.reviewed_at, time.min) if declared.reviewed_at else None
        )
        control = existing_controls.get(declared.id)
        if control is None:
            session.add(
                RepoControl(
                    repo_full_name=repo_full_name,
                    declared_by=surfaces.MANIFEST_ACTOR,
                    manifest_key=declared.id,
                    declared_at=stamp,
                    last_verified_at=reviewed or stamp,
                    **control_values,
                )
            )
            report.controls.added += 1
        elif _assign(control, control_values):
            # A changed declaration is a fresh assertion; an unchanged one
            # re-read every six hours is not, or nothing would ever go stale.
            control.last_verified_at = reviewed or stamp
            report.controls.updated += 1
        elif reviewed is not None and control.last_verified_at != reviewed:
            control.last_verified_at = reviewed
            report.controls.updated += 1
        else:
            report.controls.unchanged += 1

    for key, stale in existing_controls.items():
        if key not in wanted_controls:
            session.delete(stale)
            report.controls.removed += 1
    session.flush()
    return report


def _assign(row: Any, values: dict[str, Any]) -> bool:
    changed = False
    for name, value in values.items():
        if getattr(row, name) != value:
            setattr(row, name, value)
            changed = True
    return changed


async def read(github: GitHubClient, repo_full_name: str, branch: str) -> ManifestState:
    """Fetch and parse the default branch's manifest, as `process.yaml` is."""
    try:
        text = await github.get_file(repo_full_name, MANIFEST_PATH, branch)
    except (GitHubError, httpx2.HTTPError) as exc:
        logger.warning(
            "Could not read %s from %s: %s",
            MANIFEST_PATH,
            scrub(repo_full_name),
            scrub(str(exc)),
        )
        return ManifestState(
            state="unreadable", error=f"{MANIFEST_PATH} could not be read from GitHub."
        )
    return parse_manifest(text)


async def sync_repo(
    db: Database,
    github: GitHubClient,
    repo_full_name: str,
    branch: str,
    *,
    actor: str = SYNC_ACTOR,
) -> SyncReport:
    """Read, apply, and audit one repository's manifest."""
    state = await read(github, repo_full_name, branch)
    with db.session() as session:
        report = apply(session, repo_full_name, state)
        changed = report.applied and any(
            c.added or c.updated or c.removed for c in (report.surfaces, report.controls)
        )
        # Audited when something changed, or whenever a person asked; the
        # job's re-read that changed nothing every six hours is not an event.
        if changed or actor != SYNC_ACTOR:
            db.audit(
                session,
                actor=actor,
                action="threat_model.sync",
                entity_type="repo",
                entity_id=repo_full_name,
                repo_full_name=repo_full_name,
                state=state.state,
                error=state.error,
                surfaces_added=report.surfaces.added,
                surfaces_updated=report.surfaces.updated,
                surfaces_removed=report.surfaces.removed,
                controls_added=report.controls.added,
                controls_updated=report.controls.updated,
                controls_removed=report.controls.removed,
            )
    return report


@dataclass
class SweepResult:
    reports: list[SyncReport] = field(default_factory=list)

    def summary(self) -> str:
        applied = [r for r in self.reports if r.applied]
        broken = [r for r in self.reports if r.state == "invalid"]
        unreadable = [r for r in self.reports if r.state == "unreadable"]
        return (
            f"{len(applied)} synced, {len(broken)} invalid, {len(unreadable)} unreadable"
            + (f"; invalid: {', '.join(r.repo_full_name for r in broken)}" if broken else "")
        )


async def sweep(db: Database, factory: GitHubClientFactory) -> SweepResult:
    """Sync every active onboarded repository. One failing never ends it."""
    result = SweepResult()
    with db.session() as session:
        # `int | None` although the column is NOT NULL today: the guard below
        # must survive a nullable column, a fixture or a half-onboarded row.
        repos: list[tuple[str, str, int | None]] = [
            (r.github_repo_full_name, r.default_branch or "main", r.github_installation_id)
            for r in session.scalars(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            )
        ]
    for name, branch, installation in repos:
        if installation is None:
            # Never `for_installation(None)`: no installation, nothing to read with.
            result.reports.append(
                SyncReport(name, "unreadable", "No GitHub installation to read the manifest with.")
            )
            continue
        result.reports.append(
            await sync_repo(db, factory.for_installation(installation), name, branch)
        )
    return result
