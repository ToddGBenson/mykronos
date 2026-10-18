"""What this repository *is*, so the threat model can say what is at stake.

`controls.py` closed one quarter of a threat model: what stops the things the
tab lists. This closes the other three — assets, entry points, trust
boundaries — and the argument is the same one step earlier.

A tab built only from findings can say what was found and never what is at
risk. "Twelve mediums in the payments service" and "twelve mediums in the
internal changelog renderer" render identically today, and they are not the
same problem. Severity is a property of a finding; consequence is a property
of the thing the finding is in, and nothing in the platform held the second.

**Declared, never verified.** The same rule controls follow, and it is worth
restating rather than assuming: nothing here can confirm that a database holds
customer records or that a port is reachable from the internet. A row is a
person asserting something. That is a weaker and clearer claim than a machine
implying it, and it is useful the day somebody types it — which is the whole
reason this is admin-authored rather than waiting on the entry-point inventory
spec 23 §2 will eventually build.

**`unknown` is the default and a real answer.** A platform that guessed
`internal` for exposure would be understating risk by default, and the wrong
direction to be wrong in is the one that reads as reassurance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from mykronos.db.models import PublicEndpoint, RepoControl, RepoSurface
from mykronos.surface_match import SelectorError, normalize_selectors, validate_requirement

#: `declared_by` on every row `.sdlc/threat-model.yaml` declared (TheHub
#: #60825, D4). Such a row is read-only through the API and the UI: the file
#: is the source of truth, it changes by pull request, and an edit made here
#: would be silently undone by the next sync.
MANIFEST_ACTOR = "manifest"

#: The three parts of a threat model this platform did not hold. Mitigations
#: are `controls.py`; together the four are the whole model.
SURFACE_KINDS = ("asset", "entry_point", "trust_boundary")

#: How reachable something is. The accepted vocabulary, in the order a person
#: would read it.
EXPOSURES = ("internet", "internal", "local", "unknown")

#: ...and the order things are *shown* in, which is not the same list. Reading
#: order puts `unknown` last, where it renders as the mildest thing on the
#: page; it is not mild. An unclassified entry point is an open question about
#: whether the internet can reach it, and it belongs directly under the ones
#: somebody has already confirmed it can.
EXPOSURE_ORDER = ("internet", "unknown", "internal", "local")

#: What is at stake, for an asset. `unknown` again rather than a default that
#: reads as "nothing important here".
SENSITIVITIES = ("pii", "financial", "credentials", "source", "public", "unknown")

#: What could contradict a claim about exposure, by the claim being made.
#: The same move `RepoControl.verified_by_capability` makes, and worth holding
#: as structure rather than prose for the same reason.
#:
#: **This named `dast` for all three and dast can contradict none of them.**
#: `risk_profile_builder`'s docstring already explains why: a DAST lane
#: commonly runs inside CI against an ephemeral stack — which is exactly what
#: this platform's own lane does — so a successful scan proves an HTTP surface
#: *exists*, not that anybody outside can reach it. Wiring the old value up as
#: written would have manufactured a contradiction against every surface in
#: this estate declared `internal`, which is most of them.
#:
#: What can actually do the job:
#:
#: * `network` — a port that answers from **outside** is not `internal` and
#:   not `local`: a `port_published` ControlObservation from the `internet`
#:   vantage (the exposure sweep) contradicts both, and one from the `lan`
#:   vantage (`mykronos.lan_scan`) contradicts `local` only - `internal`
#:   *means* reachable on the LAN.
#: * `published_ingress` — a reverse proxy or tunnel config naming the port is
#:   a *statement* that it is published, not an inference. The host collector
#:   (`deploy/concourse/Publish-ControlObservations.ps1`) records each
#:   cloudflared rule as an `ingress_published` observation. TheHub declares
#:   `Demo backend (tcp/8002)` as `internal` while `~/.cloudflared/config.yml`
#:   publishes that exact port (#348).
#:
#: Read by `control_observations.contradictions` (TheHub #60826), which takes
#: only fresh (<= 14 days) `pass` observations and matches them to a surface
#: by its `selectors`, falling back to the surface's text when it has none.
#:
#: `internet` has no key, deliberately. Unreachability is not observable: a
#: scan that fails to reach something has not shown the internet cannot, and
#: an entry here would invite exactly that inference.
CONTRADICTED_BY = {
    "internal": ("network", "published_ingress"),
    "local": ("network", "published_ingress"),
}


class SurfaceError(ValueError):
    """A declaration the register will not accept."""


class DeclaredInManifestError(ValueError):
    """The row belongs to `.sdlc/threat-model.yaml` and changes only there."""

    def __init__(self, what: str) -> None:
        super().__init__(
            f"This {what} is declared in .sdlc/threat-model.yaml. Change it there, "
            "by pull request; an edit here would be undone by the next sync."
        )


def declared_via(row: Any) -> Literal["api", "manifest"]:
    """`manifest` or `api`: who owns the row."""
    return "manifest" if getattr(row, "declared_by", "") == MANIFEST_ACTOR else "api"


def validate(
    *,
    kind: str,
    name: str,
    exposure: str,
    sensitivity: str,
    selectors: dict[str, Any] | None,
    cr: str | None,
    ir: str | None,
    ar: str | None,
) -> dict[str, Any]:
    """Every rule a declaration meets, API or manifest. Returns the cleaned
    values; raises `SurfaceError` with a sentence a person can act on."""
    if kind not in SURFACE_KINDS:
        raise SurfaceError(
            f"{kind!r} is not part of a threat model. Expected one of: "
            f"{', '.join(SURFACE_KINDS)}."
        )
    if exposure not in EXPOSURES:
        raise SurfaceError(
            f"{exposure!r} is not an exposure. Expected one of: {', '.join(EXPOSURES)}."
        )
    if sensitivity not in SENSITIVITIES:
        raise SurfaceError(
            f"{sensitivity!r} is not a sensitivity. Expected one of: "
            f"{', '.join(SENSITIVITIES)}."
        )
    if not name.strip():
        raise SurfaceError("A surface needs a name. An unnamed asset cannot be reviewed.")
    try:
        cleaned_selectors = normalize_selectors(selectors)
        levels = {
            metric: validate_requirement(value, metric)
            for metric, value in (("cr", cr), ("ir", ir), ("ar", ar))
        }
    except SelectorError as exc:
        raise SurfaceError(str(exc)) from exc
    # Security Requirements are a property of what is held. On an entry point
    # or a boundary they would be a number nobody can act on, so they are
    # refused rather than silently dropped: the person sending one believes
    # it means something.
    if kind != "asset" and any(levels.values()):
        raise SurfaceError(
            "CR/IR/AR overrides belong to an asset — what is held — not to "
            f"{'an entry point' if kind == 'entry_point' else 'a trust boundary'}."
        )
    # Sensitivity is a property of a thing that holds something. An entry point
    # is a way in; asking how sensitive a way in is produces an answer nobody
    # can act on, so it is not stored rather than stored as a guess.
    if kind != "asset":
        sensitivity = "unknown"
    return {
        "kind": kind,
        "name": name.strip(),
        "exposure": exposure,
        "sensitivity": sensitivity,
        "selectors": cleaned_selectors,
        **levels,
    }


@dataclass
class SurfaceSummary:
    """What is known about a repository, and what is not.

    `unknowns` is reported rather than derived at the call site because it is
    the number that says how much of the model is actually a model. A threat
    model with nine assets and nine unknown sensitivities is an inventory.
    """

    assets: list[RepoSurface] = field(default_factory=list)
    entry_points: list[RepoSurface] = field(default_factory=list)
    trust_boundaries: list[RepoSurface] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.assets) + len(self.entry_points) + len(self.trust_boundaries)

    @property
    def internet_facing(self) -> int:
        return sum(
            1
            for surface in self.assets + self.entry_points
            if surface.exposure == "internet"
        )

    @property
    def unknowns(self) -> int:
        """Declared rows still carrying an unanswered question."""
        unknown_exposure = sum(
            1
            for surface in self.assets + self.entry_points + self.trust_boundaries
            if surface.exposure == "unknown"
        )
        unknown_sensitivity = sum(
            1 for surface in self.assets if surface.sensitivity == "unknown"
        )
        return unknown_exposure + unknown_sensitivity

    @property
    def complete(self) -> bool:
        """Whether this is a threat model or the beginning of one.

        All three parts present. A repository with entry points and no assets
        describes how somebody gets in and never what they reach, which is
        half a sentence.
        """
        return bool(self.assets and self.entry_points and self.trust_boundaries)


def declare(
    session: Session,
    repo_full_name: str,
    *,
    kind: str,
    name: str,
    description: str = "",
    exposure: str = "unknown",
    sensitivity: str = "unknown",
    evidence_ref: str = "",
    declared_by: str = "",
    selectors: dict[str, Any] | None = None,
    cr: str | None = None,
    ir: str | None = None,
    ar: str | None = None,
    manifest_key: str | None = None,
) -> RepoSurface:
    """Record an asset, entry point or trust boundary.

    Validated against the vocabularies above rather than accepting free text:
    a register where one person writes `internet` and another writes
    `public-facing` cannot be queried, and an inventory nobody can query is a
    wiki page with a database bill.
    """
    values = validate(
        kind=kind,
        name=name,
        exposure=exposure,
        sensitivity=sensitivity,
        selectors=selectors,
        cr=cr,
        ir=ir,
        ar=ar,
    )
    surface = RepoSurface(
        repo_full_name=repo_full_name,
        description=description.strip(),
        evidence_ref=evidence_ref.strip(),
        declared_by=declared_by,
        manifest_key=manifest_key,
        **values,
    )
    session.add(surface)
    session.flush()
    return surface


def remove(
    session: Session, repo_full_name: str, surface_id: str, *, by_manifest: bool = False
) -> bool:
    """Delete one declaration. Scoped by repository so an id from elsewhere
    cannot reach across.

    A manifest row is refused (`DeclaredInManifestError`) unless the manifest sync
    itself is removing it. Anything that pointed at the surface — a control's
    `applies_to_surface_id`, a public endpoint's `surface_id` — is nulled, so
    the control falls back to repository scope instead of naming a surface
    that no longer exists.
    """
    surface = session.get(RepoSurface, surface_id)
    if surface is None or surface.repo_full_name != repo_full_name:
        return False
    if surface.declared_by == MANIFEST_ACTOR and not by_manifest:
        raise DeclaredInManifestError("surface")
    detach(session, surface_id)
    session.delete(surface)
    return True


def detach(session: Session, surface_id: str) -> None:
    """Null every nullable reference to a surface about to go."""
    session.execute(
        update(RepoControl)
        .where(RepoControl.applies_to_surface_id == surface_id)
        .values(applies_to_surface_id=None)
    )
    session.execute(
        update(PublicEndpoint)
        .where(PublicEndpoint.surface_id == surface_id)
        .values(surface_id=None)
    )


def for_repo(session: Session, repo_full_name: str) -> SurfaceSummary:
    """Everything declared about one repository, split by part."""
    rows = (
        session.execute(
            select(RepoSurface)
            .where(RepoSurface.repo_full_name == repo_full_name)
            .order_by(RepoSurface.kind, RepoSurface.name)
        )
        .scalars()
        .all()
    )

    summary = SurfaceSummary()
    for row in rows:
        if row.kind == "asset":
            summary.assets.append(row)
        elif row.kind == "entry_point":
            summary.entry_points.append(row)
        else:
            summary.trust_boundaries.append(row)

    # Worst-first inside each part, by `EXPOSURE_ORDER` rather than the
    # vocabulary's reading order — see the comment there.
    for group in (summary.assets, summary.entry_points, summary.trust_boundaries):
        group.sort(key=lambda s: (EXPOSURE_ORDER.index(s.exposure), s.name))
    return summary
