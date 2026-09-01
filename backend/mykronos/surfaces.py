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

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import RepoSurface

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

#: Which capability could contradict a claim about exposure. A surface
#: declared `internal` that DAST reached from outside is a contradiction the
#: platform can detect — the same move `RepoControl.verified_by_capability`
#: makes, and the reason this is worth recording as structure rather than
#: prose.
CONTRADICTED_BY = {"internet": "dast", "internal": "dast", "local": "dast"}


class SurfaceError(ValueError):
    """A declaration the register will not accept."""


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
) -> RepoSurface:
    """Record an asset, entry point or trust boundary.

    Validated against the vocabularies above rather than accepting free text:
    a register where one person writes `internet` and another writes
    `public-facing` cannot be queried, and an inventory nobody can query is a
    wiki page with a database bill.
    """
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

    # Sensitivity is a property of a thing that holds something. An entry point
    # is a way in; asking how sensitive a way in is produces an answer nobody
    # can act on, so it is not stored rather than stored as a guess.
    if kind != "asset":
        sensitivity = "unknown"

    surface = RepoSurface(
        repo_full_name=repo_full_name,
        kind=kind,
        name=name.strip(),
        description=description.strip(),
        exposure=exposure,
        sensitivity=sensitivity,
        evidence_ref=evidence_ref.strip(),
        declared_by=declared_by,
    )
    session.add(surface)
    session.flush()
    return surface


def remove(session: Session, repo_full_name: str, surface_id: str) -> bool:
    """Delete one declaration. Scoped by repository so an id from elsewhere
    cannot reach across."""
    surface = session.get(RepoSurface, surface_id)
    if surface is None or surface.repo_full_name != repo_full_name:
        return False
    session.delete(surface)
    return True


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
