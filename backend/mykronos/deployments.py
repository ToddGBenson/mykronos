"""What revision is actually running, next to the one that was scanned (#361).

THE GAP THIS CLOSES. On 2026-09-13 the backend serving this platform was an
image built eight days earlier. Twenty-six merged PRs were not running, and
every indicator the platform publishes was green throughout:
`repos_with_stale_scans: 0`, `overdue_findings: 0`. Both measure how recently a
repository was *scanned*. Nothing measured what was *deployed*, so nothing could
notice that the two had diverged.

That divergence is not a reporting nicety. Every finding this platform records
is a claim about a repository, and the useful version of that claim is about
the artifact serving traffic. When the deployed revision and the scanned
revision differ, an open finding may already be fixed in production and a closed
one may still be running -- and the platform presents both with equal
confidence. The estate has hit the "scanned artifact is not the running
artifact" class three times already (a `perl-base` package absent from the
running image, a `next` advisory against a version nobody deployed, and this).

WHAT IS COMPARED, AND WHY IT IS NOT "COMMITS BEHIND MAIN".

The comparison here is *deployed revision vs most recently scanned revision*,
which needs no GitHub call and is the claim the platform can actually stand
behind: "the artifact I am reporting on is the artifact you are running." How
far the deployment sits behind the default branch is a different and also
useful question, answered by the GitHub compare API, and deliberately left to
follow-up work rather than approximated here. A proxy presented as the real
measurement is the defect class this module exists because of.

THE PROBE CONTRACT is deliberately narrow: a GET returning JSON with a string
at `build.sha`. Both applications already serve exactly that shape --
mykronos at `/healthz` and TheHub at `/health`, unauthenticated, because the
question "is the fix running yet?" has to be answerable from outside the
process being asked. A response in any other shape is reported `unparsed`
rather than pattern-matched for something commit-like: guessing which field
holds the revision is how a confident wrong answer gets made, and a confident
wrong answer about what is deployed is the thing being fixed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx2
from sqlalchemy import select

from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: A probe answers in well under a second when healthy. The budget is for a
#: host that accepts the connection and then stalls, which is the failure that
#: would otherwise hold the whole sweep open.
DEFAULT_TIMEOUT_SECONDS = 10.0

#: Every state the probe can be in. `not_configured` is first because it is the
#: common one and is not a fault: a repository with no deployment this platform
#: can reach is a normal thing to be, and must not be rendered as a failure.
NOT_CONFIGURED = "not_configured"
OK = "ok"
UNREACHABLE = "unreachable"
UNPARSED = "unparsed"


@dataclass
class DeploymentState:
    """One repository's answer to "what is running?"."""

    repo_full_name: str
    status: str = NOT_CONFIGURED
    revision: str | None = None
    observed_at: datetime | None = None
    #: The newest commit any capability has scanned for this repo.
    scanned_revision: str | None = None
    detail: str = ""

    @property
    def matches_scan(self) -> bool | None:
        """True, False, or None for "cannot say" — never a defaulted False.

        None is the honest answer whenever either side is unknown, and it is
        the answer for most repositories. Collapsing it to False would invent
        a divergence; collapsing it to True would repeat the original defect
        in a new place.
        """
        if not self.revision or not self.scanned_revision:
            return None
        return self.revision.lower().startswith(
            self.scanned_revision.lower()
        ) or self.scanned_revision.lower().startswith(self.revision.lower())


@dataclass
class ProbeSweep:
    """What one pass over every configured probe found."""

    states: list[DeploymentState] = field(default_factory=list)

    @property
    def unknown(self) -> int:
        return sum(1 for s in self.states if s.revision is None)

    @property
    def diverged(self) -> list[DeploymentState]:
        """Repositories running something other than what was scanned.

        This is the list the 2026-09-13 outage would have appeared in, and the
        only number in this module that should ever raise an alert.
        """
        return [s for s in self.states if s.matches_scan is False]


def _extract_revision(payload: Any) -> str | None:
    """Read `build.sha`, and nothing else.

    No fallback to a top-level `sha`, a `version`, or anything commit-shaped
    found elsewhere in the body. The contract is documented and both
    applications meet it; an endpoint that does not is telling us it has not
    been taught to answer this question yet, which is worth knowing.
    """
    if not isinstance(payload, dict):
        return None
    build = payload.get("build")
    if not isinstance(build, dict):
        return None
    revision = build.get("sha")
    if not isinstance(revision, str) or not revision.strip():
        return None
    return revision.strip()


async def probe(
    url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> tuple[str, str | None, str]:
    """Ask one deployment what it is. Returns `(status, revision, detail)`."""
    try:
        async with httpx2.AsyncClient(timeout=timeout) as http:
            response = await http.get(url)
    except Exception as exc:  # noqa: BLE001 — any failure to reach is the answer
        return UNREACHABLE, None, f"{scrub(url)} could not be reached: {scrub(str(exc))}"

    if response.status_code != 200:
        return (
            UNREACHABLE,
            None,
            f"{scrub(url)} answered HTTP {response.status_code}.",
        )

    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 — a non-JSON body is `unparsed`, not a crash
        return UNPARSED, None, f"{scrub(url)} did not return JSON."

    revision = _extract_revision(payload)
    if revision is None:
        return (
            UNPARSED,
            None,
            f"{scrub(url)} returned JSON with no string at `build.sha`.",
        )
    return OK, revision, ""


def latest_scanned_revisions(catalog: Any) -> dict[str, str]:
    """The newest `commit_sha` any capability has scanned, per repository.

    Newest across all capabilities rather than per capability: the question is
    "what code did this platform most recently look at", and a repository whose
    lanes sit on different commits has a separate problem that
    `_capability_scan_state` already reports.
    """
    rows = catalog.query(
        """
        SELECT repo_full_name, commit_sha FROM (
            SELECT repo_full_name, commit_sha,
                   row_number() OVER (
                       PARTITION BY repo_full_name
                       ORDER BY coalesce(completed_at, started_at) DESC
                   ) AS rn
            FROM scan_runs
            WHERE commit_sha IS NOT NULL AND commit_sha <> ''
        ) WHERE rn = 1
        """
    )
    return {str(repo): str(sha) for repo, sha in rows}


async def sweep(
    probes: dict[str, str],
    scanned: dict[str, str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ProbeSweep:
    """Probe every configured deployment and pair it with what was scanned.

    `probes` maps repository full name to probe URL; a repository absent from
    it is reported `not_configured` by the caller rather than omitted, so the
    coverage gap stays visible instead of shrinking the denominator.
    """
    result = ProbeSweep()
    for repo, url in sorted(probes.items()):
        status, revision, detail = await probe(url, timeout=timeout)
        state = DeploymentState(
            repo_full_name=repo,
            status=status,
            revision=revision,
            observed_at=utcnow() if revision else None,
            scanned_revision=scanned.get(repo),
            detail=detail,
        )
        if state.matches_scan is False:
            # The one line in this module worth waking somebody for. Logged at
            # warning rather than info because the state it describes is the
            # one that was invisible for eight days.
            logger.warning(
                "%s is running %s but the newest scan was of %s — every finding "
                "for this repository describes code that is not deployed.",
                scrub(repo),
                scrub(state.revision or "?"),
                scrub(state.scanned_revision or "?"),
            )
        elif status in (UNREACHABLE, UNPARSED):
            logger.info("Deployment probe for %s: %s", scrub(repo), scrub(detail))
        result.states.append(state)
    return result


def probe_targets(db: Any) -> dict[str, str]:
    """Every active repository that has told us where to ask.

    Reads onboardings rather than a config file so the answer moves with the
    estate: a repository offboarded tomorrow stops being probed without anyone
    editing a list, which is the failure mode a static list always eventually
    has.
    """
    from mykronos.db.models import RepoOnboarding

    with db.session() as session:
        rows = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.status == "active")
        ).all()
        return {
            row.github_repo_full_name: row.deployment_probe_url
            for row in rows
            if (row.deployment_probe_url or "").strip()
        }


def record(db: Any, states: list[DeploymentState]) -> int:
    """Persist what the sweep saw. Returns the number of rows updated.

    A failed probe overwrites the status but **not** the last known revision.
    "The deployment was unreachable this minute" is not evidence that it
    stopped running what it was running, and blanking the field would turn a
    network blip into an apparent rollback to unknown.
    """
    from mykronos.db.models import RepoOnboarding

    updated = 0
    with db.session() as session:
        for state in states:
            row = session.scalars(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == state.repo_full_name
                )
            ).first()
            if row is None:
                continue
            row.deployment_probe_status = state.status
            if state.revision:
                row.deployed_revision = state.revision
                row.deployed_revision_at = state.observed_at
            updated += 1
        session.commit()
    return updated


async def run_probe_sweep(
    db: Any, catalog: Any, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> ProbeSweep:
    """The scheduled job: probe, compare against what was scanned, record."""
    targets = probe_targets(db)
    if not targets:
        logger.info(
            "No deployment probes configured; nothing compares the running "
            "artifact to the scanned one."
        )
        return ProbeSweep()
    result = await sweep(targets, latest_scanned_revisions(catalog), timeout=timeout)
    record(db, result.states)
    return result
