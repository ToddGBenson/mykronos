"""How much of what this platform scanned went through a pull request (#302).

`aegis` is an enabled capability on `ToddGBenson/TheHub` and has produced zero
insider-risk signals across the repository's entire history, while `mykronos`
has produced hundreds. The obvious readings — a dead lane, a capability nobody
wired up — are both wrong. The `insider` job resolves the pull request for the
commit it is scanning, finds none, prints a correct explanation and exits
without recording anything, because scoring a commit with no pull request would
make the change nobody reviewed read as the safest change in the repository.

That refusal is right and this module does not touch it. What it adds is the
missing half: a number that says *why* the capability is silent, so "enabled
and produced nothing" stops being indistinguishable from "enabled and broken".

Three properties hold this together.

**Unreadable is not unreviewed.** A commit GitHub would not answer for gets no
row and leaves the sample, rather than counting toward the unreviewed share. A
review-coverage measure that improves when the API stops answering is worse
than none — this estate's recurring defect is a lane that reports success while
measuring nothing, and the shape it takes here would be a repository whose
review coverage climbs to 100% the moment a token expires.

**A pull request is forever; its absence is not.** Once a commit resolves to a
pull request that association cannot change, so it is cached and never
re-read. The absence *can* change: a commit pushed straight to `develop` joins
a pull request the day somebody opens `develop` -> `main`. So a recorded
absence is re-resolved after `NEGATIVE_RECHECK_DAYS`, and only the positives
are treated as settled.

**It does not gate anything.** A solo operator pushing to their own branch is a
legitimate way to work, and every repository in this estate reads
`required reviews: 1, enforce_admins: false` because a one-review rule cannot
be satisfied by one person. TheHub's own `oracle-gate` carries the lesson from
D-048: a gate that refuses everything gets switched off or routed around.
Turning this observation into a rule would be that mistake on purpose. It is
reported and nothing else.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import CommitReview, RepoOnboarding
from mykronos.db.session import Database
from mykronos.github.client import GitHubError
from mykronos.github.factory import GitHubClientFactory
from mykronos.lake.catalog import Catalog
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: How many of a repository's most recently scanned commits the share is taken
#: over. Twenty rather than "all of them": the question people ask is how this
#: repository is being worked on *now*, and a denominator that includes a year
#: of history answers a different one, more and more slowly. It is also a
#: sample small enough that one refresh costs twenty GitHub calls at most, and
#: usually far fewer because the resolved ones are cached.
DEFAULT_SAMPLE = 20

#: A recorded absence is re-read after a week. A commit pushed direct to a
#: branch acquires a pull request whenever that branch is later merged through
#: one, so caching "no pull request" forever would freeze the measure at its
#: least flattering reading and slowly stop being true.
NEGATIVE_RECHECK_DAYS = 7

#: Below this share the sentence is not worth saying. A repository where a
#: third of commits skip review has a review-coverage number worth reading on
#: its own; it does not have an *explanation* for a capability producing
#: nothing, because two thirds of its commits were available to score. The
#: threshold is where "some changes are unreviewed" becomes "there is almost
#: nothing here for Aegis to look at".
SILENCE_SHARE_THRESHOLD = 0.5

#: Under this many resolved commits, no share is reported at all. Two of three
#: is 67% and means nothing; it is a repository that has barely been scanned,
#: and printing a percentage for it would give a number the weight of a
#: measurement.
MIN_RESOLVED = 4


@dataclass(frozen=True)
class ReviewCoverage:
    """One repository's review coverage over its most recent scanned commits."""

    repo_full_name: str
    #: Distinct commits taken from `scan_runs`, before any were resolved.
    sampled: int
    via_pull_request: int
    #: Resolved, and GitHub reported no pull request containing them.
    direct: int

    @property
    def resolved(self) -> int:
        return self.via_pull_request + self.direct

    @property
    def unresolved(self) -> int:
        """Sampled commits nobody could get an answer for.

        Kept as its own number rather than folded into `direct`. It is the
        difference between "thirteen commits skipped review" and "thirteen
        commits we could not ask about", and those call for opposite actions.
        """
        return max(self.sampled - self.resolved, 0)

    @property
    def unreviewed_share(self) -> float | None:
        """Fraction of *resolved* commits that reached the branch with no PR.

        `None` under `MIN_RESOLVED`, which is how a barely-scanned repository
        says "not enough to measure" rather than emitting a percentage derived
        from three data points.
        """
        if self.resolved < MIN_RESOLVED:
            return None
        return self.direct / self.resolved

    def summary(self) -> str:
        share = self.unreviewed_share
        if share is None:
            return (
                f"{self.resolved} of the last {self.sampled} scanned commits "
                "could be resolved to a pull request or to none — too few to "
                "report a share."
            )
        return (
            f"{self.direct} of the last {self.resolved} scanned commits reached "
            f"this branch without a pull request ({share:.0%})."
        )


def scanned_commits(
    catalog: Catalog, repo_full_name: str, *, limit: int = DEFAULT_SAMPLE
) -> list[str]:
    """The repository's most recently scanned distinct commits, newest first.

    Deliberately read from `scan_runs` rather than from the repository's git
    history. The question is about the commits this platform was pointed at —
    the ones a capability had an opportunity to assess — and a commit nothing
    ever scanned is not evidence about a capability's silence.
    """
    rows = catalog.query(
        """
        SELECT commit_sha, max(coalesce(completed_at, started_at)) AS seen
        FROM scan_runs
        WHERE repo_full_name = ?
          AND commit_sha IS NOT NULL
          AND commit_sha <> ''
        GROUP BY 1
        ORDER BY seen DESC
        LIMIT ?
        """,
        [repo_full_name, int(limit)],
    )
    return [str(sha) for sha, _ in rows]


def coverage(
    repo_full_name: str,
    associations: Mapping[str, int | None],
    *,
    sampled: int,
) -> ReviewCoverage:
    """Count one repository's sample. Pure, so the arithmetic is testable alone.

    `associations` maps a *resolved* commit to its pull request number, or to
    `None` for "GitHub answered, and there is none". `sampled` is how many
    commits were taken from the lake before any were resolved, and is passed
    separately rather than inferred from the mapping — the gap between the two
    is the unreadable commits, and inferring it away is how they would come to
    be counted as unreviewed.
    """
    via = sum(1 for value in associations.values() if value is not None)
    direct = sum(1 for value in associations.values() if value is None)
    return ReviewCoverage(
        repo_full_name=repo_full_name,
        sampled=max(sampled, via + direct),
        via_pull_request=via,
        direct=direct,
    )


def _records(
    session: Session, repo_full_name: str, shas: Iterable[str]
) -> dict[str, CommitReview]:
    wanted = list(shas)
    if not wanted:
        return {}
    rows = session.execute(
        select(CommitReview)
        .where(CommitReview.repo_full_name == repo_full_name)
        .where(CommitReview.commit_sha.in_(wanted))
    ).scalars()
    return {row.commit_sha: row for row in rows}


def _is_stale(record: CommitReview, *, now: datetime) -> bool:
    """Whether a stored answer should be asked again.

    A resolved pull request never is: GitHub cannot un-associate a commit from
    the pull request that carried it. Only the absence expires.
    """
    if record.pr_number is not None:
        return False
    return record.resolved_at < now - timedelta(days=NEGATIVE_RECHECK_DAYS)


def stored(
    session: Session,
    catalog: Catalog,
    repo_full_name: str,
    *,
    sample: int = DEFAULT_SAMPLE,
) -> ReviewCoverage:
    """Coverage from what has already been resolved. No network.

    This is what the dashboard reads. Rendering a portfolio must not depend on
    GitHub answering: a page that makes one API call per commit per repository
    is a page that times out, and one that fails closed on a rate limit would
    report every repository as unmeasured at exactly the moment the estate is
    busiest. The refresher fills the table on a timer; this reads it.
    """
    shas = scanned_commits(catalog, repo_full_name, limit=sample)
    records = _records(session, repo_full_name, shas)
    associations = {
        sha: records[sha].pr_number for sha in shas if sha in records
    }
    # `sampled` counts what was scanned, not what resolved, so a repository
    # whose commits have never been looked up reads as 0 resolved out of N
    # rather than as fully reviewed.
    return coverage(repo_full_name, associations, sampled=len(shas))


def silence_reason(measure: ReviewCoverage) -> str | None:
    """Why a pull-request-scoped capability has nothing to report here.

    `None` whenever the sample does not support the claim — too few resolved
    commits, or a share low enough that the capability's silence needs a
    different explanation. Returning a sentence anyway would be the failure
    this whole module exists to correct, one level up: an explanation that is
    always available is one nobody can act on.
    """
    share = measure.unreviewed_share
    if share is None or share < SILENCE_SHARE_THRESHOLD:
        return None
    return (
        f"{measure.summary()} This capability assesses pull requests, so most "
        "of what reaches this branch is never presented to it."
    )


@dataclass
class RefreshResult:
    resolved: int = 0
    #: Sampled commits GitHub would not answer for. Reported rather than
    #: dropped: a sweep that resolved nothing and one that had nothing to
    #: resolve produce identical coverage, and only one of them is a fault.
    unreadable: int = 0
    repos: int = 0
    by_repo: dict[str, ReviewCoverage] = field(default_factory=dict)

    def summary(self) -> str:
        parts = [
            f"{self.repos} repo(s)",
            f"{self.resolved} commit(s) resolved",
            f"{self.unreadable} unreadable",
        ]
        for measure in sorted(self.by_repo.values(), key=lambda m: m.repo_full_name):
            share = measure.unreviewed_share
            if share is not None:
                parts.append(f"{measure.repo_full_name} {share:.0%} direct")
        return "; ".join(parts)


async def refresh(
    db: Database,
    catalog: Catalog,
    factory: GitHubClientFactory,
    *,
    sample: int = DEFAULT_SAMPLE,
    now: datetime | None = None,
) -> RefreshResult:
    """Resolve any unresolved commits in every active repository's sample.

    Safe to run twice: a commit already resolved to a pull request is not
    asked about again, and one resolved to no pull request is not asked again
    inside `NEGATIVE_RECHECK_DAYS`. A steady-state run therefore costs one
    call per newly scanned commit, which is a handful a day.
    """
    moment = now or utcnow()
    result = RefreshResult()

    with db.session() as session:
        repos = [
            (row.github_repo_full_name, row.github_installation_id)
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status == "active")
            ).scalars()
        ]

    for repo_full_name, installation_id in repos:
        result.repos += 1
        shas = scanned_commits(catalog, repo_full_name, limit=sample)
        if not shas:
            continue

        with db.session() as session:
            records = _records(session, repo_full_name, shas)
            to_resolve = [
                sha
                for sha in shas
                if sha not in records or _is_stale(records[sha], now=moment)
            ]

        github = factory.for_installation(installation_id)
        resolved: dict[str, int | None] = {}
        for sha in to_resolve:
            try:
                numbers = await github.pull_requests_for_commit(repo_full_name, sha)
            except GitHubError as exc:
                # One commit failing must not end the sweep, and must not be
                # recorded as unreviewed.
                numbers = None
                logger.debug(
                    "Could not resolve %s@%s: %s",
                    scrub(repo_full_name),
                    sha[:8],
                    scrub(str(exc)),
                )
            if numbers is None:
                result.unreadable += 1
                continue
            # Lowest number: the pull request that introduced the commit, not
            # a later one that happened to sweep it along. Stable across runs,
            # which a "first returned" would not be.
            resolved[sha] = min(numbers) if numbers else None
            result.resolved += 1

        with db.session() as session:
            records = _records(session, repo_full_name, shas)
            for sha, number in resolved.items():
                record = records.get(sha)
                if record is None:
                    record = CommitReview(
                        repo_full_name=repo_full_name, commit_sha=sha
                    )
                    session.add(record)
                    records[sha] = record
                record.pr_number = number
                record.resolved_at = moment
            session.commit()
            result.by_repo[repo_full_name] = stored(
                session, catalog, repo_full_name, sample=sample
            )

    return result
