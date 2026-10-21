"""The daily briefing's board and pull-request inputs (TheHub #60861, epic #60858).

`briefing_sources` gathers what the lane briefing needs from outside the
lake; this gathers the two things the morning page needs about delivery:

- **TheHub's board**, through the Product Owner tab's `HubClient`
  (`app.state.hub`, `X-Hub-Token`). Never TheHub's database: `dev_stories` is
  the system of record and its API is the contract (D-133).
- **Every open pull request** on the onboarded repositories, through
  `pull_requests.open_pull_requests` (the dashboard's listing and check
  summaries) plus one single-PR read each for GitHub's `mergeable` verdict,
  which the list endpoint does not carry.

**Cached, the way `briefing_sources` caches the workflow_run read.** A
successful read is reused for `BOARD_TTL_SECONDS` / `PULL_REQUESTS_TTL_SECONDS`,
per client object, so reloading the page does not spend the installation's
rate limit or hammer TheHub. A failed read is never cached. When a read fails
and an earlier answer is younger than `STALE_LIMIT_SECONDS`, that answer is
returned marked `stale` with the reason, and the section built from it says
`partial`; with nothing to fall back on the input is `None` and its section
says `unavailable`. Never an empty list that reads as "nothing waiting".

The number of live calls per read is bounded: one listing call per
repository, one checks call per pull request (the dashboard's own cost), and
at most `MAX_DETAIL_READS` single-PR reads, `GITHUB_CONCURRENCY` at a time,
all under `PULL_REQUESTS_TIMEOUT_SECONDS`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import weakref
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Generic, TypeVar

from sqlalchemy import select

from mykronos.db.models import RepoOnboarding
from mykronos.github.client import ChecksSummary, GitHubError
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

T = TypeVar("T")

#: TheHub's buckets (`schemas/dev_story.py` BUCKETS). `done` is read for what
#: reached `deployed` in the window.
BOARD_BUCKETS: tuple[str, ...] = ("icebox", "backlog", "sprint", "done")

BOARD_TTL_SECONDS = 120.0
PULL_REQUESTS_TTL_SECONDS = 300.0
#: How old a cached answer may be and still stand in for a failed read.
STALE_LIMIT_SECONDS = 3600.0

BOARD_TIMEOUT_SECONDS = 15.0
PULL_REQUESTS_TIMEOUT_SECONDS = 25.0
#: Single-PR reads (for `mergeable`) per gather, oldest pull request first.
MAX_DETAIL_READS = 40
GITHUB_CONCURRENCY = 6

HUB_NOT_CONNECTED = (
    "TheHub is not connected: MYKRONOS_HUB_API_URL and MYKRONOS_HUB_API_TOKEN "
    "are not both set."
)
GITHUB_NOT_CONFIGURED = "No GitHub client is configured."


# ---------------------------------------------------------------------------
# Shapes
# ---------------------------------------------------------------------------


@dataclass
class BoardRead:
    #: bucket -> TheHub's stories, as `GET /api/dev/stories` returns them.
    stories: dict[str, list[dict[str, Any]]]
    as_of: datetime
    #: True when this is an earlier answer standing in for a failed read.
    stale: bool = False
    #: Why it is stale. Empty otherwise.
    reason: str = ""

    def open_stories(self) -> list[dict[str, Any]]:
        """Everything not done: what "already on the board" means."""
        return [
            s for bucket in ("icebox", "backlog", "sprint") for s in self.stories.get(bucket, [])
        ]


@dataclass
class OpenPullRequest:
    repo_full_name: str
    number: int
    url: str
    title: str
    draft: bool
    head_branch: str
    #: The branch it merges into. Empty when the single-PR read did not run.
    base_branch: str
    #: The repository's default branch, from the onboarding ledger.
    default_branch: str
    opened_at: datetime | None
    #: None when the checks call failed: a missing column, not "no checks".
    checks: ChecksSummary | None
    mergeable: bool | None = None
    mergeable_state: str = ""
    #: TheHub story ids it names (title, body, branch).
    story_ids: list[int] = field(default_factory=list)
    #: Pull requests in the same repository it says it stacks on.
    depends_on: list[int] = field(default_factory=list)
    #: Whether the single-PR read ran and answered.
    detail_read: bool = False


@dataclass
class PullRequestRead:
    pull_requests: list[OpenPullRequest]
    #: (repo, reason) for repositories GitHub would not list.
    unreachable: list[tuple[str, str]]
    as_of: datetime
    #: Pull requests whose mergeable verdict was not read (cap or error).
    details_unread: int = 0
    stale: bool = False
    reason: str = ""


@dataclass
class DeliveryInputs:
    """What the board and GitHub said. `None` = could not ask, with why."""

    board: BoardRead | None = None
    board_error: str = "TheHub's board was not read."
    pull_requests: PullRequestRead | None = None
    pull_requests_error: str = "GitHub's pull requests were not read."


# ---------------------------------------------------------------------------
# What a pull request says about itself
# ---------------------------------------------------------------------------


#: "TheHub #60848 #60851", "TheHub #60860", "Stories: 60861, 60862".
_HUB_RUN = re.compile(
    r"(?:TheHub|Stories?:)\s*((?:#?\d+(?:\s*(?:,|&|and|/)?\s*))+)", re.IGNORECASE
)
#: A bare `#60861`. Story ids are five digits and up; these repositories'
#: pull-request numbers are not, so a short `#975` is never taken for a story.
_LONG_REF = re.compile(r"#(\d{5,})\b")
#: `feat/daily-briefing-b3-60861`, `...-60861-v2`.
_BRANCH_ID = re.compile(r"(?:^|[-_/])(\d{5,})(?:-v\d+)?$")
#: "stacks on #975", "depends on owner/repo#12", "blocked by #3".
_DEPENDS = re.compile(
    r"(?:stack(?:s|ed)?\s+on|depends\s+on|blocked\s+by|after)\s+(?:[\w.-]+/[\w.-]+)?#(\d+)",
    re.IGNORECASE,
)


def story_refs(*texts: str, branch: str = "") -> list[int]:
    """TheHub story ids a pull request names, in first-seen order."""
    found: list[int] = []
    for text in texts:
        for run in _HUB_RUN.finditer(text or ""):
            found.extend(int(n) for n in re.findall(r"\d+", run.group(1)))
        found.extend(int(n) for n in _LONG_REF.findall(text or ""))
    if match := _BRANCH_ID.search(branch or ""):
        found.append(int(match.group(1)))
    return list(dict.fromkeys(found))


def depends_on(body: str) -> list[int]:
    return list(dict.fromkeys(int(n) for n in _DEPENDS.findall(body or "")))


# ---------------------------------------------------------------------------
# The cache
# ---------------------------------------------------------------------------


@dataclass
class _Entry(Generic[T]):
    stored_at: float
    value: T


class _Cache(Generic[T]):
    """One answer per source object, held weakly so a test app's fake never
    answers for another's. Only successful reads are stored."""

    def __init__(self) -> None:
        self._entries: weakref.WeakKeyDictionary[Any, _Entry[T]] = weakref.WeakKeyDictionary()
        self._unweakable: dict[int, _Entry[T]] = {}

    def _get(self, key: Any) -> _Entry[T] | None:
        try:
            return self._entries.get(key)
        except TypeError:
            return self._unweakable.get(id(key))

    def fresh(self, key: Any, ttl: float, now: float) -> T | None:
        entry = self._get(key)
        return entry.value if entry is not None and now - entry.stored_at < ttl else None

    def fallback(self, key: Any, now: float) -> T | None:
        entry = self._get(key)
        if entry is None or now - entry.stored_at >= STALE_LIMIT_SECONDS:
            return None
        return entry.value

    def put(self, key: Any, value: T, now: float) -> None:
        try:
            self._entries[key] = _Entry(now, value)
        except TypeError:
            self._unweakable[id(key)] = _Entry(now, value)

    def clear(self) -> None:
        self._entries = weakref.WeakKeyDictionary()
        self._unweakable = {}


_board_cache: _Cache[BoardRead] = _Cache()
_pr_cache: _Cache[PullRequestRead] = _Cache()


class NothingListedError(Exception):
    """Every onboarded repository refused its listing. The message is ours."""


def clear_cache() -> None:
    _board_cache.clear()
    _pr_cache.clear()


def _error(exc: BaseException) -> str:
    """A reason that names the failure without echoing text that can carry a
    URL or a token. `HubUnavailableError`'s message is ours and safe."""
    from mykronos.product_owner import HubUnavailableError

    if isinstance(exc, HubUnavailableError):
        return str(exc)
    if isinstance(exc, NothingListedError):
        return str(exc).capitalize()
    if isinstance(exc, TimeoutError):
        return "It did not answer in time."
    return f"{type(exc).__name__} while reading it."


# ---------------------------------------------------------------------------
# The board
# ---------------------------------------------------------------------------


async def _read_board(hub: Any) -> BoardRead:
    lists = await asyncio.gather(*(hub.list_stories(bucket) for bucket in BOARD_BUCKETS))
    return BoardRead(stories=dict(zip(BOARD_BUCKETS, lists, strict=True)), as_of=utcnow())


async def board(hub: Any) -> tuple[BoardRead | None, str]:
    """TheHub's board, cached. (read, why it is None)."""
    if hub is None:
        return None, HUB_NOT_CONNECTED
    now = time.monotonic()
    if (hit := _board_cache.fresh(hub, BOARD_TTL_SECONDS, now)) is not None:
        return hit, ""
    try:
        read = await asyncio.wait_for(_read_board(hub), BOARD_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - reported, never shown as an empty board
        logger.debug("Could not read TheHub's board")
        why = f"TheHub's board could not be read: {_error(exc)}"
        if (old := _board_cache.fallback(hub, now)) is not None:
            return replace(old, stale=True, reason=why), ""
        return None, why
    _board_cache.put(hub, read, now)
    return read, ""


# ---------------------------------------------------------------------------
# Pull requests
# ---------------------------------------------------------------------------


async def _read_pull_requests(db: Any, catalog: Any, factory: Any) -> PullRequestRead:
    from mykronos.pull_requests import open_pull_requests

    with db.session() as session:
        ledger = {
            str(row.github_repo_full_name): (
                str(row.default_branch or "main"),
                row.github_installation_id,
                str(row.status or ""),
            )
            for row in session.execute(select(RepoOnboarding)).scalars()
        }
        listed = await open_pull_requests(session, catalog, factory)

    active = {name for name, (_, _, status) in ledger.items() if status != "removed"}
    unreachable = [(repo, why) for repo, why in listed.unreachable if repo in active]
    if active and len({repo for repo, _ in unreachable}) >= len(active):
        raise NothingListedError("no onboarded repository's pull requests could be listed.")

    rows = [row for row in listed.pull_requests if row.repo_full_name in active]
    out = [
        OpenPullRequest(
            repo_full_name=row.repo_full_name,
            number=row.number,
            url=row.url,
            title=row.title,
            draft=row.draft,
            head_branch=row.branch,
            base_branch="",
            default_branch=ledger[row.repo_full_name][0],
            opened_at=row.opened_at,
            checks=row.checks,
            story_ids=story_refs(row.title, branch=row.branch),
        )
        for row in rows
    ]

    # Mergeable is on the single-PR read only. Drafts are not awaiting a
    # merge, so they do not spend one; the oldest are read first.
    wanted = sorted(
        (pr for pr in out if not pr.draft),
        key=lambda pr: pr.opened_at or datetime.max,
    )
    to_read, skipped = wanted[:MAX_DETAIL_READS], len(wanted[MAX_DETAIL_READS:])
    gate = asyncio.Semaphore(GITHUB_CONCURRENCY)

    async def detail(pr: OpenPullRequest) -> bool:
        installation = ledger[pr.repo_full_name][1]
        if installation is None:
            return False
        async with gate:
            try:
                live = await factory.for_installation(int(installation)).get_pull_request(
                    pr.repo_full_name, pr.number
                )
            except GitHubError:
                logger.debug("No detail for %s#%s", pr.repo_full_name, pr.number)
                return False
        if live is None:
            return False
        pr.base_branch = live.base_branch
        pr.mergeable = live.mergeable
        pr.mergeable_state = live.mergeable_state
        pr.story_ids = story_refs(pr.title, live.body, branch=pr.head_branch)
        pr.depends_on = depends_on(live.body)
        pr.detail_read = True
        return True

    answered = await asyncio.gather(*(detail(pr) for pr in to_read))
    return PullRequestRead(
        pull_requests=out,
        unreachable=unreachable,
        as_of=utcnow(),
        details_unread=skipped + sum(1 for ok in answered if not ok),
    )


async def pull_requests(
    db: Any, catalog: Any, factory: Any
) -> tuple[PullRequestRead | None, str]:
    """Every open pull request on the onboarded repositories, cached."""
    if factory is None:
        return None, GITHUB_NOT_CONFIGURED
    now = time.monotonic()
    if (hit := _pr_cache.fresh(factory, PULL_REQUESTS_TTL_SECONDS, now)) is not None:
        return hit, ""
    try:
        read = await asyncio.wait_for(
            _read_pull_requests(db, catalog, factory), PULL_REQUESTS_TIMEOUT_SECONDS
        )
    except Exception as exc:  # noqa: BLE001 - reported, never shown as "none open"
        logger.debug("Could not read open pull requests")
        why = f"GitHub's pull requests could not be read: {_error(exc)}"
        if (old := _pr_cache.fallback(factory, now)) is not None:
            return replace(old, stale=True, reason=why), ""
        return None, why
    _pr_cache.put(factory, read, now)
    return read, ""


async def gather(state: Any, *, want_pull_requests: bool = True) -> DeliveryInputs:
    """The board, and (for the overall page) the pull requests, concurrently.
    Never raises."""
    hub = getattr(state, "hub", None)
    factory = getattr(state, "github_factory", None)

    async def no_prs() -> tuple[PullRequestRead | None, str]:
        return None, "Not read for a single product's page."

    (board_read, board_error), (pr_read, pr_error) = await asyncio.gather(
        board(hub),
        pull_requests(state.db, state.catalog, factory) if want_pull_requests else no_prs(),
    )
    return DeliveryInputs(
        board=board_read,
        board_error=board_error,
        pull_requests=pr_read,
        pull_requests_error=pr_error,
    )
