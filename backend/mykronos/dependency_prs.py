"""Open dependency-bot pull requests, linked to the findings they would close (TheHub #60915).

TheHub PR #499 (Dependabot, pypdf 6.20.1 -> 6.21.1) was open and listed under
pull requests, while the five pypdf findings it fixes did not mention it and
the briefing offered them a no-fix path. The fix existed; it was waiting for
review, and nothing joined the two.

A pull request is a dependency bot's when its head branch is one a bot names
(`dependabot/...`, `renovate/...`): the branch is set by the bot and survives
a retitle, where a title can be written by anyone. Its bumps are read from the
title, and for a group update from the body's "Updates `pkg` from a to b"
lines. A finding links to one when the repository and package match and the
bump's target is at or above the finding's `fixed_version`. When either
version cannot be compared, nothing links: a guessed "this fixes it" would be
worse than none.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import weakref
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from packaging.version import InvalidVersion, Version

from mykronos.github.client import GitHubError, PullRequest

logger = logging.getLogger(__name__)

#: Head-branch prefixes the dependency bots use.
BOT_BRANCH_PREFIXES = ("dependabot/", "renovate/")
#: How long one repository's open bot PRs are reused before GitHub is asked again.
CACHE_TTL_SECONDS = 300.0

_DEPENDABOT_TITLE = re.compile(
    r"\bbump (?P<pkg>[^\s`]+) from (?P<from>[^\s`]+) to (?P<to>[^\s`]+)", re.IGNORECASE
)
_DEPENDABOT_BODY = re.compile(
    r"^\s*Updates [`'\"]?(?P<pkg>[^\s`'\"]+)[`'\"]? from (?P<from>[^\s`]+) to (?P<to>[^\s`]+)",
    re.IGNORECASE | re.MULTILINE,
)
_RENOVATE_TITLE = re.compile(
    r"\bupdate (?:dependency )?(?P<pkg>[^\s`]+) to v?(?P<to>\d[^\s`]*)", re.IGNORECASE
)


@dataclass(frozen=True)
class Bump:
    package: str
    from_version: str | None
    to_version: str


@dataclass
class DependencyPr:
    repo_full_name: str
    number: int
    url: str
    title: str
    bumps: list[Bump] = field(default_factory=list)


@dataclass(frozen=True)
class PackageFinding:
    """An open finding about a package, with the version that fixes it."""

    finding_id: str
    repo_full_name: str
    capability: str
    package: str
    fixed_version: str


@dataclass(frozen=True)
class FixPullRequest:
    repo_full_name: str
    number: int
    url: str
    title: str
    package: str
    to_version: str

    @property
    def ref(self) -> str:
        return f"{self.repo_full_name}#{self.number}"


def is_dependency_bot(pr: PullRequest) -> bool:
    return pr.head_branch.startswith(BOT_BRANCH_PREFIXES)


def _clean(version: str) -> str:
    return version.strip().rstrip(".,;:)").lstrip("v")


def bumps_of(title: str, body: str) -> list[Bump]:
    """What a bot PR changes. A group title names no package, so its body is read."""
    found: dict[str, Bump] = {}
    for match in _DEPENDABOT_BODY.finditer(body or ""):
        bump = Bump(match["pkg"], _clean(match["from"]), _clean(match["to"]))
        found.setdefault(normalise(bump.package), bump)
    title_match = _DEPENDABOT_TITLE.search(title or "")
    if title_match and title_match["pkg"].lower() != "the":
        bump = Bump(title_match["pkg"], _clean(title_match["from"]), _clean(title_match["to"]))
        found.setdefault(normalise(bump.package), bump)
    elif not found:
        renovate = _RENOVATE_TITLE.search(title or "")
        if renovate:
            bump = Bump(renovate["pkg"], None, _clean(renovate["to"]))
            found.setdefault(normalise(bump.package), bump)
    return list(found.values())


def normalise(package: str) -> str:
    """PyPI's rule (PEP 503): case and runs of `-_.` do not distinguish names."""
    return re.sub(r"[-_.]+", "-", package.strip()).lower()


def _version(text: str) -> Version | tuple[int, ...] | None:
    text = _clean(text or "")
    if not text:
        return None
    try:
        return Version(text)
    except InvalidVersion:
        parts = text.split(".")
        if all(part.isdigit() for part in parts):
            return tuple(int(part) for part in parts)
        return None


def at_or_above(target: str, fixed: str) -> bool:
    """True only when both versions parse the same way and `target >= fixed`."""
    a, b = _version(target), _version(fixed)
    if a is None or b is None or type(a) is not type(b):
        return False
    return bool(a >= b)  # type: ignore[operator]


def fixes_for(finding: PackageFinding, prs: Iterable[DependencyPr]) -> list[FixPullRequest]:
    wanted = normalise(finding.package)
    linked: list[FixPullRequest] = []
    for pr in prs:
        if pr.repo_full_name != finding.repo_full_name:
            continue
        for bump in pr.bumps:
            if normalise(bump.package) == wanted and at_or_above(
                bump.to_version, finding.fixed_version
            ):
                linked.append(
                    FixPullRequest(
                        repo_full_name=pr.repo_full_name,
                        number=pr.number,
                        url=pr.url,
                        title=pr.title,
                        package=bump.package,
                        to_version=bump.to_version,
                    )
                )
                break
    return sorted(linked, key=lambda p: p.number)


# -- Reading ---------------------------------------------------------------------

_PACKAGE_FINDINGS_SQL = """
    SELECT finding_id, asset_id, capability, package_name,
           json_extract_string(raw_finding_json, '$.fixed_version')
    FROM findings
    WHERE status = 'open' AND package_name IS NOT NULL AND package_name <> ''
"""


def package_findings(
    catalog: Any, *, asset_id: str | None = None, finding_id: str | None = None
) -> list[PackageFinding]:
    """Open package findings with a fixed version, read from the lake.

    Read from the raw record directly, so a viewer (who is not sent the raw
    record) still sees the link.
    """
    if not catalog.all_files("findings"):
        return []
    sql, params = _PACKAGE_FINDINGS_SQL, []
    if asset_id is not None:
        sql += " AND asset_id = ?"
        params.append(asset_id)
    if finding_id is not None:
        sql += " AND finding_id = ?"
        params.append(finding_id)
    return [
        PackageFinding(str(fid), str(repo), str(cap), str(pkg), str(fixed or ""))
        for fid, repo, cap, pkg, fixed in catalog.query(sql, params)
        if fixed
    ]


#: Per factory, so a test app's fake GitHub never answers for another's.
_cache: weakref.WeakKeyDictionary[Any, dict[str, tuple[float, list[DependencyPr]]]] = (
    weakref.WeakKeyDictionary()
)


async def open_bot_prs(
    factory: Any, installs: Iterable[tuple[str, int]], *, use_cache: bool = True
) -> list[DependencyPr] | None:
    """Every open dependency-bot PR on these repositories.

    None when no repository could be read, so a GitHub outage reads as
    "could not ask", never as "none open". One repository failing among
    several drops only that one's.
    """
    installs = list(installs)
    try:
        cache = _cache.setdefault(factory, {}) if use_cache else {}
    except TypeError:  # not weak-referenceable: read every time
        cache = {}
    now = time.monotonic()

    async def one(repo: str, installation_id: int) -> list[DependencyPr] | None:
        hit = cache.get(repo)
        if hit is not None and now - hit[0] < CACHE_TTL_SECONDS:
            return hit[1]
        try:
            listed = await factory.for_installation(installation_id).list_open_pull_requests(repo)
        except GitHubError as exc:
            logger.debug("Could not list pull requests for %s: %s", repo, exc)
            return None
        prs = [
            DependencyPr(
                repo_full_name=repo,
                number=pr.number,
                url=pr.url,
                title=pr.title,
                bumps=bumps_of(pr.title, pr.body),
            )
            for pr in listed
            if is_dependency_bot(pr) and not pr.draft
        ]
        cache[repo] = (now, prs)
        return prs

    answers = await asyncio.gather(*(one(repo, i) for repo, i in installs))
    read = [prs for prs in answers if prs is not None]
    if installs and not read:
        return None
    return [pr for prs in read for pr in prs]


def installs_of(db: Any, repos: Iterable[str] | None = None) -> list[tuple[str, int]]:
    """(repository, installation id) for every active onboarded repository, or the named ones."""
    from sqlalchemy import select

    from mykronos.db.models import RepoOnboarding

    wanted = set(repos) if repos is not None else None
    with db.session() as session:
        return [
            (str(row.github_repo_full_name), int(row.github_installation_id))
            for row in session.execute(
                select(RepoOnboarding).where(RepoOnboarding.status != "removed")
            ).scalars()
            if row.github_installation_id is not None
            and (wanted is None or row.github_repo_full_name in wanted)
        ]
