"""Resolving a finding's owner at ingest (spec 24 §1).

`codeowners.py` answers "who owns this path" from text. This is the part that
has to talk to GitHub, cache the answer, and survive GitHub being unavailable
without failing an ingest — because a scan that uploads four hundred findings
must not fail because a routing label could not be fetched.

**Three failure modes, one outcome.** No CODEOWNERS file, an unreadable one,
and GitHub being down all resolve to `unresolved`. That is deliberate: each is
"we do not know who owns this", and inventing three ways to say so would put
the distinction in a column nobody can act on differently.

**Cached per repository, with a negative entry.** A repository *without* a
CODEOWNERS file is the common case in this portfolio, and re-asking GitHub for
a file that does not exist on every batch is a rate-limit budget spent on a
404. The empty result is cached exactly like a populated one.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from mykronos.codeowners import Rule, parse, resolve
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: The three locations GitHub itself looks in, in its own precedence order.
CODEOWNERS_PATHS: tuple[str, ...] = (
    ".github/CODEOWNERS",
    "CODEOWNERS",
    "docs/CODEOWNERS",
)

#: How long a read stays good. Long enough that a four-hundred-finding scan
#: costs one request, short enough that a team fixing their CODEOWNERS file
#: sees it take effect on the next scan rather than the next day.
DEFAULT_TTL_SECONDS = 900


@dataclass
class _Entry:
    rules: list[Rule]
    expires_at: float
    #: False when the lookup failed rather than found nothing. Cached with the
    #: rules so a repository does not flip between "nobody owns this" and "we
    #: could not ask" inside one TTL.
    readable: bool = True


class OwnershipResolver:
    """Reads CODEOWNERS through the installation client, and remembers."""

    def __init__(self, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[str, _Entry] = {}

    def _now(self) -> float:
        return utcnow().timestamp()

    def invalidate(self, repo_full_name: str) -> None:
        self._cache.pop(repo_full_name, None)

    async def rules_for(self, github: Any, repo_full_name: str) -> list[Rule]:
        """The parsed rules for a repository, cached.

        `github` may be None — an un-onboarded repository, or a test harness
        without a client. That is not an error here; it is one more way of not
        knowing, and it produces the same empty result as a repository with no
        file.
        """
        cached = self._cache.get(repo_full_name)
        if cached is not None and cached.expires_at > self._now():
            return cached.rules

        rules: list[Rule] = []
        # Whether we actually got an answer, as distinct from what the answer
        # was. `github is None` is not a failed read — it is a repository this
        # deployment cannot ask about, which is a knowable state.
        readable = True
        if github is not None:
            for path in CODEOWNERS_PATHS:
                try:
                    text = await github.get_file(repo_full_name, path, "HEAD")
                except Exception:
                    # Deliberately broad, and deliberately not re-raised. The
                    # caller is an ingest handler; a GitHub outage costs this
                    # batch its routing labels and nothing else.
                    logger.warning(
                        "CODEOWNERS read failed for %s at %s",
                        repo_full_name,
                        path,
                        exc_info=True,
                    )
                    text = None
                    readable = False
                if text:
                    rules = parse(text)
                    readable = True
                    break

        self._cache[repo_full_name] = _Entry(
            rules=rules, expires_at=self._now() + self._ttl, readable=readable
        )
        return rules

    async def lookup_for(self, github: Any, repo_full_name: str) -> tuple[list[Rule], bool]:
        """`(rules, readable)` — the rules, and whether we managed to look.

        **The distinction earns its keep now, and did not before.** This module
        used to collapse "no CODEOWNERS file", "an unreadable one" and "GitHub
        is down" into one empty result, on the stated grounds that nothing
        downstream could act on the difference. That was true while all three
        led to `unresolved`.

        It stopped being true when ownership gained a repository-owner rung. An
        empty file list means *nobody matched* and falling through to the
        account is a weak, true answer. A failed read means *we could not ask*,
        and falling through would convert a GitHub outage into an ownership
        assignment nobody made — worse than leaving it unresolved, because it
        looks like a decision.
        """
        rules = await self.rules_for(github, repo_full_name)
        cached = self._cache.get(repo_full_name)
        return rules, True if cached is None else cached.readable


def owner_for_finding(
    *,
    file_path: str | None,
    rules: list[Rule],
    profile_owner: str | None = None,
    repo_owner: str | None = None,
    codeowners_readable: bool = True,
) -> tuple[str | None, str]:
    """`(owner, owner_source)` for one finding.

    Three steps now, each weaker than the one above it and each labelled so a
    reader knows how much to trust the answer.

    A finding with a path resolves through CODEOWNERS. A finding *without* one
    — a dependency CVE, a container layer — falls back to the repository owner
    recorded on the risk profile (spec 21 §1), tagged `profile` so nobody reads
    it as something the team wrote in their own file. Failing both, it falls to
    the account the repository belongs to, tagged `repo_owner`.

    **Why the third rung was added.** With only two, an estate that has neither
    CODEOWNERS files nor risk profiles routes nothing: 282 finding groups on
    this deployment were unowned while routing was switched on, and an unowned
    finding is one nobody has agreed to fix. The repository's owner is a weak
    answer and a *true* one — it is genuinely who the repository belongs to —
    which is the same standard the profile rung is held to. It gives the
    reassignment conversation something to start from, which a blank column
    does not.

    What this still does **not** do is guess a manifest. A dependency finding
    names a package and not the file that declares it, so picking
    `package.json` over `requirements.txt` to match against CODEOWNERS would be
    this platform inventing a path and then routing real work by it. Every
    answer here is weaker and true; the manifest answer would be specific and
    made up.
    """
    if file_path:
        owner, source = resolve(file_path, rules)
        if owner is not None:
            return owner, source
    if profile_owner:
        return profile_owner, "profile"
    # Only when we actually looked. A failed CODEOWNERS read must not become an
    # ownership assignment: "we could not ask" looks identical to "the account
    # owns it" once it is written into a column, and only one of them is true.
    if repo_owner and codeowners_readable:
        return repo_owner, "repo_owner"
    return None, "unresolved"
