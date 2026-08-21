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
                if text:
                    rules = parse(text)
                    break

        self._cache[repo_full_name] = _Entry(rules=rules, expires_at=self._now() + self._ttl)
        return rules


def owner_for_finding(
    *,
    file_path: str | None,
    rules: list[Rule],
    profile_owner: str | None = None,
) -> tuple[str | None, str]:
    """`(owner, owner_source)` for one finding.

    Two steps, and deliberately no third.

    A finding with a path resolves through CODEOWNERS. A finding *without* one
    — a dependency CVE, a container layer — falls back to the repository owner
    recorded on the risk profile (spec 21 §1), tagged `profile` so nobody reads
    it as something the team wrote in their own file.

    What this does **not** do is guess a manifest. A dependency finding names a
    package and not the file that declares it, so picking `package.json` over
    `requirements.txt` to match against CODEOWNERS would be this platform
    inventing a path and then routing real work by it. The profile answer is
    weaker and true; the manifest answer would be specific and made up.
    """
    if file_path:
        owner, source = resolve(file_path, rules)
        if owner is not None:
            return owner, source
    if profile_owner:
        return profile_owner, "profile"
    return None, "unresolved"
