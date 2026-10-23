"""Operator actions that check themselves (TheHub #60972).

The briefing's "Needs you today" lists every icebox story titled
`OPERATOR ACTION:`. Listed by age alone it cannot tell an ask the operator
has already done from one still open, so a done ask nags every morning until
someone closes the story by hand.

This module is a small registry from a Hub story id to a named probe that
reads, from GitHub, whether the thing the story asks for is now true. Each
probe answers one of four verifications:

* `observed_done` -- GitHub was read and the ask is in place.
* `observed_not_done` -- GitHub was read and it is not.
* `unprobed` -- no probe is registered for the story. Nothing was checked.
* `probe_error` -- a probe is registered but could not read its source (no
  installation for the repository, a refused read, a timeout). It is never
  counted as done.

Every answer but `unprobed` carries an evidence string saying what was read.

Read-only by construction: a probe is handed a GitHub client and calls only
its `get_*` reads (branch protection, rulesets). Nothing here writes to
GitHub or to TheHub; `tests/test_operator_checks.py` holds that line.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any

from mykronos.github.client import GitHubError, PermissionDeniedError

logger = logging.getLogger(__name__)

OBSERVED_DONE = "observed_done"
OBSERVED_NOT_DONE = "observed_not_done"
UNPROBED = "unprobed"
PROBE_ERROR = "probe_error"
VERIFICATIONS = (OBSERVED_DONE, OBSERVED_NOT_DONE, UNPROBED, PROBE_ERROR)

#: One probe may not hold the page up longer than this.
PROBE_TIMEOUT_SECONDS = 10.0

MYKRONOS_REPO = "ToddGBenson/mykronos"


@dataclass(frozen=True)
class Verification:
    verification: str
    #: What was read, in a sentence. Empty only for `unprobed`.
    evidence: str = ""
    #: The probe's name, when one is registered.
    probe: str = ""

    def __post_init__(self) -> None:
        if self.verification not in VERIFICATIONS:
            raise ValueError(
                f"verification must be one of {VERIFICATIONS}, not {self.verification!r}"
            )
        if self.verification != UNPROBED and not self.evidence:
            raise ValueError(f"a {self.verification} verification must carry evidence")


#: A probe's check: given a client for the probe's repository, what it saw.
Check = Callable[[Any], Awaitable[Verification]]


@dataclass(frozen=True)
class Probe:
    #: `required_checks_on_main`, `tag_ruleset_exists`.
    name: str
    repo: str
    check: Check


def _refused(exc: GitHubError, what: str) -> str:
    """Why a read failed, by status, never by GitHub's response text."""
    status = getattr(exc, "status", None)
    if isinstance(exc, PermissionDeniedError) or status == 403:
        return (
            f"GitHub refused to show {what} (HTTP 403); the App installation may "
            "lack administration: read"
        )
    if status:
        return f"GitHub answered HTTP {status} when asked for {what}"
    return f"GitHub could not be reached for {what}"


def _required_contexts(protection: dict[str, Any]) -> list[str]:
    checks = protection.get("required_status_checks") or {}
    names = {str(c.get("context")) for c in checks.get("checks") or [] if c.get("context")}
    names |= {str(c) for c in checks.get("contexts") or []}
    return sorted(names)


def required_checks_on_main(repo: str, contexts: Iterable[str]) -> Probe:
    """Done when branch protection on `main` requires every one of
    `contexts` as a status check."""
    wanted = sorted(set(contexts))
    name = "required_checks_on_main"

    async def check(client: Any) -> Verification:
        try:
            protection = await client.get_branch_protection(repo, "main")
        except GitHubError as exc:
            return Verification(
                PROBE_ERROR, _refused(exc, f"branch protection on {repo} main") + ".", name
            )
        if protection is None:
            return Verification(
                OBSERVED_NOT_DONE,
                f"{repo} main has no branch protection, so nothing is a required check.",
                name,
            )
        required = _required_contexts(protection)
        missing = [c for c in wanted if c not in required]
        listed = ", ".join(required) or "none"
        if missing:
            return Verification(
                OBSERVED_NOT_DONE,
                f"Branch protection on {repo} main does not require "
                f"{', '.join(missing)} (required: {listed}).",
                name,
            )
        return Verification(
            OBSERVED_DONE,
            f"Branch protection on {repo} main requires {', '.join(wanted)} "
            f"(required: {listed}).",
            name,
        )

    return Probe(name=name, repo=repo, check=check)


def _includes(conditions: dict[str, Any], pattern: str) -> bool:
    ref_name = (conditions or {}).get("ref_name") or {}

    def bare(value: Any) -> str:
        text = str(value)
        return text[len("refs/tags/"):] if text.startswith("refs/tags/") else text

    include = {bare(v) for v in ref_name.get("include") or []}
    exclude = {bare(v) for v in ref_name.get("exclude") or []}
    return (pattern in include or "~ALL" in include) and pattern not in exclude


def tag_ruleset_exists(
    repo: str, pattern: str, rules: Iterable[str] = ("update", "deletion")
) -> Probe:
    """Done when an active tag ruleset on `repo` targets `pattern` and
    carries every one of `rules` (by default: restrict updates and
    deletions, what the release-tag ask is for)."""
    wanted = sorted(set(rules))
    name = "tag_ruleset_exists"

    async def check(client: Any) -> Verification:
        what = f"the rulesets on {repo}"
        try:
            listed = await client.get_rulesets(repo)
            tags = [
                r for r in listed
                if str(r.get("target") or "").lower() == "tag"
                and str(r.get("enforcement") or "").lower() == "active"
            ]
            # GitHub's listing leaves out conditions and rules; the single
            # ruleset read carries them.
            full = [
                r if "conditions" in r else await client.get_ruleset(repo, int(r["id"]))
                for r in tags
            ]
        except GitHubError as exc:
            return Verification(PROBE_ERROR, _refused(exc, what) + ".", name)
        except (KeyError, TypeError, ValueError):
            return Verification(PROBE_ERROR, f"GitHub's answer for {what} was not readable.", name)

        matching = [r for r in full if _includes(r.get("conditions") or {}, pattern)]
        if not matching:
            return Verification(
                OBSERVED_NOT_DONE,
                f"{repo} has {len(listed)} ruleset(s), {len(tags)} active on tags; "
                f"none targets {pattern}.",
                name,
            )
        for ruleset in matching:
            have = {str(rule.get("type")) for rule in ruleset.get("rules") or []}
            if all(rule in have for rule in wanted):
                return Verification(
                    OBSERVED_DONE,
                    f"Active tag ruleset '{ruleset.get('name') or ruleset.get('id')}' on "
                    f"{repo} targets {pattern} and restricts {', '.join(wanted)}.",
                    name,
                )
        have_any = sorted(
            {str(rule.get("type")) for r in matching for rule in r.get("rules") or []}
        )
        return Verification(
            OBSERVED_NOT_DONE,
            f"An active tag ruleset on {repo} targets {pattern} but restricts "
            f"{', '.join(have_any) or 'nothing'}, not all of {', '.join(wanted)}.",
            name,
        )

    return Probe(name=name, repo=repo, check=check)


#: Hub story id -> its probe. Exactly the asks GitHub can answer today.
REGISTRY: dict[int, Probe] = {
    # OPERATOR ACTION: make backend-tests a required check on main (D-162).
    60931: required_checks_on_main(MYKRONOS_REPO, ["backend-tests"]),
    # OPERATOR ACTION: protect the mykronos v* release tags.
    60810: tag_ruleset_exists(MYKRONOS_REPO, "v*"),
}


async def _run(probe: Probe, client: Any) -> Verification:
    try:
        return await asyncio.wait_for(probe.check(client), PROBE_TIMEOUT_SECONDS)
    except TimeoutError:
        return Verification(PROBE_ERROR, "GitHub did not answer in time.", probe.name)
    except Exception as exc:  # noqa: BLE001 - a probe never takes the page down
        logger.debug("Probe %s failed", probe.name)
        return Verification(
            PROBE_ERROR, f"{type(exc).__name__} while reading GitHub.", probe.name
        )


async def verify(
    factory: Any,
    installations: dict[str, int | None],
    registry: dict[int, Probe] | None = None,
) -> dict[int, Verification]:
    """Every registered probe's answer, by story id. Never raises.

    `installations` maps a repository to its GitHub App installation (the
    onboarding ledger); a probe whose repository has none answers
    `probe_error`, never `observed_not_done`.
    """
    probes = REGISTRY if registry is None else registry

    async def one(probe: Probe) -> Verification:
        if factory is None:
            return Verification(PROBE_ERROR, "No GitHub client is configured.", probe.name)
        installation = installations.get(probe.repo)
        if installation is None:
            return Verification(
                PROBE_ERROR,
                f"{probe.repo} is not onboarded with a GitHub App installation, so it "
                "could not be read.",
                probe.name,
            )
        return await _run(probe, factory.for_installation(int(installation)))

    ids = list(probes)
    answers = await asyncio.gather(*(one(probes[i]) for i in ids))
    return dict(zip(ids, answers, strict=True))


def for_story(
    story_id: Any,
    checks: dict[int, Verification] | None,
    why_unchecked: str,
    registry: dict[int, Probe] | None = None,
) -> Verification:
    """What the briefing says about one operator action."""
    probes = REGISTRY if registry is None else registry
    try:
        key = int(story_id)
    except (TypeError, ValueError):
        return Verification(UNPROBED)
    if key not in probes:
        return Verification(UNPROBED)
    if checks is not None and key in checks:
        return checks[key]
    return Verification(PROBE_ERROR, why_unchecked, probes[key].name)
