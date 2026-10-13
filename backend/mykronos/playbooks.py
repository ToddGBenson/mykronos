"""Playbooks as data: how an agent works each kind of item (spec 36 §5).

The work queue (`mykronos.agent_work`) says *what* needs doing. How to do it
used to live in one agent's memory file: read the failed job's annotation
first, then billing, disabled Actions, a red `unit`, the wrong branch, the
token, a host restart. Each of those orders was paid for by a lane that
stopped scanning, and an agent that had not read that file repeated the cost.
`agent-playbooks-v1.yaml` moves it into a reviewed file at the repository
root, next to the approval and Oracle policies, and every work item names the
playbook it is worked by as `<kind>@<version>`.

This module loads that file and refuses a bad one. Three refusals matter more
than the rest:

**A kind with no playbook.** `agent_work.KINDS` is the list of kinds the queue
can emit. A file missing one would hand an agent an item with a playbook
reference that resolves to nothing, which is the silent shape this platform
keeps finding (an `_unknown` dropped, a section that is empty because it was
never asked).

**A playbook for a kind that does not exist.** A renamed kind would otherwise
leave its old playbook in the file, reviewed and unreachable, while the new
kind has none.

**A step with nowhere to look.** Every step names an API route or evidence
outside the API. A step that names neither is advice, and advice is what the
memory file already was. Whether each named route exists is checked by
`tests/test_playbooks.py` against the app's own route table, not here: the
loader does not import the API, and the test is where a renamed route should
fail.

A playbook grants nothing. The routes it names enforce their own rules and
`approval-policy-v1.yaml` decides who approves; this file only orders the work.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from mykronos.agent_work import KINDS

logger = logging.getLogger(__name__)

#: What a step may do once its `if_found` applies (see the file's header).
OUTCOMES = ("continue", "repair", "escalate", "stop")

#: `METHOD /path`, optionally with a query string. Path templates use the
#: API's own parameter names, so the test can match them against the app.
_ROUTE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE) (/\S*)$")
_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_TOP_KEYS = {"version", "playbooks"}
_PLAYBOOK_KEYS = {"purpose", "steps", "stop_when", "escalate", "never"}
_STEP_KEYS = {"id", "do", "check", "routes", "outside", "if_found", "then"}
_ESCALATE_KEYS = {"when", "evidence"}


class PlaybookError(ValueError):
    """The playbooks file is missing, malformed, or out of step with the kinds."""


@dataclass(frozen=True)
class Step:
    id: str
    do: str
    check: str
    routes: tuple[str, ...] = ()
    outside: tuple[str, ...] = ()
    if_found: str = ""
    then: str = "continue"


@dataclass(frozen=True)
class Escalation:
    when: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Playbook:
    kind: str
    version: str
    purpose: str
    steps: tuple[Step, ...]
    stop_when: tuple[str, ...]
    escalate: Escalation
    never: tuple[str, ...] = ()

    @property
    def ref(self) -> str:
        """What a work item carries in its `playbook` field."""
        return f"{self.kind}@{self.version}"


@dataclass(frozen=True)
class Playbooks:
    version: str
    #: In `agent_work.KINDS` order, which is band order.
    playbooks: dict[str, Playbook] = field(default_factory=dict)

    def get(self, kind: str) -> Playbook | None:
        return self.playbooks.get(kind)

    def routes(self) -> list[tuple[str, str, str]]:
        """Every `(kind, step id, route)` the file names, for the route test."""
        return [
            (kind, step.id, route)
            for kind, playbook in self.playbooks.items()
            for step in playbook.steps
            for route in step.routes
        ]


def split_route(route: str) -> tuple[str, str]:
    """`"GET /api/x?y={z}"` -> `("GET", "/api/x")`. The query is advice, not routing."""
    match = _ROUTE.match(route)
    if match is None:
        raise PlaybookError(f"Route {route!r} is not 'METHOD /path'.")
    return match.group(1), match.group(2).split("?", 1)[0]


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlaybookError(f"{where} must be non-empty text.")
    return value.strip()


def _texts(value: Any, where: str, *, required: bool) -> tuple[str, ...]:
    if value is None and not required:
        return ()
    if not isinstance(value, list) or (required and not value):
        raise PlaybookError(f"{where} must be a {'non-empty ' if required else ''}list of text.")
    return tuple(_text(item, f"{where}[{i}]") for i, item in enumerate(value))


def _mapping(value: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlaybookError(f"{where} must be a mapping.")
    unknown = sorted(set(value) - allowed)
    if unknown:
        # Refused rather than ignored: a misspelt `stop_when` would otherwise
        # load as a playbook with no stop conditions and look reviewed.
        raise PlaybookError(f"{where} has unknown key(s): {', '.join(unknown)}.")
    return value


def _step(value: Any, where: str) -> Step:
    raw = _mapping(value, where, _STEP_KEYS)
    step_id = _text(raw.get("id"), f"{where}.id")
    if not _STEP_ID.match(step_id):
        raise PlaybookError(f"{where}.id {step_id!r} must be a lowercase slug.")
    where = f"{where} ({step_id})"
    routes = _texts(raw.get("routes"), f"{where}.routes", required=False)
    for route in routes:
        try:
            split_route(route)
        except PlaybookError as exc:
            raise PlaybookError(f"{where}: {exc}") from exc
    outside = _texts(raw.get("outside"), f"{where}.outside", required=False)
    if not routes and not outside:
        raise PlaybookError(
            f"{where} names no route and no outside evidence. A step says where to look."
        )
    then = str(raw.get("then", "continue"))
    if then not in OUTCOMES:
        raise PlaybookError(f"{where}.then is {then!r}; expected one of {', '.join(OUTCOMES)}.")
    if_found = raw.get("if_found")
    if then != "continue" and not (isinstance(if_found, str) and if_found.strip()):
        raise PlaybookError(f"{where}.then is {then!r}, which needs an if_found saying when.")
    return Step(
        id=step_id,
        do=_text(raw.get("do"), f"{where}.do"),
        check=_text(raw.get("check"), f"{where}.check"),
        routes=routes,
        outside=outside,
        if_found=_text(if_found, f"{where}.if_found") if if_found is not None else "",
        then=then,
    )


def _playbook(kind: str, value: Any, version: str) -> Playbook:
    where = f"playbooks.{kind}"
    raw = _mapping(value, where, _PLAYBOOK_KEYS)
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise PlaybookError(f"{where}.steps must be a non-empty list.")
    steps = tuple(_step(s, f"{where}.steps[{i}]") for i, s in enumerate(steps_raw))
    seen: set[str] = set()
    for step in steps:
        if step.id in seen:
            raise PlaybookError(f"{where} has two steps with id {step.id!r}.")
        seen.add(step.id)
    escalate = _mapping(raw.get("escalate"), f"{where}.escalate", _ESCALATE_KEYS)
    return Playbook(
        kind=kind,
        version=version,
        purpose=_text(raw.get("purpose"), f"{where}.purpose"),
        steps=steps,
        stop_when=_texts(raw.get("stop_when"), f"{where}.stop_when", required=True),
        escalate=Escalation(
            when=_texts(escalate.get("when"), f"{where}.escalate.when", required=True),
            evidence=_texts(escalate.get("evidence"), f"{where}.escalate.evidence", required=True),
        ),
        never=_texts(raw.get("never"), f"{where}.never", required=False),
    )


def parse_playbooks(document: Any, kinds: Iterable[str] = KINDS) -> Playbooks:
    """Validate a loaded document against the kinds the queue can emit."""
    kinds = tuple(kinds)
    raw = _mapping(document, "The playbooks file", _TOP_KEYS)
    version = raw.get("version")
    if isinstance(version, (int, float)) and not isinstance(version, bool):
        # `version: 1.0` unquoted is a float, and `1.10` would read as `1.1`.
        raise PlaybookError("version must be quoted text, e.g. version: \"1.0\".")
    version = _text(version, "version")
    books = raw.get("playbooks")
    if not isinstance(books, dict) or not books:
        raise PlaybookError("playbooks must be a mapping of work-item kind to playbook.")
    missing = [k for k in kinds if k not in books]
    unknown = sorted(str(k) for k in books if k not in kinds)
    if missing or unknown:
        problems = []
        if missing:
            problems.append(f"no playbook for kind(s): {', '.join(missing)}")
        if unknown:
            problems.append(f"playbook(s) for kind(s) the queue never emits: {', '.join(unknown)}")
        raise PlaybookError(
            "The playbooks file does not match agent_work.KINDS: " + "; ".join(problems) + "."
        )
    return Playbooks(
        version=version,
        playbooks={kind: _playbook(kind, books[kind], version) for kind in kinds},
    )


def load_playbooks(path: Path) -> Playbooks:
    if not path.is_file():
        raise PlaybookError(
            f"No agent playbooks at {path}. Every work item names its playbook, and a "
            "built-in default would be steps nobody reviewed."
        )
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PlaybookError(f"Agent playbooks at {path} are not valid YAML: {exc}") from exc
    playbooks = parse_playbooks(document)
    logger.info("Loaded agent playbooks %s from %s", playbooks.version, path)
    return playbooks


@lru_cache(maxsize=4)
def cached_playbooks(path: Path) -> Playbooks:
    return load_playbooks(path)
