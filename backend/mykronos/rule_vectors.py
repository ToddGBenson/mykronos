"""Analyst-confirmed CVSS vectors for findings that have no CVE
(TheHub #60832, S10 of epic #60822, decision D3).

SAST, DAST and secrets findings name a rule (`python.lang.security.audit...`,
`10202`, `generic-api-key`), not a CVE. Nothing publishes a vector for a rule,
so D-106 left these findings unscored on purpose: a vector invented from the
scanner's severity word would read as the standard and not be it, and the
number would be quoted.

D3 keeps that refusal and adds the honest way past it. A person records a
CVSS 3.1 base vector for one rule (`RuleVector`), for one repository or for
the whole estate, and from then on the rule's findings are scored through the
same environmental resolver as everything else, with `vector_source=analyst`.

**Three states, and only one of them scores.**

- `proposed`: somebody (a person or an agent) suggested a vector, usually
  pre-filled from a reviewed CWE-class template (`cwe-vector-templates-v1.yaml`).
  Read by nothing that scores.
- `confirmed`: a person with a human credential looked at it, perhaps edited
  it, and confirmed it. Only this state is read by `environment.choose_vectors`,
  and only after every published source (NVD, an advisory, v4.0) has been
  passed over. An agent or automation principal is refused, here and at the
  route, whatever it may otherwise write.
- `retired`: withdrawn, or replaced by a later confirmation. Kept, with who
  and when, so the audit trail and the row agree.

At most one `proposed` and one `confirmed` row per key, so a proposal can sit
beside the vector in force as a suggested change; confirming it retires the
one it replaces.

The vector is the eight base metrics only. The environment is the resolver's
job: a rule vector that arrived pre-lowered with `MAV:L` would be an analyst
arguing a score down without any of the evidence `environment.py` demands.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from mykronos import cvss
from mykronos.adminauth import Principal
from mykronos.db.models import RuleVector
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: The template file's name without its extension: a proposal's
#: `proposed_from` is `<this>:<CWE>`, so the row says which reviewed file and
#: which entry pre-filled it.
TEMPLATE_FILE = "cwe-vector-templates-v1"

PROPOSED = "proposed"
CONFIRMED = "confirmed"
RETIRED = "retired"
STATUSES = (PROPOSED, CONFIRMED, RETIRED)

#: CVSS 3.1's base metrics, in the specification's order.
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_CWE = re.compile(r"^CWE-(\d+)$")


class RuleVectorError(ValueError):
    """A request this register refuses as malformed (HTTP 422)."""


class RuleVectorConflictError(RuleVectorError):
    """A request the register's current state refuses (HTTP 409)."""


class NotAPersonError(PermissionError):
    """Only an authenticated human principal may do this (HTTP 403)."""


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Template:
    cwe: str
    name: str
    vector: str
    base_score: float
    rationale: str

    @property
    def id(self) -> str:
        return f"{TEMPLATE_FILE}:{self.cwe}"


@dataclass(frozen=True)
class Templates:
    version: str = ""
    templates: Mapping[str, Template] = field(default_factory=dict)
    by_capability: Mapping[str, str] = field(default_factory=dict)

    def get(self, template_id: str) -> Template | None:
        """By `CWE-79` or by `cwe-vector-templates-v1:CWE-79`."""
        key = template_id.strip()
        prefix = f"{TEMPLATE_FILE}:"
        if key.startswith(prefix):
            key = key[len(prefix) :]
        return self.templates.get(key.upper())

    def suggest(self, cwes: Iterable[str], capability: str) -> Template | None:
        """The template for the first of a rule's CWEs that has one, else the
        capability's default. A suggestion: it pre-fills, it does not score."""
        for cwe in sorted(_normal_cwes(cwes), key=_cwe_number):
            if cwe in self.templates:
                return self.templates[cwe]
        fallback = self.by_capability.get(capability)
        return self.templates.get(fallback) if fallback else None


def _cwe_number(cwe: str) -> int:
    match = _CWE.match(cwe)
    return int(match.group(1)) if match else 1 << 30


def _normal_cwes(raw: Iterable[Any]) -> set[str]:
    out: set[str] = set()
    for value in raw:
        text = str(value).strip().upper()
        if text.isdigit():
            text = f"CWE-{text}"
        if _CWE.match(text):
            out.add(text)
    return out


def parse_templates(document: Mapping[str, Any]) -> Templates:
    """The template file, validated: every vector must be one this register
    would accept from a person, so a template can never pre-fill a proposal
    that confirming would then refuse."""
    templates: dict[str, Template] = {}
    for raw_cwe, entry in (document.get("templates") or {}).items():
        cwe = str(raw_cwe).strip().upper()
        if not _CWE.match(cwe) or not isinstance(entry, Mapping):
            raise RuleVectorError(f"template {raw_cwe!r} is not a CWE entry")
        vector = normalize_vector(str(entry.get("vector") or ""))
        templates[cwe] = Template(
            cwe=cwe,
            name=str(entry.get("name") or cwe),
            vector=vector,
            base_score=float(entry.get("base_score") or 0.0),
            rationale=" ".join(str(entry.get("rationale") or "").split()),
        )
    by_capability = {
        str(capability): str(cwe).strip().upper()
        for capability, cwe in (document.get("by_capability") or {}).items()
    }
    for capability, cwe in by_capability.items():
        if cwe not in templates:
            raise RuleVectorError(f"by_capability.{capability} names {cwe}, which has no template")
    return Templates(
        version=str(document.get("version") or ""),
        templates=templates,
        by_capability=by_capability,
    )


@lru_cache(maxsize=4)
def load_templates(path: Path | None = None) -> Templates:
    """The template file, or no templates.

    Absent or unreadable is logged and means nothing is pre-filled; a person
    can still type a vector. Refusing to start would make a convenience a hard
    dependency, and nothing scores from a template anyway.
    """
    if path is None:
        from mykronos.config import get_settings

        path = get_settings().cwe_vector_templates_path
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        logger.warning("CWE vector templates unreadable at %s; nothing is pre-filled", path)
        return Templates()
    if not isinstance(document, Mapping):
        return Templates()
    try:
        return parse_templates(document)
    except RuleVectorError as exc:
        logger.warning("CWE vector templates at %s refused: %s", path, exc)
        return Templates()


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------


def normalize_vector(vector: str) -> str:
    """A CVSS 3.1 base vector in canonical order, or `RuleVectorError`.

    3.1 only (D1 of the epic). The eight base metrics and nothing else: no
    temporal metric (a rule is not an exploit with a maturity) and no
    environmental one (that is `environment.py`'s, from evidence).
    """
    text = (vector or "").strip()
    if not text.startswith("CVSS:3.1/"):
        raise RuleVectorError(f"A rule vector must be CVSS 3.1 (CVSS:3.1/...): {vector!r}")
    try:
        metrics = cvss.parse(text)
    except cvss.VectorError as exc:
        raise RuleVectorError(str(exc)) from exc
    extra = sorted(set(metrics) - set(BASE_METRICS))
    if extra:
        raise RuleVectorError(
            "A rule vector holds the eight base metrics only; "
            f"{', '.join(extra)} belong to the environment, which is resolved "
            "from evidence, not asserted with the vector."
        )
    parts = text.split("/")[1:]
    if len(parts) != len(BASE_METRICS):
        raise RuleVectorError(f"A metric is repeated in {vector!r}")
    return "CVSS:3.1/" + "/".join(f"{key}:{metrics[key]}" for key in BASE_METRICS)


def base_score(vector: str) -> float:
    return cvss.score(vector).base


# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------


def _scope(repo_full_name: str | None) -> Any:
    return (
        RuleVector.repo_full_name.is_(None)
        if repo_full_name is None
        else RuleVector.repo_full_name == repo_full_name
    )


def _active(
    session: Session,
    *,
    repo_full_name: str | None,
    capability: str,
    tool: str,
    rule_id: str,
    status: str,
) -> RuleVector | None:
    return session.scalars(
        select(RuleVector).where(
            _scope(repo_full_name),
            RuleVector.capability == capability,
            RuleVector.tool == tool,
            RuleVector.rule_id == rule_id,
            RuleVector.status == status,
        )
    ).first()


def _required(name: str, value: str, limit: int) -> str:
    text = (value or "").strip()
    if not text:
        raise RuleVectorError(f"{name} is required: a rule vector is keyed by it")
    if len(text) > limit:
        raise RuleVectorError(f"{name} is longer than {limit} characters")
    return text


def propose(
    session: Session,
    *,
    repo_full_name: str | None,
    capability: str,
    tool: str,
    rule_id: str,
    asserted_by: str,
    vector: str | None = None,
    template_id: str | None = None,
    note: str = "",
    templates: Templates | None = None,
    now: datetime | None = None,
) -> RuleVector:
    """Record a proposal. Changes no score: nothing reads a proposal.

    From a template (`template_id`), by hand (`vector`), or both: a template
    edited before proposing keeps the template as `proposed_from`, so a reader
    can see where the first draft came from and that it was changed.
    """
    capability = _required("capability", capability, 32)
    tool = _required("tool", tool, 64)
    rule_id = _required("rule_id", rule_id, 512)
    proposed_from = ""
    if template_id:
        template = (templates or load_templates()).get(template_id)
        if template is None:
            raise RuleVectorError(
                f"No template {template_id!r} in {TEMPLATE_FILE}.yaml. Pass a "
                "vector instead, or one of the listed templates."
            )
        proposed_from = template.id
        vector = vector or template.vector
    if not vector:
        raise RuleVectorError("A proposal needs a template_id or a vector")
    normal = normalize_vector(vector)

    def active(state: str) -> RuleVector | None:
        return _active(
            session,
            repo_full_name=repo_full_name,
            capability=capability,
            tool=tool,
            rule_id=rule_id,
            status=state,
        )

    pending = active(PROPOSED)
    if pending is not None:
        raise RuleVectorConflictError(
            f"Rule vector {pending.id} is already proposed for this rule "
            f"({pending.vector}). Edit it, or retire it first."
        )
    current = active(CONFIRMED)
    if current is not None and current.vector == normal:
        raise RuleVectorConflictError(
            f"Rule vector {current.id} is already confirmed with this vector."
        )
    row = RuleVector(
        repo_full_name=repo_full_name,
        capability=capability,
        tool=tool,
        rule_id=rule_id,
        vector=normal,
        status=PROPOSED,
        vector_source="analyst",
        proposed_from=proposed_from,
        asserted_by=asserted_by,
        asserted_at=now or utcnow(),
        note=(note or "").strip(),
    )
    session.add(row)
    session.flush()
    return row


def _get(session: Session, row_id: str) -> RuleVector:
    row = session.get(RuleVector, row_id)
    if row is None:
        raise LookupError(f"No rule vector {row_id!r}")
    return row


def edit(
    session: Session,
    row_id: str,
    *,
    vector: str | None = None,
    note: str | None = None,
) -> RuleVector:
    """Change a proposal before anybody confirms it.

    A confirmed vector is not edited in place: that would change scores
    without a confirmation. Propose the change beside it and confirm that.
    """
    row = _get(session, row_id)
    if row.status != PROPOSED:
        raise RuleVectorConflictError(
            f"Rule vector {row.id} is {row.status}; only a proposal is edited. "
            "To change a confirmed vector, propose the new one and confirm it."
        )
    if vector is not None:
        row.vector = normalize_vector(vector)
    if note is not None:
        row.note = note.strip()
    session.flush()
    return row


def require_person(principal: Principal, verb: str) -> None:
    """Refuse anything but an authenticated human principal with write access.

    Checked here as well as at the route (`HumanDep`), so no other caller of
    this module (the CLI, a job, a future route) can confirm on an agent's or
    automation's behalf by forgetting the dependency.
    """
    if not (principal.is_human and principal.may_write):
        raise NotAPersonError(
            f"{verb} must be done by a person with the 'admin' role; the caller "
            f"is {principal.kind.value} '{principal.actor}'. An agent may propose "
            "a rule vector, never confirm one."
        )


def confirm(
    session: Session,
    row_id: str,
    *,
    principal: Principal,
    vector: str | None = None,
    note: str | None = None,
    now: datetime | None = None,
) -> tuple[RuleVector, RuleVector | None]:
    """A person confirms a proposal, optionally editing it first.

    Returns the confirmed row and the confirmed row it replaced, if any, which
    is retired in the same transaction. From this moment the rule's findings
    with no published vector are scored from it.
    """
    require_person(principal, "Confirming a rule vector")
    row = _get(session, row_id)
    if row.status != PROPOSED:
        raise RuleVectorConflictError(
            f"Rule vector {row.id} is {row.status}; only a proposal is confirmed."
        )
    if vector is not None:
        row.vector = normalize_vector(vector)
    if note is not None:
        row.note = note.strip()
    when = now or utcnow()
    replaced = _active(
        session,
        repo_full_name=row.repo_full_name,
        capability=row.capability,
        tool=row.tool,
        rule_id=row.rule_id,
        status=CONFIRMED,
    )
    if replaced is not None:
        replaced.status = RETIRED
        replaced.retired_by = principal.actor
        replaced.retired_at = when
    row.status = CONFIRMED
    row.confirmed_by = principal.actor
    row.confirmed_at = when
    session.flush()
    return row, replaced


def retire(
    session: Session,
    row_id: str,
    *,
    principal: Principal,
    note: str | None = None,
    now: datetime | None = None,
) -> RuleVector:
    """Withdraw a proposal or a confirmed vector.

    Withdrawing a proposal is any writer's call. Withdrawing a confirmed
    vector changes scores (its findings go back to unscored), so it is a
    person's, like confirming one.
    """
    row = _get(session, row_id)
    if row.status == RETIRED:
        raise RuleVectorConflictError(f"Rule vector {row.id} is already retired.")
    if row.status == CONFIRMED:
        require_person(principal, "Retiring a confirmed rule vector")
    row.status = RETIRED
    row.retired_by = principal.actor
    row.retired_at = now or utcnow()
    if note is not None and note.strip():
        row.note = note.strip()
    session.flush()
    return row


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _key(finding: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(finding.get("capability") or ""),
        str(finding.get("tool") or ""),
        str(finding.get("rule_id") or ""),
    )


def _repo_of(finding: Mapping[str, Any], fallback: str | None) -> str:
    return str(finding.get("asset_id") or finding.get("repo_full_name") or fallback or "")


def rows_for(
    session: Session,
    keys: Iterable[tuple[str, str, str]],
    repos: Iterable[str],
    statuses: Sequence[str],
) -> list[RuleVector]:
    """Rows in these states for these (capability, tool, rule) keys, in these
    repositories or estate-wide."""
    wanted = {k for k in keys if all(k)}
    if not wanted:
        return []
    repo_names = sorted({r for r in repos if r})
    rule_ids = sorted({k[2] for k in wanted})
    rows: list[RuleVector] = []
    for start in range(0, len(rule_ids), 500):
        chunk = rule_ids[start : start + 500]
        rows.extend(
            session.scalars(
                select(RuleVector).where(
                    RuleVector.rule_id.in_(chunk),
                    RuleVector.status.in_(list(statuses)),
                    or_(
                        RuleVector.repo_full_name.is_(None),
                        RuleVector.repo_full_name.in_(repo_names),
                    ),
                )
            )
        )
    return [r for r in rows if (r.capability, r.tool, r.rule_id) in wanted]


def confirmed_for(
    session: Session,
    findings: Iterable[Mapping[str, Any]],
    *,
    repo_full_name: str | None = None,
) -> dict[str, RuleVector]:
    """finding_id -> the confirmed rule vector that applies to it.

    The repository's own confirmed vector, else an estate-wide one. A finding
    whose tool is unknown matches nothing: the same rule id in two tools is
    two different claims, and guessing which would be scoring on a guess.
    """
    rows = list(findings)
    if not rows:
        return {}
    confirmed = rows_for(
        session,
        (_key(f) for f in rows),
        (_repo_of(f, repo_full_name) for f in rows),
        (CONFIRMED,),
    )
    by_key: dict[tuple[str | None, str, str, str], RuleVector] = {
        (r.repo_full_name, r.capability, r.tool, r.rule_id): r for r in confirmed
    }
    out: dict[str, RuleVector] = {}
    for finding in rows:
        key = _key(finding)
        repo = _repo_of(finding, repo_full_name)
        row = by_key.get((repo, *key)) or by_key.get((None, *key))
        if row is not None:
            out[str(finding.get("finding_id"))] = row
    return out


@dataclass
class RuleSummary:
    """One rule whose open findings no published source gives a vector."""

    capability: str
    tool: str
    rule_id: str
    title: str
    findings: int
    cwes: list[str]
    suggested: Template | None
    #: Proposed and confirmed rows that could apply here: this repository's
    #: and estate-wide.
    vectors: list[RuleVector]
    #: The confirmed row the resolver would use now, if any.
    applies: RuleVector | None


def _cwes_of(finding: Mapping[str, Any]) -> set[str]:
    import json

    raw = finding.get("cwe_ids_json")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = []
    found = _normal_cwes(raw if isinstance(raw, list) else [])
    found |= _normal_cwes([finding.get("rule_id") or ""])
    return found


def rules_without_vector(
    session: Session,
    findings: Sequence[Mapping[str, Any]],
    *,
    repo_full_name: str,
    templates: Templates | None = None,
) -> list[RuleSummary]:
    """The repository's rules whose open findings nothing publishes a vector
    for, most findings first, each with what would pre-fill it and any rule
    vector already proposed or confirmed for it.

    A rule stays listed after its vector is confirmed, marked as applying, so
    the same view is where a confirmed vector is retired or replaced.
    """
    from mykronos.environment import choose_vectors

    templates = templates or load_templates()
    published = choose_vectors(
        session, findings, repo_full_name=repo_full_name, analyst=False
    )
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for finding in findings:
        if str(finding.get("finding_id")) in published:
            continue
        key = _key(finding)
        if not key[0] or not key[2]:
            continue
        groups.setdefault(key, []).append(finding)

    active = rows_for(session, groups, [repo_full_name], (PROPOSED, CONFIRMED))
    out: list[RuleSummary] = []
    for key, members in groups.items():
        cwes: set[str] = set()
        for finding in members:
            cwes |= _cwes_of(finding)
        vectors = [
            r
            for r in active
            if (r.capability, r.tool, r.rule_id) == key
            and r.repo_full_name in (None, repo_full_name)
        ]
        vectors.sort(key=lambda r: (r.repo_full_name is None, r.status, r.asserted_at))
        confirmed = [r for r in vectors if r.status == CONFIRMED]
        own = [r for r in confirmed if r.repo_full_name == repo_full_name]
        out.append(
            RuleSummary(
                capability=key[0],
                tool=key[1],
                rule_id=key[2],
                title=str(members[0].get("title") or ""),
                findings=len(members),
                cwes=sorted(cwes, key=_cwe_number),
                suggested=templates.suggest(cwes, key[0]),
                vectors=vectors,
                applies=own[0] if own else (confirmed[0] if confirmed else None),
            )
        )
    out.sort(key=lambda r: (-r.findings, r.capability, r.tool, r.rule_id))
    return out


def as_dict(row: RuleVector) -> dict[str, Any]:
    """One row as the API and the audit log say it."""
    return {
        "id": row.id,
        "repo_full_name": row.repo_full_name,
        "scope": "repository" if row.repo_full_name else "estate",
        "capability": row.capability,
        "tool": row.tool,
        "rule_id": row.rule_id,
        "vector": row.vector,
        "base_score": base_score(row.vector) if row.vector else None,
        "status": row.status,
        "vector_source": row.vector_source,
        "proposed_from": row.proposed_from,
        "asserted_by": row.asserted_by,
        "asserted_at": row.asserted_at,
        "confirmed_by": row.confirmed_by,
        "confirmed_at": row.confirmed_at,
        "retired_by": row.retired_by,
        "retired_at": row.retired_at,
        "note": row.note,
    }
