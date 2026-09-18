"""A provisional advisory id becoming a CVE must not silently re-ask a settled
question (#280).

Debian's security tracker issues a placeholder identifier —
`TEMP-0000000-B05303` — for a vulnerability that has no CVE number yet. When
one is assigned, the placeholder is retired and the same vulnerability is
reported under the CVE. Nothing about the package changes; the *name* changes.

`finding_id` is derived from `rule_id` among other things (spec 05 §5), so
that rename is a new finding. **Observed 2026-09-11**, twice: a Trivy database
update between two container scans of `libpcre2-8-0` `10.46-1~deb13u1` retired
four `TEMP-*` findings — each one accepted, with a written reason and a review
date — and opened six `CVE-2026-891xx` ones for the same package at the same
version, on an image that had not changed. The investigation behind the
acceptance (`apt-cache policy`: Installed == Candidate, no vendor fix) was
then done a second time, reaching the same conclusion.

**What this module does, and deliberately does not do.** It surfaces the
earlier decision on the new row. It does not move it. Four placeholders became
*six* CVEs, which is the whole argument against carrying the disposition
automatically: there is no pairing to infer, and applying an acceptance to a
vulnerability nobody has looked at would silently suppress real findings —
the direction this codebase refuses (spec 04 §6). Re-deciding is fine;
re-deciding without being told you already decided is the waste.

**Why only provisional identifiers.** The tempting general rule — "any prior
acceptance on the same package and version" — fires for genuinely distinct
CVEs in the same package, which is the common case for an OS package and
would bury the signal in noise. A `TEMP-` id is *by construction* a name due
to be replaced, so a decision recorded under one, against the same package at
the same version, is evidence about the row in front of you rather than a
coincidence of packaging.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

#: Statuses that record a person's judgement, as opposed to an observation a
#: scanner or the reconciler owns. Same set as `carry_forward.HUMAN_DISPOSITIONS`
#: — restated rather than imported because that module is about code findings
#: and this one is about packages, and a shared constant would imply the two
#: mechanisms move together.
DECIDED_STATUSES: tuple[str, ...] = ("accepted_risk", "false_positive", "suppressed")

#: Debian's placeholder form: `TEMP-0000000-B05303`. Anchored and specific, so
#: a rule a tool happens to call `TEMPLATE-INJECTION` is not read as a
#: placeholder.
_PROVISIONAL = re.compile(r"^TEMP-\d+-[0-9A-Za-z]+$")

#: How each disposition reads when it is being reported as precedent.
_VERB = {
    "accepted_risk": "previously accepted as",
    "false_positive": "previously dismissed as a false positive under",
    "suppressed": "previously suppressed under",
}


def is_provisional_advisory(rule_id: str | None) -> bool:
    """Whether this identifier is a placeholder awaiting a real one.

    Only Debian's `TEMP-` form for now. GHSA and CVE ids co-exist for the same
    vulnerability rather than replacing one another, so neither is provisional
    in the sense that matters here: nothing retires them.
    """
    return bool(rule_id) and bool(_PROVISIONAL.match(str(rule_id)))


@dataclass(frozen=True)
class PriorDisposition:
    """A decision recorded under an identifier that has since been replaced."""

    finding_id: str
    rule_id: str
    status: str
    package_name: str
    package_version: str
    #: When the person decided, from `resolved_at`. None for a row written
    #: before that column was populated — reported as absent, never guessed.
    decided_at: datetime | None
    accepted_reason_code: str | None
    accepted_until: date | None

    def describe(self) -> str:
        """One sentence, for a person deciding whether to look further."""
        parts = [f"{_VERB.get(self.status, 'previously dispositioned under')} {self.rule_id}"]
        if self.decided_at is not None:
            parts.append(f"on {self.decided_at.date().isoformat()}")
        sentence = " ".join(parts)
        if self.accepted_reason_code:
            sentence += f" — reason: {self.accepted_reason_code}"
        if self.accepted_until is not None:
            sentence += f" — review {self.accepted_until.isoformat()}"
        return sentence

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "status": self.status,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "decided_at": self.decided_at,
            "accepted_reason_code": self.accepted_reason_code,
            "accepted_until": self.accepted_until,
            "summary": self.describe(),
        }


def _key(row: Mapping[str, Any]) -> tuple[str, str, str] | None:
    package = row.get("package_name")
    version = row.get("package_version")
    if not package or not version:
        # A dependency finding with no version cannot be matched: "accepted for
        # 10.46-1~deb13u1" says nothing about an unknown version, and treating
        # the two as the same row is how an acceptance gets shown against a
        # package that has since been upgraded.
        return None
    return (str(row.get("capability") or ""), str(package), str(version))


def _decided(candidate: PriorDisposition) -> tuple[datetime, str]:
    # A missing decision date sorts oldest rather than newest: an undated
    # decision must never outrank a dated one.
    return (candidate.decided_at or datetime.min, candidate.finding_id)


def _load(catalog: Any, repo_full_name: str) -> dict[tuple[str, str, str], list[PriorDisposition]]:
    """Every decision this repository holds under a provisional identifier.

    One query for the whole page. Scoped to a single asset and to dispositioned
    package findings, which on this estate is tens of rows, not thousands.
    """
    if not catalog.all_files("findings"):
        return {}

    statuses = ", ".join("?" for _ in DECIDED_STATUSES)
    rows = catalog.query(
        # asset_id, not repo_full_name (spec 14 §5) — the same column
        # `dashboard._status_clause` filters on.
        "SELECT finding_id, capability, rule_id, package_name, package_version, "
        "status, resolved_at, accepted_reason_code, accepted_until "
        "FROM findings "
        "WHERE asset_id = ? AND package_name IS NOT NULL "
        f"AND package_version IS NOT NULL AND status IN ({statuses})",
        [repo_full_name, *DECIDED_STATUSES],
    )

    found: dict[tuple[str, str, str], list[PriorDisposition]] = {}
    for row in rows:
        rule_id = str(row[2])
        if not is_provisional_advisory(rule_id):
            continue
        candidate = PriorDisposition(
            finding_id=str(row[0]),
            rule_id=rule_id,
            status=str(row[5]),
            package_name=str(row[3]),
            package_version=str(row[4]),
            decided_at=row[6],
            accepted_reason_code=None if row[7] is None else str(row[7]),
            accepted_until=row[8],
        )
        key = (str(row[1]), candidate.package_name, candidate.package_version)
        found.setdefault(key, []).append(
            candidate
        )
    return found


def for_findings(
    catalog: Any, repo_full_name: str, rows: Iterable[Mapping[str, Any]]
) -> dict[str, PriorDisposition]:
    """Map each supplied finding to the decision it is about to re-ask, if any.

    Matched on `(capability, package_name, package_version)` within one
    repository, which is the tuple the rename leaves untouched. `file_path` is
    deliberately not part of it: a container scan's path is the image layer the
    package was found in, and the same package at the same version is the same
    decision wherever a scanner happened to attribute it.
    """
    wanted = [(str(row["finding_id"]), _key(row), str(row.get("rule_id") or "")) for row in rows]
    if not any(key for _fid, key, _rule in wanted):
        return {}

    found = _load(catalog, repo_full_name)
    if not found:
        return {}

    matched: dict[str, PriorDisposition] = {}
    for finding_id, key, rule_id in wanted:
        if key is None:
            continue
        candidates = [c for c in found.get(key, ()) if c.rule_id != rule_id]
        if not candidates:
            continue
        # The most recent decision. Several placeholders on one package is the
        # normal shape of this defect — four became six — and the newest is the
        # one whose reasoning is most likely still current.
        matched[finding_id] = max(candidates, key=_decided)
    return matched


def best(*candidates: PriorDisposition | None) -> PriorDisposition | None:
    """The most recent of several, for a row that stands for more than one
    occurrence. None when there is nothing to report."""
    present = [c for c in candidates if c is not None]
    if not present:
        return None
    return max(present, key=_decided)
