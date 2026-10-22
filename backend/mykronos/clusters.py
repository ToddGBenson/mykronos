"""Finding clusters: one decision covering the findings it is actually about
(TheHub #60887, D-168).

`finding_id` (spec 05 §5) answers "is this the same finding as last scan's",
and answers it deliberately narrowly: the same CVE in twenty images is twenty
findings, because an acceptance recorded against one image used to cover the
other nineteen silently (`fingerprint.FINGERPRINT_CONTAINER`). That is the
right identity for a *record*. It is the wrong unit for a *decision*: the
person triaging the stdlib CVE reads the same advisory twenty times and
answers it twenty times.

A cluster is the unit of the decision. It never replaces `finding_id` -
every member keeps its own row, its own status and its own audit entry - it
only says which open findings one human judgement plausibly covers, and why.

**Deterministic and explainable, nothing else.** Every rule here is a pure
function of fields already on the row; there is no similarity score and no
model. A cluster that cannot say in one sentence why its members belong
together is not built. Three rules, tried in order, each finding in exactly
one cluster:

1. **advisory** - a dependency or container finding: the same advisory (the
   CVE the rule or title names, else the rule id) on the same package, in any
   image of any repository.
2. **location** - a code finding: the same weakness (its CWE set when the
   scanner gave one, else the rule id) in the same file at the same place
   (the enclosing symbol, else the line), whichever scanner reported it. The
   CWE is what lets two scanners' differently-named rules for one defect meet.
3. **single** - everything else is a cluster of one, keyed on its own
   `finding_id`, so the grouped view is still the whole queue.

On top of rule 1, **a provisional advisory folds into its CVE**: a Debian
`TEMP-` finding joins the CVE cluster on the same package at the same version
in the same repository - but only when exactly one CVE is open there. Four
placeholders became six CVEs on 2026-09-11 (`prior_disposition`), so with
more than one candidate there is no pairing to infer and the placeholder
stays on its own, with the reason saying so.

**Stable ids.** A cluster id is a hash of the rule and its key, never of the
members: a rescan that adds a twenty-first image keeps the id, and so does one
that removes a member. A singleton keeps its id when a second member arrives
only if the arriving one shares its key - which is the definition of joining.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from mykronos.fingerprint import image_repository
from mykronos.prior_disposition import is_provisional_advisory
from mykronos.threat_intel import extract_cve

ADVISORY = "advisory"
LOCATION = "location"
SINGLE = "single"

#: Worst first. `info` and anything unknown sort last.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEP = "\x1f"


def severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(str(severity or "").lower(), 5)


@dataclass(frozen=True)
class ClusterKey:
    """Which rule placed a finding, and the fields it matched on."""

    kind: str
    parts: tuple[str, ...]

    @property
    def cluster_id(self) -> str:
        digest = hashlib.sha256(_SEP.join((self.kind, *self.parts)).encode("utf-8"))
        return f"cl_{digest.hexdigest()[:24]}"


def normalise_path(path: Any) -> str:
    """`./src\\app.py` and `/src/app.py` are the same file to two scanners.

    Not case-folded: on the filesystems these repositories build on, `App.py`
    and `app.py` are different files.
    """
    text = str(path or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _cwes(row: Mapping[str, Any]) -> tuple[str, ...]:
    raw = row.get("cwe_ids_json")
    if not raw:
        return ()
    try:
        values = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return ()
    if not isinstance(values, list):
        return ()
    return tuple(sorted({str(v).strip().upper() for v in values if str(v).strip()}))


def advisory_of(row: Mapping[str, Any]) -> str:
    """The advisory a dependency finding is about: the CVE its rule or title
    names, else the rule id itself (a GHSA, a RUSTSEC, a `TEMP-` placeholder)."""
    return extract_cve(row.get("rule_id"), row.get("title")) or str(
        row.get("rule_id") or ""
    ).strip().upper()


def weakness_of(row: Mapping[str, Any]) -> str:
    """The weakness a code finding reports: its CWE set, else its rule id.

    The CWE is the only vocabulary two scanners share - CodeQL's
    `py/sql-injection` and Semgrep's `formatted-sql-query` are the same CWE-89
    and nothing else says so.
    """
    cwes = _cwes(row)
    if cwes:
        return "+".join(cwes)
    return str(row.get("rule_id") or "").strip()


def location_of(row: Mapping[str, Any]) -> str:
    """Where in the file: the enclosing symbol when the adapter found one,
    which survives the line moving; the line otherwise; the file alone when
    the scanner gave neither."""
    symbol = str(row.get("symbol") or "").strip()
    if symbol:
        return f"symbol {symbol}"
    line = row.get("line_start")
    if line not in (None, ""):
        return f"line {line}"
    return "file"


def key_for(row: Mapping[str, Any]) -> ClusterKey:
    """The rule that places one finding, before any provisional folding."""
    package = str(row.get("package_name") or "").strip()
    if package:
        return ClusterKey(ADVISORY, (advisory_of(row), package.lower()))
    path = normalise_path(row.get("file_path"))
    if path:
        return ClusterKey(
            LOCATION,
            (str(row.get("repo_full_name") or ""), weakness_of(row), path, location_of(row)),
        )
    return ClusterKey(SINGLE, (str(row.get("finding_id") or ""),))


@dataclass
class Cluster:
    """Open findings one decision covers, and the sentence that says why."""

    cluster_id: str
    kind: str
    key: tuple[str, ...]
    members: list[dict[str, Any]] = field(default_factory=list)
    #: `TEMP-` findings folded in, by finding_id -> the sentence for each.
    folded: dict[str, str] = field(default_factory=dict)
    #: A placeholder that could not fold, and why.
    unfolded_note: str = ""

    @property
    def member_ids(self) -> list[str]:
        return [str(m["finding_id"]) for m in self.members]

    @property
    def representative(self) -> dict[str, Any]:
        """Worst first, then oldest, then lowest id - so the same set always
        names the same representative."""
        return min(
            self.members,
            key=lambda m: (
                severity_rank(m.get("severity")),
                m.get("first_seen_at") or datetime.max,
                str(m.get("finding_id")),
            ),
        )

    @property
    def max_severity(self) -> str:
        return str(self.representative.get("severity") or "info")

    @property
    def repos(self) -> list[str]:
        return sorted({str(m.get("repo_full_name") or "") for m in self.members})

    @property
    def images(self) -> list[str]:
        found = set()
        for m in self.members:
            image = str(m.get("image") or "").strip()
            if image:
                found.add(image_repository(image))
        return sorted(found)

    @property
    def scanners(self) -> list[str]:
        return sorted({str(m.get("capability") or "") for m in self.members})

    @property
    def reason(self) -> str:
        count = len(self.members)
        if self.kind == ADVISORY:
            advisory, package = self.key
            sentence = f"Same advisory {advisory} in package {package}"
            spread = [_plural(len(self.repos), "repository", "repositories")]
            if self.images:
                spread.append(_plural(len(self.images), "image", "images"))
            sentence += f": {_plural(count, 'finding', 'findings')} across {' and '.join(spread)}."
        elif self.kind == LOCATION:
            _repo, weakness, path, where = self.key
            sentence = (
                f"Same weakness {weakness} in {path} at {where}: "
                f"{_plural(count, 'finding', 'findings')}"
            )
            if len(self.scanners) > 1:
                sentence += f" from {', '.join(self.scanners)}"
            sentence += "."
        else:
            sentence = "No other open finding shares its advisory or its location."
        if self.folded:
            sentence += " " + " ".join(self.folded[fid] for fid in sorted(self.folded))
        if self.unfolded_note:
            sentence += " " + self.unfolded_note
        return sentence

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "kind": self.kind,
            "reason": self.reason,
            "representative_id": str(self.representative["finding_id"]),
            "member_ids": self.member_ids,
            "count": len(self.members),
            "max_severity": self.max_severity,
            "repos": self.repos,
            "images": self.images,
        }


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def build(rows: Iterable[Mapping[str, Any]]) -> list[Cluster]:
    """Cluster open findings. Each row lands in exactly one cluster.

    Ordered worst-first, then by size, then by id, so a page of clusters is
    stable between two requests over the same rows.
    """
    pool = [dict(r) for r in rows]
    by_id: dict[str, Cluster] = {}
    placement: dict[str, ClusterKey] = {}
    for row in pool:
        key = key_for(row)
        placement[str(row["finding_id"])] = key
        cluster = by_id.get(key.cluster_id)
        if cluster is None:
            cluster = by_id[key.cluster_id] = Cluster(key.cluster_id, key.kind, key.parts)
        cluster.members.append(row)

    _fold_provisional(pool, placement, by_id)

    for cluster in by_id.values():
        cluster.members.sort(
            key=lambda m: (severity_rank(m.get("severity")), str(m.get("finding_id")))
        )
    return sorted(
        (c for c in by_id.values() if c.members),
        key=lambda c: (severity_rank(c.max_severity), -len(c.members), c.cluster_id),
    )


def _fold_provisional(
    rows: list[dict[str, Any]],
    placement: dict[str, ClusterKey],
    by_id: dict[str, Cluster],
) -> None:
    """Move each `TEMP-` finding into the one CVE cluster it can only be.

    Matched on (repository, capability, package, version) - the tuple a
    placeholder's renaming leaves untouched (`prior_disposition.for_findings`)
    - against open findings whose advisory is a real CVE.
    """
    cves: dict[tuple[str, str, str, str], set[str]] = {}
    for row in rows:
        key = placement[str(row["finding_id"])]
        if key.kind != ADVISORY or is_provisional_advisory(row.get("rule_id")):
            continue
        if not key.parts[0].startswith("CVE-"):
            continue
        version = str(row.get("package_version") or "")
        if not version:
            continue
        cves.setdefault(_fold_tuple(row), set()).add(key.cluster_id)

    for row in rows:
        if not is_provisional_advisory(row.get("rule_id")):
            continue
        if not row.get("package_name") or not row.get("package_version"):
            continue
        finding_id = str(row["finding_id"])
        home = by_id[placement[finding_id].cluster_id]
        targets = sorted(cves.get(_fold_tuple(row), set()))
        if len(targets) == 1:
            target = by_id[targets[0]]
            home.members = [m for m in home.members if str(m["finding_id"]) != finding_id]
            target.members.append(row)
            target.folded[finding_id] = (
                f"Folded in {row.get('rule_id')}: a Debian placeholder on the same "
                f"package at {row.get('package_version')} in {row.get('repo_full_name')}, "
                f"where {target.key[0]} is the only CVE open."
            )
        elif len(targets) > 1:
            home.unfolded_note = (
                f"{row.get('rule_id')} is a placeholder, but {len(targets)} CVEs are open "
                "on the same package and version, so it is not folded into any of them."
            )


def _fold_tuple(row: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(row.get("repo_full_name") or ""),
        str(row.get("capability") or ""),
        str(row.get("package_name") or "").strip().lower(),
        str(row.get("package_version") or ""),
    )


def find(clusters: Iterable[Cluster], cluster_id: str) -> Cluster | None:
    for cluster in clusters:
        if cluster.cluster_id == cluster_id:
            return cluster
    return None
