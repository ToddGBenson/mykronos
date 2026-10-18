"""Where CVSS vectors come from, and which one a finding is scored from.

Two jobs, kept apart from `cvss.py` (which does the arithmetic):

1. **Keep the advisory vectors scanners already publish.** Trivy writes the
   CVSS vectors of the advisory it matched as rule properties in its SARIF --
   `cvssv2_vector`, `cvssv3_vector` and, from 0.76, `cvssv40_vector`, each with
   a score beside it (`tests/data/trivy/`). Until TheHub #60824 every one was
   discarded at ingest, so a finding could only ever be scored from NVD, and
   only for an identifier NVD had scored. They are now kept on the finding as
   `raw_finding_json["cvss_vectors"]`, a list of
   `{version, vector, source, base_score?}`. grype's and osv-scanner's SARIF
   carry `security-severity` and no vector (checked against grype 0.87.0 and
   0.120.1 and osv-scanner 2.2.3), so their findings get no key at all.

2. **Choose one** (`choose_vector`). D1 of the environmental-rescoring epic:
   CVSS 3.1 is primary, v4.0 is stored and shown but not rescored, because the
   environmental formula implemented here is v3's. Order: NVD 3.1/3.0, then
   an advisory 3.1, then an advisory 3.0, then v4.0 (NVD's before an
   advisory's) shown only. v2 is never chosen.

Not part of finding identity: `fingerprint` reads only `image` and the
identity marker out of `raw_finding_json`, so adding the list re-keys nothing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

from mykronos import cvss

#: The key the vectors are kept under in `raw_finding_json`.
RAW_KEY = "cvss_vectors"

#: `cvssv3_vector`, `cvssv40_vector`, `cvssv2_vector` -- Trivy's spelling. The
#: version is read from the vector string, not from this name.
_PROPERTY = re.compile(r"^cvss(?:v\d+)?_vector$", re.IGNORECASE)
_PREFIXED = re.compile(r"^CVSS:(?P<version>3\.0|3\.1|4\.0)/[A-Z]+:[A-Za-z]+")
#: A v2 vector has no prefix; `Au:` (authentication) exists only in v2.
_V2 = re.compile(r"^\(?AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]")

#: Order an entry list is written in: newest version first.
_ORDER = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}

VectorSource = Literal["nvd", "advisory"]


def version_of(vector: str) -> str | None:
    """`3.1`, `3.0`, `4.0` or `2.0`, read from the vector itself, else None."""
    match = _PREFIXED.match(vector)
    if match:
        return match.group("version")
    if _V2.match(vector):
        return "2.0"
    return None


def _score_beside(properties: dict[str, Any], key: str) -> float | None:
    """The score Trivy writes next to a vector: `cvssv3_baseScore` beside
    `cvssv3_vector`, `cvssv2_score` beside `cvssv2_vector`."""
    stem = key[: -len("_vector")]
    for candidate in (f"{stem}_baseScore", f"{stem}_score"):
        value = properties.get(candidate)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return float(value)
    return None


def sarif_rule_vectors(raw_output: bytes | str, *, source: str) -> dict[str, list[dict[str, Any]]]:
    """Rule id -> the CVSS vectors that rule's properties publish.

    An unreadable document, or one with no vectors, is an empty table: the
    adapters this feeds already report unparseable SARIF on their own.
    """
    try:
        document = json.loads(raw_output)
    except (ValueError, UnicodeDecodeError, TypeError):
        return {}
    if not isinstance(document, dict):
        return {}

    table: dict[str, list[dict[str, Any]]] = {}
    for run in document.get("runs") or []:
        if not isinstance(run, dict):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            if not isinstance(rule, dict) or not rule.get("id"):
                continue
            properties = rule.get("properties")
            if not isinstance(properties, dict):
                continue
            entries: list[dict[str, Any]] = []
            seen: set[str] = set()
            for key in sorted(properties):
                value = properties[key]
                if not _PROPERTY.match(key) or not isinstance(value, str):
                    continue
                vector = value.strip()
                version = version_of(vector)
                if version is None or vector in seen:
                    continue
                seen.add(vector)
                entry: dict[str, Any] = {"version": version, "vector": vector, "source": source}
                score = _score_beside(properties, key)
                if score is not None:
                    entry["base_score"] = score
                entries.append(entry)
            if entries:
                entries.sort(key=lambda e: _ORDER.get(e["version"], 9))
                table[str(rule["id"])] = entries
    return table


def attach(findings: Iterable[Any], raw_output: bytes | str, *, source: str) -> int:
    """Copy each finding's rule vectors onto `raw_finding_json[RAW_KEY]`.

    Returns how many findings got vectors. A finding whose rule published none
    is left without the key -- absent means the tool said nothing.
    """
    table = sarif_rule_vectors(raw_output, source=source)
    if not table:
        return 0
    attached = 0
    for finding in findings:
        vectors = table.get(finding.rule_id)
        raw = finding.raw_finding_json
        if vectors and isinstance(raw, dict):
            raw[RAW_KEY] = [dict(entry) for entry in vectors]
            attached += 1
    return attached


def from_raw(raw_finding_json: object) -> list[dict[str, Any]]:
    """The vectors kept on one finding's raw record, or `[]`."""
    if isinstance(raw_finding_json, str):
        try:
            raw_finding_json = json.loads(raw_finding_json)
        except ValueError:
            return []
    if not isinstance(raw_finding_json, dict):
        return []
    vectors = raw_finding_json.get(RAW_KEY)
    if not isinstance(vectors, list):
        return []
    return [entry for entry in vectors if isinstance(entry, dict)]


@dataclass(frozen=True)
class VectorChoice:
    """The vector a finding's severity is read from, and on what terms.

    `rescored` is False for v4.0: shown, never fed to the v3 environmental
    formula. `base_score` is set only where it was published beside a v4.0
    vector -- for v3 the score is computed from the vector, never copied.
    """

    vector: str
    version: str
    source: VectorSource
    rescored: bool
    base_score: float | None = None


def _scoreable_v3(vector: str | None) -> str | None:
    """The 3.x version of a vector `cvss.score` can actually score, else None."""
    if not vector or version_of(vector) not in ("3.1", "3.0"):
        return None
    try:
        cvss.parse(vector)
    except cvss.VectorError:
        return None
    return version_of(vector)


def _float(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def choose_vector(
    *,
    nvd_v3: str | None,
    nvd_v4: str | None = None,
    nvd_v4_base_score: float | None = None,
    advisory: Iterable[Any] = (),
) -> VectorChoice | None:
    """NVD 3.1/3.0 > advisory 3.1 > advisory 3.0 > v4.0 (shown, not rescored).

    A 3.x vector that does not parse is passed over rather than chosen, so a
    malformed advisory entry can neither hide a usable one behind it nor turn
    the whole block into nothing.
    """
    version = _scoreable_v3(nvd_v3)
    if nvd_v3 and version:
        return VectorChoice(vector=nvd_v3, version=version, source="nvd", rescored=True)

    entries = [
        entry
        for entry in advisory
        if isinstance(entry, dict) and isinstance(entry.get("vector"), str)
    ]
    for wanted in ("3.1", "3.0"):
        for entry in entries:
            vector = entry["vector"].strip()
            if _scoreable_v3(vector) == wanted:
                return VectorChoice(
                    vector=vector, version=wanted, source="advisory", rescored=True
                )

    if nvd_v4 and version_of(nvd_v4) == "4.0":
        return VectorChoice(
            vector=nvd_v4,
            version="4.0",
            source="nvd",
            rescored=False,
            base_score=_float(nvd_v4_base_score),
        )
    for entry in entries:
        vector = entry["vector"].strip()
        if version_of(vector) == "4.0":
            return VectorChoice(
                vector=vector,
                version="4.0",
                source="advisory",
                rescored=False,
                base_score=_float(entry.get("base_score")),
            )
    return None
