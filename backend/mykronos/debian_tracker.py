"""Debian security-tracker states as false-positive evidence (TheHub #60744).

OS-package CVEs from container scans are otherwise triaged on severity alone,
yet Debian publishes a decision for most of them. Its security tracker records,
per source package, CVE and release, whether the release is affected and
whether the security team will ship an advisory. Three of those answers say a
finding in that release is not worth a person's attention:

- `not-affected` - resolved with fixed version `0`: the release never shipped
  the vulnerable code.
- `no-dsa` - open, but marked as not warranting a security advisory.
- `will-not-fix` - no-dsa with the `ignored` reason.

The rule this module holds to: a deterministic distribution decision may
*label* a finding `likely_false_positive` with the tracker URL and state cited
(`patchwork/triage.py`). It never closes, dismisses or re-keys anything, and
`auto_triage` has no rule that reads it.

The tracker JSON is large and changes daily, so it is fetched by `refresh()`
over HTTPS into a cache file that records its fetch time, never at request
time. A copy older than `STALE_AFTER` is not used, and saying so is a logged
warning: a stale "no-dsa" may since have become a fix.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mykronos.threat_intel import extract_cve

logger = logging.getLogger(__name__)

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
#: Where a person reads the decision for one CVE.
CVE_URL = "https://security-tracker.debian.org/tracker/{cve}"
#: Older than this, the cached copy is not used.
STALE_AFTER = timedelta(days=7)
TIMEOUT = 120.0

NOT_AFFECTED = "not-affected"
NO_DSA = "no-dsa"
WILL_NOT_FIX = "will-not-fix"
#: The states that count as false-positive evidence. Everything else the
#: tracker says (open, resolved with a real fix, undetermined) is not.
FALSE_POSITIVE_STATES = (NOT_AFFECTED, NO_DSA, WILL_NOT_FIX)

#: Debian major version -> codename, for the releases the tracker covers.
#: Trivy reports the OS as `debian 12.7`; the tracker is keyed by codename.
CODENAMES: Mapping[str, str] = {
    "9": "stretch",
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}
_DEBIAN_VERSION = re.compile(r"^\s*debian\s+(?P<major>\d+)(?:\.\d+)*\s*$", re.IGNORECASE)


def release_codename(text: str | None) -> str | None:
    """`bookworm` for `debian 12.7` or `bookworm`; None for anything else.

    A non-Debian OS, a bare `debian` and an unknown major version are None:
    a decision for one release says nothing about another.
    """
    if not text:
        return None
    value = str(text).strip()
    if value.lower() in CODENAMES.values():
        return value.lower()
    match = _DEBIAN_VERSION.match(value)
    if match is None:
        return None
    return CODENAMES.get(match.group("major"))


@dataclass(frozen=True)
class TrackerState:
    """One tracker decision that counts as false-positive evidence."""

    cve: str
    source_package: str
    release: str
    state: str
    note: str = ""

    @property
    def url(self) -> str:
        return CVE_URL.format(cve=self.cve)

    def as_evidence(self) -> dict[str, Any]:
        return {
            "type": "debian_security_tracker",
            "cve": self.cve,
            "source_package": self.source_package,
            "release": self.release,
            "state": self.state,
            "note": self.note,
            "url": self.url,
            # Evidence for a label, never for a close (AC2).
            "closes_finding": False,
        }


@dataclass
class TrackerSnapshot:
    """The tracker JSON and when it was fetched."""

    data: Mapping[str, Any]
    fetched_at: datetime
    _by_cve: dict[str, list[str]] | None = field(default=None, repr=False, compare=False)

    def age(self, now: datetime) -> timedelta:
        return now - self.fetched_at

    def is_stale(self, now: datetime) -> bool:
        return self.age(now) > STALE_AFTER

    def sources_for(self, cve: str) -> list[str]:
        """The source packages the tracker records `cve` against."""
        if self._by_cve is None:
            index: dict[str, list[str]] = {}
            for source, cves in self.data.items():
                if isinstance(cves, Mapping):
                    for cve_id in cves:
                        index.setdefault(str(cve_id), []).append(str(source))
            self._by_cve = index
        return self._by_cve.get(cve, [])

    def state(self, source: str, cve: str, release: str) -> TrackerState | None:
        """The false-positive state for this package, CVE and release, if any."""
        entry = (self.data.get(source) or {}).get(cve)
        releases = entry.get("releases") if isinstance(entry, Mapping) else None
        decision = releases.get(release) if isinstance(releases, Mapping) else None
        if not isinstance(decision, Mapping):
            return None
        status = str(decision.get("status") or "")
        fixed = str(decision.get("fixed_version") or "").strip()
        if status == "resolved" and fixed == "0":
            return TrackerState(cve, source, release, NOT_AFFECTED)
        if status == "open" and decision.get("nodsa") is not None:
            note = str(decision.get("nodsa") or "")
            if str(decision.get("nodsa_reason") or "") == "ignored":
                return TrackerState(cve, source, release, WILL_NOT_FIX, note)
            return TrackerState(cve, source, release, NO_DSA, note)
        return None


def usable(snapshot: TrackerSnapshot | None, now: datetime) -> TrackerSnapshot | None:
    """The snapshot if it is fresh enough to cite; None, with a warning, if not."""
    if snapshot is None:
        return None
    if snapshot.is_stale(now):
        days = snapshot.age(now).total_seconds() / 86400
        logger.warning(
            "Debian security tracker copy is stale: fetched %s, %.1f days ago, older "
            "than the %d days allowed; its states are not used as false-positive "
            "evidence until it is refreshed.",
            snapshot.fetched_at.isoformat(),
            days,
            STALE_AFTER.days,
        )
        return None
    return snapshot


def _fixed_version(finding: Mapping[str, Any]) -> str:
    raw = finding.get("raw_finding_json")
    candidates = [finding.get("fixed_version")]
    if isinstance(raw, Mapping):
        candidates.append(raw.get("fixed_version"))
    for value in candidates:
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _release(finding: Mapping[str, Any]) -> str | None:
    raw = finding.get("raw_finding_json")
    for value in (
        finding.get("os_release"),
        finding.get("base_os"),
        raw.get("base_os") if isinstance(raw, Mapping) else None,
    ):
        codename = release_codename(value)
        if codename is not None:
            return codename
    return None


def evidence_for(
    finding: Mapping[str, Any], snapshot: TrackerSnapshot | None, now: datetime
) -> TrackerState | None:
    """The tracker decision that makes `finding` a likely false positive, if any.

    None - and the finding is triaged as it is today - when the snapshot is
    missing or stale, the finding names no CVE, package or Debian release, the
    tracker has no false-positive state for that release, or the finding's own
    fixed-version data contradicts the tracker (a scanner that reports a fix
    for this release disagrees with "not-affected", "no-dsa" and
    "will-not-fix" alike, and a disagreement is a reason to look, not to
    quieten).
    """
    snapshot = usable(snapshot, now)
    if snapshot is None:
        return None
    cve = extract_cve(str(finding.get("rule_id") or ""), str(finding.get("title") or ""))
    release = _release(finding)
    if cve is None or release is None:
        return None
    if _fixed_version(finding):
        return None

    package = str(finding.get("source_package") or finding.get("package_name") or "")
    source = package if package and cve in (snapshot.data.get(package) or {}) else None
    if source is None:
        # Trivy names the binary package (libssl3), the tracker the source
        # (openssl). A CVE the tracker records against exactly one source
        # package can only be about that source; with two or more, which one
        # this binary came from is unknown and nothing is claimed.
        sources = snapshot.sources_for(cve)
        if len(sources) != 1:
            return None
        source = sources[0]
    return snapshot.state(source, cve, release)


# -- the cache ---------------------------------------------------------------


def save(snapshot: TrackerSnapshot, path: Path) -> None:
    """Write the snapshot with its fetch time, atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            {
                "source": TRACKER_URL,
                "fetched_at": snapshot.fetched_at.isoformat(),
                "data": snapshot.data,
            }
        ),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def load_cached(path: Path, *, now: datetime) -> TrackerSnapshot | None:
    """The cached snapshot if present, readable and fresh; else None, with a warning."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning(
            "Debian security tracker has no cached copy at %s; tracker states are "
            "not used as false-positive evidence.",
            path,
        )
        return None
    except (OSError, ValueError) as exc:
        logger.warning("Debian security tracker cache at %s is unreadable: %s", path, exc)
        return None
    try:
        fetched_at = datetime.fromisoformat(str(document["fetched_at"]))
        data = document["data"]
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Debian security tracker cache at %s is malformed: %s", path, exc)
        return None
    if fetched_at.tzinfo is None:
        fetched_at = fetched_at.replace(tzinfo=UTC)
    if not isinstance(data, Mapping):
        logger.warning("Debian security tracker cache at %s holds no tracker data", path)
        return None
    return usable(TrackerSnapshot(data=data, fetched_at=fetched_at), now)


def default_fetch() -> object:
    """The tracker JSON, over HTTPS."""
    import httpx2

    response = httpx2.get(TRACKER_URL, timeout=TIMEOUT, follow_redirects=True)
    response.raise_for_status()
    if not str(response.url).startswith("https://"):
        raise OSError(f"the tracker redirected off HTTPS to {response.url}")
    return response.json()


def refresh(
    path: Path,
    *,
    fetch: Callable[[], object] = default_fetch,
    now: datetime | None = None,
) -> bool:
    """Fetch the tracker and replace the cache. False, with a warning, on failure.

    A failed fetch leaves the previous copy in place; whether that copy is
    still usable is `load_cached`'s 7-day question, not this one's.
    """
    try:
        payload = fetch()
    except Exception as exc:  # noqa: BLE001 - any failure is "unreachable"
        logger.warning(
            "Debian security tracker unreachable (%s); the cached copy, if any, is kept.",
            exc,
        )
        return False
    if not isinstance(payload, Mapping):
        logger.warning(
            "Debian security tracker returned %s, not a JSON object; cache not replaced.",
            type(payload).__name__,
        )
        return False
    save(TrackerSnapshot(data=payload, fetched_at=now or datetime.now(UTC)), path)
    return True
