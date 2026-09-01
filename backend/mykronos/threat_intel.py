"""Public exploitation data, matched against this portfolio's findings (spec 17 §4).

Two feeds, both public, both unauthenticated, both about vulnerabilities in
general rather than about any repository's own content — which is the
distinction that matters here. `ai_classifier_url` (spec 06 §5, spec 12 §5.2)
is opt-in because using it means a repository's source or diff leaves the
platform; fetching a public catalog of CVEs sends nothing anywhere, and this
module needs no equivalent gate. (`fix_generator_url` was the other example
until D-096 withdrew it — it never made a call to withhold.)

- **CISA KEV** — the Known Exploited Vulnerabilities catalog: a boolean,
  "is this CVE known to be actively exploited."
- **FIRST EPSS** — a 0-1 probability of exploitation in the next 30 days.

**Only CVEs an open finding actually names are stored.** The full catalogs
are a few hundred KB and a few dozen MB respectively; a portfolio references
a few hundred CVEs at most, and storing the rest would be a standing cost for
rows nothing reads (spec 17 §4.3).

**Fetch failure degrades, it does not block** (spec 17 §4.3, matching spec 11
§6's retrieval-failure rule): `refresh()` logs and returns without touching
existing rows rather than raising, so a feed being unreachable never fails a
scan, a decision, or a dashboard render that doesn't depend on it.
"""

from __future__ import annotations

import csv
import gzip
import logging
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, time
from typing import Any

import httpx2
from sqlalchemy import select
from sqlalchemy.orm import Session

from mykronos.db.models import ThreatIntelMatch
from mykronos.db.session import Database
from mykronos.lake.catalog import Catalog
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.logsafe import scrub
from mykronos.schemas import utcnow

logger = logging.getLogger(__name__)

#: The public, unauthenticated, full-catalog feeds. Both are the vendor's own
#: default distribution point, not a mirror this project stood up.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

#: Short. A daily refresh job blocking on a slow feed for minutes is worse
#: than the job trying again tomorrow (spec 17 §4.3's degrade-not-block rule).
TIMEOUT = 15.0

#: Trivy's `rule_id` *is* the CVE; an OSV-derived Atlas finding carries it in
#: `title` instead. Matched against both, uppercased for a stable key.
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def extract_cve(rule_id: str | None, title: str | None) -> str | None:
    """The CVE a finding is about, if it names one — else None.

    A finding without a CVE (most SAST/IaC findings, which describe a code
    pattern rather than a published vulnerability) has no exploitability
    data available, honestly (spec 17 §5.4) — this returns None for it
    rather than a guess.
    """
    for text in (rule_id, title):
        if not text:
            continue
        match = _CVE_PATTERN.search(text)
        if match:
            return match.group(0).upper()
    return None


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    added_at: date | None
    due_date: date | None


@dataclass(frozen=True)
class EpssEntry:
    cve_id: str
    score: float
    percentile: float


def _parse_kev_date(value: object) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        # A feed that changes its date format is not a reason to fail the
        # whole refresh over one field on one entry.
        return None


def parse_kev(payload: object) -> list[KevEntry]:
    """CISA's `known_exploited_vulnerabilities.json` shape: a top-level
    `vulnerabilities` list, each carrying `cveID`, `dateAdded`, and an
    optional `dueDate`.

    Never raises on a malformed entry — logs and skips it, same rule as an
    adapter's `normalize()` (spec 04 §4): partial, real data beats none.
    """
    if not isinstance(payload, dict):
        return []
    raw_entries = payload.get("vulnerabilities")
    if not isinstance(raw_entries, list):
        return []

    entries: list[KevEntry] = []
    for raw in raw_entries:
        if not isinstance(raw, dict):
            continue
        cve_id = raw.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        entries.append(
            KevEntry(
                cve_id=cve_id.upper(),
                added_at=_parse_kev_date(raw.get("dateAdded")),
                due_date=_parse_kev_date(raw.get("dueDate")),
            )
        )
    return entries


def parse_epss_csv(text: str) -> list[EpssEntry]:
    """FIRST's bulk CSV: a `#model_version:...` comment line, then a header
    row `cve,epss,percentile`, then one row per scored CVE.

    Never raises on a malformed row — skipped, same rule as `parse_kev`.
    """
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not lines:
        return []

    reader = csv.DictReader(lines)
    entries: list[EpssEntry] = []
    for row in reader:
        cve_id = (row.get("cve") or "").strip()
        if not cve_id:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        entries.append(EpssEntry(cve_id=cve_id.upper(), score=score, percentile=percentile))
    return entries


def default_fetch_kev() -> object:
    # `follow_redirects` on both feeds — see `default_fetch_epss`. KEV serves
    # 200 today and there is no reason to be the one that breaks when it stops.
    response = httpx2.get(KEV_URL, timeout=TIMEOUT, follow_redirects=True)
    response.raise_for_status()
    return response.json()


def default_fetch_epss() -> str:
    # `follow_redirects=True`, and it is the whole reason EPSS ever worked.
    # The feed answers `302 Found` with a relative `Location` naming the day's
    # file — `epss_scores-2026-09-01.csv.gz` — and httpx does not follow
    # redirects unless asked, so `raise_for_status()` raised on the redirect
    # itself. Every refresh recorded a `fetched_at` and stored no score: 110
    # CVEs matched to open findings, 0 with an EPSS score, for as long as this
    # has been deployed. The old page rendered that as a dash at the bottom of
    # a list sorted by score, which is exactly where nobody looks.
    response = httpx2.get(EPSS_URL, timeout=TIMEOUT, follow_redirects=True)
    response.raise_for_status()
    # The feed is gzip-compressed; a plain `.text` would be the compressed
    # bytes decoded as if they were already the CSV.
    return gzip.decompress(response.content).decode("utf-8", errors="replace")


def upsert(
    session: Session,
    *,
    kev: list[KevEntry],
    epss: list[EpssEntry],
    relevant_cves: set[str],
    fetched_at: datetime,
) -> int:
    """Write only rows for `relevant_cves` — CVEs an open finding actually
    names (spec 17 §4.3). Returns the number of rows written.

    One row per CVE, overwritten in place: this is a current-value table, not
    an append-only record (see the module docstring on `ThreatIntelMatch`).
    """
    if not relevant_cves:
        return 0

    kev_by_cve = {entry.cve_id: entry for entry in kev}
    epss_by_cve = {entry.cve_id: entry for entry in epss}

    existing = {
        row.cve_id: row
        for row in session.execute(
            select(ThreatIntelMatch).where(ThreatIntelMatch.cve_id.in_(relevant_cves))
        ).scalars()
    }

    written = 0
    for cve_id in sorted(relevant_cves):
        kev_entry = kev_by_cve.get(cve_id)
        epss_entry = epss_by_cve.get(cve_id)
        row = existing.get(cve_id)
        if row is None:
            row = ThreatIntelMatch(cve_id=cve_id)
            session.add(row)

        row.in_kev = kev_entry is not None
        row.kev_added_at = kev_entry.added_at if kev_entry else None
        row.kev_due_date = kev_entry.due_date if kev_entry else None
        row.epss_score = epss_entry.score if epss_entry else None
        row.epss_percentile = epss_entry.percentile if epss_entry else None
        row.fetched_at = fetched_at
        written += 1

    session.flush()
    return written


@dataclass(frozen=True)
class RefreshResult:
    written: int
    kev_error: str | None = None
    epss_error: str | None = None

    @property
    def ok(self) -> bool:
        return self.kev_error is None and self.epss_error is None


def refresh(
    session: Session,
    relevant_cves: set[str],
    *,
    fetch_kev: Callable[[], object] = default_fetch_kev,
    fetch_epss: Callable[[], str] = default_fetch_epss,
    now: Callable[[], datetime] = utcnow,
) -> RefreshResult:
    """Fetch both feeds, parse, and upsert rows for `relevant_cves` only.

    A failure on either feed degrades to "keep what's already stored" for
    that feed rather than raising (spec 17 §4.3) — a KEV outage must not
    erase yesterday's EPSS scores, and vice versa. The caller (the scheduled
    refresh job) logs `RefreshResult`'s errors; nothing here blocks a scan,
    a decision, or an unrelated dashboard render.
    """
    kev: list[KevEntry] = []
    kev_error: str | None = None
    try:
        kev = parse_kev(fetch_kev())
    except Exception as exc:  # noqa: BLE001 - a network/parse failure degrades, not raises
        kev_error = scrub(str(exc))
        logger.warning("KEV fetch failed, keeping existing rows: %s", kev_error)

    epss: list[EpssEntry] = []
    epss_error: str | None = None
    try:
        epss = parse_epss_csv(fetch_epss())
    except Exception as exc:  # noqa: BLE001
        epss_error = scrub(str(exc))
        logger.warning("EPSS fetch failed, keeping existing rows: %s", epss_error)

    if kev_error is not None and epss_error is not None:
        # Neither feed answered — nothing to upsert, and upserting an empty
        # `kev`/`epss` against existing rows would wrongly clear them.
        return RefreshResult(written=0, kev_error=kev_error, epss_error=epss_error)

    written = upsert(
        session,
        kev=kev,
        epss=epss,
        relevant_cves=relevant_cves,
        fetched_at=now(),
    )
    return RefreshResult(written=written, kev_error=kev_error, epss_error=epss_error)


def relevant_cves_for_open_findings(rows: list[dict[str, Any]]) -> set[str]:
    """Which CVEs to bother fetching — extracted from a portfolio's open
    findings (spec 17 §4.3). `rows` carries at least `rule_id` and `title`."""
    cves: set[str] = set()
    for row in rows:
        cve_id = extract_cve(row.get("rule_id"), row.get("title"))
        if cve_id:
            cves.add(cve_id)
    return cves


def refresh_job(db: Database, catalog: Catalog) -> RefreshResult:
    """The scheduled entry point (spec 17 §4.3), wired into `main.py` the
    same way `purge_expired_insider_risk`/`score_portfolio` are.

    Reads which CVEs matter from the lake directly — findings are the lake's
    responsibility, not the operational database's — then upserts through the
    operational session, same split every other job in this module family
    follows.
    """
    rows = catalog.query("SELECT DISTINCT rule_id, title FROM findings WHERE status = 'open'")
    relevant = relevant_cves_for_open_findings(
        [{"rule_id": r, "title": t} for r, t in rows]
    )
    with db.session() as session:
        result = refresh(session, relevant)
        apply_kev_due_dates(session, catalog)
    return result


def apply_kev_due_dates(session: Session, catalog: Catalog) -> int:
    """Stamp CISA's due date onto every open finding whose CVE is in KEV.

    Spec 24 §2.2: KEV wins over the policy target. That date is authored
    outside this organisation and is the only externally-committed deadline
    this platform holds — a locally-computed one that disagreed with it would
    be the platform quietly negotiating with CISA.

    Runs here rather than at ingest because the CVE-to-KEV mapping is not
    known when a finding arrives: `refresh` is what learns it, and it runs on
    its own schedule. Ingest sets the policy date; this replaces it the first
    time the intel says it should.

    Returns the number of findings restamped, for the caller's log. A finding
    already carrying the same KEV date is left alone — a no-op update would
    rewrite a Parquet partition for nothing.
    """
    kev_due: dict[str, date] = {
        row.cve_id: row.kev_due_date
        for row in session.execute(
            select(ThreatIntelMatch).where(
                ThreatIntelMatch.in_kev.is_(True),
                ThreatIntelMatch.kev_due_date.is_not(None),
            )
        ).scalars()
        if row.kev_due_date is not None
    }
    if not kev_due:
        return 0

    rows = catalog.query(
        "SELECT finding_id, rule_id, title, due_at, due_source "
        "FROM findings WHERE status = 'open'"
    )
    wanted: dict[date, list[str]] = defaultdict(list)
    for finding_id, rule_id, title, due_at, due_source in rows:
        cve = extract_cve(rule_id, title)
        if cve is None:
            continue
        due = kev_due.get(cve.upper())
        if due is None:
            continue
        if due_source == "kev" and due_at is not None and due_at.date() == due:
            continue
        wanted[due].append(str(finding_id))

    restamped = 0
    for due, finding_ids in wanted.items():
        outcome = update_findings(
            catalog,
            locate_findings(catalog, finding_ids),
            "due_at = ?, due_source = ?",
            [datetime.combine(due, time.min), "kev"],
        )
        restamped += outcome.count
    if restamped:
        logger.info("KEV due dates applied to %d finding(s).", restamped)
    return restamped
