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
import os
import re

# `time` is already bound to `datetime.time` in this module, so the standard
# library clock comes in under its own name rather than shadowing it.
import time as clock
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any

import httpx2
from sqlalchemy import and_, or_, select
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
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: CVEs to look up per run of the `nvd-vectors` job (TheHub #61034). It used to
#: be 20 a day, inside the daily KEV/EPSS job: measured 2026-10-27, 3,603 rows
#: had never been asked and the queue would have taken ~180 days to drain,
#: growing with every new CVE, while no environmental score could be computed
#: for any of them. The lookup now has its own hourly job
#: (`nvd_vector_interval_seconds`), and 80 an hour is 1,920 a day: that
#: backlog in about two days.
#:
#: **The rate.** NVD's published limit for a caller without a key is five
#: requests in any thirty seconds. `NVD_DELAY_SECONDS` spaces requests 6.5 s
#: apart -- 30 / 6.5 = 4.6 per window, below five before any response time
#: is counted -- so the batch size sets how long a run takes, never how fast
#: it asks. 80 vectors + `NVD_REFS_BATCH` = 120 requests = 13 minutes of an
#: hour, inside `NVD_RUN_SECONDS`.
NVD_BATCH = 80
#: Beside that budget, not out of it: at most this many requests per run
#: read NVD's exploit references for rows whose vector was looked up before
#: #60890. Every such row is eligible at once after the upgrade, so without
#: a cap the backfill would be one estate-wide wave of NVD load. It is not
#: carved from `NVD_BATCH` because the vector queue is itself backlogged
#: (TheHub #61034): a share of whatever the vectors leave would be zero for
#: as long as it is, and until a row's references are read its verdict
#: cannot say "no known exploit". 40 an hour is 960 a day.
NVD_REFS_BATCH = 40
#: Between requests. Above NVD's published unauthenticated floor with margin,
#: because being rate-limited by a public feed is a way to get an IP blocked
#: rather than a way to go faster.
NVD_DELAY_SECONDS = 6.5
#: Refusals in a row after which a CVE is no longer asked (TheHub #61037).
#: Its verdict stays `not_checked`, which is true. Five daily runs is long
#: enough that a CVE NVD publishes a day late is not given up on.
NVD_MAX_FAILURES = 5
#: Days after its last refusal that a retired CVE is asked once more, so a
#: retirement that was wrong, or a CVE NVD publishes late, heals itself.
NVD_RETRY_DAYS = 30
#: 4xx answers that describe the feed, not the CVE: rate-limited, or refused
#: for this address. Counting them would retire every row an outage touched.
_FEED_STATUSES = frozenset({403, 429})

#: With an NVD API key (`nvd_api_key`, or `NVD_API_KEY` in the environment)
#: the published limit is fifty requests in thirty seconds. 0.7 s apart is
#: 30 / 0.7 = 42.9 per window. 500 + 250 requests is 525 s a run, and 12,000
#: vectors a day.
NVD_KEYED_BATCH = 500
NVD_KEYED_REFS_BATCH = 250
NVD_KEYED_DELAY_SECONDS = 0.7

#: The wall-clock ceiling on one run, whatever the batch sizes say. A run
#: stops asking when the next request would start past it and leaves the
#: rest unstamped, so the next run resumes exactly where this one stopped:
#: the queue is the table's own stamps, not a cursor this job keeps. Only
#: reached when NVD answers slowly -- a full batch at the spacing above is 13
#: minutes unauthenticated and under 9 with a key.
NVD_RUN_SECONDS = 900.0

#: Responses that say NVD itself is unavailable or is rate-limiting this
#: caller (it answers 403 for the latter) rather than anything about one CVE.
#: The run stops at the first: the rows behind it would fail the same way,
#: and asking faster than a limit NVD is enforcing is how an address gets
#: blocked.
_NVD_UNAVAILABLE_STATUS = frozenset({403, 429, 502, 503, 504})

#: The scheduled job's name, as platform health and `job_runs` record it.
NVD_JOB = "nvd-vectors"

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


@dataclass(frozen=True)
class NvdVectors:
    """The base vectors one NVD CVE response publishes (TheHub #60824).

    `v3` is the one scored; `v4` is stored and shown, never rescored (D1).
    `v4_base_score` is NVD's own figure for the v4 vector.
    """

    v3: str | None = None
    v4: str | None = None
    v4_base_score: float | None = None


def _metrics(payload: object) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return None
    entry = vulnerabilities[0]
    if not isinstance(entry, dict):
        return None
    metrics = (entry.get("cve") or {}).get("metrics")
    return metrics if isinstance(metrics, dict) else None


def parse_nvd_vectors(payload: object) -> NvdVectors:
    """Both the v3.x vector (`parse_nvd_vector`) and NVD's `cvssMetricV40`.

    A CVE NVD scored only in v4.0 used to come out of this as nothing at all,
    indistinguishable from a reserved CVE NVD has never heard of. It is now a
    v4 vector with no v3 -- shown, not rescored.
    """
    v3 = parse_nvd_vector(payload)
    metrics = _metrics(payload) or {}
    candidates = metrics.get("cvssMetricV40")
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            data = candidate.get("cvssData")
            if not isinstance(data, dict):
                continue
            vector = data.get("vectorString")
            if isinstance(vector, str) and vector.startswith("CVSS:4.0/"):
                score = data.get("baseScore")
                return NvdVectors(
                    v3=v3,
                    v4=vector,
                    v4_base_score=(
                        float(score)
                        if isinstance(score, (int, float)) and not isinstance(score, bool)
                        else None
                    ),
                )
    return NvdVectors(v3=v3)


def parse_nvd_vector(payload: object) -> str | None:
    """Pull the CVSS v3.x base vector out of one NVD CVE response.

    v3.1 preferred over v3.0 where both are published, and v2 ignored entirely:
    the environmental formula implemented here is v3's, and a v2 vector fed to
    it would produce a number in the right range and the wrong units.

    Returns `None` rather than raising for a CVE NVD has not scored. That is a
    real and common state — reserved CVEs, and every Debian `TEMP-` identifier
    this estate is full of — and it must be storable as "looked, found nothing"
    rather than retried forever.
    """
    metrics = _metrics(payload)
    if metrics is None:
        return None

    for key in ("cvssMetricV31", "cvssMetricV30"):
        candidates = metrics.get(key)
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            data = candidate.get("cvssData")
            if isinstance(data, dict):
                vector = data.get("vectorString")
                if isinstance(vector, str) and vector.startswith("CVSS:3."):
                    return vector
    return None


def default_fetch_nvd(cve_id: str, *, api_key: str = "") -> object:
    """One CVE from NVD. A public endpoint that needs no key; one only raises
    the rate limit. When a deployment supplies one it comes from that
    deployment's environment and is sent as NVD's `apiKey` header -- never
    stored, logged, or held in this repository (spec 12 §2)."""
    response = httpx2.get(
        NVD_URL,
        params={"cveId": cve_id},
        headers={"apiKey": api_key} if api_key else None,
        timeout=TIMEOUT,
        follow_redirects=True,
    )
    response.raise_for_status()
    return response.json()


def _refused(exc: Exception) -> bool:
    """Did NVD refuse this CVE, rather than fail to answer at all?

    Only a 4xx NVD chose to send is about the CVE. Anything else -- a transport
    error, a 5xx, a 200 that is a maintenance page, a parser that broke --
    would be charged to every row a run asked, and five runs of it would
    retire the queue (review of #1034).
    """
    if not isinstance(exc, httpx2.HTTPStatusError):
        return False
    code = exc.response.status_code
    return 400 <= code < 500 and code not in _FEED_STATUSES


@dataclass(frozen=True)
class NvdBudget:
    """How much one `nvd-vectors` run may ask of NVD, and how fast."""

    vectors: int
    refs: int
    delay_seconds: float
    seconds: float = NVD_RUN_SECONDS

    def per_day(self, interval_seconds: int) -> int:
        """Vector lookups a day at this budget, run every `interval_seconds`."""
        return int(self.vectors * 86_400 / max(interval_seconds, 1))


def nvd_budget(api_key: str = "") -> NvdBudget:
    """The budget for a caller with or without an NVD API key (TheHub #61034)."""
    if api_key:
        return NvdBudget(
            vectors=NVD_KEYED_BATCH,
            refs=NVD_KEYED_REFS_BATCH,
            delay_seconds=NVD_KEYED_DELAY_SECONDS,
        )
    return NvdBudget(vectors=NVD_BATCH, refs=NVD_REFS_BATCH, delay_seconds=NVD_DELAY_SECONDS)


def nvd_api_key(configured: str = "") -> str:
    """`nvd_api_key` from settings, else NVD's own conventional `NVD_API_KEY`."""
    return configured or os.environ.get("NVD_API_KEY", "")


def _nvd_unavailable(exc: Exception) -> bool:
    """Whether a failed fetch says NVD is down or limiting us, not this CVE."""
    if isinstance(exc, httpx2.TransportError):
        return True
    if isinstance(exc, httpx2.HTTPStatusError):
        return exc.response.status_code in _NVD_UNAVAILABLE_STATUS
    return False



def _askable(at: datetime) -> Any:
    """Rows NVD may be asked about: fewer than `NVD_MAX_FAILURES` refusals,
    or `NVD_RETRY_DAYS` since the last one. The queue and its backlog count
    read the same rule."""
    return or_(
        ThreatIntelMatch.nvd_failures < NVD_MAX_FAILURES,
        ThreatIntelMatch.nvd_failed_at < at - timedelta(days=NVD_RETRY_DAYS),
    )


def refresh_vectors(
    session: Session,
    *,
    fetch: Callable[[str], object] = default_fetch_nvd,
    sleep: Callable[[float], None] = clock.sleep,
    limit: int = NVD_BATCH,
    refs_limit: int = NVD_REFS_BATCH,
    now: Callable[[], datetime] = utcnow,
    delay: float = NVD_DELAY_SECONDS,
    budget_seconds: float = NVD_RUN_SECONDS,
    monotonic: Callable[[], float] = clock.monotonic,
) -> int:
    """Look up base vectors for CVEs that do not have one yet.

    **Why the vector and not the score.** A base score is one number for every
    system in the world. The vector is what lets it be re-read for *this*
    system — the difference between "7.5 everywhere" and "7.5 there, 5.9 here
    because nothing outside can reach it". Storing the score would have been
    simpler and would have made the environmental feature impossible.

    **Only rows this platform already tracks**, which are already only CVEs an
    open finding names. NVD is not asked about anything nobody here has.

    **Once, not repeatedly.** `vector_checked_at` records that the lookup ran
    whether or not it found anything, so a CVE NVD has never scored is asked
    about once rather than on every sweep for ever. Roughly two thirds of this
    estate's container findings carry Debian `TEMP-` identifiers that NVD has
    no record of, and retrying those daily would be the whole budget.

    **v4.0 too** (TheHub #60824). NVD's `cvssMetricV40` is stored beside the
    v3 vector and shown, never rescored. A row the v3-only lookup stamped has
    `v4_checked_at` null and may have had a v4 it dropped, so it is eligible
    once more; this lookup stamps both, so the once-only rule still holds.

    Degrades rather than raises: a failed lookup stamps none of the checked
    columns, so a later run tries again. A failure that says NVD itself is
    unavailable or limiting this caller ends the run there.

    **Bounded and resumable** (TheHub #61034). `budget_seconds` caps the run:
    no request starts past it. The vector lookups get the share of it their
    queue is of the whole, so the references are never starved by a slow
    vector queue. Whatever is not reached is still unstamped, which is all a
    later run needs to resume.

    **References are a backfill, not a second vector lookup** (TheHub
    #60890). NVD's exploit-tagged references arrive in the same response, so
    a row whose vector was looked up before they were read is eligible once
    more -- but only for them: at most `refs_limit` per run, beside the
    vector budget rather than out of it so a full vector queue cannot starve
    it, asked after the vector lookups, and without touching the row's
    vectors or their stamps. It never counts as found, because found is what
    fans out into an estate-wide environmental rescore.

    **A refused lookup goes to the back** (TheHub #61037). A row NVD refuses
    is not stamped, so it used to head its queue on every run; with more of
    them than a batch, nothing behind them was ever asked. Each refusal is
    recorded, refused rows queue after everything else, and after
    `NVD_MAX_FAILURES` in a row the row is not asked again until
    `NVD_RETRY_DAYS` after the last refusal. Only a 4xx NVD chose to send
    counts; anything else describes the feed, so it charges no row.
    """
    from mykronos.exploitability import store_nvd_refs

    needs_vector = and_(
        ThreatIntelMatch.cvss_vector.is_(None),
        ThreatIntelMatch.v4_checked_at.is_(None),
    )
    askable = _askable(now())
    refused_last = ThreatIntelMatch.nvd_failed_at.is_not(None)
    pending = list(
        session.execute(
            select(ThreatIntelMatch)
            .where(needs_vector, askable)
            # Never looked at first: a CVE matched today is not queued behind
            # rows being asked about v4 a second time, or behind refusals.
            .order_by(
                refused_last,
                ThreatIntelMatch.vector_checked_at.is_not(None),
                ThreatIntelMatch.nvd_failed_at,
                ThreatIntelMatch.cve_id,
            )
            .limit(limit)
        ).scalars()
    )
    refs_only: list[ThreatIntelMatch] = []
    if refs_limit > 0:
        refs_only = list(
            session.execute(
                select(ThreatIntelMatch)
                .where(~needs_vector, ThreatIntelMatch.nvd_refs_checked_at.is_(None), askable)
                .order_by(refused_last, ThreatIntelMatch.nvd_failed_at, ThreatIntelMatch.cve_id)
                .limit(refs_limit)
            ).scalars()
        )
    if not pending and not refs_only:
        return 0

    started = monotonic()
    share = len(pending) / (len(pending) + len(refs_only))
    found = 0
    asked = 0
    failed = 0
    unavailable = False
    for rows, deadline, is_vector in (
        (pending, started + budget_seconds * share, True),
        (refs_only, started + budget_seconds, False),
    ):
        for row in rows:
            wait = delay if asked else 0.0
            if monotonic() + wait > deadline:
                # Out of time for this queue. The rows not reached are still
                # unstamped, so the next run starts with them.
                break
            if wait:
                sleep(wait)
            asked += 1
            try:
                payload = fetch(row.cve_id)
                vectors = parse_nvd_vectors(payload)
            except Exception as exc:  # noqa: BLE001 - a feed failure degrades
                failed += 1
                logger.warning("NVD lookup failed for %s: %s", row.cve_id, scrub(str(exc)))
                if _refused(exc):
                    row.nvd_failures = (row.nvd_failures or 0) + 1
                    row.nvd_failed_at = now()
                if _nvd_unavailable(exc):
                    unavailable = True
                    break
                continue
            # A lookup that answered clears the failure count whatever it
            # found: the CVE is readable.
            row.nvd_failures = 0
            row.nvd_failed_at = None
            # Stamped even when nothing was found: that is the record of having
            # looked, and it is what stops this retrying for ever.
            checked = now()
            store_nvd_refs(row, payload, checked)
            if not is_vector:
                continue
            row.vector_checked_at = checked
            row.v4_checked_at = checked
            if vectors.v3:
                row.cvss_vector = vectors.v3
            if vectors.v4:
                row.cvss_v4_vector = vectors.v4
                row.cvss_v4_base_score = vectors.v4_base_score
            if vectors.v3 or vectors.v4:
                found += 1
        if unavailable:
            logger.warning("NVD unavailable or rate-limiting; this run stops here.")
            break

    logger.info(
        "NVD lookups: %d asked of %d queued, %d failed, %d new vector(s).",
        asked,
        len(pending) + len(refs_only),
        failed,
        found,
    )
    session.flush()
    return found


@dataclass(frozen=True)
class VectorBacklog:
    """What the `nvd-vectors` queue still holds (TheHub #61034)."""

    #: CVEs that still wait for a vector lookup and will be asked.
    vectors: int
    #: CVEs whose vector is settled and whose NVD references are not read.
    refs: int
    #: CVEs not asked after `NVD_MAX_FAILURES` refusals, until `NVD_RETRY_DAYS`.
    given_up: int

    def detail(self, budget: NvdBudget, interval_seconds: int) -> str:
        """One sentence for the platform-health row: how much, and how long."""
        per_day = budget.per_day(interval_seconds)
        refs_per_day = int(budget.refs * 86_400 / max(interval_seconds, 1))
        parts = [
            f"{self.vectors:,} CVE{'s' if self.vectors != 1 else ''} wait for a "
            f"CVSS vector{_days(self.vectors, per_day, 'vector')}",
            f"{self.refs:,} for exploit references{_days(self.refs, refs_per_day, '')}",
        ]
        if self.given_up:
            parts.append(
                f"{self.given_up:,} not asked for {NVD_RETRY_DAYS} days after "
                f"{NVD_MAX_FAILURES} refusals"
            )
        return "; ".join(parts)


def _days(count: int, per_day: int, noun: str) -> str:
    if not count or per_day <= 0:
        return ""
    days = count / per_day
    rate = f"{per_day:,} {noun + 's ' if noun else ''}a day"
    return f" (about {max(days, 0.1):.1f} days at {rate})"


def vector_backlog(session: Session) -> VectorBacklog:
    """Count both queues `refresh_vectors` reads, and the rows it gave up on."""
    from sqlalchemy import func

    needs_vector = and_(
        ThreatIntelMatch.cvss_vector.is_(None),
        ThreatIntelMatch.v4_checked_at.is_(None),
    )

    def count(*where: Any) -> int:
        return int(
            session.execute(
                select(func.count()).select_from(ThreatIntelMatch).where(*where)
            ).scalar_one()
        )

    at = utcnow()
    askable = _askable(at)
    return VectorBacklog(
        vectors=count(needs_vector, askable),
        refs=count(~needs_vector, ThreatIntelMatch.nvd_refs_checked_at.is_(None), askable),
        # Retired until their retry date; a row past it is back in a queue.
        given_up=count(
            ThreatIntelMatch.nvd_failures >= NVD_MAX_FAILURES,
            or_(
                ThreatIntelMatch.nvd_failed_at.is_(None),
                ThreatIntelMatch.nvd_failed_at >= at - timedelta(days=NVD_RETRY_DAYS),
            ),
        ),
    )


def vector_job(db: Database, *, api_key: str = "") -> int:
    """The `nvd-vectors` scheduled job (TheHub #61034): one bounded run.

    Its own job, hourly, rather than a step at the end of the daily KEV/EPSS
    refresh, so the lookup can drain a backlog in days without holding that
    job open for hours. Raises rather than degrading: unlike the KEV/EPSS
    work it once rode on, nothing else depends on this run finishing, and a
    failure belongs on the platform-health page as this job failing.
    """
    budget = nvd_budget(api_key)

    def fetch(cve_id: str) -> object:
        return default_fetch_nvd(cve_id, api_key=api_key)

    with db.session() as session:
        found = refresh_vectors(
            session,
            fetch=fetch,
            limit=budget.vectors,
            refs_limit=budget.refs,
            delay=budget.delay_seconds,
            budget_seconds=budget.seconds,
        )
    if found:
        logger.info("Fetched %s new CVSS vector(s) from NVD", found)
        # A new vector is a finding that can now be scored, in any
        # repository that has it (TheHub #60827).
        from mykronos import environment

        environment.mark_all_dirty("vector refresh")
    return found


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
    # A finding that joined KEV comes back out of snooze (spec 27 §3, #728).
    # After the session above commits, so the new KEV rows are readable.
    from mykronos.worklist import break_snoozes_on_kev

    try:
        break_snoozes_on_kev(db, catalog)
    except Exception as exc:  # noqa: BLE001 - never fails the KEV/EPSS work
        logger.warning("Could not break snoozes on KEV: %s", scrub(str(exc)))
    # The NVD vector lookup is no longer a step here: it has its own hourly
    # job, `vector_job` (TheHub #61034), which picks up a CVE this run
    # matched within the hour.
    #
    # Public exploit catalogs (TheHub #60890), after the upsert so a CVE that
    # arrived on this run is matched today. Degrades like the feeds above.
    from mykronos.exploitability import refresh_exploits

    with db.session() as session:
        try:
            exploits = refresh_exploits(session)
        except Exception as exc:  # noqa: BLE001 - never fails the KEV/EPSS work
            logger.warning("Exploit lookup degraded: %s", scrub(str(exc)))
        else:
            if exploits.exploitdb_error or exploits.metasploit_error:
                logger.warning(
                    "Exploit feeds partly unavailable: exploit-db=%s metasploit=%s",
                    exploits.exploitdb_error,
                    exploits.metasploit_error,
                )
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
