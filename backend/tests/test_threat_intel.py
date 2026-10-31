"""Public exploitation data — spec 17 §4."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import httpx2
import pytest

from mykronos import threat_intel
from mykronos.db import Database
from mykronos.db.models import ThreatIntelMatch
from mykronos.threat_intel import (
    EpssEntry,
    KevEntry,
    RefreshResult,
    extract_cve,
    parse_epss_csv,
    parse_kev,
    refresh,
    relevant_cves_for_open_findings,
    upsert,
)


@pytest.fixture
def db(tmp_path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'threat-intel.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def session(db: Database) -> Iterator[object]:
    with db.session() as opened:
        yield opened


class TestExtractCve:
    def test_a_trivy_style_rule_id_is_the_cve_itself(self) -> None:
        assert extract_cve("CVE-2024-12345", "some title") == "CVE-2024-12345"

    def test_an_osv_style_finding_carries_it_in_the_title(self) -> None:
        assert extract_cve("GHSA-xxxx-yyyy", "urllib3: CVE-2024-37891 (proxy)") == (
            "CVE-2024-37891"
        )

    def test_uppercased_for_a_stable_key(self) -> None:
        assert extract_cve("cve-2024-12345", None) == "CVE-2024-12345"

    def test_a_finding_with_no_cve_is_honestly_none(self) -> None:
        """Most SAST/IaC findings describe a code pattern, not a published
        vulnerability — no CVE, no exploitability data available (spec 17
        §5.4), and this must not guess one."""
        assert extract_cve("CWE-89", "SQL injection") is None


class TestParseKev:
    def test_parses_the_real_shape(self) -> None:
        entries = parse_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-12345",
                        "dateAdded": "2024-03-01",
                        "dueDate": "2024-03-22",
                    }
                ]
            }
        )
        assert entries == [
            KevEntry(
                cve_id="CVE-2024-12345",
                added_at=date(2024, 3, 1),
                due_date=date(2024, 3, 22),
            )
        ]

    def test_a_malformed_entry_is_skipped_not_fatal(self) -> None:
        """Same rule as an adapter's normalize() (spec 04 §4): partial, real
        data beats none."""
        entries = parse_kev(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-2024-1"},  # no dates — still valid
                    {"dateAdded": "2024-03-01"},  # no cveID — dropped
                    "not even a dict",
                ]
            }
        )
        assert [e.cve_id for e in entries] == ["CVE-2024-1"]

    def test_an_unrecognisable_payload_is_an_empty_list_not_an_error(self) -> None:
        assert parse_kev(None) == []
        assert parse_kev({"unexpected": "shape"}) == []


class TestParseEpss:
    def test_parses_the_real_shape(self) -> None:
        text = (
            "#model_version:v2023.03.01,score_date:2024-03-01\n"
            "cve,epss,percentile\n"
            "CVE-2024-12345,0.42,0.91\n"
        )
        assert parse_epss_csv(text) == [
            EpssEntry(cve_id="CVE-2024-12345", score=0.42, percentile=0.91)
        ]

    def test_a_malformed_row_is_skipped_not_fatal(self) -> None:
        text = "cve,epss,percentile\nCVE-1,not-a-number,0.5\nCVE-2,0.1,0.2\n"
        entries = parse_epss_csv(text)
        assert [e.cve_id for e in entries] == ["CVE-2"]

    def test_empty_input_is_an_empty_list(self) -> None:
        assert parse_epss_csv("") == []


class TestUpsert:
    def test_writes_only_relevant_cves(self, db: Database) -> None:
        """The full catalogs are orders of magnitude larger than anything a
        portfolio references (spec 17 §4.3) — writing everything fetched
        would be a standing cost for rows nothing reads."""
        with db.session() as session:
            written = upsert(
                session,
                kev=[
                    KevEntry("CVE-2024-1", date(2024, 1, 1), None),
                    KevEntry("CVE-2024-99", date(2024, 1, 1), None),
                ],
                epss=[],
                relevant_cves={"CVE-2024-1"},
                fetched_at=datetime(2024, 1, 2, tzinfo=UTC),
            )
            assert written == 1

        with db.session() as session:
            rows = session.query(ThreatIntelMatch).all()
            assert [r.cve_id for r in rows] == ["CVE-2024-1"]
            assert rows[0].in_kev is True

    def test_a_relevant_cve_with_no_feed_hit_is_still_written(self, db: Database) -> None:
        """`in_kev=False`, both scores null — a real, negative answer, not an
        absent row. A caller asking "is CVE-2024-1 in KEV" must get `False`
        rather than nothing, or the two look identical."""
        with db.session() as session:
            upsert(
                session,
                kev=[],
                epss=[],
                relevant_cves={"CVE-2024-1"},
                fetched_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

        with db.session() as session:
            row = session.get(ThreatIntelMatch, "CVE-2024-1")
            assert row is not None
            assert row.in_kev is False
            assert row.epss_score is None

    def test_reconfirmation_overwrites_in_place(self, db: Database) -> None:
        """A current-value table, not an append-only one — a CVE's EPSS score
        moving is a correction, not a new row."""
        with db.session() as session:
            upsert(
                session,
                kev=[],
                epss=[EpssEntry("CVE-2024-1", 0.1, 0.2)],
                relevant_cves={"CVE-2024-1"},
                fetched_at=datetime(2024, 1, 1, tzinfo=UTC),
            )
        with db.session() as session:
            upsert(
                session,
                kev=[],
                epss=[EpssEntry("CVE-2024-1", 0.9, 0.99)],
                relevant_cves={"CVE-2024-1"},
                fetched_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

        with db.session() as session:
            assert session.query(ThreatIntelMatch).count() == 1
            row = session.get(ThreatIntelMatch, "CVE-2024-1")
            assert row.epss_score == 0.9

    def test_no_relevant_cves_writes_nothing(self, db: Database) -> None:
        with db.session() as session:
            written = upsert(
                session,
                kev=[],
                epss=[],
                relevant_cves=set(),
                fetched_at=datetime(2024, 1, 1, tzinfo=UTC),
            )
            assert written == 0


class TestRefresh:
    def test_degrades_on_a_single_feed_failure(self, db: Database) -> None:
        """Spec 17 §4.3 — a KEV outage must not erase EPSS data or vice
        versa, and must not fail whatever called the refresh."""

        def failing_kev() -> object:
            raise RuntimeError("CISA is down")

        def working_epss() -> str:
            return "cve,epss,percentile\nCVE-2024-1,0.5,0.6\n"

        with db.session() as session:
            result = refresh(
                session,
                {"CVE-2024-1"},
                fetch_kev=failing_kev,
                fetch_epss=working_epss,
                now=lambda: datetime(2024, 1, 1, tzinfo=UTC),
            )

        assert not result.ok
        assert result.kev_error is not None
        assert result.epss_error is None
        assert result.written == 1

        with db.session() as session:
            row = session.get(ThreatIntelMatch, "CVE-2024-1")
            assert row.epss_score == 0.5
            assert row.in_kev is False  # honest: no KEV data arrived, not a guess

    def test_both_feeds_failing_leaves_existing_rows_untouched(self, db: Database) -> None:
        with db.session() as session:
            upsert(
                session,
                kev=[KevEntry("CVE-2024-1", date(2024, 1, 1), None)],
                epss=[],
                relevant_cves={"CVE-2024-1"},
                fetched_at=datetime(2024, 1, 1, tzinfo=UTC),
            )

        def failing() -> object:
            raise RuntimeError("unreachable")

        with db.session() as session:
            result = refresh(
                session,
                {"CVE-2024-1"},
                fetch_kev=failing,
                fetch_epss=failing,  # type: ignore[arg-type]
                now=lambda: datetime(2024, 1, 2, tzinfo=UTC),
            )
        assert result.written == 0
        assert not result.ok

        with db.session() as session:
            row = session.get(ThreatIntelMatch, "CVE-2024-1")
            assert row.in_kev is True  # yesterday's row, not cleared


def test_relevant_cves_for_open_findings_extracts_from_either_field() -> None:
    rows = [
        {"rule_id": "CVE-2024-0001", "title": "x"},
        {"rule_id": "GHSA-x", "title": "urllib3: CVE-2024-0002"},
        {"rule_id": "CWE-89", "title": "SQL injection"},
    ]
    assert relevant_cves_for_open_findings(rows) == {"CVE-2024-0001", "CVE-2024-0002"}


def test_refresh_result_ok_requires_both_feeds_to_have_answered() -> None:
    assert RefreshResult(written=1).ok
    assert not RefreshResult(written=0, kev_error="boom").ok
    assert not RefreshResult(written=0, epss_error="boom").ok

class TestTheFeedsAreActuallyReachable:
    """The bug that made this whole page decorative.

    EPSS answers `302 Found` with a relative Location naming the day's file,
    and httpx does not follow redirects unless asked — so `raise_for_status()`
    raised on the redirect and every refresh stored a `fetched_at` with no
    score. 110 CVEs matched to open findings, 0 with an EPSS score, for as long
    as it had been deployed. Fixing it scored 96 of them and surfaced one at
    73% into a band nobody could previously see.
    """

    def _capture(self, monkeypatch, module):
        seen: dict[str, object] = {}

        class _Response:
            content = gzip.compress(
                b"cve,epss,percentile\nCVE-2026-1000,0.5,0.9\n"
            )
            text = ""

            def raise_for_status(self) -> None:
                return None

            def json(self) -> object:
                return {"vulnerabilities": []}

        def fake_get(url, **kwargs):
            seen["url"] = url
            seen.update(kwargs)
            return _Response()

        monkeypatch.setattr(module.httpx2, "get", fake_get)
        return seen

    def test_epss_follows_redirects(self, monkeypatch) -> None:
        from mykronos import threat_intel

        seen = self._capture(monkeypatch, threat_intel)
        threat_intel.default_fetch_epss()

        assert seen.get("follow_redirects") is True, (
            "EPSS 302s to a dated file; without this every score is silently absent"
        )

    def test_kev_follows_redirects(self, monkeypatch) -> None:
        """KEV serves 200 today. There is no reason to be the one that breaks
        when it stops."""
        from mykronos import threat_intel

        seen = self._capture(monkeypatch, threat_intel)
        threat_intel.default_fetch_kev()

        assert seen.get("follow_redirects") is True


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class TestVectorLookup:
    """Base vectors from NVD, so a score can be re-read for one system.

    The platform stored `cvss_score` and no vector, which meant every finding
    carried one number for every system in the world. A score cannot be
    recomputed for an environment; a vector can, and that is the whole
    difference.
    """

    def test_prefers_v31_over_v30_and_ignores_v2(self) -> None:
        """A v2 vector fed to the v3 environmental formula would produce a
        number in the right range and the wrong units."""
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV2": [
                                {"cvssData": {"vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}}
                            ],
                            "cvssMetricV30": [{"cvssData": {"vectorString": V30}}],
                            "cvssMetricV31": [{"cvssData": {"vectorString": V31}}],
                        }
                    }
                }
            ]
        }

        assert threat_intel.parse_nvd_vector(payload) == V31

    def test_an_unscored_cve_returns_none_rather_than_raising(self) -> None:
        """Reserved CVEs and the Debian `TEMP-` identifiers this estate is full
        of have no NVD record at all. That is a real state and must be
        storable, not an error."""
        for payload in ({}, {"vulnerabilities": []}, {"vulnerabilities": [{"cve": {}}]}, None):
            assert threat_intel.parse_nvd_vector(payload) is None

    def test_only_rows_without_a_vector_are_looked_up(self, session) -> None:
        # Its references were read too (TheHub #60890): nothing left to ask.
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2021-44228",
                cvss_vector=V31,
                nvd_refs_checked_at=datetime(2026, 10, 1),
            )
        )
        session.add(ThreatIntelMatch(cve_id="CVE-2014-0160"))
        session.flush()

        asked: list[str] = []

        def fetch(cve_id: str) -> object:
            asked.append(cve_id)
            return {}

        threat_intel.refresh_vectors(session, fetch=fetch, sleep=lambda _: None)

        assert asked == ["CVE-2014-0160"]

    def test_a_miss_is_recorded_so_it_is_not_retried_forever(self, session) -> None:
        """Two thirds of this estate's container findings carry identifiers NVD
        has never heard of. Retrying those daily would be the whole budget."""
        session.add(ThreatIntelMatch(cve_id="CVE-2014-0160"))
        session.flush()

        threat_intel.refresh_vectors(session, fetch=lambda _: {}, sleep=lambda _: None)

        row = session.get(ThreatIntelMatch, "CVE-2014-0160")
        assert row is not None
        assert row.cvss_vector is None
        assert row.vector_checked_at is not None

        asked: list[str] = []
        threat_intel.refresh_vectors(
            session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None
        )
        assert asked == []

    def test_a_failed_lookup_leaves_the_row_for_next_time(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2014-0160"))
        session.flush()

        def boom(_: str) -> object:
            raise RuntimeError("NVD is down")

        found = threat_intel.refresh_vectors(session, fetch=boom, sleep=lambda _: None)

        row = session.get(ThreatIntelMatch, "CVE-2014-0160")
        assert found == 0
        assert row is not None and row.vector_checked_at is None


V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _nvd(**metrics: object) -> dict[str, object]:
    return {"vulnerabilities": [{"cve": {"metrics": metrics}}]}


def _v40(vector: str = V40, score: float = 9.3) -> list[dict[str, object]]:
    return [{"cvssData": {"version": "4.0", "vectorString": vector, "baseScore": score}}]


class TestV4Capture:
    """CVSS v4.0 is stored and shown, never rescored (TheHub #60824, D1).

    NVD publishes `cvssMetricV40` for a growing share of new CVEs, some with
    no v3 beside it. Reading only V31/V30 recorded those as "looked, found
    nothing" -- the same answer as a reserved CVE NVD has never heard of.
    """

    def test_v4_is_read_alongside_v31(self) -> None:
        vectors = threat_intel.parse_nvd_vectors(
            _nvd(cvssMetricV31=[{"cvssData": {"vectorString": V31}}], cvssMetricV40=_v40())
        )

        assert vectors == threat_intel.NvdVectors(v3=V31, v4=V40, v4_base_score=9.3)

    def test_a_v4_only_cve_has_a_v4_and_no_v3(self) -> None:
        vectors = threat_intel.parse_nvd_vectors(_nvd(cvssMetricV40=_v40()))

        assert vectors.v3 is None
        assert vectors.v4 == V40
        # The v3 reader is unchanged: v4 is never handed to the v3 formula.
        assert threat_intel.parse_nvd_vector(_nvd(cvssMetricV40=_v40())) is None

    def test_a_v4_metric_that_is_not_a_v4_vector_is_ignored(self) -> None:
        vectors = threat_intel.parse_nvd_vectors(_nvd(cvssMetricV40=_v40(vector=V31)))

        assert vectors.v4 is None

    def test_a_non_numeric_v4_score_is_dropped_but_the_vector_kept(self) -> None:
        payload = _nvd(cvssMetricV40=[{"cvssData": {"vectorString": V40, "baseScore": "x"}}])

        vectors = threat_intel.parse_nvd_vectors(payload)

        assert vectors.v4 == V40 and vectors.v4_base_score is None

    def test_a_v4_only_cve_no_longer_reads_as_found_nothing(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2025-0001"))
        session.flush()

        found = threat_intel.refresh_vectors(
            session, fetch=lambda _: _nvd(cvssMetricV40=_v40()), sleep=lambda _: None
        )

        row = session.get(ThreatIntelMatch, "CVE-2025-0001")
        assert found == 1
        assert row is not None
        assert row.cvss_vector is None
        assert row.cvss_v4_vector == V40
        assert row.cvss_v4_base_score == 9.3
        assert row.vector_checked_at is not None
        assert row.v4_checked_at is not None

    def test_a_cve_checked_before_v4_was_read_is_asked_once_more(self, session) -> None:
        """A row stamped by the v3-only lookup may have had a v4 it dropped.
        It is eligible exactly once again -- then it is a true miss."""
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2025-0002", vector_checked_at=datetime(2026, 10, 1)
            )
        )
        session.flush()

        asked: list[str] = []

        def fetch(cve_id: str) -> object:
            asked.append(cve_id)
            return _nvd(cvssMetricV40=_v40())

        threat_intel.refresh_vectors(session, fetch=fetch, sleep=lambda _: None)
        threat_intel.refresh_vectors(session, fetch=fetch, sleep=lambda _: None)

        assert asked == ["CVE-2025-0002"]
        row = session.get(ThreatIntelMatch, "CVE-2025-0002")
        assert row is not None and row.cvss_v4_vector == V40

    def test_a_true_miss_is_still_asked_only_once(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2025-0003"))
        session.flush()

        asked: list[str] = []
        for _ in range(2):
            threat_intel.refresh_vectors(
                session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None
            )

        assert asked == ["CVE-2025-0003"]

V31_MOVED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _nvd_with_poc(vector: str) -> dict[str, object]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"vectorString": vector}}]},
                    "references": [{"url": "https://github.com/a/poc", "tags": ["Exploit"]}],
                }
            }
        ]
    }


class TestRefsBackfill:
    """Reading NVD's exploit references for rows looked up before #60890 is a
    backfill, not a second vector lookup (review of #1006): it is capped per
    run, it never rewrites a vector the row already has, and it never counts
    as a new vector -- which is what fans out into an estate-wide rescore."""

    def _known(self, cve_id: str) -> ThreatIntelMatch:
        checked = datetime(2026, 10, 1)
        return ThreatIntelMatch(
            cve_id=cve_id,
            cvss_vector=V31,
            vector_checked_at=checked,
            v4_checked_at=checked,
        )

    def test_a_current_vector_is_not_overwritten_or_rescored(self, session) -> None:
        session.add(self._known("CVE-2021-44228"))
        session.flush()

        found = threat_intel.refresh_vectors(
            session, fetch=lambda _: _nvd_with_poc(V31_MOVED), sleep=lambda _: None
        )

        row = session.get(ThreatIntelMatch, "CVE-2021-44228")
        assert row is not None
        assert found == 0
        assert row.cvss_vector == V31
        assert row.vector_checked_at == datetime(2026, 10, 1)
        assert row.v4_checked_at == datetime(2026, 10, 1)
        assert [r["source"] for r in row.exploit_refs_json] == ["github-poc"]
        assert row.nvd_refs_checked_at is not None

    def test_the_backfill_is_capped_per_run(self, session) -> None:
        for n in range(threat_intel.NVD_REFS_BATCH + 5):
            session.add(self._known(f"CVE-2020-{n:05d}"))
        session.flush()
        asked: list[str] = []

        threat_intel.refresh_vectors(
            session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None
        )

        assert len(asked) == threat_intel.NVD_REFS_BATCH

    def test_a_new_cve_is_looked_up_before_any_backfill(self, session) -> None:
        for n in range(5):
            session.add(self._known(f"CVE-2000-{n:05d}"))
        session.add(ThreatIntelMatch(cve_id="CVE-2026-99999"))
        session.flush()
        asked: list[str] = []

        threat_intel.refresh_vectors(
            session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None, limit=1
        )

        assert asked[0] == "CVE-2026-99999"

    def test_a_full_vector_queue_does_not_starve_the_backfill(self, session) -> None:
        """Production had 3,603 never-looked rows at 20 a day: a backfill that
        took only what the vectors left would not move for months, and every
        scored row would read `not_checked` meanwhile (re-review of #1006)."""
        for n in range(3):
            session.add(self._known(f"CVE-2000-{n:05d}"))
        for n in range(10):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        asked: list[str] = []

        found = threat_intel.refresh_vectors(
            session,
            fetch=lambda c: asked.append(c) or _nvd_with_poc(V31_MOVED),
            sleep=lambda _: None,
            limit=4,
        )

        assert asked == [
            "CVE-2026-00000",
            "CVE-2026-00001",
            "CVE-2026-00002",
            "CVE-2026-00003",
            "CVE-2000-00000",
            "CVE-2000-00001",
            "CVE-2000-00002",
        ]
        # Four new vectors; the backfilled rows are not counted.
        assert found == 4
        for cve_id in ("CVE-2000-00000", "CVE-2000-00001", "CVE-2000-00002"):
            row = session.get(ThreatIntelMatch, cve_id)
            assert row is not None
            assert row.nvd_refs_checked_at is not None
            assert row.cvss_vector == V31
            assert row.vector_checked_at == datetime(2026, 10, 1)


def _status(code: int) -> httpx2.HTTPStatusError:
    request = httpx2.Request("GET", threat_intel.NVD_URL)
    response = httpx2.Response(code, request=request)
    return httpx2.HTTPStatusError(f"HTTP {code}", request=request, response=response)


class TestFailedLookups:
    """A lookup NVD refuses for one CVE is recorded, so it stops sitting at
    the head of both queues every run; a feed that is down charges nobody
    (TheHub #61037)."""
class _Clock:
    """A monotonic clock a test moves, so a time budget needs no sleeping."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _v31_payload(_: str) -> object:
    return {"vulnerabilities": [{"cve": {"metrics": {
        "cvssMetricV31": [{"cvssData": {"vectorString": V31}}]
    }}}]}


class TestTheQueueDrains:
    """TheHub #61034: 3,603 CVEs waited for a vector at 20 a day, ~180 days to
    drain, and none of them could be environmentally scored meanwhile."""

    def test_the_budgets_stay_under_nvds_published_limits(self) -> None:
        """5 requests per 30 s without a key, 50 with one -- with the spacing
        alone, before any response time is counted."""
        bare = threat_intel.nvd_budget("")
        keyed = threat_intel.nvd_budget("a-key")

        assert 30 / bare.delay_seconds < 5
        assert 30 / keyed.delay_seconds < 50
        for budget in (bare, keyed):
            # A whole batch fits inside one run's wall-clock ceiling...
            assert (budget.vectors + budget.refs) * budget.delay_seconds < budget.seconds
            # ... and a run is over well before the next hourly one is due.
            assert budget.seconds < 3_600

    def test_the_measured_backlog_drains_in_days_not_months(self) -> None:
        from mykronos.config import Settings

        interval = Settings().nvd_vector_interval_seconds
        for key in ("", "a-key"):
            per_day = threat_intel.nvd_budget(key).per_day(interval)
            assert 3_603 / per_day < 3

    def test_a_queue_larger_than_one_batch_drains_across_runs(self, session) -> None:
        """Never-looked rows first, then the v4 re-ask, and nothing twice."""
        session.add(
            ThreatIntelMatch(cve_id="CVE-2000-00000", vector_checked_at=datetime(2026, 10, 1))
        )
        for n in range(5):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        runs: list[list[str]] = []

        for _ in range(4):
            asked: list[str] = []
            threat_intel.refresh_vectors(
                session,
                fetch=lambda c, asked=asked: asked.append(c) or {},
                sleep=lambda _: None,
                limit=2,
                refs_limit=0,
            )
            runs.append(asked)

        assert runs == [
            ["CVE-2026-00000", "CVE-2026-00001"],
            ["CVE-2026-00002", "CVE-2026-00003"],
            ["CVE-2026-00004", "CVE-2000-00000"],
            [],
        ]

    def test_a_run_stops_at_its_time_budget_and_the_next_resumes(self, session) -> None:
        for n in range(10):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        clock = _Clock()

        def slow(_: str) -> object:
            clock.now += 4.0  # NVD answering slowly
            return {}

        threat_intel.refresh_vectors(
            session,
            fetch=slow,
            sleep=clock.sleep,
            monotonic=clock,
            delay=1.0,
            budget_seconds=12.0,
            refs_limit=0,
        )

        # Requests start at 0, 5 and 10 s; a fourth would start at 15 s.
        looked = sorted(
            r.cve_id
            for r in session.query(ThreatIntelMatch)
            if r.vector_checked_at is not None
        )
        assert looked == ["CVE-2026-00000", "CVE-2026-00001", "CVE-2026-00002"]

        asked: list[str] = []
        threat_intel.refresh_vectors(
            session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None, limit=2
        )
        assert asked == ["CVE-2026-00003", "CVE-2026-00004"]

    def test_requests_are_spaced_by_the_delay(self, session) -> None:
        for n in range(3):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        slept: list[float] = []

        threat_intel.refresh_vectors(session, fetch=lambda _: {}, sleep=slept.append, delay=0.7)

        assert slept == [0.7, 0.7]

    def test_the_job_uses_the_keyed_budget_and_sends_the_key(self, db, monkeypatch) -> None:
        seen: dict[str, object] = {}

        def fake_refresh(session: object, **kwargs: object) -> int:
            seen.update(kwargs)
            kwargs["fetch"]("CVE-2026-00001")  # type: ignore[operator]
            return 0

        class Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> object:
                return {}

        def fake_get(url: str, **kwargs: object) -> Response:
            seen["headers"] = kwargs.get("headers")
            return Response()

        monkeypatch.setattr(threat_intel, "refresh_vectors", fake_refresh)
        monkeypatch.setattr(threat_intel.httpx2, "get", fake_get)

        threat_intel.vector_job(db, api_key="a-key")
        assert seen["limit"] == threat_intel.NVD_KEYED_BATCH
        assert seen["delay"] == threat_intel.NVD_KEYED_DELAY_SECONDS
        assert seen["headers"] == {"apiKey": "a-key"}

        threat_intel.vector_job(db)
        assert seen["limit"] == threat_intel.NVD_BATCH
        assert seen["delay"] == threat_intel.NVD_DELAY_SECONDS
        assert seen["headers"] is None

    def test_the_key_falls_back_to_nvds_own_variable(self, monkeypatch) -> None:
        monkeypatch.setenv("NVD_API_KEY", "from-env")
        assert threat_intel.nvd_api_key("") == "from-env"
        assert threat_intel.nvd_api_key("configured") == "configured"
        monkeypatch.delenv("NVD_API_KEY")
        assert threat_intel.nvd_api_key("") == ""

    def test_the_daily_job_no_longer_holds_the_vector_lookup(self, db, monkeypatch) -> None:
        from types import SimpleNamespace

        from mykronos import exploitability, worklist

        called: list[str] = []
        monkeypatch.setattr(
            threat_intel, "refresh", lambda session, relevant: RefreshResult(written=0)
        )
        monkeypatch.setattr(threat_intel, "apply_kev_due_dates", lambda s, c: 0)
        monkeypatch.setattr(
            threat_intel, "refresh_vectors", lambda *a, **k: called.append("vectors") or 0
        )
        monkeypatch.setattr(worklist, "break_snoozes_on_kev", lambda db, catalog: None)
        monkeypatch.setattr(
            exploitability,
            "refresh_exploits",
            lambda session: SimpleNamespace(exploitdb_error=None, metasploit_error=None),
        )
        catalog = SimpleNamespace(query=lambda sql, params=None: [])

        threat_intel.refresh_job(db, catalog)  # type: ignore[arg-type]

        assert called == []


class TestTheBacklogIsReported:
    def test_it_counts_both_queues_and_the_rows_given_up(self, session) -> None:
        checked = datetime(2026, 10, 1)
        session.add(ThreatIntelMatch(cve_id="CVE-2026-00001"))
        session.add(ThreatIntelMatch(cve_id="CVE-2026-00002"))
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2026-00003",
                nvd_failures=threat_intel.NVD_MAX_FAILURES,
                nvd_failed_at=checked,
            )
        )
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2021-44228",
                cvss_vector=V31,
                vector_checked_at=checked,
                v4_checked_at=checked,
            )
        )
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2014-0160",
                cvss_vector=V31,
                vector_checked_at=checked,
                v4_checked_at=checked,
                nvd_refs_checked_at=checked,
            )
        )
        session.flush()

        backlog = threat_intel.vector_backlog(session, now=lambda: checked + timedelta(days=1))

        assert backlog == threat_intel.VectorBacklog(vectors=2, refs=1, given_up=1)

    def test_a_given_up_row_is_back_in_the_queue_after_the_retry_days(self, session) -> None:
        # TheHub #61095: the count above read the real clock against a fixed
        # refusal date and went red at midnight on 2026-10-31. Both sides of
        # the boundary, on a fixed clock.
        failed = datetime(2026, 10, 1)
        session.add(
            ThreatIntelMatch(
                cve_id="CVE-2026-00003",
                nvd_failures=threat_intel.NVD_MAX_FAILURES,
                nvd_failed_at=failed,
            )
        )
        session.flush()
        days = timedelta(days=threat_intel.NVD_RETRY_DAYS)

        inside = threat_intel.vector_backlog(session, now=lambda: failed + days)
        past = threat_intel.vector_backlog(
            session, now=lambda: failed + days + timedelta(seconds=1)
        )

        assert inside == threat_intel.VectorBacklog(vectors=0, refs=0, given_up=1)
        assert past == threat_intel.VectorBacklog(vectors=1, refs=0, given_up=0)

    def test_the_sentence_says_how_many_and_how_long(self) -> None:
        backlog = threat_intel.VectorBacklog(vectors=3_603, refs=1_650, given_up=4)

        detail = backlog.detail(threat_intel.nvd_budget(""), 3_600)

        assert detail == (
            "3,603 CVEs wait for a CVSS vector (about 1.9 days at 1,920 vectors a day); "
            "1,650 for exploit references (about 1.7 days at 960 a day); "
            "4 not asked for 30 days after 5 refusals"
        )

    def test_an_empty_queue_says_so_without_a_rate(self) -> None:
        detail = threat_intel.VectorBacklog(0, 0, 0).detail(threat_intel.nvd_budget(""), 3_600)

        assert detail == "0 CVEs wait for a CVSS vector; 0 for exploit references"

    def test_the_platform_health_row_carries_it(self, client, admin_auth, monkeypatch) -> None:
        from mykronos.api import dashboard
        from mykronos.db.models import JobRun

        async def checks(_settings: object) -> list[object]:
            return []

        monkeypatch.setattr(dashboard, "jobs_self_check", checks)
        with client.app.state.db.session() as opened:
            opened.add(
                JobRun(
                    name=threat_intel.NVD_JOB,
                    last_run_at=datetime(2026, 10, 27),
                    last_succeeded_at=datetime(2026, 10, 27),
                    interval_seconds=3_600,
                )
            )
            opened.add(ThreatIntelMatch(cve_id="CVE-2026-00001"))

        body = client.get("/api/dashboard/platform-health", headers=admin_auth).json()

        row = next(j for j in body["jobs"] if j["name"] == threat_intel.NVD_JOB)
        assert "1 CVE wait for a CVSS vector" in row["detail"]


def _boom(_: str) -> object:
    raise RuntimeError("NVD answered garbage")


class TestAFailingLookupStopsBlocking:
    """TheHub #61037: a fetch that always failed stamped nothing, so the row
    stayed at the head of the queue and took a request from every run."""

    def _known(self, cve_id: str) -> ThreatIntelMatch:
        checked = datetime(2026, 10, 1)
        return ThreatIntelMatch(
            cve_id=cve_id, cvss_vector=V31, vector_checked_at=checked, v4_checked_at=checked
        )

    def _fetch(self, bad: set[str], asked: list[str], exc: Exception | None = None):
        def fetch(cve_id: str) -> object:
            asked.append(cve_id)
            if cve_id in bad:
                raise exc or _status(404)
            return _nvd_with_poc(V31)

        return fetch

    def test_a_refused_lookup_is_recorded_and_retried_later(self, session) -> None:
        session.add(self._known("CVE-2000-00001"))
        session.flush()

        threat_intel.refresh_vectors(
            session,
            fetch=self._fetch({"CVE-2000-00001"}, []),
            sleep=lambda _: None,
            now=lambda: datetime(2026, 10, 2),
        )
        row = session.get(ThreatIntelMatch, "CVE-2000-00001")
        assert row is not None
        assert (row.nvd_failures, row.nvd_failed_at) == (1, datetime(2026, 10, 2))
        assert row.nvd_refs_checked_at is None

        asked: list[str] = []
        threat_intel.refresh_vectors(
            session, fetch=self._fetch(set(), asked), sleep=lambda _: None
        )
        assert asked == ["CVE-2000-00001"]
        assert (row.nvd_failures, row.nvd_failed_at) == (0, None)
        assert row.nvd_refs_checked_at is not None

    def test_permanently_refused_rows_do_not_stop_a_healthy_row_behind_them(
        self, session
    ) -> None:
        bad = {f"CVE-2000-{n:05d}" for n in range(threat_intel.NVD_REFS_BATCH + 5)}
        for cve_id in bad:
            session.add(self._known(cve_id))
        session.add(self._known("CVE-2001-00000"))
        session.flush()

        first: list[str] = []
        threat_intel.refresh_vectors(session, fetch=self._fetch(bad, first), sleep=lambda _: None)
        assert "CVE-2001-00000" not in first
        second: list[str] = []
        threat_intel.refresh_vectors(
            session, fetch=self._fetch(bad, second), sleep=lambda _: None
        )

        assert "CVE-2001-00000" in second
        row = session.get(ThreatIntelMatch, "CVE-2001-00000")
        assert row is not None and row.nvd_refs_checked_at is not None

    def test_a_refused_vector_lookup_queues_after_new_cves(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2000-00001"))
        session.add(ThreatIntelMatch(cve_id="CVE-2026-00001"))
        session.flush()
        threat_intel.refresh_vectors(
            session, fetch=self._fetch({"CVE-2000-00001"}, []), sleep=lambda _: None, limit=1
        )
        asked: list[str] = []

        threat_intel.refresh_vectors(
            session, fetch=self._fetch(set(), asked), sleep=lambda _: None, limit=1
        )

        assert asked == ["CVE-2026-00001"]

    def test_after_the_limit_a_row_is_no_longer_asked(self, session) -> None:
        session.add(self._known("CVE-2000-00001"))
        session.flush()
        for _ in range(threat_intel.NVD_MAX_FAILURES):
            threat_intel.refresh_vectors(
                session, fetch=self._fetch({"CVE-2000-00001"}, []), sleep=lambda _: None
            )
        asked: list[str] = []

        threat_intel.refresh_vectors(
            session, fetch=self._fetch({"CVE-2000-00001"}, asked), sleep=lambda _: None
        )

        assert asked == []
        row = session.get(ThreatIntelMatch, "CVE-2000-00001")
        assert row is not None and row.nvd_refs_checked_at is None

    def test_a_retired_row_is_asked_again_after_the_window(self, session) -> None:
        """A retirement that was wrong, or a CVE NVD publishes late, heals
        itself rather than staying unasked for ever."""
        last = datetime(2026, 10, 1)
        row = self._known("CVE-2000-00001")
        row.nvd_failures = threat_intel.NVD_MAX_FAILURES
        row.nvd_failed_at = last
        session.add(row)
        session.flush()
        window = timedelta(days=threat_intel.NVD_RETRY_DAYS)

        early: list[str] = []
        threat_intel.refresh_vectors(
            session,
            fetch=self._fetch(set(), early),
            sleep=lambda _: None,
            now=lambda: last + window - timedelta(hours=1),
        )
        later: list[str] = []
        threat_intel.refresh_vectors(
            session,
            fetch=self._fetch(set(), later),
            sleep=lambda _: None,
            now=lambda: last + window + timedelta(hours=1),
        )

        assert (early, later) == ([], ["CVE-2000-00001"])
        assert (row.nvd_failures, row.nvd_failed_at) == (0, None)
        assert row.nvd_refs_checked_at is not None

    @pytest.mark.parametrize(
        "exc",
        [
            httpx2.ConnectError("down"),
            _status(429),
            _status(403),
            _status(503),
            ValueError("Expecting value: line 1 column 1 (char 0)"),
            KeyError("vulnerabilities"),
        ],
        ids=["transport", "429", "403", "503", "html-body", "parser"],
    )
    def test_a_feed_failure_charges_no_row(self, session, exc: Exception) -> None:
        """NVD being down or rate-limiting this address says nothing about the
        CVE: counting it would retire the whole estate after a five-day outage.
        Nor does a 200 that is a maintenance page, or a parser that broke: only
        a 4xx NVD chose to send is about the CVE."""
        session.add(self._known("CVE-2000-00001"))
        session.flush()

        threat_intel.refresh_vectors(
            session, fetch=self._fetch({"CVE-2000-00001"}, [], exc), sleep=lambda _: None
        )

        row = session.get(ThreatIntelMatch, "CVE-2000-00001")
        assert row is not None
        assert (row.nvd_failures, row.nvd_failed_at) == (0, None)

    def test_a_successful_lookup_is_unchanged(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2026-00001"))
        session.flush()

        found = threat_intel.refresh_vectors(
            session, fetch=self._fetch(set(), []), sleep=lambda _: None
        )

        row = session.get(ThreatIntelMatch, "CVE-2026-00001")
        assert row is not None
        assert found == 1 and row.cvss_vector == V31
        assert (row.nvd_failures, row.nvd_failed_at) == (0, None)

    def test_a_transient_failure_retries_and_then_reads_as_normal(self, session) -> None:
        session.add(ThreatIntelMatch(cve_id="CVE-2014-0160"))
        session.flush()

        threat_intel.refresh_vectors(session, fetch=_boom, sleep=lambda _: None)
        found = threat_intel.refresh_vectors(session, fetch=_v31_payload, sleep=lambda _: None)

        row = session.get(ThreatIntelMatch, "CVE-2014-0160")
        assert row is not None
        assert found == 1
        assert row.cvss_vector == V31
        assert row.vector_checked_at is not None
        assert row.nvd_failures == 0
        assert row.nvd_failed_at is None

    def test_nvd_rate_limiting_ends_the_run(self, session) -> None:
        import httpx2

        for n in range(3):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        asked: list[str] = []

        def limited(cve_id: str) -> object:
            asked.append(cve_id)
            request = httpx2.Request("GET", threat_intel.NVD_URL)
            raise httpx2.HTTPStatusError(
                "403", request=request, response=httpx2.Response(403, request=request)
            )

        threat_intel.refresh_vectors(session, fetch=limited, sleep=lambda _: None)

        assert asked == ["CVE-2026-00000"]
        # A 403 describes the feed, not the CVE, so it charges no row (#1034).
        row = session.get(ThreatIntelMatch, "CVE-2026-00000")
        assert row is not None and row.nvd_failures == 0
