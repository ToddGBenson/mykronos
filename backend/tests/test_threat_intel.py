"""Public exploitation data — spec 17 §4."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import UTC, date, datetime

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

        assert asked == ["CVE-2026-99999"]

    def test_backfill_shares_the_run_budget(self, session) -> None:
        for n in range(5):
            session.add(self._known(f"CVE-2000-{n:05d}"))
        for n in range(3):
            session.add(ThreatIntelMatch(cve_id=f"CVE-2026-{n:05d}"))
        session.flush()
        asked: list[str] = []

        threat_intel.refresh_vectors(
            session, fetch=lambda c: asked.append(c) or {}, sleep=lambda _: None, limit=4
        )

        assert asked[:3] == ["CVE-2026-00000", "CVE-2026-00001", "CVE-2026-00002"]
        assert len(asked) == 4
