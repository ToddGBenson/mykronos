"""Public exploitation data — spec 17 §4."""

from __future__ import annotations

import gzip
from collections.abc import Iterator
from datetime import UTC, date, datetime

import pytest

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
