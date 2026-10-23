"""The weekly intelligence briefing and its flash DM (TheHub #60865, B7).

Acceptance criteria, each a test that reads as its statement:

- A Monday page per application.
- A flash DM fires only on an exploited or critical match.
- Every item cites its source.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, date, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import briefing_flash
from mykronos import weekly_briefing as wb
from mykronos.api.briefing_weekly import WeeklyBriefingOut, WeeklyPageOut
from mykronos.config import Settings
from mykronos.db.models import AuditLogEntry, PublicEndpoint, ThreatIntelMatch
from mykronos.jobs import JobSkipped
from mykronos.lake import compact
from mykronos.notify import Notification
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

NOW = datetime(2026, 10, 22, 15, 0, 0)  # a Thursday
TODAY = date(2026, 10, 22)
MONDAY = date(2026, 10, 19)


def _row(finding_id: str, **values: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "finding_id": finding_id,
        "capability": "atlas",
        "rule_id": "",
        "title": "",
        "severity": "high",
        "package_name": "",
        "package_version": "",
        "version_basis": "resolved",
        "file_path": "backend/pyproject.toml",
        "raw_finding_json": "{}",
        "first_seen_at": datetime(2026, 9, 1),
        "shipped": True,
    }
    row.update(values)
    return row


def _inputs(**overrides: Any) -> wb.Inputs:
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "repo_id": "repo-1",
        "findings": [
            # Known exploited, shipped, high: a flash.
            _row("kev", rule_id="CVE-2026-1000", package_name="urllib3",
                 package_version="2.0.4", severity="high",
                 raw_finding_json=json.dumps({"fixed_version": "2.2.2"})),
            # Critical, shipped, not exploited: a flash.
            _row("crit", rule_id="CVE-2026-2000", package_name="jinja2", severity="critical"),
            # High, shipped, not exploited: the page, not a flash.
            _row("high", rule_id="CVE-2026-3000", package_name="idna", severity="high",
                 first_seen_at=datetime(2026, 10, 20)),
            # Critical, but only on a pull-request branch: not a flash.
            _row("branch", rule_id="CVE-2026-4000", package_name="lxml", severity="critical",
                 shipped=False),
            # High by the scanner, critical here: a flash.
            _row("env", rule_id="CVE-2026-5000", package_name="pyyaml", severity="high"),
            # In a file nothing imports: set aside.
            _row("orphan", rule_id="CVE-2026-6000", package_name="six", severity="critical",
                 file_path="tools/unused.py"),
            # A container on an end-of-life base, in a declared surface.
            _row("os", capability="containers", rule_id="CVE-2026-7000",
                 package_name="openssl", severity="medium", version_basis=None,
                 file_path="shop-backend",
                 raw_finding_json=json.dumps(
                     {"image": "shop-backend:abc", "base_os_eol": True, "base_os": "debian 10"}
                 )),
            _row("mal", rule_id="MAL-2026-42", package_name="colourama", severity="critical",
                 version_basis="declared_floor"),
            _row("secret", capability="secrets", rule_id="generic-api-key",
                 file_path="config/settings.py"),
            _row("sast", capability="sast", rule_id="py/sql-injection"),
        ],
        "intel": {
            "CVE-2026-1000": {"in_kev": True, "kev_added_at": date(2026, 10, 1),
                              "epss_score": 0.91},
            "CVE-2026-2000": {"in_kev": False, "epss_score": 0.02},
            "CVE-2026-7000": {"in_kev": True},
        },
        "environmental": {"env": "critical", "high": "high"},
        "orphaned": {"tools/unused.py"},
        "surfaces": [
            {
                "id": "s1",
                "kind": "entry_point",
                "name": "Public shop",
                "exposure": "internet",
                "selectors": {"images": ["library/shop-backend"]},
            }
        ],
        "endpoints": [
            {"url": "https://shop.example.net/", "last_status": "open",
             "last_probed_at": NOW}
        ],
    }
    values.update(overrides)
    return wb.Inputs(**values)


def _page(**overrides: Any) -> wb.WeeklyPage:
    return wb.build(_inputs(**overrides), now=NOW, local_today=TODAY)


def _section(page: wb.WeeklyPage, key: str) -> wb.Section:
    return next(s for s in page.sections if s.key == key)


SECTION_KEYS = [
    "advisories",
    "threat_model",
    "end_of_life",
    "malicious_packages",
    "external_exposure",
    "vendor_changes",
    "standards",
]


class TestPage:
    def test_the_page_is_a_mondays(self) -> None:
        page = _page()

        assert page.week_of == MONDAY
        assert [s.key for s in page.sections] == SECTION_KEYS

    def test_every_item_cites_its_source(self) -> None:
        page = _page()
        items = list(page.items())

        assert len(items) >= 8
        for item in items:
            assert item.source.startswith(("https://", "/repos/")), item
            assert item.what and item.so_what and item.action, item
            assert item.confidence in ("observed", "inferred")
            assert item.confidence_reason, item

    def test_advisories_rank_exploited_first_and_set_aside_the_unreachable(self) -> None:
        section = _section(_page(), "advisories")
        names = [i.what.split(" ", 1)[0] for i in section.items]

        assert names[0] in ("CVE-2026-1000", "CVE-2026-7000")
        assert set(names[:2]) == {"CVE-2026-1000", "CVE-2026-7000"}
        assert "CVE-2026-6000" not in names
        assert "MAL-2026-42" not in names
        assert section.data["set_aside_unreachable"] == 1
        assert section.data["known_exploited"] == 2
        kev = section.items[names.index("CVE-2026-1000")]
        assert kev.source == "https://nvd.nist.gov/vuln/detail/CVE-2026-1000"
        assert "Known exploited" in kev.so_what and "EPSS 91.0%" in kev.so_what
        assert kev.action == "Upgrade urllib3 to 2.2.2 or later."
        assert kev.confidence == "observed"
        env = section.items[names.index("CVE-2026-5000")]
        assert "Critical here (scanner: high)" in env.so_what
        new = section.items[names.index("CVE-2026-3000")]
        assert new.new_this_week and not kev.new_this_week

    def test_threats_are_fitted_to_the_declared_model(self) -> None:
        section = _section(_page(), "threat_model")

        assert section.status == "ok"
        assert [i.what for i in section.items] == [
            "CVE-2026-7000 lands in Public shop (entry point)"
        ]
        assert "declares Public shop as internet" in section.items[0].so_what

    def test_no_declared_model_is_said_not_left_empty(self) -> None:
        section = _section(_page(surfaces=[]), "threat_model")

        assert section.status == "not_available"
        assert "declares no threat model" in section.reason

    def test_end_of_life_images(self) -> None:
        section = _section(_page(), "end_of_life")

        assert [i.what for i in section.items] == [
            "shop-backend:abc is built on debian 10, which is end-of-life"
        ]
        assert section.items[0].source == "/repos/repo-1/findings/os"
        assert section.status == "partial" and "runtimes" in section.reason

    def test_malicious_packages(self) -> None:
        section = _section(_page(), "malicious_packages")

        assert len(section.items) == 1
        item = section.items[0]
        assert item.source == "https://osv.dev/vulnerability/MAL-2026-42"
        assert item.confidence == "inferred" and "declared floor" in item.confidence_reason

    def test_external_exposure(self) -> None:
        section = _section(_page(), "external_exposure")

        whats = [i.what for i in section.items]
        assert "https://shop.example.net/: open" in whats
        assert "1 open secret finding(s) in the code" in whats
        assert "Shodan/Censys" in section.reason

    def test_feeds_that_do_not_exist_are_named(self) -> None:
        page = _page()

        vendors = _section(page, "vendor_changes")
        assert vendors.status == "not_available"
        for name in ("GitHub", "Cloudflare", "Concourse", "Next.js", "FastAPI"):
            assert name in vendors.reason
        assert _section(page, "standards").status == "not_available"

    def test_an_unreadable_lake_is_unavailable_not_all_clear(self) -> None:
        page = _page(findings=None)

        for key in ("advisories", "threat_model", "end_of_life", "malicious_packages"):
            section = _section(page, key)
            assert section.status == "unavailable", key
            assert section.items == [] and section.reason

    def test_unreadable_intel_makes_advisories_partial(self) -> None:
        section = _section(_page(intel=None), "advisories")

        assert section.status == "partial"
        assert "KEV and EPSS" in section.reason


class TestFlashRule:
    def test_a_flash_is_only_an_exploited_or_critical_match_to_something_shipped(
        self,
    ) -> None:
        page = _page()
        flashed = {i.key for i in page.flashes()}

        assert "advisory:CVE-2026-1000:urllib3" in flashed  # KEV, shipped
        assert "advisory:CVE-2026-2000:jinja2" in flashed  # critical, shipped
        assert "advisory:CVE-2026-5000:pyyaml" in flashed  # critical here, shipped
        assert "advisory:CVE-2026-3000:idna" not in flashed  # high, not exploited
        assert "advisory:CVE-2026-4000:lxml" not in flashed  # critical, not shipped
        assert not any(k.startswith(("eol:", "exposure:")) for k in flashed)
        for item in page.flashes():
            assert item.flash_reason in (
                "known exploited (CISA KEV) and shipped",
                "critical and shipped",
            )


# --------------------------------------------------------------------------
# The flash DM
# --------------------------------------------------------------------------


class RecordingNotifier:
    enabled = True

    def __init__(self, accept: bool = True) -> None:
        self.sent: list[Notification] = []
        self.accept = accept

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return self.accept


def _configured(settings: Settings, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "slack_bot_token": "xoxb-test-not-a-token",
        "briefing_dm_channel": "U0TODD",
        "dashboard_url": "https://mykronos.example/",
    }
    values.update(overrides)
    return settings.model_copy(update=values)


def _reader(page: wb.WeeklyPage) -> Any:
    import dataclasses

    out = WeeklyBriefingOut(
        generated_at=NOW,
        week_of=page.week_of,
        pages=[WeeklyPageOut.model_validate(dataclasses.asdict(page))],
    )

    async def read() -> WeeklyBriefingOut:
        return out

    return read


class TestFlashDm:
    def test_fires_once_for_each_exploited_or_critical_match(
        self, client: TestClient, settings: Settings
    ) -> None:
        db = client.app.state.db
        notifier = RecordingNotifier()

        sent = asyncio.run(
            briefing_flash.send_flashes(
                _configured(settings), db=db, read=_reader(_page()), notifier=notifier
            )
        )

        assert {f.key for f in sent} == {
            "advisory:CVE-2026-1000:urllib3",
            "advisory:CVE-2026-2000:jinja2",
            "advisory:CVE-2026-5000:pyyaml",
            "advisory:CVE-2026-7000:openssl",
            "malicious:MAL-2026-42:colourama",
        }
        assert len(notifier.sent) == 1
        text = notifier.sent[0].render()
        assert "CVE-2026-3000" not in text and "CVE-2026-4000" not in text
        assert "https://nvd.nist.gov/vuln/detail/CVE-2026-1000" in text
        with db.session() as session:
            audited = session.scalars(
                select(AuditLogEntry).where(AuditLogEntry.action == briefing_flash.ACTION)
            ).all()
        assert len(audited) == 5

        again = asyncio.run(
            briefing_flash.send_flashes(
                _configured(settings), db=db, read=_reader(_page()), notifier=notifier
            )
        )
        assert again == []
        assert len(notifier.sent) == 1

    def test_nothing_exploited_or_critical_sends_nothing(
        self, client: TestClient, settings: Settings
    ) -> None:
        quiet = _page(
            findings=[_row("high", rule_id="CVE-2026-3000", package_name="idna")],
            intel={},
            environmental={},
        )
        notifier = RecordingNotifier()

        sent = asyncio.run(
            briefing_flash.send_flashes(
                # Unconfigured, and still not skipped: a quiet week is a success.
                settings, db=client.app.state.db, read=_reader(quiet), notifier=notifier
            )
        )

        assert sent == [] and notifier.sent == []

    def test_something_to_send_without_slack_is_skipped_by_name(
        self, client: TestClient, settings: Settings
    ) -> None:
        with pytest.raises(JobSkipped, match="MYKRONOS_SLACK_BOT_TOKEN"):
            asyncio.run(
                briefing_flash.send_flashes(
                    settings, db=client.app.state.db, read=_reader(_page()),
                    notifier=RecordingNotifier(),
                )
            )

    def test_an_undelivered_flash_is_retried(
        self, client: TestClient, settings: Settings
    ) -> None:
        db = client.app.state.db
        with pytest.raises(briefing_flash.FlashUndeliveredError):
            asyncio.run(
                briefing_flash.send_flashes(
                    _configured(settings), db=db, read=_reader(_page()),
                    notifier=RecordingNotifier(accept=False),
                )
            )
        assert briefing_flash.already_sent(db) == set()


# --------------------------------------------------------------------------
# API, end to end through ingestion
# --------------------------------------------------------------------------


def _ingest(client: TestClient, *, scan_id: str, branch: str, pr: int | None,
            cve: str, severity: str) -> None:
    token = issue_token(client, REPO, "atlas")
    auth = {"Authorization": f"Bearer {token}"}
    r = post_scan(
        client, auth, scan_run_id=scan_id, capability="atlas", tool_name="osv-scanner",
        branch=branch, pr_number=pr, triggered_by="push" if pr is None else "pull_request",
    )
    assert r.status_code in (200, 201), r.text
    r = post_findings(
        client,
        auth,
        [
            {
                "rule_id": cve,
                "title": f"{cve} in requests",
                "severity": severity,
                "package_name": "requests",
                "package_version": "2.0.0",
                "file_path": "backend/pyproject.toml",
            }
        ],
        scan_run_id=scan_id,
        capability="atlas",
    )
    assert r.status_code in (200, 201, 202), r.text


class TestApi:
    def test_a_monday_page_per_application(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        onboard(client, admin_auth, scanned_by="concourse")
        onboard(client, admin_auth, repo="example-org/second-app", scanned_by="concourse")

        r = client.get("/api/briefing/weekly", headers=admin_auth)

        assert r.status_code == 200, r.text
        out = r.json()
        assert date.fromisoformat(out["week_of"]).weekday() == 0
        assert sorted(p["repo_full_name"] for p in out["pages"]) == [
            REPO, "example-org/second-app"
        ]
        for page in out["pages"]:
            assert page["week_of"] == out["week_of"]
            assert [s["key"] for s in page["sections"]] == SECTION_KEYS

        one = out["pages"][0]["repo_id"]
        r = client.get(f"/api/briefing/weekly?repo_id={one}", headers=admin_auth)
        assert [p["repo_id"] for p in r.json()["pages"]] == [one]

    def test_shipped_is_the_default_branch_and_kev_makes_a_flash(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        onboard(client, admin_auth, scanned_by="concourse")
        _ingest(client, scan_id="33333333-3333-3333-3333-333333333333", branch="main",
                pr=None, cve="CVE-2026-8000", severity="high")
        _ingest(client, scan_id="44444444-4444-4444-4444-444444444444", branch="feature",
                pr=7, cve="CVE-2026-9000", severity="critical")
        compact(client.app.state.catalog, client.app.state.buffer)
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2026-8000", in_kev=True))
            session.add(
                PublicEndpoint(url="https://shop.example.net/", repo_full_name=REPO,
                               last_status="gated",
                               last_probed_at=datetime.now(UTC).replace(tzinfo=None))
            )

        r = client.get("/api/briefing/weekly", headers=admin_auth)

        assert r.status_code == 200, r.text
        page = r.json()["pages"][0]
        advisories = next(s for s in page["sections"] if s["key"] == "advisories")
        items = {i["what"].split(" ", 1)[0]: i for i in advisories["items"]}
        assert items["CVE-2026-8000"]["flash"] is True
        assert items["CVE-2026-9000"]["flash"] is False
        assert "not the default" in items["CVE-2026-9000"]["so_what"]
        for section in page["sections"]:
            for item in section["items"]:
                assert item["source"].startswith(("https://", "/repos/"))
