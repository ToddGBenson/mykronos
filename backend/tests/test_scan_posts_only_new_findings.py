"""A scan posts only the high/critical findings it is first to see (TheHub #61195).

Comms audit change 3 (TheHub #61176). Before this, every findings batch
posted `<lane> reported N critical` for the whole standing backlog: 318 posts
in 14 days, 220 of them verbatim repeats, because the same 16 criticals were
re-reported on every scan and the reader could not tell new from old.

Pinned here:

* a scan with no new high/critical finding posts nothing in real time,
  whether the earlier sighting is compacted into the lake or still buffered;
* a new finding posts once, and the post links to the finding's page;
* a batch with old and new findings posts only the new ones, and its counts
  are the new ones, never the backlog's;
* the backlog's totals are in the daily digest (the briefing DM) instead.

No test sends anything to Slack: the notifier is a recorder throughout.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import briefing_dm, daily_briefing
from mykronos.api.briefing_daily import DailyBriefingOut
from mykronos.config import Settings
from mykronos.lake import compact
from mykronos.main import create_app
from mykronos.notify import Notification
from tests.conftest import REPO, issue_token, post_findings

FIRST_RUN = "11111111-1111-1111-1111-111111111111"
SECOND_RUN = "22222222-2222-2222-2222-222222222222"
DASHBOARD = "https://mykronos.example"


class Recorder:
    """A notifier that keeps what it was given and sends nothing anywhere."""

    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


def _finding(n: int, severity: str = "critical") -> dict[str, Any]:
    return {
        "rule_id": f"rule-{n}",
        "title": f"Exposed secret number {n}",
        "description": "d",
        "severity": severity,
        "file_path": f"app/f{n}.py",
        "line_start": 10,
    }


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "datalake_dir": tmp_path / "lake",
        "database_url": f"sqlite:///{(tmp_path / 'm.db').as_posix()}",
        "run_compaction_in_background": False,
        "run_jobs_in_background": False,
        "gate_token": "",
        "github_app_id": "",
        "github_app_private_key_path": None,
        "slack_notify_min_severity": "high",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def app_client(tmp_path: Path) -> Any:
    with TestClient(create_app(_settings(tmp_path, dashboard_url=DASHBOARD + "/"))) as client:
        client.app.state.notifier = Recorder()  # type: ignore[attr-defined]
        yield client


def _auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'secrets')}"}


def _post(client: TestClient, auth: dict[str, str], findings: list[dict[str, Any]],
          run: str) -> None:
    response = post_findings(client, auth, findings, scan_run_id=run, capability="secrets")
    assert response.status_code == 200, response.text


def _compact(client: TestClient) -> None:
    state = client.app.state  # type: ignore[attr-defined]
    compact(state.catalog, state.buffer, db=state.db)


def _sent(client: TestClient) -> list[Notification]:
    return client.app.state.notifier.sent  # type: ignore[attr-defined, no-any-return]


def _onboard(client: TestClient) -> str:
    from mykronos.db.models import Organization, RepoOnboarding

    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        org = Organization(github_org_login=REPO.split("/")[0])
        session.add(org)
        session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=REPO,
            github_installation_id=1,
            status="active",
            enabled_capabilities=["secrets"],
            default_branch="main",
            onboarded_by="test",
        )
        session.add(row)
        session.flush()
        return str(row.id)


def _finding_ids(client: TestClient) -> dict[str, str]:
    """title -> finding_id, as the lake holds them."""
    rows = client.app.state.catalog.query(  # type: ignore[attr-defined]
        "SELECT title, finding_id FROM findings"
    )
    return {str(title): str(fid) for title, fid in rows}


def _text(note: Notification) -> str:
    return "\n".join([note.title, note.detail, *note.lines])


class TestRealTimePostsOnlyNewFindings:
    def test_a_rescan_of_the_compacted_backlog_posts_nothing(
        self, app_client: TestClient
    ) -> None:
        """The 220 repeats: the same criticals, a later scan, already in the
        lake. Nothing is new, so nothing is posted."""
        auth = _auth(app_client)
        backlog = [_finding(n) for n in range(16)]
        _post(app_client, auth, backlog, FIRST_RUN)
        assert len(_sent(app_client)) == 1
        _compact(app_client)

        _post(app_client, auth, backlog, SECOND_RUN)
        assert len(_sent(app_client)) == 1, [n.title for n in _sent(app_client)]

    def test_a_rescan_before_compaction_posts_nothing_either(
        self, app_client: TestClient
    ) -> None:
        """Compaction runs every five minutes, and a lane can post twice in
        that window. A finding still in the write-ahead buffer is known."""
        auth = _auth(app_client)
        _post(app_client, auth, [_finding(1)], FIRST_RUN)
        _post(app_client, auth, [_finding(1)], SECOND_RUN)
        assert len(_sent(app_client)) == 1

    def test_three_scans_of_one_new_finding_post_once(self, app_client: TestClient) -> None:
        auth = _auth(app_client)
        _post(app_client, auth, [_finding(1)], FIRST_RUN)
        _compact(app_client)
        _post(app_client, auth, [_finding(1)], SECOND_RUN)
        _post(app_client, auth, [_finding(1)], "33333333-3333-3333-3333-333333333333")
        assert len(_sent(app_client)) == 1

    def test_a_new_finding_among_the_backlog_posts_only_itself(
        self, app_client: TestClient
    ) -> None:
        """The counts in the post are the new ones. The backlog's sixteen are
        not in it: they are the digest's to report."""
        auth = _auth(app_client)
        backlog = [_finding(n) for n in range(16)]
        _post(app_client, auth, backlog, FIRST_RUN)
        _compact(app_client)

        _post(app_client, auth, [*backlog, _finding(99, "high")], SECOND_RUN)
        assert len(_sent(app_client)) == 2
        note = _sent(app_client)[-1]
        assert "1 new high" in note.title
        assert "critical" not in note.title
        text = _text(note)
        assert "Exposed secret number 99" in text
        assert "Exposed secret number 0" not in text
        assert "16" not in note.title

    def test_the_title_says_new_not_reported(self, app_client: TestClient) -> None:
        """'reported' was the honest word for a post that could not tell new
        from old. This one can."""
        auth = _auth(app_client)
        _post(app_client, auth, [_finding(1), _finding(2, "high")], FIRST_RUN)
        title = _sent(app_client)[0].title
        assert "reported" not in title
        assert "1 new critical" in title and "1 new high" in title

    def test_a_new_finding_links_to_its_page(self, app_client: TestClient) -> None:
        repo_id = _onboard(app_client)
        auth = _auth(app_client)
        _post(app_client, auth, [_finding(7)], FIRST_RUN)
        _compact(app_client)
        finding_id = _finding_ids(app_client)["Exposed secret number 7"]

        text = _text(_sent(app_client)[0])
        assert f"{DASHBOARD}/repos/{repo_id}/findings/{finding_id}" in text

    def test_below_the_floor_stays_silent(self, app_client: TestClient) -> None:
        auth = _auth(app_client)
        _post(app_client, auth, [_finding(1, "medium")], FIRST_RUN)
        assert _sent(app_client) == []


class TestTheBacklogIsInTheDigest:
    def test_the_risk_delta_counts_the_open_high_and_critical_backlog(
        self, app_client: TestClient
    ) -> None:
        auth = _auth(app_client)
        _post(
            app_client,
            auth,
            [_finding(1), _finding(2), _finding(3, "high"), _finding(4, "medium")],
            FIRST_RUN,
        )
        _compact(app_client)
        state = app_client.app.state  # type: ignore[attr-defined]
        read = daily_briefing.read_risk_delta(
            state.catalog, state.db, now=datetime.now(UTC).replace(tzinfo=None)
        )
        data = daily_briefing.risk_delta_section(read).data
        assert data["open_backlog"] == {"total": 3, "by_severity": {"critical": 2, "high": 1}}

    def test_the_dm_carries_the_backlog_overall_and_per_product(self) -> None:
        backlog = {"total": 18, "by_severity": {"critical": 16, "high": 2}}

        def section(key: str, data: dict[str, Any]) -> dict[str, Any]:
            return {
                "key": key, "title": key, "status": "ok", "source": "test",
                "as_of": "2026-11-01T13:00:00", "reason": "", "lines": [], "data": data,
            }

        overall = DailyBriefingOut.model_validate({
            "generated_at": "2026-11-01T14:00:00", "scope": "overall",
            "repo_full_name": None,
            "sections": [section("risk_delta", {"open_backlog": backlog})],
        })
        product = DailyBriefingOut.model_validate({
            "generated_at": "2026-11-01T14:00:00", "scope": "product",
            "repo_full_name": REPO,
            "sections": [section("findings_delta", {
                "window_hours": 24, "introduced": {"total": 0}, "closed": {"total": 0},
                "open_backlog": backlog,
            })],
        })
        note = briefing_dm.compose(
            overall,
            [briefing_dm.ProductRead(REPO, product)],
            url=f"{DASHBOARD}/briefing",
            local_now=datetime(2026, 11, 1, 7, 0),
        )
        text = "\n".join(note.lines)
        assert "*Open critical/high backlog:* 16 critical, 2 high." in text
        assert "18 open critical/high" in briefing_dm.product_line(
            briefing_dm.ProductRead(REPO, product)
        )
