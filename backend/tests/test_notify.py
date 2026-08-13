"""Slack notification (spec 16 §14).

Two halves, tested separately because they fail differently:

- `SlackNotifier` itself, where the property that matters is that *nothing* it
  does can reach the caller as an exception.
- The three hooks, where the property that matters is which events fire and —
  more importantly — which do not. An alert channel is destroyed by volume
  rather than by silence, so most of these assert that something stayed quiet.
"""

from __future__ import annotations

from typing import Any

import httpx2
import pytest
from fastapi.testclient import TestClient

from mykronos.config import Settings
from mykronos.main import create_app
from mykronos.notify import Notification, SlackNotifier
from tests.conftest import REPO, issue_token, post_findings, post_scan


class RecordingNotifier:
    """Stands in for the real notifier and records what it was asked to send.

    A fake rather than a mocked webhook: the assertion is about which events
    the endpoints decide are worth reporting, and routing that decision through
    an HTTP stub would test Slack's API shape instead.
    """

    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


@pytest.fixture
def notified(client: TestClient) -> RecordingNotifier:
    recorder = RecordingNotifier()
    client.app.state.notifier = recorder  # type: ignore[attr-defined]
    return recorder


class TestTheNotifierItself:
    def test_no_webhook_means_disabled_rather_than_broken(self) -> None:
        """The common case. An unconfigured deployment posts nowhere, and that
        is a state rather than an error (spec 12 §5.2's rule about defaults)."""
        assert SlackNotifier("").enabled is False
        assert SlackNotifier("   ").enabled is False

    async def test_a_disabled_notifier_reports_that_it_sent_nothing(self) -> None:
        sent = await SlackNotifier("").send(
            Notification(title="t", detail="d", repo_full_name=REPO)
        )
        assert sent is False

    async def test_slack_being_down_is_never_an_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The rule the whole module exists to keep. A security platform that
        stops accepting findings because a chat service is unreachable has
        inverted its own priorities."""

        class Exploding:
            async def __aenter__(self) -> Exploding:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def post(self, *args: Any, **kwargs: Any) -> Any:
                raise httpx2.ConnectError("no route to host")

        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: Exploding())
        sent = await SlackNotifier("https://hooks.slack.test/x").send(
            Notification(title="t", detail="d", repo_full_name=REPO)
        )
        assert sent is False

    async def test_a_4xx_from_slack_is_reported_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class Rejecting:
            async def __aenter__(self) -> Rejecting:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

            async def post(self, *args: Any, **kwargs: Any) -> Any:
                return httpx2.Response(404, text="no_service")

        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: Rejecting())
        sent = await SlackNotifier("https://hooks.slack.test/x").send(
            Notification(title="t", detail="d", repo_full_name=REPO)
        )
        assert sent is False

    def test_untrusted_text_is_scrubbed_on_the_way_out(self) -> None:
        """Finding titles come from scanner output, which comes from repository
        content. A newline in one would otherwise forge a line of the message."""
        rendered = Notification(
            title="Injected\r\n:rotating_light: *SYSTEM*",
            detail="also\nnewlines",
            repo_full_name=REPO,
        ).render()
        assert "\r" not in rendered
        assert "Injected" in rendered

    def test_a_long_message_is_truncated(self) -> None:
        rendered = Notification(
            title="t", detail="x" * 10_000, repo_full_name=REPO
        ).render()
        assert len(rendered) <= 2_500


class TestScanFailureAlerts:
    def test_a_failed_scan_notifies(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """The alert that matters most and reads as the dullest: a failed scan
        reports no findings, which is indistinguishable from a clean repository
        on every dashboard (spec 04 §6)."""
        post_scan(
            client,
            auth,
            scan_status="failure",
            completed_at="2026-08-12T10:00:00Z",
            finding_count=0,
        )
        assert len(notified.sent) == 1
        assert "failure" in notified.sent[0].title
        assert notified.sent[0].repo_full_name == REPO

    def test_partial_failure_notifies_too(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        post_scan(
            client,
            auth,
            scan_status="partial_failure",
            completed_at="2026-08-12T10:00:00Z",
        )
        assert len(notified.sent) == 1

    def test_the_opening_post_is_silent(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """A scan run is posted twice (D-002). The first has no `completed_at`,
        and alerting on it would fire on every scan that merely started."""
        post_scan(client, auth, scan_status="failure", completed_at=None)
        assert notified.sent == []

    def test_a_successful_scan_is_silent(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        post_scan(
            client, auth, scan_status="success", completed_at="2026-08-12T10:00:00Z"
        )
        assert notified.sent == []

    def test_nothing_to_scan_is_silent(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """L0001's third state is a normal result for a repo with no
        Dockerfiles or no declared dependencies. Alerting on it trains people
        to ignore the channel, which is how the real alerts stop being read."""
        post_scan(
            client,
            auth,
            scan_status="no_applicable_targets",
            completed_at="2026-08-12T10:00:00Z",
        )
        assert notified.sent == []


def _finding(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": "py/sql-injection",
        "title": "SQL injection",
        "description": "d",
        "severity": "critical",
        "file_path": "app/db.py",
        "line_start": 10,
    }
    payload.update(overrides)
    return payload


class TestFindingAlerts:
    def test_one_message_per_batch_not_per_finding(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """The rule that keeps this channel readable. A scan uploading four
        hundred criticals is one event a person needs to know about."""
        post_findings(
            client,
            auth,
            [_finding(rule_id=f"r{n}", file_path=f"a/{n}.py") for n in range(50)],
        )
        assert len(notified.sent) == 1
        assert "50 critical" in notified.sent[0].title

    def test_the_summary_lists_a_handful_and_says_how_many_it_left_out(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        post_findings(
            client,
            auth,
            [_finding(rule_id=f"r{n}", file_path=f"a/{n}.py") for n in range(9)],
        )
        assert "...and 4 more." in notified.sent[0].detail

    def test_findings_below_the_floor_are_silent(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """They are still ingested for trend data (spec 04 §5). Ingested and
        announced are different questions."""
        response = post_findings(client, auth, [_finding(severity="low")])
        assert response.status_code == 200
        assert notified.sent == []

    def test_an_empty_batch_is_silent(
        self, client: TestClient, auth: dict[str, str], notified: RecordingNotifier
    ) -> None:
        """An empty batch is how a scanner says 'I ran and found nothing',
        which is a good outcome and not news."""
        post_findings(client, auth, [])
        assert notified.sent == []

    def test_the_floor_is_configurable(
        self, tmp_path: Any, notified: RecordingNotifier
    ) -> None:
        """`high` is the default; a noisy portfolio can raise it to `critical`
        rather than turn notification off entirely."""
        settings = Settings(
            datalake_dir=tmp_path / "lake",
            database_url=f"sqlite:///{(tmp_path / 'm.db').as_posix()}",
            run_compaction_in_background=False,
            run_jobs_in_background=False,
            gate_token="",
            github_app_id="",
            github_app_private_key_path=None,
            slack_notify_min_severity="critical",
        )
        with TestClient(create_app(settings)) as client:
            recorder = RecordingNotifier()
            client.app.state.notifier = recorder  # type: ignore[attr-defined]
            token = issue_token(client, REPO, "sast")
            auth = {"Authorization": f"Bearer {token}"}

            post_findings(client, auth, [_finding(severity="high")])
            assert recorder.sent == []

            post_findings(client, auth, [_finding(severity="critical")])
            assert len(recorder.sent) == 1


class TestOracleGateAlerts:
    """`no_go` is the one decision that stops a deploy, and the pipeline that
    asked has already exited by the time anybody looks at the build."""

    def _seed_and_evaluate(
        self,
        client: TestClient,
        auth: dict[str, str],
        run_compaction: Any,
        count: int,
        notified: RecordingNotifier,
    ) -> Any:
        from tests.test_oracle import critical, seed

        if count:
            seed(client, auth, run_compaction, [critical(i) for i in range(count)])
        else:
            post_scan(client, auth, scan_run_id="none")
            post_findings(client, auth, [], scan_run_id="none")
            run_compaction()

        # Seeding critical findings legitimately fires the findings alert.
        # Cleared so these assertions are about the gate rather than about
        # whatever the fixture had to create to make the gate say no.
        notified.sent.clear()

        token = issue_token(client, REPO, "oracle")
        return client.post(
            "/api/oracle/evaluate",
            json={"commit_sha": "abc123", "decision_type": "portfolio"},
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_a_no_go_notifies(
        self,
        client: TestClient,
        auth: dict[str, str],
        run_compaction: Any,
        notified: RecordingNotifier,
    ) -> None:
        response = self._seed_and_evaluate(client, auth, run_compaction, 3, notified)
        assert response.json()["recommendation"] == "no_go"
        assert len(notified.sent) == 1
        assert notified.sent[0].level == "critical"
        assert "abc123" in notified.sent[0].detail

    def test_a_go_is_silent(
        self,
        client: TestClient,
        auth: dict[str, str],
        run_compaction: Any,
        notified: RecordingNotifier,
    ) -> None:
        """Every clean build would otherwise post. The gate passing is the
        normal case and is not news."""
        response = self._seed_and_evaluate(client, auth, run_compaction, 0, notified)
        assert response.json()["recommendation"] == "go"
        assert notified.sent == []
