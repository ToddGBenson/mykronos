"""The risk gate posts when a repository's decision changes (TheHub #61197).

Before this, every `no_go` from `POST /api/oracle/evaluate` posted "A risk
decision refused a commit", so a repository refused for its backlog posted
the same score on every commit: 33 times on 10-31, 130 posts in 14 days.

The rule, per repository and decision scope:

* clean -> refused (or refused the first time it is seen): one post.
* refused -> refused: nothing, whatever the score, unless the commit itself
  introduced a critical or high finding (a new blocking finding), which posts.
* refused -> clean: one "passes again" post.
* clean -> clean: nothing.

The recorded state is in the database, so a restart does not post again.
Tests use the recording notifier; nothing here reaches Slack.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.config import Settings
from mykronos.main import create_app
from mykronos.notify import Notification
from mykronos.oracle.engine import Decision
from mykronos.oracle.service import PublishedDecision
from mykronos.github.factory import FakeGitHubClientFactory
from tests.conftest import REPO, issue_token

#: Pinned so no assertion depends on the wall clock.
FIXED = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


class RecordingNotifier:
    """Records what would have gone to Slack."""

    enabled = True

    def __init__(self) -> None:
        self.sent: list[Notification] = []

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


class ScriptedService:
    """Stands in for `OracleService`: returns the next scripted decision.

    The scoring engine has its own tests; this is about what the endpoint
    does with a decision, so the decision is chosen by the test."""

    def __init__(self) -> None:
        self.next: tuple[str, int] = ("no_go", 100)

    async def evaluate_and_publish(
        self, repo_full_name: str, **kwargs: Any
    ) -> PublishedDecision:
        recommendation, score = self.next
        pr_number = kwargs.get("pr_number")
        return PublishedDecision(
            decision=Decision(
                decision_id=f"d-{kwargs.get('commit_sha')}",
                repo_full_name=repo_full_name,
                decision_type="pr_gate" if pr_number else "commit_gate",
                commit_sha=str(kwargs.get("commit_sha") or ""),
                pr_number=pr_number,
                release_tag=None,
                overall_risk_score=score,
                recommendation=recommendation,
                reasoning=f"No-go at {score}/100. 12 open high findings.",
                inputs_snapshot={},
                policy_version="test",
                evaluated_at=FIXED,
            ),
            blocking=False,
        )


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch) -> ScriptedService:
    service = ScriptedService()
    monkeypatch.setattr("mykronos.api.oracle._service", lambda request: service)
    return service


@pytest.fixture
def notified(client: TestClient) -> RecordingNotifier:
    recorder = RecordingNotifier()
    client.app.state.notifier = recorder  # type: ignore[attr-defined]
    return recorder


def _evaluate(
    client: TestClient, token: str, sha: str, pr_number: int | None = None
) -> dict[str, Any]:
    body: dict[str, Any] = {"commit_sha": sha, "decision_type": "commit_gate"}
    if pr_number is not None:
        body = {"commit_sha": sha, "decision_type": "pr_gate", "pr_number": pr_number}
    response = client.post(
        "/api/oracle/evaluate",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestTheRule:
    """The transition table, without the endpoint."""

    @pytest.mark.parametrize(
        ("previous", "recommendation", "introduced_blocking", "expected"),
        [
            (None, "no_go", False, "refused"),
            (None, "go", False, None),
            (None, "go_withheld", False, None),
            ("clear", "no_go", False, "refused"),
            ("refused", "no_go", False, None),
            ("refused", "no_go", True, "new_blocking"),
            ("refused", "go", False, "cleared"),
            ("refused", "go_withheld", False, "cleared"),
            ("clear", "go", False, None),
        ],
    )
    def test_transitions(
        self,
        previous: str | None,
        recommendation: str,
        introduced_blocking: bool,
        expected: str | None,
    ) -> None:
        from mykronos import risk_gate_notice

        assert (
            risk_gate_notice.decide(previous, recommendation, introduced_blocking)
            == expected
        )

    def test_a_pull_request_is_its_own_subject(self) -> None:
        """A refused pull request says nothing about main, and the reverse."""
        from mykronos import risk_gate_notice

        assert risk_gate_notice.subject_of("commit_gate", None) == "commit_gate"
        assert risk_gate_notice.subject_of("pr_gate", 7) == "pr_gate#7"
        assert risk_gate_notice.subject_of("pr_gate", 8) != risk_gate_notice.subject_of(
            "pr_gate", 7
        )


class TestADayOfCommits:
    def test_the_same_decision_posts_nothing(
        self, client: TestClient, notified: RecordingNotifier, scripted: ScriptedService
    ) -> None:
        """10-31 as it happened: 33 commits refused for the same backlog,
        the score moving between 96 and 100. One post, not 33."""
        token = issue_token(client, REPO, "oracle")
        for i in range(33):
            scripted.next = ("no_go", 96 + i % 5)
            _evaluate(client, token, f"sha{i:03d}")

        assert len(notified.sent) == 1
        assert notified.sent[0].title == "A risk decision refused a commit"
        assert "sha000" in notified.sent[0].detail

    def test_a_change_posts_once_each_way(
        self, client: TestClient, notified: RecordingNotifier, scripted: ScriptedService
    ) -> None:
        """A day: refused all morning, cleared at noon, clean all afternoon,
        refused again in the evening. Three posts across 50 commits, where
        the old rule posted one per refused commit (43)."""
        token = issue_token(client, REPO, "oracle")
        timeline = (
            [("no_go", 100)] * 30
            + [("go", 40)] * 7
            + [("no_go", 98)] * 13
        )
        for i, decision in enumerate(timeline):
            scripted.next = decision
            _evaluate(client, token, f"c{i:03d}")

        assert [note.title for note in notified.sent] == [
            "A risk decision refused a commit",
            "The risk gate passes again",
            "A risk decision refused a commit",
        ]
        refused, cleared, again = notified.sent
        assert "c000" in refused.detail
        assert "c030" in cleared.detail
        # The reader learns how much was held back, and since when.
        assert "c000" in cleared.detail
        assert "29" in cleared.detail
        assert cleared.level == "info"
        assert "c037" in again.detail

    def test_a_clean_day_posts_nothing(
        self, client: TestClient, notified: RecordingNotifier, scripted: ScriptedService
    ) -> None:
        token = issue_token(client, REPO, "oracle")
        for i in range(20):
            scripted.next = ("go", 30)
            _evaluate(client, token, f"g{i:03d}")
        assert notified.sent == []

    def test_a_new_blocking_finding_posts_while_refused(
        self,
        client: TestClient,
        notified: RecordingNotifier,
        scripted: ScriptedService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Already refused for the backlog is not the same news as a commit
        that adds a critical: that one is announced."""
        token = issue_token(client, REPO, "oracle")
        scripted.next = ("no_go", 100)
        _evaluate(client, token, "base")
        _evaluate(client, token, "quiet")

        from mykronos.dashboard import DashboardQueries

        monkeypatch.setattr(
            DashboardQueries,
            "introduced_by",
            lambda self, repo, sha: {"critical": 1} if sha == "adds" else {},
        )
        _evaluate(client, token, "adds")
        _evaluate(client, token, "after")

        assert len(notified.sent) == 2
        assert "adds" in notified.sent[1].detail
        assert "new" in notified.sent[1].title.lower()

    def test_a_pull_request_does_not_reset_main(
        self, client: TestClient, notified: RecordingNotifier, scripted: ScriptedService
    ) -> None:
        token = issue_token(client, REPO, "oracle")
        scripted.next = ("no_go", 100)
        _evaluate(client, token, "m1")
        scripted.next = ("go", 20)
        _evaluate(client, token, "p1", pr_number=7)
        scripted.next = ("no_go", 100)
        _evaluate(client, token, "m2")

        # main refused once; the clean PR, first seen clean, is silent.
        assert len(notified.sent) == 1


def test_a_restart_does_not_post_the_same_refusal_again(
    settings: Settings,
    github: Any,
    monkeypatch: pytest.MonkeyPatch,
    scripted: ScriptedService,
) -> None:
    """The state is in the database, not in memory."""

    def run(sha: str) -> list[Notification]:
        with TestClient(create_app(settings)) as client:
            client.app.state.github_factory = FakeGitHubClientFactory(github)  # type: ignore[attr-defined]
            recorder = RecordingNotifier()
            client.app.state.notifier = recorder  # type: ignore[attr-defined]
            token = issue_token(client, REPO, "oracle")
            _evaluate(client, token, sha)
            return recorder.sent

    scripted.next = ("no_go", 100)
    assert len(run("before")) == 1
    assert run("after") == []
