"""What THIS change did, headlined beside the standing posture (TheHub #60914).

TheHub develop 525152e passed all nine lanes and introduced nothing
(`introduced={}`, `introduced_blocking=false`), yet the delivery view and the
decision headline read "no_go 100/100". Every TheHub commit reads the same,
so a developer learns to ignore the gate. D-048 and S60732 settled that
`no_go` describes the backlog; the verdict a developer acts on is what the
commit introduced. This is presentation only: the policy, the recorded
recommendation and deploy.ps1's rule are untouched.

So every by-commit decision and every delivery row carries two things,
named apart:

- `change`: "change: clean" or "change: introduces N blocking", by the same
  rule as `introduced_blocking` (an open critical or high this commit
  introduced);
- `posture`: the Oracle recommendation and score, labelled as posture.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.dashboard import DashboardQueries
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.po_support import connect  # noqa: F401

NEW = "b" * 40
OTHER = "c" * 40


def _change(introduced: dict[str, int] | None, overridden: bool = False) -> dict[str, Any]:
    from mykronos.change_verdict import change_of

    return change_of(introduced, overridden=overridden).model_dump()


class TestTheRule:
    def test_nothing_introduced_is_clean(self) -> None:
        change = _change({})
        assert change["verdict"] == "clean"
        assert change["blocking"] == 0
        assert change["text"] == "change: clean"

    def test_a_medium_introduced_is_clean_and_says_what_it_did_bring(self) -> None:
        change = _change({"medium": 2, "low": 1})
        assert change["verdict"] == "clean"
        assert change["non_blocking"] == 3
        assert change["text"] == "change: clean"

    def test_critical_and_high_are_blocking(self) -> None:
        change = _change({"critical": 1, "high": 2, "medium": 4})
        assert change["verdict"] == "introduces_blocking"
        assert change["blocking"] == 3
        assert change["text"] == "change: introduces 3 blocking"

    def test_an_override_is_shown_and_does_not_rewrite_what_the_change_did(self) -> None:
        change = _change({"high": 1}, overridden=True)
        assert change["verdict"] == "introduces_blocking"
        assert change["overridden"] is True
        assert "overridden" in change["text"]

    def test_an_unread_count_is_unknown_never_clean(self) -> None:
        change = _change(None)
        assert change["verdict"] == "unknown"
        assert change["blocking"] is None
        assert "clean" not in change["text"]

    def test_posture_is_labelled_as_posture(self) -> None:
        from mykronos.change_verdict import posture_of

        posture = posture_of("no_go", 100).model_dump()
        assert posture == {
            "recommendation": "no_go",
            "score": 100,
            "text": "posture: no_go 100/100",
        }
        assert posture_of(None, None).text == "posture: not recorded"


# -- /api/oracle/decisions/by-commit -------------------------------------------


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


def _scan(client, auth, run_compaction, scan_run_id, commit, findings, **extra):
    post_scan(client, auth, scan_run_id=scan_run_id, commit_sha=commit, **extra)
    post_findings(client, auth, findings, scan_run_id=scan_run_id)
    run_compaction()


def _gate(client, oracle_auth, run_compaction, commit) -> None:
    client.post(
        "/api/oracle/evaluate",
        json={"commit_sha": commit, "decision_type": "commit_gate"},
        headers=oracle_auth,
    )
    run_compaction()


class TestByCommit:
    def test_a_clean_commit_on_a_backlog_headlines_clean_beside_its_posture(
        self, client, auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        # The backlog: an old commit's critical, still open.
        _scan(
            client, auth, run_compaction, "run-old", "a" * 40,
            [finding_payload(rule_id="R0", severity="critical")],
        )
        _scan(
            client, auth, run_compaction, "run-new", NEW,
            [finding_payload(rule_id="R1", severity="medium")],
        )
        _gate(client, oracle_auth, run_compaction, NEW)

        body = client.get(f"/api/oracle/decisions/by-commit/{NEW}", headers=viewer_auth).json()

        assert body["change"]["verdict"] == "clean"
        assert body["change"]["text"] == "change: clean"
        assert body["posture"]["recommendation"] == body["recommendation"]
        assert body["posture"]["score"] == body["overall_risk_score"]
        assert body["posture"]["text"].startswith("posture: ")
        # The fields deploy.ps1 reads are unchanged.
        assert body["introduced_blocking"] is False

    def test_a_commit_that_introduced_a_high_headlines_it(
        self, client, auth, oracle_auth, viewer_auth, run_compaction
    ) -> None:
        _scan(
            client, auth, run_compaction, "run-new", NEW,
            [finding_payload(rule_id="R1", severity="high")],
        )
        _gate(client, oracle_auth, run_compaction, NEW)

        body = client.get(
            f"/api/oracle/decisions/by-commit/{NEW[:7]}", headers=viewer_auth
        ).json()

        assert body["change"] == {
            "verdict": "introduces_blocking",
            "blocking": 1,
            "non_blocking": 0,
            "overridden": False,
            "text": "change: introduces 1 blocking",
        }
        assert body["introduced_blocking"] is True

    def test_an_unjudged_commit_carries_neither(self, client, viewer_auth) -> None:
        body = client.get(f"/api/oracle/decisions/by-commit/{OTHER}", headers=viewer_auth).json()
        assert body["found"] is False
        assert body.get("change") is None and body.get("posture") is None


# -- /product-owner/delivery ---------------------------------------------------


def _decision(sha: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "decision_id": f"d-{sha}",
        "repo_full_name": REPO,
        "decision_type": "commit_gate",
        "pr_number": None,
        "release_tag": None,
        "commit_sha": sha,
        "overall_risk_score": 100,
        "recommendation": "no_go",
        "inputs_snapshot": "{}",
        "reasoning": "",
        "policy_version": "1.1",
        "evaluated_at": utcnow() - timedelta(hours=1),
        "human_override": None,
        "github_check_run_id": None,
        "gate_outcome": None,
    }
    row.update(overrides)
    return row


def _delivery(client: TestClient, repo_id: str, headers: dict[str, str]) -> dict[str, Any]:
    url = f"/api/dashboard/repos/{repo_id}/product-owner/delivery"
    body: dict[str, Any] = client.get(url, headers=headers).json()
    return {row["sha"]: row for row in body["shipped"] + body["not_shipped"]}


class TestDeliveryRows:
    def test_each_row_headlines_its_change_and_labels_the_posture(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        buffer: Any,
        run_compaction: Callable[[], Any],
    ) -> None:
        repo_id, _ = connect([])
        _scan(
            client, auth, run_compaction, "run-clean", OTHER,
            [finding_payload(rule_id="R2", severity="low")],
            pr_number=None, triggered_by="push",
        )
        _scan(
            client, auth, run_compaction, "run-blocking", NEW,
            [finding_payload(rule_id="R1", severity="critical")],
            pr_number=None, triggered_by="push",
        )
        buffer.append("risk_decisions", [_decision(OTHER), _decision(NEW)])
        run_compaction()

        rows = _delivery(client, repo_id, viewer_auth)

        clean = rows[OTHER]["decision"]
        assert clean["change"]["verdict"] == "clean"
        assert clean["change"]["text"] == "change: clean"
        assert clean["posture"]["text"] == "posture: no_go 100/100"
        blocking = rows[NEW]["decision"]
        assert blocking["change"]["verdict"] == "introduces_blocking"
        assert blocking["change"]["text"] == "change: introduces 1 blocking"
        # The recorded recommendation is still there, unchanged.
        assert blocking["recommendation"] == "no_go"

    def test_an_unreadable_introduced_count_is_unknown_not_clean(
        self,
        client: TestClient,
        auth: dict[str, str],
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        buffer: Any,
        run_compaction: Callable[[], Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo_id, _ = connect([])
        _scan(client, auth, run_compaction, "run-new", NEW, [], pr_number=None,
              triggered_by="push")
        buffer.append("risk_decisions", [_decision(NEW)])
        run_compaction()

        def broken(self: Any, pairs: Any) -> Any:
            raise RuntimeError("lake unreadable")

        monkeypatch.setattr(DashboardQueries, "introduced_by_commits", broken)
        rows = _delivery(client, repo_id, viewer_auth)

        assert rows[NEW]["decision"]["change"]["verdict"] == "unknown"
        assert rows[NEW]["decision"]["posture"]["text"] == "posture: no_go 100/100"
