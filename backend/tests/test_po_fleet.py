"""The agent fleet view (spec 35 §8.6, D-147).

Runs, verification verdicts and cost are read through the fake TheHub; every
gate failure must name its Accountable role from TheHub's RACI table, or say
it has no agent owner.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import po_fleet
from mykronos.schemas import utcnow
from tests.po_support import connect, onboard, story  # noqa: F401

#: TheHub CLAUDE.md, "RACI over the agent fleet [AGENT-3 #48555]": the
#: Activity, Responsible and Accountable columns, as written there, with two
#: long cells cut short (marked …). The copy in `po_fleet.RACI` is checked
#: against these rows, so it changes only on purpose.
SOURCE = """
| Idea intake & backlog triage (`dev_oplans`, …) | Operator | **Synth** (AIAgentOps) |
| Epic discovery & decomposition (`dev_epics` stages) | Operator | **Atlas** (DevOps) |
| Requirements / ADR authorship | Operator | **Warden** (HubOps) |
| Technical design (story gate `designed`) | Operator | **Warden** (HubOps) |
| Threat model / security review | Operator | **Vance** (SOC) |
| Sprint planning / pull (`bucket='sprint'`) | Operator | **Warden** (HubOps) |
| Implementation (Coding stage) | Operator / Claude Code session | **Operator** — no agent … |
| Automated testing & coverage gate | CI | **Atlas** (DevOps) |
| UX / usability review | Operator | **Operator** — the Hub has no UX agent |
| Data quality & freshness contracts | Curator | **Curator** (DataOps) |
| Build, package & artifact management | CI | **Atlas** (DevOps) |
| Deploy to staging + smoke test | CI / deploy.sh | **Atlas** (DevOps) |
| Manual approval → deploy to prod | Operator | **Operator** — human-gated by design |
| Post-deploy verification & incident escalation | Beacon, IRRA | **Beacon** (NOC) |
"""


def ago(**delta: Any) -> str:
    return (utcnow() - timedelta(**delta)).isoformat()


def fleet(client: TestClient, repo_id: str, auth: dict[str, str], **params: Any) -> Any:
    response = client.get(
        f"/api/dashboard/repos/{repo_id}/product-owner/fleet", params=params, headers=auth
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestRaci:
    def test_the_copy_matches_the_source_rows(self) -> None:
        rows = [
            [cell.strip() for cell in line.strip().strip("|").split("|")]
            for line in SOURCE.strip().splitlines()
        ]
        assert len(rows) == len(po_fleet.RACI)
        for (activity, responsible, accountable), row in zip(rows, po_fleet.RACI, strict=True):
            assert activity.startswith(row.activity), (activity, row.activity)
            assert responsible == row.responsible
            name = accountable.split("**")[1]
            assert row.accountable.startswith(name)
            assert row.operator_only == ("—" in accountable)

    def test_every_hub_gate_has_an_activity(self) -> None:
        for gate in ("intake", "clarified", "designed", "ready", "tested", "deployed", "verified"):
            row, message = po_fleet.owner_of(gate)
            assert row is not None and not row.operator_only
            assert message == f"blocked at {row.activity}, Accountable: {row.accountable}"

    def test_operator_only_activities_have_no_agent_owner(self) -> None:
        row, message = po_fleet.owner_of("in_progress")
        assert row is not None and row.operator_only
        assert "no agent owner" in message
        assert "Accountable:" not in message


class TestFleet:
    def test_runs_verdicts_cost_and_owned_failures(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, hub = connect(
            [
                story(id=1, bucket="sprint", gate="in_progress"),
                # A sprint story at `clarified` with no acceptance criteria
                # fails its gate check: Requirements, Accountable Warden.
                story(id=2, bucket="sprint", gate="clarified", acceptance_criteria=[]),
                story(id=3, bucket="done", gate="verified", closed_at=ago(days=1)),
                story(id=4, bucket="sprint", tags=["repo:keel"]),
            ]
        )
        hub.runs[1] = [
            {
                "id": 10,
                "status": "shipped",
                "dry_run": False,
                "cost_usd": 1.25,
                "started_at": ago(hours=20),
            },
            {
                "id": 11,
                "status": "aborted_timeout",
                "dry_run": False,
                "cost_usd": 0.5,
                "started_at": ago(days=2),
            },
            # Outside the 7-day window.
            {
                "id": 12,
                "status": "aborted_fail",
                "dry_run": False,
                "cost_usd": 9.0,
                "started_at": ago(days=20),
            },
        ]
        hub.runs[3] = [
            {
                "id": 13,
                "status": "dry_run",
                "dry_run": True,
                "cost_usd": 0,
                "status_as_written": "shipped",
                "started_at": ago(days=1),
            },
        ]
        hub.verification[3] = {
            "status": "rejected",
            "implementer_agent": "atlas",
            "verifier_agent": "qa",
            "reason": "the edge case has no test",
            "decided_at": ago(days=1),
        }
        hub.dashboard["in_flight"] = [
            {"run_id": 20, "story_id": 1, "story_title": "A story", "elapsed_seconds": 30},
            {"run_id": 21, "story_id": 4, "story_title": "keel's", "elapsed_seconds": 30},
        ]

        body = fleet(client, repo_id, admin_auth)
        assert [r["run_id"] for r in body["runs"]] == [10, 13, 11]
        assert body["outcomes"] == {"shipped": 1, "dry_run": 1, "aborted_timeout": 1}
        assert body["cost_usd"] == 1.75
        assert [v["status"] for v in body["verdicts"]] == ["rejected"]
        assert [r["story_id"] for r in body["estate"]["in_flight"]] == [1]

        owners = {(f["story_id"], f["kind"]): f for f in body["failures"]}
        assert set(owners) == {
            (1, "run_aborted"),
            (3, "verification_rejected"),
            (2, "gate_check_failed"),
        }
        assert owners[(3, "verification_rejected")]["owner"] == (
            "blocked at Automated testing & coverage gate, Accountable: Atlas (DevOps)"
        )
        assert owners[(2, "gate_check_failed")]["accountable"] == "Warden (HubOps)"
        aborted = owners[(1, "run_aborted")]
        assert aborted["accountable"] is None
        assert "no agent owner" in aborted["owner"]
        # Every failure shown names an owner or says it has none.
        assert all(f["accountable"] or "no agent owner" in f["owner"] for f in body["failures"])

    def test_a_dry_run_is_never_counted_as_shipped(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        """Even if TheHub forgot its correction and said `shipped`."""
        repo_id, hub = connect([story(id=1, bucket="sprint", gate="in_progress")])
        hub.runs[1] = [
            {"id": 1, "status": "shipped", "dry_run": True, "started_at": ago(hours=2)},
        ]
        body = fleet(client, repo_id, viewer_auth)
        assert body["outcomes"] == {"shipped": 0, "dry_run": 1}
        assert body["runs"][0]["shipped"] is False

    def test_the_window_is_chosen(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, hub = connect([story(id=1, bucket="sprint", gate="in_progress")])
        hub.runs[1] = [
            {"id": 1, "status": "aborted_fail", "dry_run": False, "started_at": ago(days=20)},
        ]
        assert fleet(client, repo_id, viewer_auth)["runs"] == []
        assert len(fleet(client, repo_id, viewer_auth, days=30)["runs"]) == 1

    def test_no_hub_says_not_connected_and_shows_no_counts(
        self, client: TestClient, viewer_auth: dict[str, str], github: Any
    ) -> None:
        repo_id = onboard(client)
        client.app.state.hub = None  # type: ignore[attr-defined]
        body = fleet(client, repo_id, viewer_auth)
        assert body["hub"] == {"connected": False, "error": "TheHub is not connected."}
        assert body["outcomes"] is None and body["cost_usd"] is None

    def test_an_unreadable_dashboard_is_said_and_the_runs_still_show(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, hub = connect([story(id=1, bucket="sprint", gate="in_progress")])
        hub.failing.add("/api/devops/autonomy/dashboard")
        hub.runs[1] = [{"id": 1, "status": "shipped", "dry_run": False, "started_at": ago(hours=1)}]
        body = fleet(client, repo_id, viewer_auth)
        assert body["estate"] is None
        assert "HTTP 500" in body["estate_error"]
        assert body["outcomes"]["shipped"] == 1
