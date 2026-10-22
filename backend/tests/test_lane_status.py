"""A stopped lane reads retired or stale, never current (TheHub #60816).

When one capability has two lanes and one stops reporting, the capability
still reads fresh off the other. Pinned here: a lane the configuration no
longer lists - a Concourse job gone from the pipeline's job list, an Actions
tool gone from the repository's capability config - reads retired; a lane a
person retired on purpose reads retired, with who and why, audited and
reversible; any other lane that stopped reads stale; and only a lane that
reported recently reads current.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import ci, lane_status
from mykronos.db.models import AuditLogEntry, CapabilityConfig, RepoOnboarding
from tests.conftest import CAPABILITY, REPO, issue_token, post_scan
from tests.test_onboarding import onboard

NOW = datetime(2026, 10, 21, 12, 0, 0)


def _classify(**overrides: Any) -> lane_status.LaneVerdict:
    args: dict[str, Any] = {
        "pipeline": ci.THEHUB,
        "capability": "dast",
        "tool_name": "zap",
        "job": "dast-staging",
        "last_run_at": NOW - timedelta(hours=3),
        "config": {},
        "retirement": None,
        "now": NOW,
    }
    args.update(overrides)
    return lane_status.classify(**args)


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------


class TestTheRule:
    def test_a_configured_lane_that_reported_recently_is_current(self) -> None:
        assert _classify().state == lane_status.CURRENT

    def test_a_configured_lane_that_stopped_is_stale_not_current(self) -> None:
        verdict = _classify(last_run_at=NOW - timedelta(days=lane_status.LANE_STALE_DAYS + 1))
        assert (verdict.state, verdict.basis) == (lane_status.STALE, "age")
        assert "retired" in verdict.reason

    def test_a_lane_that_never_finished_is_stale(self) -> None:
        verdict = _classify(last_run_at=None)
        assert (verdict.state, verdict.basis) == (lane_status.STALE, "never_finished")

    def test_a_weekly_lane_is_current_between_runs(self) -> None:
        assert _classify(last_run_at=NOW - timedelta(days=7, hours=6)).state == lane_status.CURRENT

    def test_a_job_gone_from_the_pipeline_job_list_is_retired(self) -> None:
        # `dast-demo-old` is in no pipeline's job list: as if removed from
        # thehub.yml and from CAPABILITY_BY_JOB with it.
        verdict = _classify(job="dast-demo-old", last_run_at=NOW - timedelta(days=40))
        assert (verdict.state, verdict.basis) == (lane_status.RETIRED, "config")
        assert "thehub" in verdict.reason and "dast-demo-old" in verdict.reason

    def test_retired_by_config_even_while_it_still_reports(self) -> None:
        verdict = _classify(job="dast-demo-old")
        assert verdict.state == lane_status.RETIRED

    def test_a_job_declared_for_another_capability_is_not_this_ones(self) -> None:
        # thehub's `qa` job serves `qa`; as a `dast` lane it is not configured.
        assert _classify(job="qa").state == lane_status.RETIRED

    def test_a_job_declaring_two_capabilities_serves_both(self) -> None:
        for capability in ("functional", "dast"):
            verdict = _classify(pipeline=ci.MYKRONOS, job="demo-and-dast", capability=capability)
            assert verdict.state == lane_status.CURRENT

    def test_an_unknown_pipeline_is_never_inferred_retired(self) -> None:
        stopped = NOW - timedelta(days=30)
        verdict = _classify(pipeline="someone-else", job="whatever", last_run_at=stopped)
        assert verdict.state == lane_status.STALE  # stale, still never current

    def test_a_run_from_before_449_has_no_job_and_falls_to_staleness(self) -> None:
        assert _classify(job=None).state == lane_status.CURRENT
        stopped = NOW - timedelta(days=30)
        assert _classify(job=None, last_run_at=stopped).state == lane_status.STALE

    @pytest.mark.parametrize(
        ("tool", "config", "state"),
        [
            ("codeql", {}, lane_status.CURRENT),  # the default tool
            ("shellcheck", {"extra_analysers": ["shellcheck"]}, lane_status.CURRENT),
            ("shellcheck", {}, lane_status.RETIRED),  # dropped from extra_analysers
            ("codeql", {"enabled_tool": "semgrep"}, lane_status.RETIRED),
            ("semgrep", {"enabled_tool": "semgrep"}, lane_status.CURRENT),
        ],
    )
    def test_an_actions_lane_follows_the_repositorys_capability_config(
        self, tool: str, config: dict[str, Any], state: str
    ) -> None:
        verdict = _classify(
            pipeline="payments-api", capability="sast", job="sast", tool_name=tool, config=config
        )
        assert verdict.state == state

    def test_an_operator_retirement_wins_and_says_who_and_why(self) -> None:
        retired_at = NOW - timedelta(days=2)
        retirement = lane_status.Retirement(
            id="r1", reason="staging is torn down until Q1", retired_by="tgb", retired_at=retired_at
        )
        verdict = _classify(retirement=retirement, last_run_at=NOW - timedelta(days=20))
        assert (verdict.state, verdict.basis) == (lane_status.RETIRED, "operator")
        assert "tgb" in verdict.reason and "torn down" in verdict.reason
        assert verdict.reported_since_retired is False
        assert _classify(retirement=retirement).reported_since_retired is True

    @pytest.mark.parametrize("days", [0, 3, 9, 30, 400])
    def test_a_stopped_lane_is_never_current(self, days: int) -> None:
        """The acceptance criterion, over every kind of lane."""
        stopped = NOW - timedelta(days=lane_status.LANE_STALE_DAYS + 1 + days)
        for job in ("dast-staging", "dast-demo-old", None):
            for pipeline in (ci.THEHUB, "someone-else"):
                verdict = _classify(pipeline=pipeline, job=job, last_run_at=stopped)
                assert verdict.state in (lane_status.STALE, lane_status.RETIRED)


# ---------------------------------------------------------------------------
# The check history and the operator's control
# ---------------------------------------------------------------------------


def _auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, CAPABILITY)}"}


def _days_ago(days: float) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).replace(tzinfo=None).isoformat()


@pytest.fixture
def two_lanes(client, admin_auth, run_compaction) -> str:
    """CodeQL reporting today; ShellCheck beside it, last seen 20 days ago."""
    repo_id = str(onboard(client, admin_auth).json()["id"])
    auth = _auth(client)
    for run_id, tool, job, started in (
        ("run-codeql", "codeql", "sast", _days_ago(0.1)),
        ("run-shell", "shellcheck", "sast-shell", _days_ago(20)),
    ):
        response = post_scan(
            client,
            auth,
            scan_run_id=run_id,
            tool_name=tool,
            job=job,
            started_at=started,
            completed_at=started,
        )
        assert response.status_code in (200, 201), response.text
    run_compaction()
    return repo_id


def _lanes(client, auth, repo_id: str) -> dict[str, dict[str, Any]]:
    response = client.get(
        f"/api/dashboard/repos/{repo_id}/scan-runs",
        params={"capability": CAPABILITY},
        headers=auth,
    )
    assert response.status_code == 200, response.text
    return {lane["tool_name"]: lane for lane in response.json()["lanes"]}


def _configure(client, extra: list[str]) -> None:
    with client.app.state.db.session() as session:
        onboarding = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).one()
        session.add(
            CapabilityConfig(
                repo_onboarding_id=onboarding.id,
                capability=CAPABILITY,
                config_json={"extra_analysers": extra},
            )
        )


def _retire(client, auth, repo_id: str, path: str = "retire", **body: Any):
    payload = {"tool_name": "shellcheck", "job": "sast-shell", "reason": "Replaced by CodeQL."}
    payload.update(body)
    return client.post(
        f"/api/dashboard/repos/{repo_id}/checks/{CAPABILITY}/lanes/{path}",
        json=payload,
        headers=auth,
    )


class TestTheCheckHistory:
    def test_a_lane_the_config_dropped_reads_retired(self, client, admin_auth, two_lanes) -> None:
        lanes = _lanes(client, admin_auth, two_lanes)
        assert lanes["codeql"]["state"] == "current"
        assert lanes["shellcheck"]["state"] == "retired"
        assert lanes["shellcheck"]["state_basis"] == "config"

    def test_a_configured_lane_that_stopped_reads_stale(
        self, client, admin_auth, two_lanes
    ) -> None:
        _configure(client, ["shellcheck"])
        lanes = _lanes(client, admin_auth, two_lanes)
        assert lanes["shellcheck"]["state"] == "stale"
        assert lanes["codeql"]["state"] == "current"

    def test_a_person_retires_it_and_it_reads_retired_with_why(
        self, client, admin_auth, two_lanes
    ) -> None:
        _configure(client, ["shellcheck"])
        response = _retire(client, admin_auth, two_lanes)
        assert response.status_code == 201, response.text

        shell = _lanes(client, admin_auth, two_lanes)["shellcheck"]
        assert (shell["state"], shell["state_basis"]) == ("retired", "operator")
        assert "Replaced by CodeQL." in shell["state_reason"]
        assert shell["retired_by"]

        with client.app.state.db.session() as session:
            actions = [
                e.action
                for e in session.scalars(
                    select(AuditLogEntry).where(AuditLogEntry.entity_type == "scan_lane")
                )
            ]
        assert actions == ["lane.retired"]

    def test_twice_is_refused_and_restoring_makes_it_stale_again(
        self, client, admin_auth, two_lanes
    ) -> None:
        _configure(client, ["shellcheck"])
        assert _retire(client, admin_auth, two_lanes).status_code == 201
        assert _retire(client, admin_auth, two_lanes).status_code == 409

        restored = _retire(client, admin_auth, two_lanes, "restore", reason="Needed again.")
        assert restored.status_code == 200, restored.text
        assert restored.json()["restored_at"]
        assert _lanes(client, admin_auth, two_lanes)["shellcheck"]["state"] == "stale"
        assert _retire(client, admin_auth, two_lanes, "restore").status_code == 409

    def test_a_lane_that_never_reported_cannot_be_retired(
        self, client, admin_auth, two_lanes
    ) -> None:
        response = _retire(client, admin_auth, two_lanes, tool_name="semgrep", job="sast-x")
        assert response.status_code == 404

    def test_an_agent_and_a_viewer_cannot(
        self, client, admin_auth, viewer_auth, two_lanes
    ) -> None:
        token = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()["token"]
        agent = {"Authorization": f"Bearer {token}"}
        assert _retire(client, agent, two_lanes).status_code == 403
        assert _retire(client, viewer_auth, two_lanes).status_code == 403
