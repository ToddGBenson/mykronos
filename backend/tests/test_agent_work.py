"""The agent work queue (spec 36 §2–§3).

The queue exists because an agent assembling "what needs doing" by hand drops
`_unknown` flags and misreads labels (#319). These tests pin what it promises:
platform problems before findings, a source that could not be read reported as
unknown rather than as clean, the caveats the platform knows, actions that name
the duty the route will actually apply, and paths that can be called.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from mykronos import agent_work, briefing_sources
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.briefing import AwaitingClosure, Briefing, StalledLane, TokenDelivery

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
REPO = "acme/api"
REPO_ID = "0b1377ac-0000-0000-0000-000000000001"

AGENT = Principal(actor="agent:claude-opus-5.5:abc", role=Role.AGENT, kind=ActorKind.AGENT)
PERSON = Principal(actor="operator", role=Role.ADMIN)


def _briefing(**overrides: Any) -> Briefing:
    """A briefing where every operational source was read and found nothing."""
    values: dict[str, Any] = {
        "generated_at": NOW,
        "total_open": 0,
        "paused": [],
        "paused_unknown": False,
        "failing": [],
        "failing_unknown": False,
        "unhealthy_jobs": [],
        "jobs_unknown": False,
        "tokens": [],
        "tokens_unknown": False,
        "toxic": [],
        "toxic_unknown": False,
        "exposure": [],
        "exposure_unknown": False,
    }
    values.update(overrides)
    return Briefing(**values)


def _lane(capability: str = "dast", open_findings: int = 5) -> StalledLane:
    return StalledLane(
        repo_full_name=REPO,
        capability=capability,
        reason="failing",
        consecutive_failures=3,
        streak_capped=False,
        last_success=None,
        detail="",
        open_findings=open_findings,
        scanned_by="github_actions",
    )


def _finding(finding_id: str = "f1", **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "finding_id": finding_id,
        "repo_full_name": REPO,
        "capability": "sast",
        "rule_id": "python.lang.security.x",
        "title": "Something",
        "severity": "high",
        "file_path": "app/x.py",
        "triage": "true_positive",
        "triage_rationale": "A high sast finding.",
        "state": {"claimed_by": None, "snoozed_until": None},
    }
    row.update(overrides)
    return row


def _build(
    briefing: Briefing | None = None,
    principal: Principal = AGENT,
    **inputs: Any,
) -> agent_work.WorkQueue:
    inputs.setdefault("triage_rows", [])
    inputs.setdefault("acceptances", [])
    inputs.setdefault("approval_requests", [])
    inputs.setdefault("repo_ids", {REPO: REPO_ID})
    inputs.setdefault("playbook_version", "1.0")
    return agent_work.build(
        briefing or _briefing(),
        principal,
        now=NOW,
        probe_interval_seconds=21_600,
        **inputs,
    )


def _caveats(item: agent_work.WorkItem) -> set[str]:
    return {c.code for c in item.caveats}


class TestOrder:
    def test_a_dead_lane_comes_before_everything_it_freezes(self) -> None:
        queue = _build(
            _briefing(
                stalled=[_lane()],
                tokens=[
                    TokenDelivery(
                        repo_full_name=REPO,
                        state="due",
                        issued_at=NOW - timedelta(days=100),
                        rotate_after=NOW - timedelta(days=1),
                    )
                ],
            ),
            triage_rows=[_finding()],
            acceptances=[
                {"id": "a1", "repo": REPO, "status": "review_due", "review_by": "2026-10-01"}
            ],
        )
        assert [i.kind for i in queue.items] == [
            "lane_stalled",
            "acceptance_attention",
            "token_delivery",
            "triage",
        ]

    def test_findings_order_by_severity_then_id(self) -> None:
        queue = _build(
            triage_rows=[
                _finding("b", severity="medium"),
                _finding("c", severity="critical"),
                _finding("a", severity="medium"),
            ]
        )
        assert [i.item_id for i in queue.items] == ["triage:c", "triage:a", "triage:b"]

    def test_the_same_state_gives_the_same_queue(self) -> None:
        rows = [_finding("x"), _finding("y", severity="low")]
        first = _build(_briefing(stalled=[_lane()]), triage_rows=rows)
        second = _build(_briefing(stalled=[_lane()]), triage_rows=list(reversed(rows)))
        assert [i.item_id for i in first.items] == [i.item_id for i in second.items]


class TestUnknownIsNotEmpty:
    def test_unasked_ci_is_reported_and_invents_no_items(self) -> None:
        queue = _build(_briefing(paused_unknown=True, failing_unknown=True))
        assert [u.source for u in queue.unknown] == ["concourse"]
        assert not [i for i in queue.items if i.kind.startswith("ci_job")]

    def test_every_unread_input_is_named(self) -> None:
        queue = _build(
            _briefing(jobs_unknown=True, tokens_unknown=True, toxic_unknown=True,
                      exposure_unknown=True),
            triage_rows=None,
            acceptances=None,
            approval_requests=None,
        )
        assert {u.source for u in queue.unknown} == {
            "job_runs",
            "ingestion_tokens",
            "toxic",
            "exposure",
            "triage",
            "risk_acceptances",
            "approval_requests",
        }

    def test_a_clean_read_reports_nothing_unknown(self) -> None:
        assert _build().unknown == []

    def test_the_gatherer_never_turns_an_unasked_ci_into_an_empty_list(self, client) -> None:
        state = client.app.state
        found = briefing_sources.gather(state.settings, state.db, state.catalog)
        # No Concourse configured in tests: not asked, so None - never [].
        assert found.paused_jobs is None
        assert found.failing_jobs is None


class TestAFrozenFindingSaysSo:
    def test_a_finding_in_a_stalled_lane_points_at_the_lane(self) -> None:
        queue = _build(
            _briefing(stalled=[_lane("dast")]),
            triage_rows=[_finding(capability="dast")],
        )
        finding = next(i for i in queue.items if i.kind == "triage")
        [pre] = finding.preconditions
        assert pre.met is False
        assert pre.blocked_by == agent_work.lane_id(REPO, "dast")
        assert pre.blocked_by in {i.item_id for i in queue.items}
        assert "lane_frozen" in _caveats(finding)

    def test_a_finding_in_a_healthy_lane_has_no_precondition(self) -> None:
        queue = _build(_briefing(stalled=[_lane("dast")]), triage_rows=[_finding()])
        finding = next(i for i in queue.items if i.kind == "triage")
        assert finding.preconditions == []
        assert "lane_frozen" not in _caveats(finding)


class TestCaveats:
    def test_a_dast_identity_is_its_route(self) -> None:
        [item] = _build(triage_rows=[_finding(capability="dast")]).items
        assert "identity_is_the_route" in _caveats(item)
        # #440 made DAST identity stable; the old warning would steer an
        # agent away from dispositions that do stick.
        assert "identity_unstable" not in _caveats(item)

    def test_a_container_fix_is_a_package_not_an_image(self) -> None:
        [item] = _build(triage_rows=[_finding(capability="containers")]).items
        assert "fix_is_a_package" in _caveats(item)

    def test_a_declared_version_is_not_the_running_one(self) -> None:
        [item] = _build(
            triage_rows=[_finding(capability="atlas", version_basis="declared_floor")]
        ).items
        assert "declared_version" in _caveats(item)
        [resolved] = _build(
            triage_rows=[_finding(capability="atlas", version_basis="resolved")]
        ).items
        assert "declared_version" not in _caveats(resolved)

    def test_true_positive_is_flagged_as_severity_only(self) -> None:
        [item] = _build(triage_rows=[_finding(triage="true_positive")]).items
        assert "severity_only_triage" in _caveats(item)
        [other] = _build(triage_rows=[_finding(triage="needs_human_judgment")]).items
        assert "severity_only_triage" not in _caveats(other)

    def test_an_unverified_token_must_not_be_rotated(self) -> None:
        token = TokenDelivery(
            repo_full_name=REPO,
            state="unverified",
            issued_at=NOW - timedelta(days=5),
            rotate_after=NOW + timedelta(days=85),
        )
        [item] = _build(_briefing(tokens=[token])).items
        assert "do_not_rotate" in _caveats(item)
        assert "rotat" not in item.done_when.lower()


class TestGovernance:
    def _close(self, item: agent_work.WorkItem) -> agent_work.ActionRef:
        return next(a for a in item.actions if "isposition" in a.label)

    def test_an_agent_closing_a_high_finding_is_routed_to_the_duty(self) -> None:
        [item] = _build(triage_rows=[_finding(severity="high")]).items
        action = self._close(item)
        assert action.governed_by == "finding_disposition"
        assert action.path.endswith("/disposition-requests")

    def test_a_person_closes_the_same_finding_directly(self) -> None:
        [item] = _build(principal=PERSON, triage_rows=[_finding(severity="high")]).items
        action = self._close(item)
        assert action.governed_by is None
        assert action.method == "PATCH"

    def test_an_agent_closes_a_medium_finding_directly(self) -> None:
        [item] = _build(triage_rows=[_finding(severity="medium")]).items
        assert self._close(item).governed_by is None

    def test_an_acceptance_is_always_governed(self) -> None:
        [item] = _build(principal=PERSON, triage_rows=[_finding(severity="low")]).items
        accept = next(a for a in item.actions if a.path == "/api/risk-acceptances")
        assert accept.governed_by == "risk_acceptance"


class TestClaims:
    def test_another_principals_claim_hides_the_finding(self) -> None:
        rows = [
            _finding("mine", state={"claimed_by": AGENT.actor, "snoozed_until": None}),
            _finding("theirs", state={"claimed_by": "someone-else", "snoozed_until": None}),
            _finding("free"),
        ]
        ids = {i.item_id for i in _build(triage_rows=rows).items}
        assert ids == {"triage:mine", "triage:free"}


class TestCallablePaths:
    def test_a_lane_action_names_the_onboarding_id(self) -> None:
        [item] = _build(_briefing(stalled=[_lane()])).items
        [action] = item.actions
        assert action.path == f"/api/repos/{REPO_ID}/scan?capabilities=dast"
        assert REPO not in action.path

    def test_no_dead_path_without_an_onboarding_row(self) -> None:
        [item] = _build(_briefing(stalled=[_lane()]), repo_ids={}).items
        assert item.actions == []

    def test_a_combination_grooms_by_onboarding_id(self) -> None:
        combo = {
            "repo_full_name": REPO,
            "combination_id": "c1",
            "name": "Unauthenticated injectable endpoint",
            "severity": "critical",
            "partly_accepted": True,
            "rationale": "",
            "members": [{"finding_id": "f1", "severity": "high", "rule_id": "CWE-89"}],
        }
        [item] = _build(
            _briefing(
                toxic=[combo],
                toxic_coverage={"cannot_fire": [{"rule_id": "x"}]},
            )
        ).items
        assert item.actions[0].path == f"/api/triage/repos/{REPO_ID}/combinations/c1/groom"
        assert _caveats(item) == {"partly_accepted", "rules_cannot_fire"}


class TestAcceptances:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        record = {"id": "acc-1", "repo": REPO, "status": "active", "findings": 3}
        record.update(overrides)
        return record

    def test_one_expiring_soon_is_work(self) -> None:
        soon = (NOW.date() + timedelta(days=10)).isoformat()
        [item] = _build(acceptances=[self._record(expires_at=soon)]).items
        assert item.kind == "acceptance_attention"
        assert item.actions[0].governed_by == "risk_acceptance"

    def test_one_with_time_left_is_not(self) -> None:
        later = (NOW.date() + timedelta(days=60)).isoformat()
        assert _build(acceptances=[self._record(expires_at=later)]).items == []

    def test_scope_drift_is_work(self) -> None:
        [item] = _build(acceptances=[self._record(drift=2)]).items
        assert "2 open finding(s)" in item.summary


class TestWaiting:
    def test_needs_info_is_work_and_pending_is_not(self) -> None:
        queue = _build(
            approval_requests=[
                {"id": "r1", "duty": "pull_request_merge", "subject_ref": "x#1",
                 "last_verdict": "needs_info", "last_rationale": "Which test covers it?"},
                {"id": "r2", "duty": "pull_request_merge", "subject_ref": "x#2",
                 "last_verdict": None, "last_rationale": ""},
            ]
        )
        assert [i.item_id for i in queue.items] == ["approval_needs_info:r1"]
        assert [w.ref for w in queue.waiting] == ["r2"]

    def test_findings_awaiting_closure_need_nothing(self) -> None:
        queue = _build(
            _briefing(
                awaiting=[
                    AwaitingClosure(
                        repo_full_name=REPO, capability="sast", findings=4,
                        open_findings=4, scans_needed=1,
                    )
                ]
            )
        )
        assert queue.items == []
        assert queue.waiting[0].kind == "awaiting_closure"


class TestExposure:
    def _endpoint(self, severity: str, probed: datetime) -> dict[str, Any]:
        return {
            "id": "e1",
            "url": "https://demo.example/",
            "repo_full_name": REPO,
            "last_probed_at": probed.isoformat(),
            "observations": [
                {"kind": "unauthenticated", "severity": severity, "title": "Open", "detail": ""}
            ],
        }

    def test_a_serious_observation_is_work(self) -> None:
        [item] = _build(_briefing(exposure=[self._endpoint("high", NOW)])).items
        assert item.kind == "public_exposure"
        assert "probe_stale" not in _caveats(item)

    def test_a_minor_one_is_not(self) -> None:
        assert _build(_briefing(exposure=[self._endpoint("low", NOW)])).items == []

    def test_an_old_probe_is_flagged(self) -> None:
        old = NOW - timedelta(days=2)
        [item] = _build(_briefing(exposure=[self._endpoint("critical", old)])).items
        assert "probe_stale" in _caveats(item)


class TestTheRoute:
    def test_a_person_reads_the_queue(self, client, admin_auth) -> None:
        response = client.get("/api/agent/work", headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["actor_kind"] == "human"
        # Tests configure no Concourse: the queue must say it did not ask.
        assert "concourse" in {u["source"] for u in body["unknown"]}

    def test_an_agent_reads_its_own_queue(self, client, admin_auth) -> None:
        minted = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()
        response = client.get(
            "/api/agent/work", headers={"Authorization": f"Bearer {minted['token']}"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["actor"] == minted["actor"]
        assert response.json()["actor_kind"] == "agent"

    def test_it_needs_a_credential(self, client) -> None:
        assert client.get("/api/agent/work").status_code == 401
