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

import pytest

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


def _lane(capability: str = "dast", open_findings: int = 5, repo_id: str = REPO_ID) -> StalledLane:
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
        repo_id=repo_id,
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
    inputs.setdefault("pull_request_requests", [])
    inputs.setdefault("patchwork_prs", [])
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
            pull_request_requests=None,
            patchwork_prs=None,
        )
        assert {u.source for u in queue.unknown} == {
            "job_runs",
            "ingestion_tokens",
            "toxic",
            "exposure",
            "triage",
            "risk_acceptances",
            "approval_requests",
            "pull_request_requests",
            "patchwork",
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

    def test_a_stalled_lane_links_its_latest_run(self) -> None:
        """TheHub #60761: the run's outcome and raw output are one read away."""
        lane = _lane("dast")
        lane.last_scan_run_id = "run-9"
        [item] = _build(_briefing(stalled=[lane])).items
        assert "/api/dashboard/scan-runs/run-9" in {e.ref for e in item.evidence}

    def test_a_lane_with_no_known_run_offers_no_link(self) -> None:
        [item] = _build(_briefing(stalled=[_lane("dast")])).items
        assert all(e.source != "scan_run" for e in item.evidence)


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

    def test_an_agent_closes_an_info_finding_directly(self) -> None:
        [item] = _build(triage_rows=[_finding(severity="info")]).items
        assert self._close(item).governed_by is None

    @pytest.mark.parametrize("severity", ["medium", "low"])
    def test_an_agents_medium_or_low_close_is_governed(self, severity: str) -> None:
        """TheHub #61158: low and medium are a request too."""
        [item] = _build(triage_rows=[_finding(severity=severity)]).items
        assert self._close(item).governed_by == "finding_disposition"

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
        [item] = _build(_briefing(stalled=[_lane(repo_id="")])).items
        assert item.actions == []

    def test_a_partly_accepted_combination_offers_no_retired_groom(self) -> None:
        """#60756. The groom route answers 410 for every combination since D-161,
        so offering it turned a partly-accepted combination the Findings tab
        shows into a call that cannot succeed. The item still carries the
        combination, its members and its caveats; the playbook says where the
        story is filed."""
        combo = {
            "repo_full_name": REPO,
            "combination_id": "c1",
            "name": "Unauthenticated injectable endpoint",
            "severity": "critical",
            "partly_accepted": True,
            "rationale": "",
            "members": [
                {"finding_id": "f1", "severity": "high", "rule_id": "CWE-89"},
                {
                    "finding_id": "f2",
                    "severity": "medium",
                    "rule_id": "CWE-306",
                    "status": "accepted_risk",
                },
            ],
        }
        [item] = _build(
            _briefing(
                toxic=[combo],
                toxic_coverage={"cannot_fire": [{"rule_id": "x"}]},
            )
        ).items
        # The repository has an onboarding row, so an empty list is not the
        # "no dead path without an id" rule: there is no route to offer.
        assert item.actions == []
        assert [e.ref for e in item.evidence] == ["f1", "f2"]
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

    def _failed(self, **overrides: Any) -> dict[str, Any]:
        record = self._record(
            status="premise_failed",
            closed_reason="premise failed: port_not_published",
            outstanding=2,
            premise_failure={
                "failed": [
                    {
                        "index": 0,
                        "type": "port_not_published",
                        "status": "failed",
                        "reason": "5432 is published to the internet",
                        "observation_ids": ["obs-1"],
                    }
                ],
                "observation_ids": ["obs-1"],
            },
        )
        record.update(overrides)
        return record

    def test_a_failed_premise_is_never_offered_a_renewal(self) -> None:
        """#60846: the renew route refuses a parent that is not live, and so
        does revoke. The item offers what premise_failed accepts: a read, and
        a new acceptance with corrected premises."""
        [item] = _build(acceptances=[self._failed()]).items
        calls = {(a.method, a.path) for a in item.actions}
        assert calls == {
            ("GET", "/api/risk-acceptances/acc-1"),
            ("POST", "/api/risk-acceptances"),
        }
        propose = next(a for a in item.actions if a.method == "POST")
        assert propose.governed_by == "risk_acceptance"
        assert "renew" not in item.done_when.lower()

    def test_a_failed_premise_is_named_with_its_evidence(self) -> None:
        [item] = _build(acceptances=[self._failed()]).items
        assert "port_not_published" in item.title
        assert "5432 is published to the internet" in item.summary
        assert "obs-1" in item.summary
        assert "2 covered finding(s) are open again" in item.summary
        assert ("control_observations", "obs-1") in {(e.source, e.ref) for e in item.evidence}
        assert item.weight == 2

    def test_an_epss_failure_cites_the_score(self) -> None:
        failure = {
            "failed": [
                {
                    "type": "epss_below",
                    "reason": "EPSS above 0.2",
                    "observation_ids": [],
                    "epss": [{"cve": "CVE-2026-1", "epss": 0.4, "threshold": 0.2}],
                }
            ]
        }
        [item] = _build(acceptances=[self._failed(premise_failure=failure)]).items
        assert ("threat_intel", "CVE-2026-1") in {(e.source, e.ref) for e in item.evidence}

    def test_without_the_audit_entry_the_reason_still_names_the_premise(self) -> None:
        [item] = _build(acceptances=[self._failed(premise_failure=None)]).items
        assert "port_not_published" in item.title
        assert "could not be read" in item.summary

    def test_nothing_outstanding_is_not_work(self) -> None:
        """Every covered finding fixed, or held by a corrected acceptance."""
        assert _build(acceptances=[self._failed(outstanding=0)]).items == []

    def test_unknown_outstanding_keeps_the_item(self) -> None:
        [item] = _build(acceptances=[self._failed(outstanding=None)]).items
        assert "reopened" in item.summary

    def test_every_status_the_queue_reads_offers_only_what_its_routes_accept(self) -> None:
        """The static half of the #60846 pin (the live half calls each route:
        test_agent_work_actions.py). Renew and revoke refuse any record outside
        the statuses their routes check; the queue must never offer them there."""
        from mykronos import risk_acceptance as ra
        from mykronos.api.agent import _ACCEPTANCE_STATES

        accepts = {
            "/renew": set(ra.LIVE),
            "/revoke": {*ra.LIVE, "pending_approval"},
        }
        soon = (NOW.date() + timedelta(days=3)).isoformat()
        for status in _ACCEPTANCE_STATES:
            record = self._failed() if status == "premise_failed" else self._record()
            record.update(status=status, expires_at=soon, drift=1, review_by="2026-10-01")
            [item] = _build(acceptances=[record]).items
            assert item.actions, f"{status}: an item with nothing to call"
            for action in item.actions:
                for suffix, statuses in accepts.items():
                    if action.path.endswith(suffix):
                        assert status in statuses, f"{status} offered {action.path}"


class TestWaiting:
    def test_needs_info_is_work_and_pending_is_not(self) -> None:
        queue = _build(
            approval_requests=[
                {"id": "r1", "duty": "finding_disposition", "subject_ref": "f1",
                 "last_verdict": "needs_info", "last_rationale": "Which test covers it?"},
                {"id": "r2", "duty": "finding_disposition", "subject_ref": "f2",
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


def _pr_request(
    request_id: str,
    number: int = 7,
    *,
    state: str = "rejected",
    verdict: str | None = "reject",
    by: str = AGENT.actor,
    age_hours: int = 2,
    repo: str = REPO,
) -> dict[str, Any]:
    return {
        "id": request_id,
        "duty": "pull_request_merge",
        "subject_ref": f"{repo}#{number}@{(request_id * 40)[:40]}",
        "requested_by": by,
        "state": state,
        "created_at": NOW - timedelta(hours=age_hours),
        "last_verdict": verdict,
        "last_rationale": "No test covers the parser change.",
    }


def _draft(number: int = 40, status: str = "draft_open", repo: str = REPO) -> dict[str, Any]:
    return {
        "event_id": f"ev-{number}",
        "repo_full_name": repo,
        "finding_id": f"f-{number}",
        "fix_pr_number": number,
        "fix_pr_url": f"https://github.com/{repo}/pull/{number}",
        "pr_status": status,
        "fixer_name": "pin_action",
        "rationale": "Pinned to a sha.",
    }


def _governed(item: agent_work.WorkItem) -> set[str | None]:
    return {a.governed_by for a in item.actions}


class TestPullRequestAttention:
    """TheHub #60797: the agent's own pull requests that need it, and the
    Patchwork drafts nobody has asked to have reviewed. Option B: both from
    records the platform already holds, no GitHub call."""

    def test_it_is_a_kind(self) -> None:
        assert "pull_request_attention" in agent_work.KINDS

    def test_a_rejected_request_is_work_governed_by_the_merge_duty(self) -> None:
        [item] = _build(pull_request_requests=[_pr_request("a")]).items
        assert item.kind == "pull_request_attention"
        assert item.item_id == f"pull_request_attention:{REPO}#7"
        assert item.band == agent_work.BAND_APPROVAL
        assert "pull_request_merge" in _governed(item)
        assert item.done_when
        assert "rejected" in item.title
        assert "No test covers" in item.summary
        assert any(a.path == "/api/approvals/a" for a in item.actions)

    def test_needs_info_on_a_pull_request_is_this_kind_not_the_generic_one(self) -> None:
        queue = _build(
            pull_request_requests=[_pr_request("b", state="pending", verdict="needs_info")]
        )
        assert [i.kind for i in queue.items] == ["pull_request_attention"]
        assert "pull_request_merge" in _governed(queue.items[0])

    def test_a_pull_request_in_approval_requests_is_not_listed_twice(self) -> None:
        pending = _pr_request("b", state="pending", verdict="needs_info")
        queue = _build(approval_requests=[pending], pull_request_requests=[pending])
        assert [i.kind for i in queue.items] == ["pull_request_attention"]

    def test_an_open_request_with_no_question_waits(self) -> None:
        queue = _build(pull_request_requests=[_pr_request("c", state="pending", verdict=None)])
        assert queue.items == []
        assert [(w.kind, w.ref) for w in queue.waiting] == [("approval_pending", "c")]

    def test_a_rejection_answered_by_a_newer_head_is_not_work(self) -> None:
        queue = _build(
            pull_request_requests=[
                _pr_request("d", age_hours=5),
                _pr_request("e", state="pending", verdict=None, age_hours=1),
            ]
        )
        assert queue.items == []
        assert [w.ref for w in queue.waiting] == ["e"]

    def test_another_principals_requests_are_not_yours(self) -> None:
        queue = _build(pull_request_requests=[_pr_request("f", by="agent:other:xyz")])
        assert queue.items == []
        assert queue.waiting == []

    def test_an_approved_request_is_not_work(self) -> None:
        queue = _build(pull_request_requests=[_pr_request("g", state="approved", verdict="approve")])
        assert queue.items == []

    def test_an_open_patchwork_draft_nobody_requested_is_work(self) -> None:
        [item] = _build(patchwork_prs=[_draft(40)]).items
        assert item.kind == "pull_request_attention"
        assert item.item_id == f"pull_request_attention:{REPO}#40"
        assert "pull_request_merge" in _governed(item)
        assert item.done_when
        assert any(e.source == "remediation_events" for e in item.evidence)

    def test_a_human_edited_draft_is_work_and_says_so(self) -> None:
        [item] = _build(patchwork_prs=[_draft(41, status="human_edited")]).items
        assert "human_edited" in _caveats(item)

    def test_a_draft_already_under_review_is_not(self) -> None:
        queue = _build(
            patchwork_prs=[_draft(7)],
            pull_request_requests=[
                _pr_request("h", state="pending", verdict=None, by="agent:other:xyz")
            ],
        )
        assert queue.items == []

    def test_settled_patchwork_pull_requests_are_not_work(self) -> None:
        queue = _build(patchwork_prs=[_draft(42, "merged"), _draft(43, "closed_unmerged")])
        assert queue.items == []

    def test_a_patchwork_pull_request_that_closed_ends_its_rejection(self) -> None:
        queue = _build(
            pull_request_requests=[_pr_request("i", number=44)],
            patchwork_prs=[_draft(44, "closed_unmerged")],
        )
        assert queue.items == []

    def test_a_rejection_outside_patchwork_says_a_close_is_not_seen(self) -> None:
        [item] = _build(pull_request_requests=[_pr_request("j")]).items
        assert "close_not_recorded" in _caveats(item)

    def test_an_unreadable_source_is_unknown_not_empty(self) -> None:
        requests_unread = _build(pull_request_requests=None, patchwork_prs=[_draft(40)])
        assert [u.source for u in requests_unread.unknown] == ["pull_request_requests"]
        # A draft cannot be shown as unrequested when the requests were not read.
        assert requests_unread.items == []

        drafts_unread = _build(pull_request_requests=[_pr_request("k")], patchwork_prs=None)
        assert [u.source for u in drafts_unread.unknown] == ["patchwork"]
        assert [i.kind for i in drafts_unread.items] == ["pull_request_attention"]

    def test_the_same_state_gives_the_same_order(self) -> None:
        requests = [_pr_request("m", number=9), _pr_request("n", number=3, age_hours=1)]
        drafts = [_draft(50), _draft(12), _draft(31, "human_edited")]
        first = _build(pull_request_requests=requests, patchwork_prs=drafts)
        second = _build(
            pull_request_requests=list(reversed(requests)), patchwork_prs=list(reversed(drafts))
        )
        assert [i.item_id for i in first.items] == [i.item_id for i in second.items]
        assert len(first.items) == 5
        assert [i.item_id for i in first.items] == sorted(i.item_id for i in first.items)


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

    def test_an_agents_rejected_pull_request_and_an_open_draft_reach_its_queue(
        self, client, admin_auth, buffer, run_compaction
    ) -> None:
        """TheHub #60797, end to end: the gatherer reads the agent's own
        `pull_request_merge` requests and Patchwork's open drafts from the
        platform's records, with no GitHub call."""
        from mykronos.db.models import ApprovalDecision, ApprovalRequest
        from mykronos.schemas import utcnow

        minted = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()
        now = utcnow()
        with client.app.state.db.session() as session:
            session.add(
                ApprovalRequest(
                    id="req-60797",
                    duty="pull_request_merge",
                    subject_ref=f"{REPO}#7@{'a' * 40}",
                    requested_by=minted["actor"],
                    requester_kind="agent",
                    state="rejected",
                    created_at=now - timedelta(hours=1),
                    expires_at=now + timedelta(days=6),
                    decided_at=now,
                )
            )
            session.add(
                ApprovalDecision(
                    request_id="req-60797",
                    approver="operator",
                    verdict="reject",
                    rationale="No test covers the parser change.",
                    created_at=now,
                )
            )
        buffer.append(
            "remediation_events",
            [
                {
                    "event_id": "ev-60797",
                    "repo_full_name": REPO,
                    "finding_id": "f-60797",
                    "fix_pr_number": 40,
                    "fix_pr_url": f"https://github.com/{REPO}/pull/40",
                    "pr_status": "draft_open",
                    "created_at": now,
                    "updated_at": now,
                }
            ],
        )
        run_compaction()

        response = client.get(
            "/api/agent/work", headers={"Authorization": f"Bearer {minted['token']}"}
        )

        assert response.status_code == 200, response.text
        body = response.json()
        attention = {
            i["item_id"]: i for i in body["items"] if i["kind"] == "pull_request_attention"
        }
        assert set(attention) == {
            f"pull_request_attention:{REPO}#7",
            f"pull_request_attention:{REPO}#40",
        }
        for item in attention.values():
            assert "pull_request_merge" in {a["governed_by"] for a in item["actions"]}
            assert item["playbook"].startswith("pull_request_attention@")
        sources = {u["source"] for u in body["unknown"]}
        assert not sources & {"pull_request_requests", "patchwork"}
