"""An agent's track record (spec 36 §6).

The scorecard is what a delegation is meant to rest on, so the tests pin the
property that makes it trustworthy before any number in it: a metric that
cannot be computed says so, with a reason, and never reads as zero. Then each
metric against records made through the real engine, sampling and routes,
grouped by model family and by instance.
"""

from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from mykronos import agent_scorecard as sc
from mykronos import worklist
from mykronos.adminauth import Principal, Role
from mykronos.agents import TOKEN_PREFIX, resolve_agent_credential
from mykronos.approvals import engine, sampling
from mykronos.approvals.engine import Subject
from mykronos.approvals.policy import cached_policy
from mykronos.auth import hash_token
from mykronos.db.models import AgentCredential, ApprovalRequest, Delegation
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan

NOW = utcnow()
OPUS = "claude-opus-5.5"
SONNET = "claude-sonnet-5"
RATIONALE = "Checked the premise and the scope against the evidence bundle."
PERSON = Principal(actor="operator", role=Role.ADMIN)


def _policy() -> Any:
    """The repository's own policy file, so the window and threshold are real."""
    return cached_policy(Path(__file__).resolve().parents[2] / "approval-policy-v1.yaml")


def _metric(group: sc.GroupRecord, name: str) -> sc.Metric:
    [metric] = [m for m in group.metrics if m.name == name]
    return metric


def _gathered(**overrides: Any) -> sc.Gathered:
    values: dict[str, Any] = {
        "agents": [],
        "decisions": [],
        "requests": [],
        "status_events": [],
        "claims": [],
        "finding_status": {},
        "delegation_stats": {},
        "unattributed_dispositions": 0,
    }
    values.update(overrides)
    return sc.Gathered(**values)


def _decision(instance: str = "r1", family: str = SONNET, **overrides: Any) -> sc.DecisionRow:
    values: dict[str, Any] = {
        "family": family,
        "instance": instance,
        "verdict": "approve",
        "delegation_id": "dlg",
        "sampled": True,
        "sample_verdict": None,
        "sample_reviewed_at": None,
    }
    values.update(overrides)
    return sc.DecisionRow(**values)


def _request(instance: str = "a1", family: str = OPUS, **overrides: Any) -> sc.RequestRow:
    values: dict[str, Any] = {
        "family": family,
        "instance": instance,
        "duty": "risk_acceptance",
        "state": "approved",
        "expires_at": NOW + timedelta(days=1),
        "verdicts": ("approve",),
    }
    values.update(overrides)
    return sc.RequestRow(**values)


def _event(finding: str, action: str, minutes: int, **overrides: Any) -> sc.StatusEvent:
    values: dict[str, Any] = {
        "finding_id": finding,
        "action": action,
        "created_at": NOW + timedelta(minutes=minutes),
        "actor": "agent:x",
        "actor_kind": "agent",
        "family": OPUS,
        "instance": "a1",
        "new_status": "false_positive" if action == "finding.status" else "",
    }
    values.update(overrides)
    return sc.StatusEvent(**values)


# -- Could not compute is not zero ---------------------------------------------


class TestUnavailableIsNeverZero:
    def test_an_unreadable_source_is_unavailable_with_its_reason(self) -> None:
        card = sc.compute(
            _gathered(decisions=None, requests=[_request()], status_events=None),
            _policy(),
            now=NOW,
        )
        [group] = card.instances
        for name in ("approver.agreement", "approver.overturned", "dispositions.reopened"):
            metric = _metric(group, name)
            assert metric.status == sc.UNAVAILABLE
            assert metric.value is None and metric.rate is None
            assert "could not be read" in metric.note

    def test_what_the_records_cannot_support_is_reported_on_every_group(self) -> None:
        card = sc.compute(_gathered(requests=[_request()]), _policy(), now=NOW)
        for group in [*card.families, *card.instances]:
            for name in sc.NOT_DERIVABLE:
                metric = _metric(group, name)
                assert metric.status == sc.UNAVAILABLE
                assert metric.value is None
                assert metric.note

    def test_an_empty_denominator_is_no_data_not_a_rate(self) -> None:
        card = sc.compute(_gathered(requests=[_request()]), _policy(), now=NOW)
        [group] = card.instances
        agreement = _metric(group, "approver.agreement")
        assert agreement.status == sc.NO_DATA
        assert agreement.denominator == 0
        assert agreement.rate is None
        assert agreement.note

    def test_lapsed_claims_without_the_lake_are_unavailable(self) -> None:
        card = sc.compute(
            _gathered(
                agents=[sc.AgentRef(family=OPUS, instance="a1", actor="agent:opus:a1")],
                claims=[sc.ClaimRow("f1", "agent:opus:a1", NOW - timedelta(days=1))],
                finding_status=None,
            ),
            _policy(),
            now=NOW,
        )
        [group] = card.instances
        assert _metric(group, "claims.lapsed_open").status == sc.UNAVAILABLE

    def test_claims_without_the_credentials_are_unavailable(self) -> None:
        card = sc.compute(
            _gathered(agents=None, requests=[_request()]), _policy(), now=NOW
        )
        [group] = card.instances
        metric = _metric(group, "claims.lapsed_open")
        assert metric.status == sc.UNAVAILABLE
        assert "agent_credentials" in metric.note


# -- Each metric ---------------------------------------------------------------


class TestAsAnApprover:
    def test_overturned_and_agreement_count_reviewed_samples_only(self) -> None:
        rows = [
            _decision(sample_verdict="agree", sample_reviewed_at=NOW),
            _decision(sample_verdict="disagree", sample_reviewed_at=NOW),
            _decision(),  # sampled, not yet reviewed
            _decision(sampled=False),
            _decision(verdict="reject", delegation_id=None, sampled=False),
        ]
        [group] = sc.compute(_gathered(decisions=rows), _policy(), now=NOW).instances

        verdicts = _metric(group, "approver.verdicts")
        assert (verdicts.value, verdicts.denominator) == (1, 5)
        assert verdicts.breakdown == {"approve": 4, "reject": 1}
        assert (_metric(group, "approver.sampled").value,
                _metric(group, "approver.sampled").denominator) == (3, 4)
        reviewed = _metric(group, "approver.sample_reviewed")
        assert (reviewed.value, reviewed.denominator) == (2, 3)
        assert reviewed.breakdown == {"awaiting_review": 1}
        overturned = _metric(group, "approver.overturned")
        assert (overturned.value, overturned.denominator, overturned.rate) == (1, 2, 0.5)
        agreement = _metric(group, "approver.agreement")
        assert (agreement.value, agreement.denominator) == (1, 2)

    def test_the_window_is_the_newest_reviewed_samples_as_sampling_uses(self) -> None:
        window = _policy().delegations.agreement_window
        old = [
            _decision(sample_verdict="disagree", sample_reviewed_at=NOW - timedelta(days=30))
            for _ in range(5)
        ]
        recent = [
            _decision(sample_verdict="agree", sample_reviewed_at=NOW - timedelta(minutes=i))
            for i in range(window)
        ]
        [group] = sc.compute(
            _gathered(decisions=old + recent), _policy(), now=NOW
        ).instances

        windowed = _metric(group, "approver.agreement_window")
        assert (windowed.value, windowed.denominator, windowed.rate) == (window, window, 1.0)
        assert "At or above" in windowed.note
        lifetime = _metric(group, "approver.agreement")
        assert (lifetime.value, lifetime.denominator) == (window, window + 5)


class TestAsARequester:
    def test_states_rejections_and_needs_info_by_duty(self) -> None:
        rows = [
            _request(),
            _request(state="rejected", verdicts=("needs_info", "reject")),
            _request(state="pending", verdicts=("needs_info",)),
            # Past its TTL but not yet swept: expired, as the engine would say.
            _request(state="pending", verdicts=(), expires_at=NOW - timedelta(hours=1)),
            _request(duty="pull_request_merge", state="rejected", verdicts=("reject",)),
        ]
        [group] = sc.compute(_gathered(requests=rows), _policy(), now=NOW).instances

        rejected = _metric(group, "requester.rejected")
        assert (rejected.value, rejected.denominator) == (2, 3)
        assert rejected.breakdown == {"approved": 1, "rejected": 2, "pending": 1, "expired": 1}
        needs_info = _metric(group, "requester.needs_info")
        assert (needs_info.value, needs_info.denominator) == (2, 5)

        duties = {d.duty: d for d in group.requests_by_duty}
        assert duties["pull_request_merge"].rejected.rate == 1.0
        assert duties["risk_acceptance"].by_state == {
            "approved": 1, "rejected": 1, "pending": 1, "expired": 1,
        }


class TestDispositions:
    def test_reopened_only_when_the_reopen_undid_this_disposition(self) -> None:
        events = [
            _event("f1", "finding.status", 0),
            _event("f1", "finding.reopened", 5, actor="operator", actor_kind="human"),
            # f2: a person re-dispositioned it before the reopen, so the reopen
            # undid their decision, not the agent's.
            _event("f2", "finding.status", 0),
            _event("f2", "finding.status", 3, actor="operator", actor_kind="human",
                   family="", instance="", new_status="suppressed"),
            _event("f2", "finding.reopened", 5, actor="operator", actor_kind="human"),
            _event("f3", "finding.status", 0),
            _event("f3", "finding.reopened", 5),  # the agent reopened its own
            _event("f4", "finding.status", 0),  # still standing
            _event("f5", "finding.status", 0, new_status="accepted_risk"),
            _event("f6", "finding.status", 0, applied=False),  # never applied
        ]
        [group] = sc.compute(_gathered(status_events=events), _policy(), now=NOW).instances

        metric = _metric(group, "dispositions.reopened")
        assert (metric.value, metric.denominator, metric.rate) == (2, 4, 0.5)
        assert metric.breakdown == {
            "reopened_by_human": 1,
            "superseded": 1,
            "reopened_by_self": 1,
            "standing": 1,
            "not_measurable": 1,
        }


class TestClaims:
    def test_lapsed_open_against_every_claim_held_under_the_actor(self) -> None:
        actor = "agent:claude-opus-5.5:a1"
        card = sc.compute(
            _gathered(
                agents=[sc.AgentRef(family=OPUS, instance="a1", actor=actor)],
                claims=[
                    sc.ClaimRow("open", actor, NOW - timedelta(days=1)),
                    sc.ClaimRow("closed", actor, NOW - timedelta(days=1)),
                    sc.ClaimRow("gone", actor, NOW - timedelta(days=1)),
                    sc.ClaimRow("live", actor, NOW + timedelta(days=3)),
                    sc.ClaimRow("someone-else", "operator", NOW - timedelta(days=1)),
                ],
                finding_status={"open": "open", "closed": "false_positive"},
            ),
            _policy(),
            now=NOW,
        )
        [group] = card.instances
        metric = _metric(group, "claims.lapsed_open")
        assert (metric.value, metric.denominator) == (1, 4)
        assert metric.breakdown == {
            "live": 1,
            "lapsed_open": 1,
            "lapsed_closed": 1,
            "lapsed_finding_not_in_lake": 1,
        }


class TestGrouping:
    def test_a_family_aggregates_its_instances_and_filters_select(self) -> None:
        gathered = _gathered(
            requests=[
                _request("a1", state="rejected"),
                _request("a2"),
                _request("b1", family=SONNET),
            ]
        )
        card = sc.compute(gathered, _policy(), now=NOW)
        families = {g.family: g for g in card.families}
        assert set(families) == {OPUS, SONNET}
        assert families[OPUS].instances == ["a1", "a2"]
        assert families[OPUS].instance is None
        opus = _metric(families[OPUS], "requester.rejected")
        assert (opus.value, opus.denominator) == (1, 2)
        assert [g.instance for g in card.instances] == ["a1", "a2", "b1"]

        by_family = sc.compute(gathered, _policy(), now=NOW, family=SONNET)
        assert [g.family for g in by_family.families] == [SONNET]
        assert [g.instance for g in by_family.instances] == ["b1"]

        by_instance = sc.compute(gathered, _policy(), now=NOW, instance="a2")
        assert [g.instance for g in by_instance.instances] == ["a2"]
        # The family's aggregate is still the whole family.
        assert by_instance.families[0].instances == ["a1", "a2"]

    def test_a_record_with_no_family_is_shown_not_dropped(self) -> None:
        card = sc.compute(
            _gathered(requests=[_request(instance="", family="")]), _policy(), now=NOW
        )
        assert [g.family for g in card.families] == [sc.UNRECORDED]


# -- Through the real engine and the route --------------------------------------


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def stand_in_adapters(monkeypatch):
    """Tiers from the context, as test_approvals does: these tests are about
    what the record says afterwards, not about how a tier is computed."""

    def adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
        return Subject(tier=context["tier"], evidence={"subject": subject_ref, **context})

    for duty in ("risk_acceptance", "pull_request_merge"):
        monkeypatch.setitem(engine._ADAPTERS, duty, adapter)
        monkeypatch.setitem(engine._ON_APPROVED, duty, lambda session, request: None)


def _reviewer(client) -> tuple[str, str]:
    """A platform-started reviewer credential (spec 34 §4.3): (token, instance)."""
    token = TOKEN_PREFIX + "platform-reviewer-scorecard"
    instance = "rev-0000-0000-0000-000000000001"
    with client.app.state.db.session() as session:
        session.add(
            AgentCredential(
                token_sha256=hash_token(token),
                actor=f"agent:{SONNET}:reviewer",
                family=SONNET,
                instance=instance,
                lineage=[],
                on_behalf_of="operator",
                purpose="independent-reviewer",
                minted_by="platform",
                expires_at=utcnow() + timedelta(hours=1),
                platform_started=True,
            )
        )
    return token, instance


def _delegation(client) -> str:
    with client.app.state.db.session() as session:
        d = Delegation(
            granted_by="operator",
            grant_request_id="test",
            duty="risk_acceptance",
            tiers=["medium"],
            approver_families=[SONNET],
            sampling=1.0,  # every delegated decision sampled
            expires_at=utcnow() + timedelta(days=1),
        )
        session.add(d)
        session.flush()
        return d.id


def _seed_findings(client, auth, run_compaction, count: int) -> list[str]:
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=f"SC-{i}", severity="medium", line_start=10 + i * 20)
         for i in range(count)],
    )
    run_compaction()
    rows = client.app.state.catalog.query(
        "SELECT finding_id, rule_id FROM findings WHERE rule_id LIKE 'SC-%'"
    )
    by_rule = {str(rule): str(fid) for fid, rule in rows}
    return [by_rule[f"SC-{i}"] for i in range(count)]


class TestTheRecordAsTheEngineWritesIt:
    def test_every_metric_from_real_records(
        self, client, auth, admin_auth, viewer_auth, run_compaction, stand_in_adapters
    ) -> None:
        db = client.app.state.db
        policy = cached_policy(client.app.state.settings.approval_policy_path)
        minted = client.post(
            "/api/agents/credentials", json={"family": OPUS}, headers=admin_auth
        ).json()
        author = resolve_agent_credential(db, minted["token"])
        assert author is not None
        reviewer_token, reviewer_instance = _reviewer(client)
        reviewer = resolve_agent_credential(db, reviewer_token)
        assert reviewer is not None
        delegation = _delegation(client)

        def ask(subject: str, duty: str = "risk_acceptance", tier: str = "medium") -> Any:
            return engine.create_request(
                db, policy, duty=duty, subject_ref=subject, requested_by=author,
                context={"tier": tier},
            )

        def decide(req: Any, who: Principal, verdict: str) -> Any:
            return engine.decide(
                db, policy, request_id=req.id, approver=who, verdict=verdict,
                rationale=RATIONALE, evidence_digest=req.evidence_digest,
                rng=random.Random(0),
            )

        # As a requester, and the reviewer as an approver under the delegation.
        agreed_on, overturned = ask("acc-1"), ask("acc-2")
        first = decide(agreed_on, reviewer, "approve")
        second = decide(overturned, reviewer, "approve")
        assert first.sampled and second.sampled
        queried = ask("acc-3")
        decide(queried, PERSON, "needs_info")
        decide(queried, PERSON, "reject")
        lapsed = ask("acc-4")
        with db.session() as session:
            session.get(ApprovalRequest, lapsed.id).expires_at = utcnow() - timedelta(hours=1)
        merge = ask("acme/api#7@abc123", duty="pull_request_merge", tier="routine")
        decide(merge, PERSON, "reject")

        # A person reviews both samples; the disagreement suspends the delegation.
        sampling.record_sample_verdict(
            db, policy, decision_id=first.decision_id, reviewer=PERSON, verdict="agree"
        )
        outcome = sampling.record_sample_verdict(
            db, policy, decision_id=second.decision_id, reviewer=PERSON,
            verdict="disagree", note="The premise names a control the evidence does not show.",
        )
        assert outcome["delegation_suspended"]

        # Dispositions through the real route, as the agent; one reopened by a person.
        f1, f2, f3 = _seed_findings(client, auth, run_compaction, 3)
        agent = _bearer(minted["token"])
        for finding in (f1, f2):
            response = client.patch(
                f"/api/dashboard/findings/{finding}/status",
                json={"status": "false_positive", "reason": RATIONALE},
                headers=agent,
            )
            assert response.status_code == 200, response.text
        run_compaction()
        response = client.post(
            f"/api/dashboard/findings/{f1}/reopen",
            json={"reason": "The parameter is reflected unencoded on the error page."},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

        # Two claims that lapsed: one on a finding still open, one it dispositioned.
        with db.session() as session:
            for finding in (f3, f2):
                worklist.claim(
                    session, finding, REPO, by=minted["actor"],
                    now=utcnow() - timedelta(days=worklist.DEFAULT_CLAIM_DAYS + 1),
                )

        response = client.get("/api/agent/scorecard", headers=viewer_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["unknown"] == []
        assert body["agreement_window"] == policy.delegations.agreement_window
        instances = {g["instance"]: g for g in body["instances"]}
        assert set(instances) == {minted["instance"], reviewer_instance}

        def metric(group: dict[str, Any], name: str) -> dict[str, Any]:
            [m] = [m for m in group["metrics"] if m["name"] == name]
            return m

        # The reviewer, as an approver.
        rev = instances[reviewer_instance]
        assert rev["family"] == SONNET
        assert (metric(rev, "approver.sampled")["value"],
                metric(rev, "approver.sampled")["denominator"]) == (2, 2)
        overturned_m = metric(rev, "approver.overturned")
        assert (overturned_m["value"], overturned_m["denominator"]) == (1, 2)
        assert overturned_m["source"] == sc.SOURCE_DECISIONS
        assert metric(rev, "approver.agreement")["rate"] == 0.5
        [dlg] = rev["delegations"]
        assert dlg["delegation_id"] == delegation
        assert (dlg["agreed"], dlg["reviewed"], dlg["below_threshold"]) == (1, 2, True)
        assert dlg["suspended_at"] is not None

        # The author, as a requester.
        mine = instances[minted["instance"]]
        assert mine["family"] == OPUS
        assert mine["actor"] == minted["actor"]
        rejected = metric(mine, "requester.rejected")
        assert (rejected["value"], rejected["denominator"]) == (2, 4)
        assert rejected["breakdown"] == {"approved": 2, "rejected": 2, "expired": 1}
        needs_info = metric(mine, "requester.needs_info")
        assert (needs_info["value"], needs_info["denominator"]) == (1, 5)
        duties = {d["duty"]: d for d in mine["requests_by_duty"]}
        assert duties["pull_request_merge"]["by_state"] == {"rejected": 1}
        assert duties["risk_acceptance"]["requests"] == 4

        # Dispositions, attributed from the audit log's provenance.
        reopened = metric(mine, "dispositions.reopened")
        assert (reopened["value"], reopened["denominator"]) == (1, 2)
        assert reopened["breakdown"] == {"reopened_by_human": 1, "standing": 1}

        # Claims.
        claims = metric(mine, "claims.lapsed_open")
        assert (claims["value"], claims["denominator"]) == (1, 2)
        assert claims["breakdown"] == {"live": 0, "lapsed_open": 1, "lapsed_closed": 1}

        # And what cannot be derived says so on the agent's own record.
        for name in sc.NOT_DERIVABLE:
            assert metric(mine, name)["status"] == "unavailable"
            assert metric(mine, name)["value"] is None

        # Grouping and filters through the route.
        assert {g["family"] for g in body["families"]} == {OPUS, SONNET}
        only = client.get(
            "/api/agent/scorecard", params={"family": OPUS}, headers=viewer_auth
        ).json()
        assert [g["instance"] for g in only["instances"]] == [minted["instance"]]
        one = client.get(
            "/api/agent/scorecard", params={"instance": reviewer_instance}, headers=agent
        ).json()
        assert [g["instance"] for g in one["instances"]] == [reviewer_instance]


class TestTheRoute:
    def test_an_empty_estate_has_no_groups_and_nothing_unknown(
        self, client, admin_auth
    ) -> None:
        response = client.get("/api/agent/scorecard", headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["families"] == [] and body["instances"] == []
        assert body["unknown"] == []
        assert body["unattributed_dispositions"] == 0

    def test_it_needs_a_credential(self, client) -> None:
        assert client.get("/api/agent/scorecard").status_code == 401
