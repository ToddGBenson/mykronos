"""An interim review at 30 days for acceptances nothing watches (TheHub #60817).

The duration caps stay by severity. What changes: an acceptance whose reason
code is one no monitor re-reads - `not_exploitable_here`, `compensating_control`,
`cost_exceeds_risk` - unless a premise `premise_monitor` evaluates covers it,
is looked at again 30 days after it takes effect. Pinned here: the policy file
carries the rule; which records owe it; that the day it falls due the record
reads `review due` on the Risk management tab, in the briefing's acceptances
section and in the work queue; that after the grace period it lapses to
`needs_review` - loudly, with its findings still accepted, never expired
quietly; and that a person recording the review returns it to `active`.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from mykronos import agent_work, daily_briefing
from mykronos import risk_acceptance as ra
from mykronos.approvals.policy import InterimReview, PolicyError, load_policy, parse_policy
from mykronos.db.models import AuditLogEntry, RiskAcceptance
from mykronos.schemas import utcnow
from tests.test_api_repo_risk_acceptances import _list, _repo_id
from tests.test_risk_acceptance import IMAGE, _agent, _approve, _propose, _statuses, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

POLICY_FILE = Path(__file__).resolve().parents[2] / "approval-policy-v1.yaml"
RULE = InterimReview()


# ---------------------------------------------------------------------------
# The policy file
# ---------------------------------------------------------------------------


class TestThePolicyFileCarriesTheRule:
    def test_thirty_days_for_the_reasons_nothing_watches(self) -> None:
        limits = load_policy(POLICY_FILE).risk_acceptance
        rule = limits.interim_review
        assert rule.days == 30
        assert rule.grace_days > 0
        assert rule.reason_codes == {
            "not_exploitable_here",
            "compensating_control",
            "cost_exceeds_risk",
        }
        assert rule.unless_monitored_premise is True

    def test_the_caps_stay_by_severity(self) -> None:
        limits = load_policy(POLICY_FILE).risk_acceptance
        assert limits.max_duration_days == {"critical": 30, "high": 90, "medium": 180, "low": 365}

    def _doc(self, interim: Any) -> dict[str, Any]:
        return {
            "version": "t",
            "duties": {"x": {"tiers": {"any": {"approvers": [{"kind": "human"}]}}}},
            "risk_acceptance": {"interim_review": interim},
        }

    def test_absent_reads_as_the_default(self) -> None:
        doc = self._doc(None)
        assert parse_policy(doc).risk_acceptance.interim_review == InterimReview()

    @pytest.mark.parametrize("bad", [{"days": 0}, {"grace_days": -1}, "thirty"])
    def test_a_nonsense_rule_is_refused(self, bad: Any) -> None:
        with pytest.raises(PolicyError, match="interim_review"):
            parse_policy(self._doc(bad))


# ---------------------------------------------------------------------------
# Which records owe it
# ---------------------------------------------------------------------------


class TestWhoOwesIt:
    @pytest.mark.parametrize(
        ("deviation", "controls", "premises", "owed"),
        [
            ("risk_adjustment", [], [{"type": "path_unreachable"}], True),
            ("risk_adjustment", [{"control": "WAF rule"}], [{"type": "image_role"}], True),
            ("operational_requirement", [], [], True),
            # Watched already: the finding re-opens the day a fix ships.
            ("vendor_dependency", [], [{"type": "no_fixed_version"}], False),
            # A premise the monitor re-reads every day.
            ("risk_adjustment", [], [{"type": "port_not_published"}], False),
            ("risk_adjustment", [], [{"type": "path_unreachable"}, {"type": "epss_below"}], False),
            ("operational_requirement", [], [{"type": "not_internet_facing"}], False),
        ],
    )
    def test_the_reason_code_unless_a_monitored_premise(
        self, deviation: str, controls: list[Any], premises: list[Any], owed: bool
    ) -> None:
        assert ra.interim_review_owed(deviation, controls, premises, RULE) is owed

    def test_a_monitored_premise_exempts_only_when_the_policy_says(self) -> None:
        strict = InterimReview(unless_monitored_premise=False)
        assert ra.interim_review_owed(
            "risk_adjustment", [], [{"type": "port_not_published"}], strict
        )

    def test_none_when_the_expiry_review_comes_first(self) -> None:
        start = date(2026, 10, 21)
        record = RiskAcceptance(
            deviation_type="risk_adjustment",
            premises=[{"type": "path_unreachable"}],
            compensating_controls=[],
            review_by=start + timedelta(days=20),
        )
        assert ra.interim_review_date(record, RULE, starting=start) is None
        record.review_by = start + timedelta(days=200)
        assert ra.interim_review_date(record, RULE, starting=start) == start + timedelta(days=30)


# ---------------------------------------------------------------------------
# The lifecycle, end to end
# ---------------------------------------------------------------------------


def _unwatched(client, admin_auth) -> str:
    """not_exploitable_here, resting on a premise no monitor evaluates yet."""
    proposed = _propose(
        client,
        _agent(client, admin_auth),
        deviation_type="risk_adjustment",
        premises=[{"type": "path_unreachable", "detail": "the parser is never called"}],
    ).json()
    assert _approve(client, admin_auth, proposed).json()["state"] == "approved"
    return str(proposed["risk_acceptance"]["id"])


def _get(client, record_id: str) -> RiskAcceptance:
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None
        session.expunge(record)
        return record


def _actions(client, record_id: str) -> list[str]:
    with client.app.state.db.session() as session:
        return [
            e.action
            for e in session.execute(
                select(AuditLogEntry).where(AuditLogEntry.entity_id == record_id)
            ).scalars()
        ]


class TestTheLifecycle:
    def test_approval_schedules_it_thirty_days_out(self, client, admin_auth, lake) -> None:
        record = _get(client, _unwatched(client, admin_auth))
        assert record.interim_review_by == utcnow().date() + timedelta(days=30)
        assert record.status == "active"

    def test_a_watched_reason_owes_none(self, client, admin_auth, lake) -> None:
        proposed = _propose(client, _agent(client, admin_auth)).json()  # vendor_dependency
        _approve(client, admin_auth, proposed)
        record = _get(client, proposed["risk_acceptance"]["id"])
        assert record.interim_review_by is None
        db, catalog = client.app.state.db, client.app.state.catalog
        result = ra.sweep(db, catalog, today=utcnow().date() + timedelta(days=31))
        assert (result.interim_due, result.needs_review) == (0, 0)

    def test_due_then_lapsed_never_expired(self, client, admin_auth, lake) -> None:
        record_id = _unwatched(client, admin_auth)
        db, catalog = client.app.state.db, client.app.state.catalog
        due = _get(client, record_id).interim_review_by
        assert due is not None

        assert ra.sweep(db, catalog, today=due - timedelta(days=1)).interim_due == 0
        assert ra.sweep(db, catalog, today=due).interim_due == 1
        assert _get(client, record_id).status == "review_due"

        lapsed_on = due + timedelta(days=RULE.grace_days)
        result = ra.sweep(db, catalog, today=lapsed_on)
        assert (result.needs_review, result.expired) == (1, 0)
        record = _get(client, record_id)
        assert record.status == "needs_review"
        assert record.status in ra.LIVE
        # The findings it holds stay accepted: nothing reopened quietly.
        assert _statuses(client)[("CVE-2026-1", IMAGE)][0] == "accepted_risk"
        actions = _actions(client, record_id)
        assert "risk_acceptance.interim_review_due" in actions
        assert "risk_acceptance.needs_review" in actions
        assert "risk_acceptance.expired" not in actions

    def test_a_person_records_it_and_it_is_active_again(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _unwatched(client, admin_auth)
        db, catalog = client.app.state.db, client.app.state.catalog
        due = _get(client, record_id).interim_review_by
        assert due is not None
        ra.sweep(db, catalog, today=due + timedelta(days=RULE.grace_days))

        refused = client.post(
            f"/api/risk-acceptances/{record_id}/interim-review",
            json={"note": "Checked."},
            headers=_agent(client, admin_auth),
        )
        assert refused.status_code == 403, refused.text

        response = client.post(
            f"/api/risk-acceptances/{record_id}/interim-review",
            json={"note": "Re-read the call graph: the parser is still never called."},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()["risk_acceptance"]
        assert body["status"] == "active"
        assert body["interim_reviewed_at"]
        assert "risk_acceptance.interim_reviewed" in _actions(client, record_id)
        # Once is what it owes; a second sweep leaves it alone.
        later = ra.sweep(db, catalog, today=due + timedelta(days=RULE.grace_days + 5))
        assert (later.interim_due, later.needs_review) == (0, 0)
        again = client.post(
            f"/api/risk-acceptances/{record_id}/interim-review",
            json={"note": "Again."},
            headers=admin_auth,
        )
        assert again.status_code == 409

    def test_one_approved_before_the_rule_reads_due_before_it_lapses(
        self, client, admin_auth, lake
    ) -> None:
        record_id = _unwatched(client, admin_auth)
        db, catalog = client.app.state.db, client.app.state.catalog
        today = utcnow().date()
        with db.session() as session:
            record = session.get(RiskAcceptance, record_id)
            assert record is not None
            # As if approved 100 days ago, before this rule shipped.
            record.interim_review_by = None
            record.effective_at = datetime.combine(today - timedelta(days=100), datetime.min.time())
            record.review_by = today + timedelta(days=200)
            record.expires_at = today + timedelta(days=214)

        ra.sweep(db, catalog, today=today)
        record = _get(client, record_id)
        assert record.interim_review_by == today
        assert record.status == "review_due"
        assert "risk_acceptance.interim_review_scheduled" in _actions(client, record_id)


# ---------------------------------------------------------------------------
# Where it shows
# ---------------------------------------------------------------------------


class TestWhereItShows:
    def _due(self, client, admin_auth, *, lapse: bool) -> tuple[str, date]:
        record_id = _unwatched(client, admin_auth)
        due = _get(client, record_id).interim_review_by
        assert due is not None
        today = due + timedelta(days=RULE.grace_days if lapse else 0)
        ra.sweep(client.app.state.db, client.app.state.catalog, today=today)
        return record_id, today

    def test_the_risk_management_tab(self, client, admin_auth, lake) -> None:
        record_id, _ = self._due(client, admin_auth, lapse=False)
        [row] = _list(client, admin_auth, _repo_id(client))["acceptances"]
        assert row["id"] == record_id
        assert row["review_due"] is True
        assert row["interim_review_by"]

    def test_the_tab_after_it_lapses(self, client, admin_auth, lake) -> None:
        self._due(client, admin_auth, lapse=True)
        body = _list(client, admin_auth, _repo_id(client))
        [row] = body["acceptances"]
        assert row["state"] == "needs_review"
        assert row["alarm"] is True and row["review_due"] is True
        assert body["counts"]["by_state"]["needs_review"] == 1
        detail = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/{row['id']}",
            headers=admin_auth,
        ).json()
        assert "Record the interim review" in [a["label"] for a in detail["actions"]]

    @pytest.mark.parametrize("lapse", [False, True])
    def test_the_briefing(self, client, admin_auth, lake, lapse: bool) -> None:
        record_id, today = self._due(client, admin_auth, lapse=lapse)
        now = datetime.combine(today, datetime.min.time())
        section = daily_briefing.acceptances_section(client.app.state.db, now=now)
        [entry] = section.data["review_due"]
        assert entry["id"] == record_id and entry["needs_review"] is lapse
        [line] = [line for line in section.lines if "interim review" in line.what]
        assert line.work == "decision"
        assert ("lapsed" in line.what) is lapse

    @pytest.mark.parametrize("lapse", [False, True])
    def test_the_work_queue(self, client, admin_auth, lake, lapse: bool) -> None:
        record_id, today = self._due(client, admin_auth, lapse=lapse)
        record = ra.serialize(_get(client, record_id))
        [item] = agent_work._acceptance_items([record], today=today)
        assert "interim review" in item.summary
        assert ("lapsed" in item.summary) is lapse
        assert "interim review" in item.done_when
