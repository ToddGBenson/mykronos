"""The repo page's Risk management tab reads one repository's acceptances.

Pinned here: the state the tab filters by is derived from the dates as well
as the stored status; the counts cover every acceptance whatever the filter;
each row carries its covered findings (with effective severity), its premises
with today's verdict and the evidence age, and whether a fix now exists; the
detail carries the audit history and the actions the acceptance API offers;
and - above all - an acceptance from another repository never appears, in
the list or under this repository's detail URL.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from mykronos.api.repo_risk_acceptances import (
    EXPIRING_WITHIN_DAYS,
    actions_for,
    derive_state,
    evidence_at,
    worst,
)
from mykronos.db.models import EnvironmentalScore, RepoOnboarding, RiskAcceptance
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_onboarding import onboard
from tests.test_risk_acceptance import IMAGE, _agent, _approve, _propose, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

OTHER_REPO = "example-org/ledger"
TODAY = date(2026, 10, 20)


# ---------------------------------------------------------------------------
# Pure derivations
# ---------------------------------------------------------------------------


class TestDeriveState:
    def test_a_live_record_far_from_expiry_is_active(self) -> None:
        assert derive_state("active", TODAY + timedelta(days=90), TODAY) == "active"

    def test_review_due_is_still_live(self) -> None:
        assert derive_state("review_due", TODAY + timedelta(days=90), TODAY) == "active"

    def test_thirty_days_left_is_expiring(self) -> None:
        left = TODAY + timedelta(days=EXPIRING_WITHIN_DAYS)
        assert derive_state("active", left, TODAY) == "expiring"
        assert derive_state("active", left + timedelta(days=1), TODAY) == "active"

    def test_a_live_record_past_its_date_is_expired_before_the_sweep_says_so(self) -> None:
        assert derive_state("active", TODAY - timedelta(days=1), TODAY) == "expired"

    def test_the_stored_terminal_states_pass_through(self) -> None:
        for stored in ("premise_failed", "revoked", "expired", "pending_approval"):
            assert derive_state(stored, TODAY + timedelta(days=90), TODAY) == stored

    def test_closed_rejected_and_unapproved_read_closed(self) -> None:
        for stored in ("closed", "rejected", "not_approved"):
            assert derive_state(stored, None, TODAY) == "closed"


def test_worst_ignores_unknown_words() -> None:
    assert worst(["low", "HIGH", "medium"]) == "high"
    assert worst(["", "unknown"]) == ""


def test_evidence_at_reads_observations_and_epss_rows() -> None:
    assert evidence_at([]) is None
    newest = evidence_at(
        [
            {"collected_at": "2026-10-01T00:00:00"},
            {"fetched_at": "2026-10-03T12:00:00"},
            {"collected_at": "not a date"},
        ]
    )
    assert newest == datetime(2026, 10, 3, 12, 0, 0)


def test_actions_follow_the_routes_rules() -> None:
    assert [a.label for a in actions_for("x", "active")] == ["Renew", "Revoke"]
    assert [a.label for a in actions_for("x", "pending_approval")] == ["Revoke"]
    assert [a.label for a in actions_for("x", "premise_failed")] == [
        "Propose a corrected acceptance"
    ]
    assert actions_for("x", "revoked") == []


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------


def _repo_id(client, repo: str = REPO) -> str:
    with client.app.state.db.session() as session:
        row = session.scalars(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo)
        ).one()
        return str(row.id)


def _finding_ids(client, repo: str = REPO) -> dict[tuple[str, str], str]:
    rows = client.app.state.catalog.query(
        "SELECT rule_id, json_extract_string(raw_finding_json, '$.image'), finding_id "
        "FROM findings WHERE repo_full_name = ?",
        [repo],
    )
    return {(str(r[0]), str(r[1])): str(r[2]) for r in rows}


def _record(client, **fields: Any) -> str:
    today = utcnow().date()
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "scope": {"capability": "containers"},
        "covered_finding_ids": [],
        "deviation_type": "risk_adjustment",
        "justification": "Bound to loopback.",
        "residual_likelihood": "low",
        "residual_impact": "low",
        "residual_severity": "low",
        "premises": [],
        "risk_owner": "tgb",
        "requested_by": "agent:test",
        "approved_by": "admin",
        "status": "active",
        "expires_at": today + timedelta(days=80),
        "review_by": today + timedelta(days=66),
    }
    values.update(fields)
    with client.app.state.db.session() as session:
        record = RiskAcceptance(**values)
        session.add(record)
        session.flush()
        return str(record.id)


def _list(client, auth, repo_id: str, **params: str) -> dict[str, Any]:
    response = client.get(
        f"/api/dashboard/repos/{repo_id}/risk-acceptances", params=params, headers=auth
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


@pytest.fixture
def approved(client, admin_auth, lake) -> str:
    """A real acceptance, proposed by an agent and approved by a person."""
    proposed = _propose(client, _agent(client, admin_auth)).json()
    assert _approve(client, admin_auth, proposed).json()["state"] == "approved"
    return str(proposed["risk_acceptance"]["id"])


class TestTheList:
    def test_an_empty_repository_says_so(self, client, admin_auth, lake) -> None:
        body = _list(client, admin_auth, _repo_id(client))
        assert body["total"] == 0 and body["acceptances"] == []
        assert body["counts"]["by_state"]["active"] == 0
        assert body["repo_full_name"] == REPO

    def test_an_approved_acceptance_carries_what_it_rests_on(
        self, client, admin_auth, approved
    ) -> None:
        body = _list(client, admin_auth, _repo_id(client))
        [row] = body["acceptances"]
        assert row["id"] == approved
        assert row["state"] == "active"
        assert row["reason_code"] == "no_vendor_fix"
        assert row["approved_by"] == client.app.state.settings.admin_identity
        assert row["risk_owner"] == "tgb"
        assert row["days_left"] is not None and row["days_left"] > EXPIRING_WITHIN_DAYS
        assert row["alarm"] is False
        # The two unfixed postgres findings; the fixable one was out of scope.
        assert row["findings_total"] == 2
        assert {f["rule_id"] for f in row["findings"]} == {"CVE-2026-1", "CVE-2026-2"}
        assert row["findings"][0]["severity"] == "high"  # worst first
        assert row["severity"] == "high" and row["effective_severity"] == "high"
        assert all(f["effective_source"] == "scanner" for f in row["findings"])
        assert all(f["status"] == "accepted_risk" for f in row["findings"])
        [premise] = row["premises"]
        assert premise["type"] == "no_fixed_version"
        assert premise["status"] == "unverified"
        assert premise["evidence_age_days"] is None
        assert row["premise_fresh_days"] == 14

    def test_a_viewer_may_read_it_and_an_anonymous_caller_may_not(
        self, client, admin_auth, viewer_auth, approved
    ) -> None:
        repo_id = _repo_id(client)
        assert _list(client, viewer_auth, repo_id)["total"] == 1
        response = client.get(f"/api/dashboard/repos/{repo_id}/risk-acceptances")
        assert response.status_code == 401

    def test_an_unknown_repository_is_404(self, client, admin_auth) -> None:
        response = client.get(
            "/api/dashboard/repos/no-such-repo/risk-acceptances", headers=admin_auth
        )
        assert response.status_code == 404

    def test_states_are_counted_and_filtered(self, client, admin_auth, lake) -> None:
        today = utcnow().date()
        ids = {
            "active": _record(client),
            "expiring": _record(client, expires_at=today + timedelta(days=10)),
            "past_date": _record(client, expires_at=today - timedelta(days=2)),
            "expired": _record(client, status="expired", expires_at=today - timedelta(days=9)),
            "premise_failed": _record(client, status="premise_failed"),
            "revoked": _record(client, status="revoked"),
            "pending": _record(client, status="pending_approval", expires_at=None),
            "closed": _record(client, status="closed"),
        }
        repo_id = _repo_id(client)
        body = _list(client, admin_auth, repo_id)
        assert body["total"] == 8
        assert body["counts"]["by_state"] == {
            "premise_failed": 1,
            "needs_review": 0,
            "expired": 2,
            "expiring": 1,
            "active": 1,
            "pending_approval": 1,
            "revoked": 1,
            "closed": 1,
        }
        # Needs-a-decision first.
        assert body["acceptances"][0]["state"] == "premise_failed"

        expiring = _list(client, admin_auth, repo_id, state="expiring")
        assert [r["id"] for r in expiring["acceptances"]] == [ids["expiring"]]
        assert expiring["acceptances"][0]["days_left"] == 10
        # The counts do not narrow with the filter: the strip reads the same.
        assert expiring["total"] == 8 and expiring["counts"] == body["counts"]
        assert expiring["state"] == "expiring"

        expired = _list(client, admin_auth, repo_id, state="expired")
        assert {r["id"] for r in expired["acceptances"]} == {ids["past_date"], ids["expired"]}
        assert all(r["alarm"] for r in expired["acceptances"])
        past = next(r for r in expired["acceptances"] if r["id"] == ids["past_date"])
        assert past["status"] == "active" and past["days_left"] == -2

        failed = _list(client, admin_auth, repo_id, state="premise_failed")
        assert failed["acceptances"][0]["alarm"] is True

    def test_severity_and_effective_severity_filter(self, client, admin_auth, approved) -> None:
        found = _finding_ids(client)
        high = found[("CVE-2026-1", IMAGE)]
        with client.app.state.db.session() as session:
            session.add(
                EnvironmentalScore(
                    finding_id=high,
                    repo_full_name=REPO,
                    scanner_severity="high",
                    effective_severity="low",
                )
            )
        # A second acceptance covering only the medium one.
        _record(client, covered_finding_ids=[found[("CVE-2026-2", IMAGE)]])
        repo_id = _repo_id(client)
        body = _list(client, admin_auth, repo_id)
        assert body["counts"]["by_severity"]["high"] == 1
        assert body["counts"]["by_severity"]["medium"] == 1
        # Re-read for this environment, the high is low: both now read medium.
        assert body["counts"]["by_effective_severity"]["medium"] == 2
        assert body["counts"]["by_effective_severity"]["high"] == 0

        [row] = _list(client, admin_auth, repo_id, severity="high")["acceptances"]
        assert row["id"] == approved
        scored = next(f for f in row["findings"] if f["finding_id"] == high)
        assert scored["effective_severity"] == "low"
        assert scored["effective_source"] == "environmental"
        assert _list(client, admin_auth, repo_id, effective_severity="high")["acceptances"] == []

    def test_a_fix_now_available_is_flagged(self, client, admin_auth, lake) -> None:
        found = _finding_ids(client)
        fixable = found[("CVE-2026-3", IMAGE)]
        _record(client, deviation_type="vendor_dependency", covered_finding_ids=[fixable])
        [row] = _list(client, admin_auth, _repo_id(client))["acceptances"]
        assert row["reason_code"] == "no_vendor_fix"
        assert row["now_fixable"] == 1
        [finding] = row["findings"]
        assert finding["now_fixable"] is True and finding["fixed_version"] == "2.36-9"

    def test_compensating_controls_and_premise_failures_are_carried(
        self, client, admin_auth, lake
    ) -> None:
        _record(
            client,
            compensating_controls=[{"control": "WAF rule 942100", "owner": "ops"}],
            premises=[{"type": "epss_below", "threshold": 0.1, "cves": ["CVE-2026-1"]}],
        )
        [row] = _list(client, admin_auth, _repo_id(client))["acceptances"]
        assert row["reason_code"] == "compensating_control"
        assert row["compensating_controls"] == [{"control": "WAF rule 942100", "owner": "ops"}]
        [premise] = row["premises"]
        assert premise["premise"]["threshold"] == 0.1
        assert premise["status"] == "unverified"  # no EPSS row: not evaluated, not holding


class TestRepositoryScoping:
    @pytest.fixture
    def other(self, client, admin_auth, github, lake) -> str:
        github.add_repo(OTHER_REPO, files={"README.md": "# ledger"})
        assert onboard(client, admin_auth, repo=OTHER_REPO).status_code in (200, 201)
        return _record(client, repo_full_name=OTHER_REPO, justification="Ledger's own.")

    def test_another_repositorys_acceptance_never_appears(
        self, client, admin_auth, approved, other
    ) -> None:
        body = _list(client, admin_auth, _repo_id(client))
        assert [r["id"] for r in body["acceptances"]] == [approved]
        assert body["total"] == 1
        assert all(r["repo_full_name"] == REPO for r in body["acceptances"])
        for state in ("active", "expiring", "expired"):
            listed = _list(client, admin_auth, _repo_id(client), state=state)
            assert other not in {r["id"] for r in listed["acceptances"]}

        theirs = _list(client, admin_auth, _repo_id(client, OTHER_REPO))
        assert [r["id"] for r in theirs["acceptances"]] == [other]

    def test_its_detail_is_404_under_this_repository(
        self, client, admin_auth, approved, other
    ) -> None:
        response = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/{other}",
            headers=admin_auth,
        )
        assert response.status_code == 404
        assert "Ledger" not in response.text

    def test_a_covered_id_from_another_repository_reads_missing(
        self, client, admin_auth, other
    ) -> None:
        found = _finding_ids(client)
        _record(
            client,
            repo_full_name=OTHER_REPO,
            covered_finding_ids=[found[("CVE-2026-1", IMAGE)]],
        )
        theirs = _list(client, admin_auth, _repo_id(client, OTHER_REPO))
        statuses = [f["status"] for r in theirs["acceptances"] for f in r["findings"]]
        assert statuses == ["missing"]
        titles = [f["title"] for r in theirs["acceptances"] for f in r["findings"]]
        assert titles == [""]


class TestTheDetail:
    def test_the_detail_carries_history_scores_and_actions(
        self, client, admin_auth, approved
    ) -> None:
        response = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/{approved}",
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        detail = response.json()
        assert detail["justification"].startswith("Debian has not published")
        assert detail["scope"]["image"] == IMAGE
        assert "risk_acceptance.requested" in [e["action"] for e in detail["history"]]
        assert detail["scores"]["total"] == 2 and detail["scores"]["scored"] == 0
        assert [a["label"] for a in detail["actions"]] == ["Renew", "Revoke"]
        assert detail["actions"][0]["path"] == f"/api/risk-acceptances/{approved}/renew"
        assert len(detail["milestones"]) == 2
        assert detail["renewed_by"] == []

    def test_a_revocation_is_in_the_history(self, client, admin_auth, approved) -> None:
        revoked = client.post(
            f"/api/risk-acceptances/{approved}/revoke",
            json={"reason": "The vendor shipped a fix."},
            headers=admin_auth,
        )
        assert revoked.status_code == 200, revoked.text
        detail = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/{approved}",
            headers=admin_auth,
        ).json()
        assert detail["state"] == "revoked"
        assert detail["closed_reason"] == "The vendor shipped a fix."
        assert detail["history"][-1]["action"] == "risk_acceptance.revoked"
        assert detail["actions"] == []

    def test_a_renewal_names_its_successor(self, client, admin_auth, approved) -> None:
        child = _record(client, renews_id=approved, status="pending_approval")
        detail = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/{approved}",
            headers=admin_auth,
        ).json()
        assert detail["renewed_by"] == [child]

    def test_an_unknown_acceptance_is_404(self, client, admin_auth, lake) -> None:
        response = client.get(
            f"/api/dashboard/repos/{_repo_id(client)}/risk-acceptances/nope",
            headers=admin_auth,
        )
        assert response.status_code == 404
