"""Compensating controls reference an observed control (TheHub #60902).

A compensating control used to be free text. Pinned here:

* a new proposal's control cites an observation or a declared control, and
  one that cites neither - or cites something this repository does not have -
  is refused by name;
* a cited control is read against the newest fresh observation:
  verified, contradicted or unverified, and the approver and the detail page
  see which;
* only a verified control lowers the tier. A `risk_adjustment` resting on
  controls none of which is verified stays at the scanner's severity, and is
  flagged.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mykronos.db.models import ApprovalRequest, ControlObservation, RepoControl
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_risk_acceptance import _agent, _approve, _propose, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

PREMISE = {"type": "port_not_published", "port": 5432, "container": "postgres"}


def _observation(
    client,
    ident: str,
    *,
    assertion: str = "bound_loopback",
    state: str = "pass",
    age_days: float = 0.1,
    control_id: str | None = None,
    subject: str = "tgb-desktop:5432",
) -> str:
    when = utcnow() - timedelta(days=age_days)
    with client.app.state.db.session() as session:
        session.add(
            ControlObservation(
                id=ident,
                repo_full_name=REPO,
                subject=subject,
                assertion=assertion,
                state=state,
                vantage="host",
                control_id=control_id,
                collected_at=when,
                received_at=when,
            )
        )
    return ident


def _adjust(client, admin_auth, controls: list[dict[str, Any]]):
    """A risk_adjustment rated low x low over findings the scanner calls high."""
    return _propose(
        client,
        _agent(client, admin_auth),
        deviation_type="risk_adjustment",
        premises=[PREMISE],
        residual_likelihood="low",
        residual_impact="low",
        compensating_controls=controls,
    )


def _evidence(client, approval_request_id: str) -> dict[str, Any]:
    with client.app.state.db.session() as session:
        request = session.get(ApprovalRequest, approval_request_id)
        assert request is not None
        return dict(request.evidence)


class TestAControlCitesAnObservation:
    def test_free_text_is_refused(self, client, admin_auth, lake) -> None:
        response = _adjust(client, admin_auth, [{"control": "WAF rule 942100", "owner": "ops"}])
        assert response.status_code == 409
        assert "observation_id or control_id" in response.json()["detail"]

    def test_an_observation_this_repository_does_not_have_is_refused(
        self, client, admin_auth, lake
    ) -> None:
        response = _adjust(client, admin_auth, [{"observation_id": "obs-nowhere"}])
        assert response.status_code == 409
        assert "No observation obs-nowhere" in response.json()["detail"]

    def test_an_undeclared_control_is_refused(self, client, admin_auth, lake) -> None:
        response = _adjust(client, admin_auth, [{"control_id": "ctl-nowhere"}])
        assert response.status_code == 409
        assert "No declared control ctl-nowhere" in response.json()["detail"]

    def test_a_cited_control_is_stored_with_its_status_and_shown_to_the_approver(
        self, client, admin_auth, lake
    ) -> None:
        obs = _observation(client, "obs-loopback")
        response = _adjust(client, admin_auth, [{"observation_id": obs, "control": "SC-7"}])
        assert response.status_code == 201, response.text
        body = response.json()
        [stored] = body["risk_acceptance"]["compensating_controls"]
        assert stored == {
            "observation_id": obs,
            "control": "SC-7",
            "status_at_proposal": "verified",
        }
        [check] = _evidence(client, body["approval_request_id"])["control_checks"]
        assert check["status"] == "verified" and check["observation_id"] == obs


class TestOnlyAVerifiedControlLowersTheTier:
    def test_a_verified_observation_lets_the_tier_go_below_the_scanner(
        self, client, admin_auth, lake
    ) -> None:
        obs = _observation(client, "obs-loopback")
        body = _adjust(client, admin_auth, [{"observation_id": obs}]).json()
        assert body["tier"] == "low"
        assert body["risk_acceptance"]["residual_severity"] == "low"
        assert not [f for f in body["flags"] if f["code"] == "unverified_controls"]

    def test_a_stale_observation_does_not_lower_it(self, client, admin_auth, lake) -> None:
        obs = _observation(client, "obs-old", age_days=30)
        body = _adjust(client, admin_auth, [{"observation_id": obs}]).json()
        assert body["tier"] == "high"
        assert body["risk_acceptance"]["residual_severity"] == "high"
        [flag] = [f for f in body["flags"] if f["code"] == "unverified_controls"]
        assert flag["controls"] == [0]
        assert body["risk_acceptance"]["compensating_controls"][0]["status_at_proposal"] == (
            "unverified"
        )

    def test_a_newer_contradicting_observation_outweighs_the_cited_one(
        self, client, admin_auth, lake
    ) -> None:
        cited = _observation(client, "obs-then", age_days=3)
        _observation(client, "obs-now", state="fail", age_days=0.1)
        body = _adjust(client, admin_auth, [{"observation_id": cited}]).json()
        assert body["tier"] == "high"
        [check] = _evidence(client, body["approval_request_id"])["control_checks"]
        assert check["status"] == "contradicted"
        assert check["observation_id"] == "obs-now"

    @staticmethod
    def _declared(client) -> str:
        with client.app.state.db.session() as session:
            control = RepoControl(repo_full_name=REPO, stride="spoofing", kind="perimeter_gate")
            session.add(control)
            session.flush()
            return str(control.id)

    def test_a_declared_control_nothing_observes_does_not_lower_it(
        self, client, admin_auth, lake
    ) -> None:
        control_id = self._declared(client)
        body = _adjust(client, admin_auth, [{"control_id": control_id}]).json()
        assert body["tier"] == "high"

    def test_a_declared_control_is_verified_by_the_observations_tied_to_it(
        self, client, admin_auth, lake
    ) -> None:
        control_id = self._declared(client)
        _observation(
            client,
            "obs-gate",
            assertion="anonymous_401",
            subject="app.example.net",
            control_id=control_id,
        )
        body = _adjust(client, admin_auth, [{"control_id": control_id}]).json()
        assert body["tier"] == "low"

    def test_one_verified_control_among_unverified_ones_is_enough(
        self, client, admin_auth, lake
    ) -> None:
        good = _observation(client, "obs-good")
        stale = _observation(client, "obs-stale", subject="other:1", age_days=30)
        body = _adjust(
            client, admin_auth, [{"observation_id": stale}, {"observation_id": good}]
        ).json()
        assert body["tier"] == "low"


class TestTheDetailShowsEachControl:
    def test_controls_are_read_again_on_every_view(self, client, admin_auth, lake) -> None:
        obs = _observation(client, "obs-loopback")
        proposed = _adjust(client, admin_auth, [{"observation_id": obs}]).json()
        assert _approve(client, admin_auth, proposed).json()["state"] == "approved"
        record_id = proposed["risk_acceptance"]["id"]

        [check] = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()[
            "control_checks"
        ]
        assert check["status"] == "verified"

        _observation(client, "obs-later", state="fail")
        [check] = client.get(f"/api/risk-acceptances/{record_id}", headers=admin_auth).json()[
            "control_checks"
        ]
        assert check["status"] == "contradicted"
