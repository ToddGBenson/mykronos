"""Every action the work queue offers on an acceptance, called (TheHub #60846).

The queue offered "Renew it" on a `premise_failed` acceptance, and the renew
route refuses anything that is not live. Nothing caught it, because the queue's
tests read the queue and the route's tests read the route. This drives a real
record into each status the queue reads (`api.agent._ACCEPTANCE_STATES`), takes
the item `GET /api/agent/work` returns for it, and calls every action on it. A
status added to the queue without a way to reach it here, or an action whose
route refuses the record, fails.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest

from mykronos import risk_acceptance as ra
from mykronos.api.agent import _ACCEPTANCE_STATES
from mykronos.db.models import RiskAcceptance
from tests.test_premise_monitor import PORT_PREMISE, _accepted, _observe
from tests.test_risk_acceptance import _agent, _proposal, lake

__all__ = ["lake"]  # the fixture, re-exported so pytest finds it here

#: A premise that holds where PORT_PREMISE failed: the port is published, and
#: the corrected acceptance says the firewall restricts it.
CORRECTED = {"type": "firewall_scope", "port": 5432, "host": "db.example.net"}


def _to_active(client, admin_auth) -> str:
    """Live, and inside the expiry lead, so the queue surfaces it."""
    record_id = _accepted(client, admin_auth, [PORT_PREMISE])
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None
        record.expires_at = date.today() + timedelta(days=5)
    return record_id


def _to_review_due(client, admin_auth) -> str:
    record_id = _accepted(client, admin_auth, [PORT_PREMISE])
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None and record.review_by is not None
        review_by = record.review_by
    assert ra.sweep(client.app.state.db, client.app.state.catalog, today=review_by).review_due
    return record_id


def _to_premise_failed(client, admin_auth) -> str:
    """The monitor's own path: an observation contradicts the premise."""
    record_id = _accepted(client, admin_auth, [PORT_PREMISE])
    _observe(client)  # the ingest runs the monitor
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None and record.status == "premise_failed"
    return record_id


def _to_needs_review(client, admin_auth) -> str:
    """An acceptance nothing watches whose interim review lapsed (TheHub #60817)."""
    record_id = _accepted(client, admin_auth, [{"type": "path_unreachable"}])
    with client.app.state.db.session() as session:
        record = session.get(RiskAcceptance, record_id)
        assert record is not None and record.interim_review_by is not None
        lapsed_on = record.interim_review_by + timedelta(days=ra.interim_rule().grace_days)
    assert ra.sweep(client.app.state.db, client.app.state.catalog, today=lapsed_on).needs_review
    return record_id


DRIVERS = {
    "active": _to_active,
    "review_due": _to_review_due,
    "needs_review": _to_needs_review,
    "premise_failed": _to_premise_failed,
}


def _body(template: str) -> dict[str, Any]:
    """A valid body for each route the queue may offer on an acceptance."""
    until = (date.today() + timedelta(days=30)).isoformat()
    bodies: dict[str, dict[str, Any]] = {
        "POST /api/risk-acceptances/{id}/renew": {
            "requested_until": until,
            "justification": "Re-attested: the port is still closed.",
        },
        "POST /api/risk-acceptances/{id}/revoke": {"reason": "Superseded."},
        "POST /api/risk-acceptances": _proposal(
            deviation_type="risk_adjustment",
            premises=[CORRECTED],
            requested_until=until,
            justification="The port is published; the host firewall restricts it.",
        ),
    }
    assert template in bodies, f"no body for {template}: add one when the queue offers it"
    return bodies[template]


def _item(client, auth, record_id: str) -> dict[str, Any] | None:
    response = client.get("/api/agent/work", headers=auth)
    assert response.status_code == 200, response.text
    items = [
        i for i in response.json()["items"] if i["item_id"] == f"acceptance_attention:{record_id}"
    ]
    return items[0] if items else None


def test_every_status_the_queue_reads_has_a_driver() -> None:
    assert set(_ACCEPTANCE_STATES) == set(DRIVERS)


@pytest.mark.parametrize("status", _ACCEPTANCE_STATES)
def test_every_action_offered_is_one_its_route_accepts(
    client, admin_auth, lake, status: str
) -> None:
    record_id = DRIVERS[status](client, admin_auth)
    agent = _agent(client, admin_auth)
    item = _item(client, agent, record_id)
    assert item is not None, f"a {status} acceptance in reach of a decision is not on the queue"
    assert item["actions"], f"{status}: the item offers nothing to call"

    for action in item["actions"]:
        template = f"{action['method']} {action['path'].replace(record_id, '{id}')}"
        if action["method"] == "GET":
            response = client.get(action["path"], headers=agent)
        else:
            # Revoke is a person's action; everything else is the agent's.
            auth = admin_auth if template.endswith("/revoke") else agent
            response = client.post(action["path"], json=_body(template), headers=auth)
        assert response.status_code < 300, f"{status}: {template} -> {response.text}"


def test_a_corrected_acceptance_takes_a_failed_one_off_the_queue(
    client, admin_auth, lake
) -> None:
    """done_when for premise_failed: every covered finding fixed or held by a
    new acceptance. Proposing one holds them, and the item goes."""
    record_id = _to_premise_failed(client, admin_auth)
    agent = _agent(client, admin_auth)
    item = _item(client, agent, record_id)
    assert item is not None
    assert "port_not_published" in item["title"]
    assert "control_observations" in {e["source"] for e in item["evidence"]}

    proposed = client.post(
        "/api/risk-acceptances", json=_body("POST /api/risk-acceptances"), headers=agent
    )
    assert proposed.status_code == 201, proposed.text
    assert _item(client, agent, record_id) is None
