"""A scoped agent credential reads through the perimeter on its own (TheHub #61954).

On 2026-11-16 and 11-17 the security champion and Delivery could not read
`/api/approvals` or the risk acceptances: the perimeter gate wanted the
`X-Hub-Token`, which they do not hold, and 401'd the agent credential they
do hold before any handler saw it. Every check became an operator script.

The slice built here: a credential a person minted for the `security-champion`
or `delivery` purpose passes the perimeter on its own for an allow-list of
GETs, as a viewer, with every use in the audit log. Anything else it asks
for is a 403. Every other credential, and the same credential arriving
through the tunnel, is refused exactly as before.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.approvals import engine
from mykronos.approvals.engine import Subject
from mykronos.db.models import AuditLogEntry
from mykronos.gate import TOKEN_HEADER
from mykronos.main import create_app
from tests.conftest import (
    ADMIN_TOKEN,
    REPO,
    VIEWER_TOKEN,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)

GATE = "hub-token-value"
READERS = ("security-champion", "delivery")
REFUSED = {"detail": "Not authorised for this host."}


@pytest.fixture
def gated(settings) -> Any:
    with TestClient(create_app(settings.model_copy(update={"gate_token": GATE}))) as client:
        yield client


def _operator() -> dict[str, str]:
    return {TOKEN_HEADER: GATE, "Authorization": f"Bearer {ADMIN_TOKEN}"}


def _alone(token: str) -> dict[str, str]:
    """The credential and nothing else: no perimeter token."""
    return {"Authorization": f"Bearer {token}"}


def _mint(client, purpose: str, minted_by: dict[str, str] | None = None) -> dict[str, Any]:
    response = client.post(
        "/api/agents/credentials",
        json={"family": "claude-opus-5.5", "purpose": purpose},
        headers=minted_by or _operator(),
    )
    assert response.status_code == 201, response.text
    return response.json()


def _audit(client, action: str) -> list[AuditLogEntry]:
    with client.app.state.db.session() as session:
        rows = list(
            session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == action)
            ).scalars()
        )
        session.expunge_all()
        return rows


def _own_request(client, headers: dict[str, str], subject: str) -> dict[str, Any]:
    response = client.post(
        "/api/approvals",
        json={"duty": "risk_acceptance", "subject_ref": subject, "context": {"tier": "low"}},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def _approve(request: dict[str, Any]) -> dict[str, str]:
    return {
        "verdict": "approve",
        "rationale": "Checked against the evidence.",
        "evidence_digest": request["evidence_digest"],
    }


@pytest.fixture
def tiered(monkeypatch):
    """The risk-acceptance adapter stand-in test_approvals.py uses, so an agent
    can open a request of its own through the generic route."""

    def adapter(subject_ref: str, context: dict[str, Any]) -> Subject:
        return Subject(tier=context["tier"], evidence={"subject": subject_ref, **context})

    monkeypatch.setitem(engine._ADAPTERS, "risk_acceptance", adapter)
    monkeypatch.setitem(engine._ON_APPROVED, "risk_acceptance", lambda session, request: None)
    monkeypatch.delitem(engine._DEDICATED_ROUTES, "risk_acceptance", raising=False)


class TestAScopedCredentialReads:
    @pytest.mark.parametrize("purpose", READERS)
    @pytest.mark.parametrize(
        "path",
        [
            "/api/approvals",
            "/api/approvals?state=pending",
            # The story's production check spells the filter `status`; the
            # route ignores an unknown parameter and still answers.
            "/api/approvals?status=pending",
            "/api/risk-acceptances",
            "/api/agents/whoami",
        ],
    )
    def test_with_no_perimeter_token(self, gated, purpose, path) -> None:
        token = _mint(gated, purpose)["token"]

        response = gated.get(path, headers=_alone(token))

        assert response.status_code == 200, response.text

    def test_one_approval_request_and_its_evidence(self, gated, tiered) -> None:
        champion = _mint(gated, "security-champion")["token"]
        author = _mint(gated, "author")["token"]
        made = _own_request(gated, {TOKEN_HEADER: GATE, **_alone(author)}, "acc-61954")
        rid = made["id"]

        for path in (f"/api/approvals/{rid}", f"/api/approvals/{rid}/evidence"):
            assert gated.get(path, headers=_alone(champion)).status_code == 200, path

    def test_as_a_viewer_so_raw_output_is_withheld(self, gated, run_compaction) -> None:
        """One secret now opens what took two, so the read is a viewer's: a
        Secrets finding's raw record quotes the context around the secret, and
        spec 12 §5 keeps it from anyone who is not admin or a full agent."""
        ingest = _alone(issue_token(gated, REPO, "sast"))
        assert post_scan(gated, ingest).status_code == 200
        found = post_findings(gated, ingest, [finding_payload(rule_id="R61954")])
        assert found.status_code == 200, found.text
        run_compaction()
        fid = str(
            gated.app.state.catalog.query(
                "SELECT finding_id FROM findings WHERE rule_id = ?", ["R61954"]
            )[0][0]
        )
        champion = _mint(gated, "security-champion")["token"]

        alone = gated.get(f"/api/dashboard/findings/{fid}", headers=_alone(champion))
        full = gated.get(
            f"/api/dashboard/findings/{fid}", headers={TOKEN_HEADER: GATE, **_alone(champion)}
        )

        assert alone.status_code == full.status_code == 200
        assert alone.json()["raw_finding_json"] is None
        assert full.json()["raw_finding_json"] is not None

    def test_whoami_says_viewer_alone_and_agent_with_the_perimeter_token(self, gated) -> None:
        token = _mint(gated, "delivery")["token"]

        alone = gated.get("/api/agents/whoami", headers=_alone(token)).json()
        full = gated.get("/api/agents/whoami", headers={TOKEN_HEADER: GATE, **_alone(token)})

        assert (alone["kind"], alone["role"]) == ("agent", "viewer")
        assert alone["provenance"]["purpose"] == "delivery"
        assert full.json()["role"] == "agent"


class TestEverythingElseIsA403:
    @pytest.mark.parametrize("purpose", READERS)
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "/api/approvals"),
            ("POST", "/api/approvals/x/decisions"),
            ("POST", "/api/approvals/x/decide"),
            ("POST", "/api/approvals/delegations"),
            ("PUT", "/api/approvals"),
            ("POST", "/api/risk-acceptances"),
            ("POST", "/api/risk-acceptances/x/revoke"),
            ("POST", "/api/risk-acceptances/x/interim-review"),
            ("PATCH", "/api/dashboard/findings/x/status"),
            ("DELETE", "/api/dashboard/triage/x/claim"),
            ("POST", "/api/agents/credentials"),
            ("POST", "/api/agents/credentials/x/revoke"),
            ("GET", "/api/agents/credentials"),
            ("GET", "/api/admin/anything"),
            ("GET", "/api/dashboard/portfolio"),
            ("GET", "/openapi.json"),
            ("HEAD", "/api/approvals"),
        ],
    )
    def test_any_write_admin_or_mint_route(self, gated, purpose, method, path) -> None:
        token = _mint(gated, purpose)["token"]

        response = gated.request(method, path, headers=_alone(token), json={})

        assert response.status_code == 403, response.text

    def test_the_pattern_is_anchored_and_refuses_traversal(self) -> None:
        from mykronos.gate import is_agent_readable

        assert is_agent_readable("GET", "/api/approvals")
        assert is_agent_readable("GET", "/api/approvals/abc/chain")
        assert is_agent_readable("GET", "/api/dashboard/repos/r1/open-findings")
        assert not is_agent_readable("POST", "/api/approvals")
        assert not is_agent_readable("GET", "/api/approvals/")
        assert not is_agent_readable("GET", "/api/approvals/abc/decisions/x")
        assert not is_agent_readable("GET", "/api/approvals-admin")
        assert not is_agent_readable("GET", "/api/approvals/../agents/credentials")
        assert not is_agent_readable("GET", "/api/dashboard/findings/x/record")
        assert not is_agent_readable("GET", "/api/dashboard/scan-runs/x/raw/out.sarif")


class TestEveryOtherCallerIsRefusedAsBefore:
    def test_a_credential_of_another_purpose(self, gated) -> None:
        token = _mint(gated, "author")["token"]

        response = gated.get("/api/approvals", headers=_alone(token))

        assert response.status_code == 401
        assert response.json() == REFUSED

    def test_a_purpose_named_by_an_agent_for_its_child(self, gated) -> None:
        """A purpose is free text chosen at mint, and an agent may mint a child
        with any purpose it likes; the approvals engine trusts one only on a
        credential a person minted, and so does this."""
        author = _mint(gated, "author")["token"]
        child = _mint(
            gated, "security-champion", minted_by={TOKEN_HEADER: GATE, **_alone(author)}
        )

        assert gated.get("/api/approvals", headers=_alone(child["token"])).status_code == 401

    @pytest.mark.parametrize("token", ["mka_not-a-real-one", ADMIN_TOKEN, VIEWER_TOKEN])
    def test_an_unknown_credential_or_the_operator_tokens(self, gated, token) -> None:
        response = gated.get("/api/approvals", headers=_alone(token))

        assert response.status_code == 401
        assert response.json() == REFUSED

    @pytest.mark.parametrize(
        "proxied", [{"Cf-Connecting-Ip": "203.0.113.9"}, {"X-Forwarded-For": "203.0.113.9"}]
    )
    def test_the_same_credential_through_the_tunnel(self, gated, proxied) -> None:
        """Cloudflare sets `Cf-Connecting-Ip` at the edge and a client cannot
        strip it, so the one-secret path is not on the internet: there the
        perimeter token is still wanted."""
        token = _mint(gated, "security-champion")["token"]

        response = gated.get("/api/approvals", headers={**_alone(token), **proxied})

        assert response.status_code == 401

    def test_a_wrong_perimeter_token_beside_it(self, gated) -> None:
        token = _mint(gated, "security-champion")["token"]

        wrong = {TOKEN_HEADER: "not-it", **_alone(token)}

        response = gated.get("/api/approvals", headers=wrong)

        assert response.status_code == 401


class TestEveryUseIsAudited:
    def test_a_read_names_the_actor_and_purpose(self, gated) -> None:
        minted = _mint(gated, "security-champion")

        gated.get("/api/approvals?state=pending", headers=_alone(minted["token"]))

        (entry,) = _audit(gated, "perimeter.agent_read")
        assert entry.actor == minted["actor"]
        assert entry.actor_kind == "agent"
        assert entry.detail["purpose"] == "security-champion"
        assert entry.detail["instance"] == minted["instance"]
        assert (entry.detail["method"], entry.detail["path"]) == ("GET", "/api/approvals")

    def test_a_refusal_too(self, gated) -> None:
        minted = _mint(gated, "delivery")

        gated.post("/api/approvals/x/decisions", headers=_alone(minted["token"]), json={})

        (entry,) = _audit(gated, "perimeter.agent_refused")
        assert entry.actor == minted["actor"]
        assert entry.detail["purpose"] == "delivery"
        assert entry.detail["method"] == "POST"
        assert entry.detail["path"] == "/api/approvals/x/decisions"

    def test_revoking_one_leaves_the_other_working(self, gated) -> None:
        champion = _mint(gated, "security-champion")
        delivery = _mint(gated, "delivery")

        revoked = gated.post(
            f"/api/agents/credentials/{champion['instance']}/revoke", headers=_operator()
        )

        assert revoked.status_code == 200, revoked.text
        assert gated.get("/api/approvals", headers=_alone(champion["token"])).status_code == 401
        assert gated.get("/api/approvals", headers=_alone(delivery["token"])).status_code == 200


class TestPersonOnlyActionsStayRefused:
    """Minting, approving and deciding an acceptance stay a person's, for every
    agent credential and on its own work."""

    @pytest.mark.parametrize("purpose", READERS)
    def test_on_its_own_work_alone(self, gated, tiered, purpose) -> None:
        token = _mint(gated, purpose)["token"]
        own = _own_request(gated, {TOKEN_HEADER: GATE, **_alone(token)}, f"acc-{purpose}")

        decided = gated.post(
            f"/api/approvals/{own['id']}/decisions", json=_approve(own), headers=_alone(token)
        )
        minted = gated.post(
            "/api/agents/credentials",
            json={"family": "x", "purpose": purpose},
            headers=_alone(token),
        )
        revoked = gated.post(
            "/api/risk-acceptances/x/revoke", json={"reason": "x"}, headers=_alone(token)
        )

        assert decided.status_code == 403
        assert minted.status_code == 403
        assert revoked.status_code == 403

    @pytest.mark.parametrize("purpose", [*READERS, "author"])
    def test_with_the_perimeter_token_as_well(self, gated, tiered, purpose) -> None:
        """Guard: the gate token never widened this. The routes a person alone
        may take refuse an agent behind it, and nobody decides their own."""
        token = _mint(gated, purpose)
        full = {TOKEN_HEADER: GATE, **_alone(token["token"])}
        own = _own_request(gated, full, f"acc-{purpose}")

        decided = gated.post(
            f"/api/approvals/{own['id']}/decisions", json=_approve(own), headers=full
        )
        unminted = gated.post(f"/api/agents/credentials/{token['instance']}/revoke", headers=full)
        revoked = gated.post("/api/risk-acceptances/x/revoke", json={"reason": "x"}, headers=full)

        assert decided.status_code == 409
        assert "the approver is the requester" in decided.json()["detail"]
        assert unminted.status_code == 403
        assert revoked.status_code == 403
