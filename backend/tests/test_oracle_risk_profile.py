"""The risk profile as an Oracle input — spec 21 §1.

Every other input Oracle reads is derived from what a scanner found. This one
is not: no scan can tell you whether an application is internet-facing or
handles regulated data, so an admin records it and Oracle reads it like any
other honestly-gated category.
"""

from __future__ import annotations

import pytest

from mykronos.config import get_settings
from mykronos.oracle import OracleEngine, load_policy
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard


@pytest.fixture
def policy():
    return load_policy(get_settings().oracle_policy_path)


def seed(client, run_compaction, findings: list[dict] | None = None):
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        findings or [finding_payload(rule_id="CWE-89", severity="high")],
        scan_run_id="run-1",
    )
    run_compaction()


def put_profile(client, admin_auth, repo_id: str, **fields):
    body = {
        "internet_facing": None,
        "data_classification": None,
        "business_criticality": None,
        "compliance_scope": [],
        "owner": None,
        "notes": None,
    }
    body.update(fields)
    return client.put(
        f"/api/repos/{repo_id}/risk-profile", json=body, headers=admin_auth
    )


class TestTheApi:
    def test_a_repo_with_no_profile_reports_that_rather_than_404(
        self, client, admin_auth
    ) -> None:
        """"Nobody has recorded one" is a real answer about the asset, not a
        missing resource."""
        repo_id = onboard(client, admin_auth).json()["id"]

        body = client.get(f"/api/repos/{repo_id}/risk-profile", headers=admin_auth).json()

        assert body["exists"] is False
        assert body["internet_facing"] is None

    def test_a_profile_round_trips(self, client, admin_auth) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        put_profile(
            client,
            admin_auth,
            repo_id,
            internet_facing=True,
            data_classification="regulated",
            business_criticality="critical",
            compliance_scope=["pci", "soc2"],
            owner="payments-team",
        )
        body = client.get(f"/api/repos/{repo_id}/risk-profile", headers=admin_auth).json()

        assert body["exists"] is True
        assert body["internet_facing"] is True
        assert body["data_classification"] == "regulated"
        assert sorted(body["compliance_scope"]) == ["pci", "soc2"]
        assert body["owner"] == "payments-team"

    def test_it_is_a_replace_not_a_patch(self, client, admin_auth) -> None:
        """spec 21 §1.3 — a profile is a complete statement, and a field left
        out of a later write is a field the writer is saying they no longer
        assert, not one they meant to keep."""
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, internet_facing=True, owner="team-a")

        put_profile(client, admin_auth, repo_id, data_classification="internal")

        body = client.get(f"/api/repos/{repo_id}/risk-profile", headers=admin_auth).json()
        assert body["internet_facing"] is None
        assert body["owner"] is None
        assert body["data_classification"] == "internal"

    def test_the_writer_is_recorded_from_the_caller(self, client, admin_auth) -> None:
        """Not accepted from the body — "who said this is internet-facing" is
        exactly the field nobody should fill in on somebody else's behalf."""
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, internet_facing=True)

        body = client.get(f"/api/repos/{repo_id}/risk-profile", headers=admin_auth).json()
        assert body["updated_by"]
        assert body["updated_at"] is not None

    def test_a_viewer_can_read_but_not_write(
        self, client, admin_auth, viewer_auth
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        assert (
            client.get(f"/api/repos/{repo_id}/risk-profile", headers=viewer_auth).status_code
            == 200
        )
        assert put_profile(client, viewer_auth, repo_id, internet_facing=True).status_code == 403

    def test_an_unknown_classification_is_refused(self, client, admin_auth) -> None:
        """Typed rather than free text: a typo'd "confidental" would silently
        score zero and read as an honest "we said public"."""
        repo_id = onboard(client, admin_auth).json()["id"]

        assert put_profile(
            client, admin_auth, repo_id, data_classification="confidental"
        ).status_code == 422

    def test_the_write_is_audited(self, client, admin_auth) -> None:
        from mykronos.db.models import AuditLogEntry

        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, internet_facing=True)

        with client.app.state.db.session() as session:
            actions = [row.action for row in session.query(AuditLogEntry).all()]
        assert "repo.risk_profile.set" in actions


class TestTheOracleInput:
    def test_no_profile_is_available_false(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        profile = decision.inputs_snapshot["risk_profile"]
        assert profile["available"] is False
        assert profile["contribution"] == 0.0

    def test_an_empty_profile_is_available_true(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        """Somebody opened the form and recorded that they do not know yet —
        an auditable state, and not the same as never having been asked."""
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id)
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        profile = decision.inputs_snapshot["risk_profile"]
        assert profile["available"] is True
        assert profile["contribution"] == 0.0

    def test_each_recorded_fact_is_its_own_term(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(
            client,
            admin_auth,
            repo_id,
            internet_facing=True,
            data_classification="regulated",
        )
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        keys = {t["key"] for t in decision.inputs_snapshot["terms"]}
        assert "risk_profile.internet_facing" in keys
        assert "risk_profile.data_classification" in keys
        expected = (
            policy.risk_profile.internet_facing_points
            + policy.risk_profile.data_classification_points["regulated"]
        )
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(expected)

    def test_compliance_scope_scores_per_regime(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        """Unbounded by design — an asset in three regimes carries three
        kinds of exposure, and a cap would hide the third."""
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, compliance_scope=["pci", "hipaa", "soc2"])
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        expected = policy.risk_profile.compliance_scope_points_per_entry * 3
        assert decision.inputs_snapshot["risk_profile"]["contribution"] == pytest.approx(expected)

    def test_a_recorded_profile_raises_the_score(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        seed(client, run_compaction)
        before = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        repo_id = client.get("/api/repos", headers=admin_auth).json()[0]["id"]
        put_profile(
            client, admin_auth, repo_id, internet_facing=True, business_criticality="critical"
        )
        after = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        assert after.overall_risk_score > before.overall_risk_score

    def test_the_reasoning_names_the_fact_not_just_the_total(
        self, catalog, policy, client, admin_auth, run_compaction
    ) -> None:
        """spec 21 §1.4 — an admin should see which asset fact moved the
        score, not a combined number they cannot re-derive."""
        repo_id = onboard(client, admin_auth).json()["id"]
        put_profile(client, admin_auth, repo_id, internet_facing=True)
        seed(client, run_compaction)

        decision = OracleEngine(catalog, policy, db=client.app.state.db).evaluate(REPO)

        assert "Internet-facing" in decision.reasoning

    def test_unavailable_when_no_db_is_wired_in(self, catalog, policy) -> None:
        """Same optional-dependency shape exploitability uses — a caller with
        no operational DB gets `unavailable`, not a crash."""
        decision = OracleEngine(catalog, policy).evaluate(REPO)
        assert decision.inputs_snapshot["risk_profile"]["available"] is False
