"""Oracle API, Check Runs and the gate template — spec 09 §6, §7, §8."""

from __future__ import annotations

import json

import pytest
import yaml
from fastapi.testclient import TestClient

from mykronos.config import get_settings
from mykronos.db.models import AuditLogEntry, CapabilityConfig
from mykronos.installer import TemplateLibrary
from mykronos.oracle.service import render_check_run_summary
from tests.conftest import (
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
    render_context,
)
from tests.test_onboarding import onboard


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    """A repo token with the oracle grant — what the gate workflow presents."""
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


@pytest.fixture
def seeded(client: TestClient, admin_auth, oracle_auth, run_compaction):
    """One onboarded repo with two open criticals in the lake."""
    repo_id = onboard(client, admin_auth).json()["id"]
    post_scan(client, oracle_auth, scan_run_id="run-1")
    post_findings(
        client,
        oracle_auth,
        [
            finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
            finding_payload(rule_id="CWE-78", severity="critical", symbol="b"),
        ],
        scan_run_id="run-1",
    )
    run_compaction()
    return repo_id


def evaluate(client, auth, **body):
    payload = {"decision_type": "pr_gate", "commit_sha": "a91f2c7", "pr_number": 2841}
    payload.update(body)
    return client.post("/api/oracle/evaluate", json=payload, headers=auth)


class TestEvaluate:
    def test_produces_a_decision(self, client, oracle_auth, seeded) -> None:
        body = evaluate(client, oracle_auth).json()

        assert body["overall_risk_score"] == 63  # 40 × log2(3)
        assert body["recommendation"] == "review_recommended"
        assert body["policy_version"] == "1.3"

    def test_the_repo_comes_from_the_token(self, client, oracle_auth, seeded) -> None:
        """There is no repo field in the request, so a workflow cannot ask for
        a decision about somebody else's repository."""
        response = evaluate(client, oracle_auth, repo_full_name="someone/else")
        assert response.status_code == 422

    def test_the_oracle_grant_is_required(self, client, seeded, run_compaction) -> None:
        """A repo that has not enabled Oracle cannot ask it for a decision.

        Deliberately a *different* repo. Grants are per-repo, not per-token
        (D-009), so issuing a second token for the same repo would still carry
        every grant that repo has — which is the model working, not a gap.
        """
        other = "example-org/ledger-core"
        sast_only = {"Authorization": f"Bearer {issue_token(client, other, 'sast')}"}

        response = evaluate(client, sast_only)

        assert response.status_code == 403
        assert "not enabled" in response.json()["detail"]
        assert other in response.json()["detail"]

    def test_an_unauthenticated_call_is_refused(self, client, seeded) -> None:
        assert client.post("/api/oracle/evaluate", json={}).status_code == 401

    def test_the_decision_is_persisted(
        self, client, oracle_auth, admin_auth, seeded, run_compaction, catalog
    ) -> None:
        decision_id = evaluate(client, oracle_auth).json()["decision_id"]
        run_compaction()

        rows = catalog.query(
            "SELECT decision_id, recommendation, policy_version FROM risk_decisions"
        )
        assert rows == [(decision_id, "review_recommended", "1.3")]

    def test_re_evaluating_creates_a_new_decision(
        self, client, oracle_auth, seeded, run_compaction, catalog
    ) -> None:
        """spec 09 §10: decisions are immutable, so history shows both."""
        first = evaluate(client, oracle_auth).json()["decision_id"]
        second = evaluate(client, oracle_auth).json()["decision_id"]
        run_compaction()

        assert first != second
        assert catalog.count("risk_decisions") == 2

    def test_a_clean_repo_still_gets_a_decision(
        self, client, oracle_auth, admin_auth, run_compaction
    ) -> None:
        """spec 09 §10: a real 'go', not an absence of one."""
        onboard(client, admin_auth)
        post_scan(client, oracle_auth, scan_run_id="clean")
        post_findings(client, oracle_auth, [], scan_run_id="clean")
        run_compaction()

        body = evaluate(client, oracle_auth).json()
        assert body["recommendation"] == "go"
        assert body["overall_risk_score"] == 0


class TestCheckRuns:
    def test_a_check_run_is_posted(self, client, oracle_auth, seeded, github) -> None:
        body = evaluate(client, oracle_auth).json()

        assert body["check_run_id"]
        run = github.repos[REPO].check_runs[-1]
        assert run["head_sha"] == "a91f2c7"
        assert "63/100" in run["title"]

    def test_advisory_by_default_means_neutral_not_failure(
        self, client, oracle_auth, admin_auth, run_compaction, github
    ) -> None:
        """spec 09 §6. A red check nobody agreed to is how a security tool
        gets switched off in its first week."""
        onboard(client, admin_auth)
        post_scan(client, oracle_auth, scan_run_id="bad")
        post_findings(
            client,
            oracle_auth,
            [
                finding_payload(rule_id=f"R{i}", severity="critical", symbol=f"s{i}")
                for i in range(6)
            ],
            scan_run_id="bad",
        )
        run_compaction()

        body = evaluate(client, oracle_auth).json()

        assert body["recommendation"] == "no_go"
        assert body["blocking"] is False
        assert github.repos[REPO].check_runs[-1]["conclusion"] == "neutral"

    def test_blocking_turns_a_no_go_into_a_failure(
        self, client, oracle_auth, admin_auth, run_compaction, github
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        with client.app.state.db.session() as session:
            session.add(
                CapabilityConfig(
                    repo_onboarding_id=repo_id,
                    capability="oracle",
                    config_json={"blocking": True},
                )
            )

        post_scan(client, oracle_auth, scan_run_id="bad")
        post_findings(
            client,
            oracle_auth,
            [
                finding_payload(rule_id=f"R{i}", severity="critical", symbol=f"s{i}")
                for i in range(6)
            ],
            scan_run_id="bad",
        )
        run_compaction()

        body = evaluate(client, oracle_auth).json()

        assert body["blocking"] is True
        assert github.repos[REPO].check_runs[-1]["conclusion"] == "failure"

    def test_a_failed_check_run_does_not_lose_the_decision(
        self, client, oracle_auth, seeded, github, run_compaction, catalog
    ) -> None:
        """The decision is the record; the Check Run is how it is displayed.
        A scan that scored fine must not fail because GitHub had a bad minute."""
        github.permissions.pop("checks")

        body = evaluate(client, oracle_auth).json()
        run_compaction()

        assert body["check_run_id"] is None
        assert body["check_run_error"]
        assert catalog.count("risk_decisions") == 1

    def test_the_summary_shows_its_working(self, client, oracle_auth, seeded, github) -> None:
        """A score you cannot check is one people eventually stop believing."""
        evaluate(client, oracle_auth)
        summary = github.repos[REPO].check_runs[-1]["summary"]

        assert "How this score was reached" in summary
        assert "log2(1 + 2)" in summary
        assert "Not yet consulted" in summary
        assert "Advisory only" in summary

    def test_the_summary_declares_when_it_blocks(self, client, oracle_auth, seeded) -> None:
        from mykronos.oracle import OracleEngine, load_policy

        engine = OracleEngine(
            client.app.state.catalog, load_policy(get_settings().oracle_policy_path)
        )
        decision = engine.evaluate(REPO, decision_type="pr_gate", commit_sha="x")

        assert "blocking for this repository" in render_check_run_summary(
            decision, blocking=True
        )


class TestOverride:
    def _decision_id(self, client, oracle_auth, run_compaction) -> str:
        decision_id = evaluate(client, oracle_auth).json()["decision_id"]
        run_compaction()
        return str(decision_id)

    def test_an_override_requires_a_reason(
        self, client, oracle_auth, admin_auth, seeded, run_compaction
    ) -> None:
        """spec 09 §9. An override without one throws away the single most
        valuable retro signal in the system."""
        decision_id = self._decision_id(client, oracle_auth, run_compaction)

        response = client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": ""},
            headers=admin_auth,
        )
        assert response.status_code == 422

    def test_an_override_is_recorded_alongside_the_decision(
        self, client, oracle_auth, admin_auth, seeded, run_compaction, catalog
    ) -> None:
        decision_id = self._decision_id(client, oracle_auth, run_compaction)

        response = client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={
                "reason": "Both criticals are in a vendored fixture.",
                "accepted_recommendation": "go",
            },
            headers=admin_auth,
        )
        run_compaction()

        assert response.status_code == 200
        score, recommendation, override = catalog.query(
            "SELECT overall_risk_score, recommendation, human_override "
            "FROM risk_decisions WHERE decision_id = ?",
            [decision_id],
        )[0]

        # The decision itself is untouched — spec 09 §10 needs it reproducible.
        assert score == 63
        assert recommendation == "review_recommended"
        assert json.loads(override)["reason"].startswith("Both criticals")

    def test_overriding_twice_is_refused(
        self, client, oracle_auth, admin_auth, seeded, run_compaction
    ) -> None:
        """Overrides are append-only history, not a field to edit."""
        decision_id = self._decision_id(client, oracle_auth, run_compaction)
        body = {"reason": "first"}

        client.post(
            f"/api/oracle/decisions/{decision_id}/override", json=body, headers=admin_auth
        )
        run_compaction()
        second = client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "second"},
            headers=admin_auth,
        )

        assert second.status_code == 409

    def test_viewers_cannot_override(
        self, client, oracle_auth, viewer_auth, seeded, run_compaction
    ) -> None:
        decision_id = self._decision_id(client, oracle_auth, run_compaction)
        response = client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "nope"},
            headers=viewer_auth,
        )
        assert response.status_code == 403

    def test_the_override_is_audited(
        self, client, oracle_auth, admin_auth, seeded, run_compaction
    ) -> None:
        decision_id = self._decision_id(client, oracle_auth, run_compaction)
        client.post(
            f"/api/oracle/decisions/{decision_id}/override",
            json={"reason": "vendored fixture"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            entry = (
                session.query(AuditLogEntry)
                .filter(AuditLogEntry.action == "oracle.override")
                .one()
            )
        assert entry.detail["reason"] == "vendored fixture"
        assert entry.detail["original"] == "review_recommended"

    def test_an_unknown_decision_is_404(self, client, admin_auth, seeded) -> None:
        assert (
            client.post(
                "/api/oracle/decisions/nope/override",
                json={"reason": "x"},
                headers=admin_auth,
            ).status_code
            == 404
        )


class TestPolicyEndpoint:
    def test_the_active_policy_is_readable(self, client, admin_auth) -> None:
        body = client.get("/api/oracle/policy", headers=admin_auth).json()
        assert body["version"] == "1.3"
        assert body["source"]["findings"]["weights"]["critical"] == 40

    def test_viewers_can_read_the_policy(self, client, viewer_auth) -> None:
        """spec 09 §7 transparency: anyone Oracle judges is entitled to see
        how the number was produced."""
        assert client.get("/api/oracle/policy", headers=viewer_auth).status_code == 200

    def test_it_needs_authentication(self, client) -> None:
        assert client.get("/api/oracle/policy").status_code == 401


class TestDecisionHistory:
    def test_lists_decisions_newest_first(
        self, client, oracle_auth, admin_auth, seeded, run_compaction
    ) -> None:
        evaluate(client, oracle_auth, commit_sha="aaa")
        evaluate(client, oracle_auth, commit_sha="bbb")
        run_compaction()

        body = client.get(f"/api/oracle/decisions/{seeded}", headers=admin_auth).json()

        assert len(body["decisions"]) == 2
        assert body["decisions"][0]["inputs_snapshot"]["totals"]["raw_score"] > 0

    def test_filters_by_decision_type(
        self, client, oracle_auth, admin_auth, seeded, run_compaction
    ) -> None:
        evaluate(client, oracle_auth, decision_type="pr_gate")
        evaluate(client, oracle_auth, decision_type="portfolio", pr_number=None)
        run_compaction()

        body = client.get(
            f"/api/oracle/decisions/{seeded}",
            params={"decision_type": "portfolio"},
            headers=admin_auth,
        ).json()
        assert len(body["decisions"]) == 1

    def test_an_unknown_repo_is_404(self, client, admin_auth) -> None:
        assert (
            client.get("/api/oracle/decisions/nope", headers=admin_auth).status_code == 404
        )


class TestGateTemplate:
    @pytest.fixture
    def library(self) -> TemplateLibrary:
        return TemplateLibrary(get_settings().workflow_templates_dir)

    def render(self, library, depends_on):
        return library.render(
            "oracle", **render_context(gate_depends_on=depends_on)
        ).content

    def test_it_waits_on_the_scanners(self, library) -> None:
        """spec 09 §8: deciding before the scans land would score a commit
        against an empty lake."""
        content = self.render(library, ["Mykronos sast", "Mykronos secrets"])
        triggers = yaml.safe_load(content).get("on") or yaml.safe_load(content)[True]

        assert triggers["workflow_run"]["workflows"] == [
            "Mykronos sast",
            "Mykronos secrets",
        ]

    def test_it_can_post_a_check_run(self, library) -> None:
        content = self.render(library, ["Mykronos sast"])
        assert yaml.safe_load(content)["permissions"]["checks"] == "write"

    def test_it_contains_no_heredoc(self, library) -> None:
        """Jinja's variable delimiter here is `<<`, so `cat <<JSON` fails to
        compile. This guards the whole template directory against the next
        person reaching for one."""
        for capability in library.available:
            content = library.render(capability, **render_context()).content
            assert "<<" not in content, f"{capability} rendered an unresolved << delimiter"

    def test_every_template_compiles_and_is_valid_yaml(self, library) -> None:
        """Cheap, and it catches the whole class of mistake that only shows up
        when a repo's install PR merges and the workflow refuses to start."""
        for capability in library.available:
            content = library.render(capability, **render_context()).content
            parsed = yaml.safe_load(content)

            assert parsed.get("jobs"), f"{capability} has no jobs"
            # YAML 1.1 parses a bare `on:` as the boolean True, which is why
            # this checks both spellings rather than the obvious one.
            assert "on" in parsed or True in parsed, f"{capability} has no triggers"
