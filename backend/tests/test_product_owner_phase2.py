"""The Product Owner tab, phase 2 (spec 35 §7).

Reuses phase 1's fake TheHub and onboarding helpers, so a phase-2 test drives
the same endpoint the same way and differs only in what it declares.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import product_owner as po
from mykronos.db.models import RepoGovernance
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_product_owner import VALID, connect, story  # noqa: F401 -- `connect` is a fixture

# --------------------------------------------------------------------------
# 7.1 Declared versus observed (B-070)
# --------------------------------------------------------------------------

DECLARES = (
    VALID
    + """
branch_controls:
  required_review: true
  required_checks: true
  owner: Platform admins
"""
).replace(
    """  - id: G2
    name: Building""",
    """  - id: G2
    name: Building
    approves: Delivery Lead
    enforced_by:
      file: .env.example
      key: ENFORCE_BUILD_GATE""",
)


def store_governance(client: TestClient, states: dict[str, str], *, age_days: int = 0) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.merge(
            RepoGovernance(
                repo_full_name=REPO,
                governance_score=40,
                source="branch_protection",
                controls_read=len(states),
                control_states=states,
                read_at=utcnow() - timedelta(days=age_days),
            )
        )
        session.commit()


def product_owner(client: TestClient, repo_id: str, auth: dict[str, str]) -> dict[str, Any]:
    response = client.get(f"/api/dashboard/repos/{repo_id}/product-owner", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


class TestDriftModel:
    def test_the_declarations_parse_and_an_unknown_one_is_refused(self) -> None:
        state = po.parse_manifest(DECLARES)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        assert state.manifest.branch_controls is not None
        assert state.manifest.branch_controls.required_review is True
        assert state.manifest.gates[1].enforced_by is not None

        typo = po.parse_manifest(DECLARES.replace("required_checks:", "required_chekcs:"))
        assert typo.state == "invalid"
        assert "required_chekcs" in (typo.error or "")

    def test_required_review_without_protection_is_a_finding_naming_both(self) -> None:
        manifest = po.parse_manifest(DECLARES).manifest
        (review, checks) = po.branch_control_observations(
            manifest,
            "main",
            {"approving_reviews_required": "off", "required_status_checks": "on"},
        )
        assert review.status == "drift"
        assert review.declared == "required_review: true"
        assert review.observed == "approving_reviews_required: off"
        assert "manifest declares" in review.detail and "branch protection" in review.detail
        assert review.owner == "Platform admins"
        assert checks.status == "consistent"

    def test_one_approval_satisfies_a_required_review_declaration(self) -> None:
        manifest = po.parse_manifest(DECLARES).manifest
        review = po.branch_control_observations(
            manifest, "main", {"approving_reviews_required": "partial"}
        )[0]
        assert review.status == "consistent"

    def test_no_reading_is_unobserved_not_consistent(self) -> None:
        manifest = po.parse_manifest(DECLARES).manifest
        for states in (None, {"approving_reviews_required": "unknown"}, {}):
            review = po.branch_control_observations(manifest, "main", states)[0]
            assert review.status == "unobserved", states

    def test_a_declared_gate_switched_off_in_config_is_a_finding(self) -> None:
        manifest = po.parse_manifest(DECLARES).manifest
        (gate,) = po.gate_switch_observations(
            manifest, {".env.example": "# flags\nENFORCE_BUILD_GATE=false  # dark\n"}
        )
        assert gate.status == "drift"
        assert gate.kind == "gate_switch"
        assert "ENFORCE_BUILD_GATE" in gate.observed
        assert gate.owner == "Delivery Lead"

    def test_a_switch_on_is_consistent_and_a_missing_one_unobserved(self) -> None:
        manifest = po.parse_manifest(DECLARES).manifest
        on = po.gate_switch_observations(manifest, {".env.example": 'ENFORCE_BUILD_GATE="true"'})
        assert on[0].status == "consistent"
        absent_key = po.gate_switch_observations(manifest, {".env.example": "OTHER=1"})
        assert absent_key[0].status == "unobserved"
        absent_file = po.gate_switch_observations(manifest, {".env.example": None})
        assert absent_file[0].status == "unobserved"

    def test_a_yaml_switch_is_read_by_dotted_path(self) -> None:
        assert po.read_switch("gates:\n  build: false\n", "cfg.yaml", "gates.build") == "false"
        assert po.read_switch("gates:\n  build: true\n", "cfg.yml", "gates.missing") is None


class TestDriftInTheTab:
    def test_drift_needs_a_human_with_an_owner(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=DECLARES)
        github.repos[REPO].branches["main"][".env.example"] = "ENFORCE_BUILD_GATE=false\n"
        store_governance(
            client, {"approving_reviews_required": "off", "required_status_checks": "off"}
        )

        body = product_owner(client, repo_id, admin_auth)

        drift = [n for n in body["needs_human"] if n["kind"] == "process_drift"]
        assert {n["owner"] for n in drift} == {"Platform admins", "Delivery Lead"}
        assert len(drift) == 3
        statuses = {o["id"]: o["status"] for o in body["observations"]}
        assert statuses == {
            "branch:required_review": "drift",
            "branch:required_checks": "drift",
            "gate:G2": "drift",
        }

    def test_a_stale_reading_is_unobserved_and_needs_nobody(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=DECLARES)
        github.repos[REPO].branches["main"][".env.example"] = "ENFORCE_BUILD_GATE=true\n"
        store_governance(client, {"approving_reviews_required": "off"}, age_days=30)

        body = product_owner(client, repo_id, admin_auth)

        assert not [n for n in body["needs_human"] if n["kind"] == "process_drift"]
        by_id = {o["id"]: o for o in body["observations"]}
        assert by_id["branch:required_review"]["status"] == "unobserved"
        assert "older than" in by_id["branch:required_review"]["detail"]
        assert by_id["gate:G2"]["status"] == "consistent"

    def test_a_manifest_that_declares_nothing_observes_nothing(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=1)])
        store_governance(client, {"approving_reviews_required": "off"})
        assert product_owner(client, repo_id, admin_auth)["observations"] == []
