"""The investigation dossier and model proposals in shadow (TheHub #60893)."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from mykronos import dossier, shadow_proposals
from mykronos.db.models import ApprovalRequest, AuditLogEntry, RepoOnboarding
from tests.test_dashboard import outstanding  # noqa: F401  (fixture)
from tests.test_environmental_view import _ids, _page

MODEL = "claude-test-model-2026-10-01"


@pytest.fixture
def estate(client: TestClient, admin_auth: dict[str, str], outstanding):  # noqa: F811
    """`outstanding`, active, with the finding ids by (rule, file) for CWE-79."""
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        for row in session.scalars(select(RepoOnboarding)):
            row.status = "active"
    page = _page(client, admin_auth, outstanding)
    xss = {
        loc["file_path"]: loc["finding_id"]
        for g in page["groups"]
        if g["rule_id"] == "CWE-79"
        for loc in g["locations"]
    }
    return SimpleNamespace(repo_id=outstanding, ids=_ids(page), xss=xss)


def _dossier(client: TestClient, auth: dict[str, str], finding_id: str) -> dict[str, Any]:
    response = client.get(f"/api/dashboard/findings/{finding_id}/dossier", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()


def _propose(
    client: TestClient, auth: dict[str, str], finding_id: str, status: str = "false_positive"
) -> Any:
    return client.post(
        f"/api/dashboard/findings/{finding_id}/model-proposals",
        json={
            "proposed_status": status,
            "rationale": "The value is escaped by the template engine before output.",
            "model": MODEL,
            "confidence": 0.8,
            "evidence": {"read": ["web/a.py:1-40"]},
        },
        headers=auth,
    )


def _dispose(
    client: TestClient, auth: dict[str, str], finding_id: str, status: str, reason: str
) -> None:
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": status, "reason": reason},
        headers=auth,
    )
    assert response.status_code == 200, response.text


class TestDossier:
    def test_location_owner_history_and_cluster(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        finding_id = estate.xss["web/a.py"]
        got = _dossier(client, admin_auth, finding_id)

        assert got["location"]["file_path"] == "web/a.py"
        assert got["location"]["symbol"] == "a"
        assert "owner_source" in got["owner"]
        assert [e["event"] for e in got["history"]][:1] == ["first seen"]
        assert got["cluster"] is not None
        assert finding_id in got["cluster"]["member_ids"]
        assert got["cluster"]["reason"]
        assert got["proposals"] == [] and got["proposals_mode"] == "shadow"

    def test_similar_past_dispositions_carry_the_reason_and_who(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        _dispose(
            client, admin_auth, estate.xss["web/b.py"], "false_positive", "escaped by Jinja"
        )

        got = _dossier(client, admin_auth, estate.xss["web/a.py"])

        [precedent] = got["similar_dispositions"]
        assert precedent["finding_id"] == estate.xss["web/b.py"]
        assert precedent["status"] == "false_positive"
        assert precedent["reason"] == "escaped by Jinja"
        assert precedent["decided_by"]
        # The disposition is on the finding's own history too.
        mine = _dossier(client, admin_auth, estate.xss["web/b.py"])
        assert any(e["event"] == "finding.status" for e in mine["history"])

    def test_a_precedent_links_to_its_own_repository(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        """The record page's route takes the precedent's repository id, not
        the current page's (review of #1006)."""
        _dispose(
            client, admin_auth, estate.xss["web/b.py"], "false_positive", "escaped by Jinja"
        )

        [precedent] = _dossier(client, admin_auth, estate.xss["web/a.py"])["similar_dispositions"]

        assert precedent["repo_id"] == estate.repo_id

    def test_history_keeps_the_newest_entries(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        """A long history is cut from the old end: the latest decision is the
        one an investigator needs (review of #1006)."""
        finding_id = estate.xss["web/a.py"]
        start = datetime(2026, 1, 1)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            for n in range(dossier.HISTORY_LISTED + 5):
                session.add(
                    AuditLogEntry(
                        actor="admin",
                        action=f"test.event-{n:03d}",
                        entity_type="finding",
                        entity_id=finding_id,
                        detail={},
                        created_at=start + timedelta(hours=n),
                    )
                )

        events = [e["event"] for e in _dossier(client, admin_auth, finding_id)["history"]]

        assert f"test.event-{dossier.HISTORY_LISTED + 4:03d}" in events
        assert "test.event-000" not in events

    def test_a_viewer_can_read_it(
        self, client: TestClient, viewer_auth: dict[str, str], estate
    ) -> None:
        assert _dossier(client, viewer_auth, estate.xss["web/a.py"])["finding_id"]

    def test_an_unknown_finding_is_404(self, client: TestClient, admin_auth, estate) -> None:
        response = client.get("/api/dashboard/findings/nope/dossier", headers=admin_auth)
        assert response.status_code == 404


class TestProposalsAreNeverApplied:
    def test_a_proposal_is_recorded_and_changes_nothing(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        finding_id = estate.xss["web/a.py"]

        response = _propose(client, admin_auth, finding_id)

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["applied"] is False and body["grade"] == "pending"
        got = _dossier(client, admin_auth, finding_id)
        assert got["status"] == "open"
        [shown] = got["proposals"]
        assert (shown["model"], shown["proposed_status"]) == (MODEL, "false_positive")
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.scalar(select(func.count()).select_from(ApprovalRequest)) == 0
            actions = [
                e.action
                for e in session.scalars(
                    select(AuditLogEntry).where(AuditLogEntry.entity_id == finding_id)
                )
            ]
        assert actions == ["finding.model_proposal"]

    def test_a_viewer_cannot_record_one(
        self, client: TestClient, viewer_auth: dict[str, str], estate
    ) -> None:
        assert _propose(client, viewer_auth, estate.xss["web/a.py"]).status_code == 403

    def test_an_unknown_verdict_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        response = _propose(client, admin_auth, estate.xss["web/a.py"], status="fixed")
        assert response.status_code == 422


class TestProposalEvidenceIsBounded:
    def test_an_oversized_evidence_object_is_refused(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        response = client.post(
            f"/api/dashboard/findings/{estate.xss['web/a.py']}/model-proposals",
            json={
                "proposed_status": "false_positive",
                "rationale": "escaped",
                "model": MODEL,
                "evidence": {"read": ["x" * 1000] * 100},
            },
            headers=admin_auth,
        )
        assert response.status_code == 422


class TestSimilarQuery:
    def test_an_empty_rule_id_is_not_matched_against_other_empty_rule_ids(self) -> None:
        """A CVE named only in the title must not add `rule_id = ''`, which
        matches every disposed finding that has no rule id (review of #1006)."""
        seen: list[tuple[str, list[Any]]] = []

        class Catalog:
            def query(self, sql: str, params: list[Any]) -> list[Any]:
                seen.append((sql, params))
                return []

        dossier.similar(
            Catalog(),
            None,  # type: ignore[arg-type]
            {"finding_id": "f1", "rule_id": "", "title": "openssl CVE-2014-0160"},
        )

        [(sql, params)] = seen
        assert "rule_id = ?" not in sql
        assert "" not in params


class TestGrading:
    def test_proposals_are_graded_against_the_later_human_verdict(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        right, wrong, open_ = (estate.xss[f"web/{n}.py"] for n in ("a", "b", "c"))
        assert _propose(client, admin_auth, right, "false_positive").status_code == 201
        assert _propose(client, admin_auth, wrong, "false_positive").status_code == 201
        assert _propose(client, admin_auth, open_, "true_positive").status_code == 201
        _dispose(client, admin_auth, right, "false_positive", "escaped")
        _dispose(client, admin_auth, wrong, "suppressed", "test fixture only")

        response = client.get(
            "/api/dashboard/triage/model-proposals/grade", headers=admin_auth
        )
        assert response.status_code == 200, response.text
        report = response.json()

        assert report["applied"] == 0 and report["mode"] == "shadow"
        [model] = report["models"]
        assert model["model"] == MODEL
        assert (model["agree"], model["disagree"], model["pending"]) == (1, 1, 1)
        assert model["agreement_rate"] == 0.5
        assert model["pairs"] == {
            "false_positive -> false_positive": 1,
            "false_positive -> suppressed": 1,
        }
        graded = _dossier(client, admin_auth, right)["proposals"][0]
        assert (graded["grade"], graded["human_verdict"]) == ("agree", "false_positive")

    def test_a_proposal_made_after_the_verdict_is_ineligible(
        self, client: TestClient, admin_auth: dict[str, str], estate
    ) -> None:
        finding_id = estate.xss["web/a.py"]
        _dispose(client, admin_auth, finding_id, "false_positive", "escaped")
        assert _propose(client, admin_auth, finding_id).status_code == 201

        [model] = client.get(
            "/api/dashboard/triage/model-proposals/grade", headers=admin_auth
        ).json()["models"]
        assert (model["ineligible"], model["graded"]) == (1, 0)
        assert model["agreement_rate"] is None


class TestGradeOne:
    T0 = datetime(2026, 10, 1)

    def _p(self, status: str) -> Any:
        return SimpleNamespace(proposed_status=status, created_at=self.T0)

    def test_a_fix_observed_later_confirms_true_positive(self) -> None:
        got = shadow_proposals.grade_one(
            self._p("true_positive"), [], self.T0 + timedelta(days=2)
        )
        assert (got["grade"], got["human_verdict"]) == ("agree", "fixed")

    def test_agent_verdicts_are_not_graders(self) -> None:
        # human_verdicts filters on actor_kind; with none, the grade waits.
        assert shadow_proposals.grade_one(self._p("false_positive"), [], None)["grade"] == (
            "pending"
        )

    def test_the_latest_proposal_per_model_is_the_one_graded(self) -> None:
        old = SimpleNamespace(finding_id="f", model="m", created_at=self.T0, id="1")
        new = SimpleNamespace(
            finding_id="f", model="m", created_at=self.T0 + timedelta(hours=1), id="2"
        )
        other = SimpleNamespace(finding_id="f", model="n", created_at=self.T0, id="3")
        assert [p.id for p in shadow_proposals.latest([old, new, other])] == ["3", "2"]
