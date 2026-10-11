"""The Product Owner tab, phase 2 (spec 35 §7).

Reuses phase 1's fake TheHub and onboarding helpers, so a phase-2 test drives
the same endpoint the same way and differs only in what it declares.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx2
from fastapi.testclient import TestClient

from mykronos import product_owner as po
from mykronos.db.models import RepoGovernance
from mykronos.process_templates import TEMPLATES
from mykronos.schemas import utcnow
from tests.conftest import REPO, post_scan
from tests.test_product_owner import (  # noqa: F401 -- `connect` is a fixture
    VALID,
    FakeHub,
    audit_entries,
    connect,
    story,
)

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


# --------------------------------------------------------------------------
# 7.2 A template pull request (B-069)
# --------------------------------------------------------------------------


class TestTemplates:
    def test_every_template_is_a_valid_manifest_with_the_repo_tag(self) -> None:
        assert set(TEMPLATES) == {"keel", "thehub", "lightweight"}
        for template in TEMPLATES.values():
            state = po.parse_manifest(template.render("repo:payments-api"))
            assert state.state == "valid", (template.id, state.error)
            assert state.manifest is not None
            assert state.manifest.backlog.tag == "repo:payments-api"
        keel = po.parse_manifest(TEMPLATES["keel"].render("repo:x")).manifest
        assert keel is not None and [g.id for g in keel.gates][0] == "G0"

    def test_an_absent_manifest_is_offered_the_three_templates(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        body = product_owner(client, repo_id, admin_auth)
        assert [t["id"] for t in body["templates"]] == ["keel", "thehub", "lightweight"]

    def test_a_declared_process_is_offered_none(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=1)])
        assert product_owner(client, repo_id, admin_auth)["templates"] == []

    def test_choosing_one_opens_a_draft_pr_adding_only_the_manifest(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/template",
            json={"template": "lightweight"},
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["created"] is True
        assert body["branch"].startswith(po.TEMPLATE_BRANCH_PREFIX)

        repo = github.repos[REPO]
        (pr,) = repo.pull_requests
        assert pr.draft is True
        assert pr.number == body["pr_number"]
        # Nothing on the default branch; one new file on the PR branch.
        assert po.MANIFEST_PATH not in repo.branches["main"]
        added = set(repo.branches[body["branch"]]) - set(repo.branches["main"])
        assert added == {po.MANIFEST_PATH}
        manifest = po.parse_manifest(repo.branches[body["branch"]][po.MANIFEST_PATH])
        assert manifest.state == "valid" and manifest.manifest is not None
        assert manifest.manifest.backlog.tag == "repo:payments-api"

        (entry,) = audit_entries(client, "po.template_pr")
        assert entry.actor == "admin"
        assert entry.detail["outcome"] == "opened"
        assert entry.detail["template"] == "lightweight"
        assert entry.detail["pr_number"] == pr.number

    def test_an_open_template_pr_is_reused_not_duplicated(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        url = f"/api/dashboard/repos/{repo_id}/product-owner/template"
        first = client.post(url, json={"template": "keel"}, headers=admin_auth).json()
        second = client.post(url, json={"template": "thehub"}, headers=admin_auth).json()
        assert second["created"] is False
        assert second["pr_number"] == first["pr_number"]
        assert len(github.repos[REPO].pull_requests) == 1
        outcomes = [e.detail["outcome"] for e in audit_entries(client, "po.template_pr")]
        assert sorted(outcomes) == ["opened", "reused"]

    def test_a_viewer_is_refused(
        self,
        client: TestClient,
        viewer_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/template",
            json={"template": "keel"},
            headers=viewer_auth,
        )
        assert response.status_code == 403
        assert github.repos[REPO].pull_requests == []

    def test_a_repository_with_a_manifest_is_refused_and_audited(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
        github: Any,
    ) -> None:
        repo_id, _ = connect([story(id=1)])
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/template",
            json={"template": "keel"},
            headers=admin_auth,
        )
        assert response.status_code == 409
        assert "already declares" in response.json()["detail"]
        assert github.repos[REPO].pull_requests == []
        (entry,) = audit_entries(client, "po.template_pr")
        assert entry.detail["outcome"] == "refused_valid"

    def test_an_unknown_template_is_a_validation_error(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        repo_id, _ = connect([story(id=1)], manifest=None)
        response = client.post(
            f"/api/dashboard/repos/{repo_id}/product-owner/template",
            json={"template": "waterfall"},
            headers=admin_auth,
        )
        assert response.status_code == 422


# --------------------------------------------------------------------------
# 7.3 Definition of Done
# --------------------------------------------------------------------------

DOD = VALID.replace("  G2: building\n", "  G2: building\n  G5: done\n").replace(
    """backlog:
  source: thehub""",
    """  - id: G5
    name: Done
    story_gates: [verified]
definition_of_done:
  - id: committed
    text: A commit names the story
    evidence: commit
  - id: scanned
    text: That commit passed a scan
    evidence: scan_passed
  - id: deployed
    text: That commit was deployed
    evidence: deployed
  - id: demoed
    text: Shown to the Product Owner
backlog:
  source: thehub""",
)


class DeploysHub(FakeHub):
    """Phase 1's fake TheHub, answering the deploys read too."""

    def __init__(self, stories: list[dict[str, Any]], deploys: dict[int, Any]) -> None:
        super().__init__(stories)
        self.deploys = deploys

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        path = request.url.path
        if request.method == "GET" and path.endswith("/deploys"):
            self.calls.append((request.method, path, None))
            sid = int(path.split("/")[-2])
            answer = self.deploys.get(sid)
            if answer is None:
                return httpx2.Response(503, json={"detail": "busy"})
            return httpx2.Response(200, json={"story_id": sid, "deploys": answer, "count": 0})
        return super().handler(request)


def use_hub(client: TestClient, hub: FakeHub) -> None:
    client.app.state.hub = po.HubClient(  # type: ignore[attr-defined]
        "http://hub.test", "hub-secret", transport=httpx2.MockTransport(hub.handler)
    )


def done(**kwargs: Any) -> po.DoneEvidence:
    base: dict[str, Any] = {"commits": ["a91f2c7abcde"], "deployed": [], "scanned": []}
    base.update(kwargs)
    return po.DoneEvidence(**base)


class TestDefinitionOfDoneModel:
    def test_the_definition_of_done_parses(self) -> None:
        state = po.parse_manifest(DOD)
        assert state.state == "valid", state.error
        assert state.manifest is not None
        assert [i.evidence for i in state.manifest.definition_of_done] == [
            "commit",
            "scan_passed",
            "deployed",
            None,
        ]

    def test_an_unknown_dod_evidence_key_fails_validation_not_manual(self) -> None:
        state = po.parse_manifest(DOD.replace("evidence: deployed", "evidence: shipped"))
        assert state.state == "invalid"
        assert "definition_of_done" in (state.error or "")

    def test_each_evidence_key_passes_and_fails(self) -> None:
        check = po.check_dod_evidence
        assert check("commit", done()) == "passed"
        assert check("commit", done(commits=[])) == "failed"
        assert check("scan_passed", done(scanned=["a91f2c7"])) == "passed"
        assert check("scan_passed", done(scanned=["0000000"])) == "failed"
        assert check("scan_passed", done(commits=[], scanned=["a91f2c7"])) == "failed"
        assert check("deployed", done(deployed=["a91f2c7abcde"])) == "passed"
        assert check("deployed", done(deployed_revision="a91f2c7abcdef0123")) == "passed"
        assert check("deployed", done(deployed_revision="ffffffff")) == "failed"
        assert check(None, done()) == "manual"

    def test_what_the_hub_or_the_lake_could_not_say_is_unavailable(self) -> None:
        assert po.check_dod_evidence("commit", done(commits=None)) == "unavailable"
        assert po.check_dod_evidence("deployed", done(commits=None)) == "unavailable"
        assert po.check_dod_evidence("scan_passed", done(scanned=None)) == "unavailable"

    def test_a_short_sha_never_matches(self) -> None:
        assert not po.same_commit("a91f", "a91f2c7abcde")
        assert po.same_commit("A91F2C7", "a91f2c7abcde")

    def test_deploy_rows_give_commits_and_successful_deploys(self) -> None:
        commits, deployed = po.evidence_from_deploys(
            [
                {"sha": "a91f2c7abcde", "final_status": "failed"},
                {"sha": "a91f2c7abcde", "final_status": "success"},
                {"sha": "bbbbbbbbbbbb", "final_status": "aborted"},
                {"sha": None, "final_status": "success"},
            ]
        )
        assert commits == ["a91f2c7abcde", "bbbbbbbbbbbb"]
        assert deployed == ["a91f2c7abcde"]
        assert po.evidence_from_deploys(None) == (None, [])


class TestDefinitionOfDoneInTheTab:
    def test_a_done_story_with_failing_dod_needs_a_human(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        stories = [
            story(id=5, bucket="sprint", gate="verified", title="Shipped one"),
            story(id=6, bucket="sprint", gate="verified", title="Never committed"),
            story(id=7, bucket="sprint", gate="in_progress"),
        ]
        repo_id, _ = connect(stories, manifest=DOD)
        hub = DeploysHub(
            stories, {5: [{"sha": "a91f2c7abcde", "final_status": "success"}], 6: []}
        )
        use_hub(client, hub)

        body = product_owner(client, repo_id, admin_auth)

        by_id = {s["id"]: s for s in body["sprint"]}
        five = {i["id"]: i["status"] for i in by_id[5]["dod"]["items"]}
        # No scan run in the lake for that commit: scanned fails, the rest pass.
        assert five == {
            "committed": "passed",
            "scanned": "failed",
            "deployed": "passed",
            "demoed": "manual",
        }
        assert by_id[6]["dod"]["failed"] == 3
        assert by_id[7]["dod"] is None
        failing = {n["story_id"] for n in body["needs_human"] if n["kind"] == "dod_failed"}
        assert failing == {5, 6}
        # Only done stories were asked about.
        asked = {p for _, p, _ in hub.calls if p.endswith("/deploys")}
        assert asked == {"/api/dev/stories/5/deploys", "/api/dev/stories/6/deploys"}

    def test_a_scanned_and_deployed_story_passes(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        auth: dict[str, str],
        run_compaction: Any,
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        post_scan(client, auth, commit_sha="a91f2c7")
        run_compaction()
        stories = [story(id=5, bucket="sprint", gate="verified")]
        repo_id, _ = connect(stories, manifest=DOD)
        use_hub(
            client,
            DeploysHub(stories, {5: [{"sha": "a91f2c7abcde", "final_status": "success"}]}),
        )

        body = product_owner(client, repo_id, admin_auth)

        dod = body["sprint"][0]["dod"]
        assert (dod["passed"], dod["failed"], dod["manual"]) == (3, 0, 1)
        assert not [n for n in body["needs_human"] if n["kind"] == "dod_failed"]

    def test_when_the_hub_cannot_say_nothing_is_failed(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        connect: Callable[..., Any],  # noqa: F811
    ) -> None:
        stories = [story(id=5, bucket="sprint", gate="verified")]
        repo_id, _ = connect(stories, manifest=DOD)
        use_hub(client, DeploysHub(stories, {}))

        body = product_owner(client, repo_id, admin_auth)

        assert body["sprint"][0]["dod"]["unavailable"] == 3
        assert not [n for n in body["needs_human"] if n["kind"] == "dod_failed"]
