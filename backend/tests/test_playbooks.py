"""Agent playbooks as data (spec 36 §5).

The playbooks move how-to knowledge out of one agent's memory file and into a
reviewed file. That is only worth doing if the file stays true, so these tests
hold it to the code: one playbook per kind the queue can emit, and every route
a playbook names exists in the app. The second test is the one that keeps the
playbooks honest as the API changes: rename a route and it fails here, naming
the playbook and step that still send an agent to the old one.
"""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi import FastAPI

from mykronos import agent_work, playbooks
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.briefing import (
    Briefing,
    FailingLane,
    PausedLane,
    StalledLane,
    TokenDelivery,
)
from mykronos.config import Settings
from tests.conftest import post_scan

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = ROOT / "agent-playbooks-v1.yaml"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
REPO = "acme/api"
REPO_ID = "0b1377ac-0000-0000-0000-000000000001"
AGENT = Principal(actor="agent:claude-opus-5.5:abc", role=Role.AGENT, kind=ActorKind.AGENT)


def _document() -> dict[str, Any]:
    loaded = yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _app_routes(app: FastAPI) -> set[tuple[str, str]]:
    """Every `(method, path template)` the app serves.

    Recent FastAPI keeps an included router as one entry in `app.routes` and
    flattens it through `fastapi.routing.iter_route_contexts`; older versions
    list every route directly. Both are walked, and the route test checks it
    found the queue's own route, so it cannot pass by finding nothing.
    """
    import fastapi.routing

    walk = getattr(fastapi.routing, "iter_route_contexts", None)
    routes = list(walk(app.routes)) if walk is not None else list(app.routes)
    found: set[tuple[str, str]] = set()
    for route in routes:
        path = getattr(route, "path", None)
        for method in getattr(route, "methods", None) or ():
            if path:
                found.add((method, _template(path)))
    return found


def _template(path: str) -> str:
    """Parameter names do not route: `{repo_id}` and `{id}` match the same paths."""
    return re.sub(r"\{[^}]+\}", "{}", path)


class TestTheShippedFile:
    def test_it_loads(self) -> None:
        loaded = playbooks.load_playbooks(SHIPPED)
        assert loaded.version

    def test_every_kind_has_a_playbook_and_no_more(self) -> None:
        loaded = playbooks.load_playbooks(SHIPPED)
        assert tuple(loaded.playbooks) == agent_work.KINDS

    def test_the_setting_points_at_it(self) -> None:
        assert Settings().agent_playbooks_path.resolve() == SHIPPED.resolve()

    def test_every_route_a_playbook_names_exists(self, client) -> None:
        served = _app_routes(client.app)
        assert ("GET", "/api/agent/work") in served, "the route walk found nothing"
        missing = [
            f"{kind}.{step}: {route}"
            for kind, step, route in playbooks.load_playbooks(SHIPPED).routes()
            if (lambda m, p: (m, _template(p)) not in served)(*playbooks.split_route(route))
        ]
        assert not missing, "Playbooks name routes the app does not serve:\n" + "\n".join(
            missing
        )

    def test_the_two_lanes_that_kept_stopping_read_the_failure_first(self) -> None:
        """The order is the content (spec 36 §5): every later branch of these two
        depends on what the failed job said, so reading it comes before any
        diagnosis."""
        loaded = playbooks.load_playbooks(SHIPPED)
        for kind in ("lane_stalled", "ci_job_failing"):
            ids = [s.id for s in loaded.playbooks[kind].steps]
            diagnoses = [s.id for s in loaded.playbooks[kind].steps if s.then != "continue"]
            assert "read-the-failure-first" in ids
            assert all(ids.index("read-the-failure-first") < ids.index(d) for d in diagnoses)

    def test_lane_stalled_covers_every_known_cause(self) -> None:
        ids = {s.id for s in playbooks.load_playbooks(SHIPPED).playbooks["lane_stalled"].steps}
        assert {
            "quiet-repository",
            "billing-or-spending-limit",
            "actions-disabled",
            "red-upstream-quality-lane",
            "wrong-branch-or-pinned-commit",
            "ingestion-token-out-of-sync",
            "host-or-docker-restart",
        } <= ids

    def test_no_playbook_sends_an_agent_round_the_governed_routes(self) -> None:
        """A playbook that told an agent to approve, revoke or grant would be
        asking it to call routes that refuse it. None does."""
        human_only = {
            ("POST", "/api/approvals/{}/decisions"),
            ("POST", "/api/risk-acceptances/{}/revoke"),
            ("POST", "/api/approvals/delegations"),
            ("POST", "/api/agents/credentials/{}/revoke"),
        }
        named = {
            (m, _template(p))
            for _, _, r in playbooks.load_playbooks(SHIPPED).routes()
            for m, p in [playbooks.split_route(r)]
        }
        assert not named & human_only


class TestTheValidator:
    def test_a_missing_kind_is_refused(self) -> None:
        document = _document()
        del document["playbooks"]["triage"]
        with pytest.raises(playbooks.PlaybookError, match="no playbook for kind.*triage"):
            playbooks.parse_playbooks(document)

    def test_a_kind_the_queue_never_emits_is_refused(self) -> None:
        document = _document()
        document["playbooks"]["lane_wobbly"] = copy.deepcopy(document["playbooks"]["triage"])
        with pytest.raises(playbooks.PlaybookError, match="never emits: lane_wobbly"):
            playbooks.parse_playbooks(document)

    def test_a_misspelt_key_is_refused_not_ignored(self) -> None:
        document = _document()
        book = document["playbooks"]["triage"]
        book["stop_whne"] = book.pop("stop_when")
        with pytest.raises(playbooks.PlaybookError, match="unknown key"):
            playbooks.parse_playbooks(document)

    def test_a_step_with_nowhere_to_look_is_refused(self) -> None:
        document = _document()
        step = document["playbooks"]["triage"]["steps"][0]
        step.pop("routes", None)
        step.pop("outside", None)
        with pytest.raises(playbooks.PlaybookError, match="names no route"):
            playbooks.parse_playbooks(document)

    def test_a_malformed_route_is_refused(self) -> None:
        document = _document()
        document["playbooks"]["triage"]["steps"][0]["routes"] = ["/api/agent/work"]
        with pytest.raises(playbooks.PlaybookError, match="METHOD /path"):
            playbooks.parse_playbooks(document)

    def test_a_branch_must_say_when_it_applies(self) -> None:
        document = _document()
        step = document["playbooks"]["triage"]["steps"][0]
        step["then"] = "escalate"
        step.pop("if_found", None)
        with pytest.raises(playbooks.PlaybookError, match="needs an if_found"):
            playbooks.parse_playbooks(document)

    def test_an_unknown_outcome_is_refused(self) -> None:
        document = _document()
        document["playbooks"]["triage"]["steps"][0]["then"] = "shrug"
        with pytest.raises(playbooks.PlaybookError, match="expected one of"):
            playbooks.parse_playbooks(document)

    def test_duplicate_step_ids_are_refused(self) -> None:
        document = _document()
        steps = document["playbooks"]["triage"]["steps"]
        steps.append(copy.deepcopy(steps[0]))
        with pytest.raises(playbooks.PlaybookError, match="two steps with id"):
            playbooks.parse_playbooks(document)

    def test_an_unquoted_version_is_refused(self) -> None:
        document = _document()
        document["version"] = 1.1
        with pytest.raises(playbooks.PlaybookError, match="quoted"):
            playbooks.parse_playbooks(document)

    def test_a_missing_file_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(playbooks.PlaybookError, match="No agent playbooks"):
            playbooks.load_playbooks(tmp_path / "absent.yaml")


def _every_kind_queue(version: str = "1.0") -> agent_work.WorkQueue:
    """A queue holding one item of every kind `build` can emit."""
    from mykronos.platform_health import JobHealth

    briefing = Briefing(
        generated_at=NOW,
        total_open=1,
        stalled=[
            StalledLane(
                repo_full_name=REPO,
                capability="sast",
                reason="failing",
                consecutive_failures=3,
                streak_capped=False,
                last_success=None,
                detail="",
                open_findings=1,
                scanned_by="github_actions",
            )
        ],
        failing=[FailingLane(pipeline="acme", job="unit", last_status="failed")],
        paused=[PausedLane(pipeline="acme", job="dast", last_status="failed")],
        unhealthy_jobs=[
            JobHealth(name="absences", status="failing", detail="boom", consecutive_failures=4)
        ],
        toxic=[
            {
                "repo_full_name": REPO,
                "combination_id": "c1",
                "name": "Secret plus exposure",
                "severity": "critical",
                "members": [{"finding_id": "f1", "severity": "high", "rule_id": "r"}],
            }
        ],
        exposure=[
            {
                "id": "e1",
                "url": "https://example.invalid/",
                "repo_full_name": REPO,
                "last_probed_at": NOW.isoformat(),
                "observations": [
                    {"kind": "unauthenticated", "severity": "high", "title": "Open", "detail": ""}
                ],
            }
        ],
        tokens=[
            TokenDelivery(
                repo_full_name=REPO,
                state="due",
                issued_at=NOW - timedelta(days=100),
                rotate_after=NOW - timedelta(days=1),
                scanned_by="concourse",
            )
        ],
    )
    return agent_work.build(
        briefing,
        AGENT,
        triage_rows=[
            {
                "finding_id": "f1",
                "repo_full_name": REPO,
                "capability": "sast",
                "rule_id": "r",
                "title": "Something",
                "severity": "high",
                "triage": "true_positive",
                "triage_rationale": "A high sast finding.",
                "state": {"claimed_by": None},
            }
        ],
        acceptances=[
            {"id": "a1", "status": "review_due", "review_by": "2026-10-01", "repo": REPO}
        ],
        approval_requests=[
            {"id": "r1", "duty": "pull_request_merge", "subject_ref": "x#1",
             "last_verdict": "needs_info", "last_rationale": "Which test?"}
        ],
        repo_ids={REPO: REPO_ID},
        now=NOW,
        probe_interval_seconds=21_600,
        playbook_version=version,
    )


class TestKinds:
    def test_kinds_is_exactly_what_build_can_emit(self) -> None:
        """`KINDS` is the single source of the list; this pins it to `build`.
        A kind added to `build` and not to `KINDS` fails in `WorkItem`, and one
        added to `KINDS` that `build` cannot emit fails here."""
        emitted = {item.kind for item in _every_kind_queue().items}
        assert emitted == set(agent_work.KINDS)

    def test_a_kind_not_in_kinds_cannot_be_made(self) -> None:
        with pytest.raises(ValueError, match="not in agent_work.KINDS"):
            agent_work.WorkItem(
                item_id="x", kind="mystery", band=1, title="", summary="", done_when=""
            )


class TestVersionStamping:
    def test_every_item_names_its_playbook_at_the_loaded_version(self) -> None:
        queue = _every_kind_queue(version="7.3")
        assert queue.items
        assert all(item.playbook == f"{item.kind}@7.3" for item in queue.items)

    def test_the_route_stamps_the_shipped_version(
        self, client, admin_auth, auth, run_compaction
    ) -> None:
        """A failing scan makes a stalled lane, and the route names its
        playbook at the version of the file it loaded."""
        assert post_scan(client, auth, scan_status="failure").status_code < 300
        run_compaction()
        version = playbooks.load_playbooks(SHIPPED).version

        body = client.get("/api/agent/work", headers=admin_auth).json()

        [lane] = [i for i in body["items"] if i["kind"] == "lane_stalled"]
        assert lane["playbook"] == f"lane_stalled@{version}"
        assert all(i["playbook"] == f"{i['kind']}@{version}" for i in body["items"])


class TestTheRoutes:
    def test_all_playbooks_in_band_order(self, client, admin_auth) -> None:
        response = client.get("/api/agent/playbooks", headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert [p["kind"] for p in body["playbooks"]] == list(agent_work.KINDS)
        assert all(p["ref"] == f"{p['kind']}@{body['version']}" for p in body["playbooks"])

    def test_one_playbook(self, client, admin_auth) -> None:
        response = client.get("/api/agent/playbooks/lane_stalled", headers=admin_auth)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["kind"] == "lane_stalled"
        assert body["steps"][0]["id"] == "read-the-item"
        assert body["escalate"]["evidence"]

    def test_an_unknown_kind_is_404(self, client, admin_auth) -> None:
        response = client.get("/api/agent/playbooks/lane_wobbly", headers=admin_auth)
        assert response.status_code == 404
        assert "lane_stalled" in response.json()["detail"]

    def test_any_principal_may_read(self, client, admin_auth, viewer_auth) -> None:
        minted = client.post(
            "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
        ).json()
        agent = {"Authorization": f"Bearer {minted['token']}"}
        for headers in (viewer_auth, agent):
            assert client.get("/api/agent/playbooks", headers=headers).status_code == 200
            assert (
                client.get("/api/agent/playbooks/triage", headers=headers).status_code == 200
            )

    def test_it_needs_a_credential(self, client) -> None:
        assert client.get("/api/agent/playbooks").status_code == 401

    def test_a_broken_file_fails_loudly(self, client, admin_auth, tmp_path: Path) -> None:
        broken = tmp_path / "agent-playbooks-v1.yaml"
        document = _document()
        del document["playbooks"]["triage"]
        broken.write_text(yaml.safe_dump(document), encoding="utf-8")
        client.app.state.settings.agent_playbooks_path = broken
        for path in ("/api/agent/playbooks", "/api/agent/work"):
            response = client.get(path, headers=admin_auth)
            assert response.status_code == 503, path
            assert "triage" in response.json()["detail"]
