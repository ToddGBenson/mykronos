"""Deterministic auto-triage (TheHub #60888, D-169).

One test class per lane, then the properties every lane shares: a serious
finding is closed only on a verified fix or a vendor statement, an undo puts
back exactly what was there and the lane never re-applies, each lane has a
kill switch, and the digest lists what happened. The classifier's verdict is
never read - pinned at the source, because "it does not happen today" is not
a guard.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

import mykronos.auto_triage as auto_triage_module
from mykronos.db.models import AuditLogEntry, AutoTriageAction, ReachabilityReport, RepoOnboarding
from mykronos.oracle.policy import (
    AUTO_TRIAGE_RULES,
    AutoTriagePolicy,
    PolicyError,
    load_policy,
    parse_policy,
)
from mykronos.schemas import utcnow
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

REPO_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def activate(client: TestClient, admin_auth: dict[str, str], repo: str = REPO) -> dict[str, str]:
    onboard(client, admin_auth, repo)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        record = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo)
        ).scalars().one()
        record.status = "active"
    token = issue_token(client, repo, "sast", "containers")
    return {"Authorization": f"Bearer {token}"}


def ingest(
    client: TestClient,
    auth: dict[str, str],
    findings: list[dict[str, Any]],
    capability: str = "containers",
    run: str | None = None,
) -> str:
    run = run or str(uuid.uuid4())
    response = post_scan(
        client, auth, scan_run_id=run, repo_full_name=REPO, capability=capability,
        tool_name="trivy" if capability == "containers" else "codeql",
        finding_count=len(findings),
    )
    assert response.status_code in (200, 201), response.text
    response = post_findings(client, auth, findings, scan_run_id=run, capability=capability)
    assert response.status_code in (200, 201), response.text
    return run


def container(image: str, severity: str = "medium", **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": "CVE-2026-1000",
        "title": "openssl: buffer overread",
        "severity": severity,
        "package_name": "openssl",
        "package_version": "3.0.1",
        "raw_finding_json": {"image": image},
    }
    payload.update(extra)
    return payload


def code(path: str, severity: str = "medium") -> dict[str, Any]:
    return {
        "rule_id": "CWE-78",
        "title": "Command injection",
        "severity": severity,
        "file_path": path,
        "line_start": 3,
        "symbol": "run",
        "code_snippet": "os.system(cmd)",
    }


def findings(client: TestClient) -> dict[str, dict[str, Any]]:
    rows = client.app.state.catalog.query(  # type: ignore[attr-defined]
        "SELECT finding_id, status, resolved_at, severity, "
        "json_extract_string(raw_finding_json, '$.image') FROM findings"
    )
    return {
        str(r[0]): {"status": r[1], "resolved_at": r[2], "severity": r[3], "image": r[4]}
        for r in rows
    }


def only_id(client: TestClient) -> str:
    [finding_id] = findings(client)
    return finding_id


def run(client: TestClient, headers: dict[str, str], *, dry_run: bool = False) -> dict[str, Any]:
    response = client.post(
        "/api/dashboard/auto-triage/run", params={"dry_run": dry_run}, headers=headers
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


def actions(client: TestClient) -> list[AutoTriageAction]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = list(session.execute(select(AutoTriageAction)).scalars())
        for row in rows:
            session.expunge(row)
        return rows


def set_lanes(client: TestClient, *enabled: str) -> None:
    policy = client.app.state.oracle_policy  # type: ignore[attr-defined]
    client.app.state.oracle_policy = dataclasses.replace(  # type: ignore[attr-defined]
        policy, auto_triage=AutoTriagePolicy(enabled_rules=frozenset(enabled))
    )


def seed_verified_fix(
    client: TestClient, run_compaction: Any, finding_id: str, *, verified_at: Any = None
) -> str:
    event_id = f"event-{finding_id[:8]}"
    client.app.state.buffer.append(  # type: ignore[attr-defined]
        "remediation_events",
        [
            {
                "event_id": event_id,
                "repo_full_name": REPO,
                "finding_id": finding_id,
                "toxic_combination_id": None,
                "contributing_finding_ids": json.dumps([]),
                "pipeline_stage_reached": "pr_opened",
                "triage_classification": "true_positive",
                "fix_pr_number": 77,
                "fix_pr_url": "https://example.invalid/pr/77",
                "pr_status": "merged",
                "rationale": "bumped openssl",
                "verification_commit_sha": "cafe1234cafe1234cafe1234cafe1234cafe1234",
                "verification_dispatched_at": utcnow() - timedelta(hours=1),
                "verification_scan_run_id": "verifying-run",
                "verification_outcome": "verified_fixed",
                "verified_at": verified_at or utcnow() + timedelta(minutes=5),
                "time_to_verified_seconds": 60,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    run_compaction()
    return event_id


def record_vex(client: TestClient, headers: dict[str, str], **overrides: Any) -> Any:
    body: dict[str, Any] = {
        "vulnerability_id": "cve-2026-1000",
        "package_name": "openssl",
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "source_kind": "vendor",
        "source": "https://vendor.example/advisories/CVE-2026-1000",
    }
    body.update(overrides)
    return client.post("/api/dashboard/vex-statements", json=body, headers=headers)


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    response = client.post(
        "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def disposition(client: TestClient, headers: dict[str, str], finding_id: str, status: str):
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status",
        json={"status": status, "reason": "The decoder is not shipped in this image."},
        headers=headers,
    )
    assert response.status_code == 200, response.text


def add_reachability(
    client: TestClient, orphaned: list[str], unparseable: int = 0
) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        repo = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).scalars().one()
        session.add(
            ReachabilityReport(
                repo_onboarding_id=repo.id,
                language="python",
                commit_sha="abc123def456",
                orphaned_paths=orphaned,
                files_analysed=40,
                files_unparseable=unparseable,
            )
        )


# --------------------------------------------------------------------------
# The lanes
# --------------------------------------------------------------------------


class TestFixVerified:
    def test_a_verified_fix_closes_even_a_high(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1", severity="high")])
        run_compaction()
        finding_id = only_id(client)
        event_id = seed_verified_fix(client, run_compaction, finding_id)

        body = run(client, admin_auth)
        run_compaction()

        assert len(body["applied"]) == 1
        assert findings(client)[finding_id]["status"] == "fixed"
        [action] = actions(client)
        assert action.rule == "fix_verified"
        assert action.evidence["type"] == "remediation_event"
        assert action.evidence["ref"] == event_id
        assert action.prior_state["status"] == "open"

    def test_seen_again_after_the_verifying_scan_is_a_regression(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1", severity="high")])
        run_compaction()
        finding_id = only_id(client)
        seed_verified_fix(
            client, run_compaction, finding_id, verified_at=utcnow() - timedelta(days=2)
        )

        assert run(client, admin_auth)["proposed"] == []
        assert findings(client)[finding_id]["status"] == "open"


class TestVexNotAffected:
    def test_a_vendor_statement_closes_a_high(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1", severity="high")])
        run_compaction()
        recorded = record_vex(client, admin_auth)
        assert recorded.status_code == 201, recorded.text

        run(client, admin_auth)
        run_compaction()

        [state] = findings(client).values()
        assert state["status"] == "suppressed"
        [action] = actions(client)
        assert action.rule == "vex_not_affected"
        assert action.evidence["ref"] == recorded.json()["id"]
        assert action.evidence["source"].startswith("https://vendor.example/")

    def test_a_statement_for_another_version_does_not_apply(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1")])
        run_compaction()
        record_vex(client, admin_auth, package_version="9.9.9")

        assert run(client, admin_auth)["proposed"] == []

    def test_a_revoked_statement_is_not_evidence(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1")])
        run_compaction()
        statement = record_vex(client, admin_auth).json()
        client.delete(f"/api/dashboard/vex-statements/{statement['id']}", headers=admin_auth)

        assert run(client, admin_auth)["proposed"] == []

    def test_an_agent_cannot_record_one(self, client: TestClient, admin_auth) -> None:
        """An agent that may not close a critical (#713) must not write the
        evidence that would close it."""
        assert record_vex(client, _agent(client, admin_auth)).status_code == 403

    def test_not_affected_needs_a_justification(self, client: TestClient, admin_auth) -> None:
        response = record_vex(client, admin_auth, justification=None)

        assert response.status_code == 422


class TestExactDuplicate:
    def test_a_persons_verdict_carries_to_the_same_package_in_another_image(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1"), container("worker:1")])
        run_compaction()
        by_image = {v["image"]: k for k, v in findings(client).items()}
        disposition(client, admin_auth, by_image["app:1"], "false_positive")
        run_compaction()

        run(client, admin_auth)
        run_compaction()

        assert findings(client)[by_image["worker:1"]]["status"] == "false_positive"
        [action] = actions(client)
        assert action.rule == "exact_duplicate"
        assert action.evidence["ref"] == by_image["app:1"]
        assert action.evidence["cluster_id"].startswith("cl_")

    def test_another_version_is_not_an_exact_duplicate(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1"), container("worker:1", package_version="3.0.2")])
        run_compaction()
        by_image = {v["image"]: k for k, v in findings(client).items()}
        disposition(client, admin_auth, by_image["app:1"], "false_positive")
        run_compaction()

        assert run(client, admin_auth)["proposed"] == []

    def test_an_acceptance_is_never_copied(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1"), container("worker:1")])
        run_compaction()
        by_image = {v["image"]: k for k, v in findings(client).items()}
        response = client.patch(
            f"/api/dashboard/findings/{by_image['app:1']}/status",
            json={
                "status": "accepted_risk", "reason": "No vendor fix yet.",
                "accepted_reason_code": "no_vendor_fix", "indefinite": True,
            },
            headers=admin_auth,
        )
        assert response.status_code == 200, response.text
        run_compaction()

        assert run(client, admin_auth)["proposed"] == []

    def test_a_high_duplicate_waits_for_a_person(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [
            container("app:1", severity="high"), container("worker:1", severity="high"),
        ])
        run_compaction()
        by_image = {v["image"]: k for k, v in findings(client).items()}
        disposition(client, admin_auth, by_image["app:1"], "false_positive")
        run_compaction()

        body = run(client, admin_auth)

        assert body["proposed"] == [] and body["held_serious"] == 1
        assert findings(client)[by_image["worker:1"]]["status"] == "open"


class TestUnreachable:
    def test_an_orphaned_python_file_is_suppressed(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [code("pkg/dead.py"), code("pkg/live.py")], capability="sast")
        run_compaction()
        add_reachability(client, ["pkg/dead.py"])

        run(client, admin_auth)
        run_compaction()

        statuses = sorted(v["status"] for v in findings(client).values())
        assert statuses == ["open", "suppressed"]
        [action] = actions(client)
        assert action.rule == "unreachable"
        assert action.evidence["type"] == "reachability_report"
        assert action.evidence["path"] == "pkg/dead.py"

    def test_one_unparseable_file_silences_the_lane(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [code("pkg/dead.py")], capability="sast")
        run_compaction()
        add_reachability(client, ["pkg/dead.py"], unparseable=1)

        assert run(client, admin_auth)["proposed"] == []

    def test_a_high_in_an_orphaned_file_waits_for_a_person(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [code("pkg/dead.py", severity="high")], capability="sast")
        run_compaction()
        add_reachability(client, ["pkg/dead.py"])

        body = run(client, admin_auth)

        assert body["proposed"] == [] and body["held_serious"] == 1


# --------------------------------------------------------------------------
# What every lane shares
# --------------------------------------------------------------------------


class TestUndo:
    def _auto_closed(self, client, admin_auth, run_compaction) -> tuple[str, str]:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1", severity="high")])
        run_compaction()
        finding_id = only_id(client)
        record_vex(client, admin_auth)
        run(client, admin_auth)
        run_compaction()
        [action] = actions(client)
        return finding_id, action.id

    def test_undo_restores_exactly_the_prior_state_and_audits_it(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/auto-triage/actions/{action_id}/undo",
            json={"reason": "The statement covers the Debian build, not ours."},
            headers=admin_auth,
        )
        run_compaction()

        assert response.status_code == 200, response.text
        assert response.json()["undone_by"]
        state = findings(client)[finding_id]
        assert state["status"] == "open" and state["resolved_at"] is None
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            entry = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "finding.auto_triage_undone")
            ).scalar_one()
            assert entry.entity_id == finding_id
            assert entry.detail["auto_triage_action_id"] == action_id
            assert entry.detail["restored_state"]["status"] == "open"

    def test_an_undone_lane_never_reapplies(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)
        client.post(
            f"/api/dashboard/auto-triage/actions/{action_id}/undo",
            json={"reason": "Not ours."},
            headers=admin_auth,
        )
        run_compaction()

        assert run(client, admin_auth)["proposed"] == []
        assert findings(client)[finding_id]["status"] == "open"

    def test_undoing_twice_is_refused(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        _finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)
        path = f"/api/dashboard/auto-triage/actions/{action_id}/undo"
        client.post(path, json={"reason": "Not ours."}, headers=admin_auth)

        again = client.post(path, json={"reason": "Not ours."}, headers=admin_auth)

        assert again.status_code == 409

    def test_a_finding_somebody_changed_since_is_not_overwritten(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)
        client.post(
            f"/api/dashboard/findings/{finding_id}/reopen",
            json={"reason": "Checking this by hand."},
            headers=admin_auth,
        )
        run_compaction()

        response = client.post(
            f"/api/dashboard/auto-triage/actions/{action_id}/undo",
            json={"reason": "Not ours."},
            headers=admin_auth,
        )

        assert response.status_code == 409

    def test_the_action_is_visible_on_the_finding(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)

        detail = client.get(f"/api/dashboard/findings/{finding_id}", headers=admin_auth).json()

        assert [a["id"] for a in detail["auto_triage"]] == [action_id]
        assert detail["auto_triage"][0]["rule"] == "vex_not_affected"

    def test_a_viewer_cannot_undo(
        self, client: TestClient, admin_auth, viewer_auth, run_compaction
    ) -> None:
        _finding_id, action_id = self._auto_closed(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/auto-triage/actions/{action_id}/undo",
            json={"reason": "Not ours."},
            headers=viewer_auth,
        )

        assert response.status_code == 403


class TestKillSwitch:
    def test_a_disabled_lane_closes_nothing_and_says_so(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1")])
        run_compaction()
        record_vex(client, admin_auth)
        set_lanes(client, "fix_verified", "exact_duplicate", "unreachable")

        body = run(client, admin_auth)

        assert body["proposed"] == []
        assert body["disabled"] == {"vex_not_affected": 1}
        assert body["enabled"]["vex_not_affected"] is False
        assert actions(client) == []

    def test_the_repositorys_policy_enables_every_lane(self) -> None:
        policy = load_policy(REPO_ROOT / "oracle-policy-v1.yaml")

        assert policy.auto_triage.enabled() == dict.fromkeys(AUTO_TRIAGE_RULES, True)

    def test_without_the_block_every_lane_is_off(self) -> None:
        document = _policy_document()
        document.pop("auto_triage", None)

        assert not any(parse_policy(document).auto_triage.enabled().values())

    def test_a_misspelt_lane_is_refused(self) -> None:
        document = _policy_document()
        document["auto_triage"] = {"exact_duplicates": {"enabled": False}}

        with pytest.raises(PolicyError, match="unknown lanes"):
            parse_policy(document)


def _policy_document() -> dict[str, Any]:
    import yaml

    loaded = yaml.safe_load((REPO_ROOT / "oracle-policy-v1.yaml").read_text(encoding="utf-8"))
    return dict(loaded)


class TestDigest:
    def test_the_digest_lists_the_last_days_actions_by_lane(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1"), code("pkg/dead.py")])
        run_compaction()
        record_vex(client, admin_auth)
        add_reachability(client, ["pkg/dead.py"])
        run(client, admin_auth)

        body = client.get("/api/dashboard/auto-triage/digest", headers=admin_auth).json()

        assert body["total"] == 2 and body["hours"] == 24
        assert body["by_rule"] == {"vex_not_affected": 1, "unreachable": 1}
        assert {a["rule"] for a in body["actions"]} == {"vex_not_affected", "unreachable"}

    def test_the_briefing_carries_the_digest(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1")])
        run_compaction()
        record_vex(client, admin_auth)
        run(client, admin_auth)

        body = client.get("/api/dashboard/briefing", headers=admin_auth).json()

        assert body["auto_triage"]["total"] == 1
        assert body["auto_triage"]["by_rule"] == {"vex_not_affected": 1}

    def test_a_dry_run_writes_nothing(self, client: TestClient, admin_auth, run_compaction):
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1")])
        run_compaction()
        record_vex(client, admin_auth)

        body = run(client, admin_auth, dry_run=True)

        assert len(body["proposed"]) == 1 and body["applied"] == []
        assert actions(client) == []
        assert set(v["status"] for v in findings(client).values()) == {"open"}


class TestNoModelVerdict:
    def test_nothing_without_evidence(self, client: TestClient, admin_auth, run_compaction):
        auth = activate(client, admin_auth)
        ingest(client, auth, [container("app:1"), code("pkg/x.py")])
        run_compaction()

        assert run(client, admin_auth)["proposed"] == []

    def test_the_module_never_reads_the_classifier(self) -> None:
        """Todd, 2026-10-22: model verdicts never auto-apply. The classifier
        is the only verdict-producing code in the platform, so the module
        that acts must not import it."""
        source = Path(auto_triage_module.__file__).read_text(encoding="utf-8")
        imported = {
            node.module or ""
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.ImportFrom)
        } | {
            alias.name
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        assert not any("patchwork" in name or "knowledge" in name for name in imported)
        assert "classify" not in source
