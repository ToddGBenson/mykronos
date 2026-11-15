"""The deploy ratchet: a deploy may not raise a repository's risk (D-182).

Two halves. `judge` is the rule as a pure function, tested branch by branch.
The rest drive `GET /api/oracle/deploy-gate` over a real lake, because the
part that is easy to get wrong is not the comparison but what is compared:
both scores must be measured over one findings snapshot, so a CVE published
since the deployed commit was scanned cannot refuse a deploy that did not
change anything (the 2026-11-14 case: main 166.3 against the deployed 165.2,
the whole difference new CVEs in unchanged images).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.db.models import OracleRatchetLatch, Organization, RepoOnboarding
from mykronos.lake.compaction import compact
from mykronos.lake.reconcile import reconcile_absences
from mykronos.oracle import deploy_gate
from mykronos.oracle.deploy_gate import (
    BASELINE_DISAGREES,
    BASELINE_UNKNOWN,
    EVALUATION_FAILED,
    INTRODUCED_BLOCKING,
    LATCHED_NO_GO,
    LOWERED,
    LOWERED_WHILE_NO_GO,
    NO_DECISION,
    NOT_ASSESSED,
    NOT_RAISED,
    SCORE_RAISED,
    TOLERANCE,
    UNCHANGED_WHILE_NO_GO,
    Reason,
    judge,
)
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_reprocess import _set_raw_ref

D = "d" * 40
C1 = "c1" + "0" * 38
C = "c" * 40
NO_GO = 70.0


def _judge(**overrides: Any) -> deploy_gate.Judgement:
    args: dict[str, Any] = {
        "candidate_found": True,
        "candidate_recommendation": "review_recommended",
        "baseline_problem": None,
        "evaluation_error": None,
        "candidate_score": 40.0,
        "baseline_score": 40.0,
        "blocking_ids": [],
        "latched": False,
        "no_go": NO_GO,
    }
    args.update(overrides)
    return judge(**args)


def _codes(outcome: deploy_gate.Judgement) -> list[str]:
    return [r.code for r in outcome.reasons]


class TestTheRule:
    def test_a_raise_beyond_the_tolerance_is_refused(self) -> None:
        outcome = _judge(candidate_score=41.2, baseline_score=40.0)
        assert not outcome.allow
        assert _codes(outcome) == [SCORE_RAISED]

    def test_a_raise_within_the_tolerance_is_allowed(self) -> None:
        outcome = _judge(candidate_score=40.0 + TOLERANCE, baseline_score=40.0)
        assert outcome.allow
        assert _codes(outcome) == [NOT_RAISED]

    def test_equal_is_allowed(self) -> None:
        assert _judge().allow

    def test_a_lower_score_is_allowed(self) -> None:
        outcome = _judge(candidate_score=30.0, baseline_score=40.0)
        assert outcome.allow
        assert _codes(outcome) == [LOWERED]

    def test_an_introduced_high_is_refused_whatever_the_score(self) -> None:
        """A high in a large band can add less than the tolerance; it still refuses."""
        outcome = _judge(candidate_score=40.1, baseline_score=40.0, blocking_ids=["f-1"])
        assert not outcome.allow
        assert _codes(outcome) == [INTRODUCED_BLOCKING]
        assert "f-1" in outcome.reasons[0].message

    def test_latched_no_go_is_a_hard_refusal_even_when_unchanged(self) -> None:
        outcome = _judge(candidate_score=80.0, baseline_score=80.0, latched=True)
        assert not outcome.allow
        assert _codes(outcome) == [LATCHED_NO_GO]
        assert "the No-Go is the backlog" in outcome.reasons[0].message

    def test_latched_below_no_go_is_allowed(self) -> None:
        assert _judge(candidate_score=69.9, baseline_score=69.9, latched=True).allow

    def test_unlatched_no_go_unchanged_is_allowed(self) -> None:
        outcome = _judge(candidate_score=165.2, baseline_score=165.2)
        assert outcome.allow
        assert _codes(outcome) == [UNCHANGED_WHILE_NO_GO]

    def test_unlatched_no_go_fix_is_allowed(self) -> None:
        """(d): a fix that lowers the score while still No-Go."""
        outcome = _judge(candidate_score=150.0, baseline_score=165.2)
        assert outcome.allow
        assert _codes(outcome) == [LOWERED_WHILE_NO_GO]

    def test_unlatched_no_go_raise_is_still_refused(self) -> None:
        assert not _judge(candidate_score=170.0, baseline_score=165.2).allow

    def test_every_applicable_refusal_is_listed(self) -> None:
        outcome = _judge(
            candidate_score=90.0, baseline_score=60.0, blocking_ids=["f"], latched=True
        )
        assert _codes(outcome) == [INTRODUCED_BLOCKING, SCORE_RAISED, LATCHED_NO_GO]

    def test_a_missing_decision_is_refused(self) -> None:
        outcome = _judge(candidate_found=False, candidate_recommendation=None)
        assert not outcome.allow
        assert _codes(outcome) == [NO_DECISION]

    @pytest.mark.parametrize("word", ["not_assessed", "insufficient_evidence", "", None])
    def test_a_verdict_that_is_not_a_measurement_is_refused(self, word) -> None:
        outcome = _judge(candidate_recommendation=word)
        assert not outcome.allow
        assert _codes(outcome) == [NOT_ASSESSED]

    def test_a_missing_baseline_is_refused(self) -> None:
        problem = Reason(BASELINE_UNKNOWN, "no baseline")
        outcome = _judge(baseline_problem=problem, baseline_score=None)
        assert not outcome.allow
        assert _codes(outcome) == [BASELINE_UNKNOWN]

    def test_an_evaluation_error_is_refused(self) -> None:
        outcome = _judge(evaluation_error="boom", candidate_score=None, baseline_score=None)
        assert not outcome.allow
        assert _codes(outcome) == [EVALUATION_FAILED]

    def test_no_scores_with_no_named_problem_is_still_refused(self) -> None:
        """The default branch of a fail-closed gate is the refusal."""
        outcome = _judge(candidate_score=None)
        assert not outcome.allow
        assert _codes(outcome) == [EVALUATION_FAILED]


# -- over a real lake ---------------------------------------------------------


@pytest.fixture
def oracle_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'oracle')}"}


def _push_scan(
    client: TestClient,
    run_compaction: Any,
    scan_run_id: str,
    commit: str,
    started_at: str,
    findings: list[dict[str, Any]],
) -> None:
    """A push scan on main (no pull request), the kind the range is read from."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    response = post_scan(
        client, auth, scan_run_id=scan_run_id, commit_sha=commit, pr_number=None,
        triggered_by="push", started_at=started_at,
    )
    assert response.status_code in (200, 201, 202), response.text
    if findings:
        posted = post_findings(client, auth, findings, scan_run_id=scan_run_id)
        assert posted.status_code in (200, 201, 202), posted.text
    run_compaction()


def _sast(rule: str, severity: str) -> dict[str, Any]:
    return finding_payload(rule_id=rule, severity=severity, file_path=f"src/{rule}.py")


ZAP = "ghcr.io/zaproxy/zaproxy:stable"
SAME_BYTES = "sha256:9e18"


def _container_push_scan(
    client: TestClient,
    run_compaction: Any,
    scan_run_id: str,
    commit: str,
    started_at: str,
    cves: list[tuple[str, str]],
) -> None:
    """A push containers scan of one image whose bytes never change, with the
    archived Trivy report that proves it (#734)."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'containers')}"}
    post_scan(
        client, auth, scan_run_id=scan_run_id, commit_sha=commit, pr_number=None,
        triggered_by="push", capability="containers", tool_name="trivy",
        tool_version="0.58.1", started_at=started_at,
    )
    post_findings(
        client,
        auth,
        [
            finding_payload(
                rule_id=cve, severity=severity, title=f"otel-sdk {cve}",
                file_path="zaproxy/zaproxy", line_start=1, line_end=1, symbol=None,
                code_snippet=None, package_name="otel-sdk", package_version="1.2.3",
                raw_finding_json={"ruleId": cve, "image": ZAP},
            )
            for cve, severity in cves
        ],
        scan_run_id=scan_run_id,
        capability="containers",
    )
    settings = client.app.state.settings
    owner, name = REPO.split("/")
    folder = settings.raw_dir / owner / name / scan_run_id
    folder.mkdir(parents=True, exist_ok=True)
    report = {
        "version": "2.1.0",
        "runs": [{"results": [], "properties": {"imageName": ZAP, "imageID": SAME_BYTES}}],
    }
    (folder / "trivy-zap.sarif").write_text(json.dumps(report), encoding="utf-8")
    run_compaction()
    _set_raw_ref(
        client.app.state.catalog, scan_run_id, f"raw/{owner}/{name}/{scan_run_id}/trivy-zap.sarif"
    )


def _decide(client: TestClient, oracle_auth: dict[str, str], commit: str) -> dict[str, Any]:
    """Record a gate decision and compact it, as the background compactor
    would before a deploy reads it back."""
    response = client.post(
        "/api/oracle/evaluate",
        json={"decision_type": "commit_gate", "commit_sha": commit},
        headers=oracle_auth,
    )
    assert response.status_code == 200, response.text
    compact(client.app.state.catalog, client.app.state.buffer)
    return response.json()


def _gate(
    client: TestClient, viewer_auth: dict[str, str], commit: str, deployed: str | None = D
) -> dict[str, Any]:
    params = {"repo": REPO, "commit": commit}
    if deployed is not None:
        params["deployed"] = deployed
    response = client.get("/api/oracle/deploy-gate", params=params, headers=viewer_auth)
    assert response.status_code == 200, response.text
    return response.json()


def _codes_of(body: dict[str, Any]) -> list[str]:
    return [r["code"] for r in body["reasons"]]


def _latch(client: TestClient) -> None:
    with client.app.state.db.session() as session:
        session.add(OracleRatchetLatch(repo_full_name=REPO, commit_sha=D, raw_score=10.0))


def _stored_raw(client: TestClient, commit: str) -> float:
    rows = client.app.state.catalog.query(
        "SELECT inputs_snapshot FROM risk_decisions WHERE commit_sha = ? "
        "ORDER BY evaluated_at DESC LIMIT 1",
        [commit],
    )
    return float(json.loads(rows[0][0])["totals"]["raw_score"])


class TestTheSameSnapshot:
    def test_a_cve_published_since_the_baseline_does_not_refuse(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """The PO's case, exactly: the deployed commit was scored a day earlier;
        overnight three mediums and a low were published against an image
        neither commit changed. The stored decisions differ, and comparing
        them would refuse; over one snapshot nothing moved."""
        _container_push_scan(
            client, run_compaction, "ctr-d", D, "2026-11-13T04:00:00", [("CVE-OLD", "medium")]
        )
        _decide(client, oracle_auth, D)
        _container_push_scan(
            client, run_compaction, "ctr-c", C, "2026-11-14T04:54:00",
            [("CVE-OLD", "medium"), ("CVE-N1", "medium"), ("CVE-N2", "medium"),
             ("CVE-N3", "medium"), ("CVE-N4", "low")],
        )
        _decide(client, oracle_auth, C)
        assert _stored_raw(client, C) - _stored_raw(client, D) > TOLERANCE

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert body["verdict"] == "allow"
        assert body["candidate_score"] == body["baseline_score"]
        assert body["introduced"] == {}
        assert body["introduced_blocking_ids"] == []
        assert body["direction"] == "forward"
        assert body["range_commits"] == [C]


class TestTheRatchetOverALake:
    def _baseline(self, client, run_compaction, oracle_auth, findings) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", findings)
        _decide(client, oracle_auth, D)

    def test_a_commit_that_raises_the_score_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        old = [_sast("OLD1", "medium")]
        self._baseline(client, run_compaction, oracle_auth, old)
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
            old + [_sast("NEW1", "medium"), _sast("NEW2", "medium")],
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert _codes_of(body) == [SCORE_RAISED]
        assert body["introduced"] == {"medium": 2}
        assert body["candidate_score"] > body["baseline_score"] + TOLERANCE

    def test_a_small_rise_within_the_tolerance_is_allowed(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        old = [_sast(f"L{i}", "low") for i in range(3)]
        self._baseline(client, run_compaction, oracle_auth, old)
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
            old + [_sast("L9", "low")],
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert _codes_of(body) == [NOT_RAISED]
        assert 0 < body["score_delta"] <= TOLERANCE

    def test_an_introduced_high_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        self._baseline(client, run_compaction, oracle_auth, [])
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [_sast("H1", "high")]
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert len(body["introduced_blocking_ids"]) == 1

    def test_a_high_introduced_mid_range_is_refused_too(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """The deploy skips a commit: what that commit introduced still ships."""
        self._baseline(client, run_compaction, oracle_auth, [])
        _push_scan(
            client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00", [_sast("H1", "high")]
        )
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [_sast("H1", "high")]
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["range_commits"] == [C1, C]

    def _fixed_by_c(self, client, run_compaction, oracle_auth, gone_severity: str) -> None:
        """D carries three criticals and one more finding; C1 and C fix it, and
        two absences close it."""
        crits = [_sast(f"K{i}", "critical") for i in range(3)]
        self._baseline(client, run_compaction, oracle_auth, crits + [_sast("GONE", gone_severity)])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00", crits)
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", crits)
        reconcile_absences(client.app.state.catalog)
        _decide(client, oracle_auth, C)

    def test_a_fix_that_lowers_the_score_while_no_go_is_allowed(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        self._fixed_by_c(client, run_compaction, oracle_auth, "critical")

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert _codes_of(body) == [LOWERED_WHILE_NO_GO]
        assert body["fixed"] == {"critical": 1}
        assert body["candidate_score"] < body["baseline_score"]
        assert body["candidate_score"] >= NO_GO

    def test_unchanged_no_go_is_allowed_until_latched_then_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        crits = [_sast(f"K{i}", "critical") for i in range(3)]
        self._baseline(client, run_compaction, oracle_auth, crits)
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", crits)
        _decide(client, oracle_auth, C)

        before = _gate(client, viewer_auth, C)
        _latch(client)
        after = _gate(client, viewer_auth, C)

        assert before["allow"] is True and _codes_of(before) == [UNCHANGED_WHILE_NO_GO]
        assert before["latch"]["latched"] is False
        assert after["allow"] is False
        assert _codes_of(after) == [LATCHED_NO_GO]
        assert after["latch"]["latched"] is True

    def test_a_rollback_past_a_security_fix_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """Deploying D over C brings back the high C fixed."""
        self._fixed_by_c(client, run_compaction, oracle_auth, "high")

        body = _gate(client, viewer_auth, D, deployed=C)

        assert body["direction"] == "rollback"
        assert body["allow"] is False
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["introduced"] == {"high": 1}

    def test_a_redeploy_of_the_running_commit_is_allowed(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        self._baseline(client, run_compaction, oracle_auth, [_sast("M", "medium")])

        body = _gate(client, viewer_auth, D)

        assert body["allow"] is True, body
        assert body["direction"] == "same"


class TestItFailsClosed:
    def test_a_commit_nothing_scored_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert _codes_of(body) == [NO_DECISION]

    def test_a_commit_nothing_has_scanned_is_no_decision_alone(
        self, client, run_compaction, viewer_auth
    ) -> None:
        """The state deploy.ps1 waits on, so it must not carry a second code."""
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert _codes_of(body) == [NO_DECISION]

    def test_no_deployed_commit_and_no_probe_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C, deployed=None)

        assert body["allow"] is False
        assert _codes_of(body) == [BASELINE_UNKNOWN]

    def test_a_deployed_commit_the_lake_never_saw_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C, deployed="e" * 40)

        assert body["allow"] is False
        assert _codes_of(body) == [BASELINE_UNKNOWN]

    def test_the_probe_reading_is_the_baseline_when_none_is_named(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C)
        with client.app.state.db.session() as session:
            org = Organization(github_org_login=REPO.split("/")[0])
            session.add(org)
            session.flush()
            session.add(RepoOnboarding(
                org_id=org.id, github_repo_full_name=REPO, github_installation_id=1,
                deployment_probe_status="ok", deployed_revision=D,
            ))

        body = _gate(client, viewer_auth, C, deployed=None)

        assert body["allow"] is True, body
        assert body["baseline_source"] == "deployment probe"
        assert body["deployed_sha"] == D

    def test_an_evaluation_that_raises_is_a_refusal(
        self, client, run_compaction, oracle_auth, viewer_auth, monkeypatch
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C)

        def boom(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("lake unreadable")

        monkeypatch.setattr(deploy_gate.OracleEngine, "evaluate", boom)
        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False
        assert _codes_of(body) == [EVALUATION_FAILED]
        assert "lake unreadable" in body["reasons"][0]["message"]

    def test_this_platform_refuses_a_baseline_it_is_not_running(self, client) -> None:
        own = "a" * 40
        baseline = deploy_gate.baseline_for(
            client.app.state.db, "someone/mykronos", "b" * 40, own
        )
        assert baseline.problem is not None
        assert baseline.problem.code == BASELINE_DISAGREES
        agreed = deploy_gate.baseline_for(
            client.app.state.db, "someone/mykronos", own[:12], own
        )
        assert agreed.problem is None and agreed.sha == own

    def test_a_viewer_without_a_token_is_refused_by_auth(self, client) -> None:
        response = client.get(
            "/api/oracle/deploy-gate", params={"repo": REPO, "commit": C}
        )
        assert response.status_code == 401


class TestTheLatch:
    def test_a_decision_below_no_go_latches_the_repository(
        self, client, run_compaction, oracle_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00",
                   [_sast("M", "medium")])
        _decide(client, oracle_auth, D)

        with client.app.state.db.session() as session:
            row = session.get(OracleRatchetLatch, REPO)
            assert row is not None
            assert row.commit_sha == D and row.source == "decision"

    def test_a_no_go_decision_does_not_latch(self, client, run_compaction, oracle_auth) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00",
                   [_sast(f"K{i}", "critical") for i in range(3)])
        _decide(client, oracle_auth, D)

        with client.app.state.db.session() as session:
            assert session.get(OracleRatchetLatch, REPO) is None

    def test_the_latch_is_never_moved(self, client) -> None:
        db = client.app.state.db
        policy = client.app.state.oracle_policy
        assert deploy_gate.note_score(
            db, REPO, raw_score=10.0, recommendation="go", policy=policy,
            commit_sha=D, source="decision",
        )
        assert not deploy_gate.note_score(
            db, REPO, raw_score=5.0, recommendation="go", policy=policy,
            commit_sha=C, source="decision",
        )
        assert deploy_gate.read_latch(db, REPO).commit_sha == D

    def test_not_assessed_never_latches(self, client) -> None:
        assert not deploy_gate.note_score(
            client.app.state.db, REPO, raw_score=0.0, recommendation="not_assessed",
            policy=client.app.state.oracle_policy, commit_sha=D, source="decision",
        )
