"""The deploy ratchet: a deploy may not raise a repository's risk (D-183).

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

from mykronos.db.models import (
    OracleRatchetCreep,
    OracleRatchetLatch,
    Organization,
    RepoOnboarding,
    ThreatIntelMatch,
)
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
    LOWERED_WHILE_LATCHED,
    LOWERED_WHILE_NO_GO,
    NO_DECISION,
    NOT_ASSESSED,
    NOT_ENFORCEABLE,
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


@pytest.fixture(autouse=True)
def _judged_here(monkeypatch: pytest.MonkeyPatch) -> None:
    """The comparison is driven for the test repository as if it were this
    platform's own; `TestOnlyThisPlatformIsJudged` takes that away."""
    monkeypatch.setattr(deploy_gate, "_TEST_ENFORCEABLE", frozenset({REPO}), raising=False)


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

    def test_latched_no_go_that_lowers_by_more_than_the_tolerance_is_allowed(self) -> None:
        """Operator decision 2026-11-15, replacing (b) as literally applied:
        while latched, a No-Go candidate that lowers the score by more than
        the tolerance and introduces no critical or high ships."""
        outcome = _judge(candidate_score=150.0, baseline_score=165.2, latched=True)
        assert outcome.allow
        assert _codes(outcome) == [LOWERED_WHILE_LATCHED]

    @pytest.mark.parametrize(
        ("candidate", "blocking"),
        [(165.2 - TOLERANCE, []), (165.0, []), (150.0, ["f-1"])],
        ids=["lowered-by-exactly-the-tolerance", "lowered-within-it", "lowered-but-a-high"],
    )
    def test_latched_no_go_is_refused_unless_it_lowers_cleanly(
        self, candidate: float, blocking: list[str]
    ) -> None:
        outcome = _judge(
            candidate_score=candidate, baseline_score=165.2, latched=True, blocking_ids=blocking
        )
        assert not outcome.allow
        assert LATCHED_NO_GO in _codes(outcome)

    def test_creep_earlier_deploys_spent_counts_against_this_one(self) -> None:
        """Three +0.3 deploys are +0.9, not three rises under 0.5 (B4)."""
        assert _judge(candidate_score=40.3, baseline_score=40.0).allow
        outcome = _judge(candidate_score=40.3, baseline_score=40.0, creep=0.3)
        assert not outcome.allow
        assert _codes(outcome) == [SCORE_RAISED]
        assert "earlier deploys already added" in outcome.reasons[0].message
        assert _judge(candidate_score=40.1, baseline_score=40.0, creep=0.3).allow

    def test_creep_never_refuses_a_deploy_that_does_not_raise(self) -> None:
        assert _judge(candidate_score=39.0, baseline_score=40.0, creep=5.0).allow

    def test_an_allow_says_when_fix_credit_is_pending(self) -> None:
        outcome = _judge(fix_credit_pending=2)
        assert outcome.allow
        assert "Fix credit pending: 2 finding(s)" in outcome.reasons[0].message
        assert "Fix credit pending" not in _judge().reasons[0].message

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
    branch: str | None = None,
    status: str | None = None,
) -> None:
    """A push scan on main (no pull request), the kind the range is read from."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    extra: dict[str, Any] = {"branch": branch} if branch is not None else {}
    if status is not None:
        extra["scan_status"] = status
    response = post_scan(
        client, auth, scan_run_id=scan_run_id, commit_sha=commit, pr_number=None,
        triggered_by="push", started_at=started_at, **extra,
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
        # The detail is logged under an id; the response carries neither the
        # exception's text nor its type (review should-fix 5).
        assert "lake unreadable" not in body["reasons"][0]["message"]
        assert "RuntimeError" not in body["reasons"][0]["message"]
        assert body["error_id"] and body["error_id"] in body["reasons"][0]["message"]

    def test_this_platform_refuses_a_baseline_it_is_not_running(self, client) -> None:
        own = "a" * 40
        baseline = deploy_gate.baseline_for(
            client.app.state.db, deploy_gate.SELF_REPO_FULL_NAME, "b" * 40, own
        )
        assert baseline.problem is not None
        assert baseline.problem.code == BASELINE_DISAGREES
        agreed = deploy_gate.baseline_for(
            client.app.state.db, deploy_gate.SELF_REPO_FULL_NAME, own[:12], own
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


# -- review of 5dd9e320 (PR #1171): the paths that answered allow ------------

E1 = "e1" + "0" * 38
E2 = "e2" + "0" * 38
F1 = "f1" + "0" * 38
F2 = "f2" + "0" * 38


def _pr_scan(
    client: TestClient,
    run_compaction: Any,
    scan_run_id: str,
    commit: str,
    started_at: str,
    pr: int,
    findings: list[dict[str, Any]],
) -> None:
    """A pull-request scan: on no branch's line of history."""
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
    response = post_scan(
        client, auth, scan_run_id=scan_run_id, commit_sha=commit, pr_number=pr,
        triggered_by="pull_request", started_at=started_at,
    )
    assert response.status_code in (200, 201, 202), response.text
    if findings:
        posted = post_findings(client, auth, findings, scan_run_id=scan_run_id)
        assert posted.status_code in (200, 201, 202), posted.text
    run_compaction()


def _mediums(n: int) -> list[dict[str, Any]]:
    return [_sast(f"M{i}", "medium") for i in range(n)]


TOXIC_FILE = "orders/query.py"


def _injectable(severity: str) -> dict[str, Any]:
    return finding_payload(
        rule_id="CWE-89", title="SQL injection via string concatenation",
        severity=severity, file_path=TOXIC_FILE, symbol="get_order", code_snippet="q()",
    )


def _unauthenticated(severity: str) -> dict[str, Any]:
    return finding_payload(
        rule_id="CWE-306", title="Missing authentication for critical function",
        severity=severity, file_path=TOXIC_FILE, symbol="admin", code_snippet="a()",
    )


class TestEveryTermIsReScored:
    """B1: the bands were the only terms re-scored, so a KEV boost, a toxic
    combination and the No-Go it forces sat in both scores and cancelled."""

    def test_a_kev_listed_medium_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """One more medium on 13 is +0.497 on the band; KEV-listed it is a
        high's weight, and blocking."""
        cve = "CVE-2024-77777"
        kev = finding_payload(
            rule_id=cve, title=f"requests {cve}", severity="medium",
            file_path="requirements.txt", symbol=None, code_snippet=None,
        )
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id=cve, in_kev=True))
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", _mediums(13))
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00", _mediums(13) + [kev]
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert SCORE_RAISED in _codes_of(body)
        assert body["score_delta"] > 10
        assert body["introduced"] == {"medium": 1}

    def test_a_medium_that_completes_a_critical_combination_is_refused(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """Unlatched: the forced No-Go used to be in both scores, so the deploy
        read as `unchanged_while_no_go` and shipped."""
        before = [_injectable("high"), *_mediums(13)]
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", before)
        _push_scan(
            client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
            before + [_unauthenticated("medium")],
        )
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["latch"]["latched"] is False
        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["candidate_score"] >= NO_GO
        assert body["baseline_score"] < NO_GO
        assert len(body["introduced_blocking_ids"]) == 1


class TestPullRequestFirstFindings:
    """B2: a squash merge's commit never first-sees what its pull request
    reported, and `last_seen_scan_run_id` is overwritten by any scan."""

    def test_a_high_last_seen_by_another_pull_request_is_still_introduced(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _pr_scan(client, run_compaction, "pr-7", F1, "2026-11-14T02:00:00", 7,
                 [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        # Another open pull request, based on the branch, carries it now.
        _pr_scan(client, run_compaction, "pr-8", F2, "2026-11-14T05:00:00", 8,
                 [_sast("H1", "high")])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["introduced"] == {"high": 1}

    def test_a_pull_request_first_scanned_before_the_deployed_commit_counts(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """Opened before D was pushed, scanned again after, merged as C."""
        _pr_scan(client, run_compaction, "pr-7a", F1, "2026-11-13T02:00:00", 7,
                 [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _pr_scan(client, run_compaction, "pr-7b", F2, "2026-11-13T06:00:00", 7,
                 [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)

    def test_a_finding_only_its_own_open_pull_request_has_is_on_neither_side(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """The other direction: an unmerged pull request's high does not
        refuse a deploy of the branch."""
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T03:00:00", [])
        _pr_scan(client, run_compaction, "pr-9", F1, "2026-11-14T05:00:00", 9,
                 [_sast("H9", "high")])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert body["introduced"] == {}


class TestACandidateOlderThanTheHead:
    """B3: the snapshot is the backlog now, so a high C introduced and a later
    commit fixed was closed, and absent from both scores."""

    def test_a_high_a_later_commit_fixed_still_ships_with_the_older_one(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-e1", E1, "2026-11-14T04:00:00", [])
        _push_scan(client, run_compaction, "run-e2", E2, "2026-11-14T05:00:00", [])
        reconcile_absences(client.app.state.catalog)
        status = client.app.state.catalog.query(
            "SELECT status FROM findings WHERE rule_id = 'H1'"
        )
        assert status == [("fixed",)]
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["introduced"] == {"high": 1}
        assert body["candidate_score"] > body["baseline_score"]


class TestTheCreepLedger:
    """B4: the tolerance was per deploy, so a rise could creep without limit."""

    def test_small_rises_that_shipped_add_up(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        lows = [_sast(f"L{i}", "low") for i in range(5)]
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", lows[:3])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00", lows[:4])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", lows)
        _decide(client, oracle_auth, C1)
        _decide(client, oracle_auth, C)

        first = _gate(client, viewer_auth, C1, deployed=D)
        again = _gate(client, viewer_auth, C1, deployed=D)
        # C1 is deployed; the next check names it as what runs.
        second = _gate(client, viewer_auth, C, deployed=C1)

        assert first["allow"] is True, first
        assert 0 < first["score_delta"] <= TOLERANCE
        assert 0 < second["score_delta"] <= TOLERANCE
        assert second["allow"] is False, second
        assert _codes_of(second) == [SCORE_RAISED]
        assert again["accepted_creep"] == 0.0  # asked twice, not deployed twice
        assert second["accepted_creep"] == pytest.approx(first["score_delta"], abs=0.01)

    def test_only_a_deploy_seen_running_adds_and_a_fall_pays_it_back(self, client) -> None:
        db = client.app.state.db
        measured: list[tuple[str, str]] = []

        def hand_deploy(frm: str, to: str) -> float:
            measured.append((frm, to))
            return 0.2

        def settle(sha: str) -> float:
            return deploy_gate.settle_creep(db, REPO, sha, measure=hand_deploy)

        assert settle(D) == 0.0  # the starting point
        deploy_gate.record_pending(db, REPO, candidate=C1, baseline=D, delta=0.3)
        assert settle(D) == 0.0  # never deployed
        assert settle(C1) == pytest.approx(0.3)
        assert settle(C1) == pytest.approx(0.3)  # added once
        deploy_gate.record_pending(db, REPO, candidate=C, baseline=C1, delta=0.15)
        assert settle(C) == pytest.approx(0.45)
        deploy_gate.record_pending(db, REPO, candidate=E1, baseline=C, delta=-0.1)
        assert settle(E1) == pytest.approx(0.35)
        deploy_gate.record_pending(db, REPO, candidate=E2, baseline=E1, delta=-2.0)
        assert settle(E2) == 0.0  # never below zero
        assert measured == []  # every one was pending
        assert settle(F1) == pytest.approx(0.2)  # never asked about: measured
        assert measured == [(E2, F1)]
        assert settle(E2) == pytest.approx(0.4)  # and back by hand, measured again
        assert measured[-1] == (F1, E2)
        assert settle(E2) == pytest.approx(0.4)
        deploy_gate.record_pending(db, REPO, candidate=E1, baseline=E2, delta=-2.0)
        assert settle(E1) == 0.0
        with db.session() as session:
            assert session.get(OracleRatchetCreep, REPO).confirmed_sha == E1


class TestTheCreepLedgerUnderARace:
    """TheHub #61730 (1): the pending set was read, changed in Python and
    written back whole, so a write by a concurrent deploy-gate call between
    the read and the write was lost. Each test lands that write at the worst
    moment, from inside the reader's own parse of the pending set."""

    @staticmethod
    def _interleave(monkeypatch: pytest.MonkeyPatch, concurrent: Any) -> None:
        real = deploy_gate._pending
        fired: list[bool] = []

        def racing(*args: Any) -> Any:
            if not fired:
                fired.append(True)
                concurrent()
            return real(*args)

        monkeypatch.setattr(deploy_gate, "_pending", racing)

    @staticmethod
    def _row(db: Any) -> OracleRatchetCreep:
        with db.session() as session:
            row = session.get(OracleRatchetCreep, REPO)
            assert row is not None
            session.expunge(row)
            return row

    def test_two_concurrent_records_both_stay_pending(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = client.app.state.db
        deploy_gate.settle_creep(db, REPO, D, measure=lambda a, b: 0.0)
        self._interleave(monkeypatch, lambda: deploy_gate.record_pending(
            db, REPO, candidate=C1, baseline=D, delta=0.3))

        deploy_gate.record_pending(db, REPO, candidate=C, baseline=D, delta=0.2)

        assert set(json.loads(self._row(db).pending_json)) == {C1, C}

    def test_a_record_never_writes_back_what_a_settle_cleared(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = client.app.state.db
        deploy_gate.settle_creep(db, REPO, D, measure=lambda a, b: 0.0)
        deploy_gate.record_pending(db, REPO, candidate=C1, baseline=D, delta=0.3)
        # C1 is seen running while another call records E1 against it.
        self._interleave(monkeypatch, lambda: deploy_gate.settle_creep(
            db, REPO, C1, measure=lambda a, b: 0.0))

        deploy_gate.record_pending(db, REPO, candidate=E1, baseline=C1, delta=0.1)

        row = self._row(db)
        assert row.confirmed_sha == C1
        assert row.accepted_creep == pytest.approx(0.3)
        # C1's entry was measured against D, which no longer runs.
        assert set(json.loads(row.pending_json)) == {E1}

    def test_a_settle_that_loses_the_race_reads_again(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = client.app.state.db
        deploy_gate.settle_creep(db, REPO, D, measure=lambda a, b: 0.0)
        deploy_gate.record_pending(db, REPO, candidate=C1, baseline=D, delta=0.3)
        self._interleave(monkeypatch, lambda: deploy_gate.settle_creep(
            db, REPO, C1, measure=lambda a, b: 0.0))

        # A second caller settles the same deploy: it is added once, not twice.
        assert deploy_gate.settle_creep(
            db, REPO, C1, measure=lambda a, b: 0.0) == pytest.approx(0.3)
        assert self._row(db).accepted_creep == pytest.approx(0.3)

    def test_a_ledger_that_never_stops_changing_is_an_error(
        self, client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = client.app.state.db
        deploy_gate.settle_creep(db, REPO, D, measure=lambda a, b: 0.0)
        monkeypatch.setattr(deploy_gate, "_write_creep", lambda *a, **k: False)

        with pytest.raises(deploy_gate.CreepLedgerContendedError):
            deploy_gate.record_pending(db, REPO, candidate=C, baseline=D, delta=0.2)
        with pytest.raises(deploy_gate.CreepLedgerContendedError):
            deploy_gate.settle_creep(db, REPO, C, measure=lambda a, b: 0.0)


class TestShouldFix:
    def test_fix_credit_uses_the_deployed_commits_first_scan(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """A high introduced on a pull request and fixed inside the range is
        not D's to be credited, however late D was rescanned."""
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _pr_scan(client, run_compaction, "pr-7", F1, "2026-11-13T06:00:00", 7,
                 [_sast("X", "high")])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T01:00:00",
                   [_sast("X", "high")])
        _push_scan(client, run_compaction, "run-e1", E1, "2026-11-14T02:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T03:00:00",
                   [_sast("N1", "medium"), _sast("N2", "medium")])
        reconcile_absences(client.app.state.catalog)
        # The daily image refresh rescans what runs.
        _push_scan(client, run_compaction, "run-d2", D, "2026-11-14T05:00:00", [])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert _codes_of(body) == [SCORE_RAISED]
        assert body["fixed"] == {}

    def test_a_prefix_cannot_borrow_another_commits_decision(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        other = C[:7] + "e" * 33
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, other)

        body = _gate(client, viewer_auth, C[:7])

        assert body["allow"] is False, body
        assert _codes_of(body) == [NO_DECISION]

    def test_a_branchless_history_is_no_baseline(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        """Ingest now requires a branch; older push scans in the lake have none,
        and `coalesce(branch, '')` would make them all one line of history."""
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        catalog = client.app.state.catalog
        for path in catalog.all_files("scan_runs"):
            with catalog.connect() as con:
                con.execute(
                    "CREATE OR REPLACE TABLE _sr AS SELECT * FROM read_parquet(?)", [str(path)]
                )
                con.execute("UPDATE _sr SET branch = NULL")
                con.execute("COPY _sr TO ? (FORMAT PARQUET)", [str(path)])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert _codes_of(body) == [BASELINE_UNKNOWN]
        assert "no branch" in body["reasons"][0]["message"]

    def test_a_repeated_question_is_answered_from_the_cache(
        self, client, run_compaction, oracle_auth, viewer_auth, monkeypatch
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C)
        calls: list[int] = []
        real = deploy_gate.OracleEngine.evaluate

        def counting(self: Any, *args: Any, **kwargs: Any) -> Any:
            calls.append(1)
            return real(self, *args, **kwargs)

        monkeypatch.setattr(deploy_gate.OracleEngine, "evaluate", counting)
        first = _gate(client, viewer_auth, C)
        second = _gate(client, viewer_auth, C)
        # Something it read changed (a scan landed): asked again.
        _push_scan(client, run_compaction, "run-e1", E1, "2026-11-14T05:00:00", [])
        third = _gate(client, viewer_auth, C)

        assert first == second
        assert third["allow"] is True
        assert len(calls) == 2


# -- re-review of 6a448dfc (PR #1171) ------------------------------------------


class TestOnlyThisPlatformIsJudged:
    """N-B1: for another repository the caller names the baseline, and a
    finding first seen off the compared branch's line of history is on
    neither side, so an introduced high answered allow."""

    @pytest.fixture(autouse=True)
    def _not_judged_here(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(deploy_gate, "_TEST_ENFORCEABLE", frozenset(), raising=False)

    def test_a_high_pushed_on_a_feature_branch_before_d_is_not_allowed(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-x", F1, "2026-11-13T02:00:00",
                   [_sast("H1", "high")], branch="feat/x")
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
                   [_sast("H1", "high")])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert _codes_of(body) == [NOT_ENFORCEABLE]

    def test_a_high_on_a_pull_request_scanned_only_before_d_is_not_allowed(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _pr_scan(client, run_compaction, "pr-7", F1, "2026-11-13T02:00:00", 7,
                 [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
                   [_sast("H1", "high")])
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert _codes_of(body) == [NOT_ENFORCEABLE]

    def test_only_this_platform_with_its_own_build_is_enforceable(self) -> None:
        own = deploy_gate.SELF_REPO_FULL_NAME
        assert deploy_gate.enforceable(own, "a" * 40)
        assert deploy_gate.enforceable(own.lower(), "a" * 40)
        assert not deploy_gate.enforceable(own, "")  # caller's word
        # Another owner's repository of the same name is not this platform.
        assert not deploy_gate.enforceable("someone/mykronos", "a" * 40)
        assert not deploy_gate.enforceable("someone/thehub", "a" * 40)
        assert not deploy_gate.enforceable(REPO, "a" * 40)


class TestNoDeployPathEscapesTheLedger:
    """Re-review non-blocking 1: the ledger counted only deploys it allowed and
    remembered, so an evicted entry or a forced deploy shipped its rise free."""

    def _lows(self, client, run_compaction, oracle_auth) -> None:
        lows = [_sast(f"L{i}", "low") for i in range(5)]
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", lows[:3])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00", lows[:4])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", lows)
        for sha in (D, C1, C):
            _decide(client, oracle_auth, sha)

    def test_an_evicted_pending_entry_is_measured_instead(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        self._lows(client, run_compaction, oracle_auth)
        first = _gate(client, viewer_auth, C1, deployed=D)
        db = client.app.state.db
        for i in range(60):  # any viewer can ask about other scored commits
            deploy_gate.record_pending(
                db, REPO, candidate=f"{i:040x}", baseline=D, delta=0.0
            )
        second = _gate(client, viewer_auth, C, deployed=C1)

        assert first["allow"] is True, first
        assert second["allow"] is False, second
        assert _codes_of(second) == [SCORE_RAISED]
        assert second["accepted_creep"] == pytest.approx(first["score_delta"], abs=0.01)

    def test_a_deploy_the_gate_never_allowed_is_counted(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        self._lows(client, run_compaction, oracle_auth)
        start = _gate(client, viewer_auth, D, deployed=D)  # D runs; the ledger starts
        rise = _gate(client, viewer_auth, C1, deployed=D)["score_delta"]
        with client.app.state.db.session() as session:  # forgotten: forced or by hand
            session.get(OracleRatchetCreep, REPO).pending_json = "{}"
        after = _gate(client, viewer_auth, C, deployed=C1)

        assert start["allow"] is True, start
        assert after["allow"] is False, after
        assert _codes_of(after) == [SCORE_RAISED]
        assert after["accepted_creep"] == pytest.approx(rise, abs=0.01)


class TestAFixInsideTheRange:
    """Re-review non-blocking 3: a commit that removes a high introduced inside
    the range was refused as introducing it until reconciliation closed it."""

    def test_the_hotfix_is_not_refused_as_introducing_what_it_removes(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        status = client.app.state.catalog.query(
            "SELECT status FROM findings WHERE rule_id = 'H1'"
        )
        assert status == [("open",)]  # scanned once since: not reconciled
        _decide(client, oracle_auth, C)

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert body["introduced"] == {}
        assert body["introduced_blocking_ids"] == []
        assert body["fix_credit_pending"] == 0

    def test_the_commit_that_introduced_it_still_refuses(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00", [])
        _decide(client, oracle_auth, C1)

        body = _gate(client, viewer_auth, C1)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)


class TestOnlyACompletedScanSaysAFindingIsGone:
    """Re-review of ab9a17d7, R-B1: C's last scan of a capability, of any
    status, decided that C no longer carried a finding, so a failed rescan
    reporting nothing made a high C carries read as fixed."""

    def test_a_failed_rescan_does_not_fix_a_high(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
                   [_sast("H1", "high")])
        _decide(client, oracle_auth, C)
        _push_scan(client, run_compaction, "run-c-failed", C, "2026-11-14T05:00:00", [],
                   status="failure")

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["introduced"] == {"high": 1}

    def test_a_partially_failed_rescan_does_not_fix_a_high(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00", [])
        _push_scan(client, run_compaction, "run-c1", C1, "2026-11-14T03:00:00",
                   [_sast("H1", "high")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
                   [_sast("H1", "high")])
        _decide(client, oracle_auth, C)
        _push_scan(client, run_compaction, "run-c-partial", C, "2026-11-14T05:00:00", [],
                   status="partial_failure")

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is False, body
        assert INTRODUCED_BLOCKING in _codes_of(body)
        assert body["introduced"] == {"high": 1}

    def test_a_failed_rescan_earns_no_fix_credit_note(
        self, client, run_compaction, oracle_auth, viewer_auth
    ) -> None:
        _push_scan(client, run_compaction, "run-d", D, "2026-11-13T04:00:00",
                   [_sast("M1", "medium")])
        _push_scan(client, run_compaction, "run-c", C, "2026-11-14T04:00:00",
                   [_sast("M1", "medium")])
        _decide(client, oracle_auth, C)
        _push_scan(client, run_compaction, "run-c-failed", C, "2026-11-14T05:00:00", [],
                   status="failure")

        body = _gate(client, viewer_auth, C)

        assert body["allow"] is True, body
        assert body["fix_credit_pending"] == 0
