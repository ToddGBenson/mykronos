"""The review inbox's recommendations (scripts/review_inbox.py).

`scripts/review-inbox.ps1` asks the operator agree-or-not on every pending
approval request. What it offers, and what it recommends, is decided here:

- a request the operator cannot or should not decide is not offered, with the
  reason: a superseded head, a closed PR, the operator's own request;
- a PR with a red or running check is WAIT, whatever else is true;
- the reviewer's reject on governance is advice (governance always goes to a
  person by rule), but on any other tier it makes the item CHECK;
- a risk acceptance with no premise or control, a critical finding, a high
  residual or a long term is CHECK; a container image's patched package is
  shown, not flagged, because it is not a patched image.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import review_inbox as inbox  # noqa: E402

NOW = "2026-10-15T00:00:00+00:00"
SHA = "a" * 40


def run(name: str, conclusion: str = "SUCCESS", status: str = "COMPLETED") -> dict[str, Any]:
    return {"__typename": "CheckRun", "name": name, "status": status, "conclusion": conclusion}


def pr_request(
    number: int = 7, sha: str = SHA, tier: str = "production", **kw: Any
) -> dict[str, Any]:
    return {
        "request": {
            "id": f"req-{number}-{sha[:4]}",
            "duty": "pull_request_merge",
            "tier": tier,
            "subject_ref": f"o/r#{number}@{sha}",
            "requested_by": kw.get("requested_by", "agent:x:1"),
            "requester_statement": "claim",
            "evidence_digest": "d" * 64,
            "expires_at": NOW,
            "decisions": kw.get("decisions", []),
        },
        "evidence": {
            "number": number,
            "title": "a change",
            "head_sha": sha,
            "files": [
                {
                    "path": "a.py",
                    "class": "routine",
                    "status": "modified",
                    "additions": 1,
                    "deletions": 0,
                }
            ],
        },
        "evidence_digest": "d" * 64,
    }


def pr_state(
    number: int = 7, sha: str = SHA, state: str = "OPEN", checks: list[Any] | None = None
) -> dict[str, Any]:
    return {
        str(number): {
            "number": number,
            "state": state,
            "headRefOid": sha,
            "statusCheckRollup": checks if checks is not None else [run("backend-tests")],
        }
    }


def ra_request(**ev: Any) -> dict[str, Any]:
    evidence = {
        "risk_acceptance_id": "ra-1",
        "repo": "o/r",
        "scope": {"capability": "containers", "image": "img", "rule_ids": ["CVE-1"]},
        "response": "accept",
        "deviation_type": "risk_adjustment",
        "justification": "why",
        "residual": {"likelihood": "low", "impact": "moderate", "severity": "low"},
        "premises": [{"type": "not_internet_facing", "asserts": "no route"}],
        "compensating_controls": [],
        "milestones": [{"title": "upgrade", "due": "2026-11-14"}],
        "risk_owner": "admin",
        "requested_until": "2026-12-14",
        "matched": {"findings": 2, "by_severity": {"high": 2}},
    }
    evidence.update(ev)
    return {
        "request": {
            "id": "req-ra",
            "duty": "risk_acceptance",
            "tier": "low",
            "subject_ref": "ra-1",
            "requested_by": "agent:x:1",
            "evidence_digest": "e" * 64,
            "decisions": [],
        },
        "evidence": evidence,
        "evidence_digest": "e" * 64,
    }


def build(requests: list[Any], prs: dict[str, Any] | None = None, **kw: Any) -> dict[str, Any]:
    bundle = {"operator": "admin", "now": NOW, "requests": requests, "prs": prs or {}, **kw}
    return inbox.build(bundle)


def only(result: dict[str, Any]) -> dict[str, Any]:
    assert len(result["offered"]) == 1, result
    return result["offered"][0]


# -- What is offered -----------------------------------------------------------


def test_a_green_pr_is_agree() -> None:
    item = only(build([pr_request()], pr_state()))
    assert item["recommendation"] == inbox.AGREE
    assert item["pr_number"] == 7
    assert len(item["approve_rationale"]) >= inbox.MIN_RATIONALE_CHARS
    assert item["evidence_digest"] == "d" * 64


def test_a_superseded_head_is_not_offered() -> None:
    result = build([pr_request(sha="b" * 40)], pr_state(sha=SHA))
    assert result["offered"] == []
    assert "superseded" in result["skipped"][0]["why_not"]


def test_a_closed_pr_is_not_offered() -> None:
    result = build([pr_request()], pr_state(state="MERGED"))
    assert result["offered"] == [] and "merged" in result["skipped"][0]["why_not"]


def test_the_operators_own_request_is_not_offered() -> None:
    result = build([pr_request(requested_by="admin")], pr_state())
    assert result["offered"] == [] and "you opened" in result["skipped"][0]["why_not"]


def test_a_request_already_answered_is_not_offered() -> None:
    answered = [{"approver": "admin", "verdict": "needs_info"}]
    result = build([pr_request(decisions=answered)], pr_state())
    assert result["offered"] == [] and "already answered" in result["skipped"][0]["why_not"]


# -- Pull request recommendations ------------------------------------------------


def test_a_red_check_is_wait() -> None:
    item = only(build([pr_request()], pr_state(checks=[run("backend-tests", "FAILURE")])))
    assert item["recommendation"] == inbox.WAIT and "backend-tests failed" in item["why"]


def test_a_running_check_is_wait() -> None:
    item = only(build([pr_request()], pr_state(checks=[run("backend-tests", "", "IN_PROGRESS")])))
    assert item["recommendation"] == inbox.WAIT


def test_independent_review_pending_is_not_a_reason_to_wait() -> None:
    """It is the check this decision produces."""
    rollup = [run("backend-tests"), run("independent-review", "", "QUEUED")]
    assert only(build([pr_request()], pr_state(checks=rollup)))["recommendation"] == inbox.AGREE


def test_the_latest_run_of_a_check_wins() -> None:
    assert inbox.checks([run("t", "FAILURE"), run("t")]) == {"t": "pass"}
    assert inbox.checks([{"context": "ci", "state": "PENDING"}]) == {"ci": "pending"}


def test_the_reviewers_reject_on_governance_is_advice() -> None:
    shadow = [
        {
            "request_id": "req-7-aaaa",
            "shadow_verdict": "reject",
            "shadow_rationale": "governance goes to a person",
        }
    ]
    item = only(build([pr_request(tier="governance")], pr_state(), shadow=shadow))
    assert item["recommendation"] == inbox.AGREE
    assert any("advice" in line for line in item["lines"])


def test_the_reviewers_reject_elsewhere_is_check() -> None:
    shadow = [{"request_id": "req-7-aaaa", "shadow_verdict": "reject", "shadow_rationale": "wrong"}]
    item = only(build([pr_request(tier="production")], pr_state(), shadow=shadow))
    assert item["recommendation"] == inbox.CHECK and "reviewer said reject" in item["why"]


# -- Risk acceptance recommendations ---------------------------------------------


def test_a_backed_time_boxed_acceptance_is_agree() -> None:
    item = only(build([ra_request()]))
    assert item["recommendation"] == inbox.AGREE
    assert any("premise" in line for line in item["lines"])


def test_an_acceptance_with_nothing_backing_it_is_check() -> None:
    item = only(build([ra_request(premises=[], compensating_controls=[])]))
    assert item["recommendation"] == inbox.CHECK and "no premise" in item["why"]


def test_a_critical_finding_is_check() -> None:
    item = only(build([ra_request(matched={"findings": 1, "by_severity": {"critical": 1}})]))
    assert "critical" in item["why"]


def test_a_long_acceptance_is_check() -> None:
    item = only(build([ra_request(requested_until="2027-10-01")]))
    assert item["recommendation"] == inbox.CHECK and "days" in item["why"]


def test_a_container_patched_package_is_shown_not_flagged() -> None:
    matched = {"findings": 2, "by_severity": {"high": 2}, "with_fixed_version": 1}
    item = only(build([ra_request(matched=matched)]))
    assert item["recommendation"] == inbox.AGREE
    assert any("not a patched image" in line for line in item["lines"])


def test_a_published_fix_outside_containers_is_check() -> None:
    item = only(
        build(
            [
                ra_request(
                    scope={"capability": "sca", "rule_ids": ["CVE-1"]},
                    matched={"findings": 1, "by_severity": {"high": 1}, "with_fixed_version": 1},
                )
            ]
        )
    )
    assert item["recommendation"] == inbox.CHECK and "published fix" in item["why"]


# -- Notices and ordering ----------------------------------------------------------


def test_expiring_and_expired_acceptances_and_samples_are_reported() -> None:
    acceptances = [
        {"id": "soon0000", "repo": "o/r", "status": "active", "expires_at": "2026-10-20T00:00:00"},
        {"id": "past0000", "repo": "o/r", "status": "active", "expires_at": "2026-10-01T00:00:00"},
        {"id": "late0000", "repo": "o/r", "status": "active", "expires_at": "2027-01-01T00:00:00"},
    ]
    notices = build([], acceptances=acceptances, samples=2)["notices"]
    assert any("soon0000" in n and "ends in" in n for n in notices)
    assert any("past0000" in n and "past its end" in n for n in notices)
    assert not any("late0000" in n for n in notices)
    assert any("2 sampled" in n for n in notices)


def test_agree_items_come_first() -> None:
    red = pr_request(number=8)
    result = build([red, ra_request()], pr_state(number=8, checks=[run("t", "FAILURE")]))
    assert [i["recommendation"] for i in result["offered"]] == [inbox.AGREE, inbox.WAIT]


def test_the_cli_prints_json(tmp_path: Path, capsys: Any) -> None:
    path = tmp_path / "in.json"
    bundle = {"operator": "admin", "now": NOW, "requests": [ra_request()]}
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert inbox.main(["review_inbox.py", "build", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["counts"] == {inbox.AGREE: 1}
