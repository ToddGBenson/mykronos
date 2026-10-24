"""A risk decision on every pull request again (TheHub #60927, mykronos#340).

`mykronos-oracle.yml` asked the risk engine for a `pr_gate` decision on every
pull request and showed the verdict as a check run. It was deleted in the
Concourse migration (766ca5f, 2026-09-08), and Concourse builds `main` only,
so the last `pr_gate` decision for this repository was 2026-09-05.

`.github/workflows/pr-gate.yml` is the caller that replaces it, and
`scripts/pr_gate.py` is its logic, kept in a file so it can be tested here.
These tests pin the story's three criteria:

- **The check appears on new PRs.** The workflow runs on `opened`,
  `synchronize` and `reopened`, judges the PR's head commit (not GitHub's
  merge commit, which no scan ever sees), and `/api/oracle/evaluate` posts
  `Mykronos / risk decision` on it through the App.
- **A block verdict fails it.** The job fails when the decision says this
  commit introduced a blocking finding (D-048), and when the answer cannot be
  read. Unknown is not a pass.
- **pr_gate decisions resume.** The request names the pull request, and the
  platform records it as `pr_gate`.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from mykronos.api.oracle import EvaluateRequest
from mykronos.oracle.engine import resolve_decision_type
from mykronos.oracle.service import CHECK_RUN_NAME
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "pr-gate.yml"
SCRIPT = ROOT / "scripts" / "pr_gate.py"

HEAD = "5e1d0c4b9a8f7e6d5c4b3a2918273645a1b2c3d4"
PR = 412


@pytest.fixture(scope="module")
def gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pr_gate", SCRIPT)
    assert spec is not None and spec.loader is not None, f"{SCRIPT} is missing"
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr_gate"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def document(text: str) -> dict[str, Any]:
    loaded: dict[Any, Any] = yaml.safe_load(text)
    # PyYAML reads a bare `on:` key as the boolean True.
    loaded["on"] = loaded.pop(True, loaded.get("on"))
    return loaded


def _step(document: dict[str, Any]) -> dict[str, Any]:
    (step,) = [
        s
        for s in document["jobs"]["risk-decision"]["steps"]
        if "scripts/pr_gate.py" in str(s.get("run", ""))
    ]
    return step


def decision(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "decision_id": "d-1",
        "decision_type": "pr_gate",
        "overall_risk_score": 12,
        "recommendation": "go",
        "reasoning": "Nothing new.",
        "policy_version": "1.16",
        "blocking": False,
        "check_run_id": "cr-1",
        "check_run_error": None,
        "introduced": {},
        "disclosed": {},
        "introduced_blocking": False,
    }
    body.update(overrides)
    return body


def env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    values = {
        "MYKRONOS_URL": "https://mykronos.example.test",
        "MYKRONOS_INGESTION_TOKEN": "mki_test_value",
        "PR_NUMBER": str(PR),
        "HEAD_SHA": HEAD,
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    values.update(overrides)
    return values


# -- the workflow ---------------------------------------------------------------


class TestTheWorkflow:
    def test_it_runs_when_a_pull_request_opens_or_moves(self, document: dict[str, Any]) -> None:
        assert set(document["on"]) == {"pull_request"}
        types = set(document["on"]["pull_request"]["types"])
        assert {"opened", "synchronize", "reopened"} <= types

    def test_never_pull_request_target(self, text: str) -> None:
        """`pull_request_target` hands a fork's code the repository's secrets."""
        assert "pull_request_target" not in re.sub(r"#.*", "", text)

    def test_the_token_is_read_only(self, document: dict[str, Any]) -> None:
        """The platform posts the check run through its App. The workflow's own
        token needs nothing but a checkout."""
        assert document["permissions"] == {"contents": "read"}
        for job in document["jobs"].values():
            assert "permissions" not in job

    def test_the_check_is_named_risk_decision(self, document: dict[str, Any]) -> None:
        assert document["jobs"]["risk-decision"]["name"] == "risk-decision"

    def test_there_is_no_path_filter(self, document: dict[str, Any]) -> None:
        """A PR the filter skips never gets a decision (D-110)."""
        trigger = document["on"]["pull_request"]
        assert not trigger.get("paths") and not trigger.get("paths-ignore")

    def test_it_judges_the_head_commit_not_the_merge_commit(
        self, document: dict[str, Any]
    ) -> None:
        """`github.sha` on a pull_request run is GitHub's synthetic merge commit.
        No scan ever sees it, and a check run on it does not show on the PR."""
        step_env = _step(document)["env"]
        assert step_env["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
        assert step_env["PR_NUMBER"] == "${{ github.event.pull_request.number }}"

    def test_the_token_reaches_the_script_through_env_only(
        self, document: dict[str, Any]
    ) -> None:
        step = _step(document)
        assert step["env"]["MYKRONOS_INGESTION_TOKEN"] == (
            "${{ secrets.MYKRONOS_INGESTION_TOKEN }}"
        )
        # Nothing interpolated into the script text itself: an expression in
        # `run:` is pasted into bash before it runs.
        assert "${{" not in step["run"]

    def test_every_action_is_pinned_by_sha(self, document: dict[str, Any]) -> None:
        for job in document["jobs"].values():
            for step in job["steps"]:
                uses = step.get("uses")
                if uses:
                    assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", uses), uses


# -- the request ----------------------------------------------------------------


class TestTheRequest:
    def test_it_asks_for_a_pr_gate_naming_the_pull_request(self, gate: ModuleType) -> None:
        assert gate.request_body(HEAD, PR) == {
            "decision_type": "pr_gate",
            "commit_sha": HEAD,
            "pr_number": PR,
        }

    def test_it_does_not_send_urllibs_default_user_agent(self, gate: ModuleType) -> None:
        """The edge in front of the platform 403s `Python-urllib/3.x` before the
        application sees it. That was this workflow's first run (PR #1001)."""
        request = gate.build_request("https://h.test/api/oracle/evaluate", "t", {})
        agent = request.get_header("User-agent")
        assert agent and "urllib" not in agent.lower()
        assert request.get_header("Authorization") == "Bearer t"

    def test_the_platform_accepts_it_and_keeps_it_a_pr_gate(self, gate: ModuleType) -> None:
        """The endpoint forbids extra fields, so a stray `repo_full_name` would
        be a 422 on every pull request."""
        body = EvaluateRequest(**gate.request_body(HEAD, PR))
        assert (
            resolve_decision_type(
                body.decision_type, commit_sha=body.commit_sha, pr_number=body.pr_number
            )
            == "pr_gate"
        )


# -- the verdict ----------------------------------------------------------------


class TestTheVerdict:
    def test_nothing_introduced_passes(self, gate: ModuleType) -> None:
        refuse, _ = gate.verdict(decision())
        assert refuse is False

    def test_an_introduced_blocking_finding_fails_it(self, gate: ModuleType) -> None:
        refuse, lines = gate.verdict(
            decision(introduced={"high": 2}, introduced_blocking=True)
        )
        assert refuse is True
        assert any("0 critical and 2 high" in line for line in lines)

    @pytest.mark.parametrize("value", [None, "true", 1, "unknown"])
    def test_an_answer_it_cannot_read_fails_it(self, gate: ModuleType, value: Any) -> None:
        """Unknown is not a pass, the same rule the commit gate follows."""
        body = decision(introduced_blocking=value)
        refuse, lines = gate.verdict(body)
        assert refuse is True
        assert any("cannot tell" in line for line in lines)

    def test_a_missing_field_fails_it(self, gate: ModuleType) -> None:
        body = decision()
        del body["introduced_blocking"]
        assert gate.verdict(body)[0] is True

    def test_a_backlog_no_go_is_reported_but_does_not_fail_it(self, gate: ModuleType) -> None:
        """D-048: the score describes the whole backlog, not this change."""
        refuse, lines = gate.verdict(decision(recommendation="no_go", overall_risk_score=88))
        assert refuse is False
        assert any("no_go" in line and "backlog" in line for line in lines)

    def test_a_relabelled_decision_is_called_out(self, gate: ModuleType) -> None:
        _, lines = gate.verdict(decision(decision_type="commit_gate"))
        assert any("commit_gate" in line and "::warning::" in line for line in lines)

    def test_a_check_run_that_was_not_posted_is_called_out(self, gate: ModuleType) -> None:
        _, lines = gate.verdict(decision(check_run_id=None, check_run_error="boom"))
        assert any("::warning::" in line and "boom" in line for line in lines)
        _, lines = gate.verdict(decision(check_run_id=None))
        assert any("::warning::" in line and "no check run" in line for line in lines)


# -- the script end to end ------------------------------------------------------


class TestMain:
    def test_no_token_fails_without_asking(self, gate: ModuleType, tmp_path: Path) -> None:
        """A fork's or Dependabot's run gets no repository secret. Nothing was
        decided, so nothing may read as decided."""
        calls: list[Any] = []
        code = gate.main(
            env(tmp_path, MYKRONOS_INGESTION_TOKEN=""), post=lambda *a: calls.append(a)
        )
        assert code == 1
        assert calls == []

    def test_a_bad_pull_request_number_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        assert gate.main(env(tmp_path, PR_NUMBER=""), post=lambda *a: decision()) == 1

    def test_a_transport_failure_fails(self, gate: ModuleType, tmp_path: Path) -> None:
        def post(*_: Any) -> dict[str, Any]:
            raise OSError("connection refused")

        assert gate.main(env(tmp_path), post=post) == 1

    def test_it_posts_to_evaluate_with_the_bearer_token(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        seen: list[tuple[str, str, dict[str, Any]]] = []

        def post(url: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
            seen.append((url, token, body))
            return decision()

        assert gate.main(env(tmp_path, MYKRONOS_URL="https://h.test/"), post=post) == 0
        assert seen == [
            ("https://h.test/api/oracle/evaluate", "mki_test_value", gate.request_body(HEAD, PR))
        ]

    def test_a_block_verdict_exits_one_and_writes_the_summary(
        self, gate: ModuleType, tmp_path: Path
    ) -> None:
        code = gate.main(
            env(tmp_path),
            post=lambda *_: decision(introduced={"critical": 1}, introduced_blocking=True),
        )
        assert code == 1
        summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
        assert "1 critical and 0 high" in summary


class TestAgainstThePlatform:
    """The script's own request, through the real endpoint, to a fake GitHub."""

    @pytest.fixture
    def through(self, client: TestClient, admin_auth: dict[str, str]) -> Any:
        onboard(client, admin_auth)
        token = issue_token(client, REPO, "sast", "oracle")

        def post(url: str, bearer: str, body: dict[str, Any]) -> dict[str, Any]:
            assert url.endswith("/api/oracle/evaluate")
            response = client.post(
                "/api/oracle/evaluate",
                json=json.loads(json.dumps(body)),
                headers={"Authorization": f"Bearer {bearer}"},
            )
            assert response.status_code == 200, response.text
            result: dict[str, Any] = response.json()
            return result

        return token, post

    def test_a_clean_pull_request_gets_a_pr_gate_and_a_check_run(
        self, gate: ModuleType, through: Any, github: Any, tmp_path: Path, catalog: Any,
        run_compaction: Any,
    ) -> None:
        token, post = through
        code = gate.main(env(tmp_path, MYKRONOS_INGESTION_TOKEN=token), post=post)
        run_compaction()

        assert code == 0
        run = github.repos[REPO].check_runs[-1]
        assert run["name"] == CHECK_RUN_NAME
        assert run["head_sha"] == HEAD
        assert catalog.query(
            "SELECT decision_type, pr_number, commit_sha FROM risk_decisions"
        ) == [("pr_gate", PR, HEAD)]

    def test_a_pull_request_that_introduces_a_critical_fails(
        self, gate: ModuleType, through: Any, client: TestClient, github: Any,
        tmp_path: Path, run_compaction: Any,
    ) -> None:
        token, post = through
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="pr-head", commit_sha=HEAD, pr_number=PR)
        post_findings(
            client, auth, [finding_payload(severity="critical")], scan_run_id="pr-head"
        )
        run_compaction()

        code = gate.main(env(tmp_path, MYKRONOS_INGESTION_TOKEN=token), post=post)

        assert code == 1
        assert github.repos[REPO].check_runs[-1]["head_sha"] == HEAD
