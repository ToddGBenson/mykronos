"""The benchmark lane's run record (spec 23 §1.6, TheHub #60742).

`scripts/bench_grade.py` grades the detectors against the seeded corpus, but
nothing ran it, so no per-rule figure existed anywhere and no change to triage
could be graded. These tests pin the record the `bench` Concourse job leaves:

* a graded run stores per-capability recall and per-rule figures with both
  commits, and the read API returns them;
* every run that could not be graded is stored too, with its reason, and
  reports a status the job turns red. "Never an empty success" is the
  property most worth pinning: a corpus that does not exist yet must not read
  as a detector that is fine.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import bench
from mykronos.db.models import Organization, RepoOnboarding
from mykronos.github.client import FakeGitHubClient
from tests.conftest import (
    INSTALLATION,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)

BENCH = "example-org/mykronos-bench"
PLATFORM = "example-org/platform"
BENCH_COMMIT = "b3c4d5e6f7a8"
PLATFORM_COMMIT = "0123456789ab"

MANIFEST = """
version: "1.0"
seeded:
  - id: sqli-orders
    file: src/orders/lookup.py
    line_start: 42
    line_end: 44
    capability: sast
    description: Order id concatenated into SQL.
  - id: xss-profile
    file: src/profile/view.py
    line_start: 10
    capability: sast
  - id: aws-key
    file: config/settings.py
    line_start: 3
    capability: secrets
"""


def _onboard(client: TestClient, repo: str, *, synthetic: bool) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        org = session.query(Organization).filter_by(github_org_login="example-org").first()
        if org is None:
            org = Organization(github_org_login="example-org")
            session.add(org)
            session.flush()
        session.add(
            RepoOnboarding(
                org_id=org.id,
                github_repo_full_name=repo,
                github_installation_id=INSTALLATION,
                status="active",
                enabled_capabilities=["sast", "secrets"],
                default_branch="main",
                synthetic=synthetic,
            )
        )


def _scan_bench(
    client: TestClient,
    run_compaction: Any,
    findings: list[dict[str, Any]],
    *,
    capability: str = "sast",
    scan_run_id: str = "22222222-2222-2222-2222-222222222222",
) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, BENCH, 'sast', 'secrets')}"}
    assert (
        post_scan(
            client,
            auth,
            scan_run_id=scan_run_id,
            repo_full_name=BENCH,
            capability=capability,
            commit_sha=BENCH_COMMIT,
            pr_number=None,
            triggered_by="push",
            finding_count=len(findings),
        ).status_code
        == 200
    )
    if findings:
        response = post_findings(
            client, auth, findings, scan_run_id=scan_run_id, capability=capability
        )
        assert response.status_code == 200, response.text
    run_compaction()


def _seeded_sqli() -> dict[str, Any]:
    return finding_payload(file_path="src/orders/lookup.py", line_start=42)


def _f(capability: str, rule_id: str, file_path: str, line: int | None) -> dict[str, Any]:
    return {
        "capability": capability,
        "rule_id": rule_id,
        "file_path": file_path,
        "line_start": line,
    }


def _grade(client: TestClient, **body: Any) -> Any:
    token = issue_token(client, PLATFORM)  # deliberately no capability grant
    payload = {"bench_repo": BENCH, "platform_commit": PLATFORM_COMMIT, **body}
    return client.post(
        "/api/ingest/bench-run",
        json=payload,
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.fixture
def corpus(github: FakeGitHubClient) -> FakeGitHubClient:
    github.add_repo(BENCH, files={"bench/manifest.yaml": MANIFEST})
    return github


class TestAGradedRun:
    def test_stores_per_capability_recall_and_per_rule_figures_with_both_commits(
        self,
        client: TestClient,
        corpus: FakeGitHubClient,
        run_compaction: Any,
        admin_auth: dict[str, str],
    ) -> None:
        _onboard(client, BENCH, synthetic=True)
        _scan_bench(
            client,
            run_compaction,
            [
                # Hits sqli-orders.
                finding_payload(
                    rule_id="py/sql-injection", file_path="src/orders/lookup.py", line_start=43
                ),
                # Same rule, nowhere near a seed: unmatched.
                finding_payload(
                    rule_id="py/sql-injection", file_path="src/unrelated.py", line_start=7
                ),
            ],
        )

        response = _grade(client)

        assert response.status_code == 200, response.text
        run = response.json()
        assert run["status"] == "graded"
        assert run["platform_commit"] == PLATFORM_COMMIT
        assert run["bench_commit"] == BENCH_COMMIT
        assert run["scan_runs"] >= 1

        caps = {c["capability"]: c for c in run["capabilities"]}
        assert caps["sast"]["seeded_total"] == 2
        assert caps["sast"]["seeded_detected"] == 1
        assert caps["sast"]["recall"] == 0.5
        assert caps["sast"]["scanned"] is True
        # No secrets scan ran at this commit: not measured, which is not 0%.
        assert caps["secrets"]["scanned"] is False
        assert caps["secrets"]["seeded_detected"] == 0
        assert caps["secrets"]["recall"] is None

        rules = {(r["capability"], r["rule_id"]): r for r in run["rules"]}
        rule = rules[("sast", "py/sql-injection")]
        assert rule["findings"] == 2
        assert rule["matched"] == 1
        assert rule["unmatched"] == 1
        assert rule["seeds_detected"] == 1
        assert rule["recall"] == 0.5
        assert rule["precision_floor"] == 0.5
        assert run["unmatched_findings"] == 1

        listed = client.get("/api/bench/runs", headers=admin_auth)
        assert listed.status_code == 200, listed.text
        latest = listed.json()["runs"][0]
        assert latest["id"] == run["id"]
        assert latest["platform_commit"] == PLATFORM_COMMIT
        assert latest["rules"] == run["rules"]
        assert latest["graded_at"]

    def test_the_manifest_is_read_at_the_graded_commit(
        self,
        client: TestClient,
        corpus: FakeGitHubClient,
        run_compaction: Any,
    ) -> None:
        """The fixtures and the manifest move together; grading one commit's
        findings against another commit's manifest is a grade of neither."""
        _onboard(client, BENCH, synthetic=True)
        _scan_bench(client, run_compaction, [_seeded_sqli()])

        _grade(client)

        assert ("get_file", f"{BENCH}:bench/manifest.yaml@{BENCH_COMMIT}") in corpus.calls

    def test_a_capability_that_scanned_and_missed_is_a_real_zero(
        self, client: TestClient, corpus: FakeGitHubClient, run_compaction: Any
    ) -> None:
        _onboard(client, BENCH, synthetic=True)
        _scan_bench(client, run_compaction, [_seeded_sqli()])
        _scan_bench(
            client,
            run_compaction,
            [],
            capability="secrets",
            scan_run_id="33333333-3333-3333-3333-333333333333",
        )

        caps = {c["capability"]: c for c in _grade(client).json()["capabilities"]}

        assert caps["secrets"]["scanned"] is True
        assert caps["secrets"]["recall"] == 0.0

    def test_a_precision_figure_is_a_floor_and_says_so(self) -> None:
        """Spec 23 §1.3: the corpus is seeded, not clean. An unmatched finding
        may be a real flaw a fixture carries by accident, so matched/reported
        is the least the precision can be, and is never named as more."""
        seeds = bench.parse_manifest(MANIFEST)
        result = bench.grade(
            seeds,
            [
                _f("sast", "r1", "src/orders/lookup.py", 42),
                _f("sast", "r1", "src/elsewhere.py", 1),
                _f("sast", "r1", "src/elsewhere.py", 90),
            ],
        )

        (rule,) = result.rules
        assert rule.precision_floor == pytest.approx(0.333, abs=0.001)
        assert "precision" not in {k for k in rule.as_dict() if k != "precision_floor"}


class TestNeverAnEmptySuccess:
    def test_a_corpus_that_is_not_onboarded_is_not_measured_and_is_stored(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = _grade(client)

        assert response.status_code == 200, response.text
        run = response.json()
        assert run["status"] == "not_measured"
        assert "not onboarded" in run["reason"]
        assert run["capabilities"] == [] and run["rules"] == []
        listed = client.get("/api/bench/runs", headers=admin_auth).json()["runs"]
        assert [r["id"] for r in listed] == [run["id"]]

    def test_a_real_repository_is_never_graded_as_a_corpus(
        self, client: TestClient, corpus: FakeGitHubClient, run_compaction: Any
    ) -> None:
        """`synthetic` is stated at onboarding and never inferred (spec 23
        §1.5). Grading a real repository would score its genuine findings as
        detector hits."""
        _onboard(client, BENCH, synthetic=False)
        _scan_bench(client, run_compaction, [finding_payload()])

        run = _grade(client).json()

        assert run["status"] == "not_measured"
        assert "synthetic" in run["reason"]

    def test_a_corpus_never_scanned_is_not_measured(
        self, client: TestClient, corpus: FakeGitHubClient
    ) -> None:
        _onboard(client, BENCH, synthetic=True)

        run = _grade(client).json()

        assert run["status"] == "not_measured"
        assert "no scan run" in run["reason"]

    def test_an_unreadable_manifest_is_its_own_status(
        self, client: TestClient, github: FakeGitHubClient, run_compaction: Any
    ) -> None:
        github.add_repo(BENCH, files={"bench/manifest.yaml": "seeded: []\n"})
        _onboard(client, BENCH, synthetic=True)
        _scan_bench(client, run_compaction, [finding_payload()])

        run = _grade(client).json()

        assert run["status"] == "manifest_invalid"
        assert "no seeded" in run["reason"]

    def test_a_missing_manifest_is_invalid_not_empty(
        self, client: TestClient, github: FakeGitHubClient, run_compaction: Any
    ) -> None:
        github.add_repo(BENCH, files={})
        _onboard(client, BENCH, synthetic=True)
        _scan_bench(client, run_compaction, [finding_payload()])

        run = _grade(client).json()

        assert run["status"] == "manifest_invalid"
        assert "bench/manifest.yaml" in run["reason"]


class TestAccess:
    def test_no_token_is_401(self, client: TestClient) -> None:
        response = client.post(
            "/api/ingest/bench-run",
            json={"bench_repo": BENCH, "platform_commit": PLATFORM_COMMIT},
        )

        assert response.status_code == 401

    def test_the_read_needs_a_principal(self, client: TestClient) -> None:
        assert client.get("/api/bench/runs").status_code == 401


# --------------------------------------------------------------------------
# The job's reporter: scripts/bench_run.py
# --------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import bench_run  # noqa: E402


class TestTheReporterTurnsTheLaneRed:
    """The pipeline's half of "never an empty success": the job exits with
    the run's verdict, so a run that was not graded is a red lane."""

    def _run(self, answer: Any) -> int:
        def post(url: str, body: dict[str, Any], token: str) -> Any:
            if isinstance(answer, Exception):
                raise answer
            return answer

        return bench_run.main(
            ["--bench-repo", BENCH, "--platform-commit", PLATFORM_COMMIT],
            post=post,
            env={"MYKRONOS_URL": "http://mykronos.test", "MYKRONOS_TOKEN": "t"},
        )

    def test_a_graded_run_is_green(self) -> None:
        assert self._run({"status": "graded", "capabilities": [], "rules": []}) == 0

    @pytest.mark.parametrize("status", ["not_measured", "manifest_invalid"])
    def test_an_ungraded_run_is_red(self, status: str) -> None:
        assert self._run({"status": status, "reason": "why"}) == bench_run.EXIT_NOT_MEASURED

    def test_an_unparseable_answer_is_red(self) -> None:
        assert self._run("<html>proxy error</html>") == bench_run.EXIT_NOT_MEASURED

    def test_an_unreachable_platform_is_red(self) -> None:
        assert self._run(OSError("connection refused")) == bench_run.EXIT_NOT_MEASURED

    def test_an_unknown_status_is_red(self) -> None:
        assert self._run({"status": "something-new"}) == bench_run.EXIT_NOT_MEASURED


# --------------------------------------------------------------------------
# The Concourse job
# --------------------------------------------------------------------------

import yaml  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
VARS = ROOT / "deploy" / "concourse" / "vars" / "mykronos.yml"
SET_PIPELINE = ROOT / "deploy" / "concourse" / "set-pipeline.ps1"
JOB = "bench"


@pytest.fixture(scope="module")
def pipeline() -> dict[str, Any]:
    return yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))


def _job(pipeline: dict[str, Any]) -> dict[str, Any]:
    jobs = {j["name"]: j for j in pipeline["jobs"]}
    assert JOB in jobs, "pipelines/mykronos.yml has no bench job"
    return jobs[JOB]


class TestTheJob:
    def test_it_runs_on_every_main_commit_that_passes_unit(self, pipeline: dict[str, Any]) -> None:
        gets = [s for s in _job(pipeline)["plan"] if s.get("get") == "source"]
        assert len(gets) == 1
        assert gets[0].get("trigger") is True
        assert gets[0].get("passed") == ["unit"]

    def test_it_runs_the_reporter_and_names_the_corpus_by_var(
        self, pipeline: dict[str, Any]
    ) -> None:
        tasks = [s for s in _job(pipeline)["plan"] if "task" in s]
        scripts = " ".join(t["config"]["run"]["args"][-1] for t in tasks)
        assert "scripts/bench_run.py" in scripts
        assert '--bench-repo "$BENCH_REPO"' in scripts
        params = {k: v for t in tasks for k, v in (t.get("params") or {}).items()}
        assert params.get("BENCH_REPO") == "((bench-repo))"

    def test_the_corpus_var_is_in_both_vars_sources(self) -> None:
        repo = yaml.safe_load(VARS.read_text(encoding="utf-8"))["bench-repo"]
        assert f'"bench-repo: {repo}"' in SET_PIPELINE.read_text(encoding="utf-8")

    def test_it_gates_nothing(self, pipeline: dict[str, Any]) -> None:
        """Red until the corpus exists, by design. Nothing may wait on it, or
        a missing corpus would stop the Oracle gate and every deploy."""
        for job in pipeline["jobs"]:
            for step in job.get("plan", []):
                assert JOB not in (step.get("passed") or []), (
                    f"{job['name']} waits on bench: a corpus that is not onboarded "
                    "would hold a real lane"
                )

    def test_it_is_in_a_group(self, pipeline: dict[str, Any]) -> None:
        assert any(JOB in g["jobs"] for g in pipeline["groups"])


class TestOneMatchingRule:
    def test_the_platform_and_the_script_detect_the_same_seeds(self, tmp_path: Path) -> None:
        """`mykronos.bench` and `scripts/bench_grade.py` must give one answer;
        two graders that disagree would make the stored figures unreproducible
        from the command line."""
        import bench_grade

        findings = [
            _f("sast", "a", "src/orders/lookup.py", 48),
            _f("sast", "b", "./src/profile/view.py", None),
            _f("secrets", "c", "config/settings.py", 9),
            _f("sast", "a", "config/settings.py", 3),
        ]
        manifest = tmp_path / "manifest.yaml"
        manifest.write_text(MANIFEST, encoding="utf-8")
        ours = bench.grade(bench.parse_manifest(MANIFEST), findings)
        theirs, unmatched = bench_grade.grade(bench_grade.load_manifest(manifest), findings)

        assert {c.capability: c.seeded_detected for c in ours.capabilities} == {
            k: g.seeded_detected for k, g in theirs.items()
        }
        assert ours.unmatched_findings == len(unmatched)
        assert bench.LINE_TOLERANCE == bench_grade.LINE_TOLERANCE

