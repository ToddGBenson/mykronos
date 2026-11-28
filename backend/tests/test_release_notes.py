"""Release notes for every MyKronos production release (TheHub #61703).

The generator, the storage and the routes. A pull request body is untrusted
input: no markup from it renders, and nothing host-like or credential-shaped
survives into the page.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import release_notes
from mykronos.db.models import Organization, RepoOnboarding
from mykronos.github.client import CommitInfo, Comparison, FakeGitHubClient, PullRequest
from mykronos.oracle.deploy_gate import SELF_REPO_FULL_NAME
from tests.conftest import INSTALLATION

PREV = "a" * 40
MID = "b" * 40
NEW = "c" * 40
SIDE = "e" * 40

#: Built at run time, so the tree holds no credential-shaped literal.
FAKE_TOKEN = "gh" + "p_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"

HOSTILE_BODY = f"""## Summary
The gate refused deploys; see http://10.1.2.3:8080/x and build01.corp.internal for the log.
Token {FAKE_TOKEN} leaked here.

<script>alert(1)</script><img src=x onerror=alert(2)>

## Production check
GET /api/oracle/deploy-gate on 172.16.20.30 answers allow (TheHub #62374).
"""


def _commit(sha: str, message: str, parents: tuple[str, ...]) -> CommitInfo:
    return CommitInfo(sha=sha, message=message, parents=parents)


class TestTheGenerator:
    def test_groups_by_pull_request_with_story_why_and_check(self) -> None:
        commits = [
            _commit(MID, "fix(oracle): ratchet (TheHub #62374) (#1231)", (PREV,)),
            _commit(NEW, "fix(concourse): secrets (TheHub #62376) (#1235)", (MID,)),
        ]
        pulls = {
            1231: PullRequest(number=1231, url="", head_branch="", title=commits[0].message,
                              body="## Summary\nWhy one. More.\n\n## Production check\nCheck one."),
            1235: PullRequest(number=1235, url="", head_branch="", title=commits[1].message,
                              body=("Why two.\n\n## Acceptance criteria\n"
                                    "- [x] done\n- [ ] Check two")),
        }
        items = release_notes.build_items(commits, pulls)
        assert [(i.pr_number, i.stories, i.why, i.check) for i in items] == [
            (1231, ["62374"], "Why one.", "Check one."),
            (1235, ["62376"], "Why two.", "Check two"),
        ]
        assert items[0].title == "fix(oracle): ratchet (TheHub #62374)"

    def test_walks_the_first_parent_line_only(self) -> None:
        commits = [
            _commit(SIDE, "wip on a branch", (PREV,)),
            _commit(MID, "feat: one (#1)", (PREV,)),
            _commit(NEW, "Merge pull request #2 from x/y", (MID, SIDE)),
        ]
        line = release_notes.first_parent(commits, NEW)
        assert [c.sha for c in line] == [MID, NEW]

    def test_hosts_addresses_tokens_and_markup_never_reach_the_page(self) -> None:
        pr = PullRequest(number=7, url="", head_branch="", title="fix: x on host.lan (#7)",
                         body=HOSTILE_BODY)
        release = release_notes.new_release(
            NEW, PREV, [_commit(NEW, "fix: x (#7)", (PREV,))], {7: pr},
            release_notes.SecurityDelta(),
        )
        page = release_notes.render(release)
        for leaked in ("10.1.2.3", "172.16.20.30", "build01.corp.internal", "host.lan",
                       FAKE_TOKEN[:9], "http://", "<script", "<img", "onerror"):
            assert leaked not in page, leaked
        assert "The gate refused deploys; see [url] and [host] for the log." in page
        assert "GET /api/oracle/deploy-gate on [address] answers allow" in page

    def test_the_security_delta_and_rollback_are_on_the_page(self) -> None:
        security = release_notes.SecurityDelta(
            score_before=12.5, score_after=11.0, introduced={"high": 1}, fixed={"critical": 2},
            open_before={"critical": 3, "high": 9}, open_after={"critical": 1, "high": 10},
            gate="allow",
        )
        release = release_notes.new_release(NEW, PREV, [], {}, security)
        page = release_notes.render(release)
        assert "12.50 &rarr; 11.00 (deploy gate: allow)" in page
        assert "Introduced: 0 critical, 1 high; fixed: 2 critical, 0 high" in page
        assert "Open before: 3 critical, 9 high; open after: 1 critical, 10 high" in page
        assert f".\\deploy.ps1 -Tag {PREV}" in page

    def test_open_counts_read_a_decisions_findings_terms(self) -> None:
        snapshot = json.dumps({"terms": [
            {"key": "findings.critical", "inputs": {"count": 2}},
            {"key": "findings.high", "inputs": {"count": 5}},
            {"key": "findings.medium", "inputs": {"count": 40}},
        ]})
        assert release_notes.open_counts(snapshot) == {"critical": 2, "high": 5}


@pytest.fixture
def released(client: TestClient, github: FakeGitHubClient) -> TestClient:
    """This platform's repository onboarded, running NEW, with PREV..NEW on GitHub."""
    with client.app.state.db.session() as session:
        org = Organization(github_org_login="ToddGBenson")
        session.add(org)
        session.flush()
        session.add(RepoOnboarding(
            org_id=org.id, github_repo_full_name=SELF_REPO_FULL_NAME,
            github_installation_id=INSTALLATION, status="active",
            enabled_capabilities=["sast"], default_branch="main",
        ))
    repo = github.add_repo(SELF_REPO_FULL_NAME, files={"README.md": "#"})
    repo.comparisons[(PREV, NEW)] = Comparison(files=[], status="ahead", ahead_by=1, commits=[
        _commit(NEW, "fix: the thing (TheHub #61703) (#9)", (PREV,)),
    ])
    repo.pull_requests.append(PullRequest(
        number=9, url="", head_branch="b", state="closed", merged=True,
        title="fix: the thing (TheHub #61703) (#9)", body=HOSTILE_BODY,
    ))
    client.app.state.settings.build_sha = NEW
    return client


def _post(client: TestClient, auth: dict[str, str], **body: Any) -> Any:
    payload = {"sha": NEW, "previous_sha": PREV, **body}
    return client.post("/api/releases", json=payload, headers=auth)


class TestTheRoutes:
    def test_a_confirmed_deploy_is_kept_listed_and_served_without_script(
        self, released, admin_auth, viewer_auth
    ) -> None:
        gate = {"verdict": "allow", "direction": "forward", "baseline_score": 5.0,
                "candidate_score": 4.5, "introduced": {}, "fixed": {"high": 1}}
        made = _post(released, admin_auth, gate=gate)
        assert made.status_code == 201, made.text
        assert made.json()["pull_requests"] == [9]
        assert made.json()["stories"] == ["61703", "62374"]

        listed = released.get("/api/releases", headers=viewer_auth).json()["releases"]
        assert [r["sha"] for r in listed] == [NEW]

        page = released.get(f"/api/releases/{NEW}", headers=viewer_auth)
        assert page.status_code == 200
        assert page.headers["content-type"].startswith("text/html")
        assert "script-src" not in page.headers["content-security-policy"]
        assert "default-src 'none'" in page.headers["content-security-policy"]
        assert "<script" not in page.text and "172.16.20.30" not in page.text
        assert "5.00 &rarr; 4.50" in page.text

        on_disk = list((released.app.state.settings.datalake_dir / "releases").iterdir())
        assert sorted(p.name for p in on_disk) == [f"{NEW}.html", f"{NEW}.json"]

    def test_a_sha_that_is_not_running_produces_nothing(self, released, admin_auth) -> None:
        released.app.state.settings.build_sha = MID
        assert _post(released, admin_auth).status_code == 409
        assert not (released.app.state.settings.datalake_dir / "releases").exists()

    def test_a_rollback_produces_nothing(self, released, admin_auth) -> None:
        gate = {"verdict": "allow", "direction": "rollback"}
        assert _post(released, admin_auth, gate=gate).status_code == 409
        repo = released.app.state.github_factory.client._repo(SELF_REPO_FULL_NAME)
        repo.comparisons[(PREV, NEW)] = Comparison(files=[], status="behind", behind_by=2)
        assert _post(released, admin_auth).status_code == 409
        assert released.get("/api/releases", headers={"Authorization": "Bearer x"}).status_code in (
            401, 403)

    def test_only_a_person_with_admin_may_record(self, released, viewer_auth) -> None:
        assert _post(released, viewer_auth).status_code in (401, 403)

    def test_an_unknown_sha_is_404_and_a_malformed_one_422(self, released, viewer_auth) -> None:
        assert released.get(f"/api/releases/{MID}", headers=viewer_auth).status_code == 404
        assert released.get("/api/releases/..%2Fsecret", headers=viewer_auth).status_code in (
            404, 422)


class TestDeployAsksOnlyAfterAConfirmedDeploy:
    def test_one_call_on_the_confirmed_branch_and_never_on_a_restore(self) -> None:
        from pathlib import Path

        text = (Path(__file__).resolve().parents[2] / "deploy" / "mykronos" / "deploy.ps1"
                ).read_text(encoding="utf-8")
        calls = [line.strip() for line in text.splitlines()
                 if "Invoke-ReleaseNotes " in line and "function" not in line]
        assert calls == [
            "if (-not $Restore) { Invoke-ReleaseNotes -Sha $running -PreviousSha $previousSha "
            "-Answer $answer }"
        ]
        confirmed = text.index('Write-Host "Confirmed: the backend is running $Tag."')
        mismatch = text.index('Write-Host "MISMATCH: asked for $Tag')
        assert confirmed < text.index(calls[0]) < mismatch
