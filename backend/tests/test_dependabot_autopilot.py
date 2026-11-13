"""The Dependabot autopilot (TheHub #61615).

An open pull request by `dependabot[bot]` in a minor/patch group, green on its
current head, is requested for approval in `live` mode, and an approved head
is squash-merged by the App at exactly that sha. `dry-run`, the default, lists
what it would do and changes nothing. Majors, advisories above moderate,
changes outside the group, red or pending checks and a moved head are skipped
with the reason, which the work queue shows.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import agent_work, dependabot_merge, jobs, main
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.approvals import pull_requests
from mykronos.approvals.policy import cached_policy
from mykronos.config import Settings
from mykronos.db.models import ApprovalRequest, AuditLogEntry
from mykronos.github.client import PullRequest, PullRequestFile
from tests.conftest import REPO
from tests.test_onboarding import onboard

SHA = "a" * 40
NEXT_SHA = "b" * 40
GROUP_TITLE = "chore(pip): Bump the pip-minor-patch group in /backend with 2 updates"
GROUP_BRANCH = "dependabot/pip/backend/pip-minor-patch-76c38e876e"
GROUP_BODY = """Bumps the pip-minor-patch group in /backend with 2 updates:

| Package | From | To |
| --- | --- | --- |
| [pydantic](https://github.com/pydantic/pydantic) | `2.14.2` | `2.14.3` |
| [sqlalchemy](https://github.com/sqlalchemy/sqlalchemy) | `2.1.6` | `2.1.8` |

Updates `pydantic` from 2.14.2 to 2.14.3
"""
REQUIRED = ("independent-review", "backend-tests", "secret-hygiene")
GREEN = ("backend-tests", "secret-hygiene", "library-allowlist")


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dependabot"


def _body(name: str) -> str:
    """A real Dependabot description, trimmed to the block that matters."""
    return (FIXTURES / name).read_text(encoding="utf-8")


@dataclass
class FakeMerger:
    calls: list[dict[str, Any]] = field(default_factory=list)

    async def squash_at_head(
        self, repo_full_name: str, number: int, *, head_sha: str, message: str
    ) -> dependabot_merge.MergeResult:
        self.calls.append(
            {"repo": repo_full_name, "number": number, "head_sha": head_sha, "message": message}
        )
        return dependabot_merge.MergeResult(repo_full_name, number, head_sha, "c" * 40)


@pytest.fixture(autouse=True)
def _reset() -> Any:
    jobs.LAST_AUTOPILOT_RUN = None
    yield
    jobs.LAST_AUTOPILOT_RUN = None


@pytest.fixture
def repo(client, admin_auth, github):
    onboard(client, admin_auth)
    github.repos[REPO].branch_protection["main"] = {
        "required_status_checks": {"checks": [{"context": c} for c in REQUIRED]}
    }
    return github.repos[REPO]


def _pr(
    repo: Any,
    *,
    number: int = 11,
    sha: str = SHA,
    title: str = GROUP_TITLE,
    branch: str = GROUP_BRANCH,
    body: str = GROUP_BODY,
    author: str = "dependabot[bot]",
    files: tuple[str, ...] = ("backend/requirements.txt", "backend/requirements-dev.txt"),
    labels: tuple[str, ...] = (),
) -> PullRequest:
    repo.pull_requests = [p for p in repo.pull_requests if p.number != number]
    pr = PullRequest(
        number=number,
        url=f"https://github.test/{REPO}/pull/{number}",
        head_branch=branch,
        title=title,
        head_sha=sha,
        base_branch="main",
        body=body,
        author=author,
        labels=labels,
    )
    repo.pull_requests.append(pr)
    repo.pull_request_files[number] = [
        PullRequestFile(filename=f, status="modified", additions=1, deletions=1, patch="@@ +x")
        for f in files
    ]
    return pr


def _checks(repo: Any, sha: str = SHA, conclusion: str | None = "success", names=GREEN) -> None:
    for name in names:
        repo.check_runs.append({"name": name, "head_sha": sha, "conclusion": conclusion})


def _run(client, mode: str, merger: FakeMerger | None = None) -> jobs.AutopilotRun:
    policy = cached_policy(client.app.state.settings.approval_policy_path)
    merger = merger or FakeMerger()
    return asyncio.run(
        jobs.dependabot_autopilot(
            client.app.state.db,
            policy,
            client.app.state.github_factory,
            mode=mode,
            merger_for=lambda _github: merger,
        )
    )


def _only(run: jobs.AutopilotRun) -> jobs.AutopilotItem:
    [item] = run.items
    return item


def _requests(client) -> list[ApprovalRequest]:
    with client.app.state.db.session() as session:
        rows = list(
            session.execute(
                select(ApprovalRequest).where(ApprovalRequest.duty == pull_requests.DUTY)
            ).scalars()
        )
        for row in rows:
            session.expunge(row)
        return rows


def _approve(client, request_id: str) -> None:
    with client.app.state.db.session() as session:
        session.get(ApprovalRequest, request_id).state = "approved"
        session.commit()


# -- Selection -------------------------------------------------------------------


class TestSelection:
    def test_a_green_group_bump_would_be_requested_in_dry_run(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)

        item = _only(_run(client, "dry-run"))

        assert item.outcome == jobs.WOULD_REQUEST
        assert item.group == "pip-minor-patch"
        assert _requests(client) == []

    def test_only_dependabot_is_looked_at(self, client, repo) -> None:
        _pr(repo, author="someone")
        _checks(repo)

        assert _run(client, "live").items == []
        assert _requests(client) == []

    @pytest.mark.parametrize(
        ("title", "branch"),
        [
            (GROUP_TITLE, "anything"),
            ("chore(npm): Bump the npm-minor-patch group in /frontend with 4 updates", "x"),
            ("whatever", "dependabot/npm_and_yarn/frontend/npm-minor-patch-a4827704b6"),
        ],
    )
    def test_the_group_is_read_from_the_title_or_the_branch(self, title, branch) -> None:
        assert jobs.autopilot_group(title, branch) is not None

    def test_a_bump_outside_the_groups_is_skipped(self, client, repo) -> None:
        _pr(
            repo,
            title="chore(pip): Bump pytest-asyncio from 1.4.1 to 1.4.1.post1 in /backend",
            branch="dependabot/pip/backend/pytest-asyncio-1.4.1.post1",
            body="Bumps [pytest-asyncio](https://x) from 1.4.1 to 1.4.1.post1.",
            files=("backend/requirements-dev.txt",),
        )
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "outside the minor/patch groups" in item.reason
        assert _requests(client) == []

    def test_a_major_is_skipped(self, client, repo) -> None:
        _pr(repo, body=GROUP_BODY + "\n| [httpx2](https://x) | `2.15.1` | `3.0.0` |\n")
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "major" in item.reason and "httpx2" in item.reason
        assert _requests(client) == []

    def test_a_zero_x_minor_counts_as_major(self) -> None:
        assert jobs.is_major("0.156.8", "0.162.0")
        assert not jobs.is_major("0.4.4", "0.4.5")
        assert not jobs.is_major("2.14.2", "2.14.3")
        assert not jobs.is_major("6.0.12.20260906", "6.0.12.20261030")
        assert jobs.is_major("1.9.0", "2.0.0")

    @pytest.mark.parametrize(
        "advisory",
        [
            "Fixes GHSA-abcd-efgh-ijkl, a high severity vulnerability.",
            "Severity: critical. CVE-2026-1234.",
            "A security update for CVE-2026-1234.",  # unstated severity
        ],
    )
    def test_an_advisory_above_moderate_or_unstated_is_skipped(
        self, client, repo, advisory: str
    ) -> None:
        _pr(repo, body=GROUP_BODY + "\n" + advisory)
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "security advisory" in item.reason
        assert _requests(client) == []

    def test_a_real_moderate_advisory_body_goes_ahead(self, client, repo) -> None:
        """#1138's body, verbatim: the severity is a `<h2>Moderate</h2>`
        heading in next.js's quoted release notes, and the GHSA ids are only
        in the links."""
        body = _body("pr-1138-next-moderate.txt")
        assert jobs.advisory_reason("", body, ()) is None
        _pr(
            repo,
            title="chore(npm): Bump the npm-minor-patch group in /frontend with 4 updates",
            branch="dependabot/npm_and_yarn/frontend/npm-minor-patch-a4827704b6",
            body=body,
            files=("frontend/package.json", "frontend/package-lock.json"),
        )
        _checks(repo)

        assert _only(_run(client, "dry-run")).outcome == jobs.WOULD_REQUEST

    @pytest.mark.parametrize("heading", ["High", "Critical"])
    def test_a_real_body_with_a_higher_heading_is_skipped(self, heading: str) -> None:
        body = _body("pr-1138-next-moderate.txt").replace(
            "<h2>Moderate</h2>", f"<h2>{heading}</h2>"
        )

        reason = jobs.advisory_reason("", body, ())

        assert reason is not None and heading.lower() in reason

    def test_a_real_advisory_with_no_severity_is_skipped(self) -> None:
        body = _body("pr-1138-next-moderate.txt").replace("<h2>Moderate</h2>", "")

        assert "does not state" in (jobs.advisory_reason("", body, ()) or "")

    @pytest.mark.parametrize(
        "name", ["pr-1139-pip-group.txt", "pr-1140-badge-only.txt", "pr-1141-badge-only.txt"]
    )
    def test_a_badge_link_is_not_an_advisory(self, name: str) -> None:
        """Every Dependabot body links its compatibility badge to
        `.../managing-security-vulnerabilities/...`; a URL is not an advisory."""
        body = _body(name)
        assert "managing-security-vulnerabilities" in body or name.startswith("pr-1139")

        assert jobs.advisory_reason("", body, ()) is None

    def test_a_moderate_advisory_goes_ahead(self, client, repo) -> None:
        _pr(repo, body=GROUP_BODY + "\nFixes CVE-2026-1234, a moderate severity issue.")
        _checks(repo)

        assert _only(_run(client, "dry-run")).outcome == jobs.WOULD_REQUEST

    def test_a_lockfile_outside_the_group_is_skipped(self, client, repo) -> None:
        _pr(repo, files=("backend/requirements.txt", "frontend/package-lock.json"))
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "frontend/package-lock.json" in item.reason
        assert _requests(client) == []

    def test_a_red_required_check_is_skipped(self, client, repo) -> None:
        _pr(repo)
        _checks(repo, names=("secret-hygiene", "library-allowlist"))
        _checks(repo, conclusion="failure", names=("backend-tests",))

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "red" in item.reason and "backend-tests" in item.reason
        assert _requests(client) == []

    def test_a_pending_or_missing_check_is_skipped(self, client, repo) -> None:
        _pr(repo)
        _checks(repo, names=("backend-tests", "library-allowlist"))

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "pending" in item.reason and "secret-hygiene" in item.reason

    def test_a_neutral_allowlist_is_not_green(self, client, repo) -> None:
        _pr(repo)
        _checks(repo, names=("backend-tests", "secret-hygiene"))
        _checks(repo, conclusion="neutral", names=("library-allowlist",))

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "library-allowlist (neutral)" in item.reason

    def test_checks_are_read_on_the_current_head_only(self, client, repo) -> None:
        _pr(repo, sha=NEXT_SHA)
        _checks(repo, sha=SHA)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "pending" in item.reason

    def test_an_unprotected_branch_is_skipped(self, client, repo) -> None:
        repo.branch_protection.clear()
        _pr(repo)
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.SKIPPED
        assert "unprotected" in item.reason


# -- Requests --------------------------------------------------------------------


class TestRequests:
    def test_live_requests_through_the_approvals_path(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.REQUESTED
        [row] = _requests(client)
        assert row.id == item.request_id
        assert row.subject_ref == pull_requests.subject_ref(REPO, 11, SHA)
        assert row.requested_by == "job:dependabot-autopilot"
        assert row.requester_kind == "automation"

    def test_requesting_again_is_idempotent(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)
        first = _only(_run(client, "live"))

        second = _only(_run(client, "live"))

        assert second.outcome == jobs.AWAITING_APPROVAL
        assert second.request_id == first.request_id
        assert len(_requests(client)) == 1

    def test_an_existing_request_is_already_requested(self, client, repo, monkeypatch) -> None:
        """The 409 path: `propose` refuses a head that already has a request
        (another requester raced it in), and the job reads that as done."""
        _pr(repo)
        _checks(repo)
        policy = cached_policy(client.app.state.settings.approval_policy_path)
        asyncio.run(
            pull_requests.propose(
                client.app.state.db,
                policy,
                client.app.state.github_factory.for_installation(4242),
                requested_by=Principal(
                    actor="someone-else", role=Role.VIEWER, kind=ActorKind.AUTOMATION
                ),
                repo=REPO,
                number=11,
            )
        )
        # The job's own read of live requests misses it, as a race would.
        monkeypatch.setattr(jobs, "_requests_by_pull_request", lambda _db: {})

        item = _only(_run(client, "live"))

        assert item.outcome == jobs.ALREADY_REQUESTED
        assert len(_requests(client)) == 1

    def test_dry_run_lists_without_requesting(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)

        run = _run(client, "dry-run")

        assert _only(run).outcome == jobs.WOULD_REQUEST
        assert _requests(client) == []
        assert jobs.LAST_AUTOPILOT_RUN is run

    def test_off_does_nothing(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)

        assert _run(client, "off").items == []
        assert _requests(client) == []


# -- The merge -------------------------------------------------------------------


class TestTheMerge:
    def _approved(self, client, repo) -> str:
        _pr(repo)
        _checks(repo)
        request_id = _only(_run(client, "live")).request_id
        _approve(client, request_id)
        _checks(repo, names=("independent-review",))
        return request_id

    def test_live_merges_an_approved_head_at_that_head(self, client, repo) -> None:
        request_id = self._approved(client, repo)
        merger = FakeMerger()

        item = _only(_run(client, "live", merger))

        assert item.outcome == jobs.MERGED
        assert merger.calls == [
            {
                "repo": REPO,
                "number": 11,
                "head_sha": SHA,
                "message": merger.calls[0]["message"],
            }
        ]
        assert f"Approval-Request: {request_id}" in merger.calls[0]["message"]
        with client.app.state.db.session() as session:
            actions = [
                e.action
                for e in session.execute(
                    select(AuditLogEntry).where(AuditLogEntry.entity_id == request_id)
                ).scalars()
            ]
        assert "dependabot_autopilot.merged" in actions

    def test_dry_run_never_merges(self, client, repo) -> None:
        self._approved(client, repo)
        merger = FakeMerger()

        item = _only(_run(client, "dry-run", merger))

        assert item.outcome == jobs.WOULD_MERGE
        assert merger.calls == []

    def test_a_moved_head_is_not_merged(self, client, repo) -> None:
        request_id = self._approved(client, repo)
        _pr(repo, sha=NEXT_SHA)
        _checks(repo, sha=NEXT_SHA, names=(*GREEN, "independent-review"))
        merger = FakeMerger()

        item = _only(_run(client, "live", merger))

        assert merger.calls == []
        assert f"head moved since request {request_id}" in item.reason
        assert item.outcome == jobs.REQUESTED  # the new head is judged afresh

    def test_a_pending_request_is_not_merged(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)
        _run(client, "live")
        merger = FakeMerger()

        item = _only(_run(client, "live", merger))

        assert item.outcome == jobs.AWAITING_APPROVAL
        assert merger.calls == []

    def test_an_approval_whose_stamp_is_not_green_waits(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)
        _approve(client, _only(_run(client, "live")).request_id)
        merger = FakeMerger()

        item = _only(_run(client, "live", merger))

        assert item.outcome == jobs.AWAITING_APPROVAL
        assert merger.calls == []

    def test_a_refused_merge_is_recorded_not_raised(self, client, repo) -> None:
        self._approved(client, repo)

        class Refusing(FakeMerger):
            async def squash_at_head(self, *a: Any, **k: Any) -> Any:
                raise dependabot_merge.MergeRefusedError("GitHub refused: 409 head moved")

        item = _only(_run(client, "live", Refusing()))

        assert item.outcome == jobs.MERGE_FAILED
        assert "409" in item.reason


class TestTheAppMerger:
    """`AppSquashMerger`: squash, at the sha, only for Dependabot."""

    def _github(self, author: str = "dependabot[bot]", head: str = SHA) -> Any:
        sent: list[tuple[str, str, dict[str, Any]]] = []

        async def get_pull_request(repo: str, number: int) -> PullRequest:
            return PullRequest(
                number=number, url="", head_branch="b", head_sha=head, author=author
            )

        async def _request(method: str, path: str, **kwargs: Any) -> Any:
            sent.append((method, path, kwargs["json"]))
            return SimpleNamespace(status_code=200, content=b"{}", json=lambda: {"sha": "m"})

        return SimpleNamespace(get_pull_request=get_pull_request, _request=_request, sent=sent)

    def test_it_squashes_at_the_approved_sha(self) -> None:
        github = self._github()
        merger = dependabot_merge.AppSquashMerger(github)

        asyncio.run(merger.squash_at_head(REPO, 11, head_sha=SHA, message="m"))

        [(method, path, body)] = github.sent
        assert (method, path) == ("PUT", f"/repos/{REPO}/pulls/11/merge")
        assert body["merge_method"] == "squash"
        assert body["sha"] == SHA

    @pytest.mark.parametrize(("author", "head"), [("someone", SHA), ("dependabot[bot]", NEXT_SHA)])
    def test_it_refuses_before_asking_github(self, author: str, head: str) -> None:
        github = self._github(author=author, head=head)
        merger = dependabot_merge.AppSquashMerger(github)

        with pytest.raises(dependabot_merge.MergeRefusedError):
            asyncio.run(merger.squash_at_head(REPO, 11, head_sha=SHA, message="m"))
        assert github.sent == []

    def test_a_fake_client_cannot_merge(self, github) -> None:
        with pytest.raises(Exception, match="cannot merge"):
            dependabot_merge.merger_for(github)

    def test_no_other_module_sends_a_merge(self) -> None:
        """spec 08 §3 still holds for everything else: this module is the only
        place in the backend that asks GitHub to merge."""
        root = Path(dependabot_merge.__file__).resolve().parent
        senders = sorted(
            str(p.relative_to(root))
            for p in root.rglob("*.py")
            if re.search(r"pulls/[^\"'\s]*/merge\b", p.read_text(encoding="utf-8"))
        )
        assert senders == ["dependabot_merge.py"]


# -- Surfacing and scheduling ------------------------------------------------------


class TestTheWorkQueue:
    def test_each_pull_request_is_listed_with_its_reason(self, client, repo) -> None:
        _pr(repo)
        _checks(repo)
        _pr(repo, number=12, body=GROUP_BODY + "| [x](y) | `1.0.0` | `2.0.0` |\n")
        _checks(repo)
        run = _run(client, "dry-run")
        queue = agent_work.WorkQueue(generated_at=run.ran_at, actor="a", actor_kind="agent")

        agent_work.add_dependabot_autopilot(queue, run, mode="dry-run")

        details = {w.ref.split("@")[0]: w.detail for w in queue.waiting}
        assert set(details) == {f"{REPO}#11", f"{REPO}#12"}
        assert "would_request" in details[f"{REPO}#11"]
        assert "skipped" in details[f"{REPO}#12"] and "major" in details[f"{REPO}#12"]
        assert all(w.kind == "dependabot_autopilot" for w in queue.waiting)

    def test_before_the_first_run_it_says_so(self) -> None:
        queue = agent_work.WorkQueue(generated_at=None, actor="a", actor_kind="agent")  # type: ignore[arg-type]

        agent_work.add_dependabot_autopilot(queue, None, mode="dry-run")

        [row] = queue.waiting
        assert row.kind == "dependabot_autopilot"
        assert "has not run since" in row.detail

    def test_off_lists_nothing(self) -> None:
        queue = agent_work.WorkQueue(generated_at=None, actor="a", actor_kind="agent")  # type: ignore[arg-type]

        agent_work.add_dependabot_autopilot(queue, None, mode="off")

        assert queue.waiting == []

    def test_the_route_shows_the_last_run(self, client, repo, admin_auth) -> None:
        _pr(repo)
        _checks(repo)
        _run(client, "dry-run")

        body = client.get("/api/agent/work", headers=admin_auth).json()

        [entry] = [w for w in body["waiting"] if w["kind"] == "dependabot_autopilot"]
        assert entry["ref"].startswith(f"{REPO}#11@")


class TestItIsScheduled:
    def _scheduled(self, settings: Settings, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job)

        monkeypatch.setattr(main, "_every", record)
        with TestClient(main.create_app(settings)):
            pass
        return captured

    def test_it_is_scheduled_in_dry_run_by_default(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert settings.dependabot_autopilot_mode == "dry-run"
        settings = settings.model_copy(update={"run_jobs_in_background": True})
        scheduled = self._scheduled(settings, monkeypatch)
        assert scheduled[jobs.DEPENDABOT_AUTOPILOT_JOB][0] == 900

    def test_off_is_not_scheduled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = settings.model_copy(
            update={"run_jobs_in_background": True, "dependabot_autopilot_mode": "off"}
        )
        assert jobs.DEPENDABOT_AUTOPILOT_JOB not in self._scheduled(settings, monkeypatch)

    def test_a_mode_outside_the_three_is_refused(self) -> None:
        with pytest.raises(ValueError):
            Settings(dependabot_autopilot_mode="yes")
