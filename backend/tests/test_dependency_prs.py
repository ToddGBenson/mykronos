"""Open dependency-bot pull requests, linked to the findings they would close (TheHub #60915).

TheHub PR #499 (Dependabot, pypdf 6.20.1 -> 6.21.1) was open and listed under
pull requests, while the five open pypdf findings it fixes said nothing about
it and the briefing offered them a no-fix, accept-risk path. An engineer
triaging those findings should read "a PR that fixes this is open - review
it", and the briefing should count them as a fix waiting for review.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import briefing
from mykronos.dependency_prs import (
    Bump,
    DependencyPr,
    PackageFinding,
    bumps_of,
    fixes_for,
    is_dependency_bot,
)
from mykronos.github.client import GitHubError, PullRequest
from tests.conftest import REPO, dependency_finding, post_findings, post_scan
from tests.test_onboarding import onboard

GROUP_BODY = """Bumps the pip-minor-patch group in /backend with 3 updates: pypdf, fastapi, httpx.

Updates `pypdf` from 6.20.1 to 6.21.1
- [Release notes](https://example.test)

Updates `fastapi` from 0.115.0 to 0.116.2
Updates `httpx` from 0.27.0 to 0.28.1
"""


def _pr(number: int = 499, title: str = "", branch: str = "", body: str = "") -> PullRequest:
    return PullRequest(
        number=number,
        url=f"https://github.com/{REPO}/pull/{number}",
        head_branch=branch,
        title=title,
        body=body,
    )


def _dep_pr(*bumps: Bump, repo: str = REPO, number: int = 499) -> DependencyPr:
    return DependencyPr(
        repo_full_name=repo,
        number=number,
        url=f"https://github.com/{repo}/pull/{number}",
        title="Bump pypdf from 6.20.1 to 6.21.1 in /backend",
        bumps=list(bumps),
    )


def _finding(package: str = "pypdf", fixed: str = "6.21.0", repo: str = REPO) -> PackageFinding:
    return PackageFinding(
        finding_id="f-1",
        repo_full_name=repo,
        capability="atlas",
        package=package,
        fixed_version=fixed,
    )


class TestWhatABotProposes:
    def test_a_single_dependabot_bump(self) -> None:
        assert bumps_of("Bump pypdf from 6.20.1 to 6.21.1 in /backend", "") == [
            Bump("pypdf", "6.20.1", "6.21.1")
        ]

    def test_a_conventional_commit_prefix_is_allowed(self) -> None:
        assert bumps_of("chore(deps): bump pypdf from 6.20.1 to 6.21.1", "") == [
            Bump("pypdf", "6.20.1", "6.21.1")
        ]

    def test_a_group_bump_reads_the_body(self) -> None:
        bumps = bumps_of("chore(pip): Bump the pip-minor-patch group in /backend with 3 updates",
                         GROUP_BODY)

        assert Bump("pypdf", "6.20.1", "6.21.1") in bumps
        assert Bump("fastapi", "0.115.0", "0.116.2") in bumps
        assert len(bumps) == 3

    def test_a_renovate_bump(self) -> None:
        assert bumps_of("chore(deps): update dependency pypdf to v6.21.1", "") == [
            Bump("pypdf", None, "6.21.1")
        ]

    def test_a_bot_is_known_by_its_branch(self) -> None:
        assert is_dependency_bot(_pr(branch="dependabot/pip/backend/pypdf-6.21.1"))
        assert is_dependency_bot(_pr(branch="renovate/pypdf-6.x"))
        assert not is_dependency_bot(_pr(branch="feat/bump-pypdf"))


class TestWhichFindingsItCloses:
    def test_a_bump_at_or_above_the_fix_links(self) -> None:
        linked = fixes_for(_finding(fixed="6.21.0"), [_dep_pr(Bump("pypdf", "6.20.1", "6.21.1"))])

        assert [(p.number, p.package, p.to_version) for p in linked] == [(499, "pypdf", "6.21.1")]

    def test_exactly_the_fixed_version_links(self) -> None:
        assert fixes_for(_finding(fixed="6.21.1"), [_dep_pr(Bump("pypdf", None, "6.21.1"))])

    def test_a_bump_below_the_fix_does_not(self) -> None:
        assert fixes_for(_finding(fixed="6.21.0"), [_dep_pr(Bump("pypdf", None, "6.20.2"))]) == []

    def test_numeric_order_not_string_order(self) -> None:
        """6.10 is above 6.9, though "6.10" sorts below "6.9" as text."""
        assert fixes_for(_finding(fixed="6.9.0"), [_dep_pr(Bump("pypdf", None, "6.10.0"))])

    def test_another_repository_does_not(self) -> None:
        pr = _dep_pr(Bump("pypdf", None, "6.21.1"), repo="example-org/other")

        assert fixes_for(_finding(), [pr]) == []

    def test_another_package_does_not(self) -> None:
        assert fixes_for(_finding(), [_dep_pr(Bump("pypdf2", None, "9.0.0"))]) == []

    def test_package_names_compare_as_pypi_does(self) -> None:
        pr = _dep_pr(Bump("typing_extensions", None, "4.12.0"))

        assert fixes_for(_finding(package="Typing-Extensions", fixed="4.11.0"), [pr])

    @pytest.mark.parametrize("fixed", ["", "Link to advisory", "not a version"])
    def test_no_comparable_fix_links_nothing(self, fixed: str) -> None:
        assert fixes_for(_finding(fixed=fixed), [_dep_pr(Bump("pypdf", None, "6.21.1"))]) == []


def _pypdf_finding() -> dict[str, Any]:
    return dependency_finding(package_name="pypdf", raw_finding_json={"fixed_version": "6.21.0"})


class TestTheBriefing:
    def test_a_class_counts_its_fixes_waiting_for_review(
        self, client: TestClient, auth: dict[str, str], catalog: Any, run_compaction: Any
    ) -> None:
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                dependency_finding(
                    rule_id="CVE-2026-0001",
                    package_name="pypdf",
                    raw_finding_json={"fixed_version": "6.21.0"},
                ),
                dependency_finding(
                    rule_id="CVE-2026-0002",
                    package_name="pypdf",
                    raw_finding_json={"fixed_version": "6.22.0"},
                ),
            ],
        )
        run_compaction()

        result = briefing.build(
            catalog, dependency_prs=[_dep_pr(Bump("pypdf", "6.20.1", "6.21.1"))]
        )

        (entry,) = result.classes
        assert entry.fix_waiting_for_review == 1
        assert entry.waiting_pull_requests == [f"{REPO}#499"]
        assert "1 of these have a fix waiting for review" in briefing.render(result)
        assert f"{REPO}#499" in briefing.render(result)

    def test_unread_pull_requests_count_nothing(
        self, client: TestClient, auth: dict[str, str], catalog: Any, run_compaction: Any
    ) -> None:
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [_pypdf_finding()],
        )
        run_compaction()

        (entry,) = briefing.build(catalog).classes

        assert entry.fix_waiting_for_review == 0


class TestTheFindingDetail:
    def _seed(
        self, client: TestClient, admin_auth: dict[str, str], auth: dict[str, str],
        catalog: Any, run_compaction: Any,
    ) -> str:
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [_pypdf_finding()],
        )
        run_compaction()
        return str(catalog.query("SELECT finding_id FROM findings")[0][0])

    def test_it_names_the_pull_request_that_would_fix_it(
        self, client: TestClient, admin_auth: dict[str, str], auth: dict[str, str],
        catalog: Any, run_compaction: Any, github: Any,
    ) -> None:
        finding_id = self._seed(client, admin_auth, auth, catalog, run_compaction)
        github.repos[REPO].pull_requests.append(
            _pr(
                title="Bump pypdf from 6.20.1 to 6.21.1 in /backend",
                branch="dependabot/pip/backend/pypdf-6.21.1",
            )
        )

        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=admin_auth).json()

        assert body["fix_pull_requests_unread"] is False
        assert body["fix_pull_requests"] == [
            {
                "repo_full_name": REPO,
                "number": 499,
                "url": f"https://github.com/{REPO}/pull/499",
                "title": "Bump pypdf from 6.20.1 to 6.21.1 in /backend",
                "package": "pypdf",
                "to_version": "6.21.1",
            }
        ]

    def test_a_human_pull_request_is_not_offered(
        self, client: TestClient, admin_auth: dict[str, str], auth: dict[str, str],
        catalog: Any, run_compaction: Any, github: Any,
    ) -> None:
        finding_id = self._seed(client, admin_auth, auth, catalog, run_compaction)
        github.repos[REPO].pull_requests.append(
            _pr(title="Bump pypdf from 6.20.1 to 6.21.1", branch="feat/pypdf")
        )

        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=admin_auth).json()

        assert body["fix_pull_requests"] == []

    def test_an_unreachable_github_is_said_not_hidden(
        self, client: TestClient, admin_auth: dict[str, str], auth: dict[str, str],
        catalog: Any, run_compaction: Any, github: Any, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        finding_id = self._seed(client, admin_auth, auth, catalog, run_compaction)

        async def down(*_args: Any, **_kwargs: Any) -> list[PullRequest]:
            raise GitHubError("GitHub is down")

        monkeypatch.setattr(github, "list_open_pull_requests", down)

        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=admin_auth).json()

        assert body["fix_pull_requests"] == []
        assert body["fix_pull_requests_unread"] is True

    def test_the_record_the_page_reads_carries_it_too(
        self, client: TestClient, admin_auth: dict[str, str], auth: dict[str, str],
        catalog: Any, run_compaction: Any, github: Any,
    ) -> None:
        finding_id = self._seed(client, admin_auth, auth, catalog, run_compaction)
        github.repos[REPO].pull_requests.append(
            _pr(
                title="Bump pypdf from 6.20.1 to 6.21.1 in /backend",
                branch="dependabot/pip/backend/pypdf-6.21.1",
            )
        )

        body = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()

        assert [p["number"] for p in body["fix_pull_requests"]] == [499]
        assert body["fix_pull_requests_unread"] is False

    def test_a_viewer_sees_it_without_the_raw_record(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth: dict[str, str],
        auth: dict[str, str], catalog: Any, run_compaction: Any, github: Any,
    ) -> None:
        """The fixed version lives in the raw record a viewer is not sent."""
        finding_id = self._seed(client, admin_auth, auth, catalog, run_compaction)
        github.repos[REPO].pull_requests.append(
            _pr(title="Bump pypdf from 6.20.1 to 6.21.1", branch="dependabot/pip/pypdf-6.21.1")
        )

        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=viewer_auth).json()

        assert [p["number"] for p in body["fix_pull_requests"]] == [499]
