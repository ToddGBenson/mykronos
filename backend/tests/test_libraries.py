"""Libraries: request, vet, approve and manage third-party libraries, and check
pull requests against the allowlist (TheHub epic #60880, #60895-#60898).

No test here touches the network: the vetting sources are a fixture behind
`app.state.library_fetch`, keyed by URL, and GitHub is the in-memory fake.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import libraries, library_check
from mykronos.db.models import ApprovalRequest, LibraryEntry
from mykronos.github import FakeGitHubClient
from mykronos.github.client import PullRequest, PullRequestFile
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_onboarding import onboard

REASON = "We need an HTTP client with retries; the stdlib one has none and urllib3 is lower level."
DEPS = libraries.DEPS_DEV


def _ago(days: int) -> str:
    return (utcnow() - timedelta(days=days)).isoformat() + "Z"


class Registry:
    """OSV and deps.dev, as fixtures. Anything not registered answers 404;
    `down` answers a transport failure (status 0) for every URL."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, Any]] = {}
        self.down = False
        self.calls: list[str] = []

    def package(
        self,
        system: str,
        name: str,
        *,
        versions: list[tuple[str, int]],
        licenses: list[str] | None = None,
        deprecated: tuple[str, ...] = (),
        vulns: list[str] | None = None,
        osv_ecosystem: str = "PyPI",
        score: float | None = 7.5,
        dependencies: int = 3,
    ) -> None:
        """`versions` is (version, days since published); the last is default."""
        base = f"{DEPS}/systems/{system}/packages/{name.replace('/', '%2F').replace('@', '%40')}"
        self.routes[base] = (
            200,
            {
                "versions": [
                    {
                        "versionKey": {"version": v},
                        "publishedAt": _ago(days),
                        "isDefault": i == len(versions) - 1,
                        "isDeprecated": v in deprecated,
                    }
                    for i, (v, days) in enumerate(versions)
                ]
            },
        )
        for v, _ in versions:
            self.routes[f"{base}/versions/{v}"] = (
                200,
                {
                    "licenses": licenses if licenses is not None else ["MIT"],
                    "isDeprecated": v in deprecated,
                    "relatedProjects": [
                        {"projectKey": {"id": f"github.com/x/{name}"},
                         "relationType": "SOURCE_REPO"}
                    ],
                },
            )
            self.routes[f"{base}/versions/{v}:dependencies"] = (
                200,
                {"nodes": [{"relation": "SELF"}]
                 + [{"relation": "INDIRECT"}] * dependencies},
            )
        project = f"{DEPS}/projects/github.com%2Fx%2F{name}"
        self.routes[project] = (
            200, {"scorecard": {"overallScore": score}} if score is not None else {}
        )
        for v, _ in versions:
            self.routes[f"osv:{osv_ecosystem}:{name}:{v}"] = (
                200, {"vulns": [{"id": i} for i in (vulns or [])]}
            )

    async def __call__(
        self, method: str, url: str, body: dict[str, Any] | None
    ) -> tuple[int, Any]:
        self.calls.append(url)
        if self.down:
            return 0, None
        if url == libraries.OSV_URL and body:
            key = f"osv:{body['package']['ecosystem']}:{body['package']['name']}:{body['version']}"
            return self.routes.get(key, (200, {}))
        return self.routes.get(url, (404, None))


@pytest.fixture
def registry(client: TestClient) -> Registry:
    fake = Registry()
    client.app.state.library_fetch = fake
    return fake


def _components(client: TestClient, rows: list[tuple[str, str, str, str]],
                licenses: dict[str, list[str]] | None = None) -> None:
    client.app.state.buffer.append(
        "sbom_components",
        [
            {
                "component_id": f"{repo}:{eco}:{name}:{version}",
                "repo_full_name": repo,
                "commit_sha": "abc",
                "scan_run_id": "run-1",
                "ecosystem": eco,
                "package_name": name,
                "package_version": version,
                "direct": True,
                "purl": f"pkg:{eco}/{name}@{version}",
                "license_ids_json": json.dumps((licenses or {}).get(version))
                if (licenses or {}).get(version) else None,
                "first_seen_at": "2026-09-01T00:00:00",
                "observed_at": "2026-09-01T00:00:00",
            }
            for repo, eco, name, version in rows
        ],
    )


def _request(client: TestClient, headers: dict[str, str], **overrides: Any) -> Any:
    body = {
        "ecosystem": "pypi",
        "package_name": "httpx",
        "version": "0.27.0",
        "reason": REASON,
        "owner": "platform-team",
        **overrides,
    }
    return client.post("/api/libraries/requests", json=body, headers=headers)


def _decide(client: TestClient, admin_auth: dict[str, str], approval_id: str,
            verdict: str, rationale: str) -> Any:
    evidence = client.get(f"/api/approvals/{approval_id}/evidence", headers=admin_auth).json()
    return client.post(
        f"/api/approvals/{approval_id}/decisions",
        json={"verdict": verdict, "rationale": rationale,
              "evidence_digest": evidence["evidence_digest"]},
        headers=admin_auth,
    )


# -- L1: a request is vetted -----------------------------------------------------


class TestVetting:
    def test_a_request_produces_a_vetting_report_with_sources(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.package("PYPI", "httpx", versions=[("0.26.0", 900), ("0.27.0", 400)])

        response = _request(client, admin_auth)

        assert response.status_code == 201, response.text
        report = response.json()["vetting"]
        assert set(report["checks"]) == {
            "typosquat", "vulnerabilities", "license", "maintenance", "scorecard",
            "new_package", "transitive",
        }
        assert all(c["status"] == "ok" for c in report["checks"].values()), report["checks"]
        assert libraries.OSV_URL in report["sources"]
        assert any(s.startswith(f"{DEPS}/systems/PYPI/packages/httpx") for s in report["sources"])
        assert report["checks"]["license"]["licenses"] == ["MIT"]
        assert report["checks"]["scorecard"]["score"] == 7.5
        assert report["checks"]["transitive"]["dependency_count"] == 3
        assert report["flags"] == []
        assert response.json()["tier"] == "clean"

    def test_a_name_one_edit_from_one_the_estate_uses_is_a_suspected_typosquat(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry,
        run_compaction: Any,
    ) -> None:
        _components(client, [("a/one", "pypi", "internal-sdk", "1.0.0")])
        run_compaction()
        registry.package("PYPI", "internal-skd", versions=[("1.0.0", 400)])

        response = _request(client, admin_auth, package_name="internal-skd", version="1.0.0")

        assert response.status_code == 201, response.text
        body = response.json()
        typosquat = body["vetting"]["checks"]["typosquat"]
        assert typosquat["suspected"] is True
        assert typosquat["similar_to"] == ["internal-sdk"]
        assert "typosquat_suspected" in body["vetting"]["flags"]
        assert body["tier"] == "flagged"

    def test_a_package_first_published_last_week_is_new(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.package("PYPI", "shiny-new-thing", versions=[("0.1.0", 7)])

        body = _request(
            client, admin_auth, package_name="shiny-new-thing", version="0.1.0"
        ).json()

        assert body["vetting"]["checks"]["new_package"]["new"] is True
        assert body["vetting"]["checks"]["new_package"]["age_days"] == 7
        assert "new_package" in body["vetting"]["flags"]
        assert body["tier"] == "flagged"

    def test_known_vulnerabilities_are_flagged(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.package("PYPI", "httpx", versions=[("0.27.0", 400)], vulns=["GHSA-aaaa"])

        body = _request(client, admin_auth).json()

        assert body["vetting"]["checks"]["vulnerabilities"]["ids"] == ["GHSA-aaaa"]
        assert body["tier"] == "flagged"

    def test_a_source_that_cannot_be_read_is_unavailable_never_clean(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.down = True

        body = _request(client, admin_auth).json()

        assert body["vetting"]["checks"]["vulnerabilities"]["status"] == "unavailable"
        assert "vulnerabilities" in body["vetting"]["unavailable"]
        assert body["tier"] == "flagged"

    def test_pypi_spellings_are_one_package(self) -> None:
        assert libraries.normalise("pypi", "Python_DateUtil") == "python-dateutil"
        assert libraries.typosquat_candidates("pypi", "python_dateutil", set()) == []
        assert libraries.typosquat_candidates("npm", "lodahs", set()) == ["lodash"]


# -- L2: approval through the approvals duty -----------------------------------


class TestApproval:
    def test_approval_puts_the_library_on_the_allowlist(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.package("PYPI", "httpx", versions=[("0.27.0", 400)])
        asked = _request(client, admin_auth).json()
        assert asked["state"] == "pending_approval"
        with client.app.state.db.session() as session:
            assert session.execute(select(LibraryEntry)).first() is None, "nothing before"
            approval = session.get(ApprovalRequest, asked["approval_request_id"])
            assert approval is not None and approval.duty == "library_approval"
            assert approval.tier == "clean"

        decided = _decide(client, admin_auth, asked["approval_request_id"], "approve",
                          "Vetting is clean and the reason names why urllib3 will not do.")

        assert decided.status_code in (200, 201), decided.text
        with client.app.state.db.session() as session:
            entry = session.execute(select(LibraryEntry)).scalar_one()
            assert (entry.ecosystem, entry.package_name, entry.status) == (
                "pypi", "httpx", "approved"
            )
            assert (entry.version_policy, entry.version_ref) == ("minimum", "0.27.0")
            assert entry.owner == "platform-team"
            assert entry.approval_request_id == asked["approval_request_id"]
        again = client.get(f"/api/libraries/requests/{asked['id']}", headers=admin_auth).json()
        assert again["state"] == "approved"

    def test_a_rejection_is_recorded_with_its_reason(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        registry.package("PYPI", "httpx", versions=[("0.27.0", 400)])
        asked = _request(client, admin_auth).json()
        reason = "We already standardise on requests; a second HTTP client is not justified."

        _decide(client, admin_auth, asked["approval_request_id"], "reject", reason)

        body = client.get(f"/api/libraries/requests/{asked['id']}", headers=admin_auth).json()
        assert body["state"] == "rejected"
        assert body["decision_reason"] == reason
        assert body["decided_by"]
        with client.app.state.db.session() as session:
            assert session.execute(select(LibraryEntry)).first() is None

    def test_the_generic_approvals_route_cannot_hand_in_its_own_report(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.post(
            "/api/approvals",
            json={
                "duty": "library_approval",
                "subject_ref": "x",
                "context": {"library_request": {"vetting": {"flags": []}}},
            },
            headers=admin_auth,
        )

        assert response.status_code >= 400
        assert "/api/libraries/requests" in response.text

    def test_a_banned_library_cannot_be_requested(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry
    ) -> None:
        client.patch(
            "/api/libraries/managed",
            json={"ecosystem": "pypi", "package_name": "httpx", "status": "banned"},
            headers=admin_auth,
        )

        response = _request(client, admin_auth)

        assert response.status_code == 409
        assert "banned" in response.json()["detail"]


# -- L3: the libraries we have -------------------------------------------------


class TestManaged:
    def test_every_library_in_use_has_a_status(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _components(client, [
            ("a/one", "npm", "lodash", "4.17.21"),
            ("a/two", "npm", "lodash", "4.17.20"),
            ("a/one", "pypi", "requests", "2.32.3"),
        ])
        run_compaction()

        body = client.get("/api/libraries/managed", headers=admin_auth).json()

        assert {(lib["package_name"], lib["status"], lib["status_source"])
                for lib in body["libraries"]} == {
            ("lodash", "tolerated", "default"),
            ("requests", "tolerated", "default"),
        }
        assert body["unrecorded"] == 2
        lodash = next(lib for lib in body["libraries"] if lib["package_name"] == "lodash")
        assert lodash["flags"]["divergent"] is True
        assert lodash["flags"]["eol"] is None, "no registry facts read yet: unknown"
        assert lodash["flags"]["abandoned"] is None

    def test_flags_are_computed_from_the_sbom_and_registry_facts(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry,
        run_compaction: Any,
    ) -> None:
        _components(
            client,
            [("a/one", "npm", "oldlib", "1.0.0"), ("a/two", "npm", "oldlib", "2.0.0")],
            licenses={"1.0.0": ["MIT"], "2.0.0": ["GPL-3.0-only"]},
        )
        run_compaction()
        registry.package(
            "NPM", "oldlib", versions=[("1.0.0", 2000), ("2.0.0", 1500)],
            licenses=["GPL-3.0-only"], deprecated=("1.0.0",), osv_ecosystem="npm",
        )

        refreshed = client.post("/api/libraries/facts/refresh", headers=admin_auth)
        assert refreshed.status_code == 200, refreshed.text
        assert refreshed.json()["read"] == 1

        flags = client.get("/api/libraries/managed", headers=admin_auth).json()[
            "libraries"][0]["flags"]
        assert flags == {
            "divergent": True,
            "eol": True,
            "abandoned": True,
            "license_changed": True,
            "version_policy_violation": None,
            "banned_in_use": False,
        }

    def test_status_owner_and_policy_are_recorded_but_approved_is_not_settable(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _components(client, [("a/one", "npm", "lodash", "4.17.20")])
        run_compaction()

        refused = client.patch(
            "/api/libraries/managed",
            json={"ecosystem": "npm", "package_name": "lodash", "status": "approved"},
            headers=admin_auth,
        )
        assert refused.status_code == 422
        assert "/api/libraries/requests" in refused.json()["detail"]

        changed = client.patch(
            "/api/libraries/managed",
            json={"ecosystem": "npm", "package_name": "lodash", "status": "tolerated",
                  "owner": "web-team", "version_policy": "minimum", "version_ref": "4.17.21"},
            headers=admin_auth,
        )
        assert changed.status_code == 200, changed.text

        lib = client.get("/api/libraries/managed", headers=admin_auth).json()["libraries"][0]
        assert (lib["owner"], lib["status_source"]) == ("web-team", "manual")
        assert lib["flags"]["version_policy_violation"] is True, "4.17.20 < 4.17.21"

    def test_the_baseline_records_every_unrecorded_library(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _components(client, [("a/one", "npm", "lodash", "4.17.20"),
                             ("a/one", "pypi", "requests", "2.32.3")])
        run_compaction()

        body = client.post("/api/libraries/baseline", headers=admin_auth).json()

        assert body["recorded"] == 2
        managed = client.get("/api/libraries/managed", headers=admin_auth).json()
        assert managed["unrecorded"] == 0
        assert {lib["status_source"] for lib in managed["libraries"]} == {"baseline"}

    def test_a_viewer_cannot_change_a_library(
        self, client: TestClient, viewer_auth: dict[str, str]
    ) -> None:
        response = client.patch(
            "/api/libraries/managed",
            json={"ecosystem": "npm", "package_name": "lodash", "status": "banned"},
            headers=viewer_auth,
        )
        assert response.status_code == 403


# -- L4: the pull request check ------------------------------------------------


def _pull_request(github: FakeGitHubClient, *, base_pkg: dict[str, Any],
                  head_pkg: dict[str, Any], number: int = 7, sha: str = "head123") -> None:
    repo = github._repo(REPO)
    repo.files["package.json"] = json.dumps(base_pkg)
    if "main" in repo.branches:
        repo.branches["main"]["package.json"] = json.dumps(base_pkg)
    repo.branches[sha] = {"package.json": json.dumps(head_pkg)}
    repo.pull_requests.append(
        PullRequest(number=number, url="u", head_branch="feature", head_sha=sha,
                    base_branch="main")
    )
    repo.pull_request_files[number] = [PullRequestFile(filename="package.json",
                                                       status="modified")]


def _check(client: TestClient, admin_auth: dict[str, str], number: int = 7) -> Any:
    return client.post("/api/libraries/pr-checks", json={"repo": REPO, "number": number},
                       headers=admin_auth)


class TestPullRequestCheck:
    def test_an_unapproved_dependency_is_reported_with_a_request_link(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(client.app.state.settings, "dashboard_url",
                            "https://mykronos.example")
        onboard(client, admin_auth)
        _pull_request(github, base_pkg={"dependencies": {"react": "^18.0.0"}},
                      head_pkg={"dependencies": {"react": "^18.0.0", "left-pad": "^1.3.0"}})

        response = _check(client, admin_auth)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["mode"] == "report"
        assert body["conclusion"] == "neutral", "report mode never blocks"
        assert [(r["name"], r["verdict"]) for r in body["results"]] == [
            ("left-pad", "unapproved")
        ]
        assert body["results"][0]["request_url"] == (
            "https://mykronos.example/libraries/request?ecosystem=npm&name=left-pad&version=1.3.0"
        )
        posted = github._repo(REPO).check_runs[-1]
        assert posted["name"] == "library-allowlist"
        assert posted["head_sha"] == "head123"
        assert posted["conclusion"] == "neutral"
        assert "request it" in posted["summary"]

    def test_an_approved_dependency_within_its_policy_passes(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        registry: Registry,
    ) -> None:
        onboard(client, admin_auth)
        registry.package("NPM", "left-pad", versions=[("1.3.0", 900)], osv_ecosystem="npm")
        asked = _request(client, admin_auth, ecosystem="npm", package_name="left-pad",
                         version="1.3.0").json()
        _decide(client, admin_auth, asked["approval_request_id"], "approve",
                "Vetting is clean and the owner is named for this package.")
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "^1.3.1"}})

        body = _check(client, admin_auth).json()

        assert body["conclusion"] == "success"
        assert body["results"][0]["verdict"] == "approved"

    def test_blocking_is_refused_until_the_repository_is_covered(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        run_compaction: Any,
    ) -> None:
        onboard(client, admin_auth)
        _components(client, [(REPO, "npm", "react", "18.2.0")])
        run_compaction()

        refused = client.put("/api/libraries/repo-mode", json={"repo": REPO, "mode": "blocking"},
                             headers=admin_auth)
        assert refused.status_code == 409
        assert "npm:react" in refused.json()["detail"]

        client.post("/api/libraries/baseline", headers=admin_auth)
        allowed = client.put("/api/libraries/repo-mode", json={"repo": REPO, "mode": "blocking"},
                             headers=admin_auth)
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["mode"] == "blocking" and allowed.json()["covered"] is True

        _pull_request(github, base_pkg={"dependencies": {"react": "^18.2.0"}},
                      head_pkg={"dependencies": {"react": "^18.2.0", "left-pad": "1.3.0"}})
        body = _check(client, admin_auth).json()
        assert (body["mode"], body["conclusion"]) == ("blocking", "failure")

    def test_blocking_is_per_repository(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        run_compaction: Any,
    ) -> None:
        onboard(client, admin_auth)
        _components(client, [(REPO, "npm", "react", "18.2.0"),
                             ("other/repo", "npm", "vue", "3.0.0")])
        run_compaction()
        client.patch("/api/libraries/managed",
                     json={"ecosystem": "npm", "package_name": "react", "status": "tolerated"},
                     headers=admin_auth)

        assert client.put("/api/libraries/repo-mode", json={"repo": REPO, "mode": "blocking"},
                          headers=admin_auth).status_code == 200
        other = client.get("/api/libraries/coverage", params={"repo": "other/repo"},
                           headers=admin_auth).json()
        assert (other["mode"], other["covered"]) == ("report", False)

    def test_a_blocking_repository_whose_coverage_lapsed_only_reports(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        run_compaction: Any,
    ) -> None:
        onboard(client, admin_auth)
        _components(client, [(REPO, "npm", "react", "18.2.0")])
        run_compaction()
        client.post("/api/libraries/baseline", headers=admin_auth)
        client.put("/api/libraries/repo-mode", json={"repo": REPO, "mode": "blocking"},
                   headers=admin_auth)
        _components(client, [(REPO, "npm", "newcomer", "1.0.0")])
        run_compaction()
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "1.3.0"}})

        body = _check(client, admin_auth).json()

        assert (body["mode"], body["conclusion"]) == ("report", "neutral")
        assert "no longer covers" in github._repo(REPO).check_runs[-1]["summary"]

    def test_a_manifest_cannot_write_markdown_into_the_check_summary(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        # The version spec is the pull request author's text. Unescaped, a `|`
        # forges a table cell and `[..](..)` a link beside the real request one.
        onboard(client, admin_auth)
        spec = "1.0.0 | approved: fine | [request it](https://evil.example/x) `"
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": spec}})

        _check(client, admin_auth)

        summary = github._repo(REPO).check_runs[-1]["summary"]
        row = next(line for line in summary.splitlines() if "left-pad" in line)
        assert row.count(" | ") == 3, row
        assert "](https://evil.example" not in summary
        assert summary.count("[request it](") == 1

    def test_the_job_checks_every_open_pull_request_once_per_head(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient
    ) -> None:
        import asyncio

        onboard(client, admin_auth)
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "1.3.0"}})
        state = client.app.state

        first = asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))
        second = asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))

        assert first == [f"{REPO}#7"]
        assert second == []
        assert [c["name"] for c in github._repo(REPO).check_runs] == ["library-allowlist"]


class TestManifests:
    def test_requirements_pyproject_and_go_mod(self) -> None:
        assert library_check.parse_manifest(
            "requirements", "requests==2.32.3\n# c\nhttpx[http2]>=0.27 ; python_version>'3'\n-e .\n"
        ) == {"requests": "==2.32.3", "httpx": ">=0.27"}
        assert library_check.parse_manifest(
            "pyproject",
            '[project]\ndependencies = ["fastapi>=0.110"]\n'
            '[project.optional-dependencies]\ndev = ["pytest"]\n',
        ) == {"fastapi": ">=0.110", "pytest": ""}
        assert library_check.parse_manifest(
            "golang", "module x\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\nrequire c.io/d v0.1.0\n"
        ) == {"github.com/a/b": "v1.2.3", "c.io/d": "v0.1.0"}

    def test_only_added_and_changed_dependencies_are_checked(self) -> None:
        changes = library_check.diff_dependencies(
            "npm", "package.json", {"a": "1", "b": "1", "gone": "1"}, {"a": "1", "b": "2", "c": "1"}
        )
        assert [(c.name, c.change) for c in changes] == [("b", "changed"), ("c", "added")]

    def test_a_version_the_policy_cannot_read_fails_it(self) -> None:
        assert libraries.version_allowed("minimum", "1.2.0", "1.10.0") is True
        assert libraries.version_allowed("minimum", "1.2.0", "latest") is False
        assert libraries.version_allowed("same_major", "1.2.0", "2.0.0") is False
        assert libraries.version_allowed("any", "", "latest") is True



# -- Rework after review (PR #1010) --------------------------------------------


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    minted = client.post("/api/agents/credentials", json={"family": "claude-opus-5.5"},
                         headers=admin_auth)
    assert minted.status_code == 201, minted.text
    return {"Authorization": f"Bearer {minted.json()['token']}"}


def _patch(client: TestClient, headers: dict[str, str], **body: Any) -> Any:
    return client.patch("/api/libraries/managed", json=body, headers=headers)


class TestTheAllowlistCannotBeWidenedByHand:
    """`tolerated` passes the PR check unvetted, so recording it is a grant."""

    def test_nobody_can_tolerate_a_library_the_estate_does_not_use(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _components(client, [("a/one", "npm", "react", "18.2.0")])
        run_compaction()
        agent = _agent(client, admin_auth)

        for headers in (agent, admin_auth):
            refused = _patch(client, headers, ecosystem="npm", package_name="left-pad",
                             status="tolerated")
            assert refused.status_code == 422, refused.text
            assert "/api/libraries/requests" in refused.json()["detail"]
        # An owner-only change would create the entry, and its default is tolerated.
        implicit = _patch(client, agent, ecosystem="npm", package_name="left-pad",
                          owner="web-team")
        assert implicit.status_code == 422, implicit.text
        with client.app.state.db.session() as session:
            assert session.execute(select(LibraryEntry)).first() is None

        in_use = _patch(client, agent, ecosystem="npm", package_name="react",
                        status="tolerated", owner="web-team")
        assert in_use.status_code == 200, in_use.text

    def test_only_a_person_bans_or_lifts_a_ban(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction: Any
    ) -> None:
        _components(client, [("a/one", "npm", "react", "18.2.0")])
        run_compaction()
        agent = _agent(client, admin_auth)

        assert _patch(client, agent, ecosystem="npm", package_name="react",
                      status="banned").status_code == 403
        assert _patch(client, admin_auth, ecosystem="npm", package_name="react",
                      status="banned").status_code == 200

        lifted = _patch(client, agent, ecosystem="npm", package_name="react",
                        status="tolerated")
        assert lifted.status_code == 403, lifted.text
        assert "person" in lifted.json()["detail"]
        with client.app.state.db.session() as session:
            assert session.execute(select(LibraryEntry)).scalar_one().status == "banned"

        assert _patch(client, admin_auth, ecosystem="npm", package_name="react",
                      status="tolerated").status_code == 200

    def test_an_agent_cannot_loosen_an_approved_library(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry,
        run_compaction: Any,
    ) -> None:
        _components(client, [("a/one", "pypi", "httpx", "0.27.0")])
        run_compaction()
        registry.package("PYPI", "httpx", versions=[("0.27.0", 400)])
        asked = _request(client, admin_auth, version_policy="exact").json()
        _decide(client, admin_auth, asked["approval_request_id"], "approve",
                "Vetting is clean and the reason names why urllib3 will not do.")
        agent = _agent(client, admin_auth)

        assert _patch(client, agent, ecosystem="pypi", package_name="httpx",
                      version_policy="any").status_code == 403
        assert _patch(client, agent, ecosystem="pypi", package_name="httpx",
                      status="tolerated").status_code == 403
        assert _patch(client, agent, ecosystem="pypi", package_name="httpx",
                      owner="platform-team").status_code == 200
        with client.app.state.db.session() as session:
            entry = session.execute(select(LibraryEntry)).scalar_one()
            assert (entry.status, entry.version_policy) == ("approved", "exact")

    def test_a_ban_made_while_a_request_is_pending_survives_its_approval(
        self, client: TestClient, admin_auth: dict[str, str], registry: Registry,
        run_compaction: Any,
    ) -> None:
        _components(client, [("a/one", "pypi", "httpx", "0.26.0")])
        run_compaction()
        registry.package("PYPI", "httpx", versions=[("0.27.0", 400)])
        asked = _request(client, admin_auth).json()
        assert _patch(client, admin_auth, ecosystem="pypi", package_name="httpx",
                      status="banned").status_code == 200

        _decide(client, admin_auth, asked["approval_request_id"], "approve",
                "Vetting is clean and the reason names why urllib3 will not do.")

        with client.app.state.db.session() as session:
            assert session.execute(select(LibraryEntry)).scalar_one().status == "banned"
        again = client.get(f"/api/libraries/requests/{asked['id']}", headers=admin_auth).json()
        assert again["state"] == "banned"
        assert "banned" in again["decision_reason"]


class TestTheCheckReadsTrue:
    def test_without_a_dashboard_url_the_check_has_no_broken_link(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(client.app.state.settings, "dashboard_url", "")
        onboard(client, admin_auth)
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "1.3.0"}})

        body = _check(client, admin_auth).json()

        assert body["results"][0]["request_url"] == ""
        summary = github._repo(REPO).check_runs[-1]["summary"]
        assert "](/libraries" not in summary, "a relative link is dead inside a check run"
        assert "MYKRONOS_DASHBOARD_URL" in summary

    def test_an_approval_rechecks_the_head_it_reported(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        registry: Registry,
    ) -> None:
        import asyncio

        onboard(client, admin_auth)
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "1.3.0"}})
        state = client.app.state
        first = asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))
        assert first == [f"{REPO}#7"]
        assert github._repo(REPO).check_runs[-1]["conclusion"] == "neutral"

        registry.package("NPM", "left-pad", versions=[("1.3.0", 900)], osv_ecosystem="npm")
        asked = _request(client, admin_auth, ecosystem="npm", package_name="left-pad",
                         version="1.3.0").json()
        _decide(client, admin_auth, asked["approval_request_id"], "approve",
                "Vetting is clean and the owner is named for this package.")

        second = asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))
        third = asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))

        assert second == [f"{REPO}#7"], "the same head, re-read after the allowlist changed"
        assert github._repo(REPO).check_runs[-1]["conclusion"] == "success"
        assert third == [], "and only once"

    def test_a_check_that_cannot_be_posted_stops_retrying(
        self, client: TestClient, admin_auth: dict[str, str], github: FakeGitHubClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import asyncio

        onboard(client, admin_auth)
        _pull_request(github, base_pkg={}, head_pkg={"dependencies": {"left-pad": "1.3.0"}})
        calls: list[str] = []

        async def refused(*args: Any, **kwargs: Any) -> str:
            calls.append(kwargs["head_sha"])
            raise RuntimeError("403 Resource not accessible by integration")

        monkeypatch.setattr(github, "create_check_run", refused)
        state = client.app.state
        for _ in range(getattr(library_check, "MAX_ATTEMPTS", 5) + 3):
            asyncio.run(library_check.sweep(state.db, state.catalog, state.github_factory))

        assert len(calls) == library_check.MAX_ATTEMPTS

    def test_the_summary_fits_in_a_check_run(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        changes = [
            library_check.DependencyChange(
                ecosystem="npm", name=f"package-{i:05d}-" + "x" * 60, spec="^1.0.0",
                manifest="packages/some/deeply/nested/workspace/package.json", change="added",
            )
            for i in range(2_000)
        ]
        with client.app.state.db.session() as session:
            outcome = library_check.evaluate(
                session, client.app.state.catalog, REPO, changes, [],
                dashboard_url="https://mykronos.example",
            )

        assert len(outcome["summary"]) <= library_check.SUMMARY_LIMIT < 65_535
        assert "not shown" in outcome["summary"]
        assert len(outcome["results"]) == 2_000, "the record keeps every row"
