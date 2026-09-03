"""The consolidation view: every library the estate carries, and where."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.test_onboarding import onboard


def _components(client: TestClient, rows: list[tuple[str, str, str, str]]) -> None:
    client.app.state.buffer.append(
        "sbom_components",
        [
            {
                "component_id": f"{repo}:{name}:{version}",
                "repo_full_name": repo,
                "commit_sha": "abc",
                "scan_run_id": "run-1",
                "ecosystem": eco,
                "package_name": name,
                "package_version": version,
                "direct": True,
                "purl": f"pkg:{eco}/{name}@{version}",
                "license_ids_json": None,
                "first_seen_at": "2026-09-01T00:00:00",
                "observed_at": "2026-09-01T00:00:00",
            }
            for repo, eco, name, version in rows
        ],
    )


class TestLibraries:
    def test_it_ranks_reach_then_divergence(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """A library in every repository is a blast radius; a library at three
        versions is a standardisation target. Those are the two reasons to act
        and the order says so."""
        onboard(client, admin_auth)
        _components(
            client,
            [
                ("a/one", "npm", "lodash", "4.17.21"),
                ("a/two", "npm", "lodash", "4.17.20"),
                ("a/one", "npm", "left-pad", "1.0.0"),
            ],
        )
        run_compaction()

        body = client.get("/api/dashboard/libraries", headers=admin_auth).json()

        assert [lib["package_name"] for lib in body["libraries"]] == ["lodash", "left-pad"]
        lodash = body["libraries"][0]
        assert lodash["repos"] == ["a/one", "a/two"]
        assert lodash["versions"] == ["4.17.20", "4.17.21"]
        assert lodash["divergent"] is True

    def test_it_counts_what_to_reduce(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _components(
            client,
            [
                ("a/one", "npm", "lodash", "4.17.21"),
                ("a/two", "npm", "lodash", "4.17.20"),
                ("a/one", "npm", "left-pad", "1.0.0"),
                ("a/one", "pypi", "requests", "2.32.3"),
            ],
        )
        run_compaction()

        body = client.get("/api/dashboard/libraries", headers=admin_auth).json()

        assert body["total_libraries"] == 3
        assert body["shared"] == 1, "lodash only"
        assert body["divergent"] == 1, "lodash only"
        assert body["single_use"] == 2, "left-pad and requests"

    def test_it_filters_by_ecosystem(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        onboard(client, admin_auth)
        _components(
            client,
            [
                ("a/one", "npm", "lodash", "4.17.21"),
                ("a/one", "pypi", "requests", "2.32.3"),
            ],
        )
        run_compaction()

        body = client.get(
            "/api/dashboard/libraries", params={"ecosystem": "pypi"}, headers=admin_auth
        ).json()

        assert [lib["package_name"] for lib in body["libraries"]] == ["requests"]

    def test_an_empty_index_is_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """An estate with no SBOM yet must render, and must not read as
        'no dependencies'."""
        body = client.get("/api/dashboard/libraries", headers=admin_auth).json()

        assert body["libraries"] == []
        assert body["total_libraries"] == 0
        assert "absent rather than clean" in body["note"]
