"""The Ctrl+K jump box's search (TheHub #60976).

One free-text box on an internet-exposed dashboard, so three things are held
here beyond "it finds things": the text is a bound parameter and never SQL,
the answer is capped, and the route sits behind the same principal check as
every other dashboard read.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from mykronos.adminauth import require_principal
from mykronos.lake.catalog import Catalog
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard

URL = "/api/dashboard/search"


def _search(client: TestClient, headers: dict[str, str], **params: Any) -> Any:
    return client.get(URL, params=params, headers=headers)


def _repo_id(client: TestClient, admin_auth: dict[str, str]) -> str:
    body = onboard(client, admin_auth).json()
    return str(body["id"])


def _seed_finding(
    client: TestClient, auth: dict[str, str], run_compaction: Any, **overrides: Any
) -> None:
    post_scan(client, auth)
    post_findings(client, auth, [finding_payload(**overrides)])
    run_compaction()


def _finding_ids(catalog: Catalog) -> list[str]:
    return [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]


class TestTheContract:
    def test_a_one_character_query_is_a_400(self, client: TestClient, admin_auth) -> None:
        r = _search(client, admin_auth, q="a")

        assert r.status_code == 400

    def test_a_blank_query_is_a_400(self, client: TestClient, admin_auth) -> None:
        """Whitespace is not two characters of intent."""
        r = _search(client, admin_auth, q="   ")

        assert r.status_code == 400

    def test_the_limit_is_capped_at_fifty(self, client: TestClient, admin_auth) -> None:
        """"Pages" alone can match more than a handful; a limit above the
        cap is served at the cap rather than refused, so a client asking for
        "everything" gets the most the server will give."""
        r = _search(client, admin_auth, q="re", limit=500)

        assert r.status_code == 200
        body = r.json()
        assert body["limit"] == 50
        assert len(body["results"]) <= 50

    def test_the_limit_bounds_the_results(self, client: TestClient, admin_auth) -> None:
        r = _search(client, admin_auth, q="re", limit=2)

        assert r.status_code == 200
        assert len(r.json()["results"]) <= 2

    def test_every_result_is_typed_and_linkable(
        self, client: TestClient, admin_auth
    ) -> None:
        body = _search(client, admin_auth, q="triage").json()

        assert body["results"], "the Triage queue page should match"
        for result in body["results"]:
            assert result["kind"] in {"repo", "finding", "cve", "page"}
            assert result["title"]
            assert isinstance(result["subtitle"], str)
            assert result["href"].startswith("/")


class TestPages:
    def test_a_page_matches_by_title(self, client: TestClient, admin_auth) -> None:
        body = _search(client, admin_auth, q="triage").json()

        pages = [r for r in body["results"] if r["kind"] == "page"]
        assert {"title": "Triage queue", "href": "/triage"}.items() <= pages[0].items()

    def test_the_cve_lookup_page_is_findable(self, client: TestClient, admin_auth) -> None:
        body = _search(client, admin_auth, q="incident").json()

        assert "/incident" in [r["href"] for r in body["results"] if r["kind"] == "page"]


class TestRepos:
    def test_a_repo_matches_by_name(self, client: TestClient, admin_auth) -> None:
        repo_id = _repo_id(client, admin_auth)

        body = _search(client, admin_auth, q="payments").json()

        repos = [r for r in body["results"] if r["kind"] == "repo"]
        assert [r["title"] for r in repos] == [REPO]
        # The repo page takes the onboarding id, never owner/repo.
        assert repos[0]["href"] == f"/repos/{repo_id}"

    def test_a_removed_repo_is_not_offered(
        self, client: TestClient, admin_auth
    ) -> None:
        repo_id = _repo_id(client, admin_auth)
        client.delete(f"/api/repos/{repo_id}", headers=admin_auth)

        body = _search(client, admin_auth, q="payments").json()

        assert [r for r in body["results"] if r["kind"] == "repo"] == []


class TestFindings:
    def test_a_finding_matches_by_id_prefix(
        self, client: TestClient, admin_auth, auth, run_compaction, catalog: Catalog
    ) -> None:
        repo_id = _repo_id(client, admin_auth)
        _seed_finding(client, auth, run_compaction)
        (finding_id,) = _finding_ids(catalog)

        body = _search(client, admin_auth, q=finding_id[:8]).json()

        findings = [r for r in body["results"] if r["kind"] == "finding"]
        assert len(findings) == 1
        assert findings[0]["href"] == f"/repos/{repo_id}/findings/{finding_id}"
        assert REPO in findings[0]["subtitle"]

    def test_a_middle_of_the_id_is_not_a_prefix(
        self, client: TestClient, admin_auth, auth, run_compaction, catalog: Catalog
    ) -> None:
        _repo_id(client, admin_auth)
        _seed_finding(client, auth, run_compaction)
        (finding_id,) = _finding_ids(catalog)

        body = _search(client, admin_auth, q=finding_id[4:12]).json()

        assert [r for r in body["results"] if r["kind"] == "finding"] == []


class TestCves:
    def test_a_cve_is_one_result_per_affected_repo(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        repo_id = _repo_id(client, admin_auth)
        _seed_finding(
            client,
            auth,
            run_compaction,
            rule_id="CVE-2026-1337",
            package_name="lodash",
            symbol="x",
        )

        body = _search(client, admin_auth, q="cve-2026-1337").json()

        cves = [r for r in body["results"] if r["kind"] == "cve"]
        assert len(cves) == 1
        assert cves[0]["title"] == "CVE-2026-1337"
        assert REPO in cves[0]["subtitle"]
        assert cves[0]["href"].startswith(f"/repos/{repo_id}")

    def test_a_cve_nothing_reported_offers_the_incident_lookup(
        self, client: TestClient, admin_auth
    ) -> None:
        """No affected repo is not "not affected": the lookup page is the
        place that says which repositories could not be checked."""
        body = _search(client, admin_auth, q="CVE-2099-9999").json()

        cves = [r for r in body["results"] if r["kind"] == "cve"]
        assert [c["href"] for c in cves] == ["/incident?q=CVE-2099-9999"]

    def test_a_partial_cve_id_is_not_a_cve_match(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        _repo_id(client, admin_auth)
        _seed_finding(
            client, auth, run_compaction, rule_id="CVE-2026-1337", symbol="x"
        )

        body = _search(client, admin_auth, q="CVE-2026").json()

        assert [r for r in body["results"] if r["kind"] == "cve"] == []


HOSTILE = [
    "' OR '1'='1",
    "%",
    "%%",
    "_%",
    "a'; DROP TABLE findings; --",
    '") UNION SELECT finding_id, 1, 2 FROM findings --',
    "\\%' ESCAPE '",
    "*' OR 1=1 /*",
    "?",
    "$1",
    "ab\x00cd",
]


class TestTheQueryIsParameterised:
    @pytest.mark.parametrize("q", HOSTILE)
    def test_metacharacters_are_text(
        self,
        q: str,
        client: TestClient,
        admin_auth,
        auth,
        run_compaction,
    ) -> None:
        """A quote, a `%` or a fragment of SQL is something a person typed,
        and it matches only what contains it literally. Every seeded row
        here is chosen to contain none of them, so any repo or finding in
        the answer is a row the text pulled in that it should not have."""
        _repo_id(client, admin_auth)
        _seed_finding(client, auth, run_compaction, rule_id="CVE-2026-1337", symbol="x")

        r = _search(client, admin_auth, q=q)

        assert r.status_code == 200, r.text
        kinds = {result["kind"] for result in r.json()["results"]}
        assert kinds <= {"page"}, r.json()

    def test_a_percent_does_not_match_everything(
        self, client: TestClient, admin_auth
    ) -> None:
        _repo_id(client, admin_auth)

        body = _search(client, admin_auth, q="%%").json()

        assert body["results"] == []

    def test_an_underscore_is_literal(self, client: TestClient, admin_auth) -> None:
        """`_` is LIKE's one-character wildcard; `payments_api` would match
        `payments-api` if it were passed through."""
        _repo_id(client, admin_auth)

        body = _search(client, admin_auth, q="payments_api").json()

        assert [r for r in body["results"] if r["kind"] == "repo"] == []


class TestAuth:
    def test_no_credential_is_a_401(self, client: TestClient) -> None:
        assert client.get(URL, params={"q": "triage"}).status_code == 401

    def test_a_viewer_may_search(self, client: TestClient, viewer_auth) -> None:
        assert _search(client, viewer_auth, q="triage").status_code == 200

    def test_it_is_pinned_to_the_dashboard_read_dependency(
        self, client: TestClient
    ) -> None:
        """The same check as the incident lookup beside it, not a looser one
        chosen because a search "only reads"."""

        def calls(path: str) -> set[Any]:
            route = next(
                r
                for r in client.app.routes  # type: ignore[attr-defined]
                if isinstance(r, APIRoute) and r.path == path and "GET" in r.methods
            )
            return {d.call for d in route.dependant.dependencies}

        assert require_principal in calls(URL)
        assert calls(URL) == calls("/api/dashboard/incident")
