"""What the scanners cannot read, per repository, and on its verdict.

TheHub #60795 (decision option B): `GET /api/dashboard/repos/{id}/coverage`
returns the B-051 analyser gap beside regression coverage, with a source that
could not be read listed in `unknown`. It is a map of what is not looked at,
so it needs an authenticated principal and is never part of the anonymous
exposure probe.

TheHub #60962 (decision 60814, option 2): the Oracle verdict carries a
read-coverage confidence note. The note never changes the verdict.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import exposure, read_coverage, regression
from tests.conftest import REPO
from tests.test_onboarding import onboard
from tests.test_oracle_api import evaluate
from tests.test_oracle_api import oracle_auth as oracle_auth  # noqa: F401  (fixture)
from tests.test_oracle_api import seeded as seeded  # noqa: F401  (fixture)

#: GitHub's byte counts for a repository that is mostly shell, which CodeQL
#: does not read: 94 000 of 313 000 bytes are read, 30%.
MOSTLY_SHELL = {"Shell": 219000, "Python": 66000, "JavaScript": 28000}
#: Everything here is a language CodeQL implements.
ALL_READ = {"Python": 50000, "TypeScript": 10000}


def _languages(client: TestClient, github: Any, counts: dict[str, int] | None) -> None:
    """Set what GitHub reports, and drop the per-repository language cache."""
    client.app.state.languages_cache = {}  # type: ignore[attr-defined]
    if counts is None:

        async def unreadable(repo_full_name: str) -> dict[str, int] | None:
            return None

        github.languages = unreadable
    else:
        github.repos[REPO].languages = dict(counts)


@pytest.fixture
def repo_id(client: TestClient, admin_auth: dict[str, str]) -> str:
    response = onboard(client, admin_auth)
    assert response.status_code in (200, 201), response.text
    return str(response.json()["id"])


def _coverage(client: TestClient, repo_id: str, auth: dict[str, str]) -> Any:
    return client.get(f"/api/dashboard/repos/{repo_id}/coverage", headers=auth)


class TestTheCoverageRoute:
    def test_it_returns_the_analyser_gap_and_regression_coverage(
        self, client, admin_auth, github, repo_id
    ) -> None:
        _languages(client, github, MOSTLY_SHELL)

        response = _coverage(client, repo_id, admin_auth)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["repo_full_name"] == REPO
        analysers = body["analysers"]
        assert analysers["available"] is True
        assert analysers["share_read"] == pytest.approx(94000 / 313000)
        assert analysers["share_unread"] == pytest.approx(219000 / 313000)
        assert analysers["unread_languages"][0] == {"language": "Shell", "bytes": 219000}
        assert "codeql" in analysers["tools"]
        assert body["regression"]["fixed_findings"] == 0
        assert "available" in body["regression"]
        assert body["unknown"] == []

    def test_unreadable_languages_are_listed_in_unknown_not_shown_as_read(
        self, client, admin_auth, github, repo_id
    ) -> None:
        _languages(client, github, None)

        body = _coverage(client, repo_id, admin_auth).json()

        assert body["analysers"]["available"] is False
        assert body["analysers"]["share_read"] is None
        assert [entry["source"] for entry in body["unknown"]] == ["analysers"]
        assert body["unknown"][0]["detail"]

    def test_a_regression_read_that_fails_is_listed_in_unknown(
        self, client, admin_auth, github, repo_id, monkeypatch
    ) -> None:
        _languages(client, github, ALL_READ)

        def broken(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("lake unavailable")

        monkeypatch.setattr(regression, "coverage", broken)
        response = _coverage(client, repo_id, admin_auth)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["regression"] is None
        assert [entry["source"] for entry in body["unknown"]] == ["regression"]
        # The failure is named, not echoed: no exception text reaches the caller.
        assert "lake unavailable" not in response.text

    def test_a_failed_analyser_lookup_is_listed_in_unknown_not_a_500(
        self, client, admin_auth, github, repo_id, monkeypatch
    ) -> None:
        from mykronos.api import dashboard

        def broken(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("catalog unavailable")

        monkeypatch.setattr(dashboard, "_sast_tools", broken)
        response = _coverage(client, repo_id, admin_auth)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["analysers"]["available"] is False
        assert [entry["source"] for entry in body["unknown"]] == ["analysers"]
        assert "catalog unavailable" not in response.text

    def test_a_repository_with_no_onboarding_row_is_404_not_empty(
        self, client, admin_auth
    ) -> None:
        response = _coverage(client, "no-such-onboarding-id", admin_auth)
        assert response.status_code == 404

    def test_without_credentials_it_is_401(self, client, repo_id) -> None:
        assert client.get(f"/api/dashboard/repos/{repo_id}/coverage").status_code == 401

    def test_a_wrong_token_is_401(self, client, repo_id) -> None:
        response = _coverage(client, repo_id, {"Authorization": "Bearer not-a-token"})
        assert response.status_code == 401

    def test_a_viewer_may_read_it(self, client, viewer_auth, github, repo_id) -> None:
        _languages(client, github, ALL_READ)
        assert _coverage(client, repo_id, viewer_auth).status_code == 200

    def test_it_is_not_part_of_the_anonymous_exposure_probe(self) -> None:
        """The probe GETs a fixed list anonymously; this route is not on it."""
        assert not any("coverage" in path for path in exposure.PATHS)


class TestTheVerdictCarriesAReadCoverageNote:
    """TheHub #60962. `seeded` scores `review_recommended` (two criticals)."""

    def _history(self, client, admin_auth, repo: str) -> dict[str, Any]:
        response = client.get(f"/api/oracle/decisions/{repo}", headers=admin_auth)
        assert response.status_code == 200, response.text
        body: dict[str, Any] = response.json()
        return body

    def test_under_the_threshold_the_note_names_the_read_share(
        self, client, admin_auth, oracle_auth, seeded, github, run_compaction
    ) -> None:
        evaluate(client, oracle_auth)
        run_compaction()
        _languages(client, github, MOSTLY_SHELL)

        body = self._history(client, admin_auth, seeded)

        verdict = body["decisions"][0]["recommendation"]
        assert body["confidence_note"] == f"{verdict} - read 30% of the code"
        assert body["read_coverage"]["share_read"] == pytest.approx(94000 / 313000)
        assert body["read_coverage"]["threshold"] == pytest.approx(0.8)

    def test_over_the_threshold_there_is_no_note(
        self, client, admin_auth, oracle_auth, seeded, github, run_compaction
    ) -> None:
        evaluate(client, oracle_auth)
        run_compaction()
        _languages(client, github, ALL_READ)

        assert self._history(client, admin_auth, seeded)["confidence_note"] is None

    def test_the_threshold_is_configured(
        self, client, admin_auth, oracle_auth, seeded, github, run_compaction
    ) -> None:
        evaluate(client, oracle_auth)
        run_compaction()
        _languages(client, github, MOSTLY_SHELL)
        client.app.state.settings.oracle_read_coverage_threshold = 0.25

        body = self._history(client, admin_auth, seeded)

        assert body["confidence_note"] is None
        assert body["read_coverage"]["threshold"] == pytest.approx(0.25)

    @pytest.mark.parametrize("counts", [None, {}])
    def test_unreadable_coverage_says_unknown_never_nothing(
        self, client, admin_auth, oracle_auth, seeded, github, run_compaction, counts
    ) -> None:
        evaluate(client, oracle_auth)
        run_compaction()
        _languages(client, github, counts)

        body = self._history(client, admin_auth, seeded)

        verdict = body["decisions"][0]["recommendation"]
        assert body["confidence_note"] == f"{verdict} - read coverage unknown"
        assert body["read_coverage"]["available"] is False

    def test_the_verdict_is_identical_with_and_without_coverage_data(
        self, client, admin_auth, oracle_auth, seeded, github, run_compaction
    ) -> None:
        """Regression guard: the note is read beside the verdict, never into it."""
        evaluate(client, oracle_auth, commit_sha="aaa")
        evaluate(client, oracle_auth, commit_sha="bbb")
        run_compaction()

        def verdicts() -> list[tuple[str, int, str]]:
            return [
                (d["recommendation"], d["overall_risk_score"], d["decision_id"])
                for d in self._history(client, admin_auth, seeded)["decisions"]
            ]

        _languages(client, github, None)
        without = verdicts()
        _languages(client, github, MOSTLY_SHELL)
        low = verdicts()
        _languages(client, github, ALL_READ)
        full = verdicts()

        assert len(without) == 2
        assert without == low == full


class TestTheNote:
    def test_the_share_is_rounded_down_so_it_never_reads_as_meeting_the_line(self) -> None:
        measured = read_coverage.measure(REPO, {"Python": 796, "Shell": 204}, "codeql")
        assert read_coverage.confidence_note(measured, "go", 0.8) == "go - read 79% of the code"

    def test_no_decision_still_gets_a_note(self) -> None:
        assert read_coverage.confidence_note(None, None, 0.8) == "read coverage unknown"
