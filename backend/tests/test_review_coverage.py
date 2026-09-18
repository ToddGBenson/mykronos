"""Review coverage, and why Aegis is silent on TheHub (#302).

`aegis` is enabled on `ToddGBenson/TheHub` and has produced zero insider-risk
signals across the repository's whole history, while `mykronos` has produced
hundreds. Measured against the lake on 2026-09-17: ten of TheHub's last twelve
scanned commits resolve to no pull request. The `insider` job finds none, says
so correctly, and exits without recording anything — because scoring a commit
with no pull request would make the change nobody reviewed read as the safest
change in the repository.

Nothing here changes that refusal. These tests are about the half that was
missing: a number that says *why*, so "enabled and produced nothing" stops
reading the same as "enabled and nobody wired it up".
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mykronos import review_coverage
from mykronos.db.models import CommitReview
from mykronos.github import FakeGitHubClient
from mykronos.schemas import utcnow
from tests.conftest import INSTALLATION, REPO, issue_token, post_scan
from tests.test_onboarding import onboard


# ---------------------------------------------------------------------------
# The arithmetic, on its own.
# ---------------------------------------------------------------------------


class TestTheMeasure:
    def test_ten_of_twelve_with_no_pull_request_is_eighty_three_percent(self) -> None:
        """TheHub's real shape, as measured against the lake."""
        associations: dict[str, int | None] = {f"sha{i}": None for i in range(10)}
        associations["sha10"] = 309
        associations["sha11"] = 310

        measure = review_coverage.coverage("o/thehub", associations, sampled=12)

        assert (measure.direct, measure.via_pull_request) == (10, 2)
        assert measure.unreviewed_share == pytest.approx(10 / 12)
        assert "10 of the last 12" in measure.summary()
        assert "83%" in measure.summary()

    def test_a_commit_nobody_could_resolve_is_not_an_unreviewed_commit(self) -> None:
        """The failure mode this module exists to avoid, one level down.

        A measure of review coverage that improves when GitHub stops answering
        is worse than no measure — it is the estate's recurring defect, a lane
        reporting success while measuring nothing. Eight sampled, two
        resolved: the share is taken over the two, and the six unreadable ones
        are named rather than counted as direct pushes.
        """
        measure = review_coverage.coverage(
            "o/r", {"a": None, "b": 7}, sampled=8
        )

        assert measure.resolved == 2
        assert measure.unresolved == 6
        assert measure.direct == 1, "the six unreadable commits are not direct pushes"

    def test_a_barely_scanned_repository_reports_no_share_rather_than_a_number(
        self,
    ) -> None:
        """Two of three is 67% and means nothing. `None` is not `0.0`: zero
        would read as 'everything here was reviewed'."""
        measure = review_coverage.coverage("o/r", {"a": None, "b": None}, sampled=2)

        assert measure.unreviewed_share is None
        assert "too few" in measure.summary()


class TestTheReason:
    def test_a_repository_that_mostly_skips_pull_requests_gets_a_reason(self) -> None:
        measure = review_coverage.coverage(
            "o/thehub", {f"s{i}": None for i in range(10)} | {"s10": 1}, sampled=11
        )

        reason = review_coverage.silence_reason(measure)

        assert reason is not None
        assert "without a pull request" in reason
        assert "assesses pull requests" in reason

    def test_a_repository_that_mostly_uses_pull_requests_gets_none(self) -> None:
        """An explanation that is always available is one nobody can act on.
        Here two thirds of commits *were* available to score, so the
        capability's silence needs a different explanation and this module
        must not offer a fluent wrong one."""
        measure = review_coverage.coverage(
            "o/r", {"a": 1, "b": 2, "c": 3, "d": None, "e": None, "f": 4}, sampled=6
        )

        assert review_coverage.silence_reason(measure) is None

    def test_too_few_resolved_commits_produce_no_reason(self) -> None:
        measure = review_coverage.coverage("o/r", {"a": None, "b": None}, sampled=2)

        assert review_coverage.silence_reason(measure) is None


# ---------------------------------------------------------------------------
# Resolving against GitHub, and remembering the answer.
# ---------------------------------------------------------------------------

SHAS = [f"{i:040x}" for i in range(12)]


@pytest.fixture
def estate(
    client: TestClient,
    admin_auth: dict[str, str],
    github: FakeGitHubClient,
    run_compaction,
    tmp_path: Path,
) -> Iterator[TestClient]:
    """An onboarded Concourse repo with twelve scanned commits in the lake.

    Two of the twelve came through a pull request, ten did not — TheHub's
    measured shape, in miniature.
    """
    onboard(client, admin_auth, scanned_by="concourse")
    token = issue_token(client, REPO, "sast", "aegis")
    auth = {"Authorization": f"Bearer {token}"}

    for index, sha in enumerate(SHAS):
        post_scan(
            client,
            auth,
            scan_run_id=f"00000000-0000-0000-0000-{index:012d}",
            commit_sha=sha,
            branch="develop",
            pr_number=None,
            triggered_by="push",
        )
    run_compaction()

    repo = github.repos[REPO]
    repo.commit_pull_requests = {SHAS[10]: [309], SHAS[11]: [310, 415]}
    yield client


def _refresh(client: TestClient, **kwargs) -> review_coverage.RefreshResult:
    """Run the sweep the way the scheduler would."""
    app = client.app
    return asyncio.run(
        review_coverage.refresh(
            app.state.db,  # type: ignore[attr-defined]
            app.state.catalog,  # type: ignore[attr-defined]
            app.state.github_factory,  # type: ignore[attr-defined]
            **kwargs,
        )
    )


class TestResolving:
    def test_the_sample_is_the_commits_this_platform_actually_scanned(
        self, estate: TestClient
    ) -> None:
        """Not the repository's git history. A commit nothing ever scanned is
        not evidence about a capability's silence."""
        catalog = estate.app.state.catalog  # type: ignore[attr-defined]

        found = review_coverage.scanned_commits(catalog, REPO)

        assert sorted(found) == sorted(SHAS)

    def test_a_sweep_records_one_row_per_commit_with_its_pull_request(
        self, estate: TestClient
    ) -> None:
        result = _refresh(estate)

        assert result.resolved == 12
        with estate.app.state.db.session() as session:  # type: ignore[attr-defined]
            rows = {
                row.commit_sha: row.pr_number
                for row in session.query(CommitReview).all()
            }
        assert rows[SHAS[10]] == 309
        assert rows[SHAS[0]] is None, "GitHub looked and found none"
        assert rows[SHAS[11]] == 310, "the lowest number, so re-runs agree"

    def test_the_repository_measure_matches_what_was_recorded(
        self, estate: TestClient
    ) -> None:
        result = _refresh(estate)

        measure = result.by_repo[REPO]
        assert (measure.direct, measure.via_pull_request) == (10, 2)
        assert measure.unreviewed_share == pytest.approx(10 / 12)

    def test_a_resolved_pull_request_is_never_asked_about_again(
        self, estate: TestClient, github: FakeGitHubClient
    ) -> None:
        """A commit cannot be un-associated from the pull request that carried
        it, so a steady-state sweep costs one call per newly scanned commit
        rather than one per commit in the sample."""
        _refresh(estate)
        github.calls.clear()

        _refresh(estate)

        assert [c for c in github.calls if c[0] == "pull_requests_for_commit"] == []

    def test_a_recorded_absence_is_re_read_once_it_is_stale(
        self, estate: TestClient, github: FakeGitHubClient
    ) -> None:
        """A commit pushed straight to `develop` joins a pull request the day
        somebody opens `develop` -> `main`. Caching that absence forever would
        freeze the measure at its least flattering reading."""
        _refresh(estate)
        github.calls.clear()

        later = utcnow() + timedelta(days=review_coverage.NEGATIVE_RECHECK_DAYS + 1)
        _refresh(estate, now=later)

        re_read = {
            call[1].split("@")[1]
            for call in github.calls
            if call[0] == "pull_requests_for_commit"
        }
        assert SHAS[0] in re_read, "the absence expires"
        assert SHAS[10] not in re_read, "the pull request does not"

    def test_a_commit_github_will_not_answer_for_is_recorded_as_nothing(
        self, estate: TestClient, github: FakeGitHubClient
    ) -> None:
        """Not as a direct push. An unreadable commit leaves the sample, which
        is what keeps a revoked token from reading as perfect review
        coverage."""
        github.repos.pop(REPO)

        result = _refresh(estate)

        assert result.resolved == 0
        assert result.unreadable == 12
        with estate.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.query(CommitReview).count() == 0


# ---------------------------------------------------------------------------
# What the portfolio then says.
# ---------------------------------------------------------------------------


class TestThePortfolioRow:
    def test_aegis_carries_the_reason_it_has_reported_nothing(
        self, estate: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The gap #302 names. `enabled: true, has_scanned: false` was the
        whole answer, and it reads identically for a capability nobody wired
        up and one with nothing here to assess."""
        _refresh(estate)

        row = estate.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        aegis = next(s for s in row["capability_states"] if s["capability"] == "aegis")

        assert aegis["enabled"] is True
        assert aegis["has_scanned"] is False
        assert aegis["silent_reason"] is not None
        assert "without a pull request" in aegis["silent_reason"]

    def test_the_unreviewed_share_is_a_number_on_the_repository(
        self, estate: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """First-class, and true whether or not `aegis` is enabled: it is a
        sharper statement about review coverage than any capability status."""
        _refresh(estate)

        row = estate.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["unreviewed_commit_share"] == pytest.approx(10 / 12)
        assert "83%" in row["unreviewed_commit_summary"]

    def test_a_capability_that_does_not_read_pull_requests_gets_no_reason(
        self, estate: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """`oracle` scores a repository and `patchwork` opens pull requests
        rather than reading them. A fluent sentence about the wrong thing is
        how an explanation stops being read."""
        _refresh(estate)

        row = estate.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        by_capability = {s["capability"]: s for s in row["capability_states"]}

        assert by_capability["oracle"]["silent_reason"] is None
        assert by_capability["patchwork"]["silent_reason"] is None
        assert by_capability["dast"]["silent_reason"] is None

    def test_nothing_is_gated_on_it(
        self, estate: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """#302 is explicit: a solo operator pushing to their own branch is a
        legitimate way to work, and TheHub's own `oracle-gate` carries D-048's
        lesson that a gate refusing everything gets routed around. The measure
        is reported and changes no verdict."""
        _refresh(estate)

        body = estate.get("/api/dashboard/portfolio", headers=admin_auth).json()
        row = body["repos"][0]

        assert row["unreviewed_commit_share"] is not None
        assert row["recommendation"] is None
        assert row["risk_score"] is None
        assert body["summary"]["repos_no_go"] == 0

    def test_a_repository_nobody_has_resolved_reports_no_share(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Before the sweep has run there is nothing to say, and the row says
        nothing rather than 0 — which would claim every commit was reviewed."""
        onboard(client, admin_auth, scanned_by="concourse")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["unreviewed_commit_share"] is None
        aegis = next(s for s in row["capability_states"] if s["capability"] == "aegis")
        assert aegis["silent_reason"] is None


def test_the_installation_the_sweep_uses_is_the_repository_s_own(
    estate: TestClient,
) -> None:
    """Guard. The factory is keyed by installation, and asking the wrong one
    returns a 404 that this module would count as unreadable — which is a
    silent degradation to 'no data' rather than a loud failure."""
    with estate.app.state.db.session() as session:  # type: ignore[attr-defined]
        from mykronos.db.models import RepoOnboarding

        row = session.query(RepoOnboarding).one()
        assert row.github_installation_id == INSTALLATION
