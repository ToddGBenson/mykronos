"""Portfolio aggregation and fleet term analytics — spec 21 §2, §3.

The trend bug is the interesting one. `trend_series` with no repo filter had
no repo filter *and no grouping*, so each bucket returned whichever single
repository happened to have decided most recently before it. That rendered as
"portfolio risk over time" and never was: consecutive points could come from
different repositories, so the line moved when the decision *order* changed
and not when any risk did.

Decisions are written straight into the buffer rather than through
`evaluate_and_publish`, because these are tests of the aggregation over stored
rows, not of the scoring that produced them.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from mykronos.maturity import trend_series
from mykronos.oracle.service import OracleService
from mykronos.schemas import utcnow


def decision_row(repo, score, *, at, raw=None, recommendation="review_recommended", terms=()):
    return {
        "decision_id": f"{repo}-{at.isoformat()}",
        "repo_full_name": repo,
        "decision_type": "portfolio",
        "pr_number": None,
        "release_tag": None,
        "commit_sha": "abc123",
        "overall_risk_score": score,
        "recommendation": recommendation,
        "inputs_snapshot": json.dumps(
            {
                "terms": [
                    {"key": k, "label": k.replace("_", " "), "contribution": c, "detail": ""}
                    for k, c in terms
                ],
                "totals": {
                    "raw_score": raw if raw is not None else score,
                    "overall_risk_score": score,
                    "clamped": False,
                },
            }
        ),
        "reasoning": "",
        "policy_version": "1.1",
        "evaluated_at": at,
        "human_override": None,
        "github_check_run_id": None,
        "gate_outcome": None,
    }


@pytest.fixture
def write_decisions(buffer, run_compaction):
    def write(*rows):
        buffer.append("risk_decisions", list(rows))
        run_compaction()

    return write


class TestPortfolioTrend:
    def test_it_averages_the_fleet_rather_than_picking_one_repo(
        self, catalog, write_decisions
    ) -> None:
        """The bug. Two repositories at 20 and 80 are a portfolio at 50, not
        at whichever of them decided last."""
        now = utcnow()
        write_decisions(
            decision_row("acme/a", 20, at=now - timedelta(hours=2)),
            decision_row("acme/b", 80, at=now - timedelta(hours=1)),
        )

        point = trend_series(catalog, None, days=7, points=2, as_of=now)[-1]

        assert point.risk_score == 50
        assert point.repos_scored == 2

    def test_decision_order_no_longer_moves_the_line(
        self, catalog, write_decisions
    ) -> None:
        """The failure that made this worth fixing: before, swapping which
        repo decided most recently swung the portfolio line from 20 to 80
        without any risk changing."""
        now = utcnow()
        write_decisions(
            decision_row("acme/a", 20, at=now - timedelta(hours=1)),
            decision_row("acme/b", 80, at=now - timedelta(hours=2)),
        )

        assert trend_series(catalog, None, days=7, points=2, as_of=now)[-1].risk_score == 50

    def test_a_median_is_reported_alongside_the_mean(
        self, catalog, write_decisions
    ) -> None:
        """A mean can be dragged a long way by one very bad repository; a
        median cannot, and a median alone hides that repository. Both, so
        neither misrepresentation replaces the other."""
        now = utcnow()
        write_decisions(
            *[
                decision_row(f"acme/{name}", score, at=now - timedelta(hours=1))
                for name, score in (("a", 10), ("b", 10), ("c", 100))
            ]
        )

        point = trend_series(catalog, None, days=7, points=2, as_of=now)[-1]

        assert point.risk_score == 40
        assert point.risk_score_median == 10

    def test_only_the_latest_decision_per_repo_counts(
        self, catalog, write_decisions
    ) -> None:
        """A repository evaluated ten times must not outweigh one evaluated
        once. That would be a fact about scan cadence, not about risk."""
        now = utcnow()
        write_decisions(
            decision_row("acme/a", 90, at=now - timedelta(days=3)),
            decision_row("acme/a", 10, at=now - timedelta(hours=1)),
            decision_row("acme/b", 10, at=now - timedelta(hours=1)),
        )

        point = trend_series(catalog, None, days=7, points=2, as_of=now)[-1]

        assert point.risk_score == 10
        assert point.repos_scored == 2

    def test_it_is_as_of_the_bucket_not_of_today(
        self, catalog, write_decisions
    ) -> None:
        """The property the per-repo series already had and the portfolio one
        must keep: an earlier bucket sees only what had been decided by then,
        so a line that improved actually shows the improvement."""
        now = utcnow()
        write_decisions(
            decision_row("acme/a", 90, at=now - timedelta(days=5)),
            decision_row("acme/a", 10, at=now - timedelta(hours=1)),
        )

        # Two days ago, only the first decision had happened.
        earlier = trend_series(
            catalog, None, days=7, points=2, as_of=now - timedelta(days=2)
        )
        assert earlier[-1].risk_score == 90

        assert trend_series(catalog, None, days=7, points=2, as_of=now)[-1].risk_score == 10

    def test_raw_score_survives_the_clamp(self, catalog, write_decisions) -> None:
        """D-018. Two repositories both pinned at 100 are indistinguishable in
        the clamped value, so averaging clamped scores stops responding once
        enough of the fleet is bad."""
        now = utcnow()
        write_decisions(
            decision_row("acme/a", 100, raw=180.0, at=now - timedelta(hours=1)),
            decision_row("acme/b", 100, raw=220.0, at=now - timedelta(hours=1)),
            decision_row("acme/c", 0, raw=0.0, at=now - timedelta(hours=1)),
        )

        point = trend_series(catalog, None, days=7, points=2, as_of=now)[-1]

        # Mean of the raw scores is 133, clamped back into the chart's range.
        assert point.risk_score == 100
        # The median is a real repo's raw score, not the ceiling.
        assert point.risk_score_median == 100

    def test_a_single_repo_reports_no_aggregate(
        self, catalog, write_decisions
    ) -> None:
        """Averaging one number is not an aggregate, and dressing it up as one
        would invite reading the two lines as agreement."""
        now = utcnow()
        write_decisions(decision_row("acme/a", 42, at=now - timedelta(hours=1)))

        point = trend_series(catalog, "acme/a", days=7, points=2, as_of=now)[-1]

        assert point.risk_score == 42
        assert point.risk_score_median is None
        assert point.repos_scored is None

    def test_no_decisions_is_null_not_zero(self, catalog) -> None:
        """Zero risk and no measurement are different claims, and the chart
        breaks the line for one of them."""
        point = trend_series(catalog, None, days=7, points=2)[-1]

        assert point.risk_score is None
        assert point.repos_scored is None


class TestTermAnalytics:
    def service(self, client) -> OracleService:
        state = client.app.state
        return OracleService(
            state.catalog, state.buffer, state.oracle_policy, state.knowledge, db=state.db
        )

    def test_it_ranks_terms_by_total_contribution(
        self, client, write_decisions
    ) -> None:
        now = utcnow()
        write_decisions(
            decision_row(
                "acme/a",
                60,
                at=now - timedelta(hours=1),
                terms=(("finding_age", 40.0), ("exploitability", 20.0)),
            ),
            decision_row(
                "acme/b",
                50,
                at=now - timedelta(hours=1),
                terms=(("finding_age", 50.0),),
            ),
        )

        report = self.service(client).term_analytics(days=30)

        assert [t["key"] for t in report["terms"]] == ["finding_age", "exploitability"]
        assert report["terms"][0]["total_contribution"] == 90.0
        assert report["terms"][0]["repos"] == 2

    def test_it_counts_the_no_go_repos_per_term(
        self, client, write_decisions
    ) -> None:
        """A term worth 300 points across 30 repos is a fleet-wide policy
        question; one worth 300 across 2 is a conversation with two teams.
        The ranking has to be readable both ways."""
        now = utcnow()
        write_decisions(
            decision_row(
                "acme/a",
                90,
                at=now - timedelta(hours=1),
                recommendation="no_go",
                terms=(("risk_profile", 30.0),),
            ),
            decision_row(
                "acme/b",
                20,
                at=now - timedelta(hours=1),
                recommendation="go",
                terms=(("risk_profile", 10.0),),
            ),
        )

        report = self.service(client).term_analytics(days=30)

        assert report["terms"][0]["repos"] == 2
        assert report["terms"][0]["no_go_repos"] == 1
        assert report["no_go_repos"] == 1

    def test_one_decision_per_repo(self, client, write_decisions) -> None:
        now = utcnow()
        write_decisions(
            decision_row(
                "acme/a", 60, at=now - timedelta(days=2), terms=(("finding_age", 99.0),)
            ),
            decision_row(
                "acme/a", 10, at=now - timedelta(hours=1), terms=(("finding_age", 10.0),)
            ),
        )

        report = self.service(client).term_analytics(days=30)

        assert report["terms"][0]["total_contribution"] == 10.0
        assert report["repos_considered"] == 1

    def test_the_window_excludes_older_decisions(
        self, client, write_decisions
    ) -> None:
        now = utcnow()
        write_decisions(
            decision_row(
                "acme/a", 60, at=now - timedelta(days=90), terms=(("finding_age", 40.0),)
            )
        )

        assert self.service(client).term_analytics(days=30)["terms"] == []

    def test_an_unreadable_snapshot_costs_one_repo_not_the_report(
        self, client, buffer, run_compaction
    ) -> None:
        """A decision row this old or this broken is a fact worth not
        crashing over."""
        now = utcnow()
        broken = decision_row("acme/broken", 50, at=now - timedelta(hours=1))
        broken["inputs_snapshot"] = "{not json"
        good = decision_row(
            "acme/good", 50, at=now - timedelta(hours=1), terms=(("finding_age", 5.0),)
        )
        buffer.append("risk_decisions", [broken, good])
        run_compaction()

        report = self.service(client).term_analytics(days=30)

        assert report["repos_considered"] == 1
        assert report["terms"][0]["total_contribution"] == 5.0

    def test_an_empty_fleet_reports_zero_rather_than_failing(self, client) -> None:
        report = self.service(client).term_analytics(days=30)

        assert report["repos_considered"] == 0
        assert report["terms"] == []


class TestTheEndpoint:
    def test_it_is_not_shadowed_by_the_repo_route(self, client, admin_auth) -> None:
        """`/decisions/{repo_id}` is parameterised and `/term-analytics` is
        literal — the same ordering trap `/shadow-mode` already sits in
        front of."""
        response = client.get("/api/oracle/term-analytics", headers=admin_auth)

        assert response.status_code == 200
        assert response.json()["window_days"] == 30

    def test_the_window_is_bounded(self, client, admin_auth) -> None:
        assert (
            client.get(
                "/api/oracle/term-analytics", params={"days": 9999}, headers=admin_auth
            ).status_code
            == 422
        )
