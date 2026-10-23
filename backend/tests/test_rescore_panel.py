"""The rescore panel: every step from base to effective, with each fact and
its freshness, and a page that follows the evidence (TheHub #60889)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import environment, rescore_panel
from mykronos.db.models import EnvironmentalScore, ThreatIntelMatch
from mykronos.environment import Fact
from mykronos.schemas import utcnow
from tests.conftest import REPO
from tests.test_severity_here_vectors import CVE, V31, seed  # noqa: F401  (fixture)

NOW = datetime(2026, 10, 22, 12, 0, 0)


def _fact(**overrides: Any) -> Fact:
    values: dict[str, Any] = {
        "metric": "MAV",
        "value": "L",
        "direction": "lower",
        "source_kind": "observation",
        "source_id": "obs-1",
        "tier": "observed",
        "asserted_by": "host-collector",
        "verified_at": NOW - timedelta(days=3),
        "expires_at": NOW + timedelta(days=11),
        "applied": True,
        "not_applied_reason": None,
        "because": "nothing outside the host reaches the port",
    }
    values.update(overrides)
    return Fact(**values)


@pytest.fixture(autouse=True)
def _clean_flags():
    environment.clear()
    yield
    environment.clear()


class TestFreshness:
    def test_a_fact_well_inside_its_window_is_fresh(self) -> None:
        assert rescore_panel.freshness(_fact(), NOW) == {
            "freshness": "fresh",
            "age_days": 3,
            "expires_in_days": 11,
        }

    def test_a_fact_lapsing_within_a_week_is_expiring(self) -> None:
        got = rescore_panel.freshness(_fact(expires_at=NOW + timedelta(days=2)), NOW)
        assert got["freshness"] == "expiring"
        assert got["expires_in_days"] == 2

    def test_a_fact_past_its_expiry_is_lapsed(self) -> None:
        got = rescore_panel.freshness(_fact(expires_at=NOW - timedelta(days=1)), NOW)
        assert got["freshness"] == "lapsed"
        assert got["expires_in_days"] < 0

    def test_a_fact_nothing_dated_says_so(self) -> None:
        got = rescore_panel.freshness(_fact(verified_at=None, expires_at=None), NOW)
        assert got == {"freshness": "undated", "age_days": None, "expires_in_days": None}


class TestSteps:
    def test_three_steps_in_order_with_every_fact_on_the_environmental_one(self) -> None:
        facts = [
            _fact(),
            _fact(
                metric="CR",
                value="H",
                direction="raise",
                applied=False,
                not_applied_reason="declared:unconfirmed",
            ),
        ]
        steps = rescore_panel.steps(
            vector=V31,
            vector_source="nvd",
            vector_version="3.1",
            base=9.8,
            environmental=8.8,
            scanner_severity="critical",
            effective="high",
            facts=facts,
            now=NOW,
        )

        assert [s["key"] for s in steps] == ["base", "environmental", "effective"]
        assert (steps[0]["score"], steps[0]["severity"]) == (9.8, "critical")
        env = steps[1]
        assert (env["score"], env["severity"]) == (8.8, "high")
        assert len(env["facts"]) == 2
        mav, cr = env["facts"]
        # The modifier is shown against the base metric it replaces.
        assert (mav["metric"], mav["from_value"], mav["to_value"]) == ("MAV", "N", "L")
        assert mav["applied"] is True and mav["freshness"] == "fresh"
        # A requirement starts undefined, and an unapplied fact keeps its reason.
        assert (cr["from_value"], cr["applied"]) == ("X", False)
        assert cr["not_applied_reason"] == "declared:unconfirmed"
        assert "1 of 2 fact(s) applied" in env["detail"]
        eff = steps[2]
        assert eff["severity"] == "high"
        assert "1 band(s) down" in eff["detail"]
        assert "critical to high" in eff["detail"]

    def test_nothing_stated_is_an_upper_bound_not_a_discount(self) -> None:
        steps = rescore_panel.steps(
            vector=V31,
            vector_source="nvd",
            vector_version="3.1",
            base=9.8,
            environmental=9.8,
            scanner_severity="high",
            effective="high",
            facts=[],
            now=NOW,
        )
        assert "upper bound" in steps[1]["detail"]
        assert "stands" in steps[2]["detail"]

    def test_a_kev_listed_finding_says_the_floor_holds(self) -> None:
        steps = rescore_panel.steps(
            vector=V31,
            vector_source="nvd",
            vector_version="3.1",
            base=9.8,
            environmental=5.0,
            scanner_severity="critical",
            effective="medium",
            facts=[_fact()],
            now=NOW,
            in_kev=True,
        )
        assert any("no lower than high" in note for note in steps[2]["notes"])


def _record(client: TestClient, auth: dict[str, str], finding_id: str) -> dict[str, Any]:
    response = client.get(f"/api/dashboard/findings/{finding_id}/record", headers=auth)
    assert response.status_code == 200, response.text
    here = response.json()["severity_here"]
    assert here is not None
    return here


def _store(
    client: TestClient, finding_id: str, *, facts: list[dict[str, Any]], effective: str = "low"
) -> None:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        session.add(
            EnvironmentalScore(
                finding_id=finding_id,
                repo_full_name=REPO,
                vector=V31,
                vector_version="3.1",
                vector_source="nvd",
                base=9.8,
                environmental=5.5,
                base_band="critical",
                env_band="medium",
                scanner_severity="critical",
                effective_severity=effective,
                facts_json=facts,
                context_id="ctx",
                computed_at=utcnow() - timedelta(days=2),
            )
        )


class TestThePanelFollowsTheEvidence:
    def test_the_record_carries_the_steps_and_each_facts_freshness(
        self, client: TestClient, admin_auth: dict[str, str], seed  # noqa: F811
    ) -> None:
        finding_id = seed(match=ThreatIntelMatch(cve_id=CVE, cvss_vector=V31))
        # Ingest marks the repository dirty; the stored row below stands for
        # the rescore that drained it.
        environment.clear()
        lowering = _fact(
            verified_at=utcnow() - timedelta(days=1),
            expires_at=utcnow() + timedelta(days=20),
        ).as_dict()
        _store(client, finding_id, facts=[lowering])

        here = _record(client, admin_auth, finding_id)

        assert here["recomputed_because"] is None
        assert here["effective_severity"] == "low"
        assert [s["key"] for s in here["steps"]] == ["base", "environmental", "effective"]
        assert here["steps"][1]["facts"][0]["freshness"] == "fresh"
        assert here["facts"][0]["freshness"] == "fresh"
        assert here["facts"][0]["expires_in_days"] in (19, 20)

    def test_a_lapsed_lowering_fact_is_not_shown_as_the_current_score(
        self, client: TestClient, admin_auth: dict[str, str], seed  # noqa: F811
    ) -> None:
        """The stored row says `low` because a lowering fact applied. That fact
        has since expired: the page must not keep saying `low` until the
        nightly rescore happens to run."""
        finding_id = seed(match=ThreatIntelMatch(cve_id=CVE, cvss_vector=V31))
        # Ingest marks the repository dirty; the stored row below stands for
        # the rescore that drained it.
        environment.clear()
        lapsed = _fact(
            verified_at=utcnow() - timedelta(days=30),
            expires_at=utcnow() - timedelta(days=1),
        ).as_dict()
        _store(client, finding_id, facts=[lapsed])

        here = _record(client, admin_auth, finding_id)

        assert here["computed_at"] is None
        assert "lapsed" in (here["recomputed_because"] or "")
        # Nothing is known about this repository, so the score is the base.
        assert here["effective_severity"] == "critical"
        assert here["environmental"] == here["base"] == 9.8

    def test_evidence_written_since_the_rescore_is_read_at_once(
        self, client: TestClient, admin_auth: dict[str, str], seed  # noqa: F811
    ) -> None:
        finding_id = seed(match=ThreatIntelMatch(cve_id=CVE, cvss_vector=V31))
        # Ingest marks the repository dirty; the stored row below stands for
        # the rescore that drained it.
        environment.clear()
        _store(client, finding_id, facts=[])
        assert _record(client, admin_auth, finding_id)["effective_severity"] == "low"

        environment.mark_dirty(REPO, "a control was written")
        here = _record(client, admin_auth, finding_id)

        assert "pending" in (here["recomputed_because"] or "")
        assert here["effective_severity"] == "critical"


class TestAPendingMarkCountsOnlyWhenNewer:
    """A rescore run directly (the daily job) leaves the debounced flags set.
    A mark the stored score already read must not send every page back to
    recomputing on read until the next drain."""

    def _stored(self, computed_at: datetime) -> Any:
        return EnvironmentalScore(
            vector=V31,
            scanner_severity="critical",
            facts_json=[],
            computed_at=computed_at,
        )

    def _reason(self, computed_at: datetime, marked_seconds_ago: float) -> str | None:
        now = datetime(2026, 10, 23, 12, 0, 0)
        return rescore_panel.stale_reason(
            self._stored(computed_at),
            vector=V31,
            scanner_severity="critical",
            repo_full_name=REPO,
            onboarding_id=None,
            pending={REPO: 1000.0 - marked_seconds_ago},
            now=now,
            monotonic_now=1000.0,
        )

    def test_a_mark_older_than_the_score_is_not_pending(self) -> None:
        # Marked ten minutes ago, scored five minutes ago.
        computed = datetime(2026, 10, 23, 11, 55, 0)
        assert self._reason(computed, marked_seconds_ago=600) is None

    def test_a_mark_newer_than_the_score_is_pending(self) -> None:
        # Scored ten minutes ago, marked five minutes ago.
        computed = datetime(2026, 10, 23, 11, 50, 0)
        assert self._reason(computed, marked_seconds_ago=300) == "evidence_changed"
