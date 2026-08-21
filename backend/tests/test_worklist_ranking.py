"""Ranked triage (spec 27 §1, §2).

The queue has held every input needed to answer "what should I do first" and
has ordered by "what is nominally worst" instead. These tests pin the
difference — and the fact that the old ordering still works, because "show me
every critical" remains a legitimate question.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos.config import get_settings
from mykronos.dashboard import effort_band, rank_terms
from mykronos.db.models import RepoOnboarding, ThreatIntelMatch
from mykronos.lake.catalog import Catalog
from mykronos.oracle import load_policy
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


@pytest.fixture
def policy() -> Any:
    return load_policy(get_settings().oracle_policy_path)


class TestEffortBands:
    def test_a_produced_fix_is_one_click(self) -> None:
        assert effort_band(fixable=True, package_name="urllib3") == "one_click"

    def test_a_code_finding_is_investigation(self) -> None:
        """The deterministic fixers are all dependency-shaped, so a code
        finding has no mechanical path."""
        assert effort_band(fixable=False, package_name=None) == "investigation"

    def test_a_package_finding_with_no_fix_yet_is_small(self) -> None:
        assert effort_band(fixable=None, package_name="urllib3") == "small"


class TestTheWeightedSum:
    def _item(self, **overrides: Any) -> dict[str, Any]:
        item = {
            "severity": "medium",
            "in_kev": False,
            "epss_score": None,
            "due_state": "on_track",
            "blast_radius_ratio": 0.0,
            "blast_radius_repos": 0,
            "repo_recommendation": "go",
            "orphaned": False,
            "effort": "small",
        }
        item.update(overrides)
        return item

    def test_severity_alone_produces_the_band_weight(self, policy: Any) -> None:
        score, terms = rank_terms(self._item(severity="critical"), policy)
        assert score == policy.triage_rank.severity["critical"]
        assert [term["key"] for term in terms] == ["severity"]

    def test_kev_outranks_a_quiet_critical(self, policy: Any) -> None:
        """The case the whole feature exists for: an exploited, overdue,
        one-click medium above a quiet critical."""
        loud_medium, _ = rank_terms(
            self._item(in_kev=True, epss_score=0.8, due_state="overdue", effort="one_click"),
            policy,
        )
        quiet_critical, _ = rank_terms(self._item(severity="critical"), policy)

        assert loud_medium > quiet_critical

    def test_every_term_carries_its_working(self, policy: Any) -> None:
        _, terms = rank_terms(
            self._item(severity="high", in_kev=True, due_state="overdue"), policy
        )

        assert {term["key"] for term in terms} == {"severity", "in_kev", "overdue"}
        for term in terms:
            assert term["detail"]
            assert term["points"]

    def test_epss_scales_with_the_score(self, policy: Any) -> None:
        low, _ = rank_terms(self._item(epss_score=0.1), policy)
        high, _ = rank_terms(self._item(epss_score=0.9), policy)
        assert high > low

    def test_orphaned_only_ever_discounts(self, policy: Any) -> None:
        """D-072's direction: never a promotion, only a reduction."""
        plain, _ = rank_terms(self._item(severity="high"), policy)
        orphaned, _ = rank_terms(self._item(severity="high", orphaned=True), policy)
        assert orphaned < plain

    def test_fixable_is_a_cheapness_bonus(self, policy: Any) -> None:
        plain, _ = rank_terms(self._item(), policy)
        cheap, _ = rank_terms(self._item(effort="one_click"), policy)
        assert cheap - plain == policy.triage_rank.fixable_bonus


class TestTheQueue:
    def _seed(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        onboard(client, admin_auth)
        # A queue is a list of work, and the queue only lists active repos.
        # Onboarding lands at `pending_install` until the workflow PR merges.
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.execute(
                select(RepoOnboarding).where(
                    RepoOnboarding.github_repo_full_name == REPO
                )
            ).scalars().one()
            row.status = "active"

        from tests.conftest import issue_token

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(rule_id="QUIET", severity="critical", symbol="q"),
                finding_payload(
                    rule_id="CVE-2026-7777",
                    title="CVE-2026-7777 in libfoo",
                    severity="medium",
                    symbol="loud",
                ),
            ],
        )
        run_compaction()

    def test_severity_order_is_still_the_default(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        assert [item["rule_id"] for item in body["items"]] == ["QUIET", "CVE-2026-7777"]
        assert body["items"][0]["rank"] is None

    def test_ranking_lifts_the_exploited_medium(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        self._seed(client, admin_auth, run_compaction)
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                ThreatIntelMatch(
                    cve_id="CVE-2026-7777",
                    in_kev=True,
                    epss_score=0.9,
                    kev_due_date=datetime(2026, 1, 1).date(),
                )
            )

        body = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        ).json()

        assert [item["rule_id"] for item in body["items"]] == ["CVE-2026-7777", "QUIET"]
        assert body["items"][0]["rank"] > body["items"][1]["rank"]

    def test_the_row_shows_the_terms_that_ordered_it(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        body = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        ).json()

        assert body["items"][0]["rank_terms"]
        assert all(term["detail"] for term in body["items"][0]["rank_terms"])

    def test_effort_is_reported_per_row(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        body = client.get(
            "/api/dashboard/triage", params={"order": "rank"}, headers=admin_auth
        ).json()

        assert {item["effort"] for item in body["items"]} == {"investigation"}

    def test_the_owner_filter_narrows_the_queue(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        body = client.get(
            "/api/dashboard/triage", params={"owner": "unresolved"}, headers=admin_auth
        ).json()

        assert len(body["items"]) == 2

    def test_an_unknown_order_is_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.get(
            "/api/dashboard/triage", params={"order": "vibes"}, headers=admin_auth
        )
        assert response.status_code == 422
