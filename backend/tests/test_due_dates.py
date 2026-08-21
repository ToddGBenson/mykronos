"""Remediation deadlines on findings (spec 24 §2).

The distinction under test throughout: a *target* is a date this organisation
set for itself, and a KEV due date is one CISA set. Age is neither, and a
finding inside its window is not late however old it is.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.dashboard import due_state
from mykronos.db.models import ThreatIntelMatch
from mykronos.lake.catalog import Catalog
from mykronos.oracle.policy import PolicyError, RemediationTargets, parse_policy
from mykronos.threat_intel import apply_kev_due_dates
from tests.conftest import REPO, finding_payload, post_findings, post_scan


def due_rows(catalog: Catalog) -> list[tuple[Any, Any]]:
    return [
        (row[0], row[1])
        for row in catalog.query("SELECT due_at, due_source FROM findings ORDER BY rule_id")
    ]


class TestTargets:
    def test_days_are_counted_from_first_sight(self) -> None:
        targets = RemediationTargets(days={"critical": 7})
        seen = datetime(2026, 8, 1, 12, 0)
        assert targets.due_at("critical", seen) == datetime(2026, 8, 8, 12, 0)

    def test_a_null_target_means_no_deadline(self) -> None:
        """`info` is the expected case. Zero days would make every repository
        permanently overdue on findings nobody intends to fix."""
        targets = RemediationTargets(days={"info": None})
        assert targets.due_at("info", datetime(2026, 8, 1)) is None

    def test_an_unconfigured_severity_has_no_deadline(self) -> None:
        assert RemediationTargets(days={}).due_at("high", datetime(2026, 8, 1)) is None

    def test_configured_is_false_when_every_target_is_null(self) -> None:
        assert not RemediationTargets(days={"high": None, "low": None}).configured
        assert RemediationTargets(days={"high": 30, "low": None}).configured


class TestPolicyParsing:
    def _document(self, **targets: Any) -> dict[str, Any]:
        return {
            "version": "test",
            "findings": {
                "curve": "log2",
                "weights": {
                    "critical": 10,
                    "high": 5,
                    "medium": 2,
                    "low": 1,
                    "info": 0,
                },
            },
            "modifiers": {
                "insider_risk": {"multiplier": 1.0},
                "sscs_trust": {"penalty_cap": 10},
                "remediation_in_flight": {"discount": 1},
                "finding_age": {
                    "escalate_after_days": 30,
                    "escalation_per_finding": 1,
                    "cap": 10,
                },
                "false_positive_dampening": {
                    "min_confidence": 0.5,
                    "max_reduction": 5,
                    "per_entry": 1,
                },
            },
            "thresholds": {"no_go": 70, "review_recommended": 30},
            **({"remediation_targets": targets} if targets else {}),
        }

    def test_a_policy_without_targets_still_loads(self) -> None:
        """A deployment on the pre-spec-24 policy file keeps working, with
        nothing overdue until somebody sets a target."""
        policy = parse_policy(self._document())
        assert not policy.remediation_targets.configured

    def test_targets_are_parsed(self) -> None:
        policy = parse_policy(self._document(critical=7, info=None))
        assert policy.remediation_targets.days["critical"] == 7
        assert policy.remediation_targets.days["info"] is None

    def test_zero_days_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="positive number of days"):
            parse_policy(self._document(critical=0))

    def test_an_unknown_severity_is_refused(self) -> None:
        with pytest.raises(PolicyError, match="unknown severities"):
            parse_policy(self._document(catastrophic=1))

    def test_the_shipped_policy_configures_targets(self) -> None:
        from pathlib import Path

        from mykronos.oracle.policy import load_policy

        policy = load_policy(Path(__file__).resolve().parents[2] / "oracle-policy-v1.yaml")
        assert policy.remediation_targets.days["critical"] == 7
        assert policy.remediation_targets.days["info"] is None


class TestDueState:
    def _now(self) -> datetime:
        return datetime(2026, 8, 20, 12, 0)

    def test_no_target_is_its_own_state(self) -> None:
        """Not 'on track'. Unmeasured is not compliant."""
        assert due_state(None, now=self._now()) == "no_target"

    def test_past_is_overdue(self) -> None:
        assert due_state(self._now() - timedelta(days=1), now=self._now()) == "overdue"

    def test_today_is_overdue(self) -> None:
        assert due_state(self._now(), now=self._now()) == "overdue"

    def test_inside_a_week_is_due_soon(self) -> None:
        assert due_state(self._now() + timedelta(days=3), now=self._now()) == "due_soon"

    def test_beyond_a_week_is_on_track(self) -> None:
        assert due_state(self._now() + timedelta(days=30), now=self._now()) == "on_track"

    def test_an_aware_timestamp_is_handled(self) -> None:
        aware = (self._now() + timedelta(days=30)).replace(tzinfo=UTC)
        assert due_state(aware, now=self._now()) == "on_track"


class TestAtIngest:
    def test_a_critical_gets_the_policy_target(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])  # critical
        run_compaction()

        (due_at, source) = due_rows(catalog)[0]
        assert source == "policy"
        assert 6 <= (due_at - datetime.now()).days <= 7

    def test_an_info_finding_gets_no_deadline(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(severity="info")])
        run_compaction()

        assert due_rows(catalog) == [(None, None)]

    def test_a_rescan_does_not_extend_the_deadline(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """spec 24 §2.2: a finding open for sixty days does not get a fresh
        thirty because somebody re-ran the scanner."""
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        first = due_rows(catalog)[0][0]

        post_findings(client, auth, [finding_payload()], scan_run_id="run-2")
        run_compaction()

        assert due_rows(catalog)[0][0] == first


class TestKevWins:
    def test_kev_replaces_the_policy_date(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-9999", title="CVE-2026-9999 in libfoo")],
        )
        run_compaction()
        assert due_rows(catalog)[0][1] == "policy"

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                ThreatIntelMatch(
                    cve_id="CVE-2026-9999",
                    in_kev=True,
                    kev_due_date=date(2026, 9, 30),
                )
            )
            session.flush()
            restamped = apply_kev_due_dates(session, catalog)

        assert restamped == 1
        due_at, source = due_rows(catalog)[0]
        assert source == "kev"
        assert due_at.date() == date(2026, 9, 30)

    def test_a_cve_not_in_kev_keeps_its_policy_date(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-1111", title="CVE-2026-1111 in libfoo")],
        )
        run_compaction()

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(ThreatIntelMatch(cve_id="CVE-2026-1111", in_kev=False, kev_due_date=None))
            session.flush()
            assert apply_kev_due_dates(session, catalog) == 0

        assert due_rows(catalog)[0][1] == "policy"

    def test_applying_twice_rewrites_nothing(
        self,
        client: TestClient,
        auth: dict[str, str],
        catalog: Catalog,
        run_compaction: Any,
    ) -> None:
        """A no-op update would rewrite a Parquet partition for nothing."""
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2026-9999", title="CVE-2026-9999 in libfoo")],
        )
        run_compaction()

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add(
                ThreatIntelMatch(
                    cve_id="CVE-2026-9999", in_kev=True, kev_due_date=date(2026, 9, 30)
                )
            )
            session.flush()
            assert apply_kev_due_dates(session, catalog) == 1
            assert apply_kev_due_dates(session, catalog) == 0


class TestTheApi:
    def _open(self, client: TestClient, viewer_auth: dict[str, str], **params: str) -> Any:
        repo_id = client.get("/api/dashboard/portfolio", headers=viewer_auth).json()["repos"][0][
            "repo_id"
        ]
        return client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings",
            params=params,
            headers=viewer_auth,
        )

    def test_a_group_reports_its_deadline_and_state(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        client.post(
            "/api/repos",
            json={"github_repo_full_name": REPO, "github_installation_id": 4242},
            headers=admin_auth,
        )
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        group = self._open(client, viewer_auth).json()["groups"][0]

        assert group["due_source"] == "policy"
        assert group["due_state"] == "due_soon"  # critical, seven days

    def test_the_due_filter_selects(
        self,
        client: TestClient,
        auth: dict[str, str],
        admin_auth: dict[str, str],
        viewer_auth: dict[str, str],
        run_compaction: Any,
    ) -> None:
        client.post(
            "/api/repos",
            json={"github_repo_full_name": REPO, "github_installation_id": 4242},
            headers=admin_auth,
        )
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [finding_payload(), finding_payload(rule_id="NOTE", severity="info", symbol="n")],
        )
        run_compaction()

        soon = self._open(client, viewer_auth, due="due_soon").json()["groups"]
        none_set = self._open(client, viewer_auth, due="no_target").json()["groups"]

        assert [g["rule_id"] for g in soon] == ["CWE-89"]
        assert [g["rule_id"] for g in none_set] == ["NOTE"]

    def test_an_unknown_due_value_is_rejected(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        viewer_auth: dict[str, str],
    ) -> None:
        client.post(
            "/api/repos",
            json={"github_repo_full_name": REPO, "github_installation_id": 4242},
            headers=admin_auth,
        )
        assert self._open(client, viewer_auth, due="whenever").status_code == 422
