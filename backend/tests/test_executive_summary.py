"""The executive report: one repository's posture, every number from the lake.

The page is read by somebody who will not check it against the other tabs, so
the tests pin the two ways it could mislead them: a number that disagrees with
the record, and a gap filled in -- a trend drawn from before the repository
was ever scanned, or a quiet "no findings" from a lane that is not running.
Every test seeds through the ingest API, as the briefing's do, so what is
asserted is what a real scan would produce.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from fastapi.testclient import TestClient

from mykronos import executive_summary as es
from mykronos.db.models import ApprovalRequest, Organization, RepoOnboarding, RiskAcceptance
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import (
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)


def _scan(
    client: TestClient,
    run_id: str,
    findings: list[dict[str, Any]],
    *,
    capability: str = "sast",
    status: str = "success",
    repo: str = REPO,
) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, repo, capability)}"}
    response = post_scan(
        client,
        auth,
        scan_run_id=run_id,
        repo_full_name=repo,
        capability=capability,
        scan_status=status,
    )
    assert response.status_code in (200, 201), response.text
    if findings:
        response = post_findings(client, auth, findings, scan_run_id=run_id, capability=capability)
        assert response.status_code == 200, response.text


def _ids(catalog: Any, where: str = "true") -> list[str]:
    return [
        str(row[0])
        for row in catalog.query(f"SELECT finding_id FROM findings WHERE {where} ORDER BY 1")
    ]


def _set(catalog: Any, finding_id: str, clause: str, params: list[Any]) -> None:
    """Writes through the helper the disposition endpoint itself uses."""
    update_findings(catalog, locate_findings(catalog, [finding_id]), clause, params)


def _image(name: str, *, severity: str, fixed: str = "", rule: str = "CVE-2026-0001") -> dict:
    raw: dict[str, Any] = {"image": name}
    if fixed:
        raw["fixed_version"] = fixed
    return dependency_finding(
        rule_id=rule,
        severity=severity,
        package_name=f"pkg-{rule}",
        raw_finding_json=raw,
    )


class TestCounts:
    def test_open_counts_are_the_open_rows(self, client, catalog, run_compaction) -> None:
        _scan(
            client,
            "run-1",
            [
                finding_payload(rule_id="R1", severity="critical", line_start=1),
                finding_payload(rule_id="R2", severity="high", line_start=20),
                finding_payload(rule_id="R3", severity="low", line_start=40),
            ],
        )
        run_compaction()
        _set(catalog, _ids(catalog, "rule_id = 'R3'")[0], "status = ?", ["false_positive"])

        summary = es.build(catalog, REPO)

        assert summary.open_by_severity == {
            "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0
        }
        assert summary.open_total == 2
        assert summary.drivers_basis == "critical_high"
        assert summary.drivers_basis_total == 2

    def test_a_repository_never_scanned_says_its_zeros_measured_nothing(self, catalog) -> None:
        summary = es.build(catalog, REPO)

        assert summary.open_total == 0
        assert summary.history_since is None
        assert all(not point.available for point in summary.trend)
        assert any("never been scanned" in gap for gap in summary.gaps)


class TestTrend:
    def test_no_history_is_said_rather_than_drawn(self, client, catalog, run_compaction) -> None:
        """The repository was first scanned today. Seven days ago nothing was
        looking, and a zero there would read as an improvement."""
        _scan(client, "run-1", [finding_payload()])
        run_compaction()

        summary = es.build(catalog, REPO)

        assert [p.days_ago for p in summary.trend] == [7, 30]
        for point in summary.trend:
            assert point.available is False
            assert point.open_by_severity is None and point.open_total is None
        assert any("No comparison with 7 or 30 days ago" in gap for gap in summary.gaps)

    def test_history_is_reconstructed_once_it_exists(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(
            client,
            "run-1",
            [
                finding_payload(rule_id="R1", severity="high", line_start=1),
                finding_payload(rule_id="R2", severity="high", line_start=20),
            ],
        )
        run_compaction()
        fixed = _ids(catalog, "rule_id = 'R2'")[0]
        # Fixed twenty days from now: open at the 30-day point of a summary
        # read forty days from now, closed by the 7-day point.
        _set(
            catalog,
            fixed,
            "status = ?, resolved_at = ?",
            ["fixed", utcnow() + timedelta(days=20)],
        )

        summary = es.build(catalog, REPO, now=utcnow() + timedelta(days=40))

        week, month = summary.trend
        assert week.available and month.available
        assert week.open_by_severity and week.open_by_severity["high"] == 1
        assert month.open_by_severity and month.open_by_severity["high"] == 2
        assert summary.open_by_severity["high"] == 1
        assert not any("No comparison" in gap for gap in summary.gaps)

    def test_a_superseded_record_is_not_counted_beside_its_successor(
        self, client, catalog, run_compaction
    ) -> None:
        """A successor inherits its predecessor's first-seen date, so counting
        the predecessor too counts one problem twice for its whole life."""
        _scan(
            client,
            "run-1",
            [
                finding_payload(rule_id="R1", severity="high", line_start=1),
                finding_payload(rule_id="R2", severity="high", line_start=20),
            ],
        )
        run_compaction()
        predecessor = _ids(catalog, "rule_id = 'R2'")[0]
        _set(
            catalog,
            predecessor,
            "status = ?, resolved_at = ?",
            ["superseded", utcnow() + timedelta(days=20)],
        )

        summary = es.build(catalog, REPO, now=utcnow() + timedelta(days=40))

        assert summary.trend[1].open_total == 1


class TestDrivers:
    def test_container_findings_concentrate_by_image_without_its_registry(
        self, client, catalog, run_compaction
    ) -> None:
        image = "registry.example.test:5000/team/db:1.0@sha256:abc"
        _scan(
            client,
            "run-c",
            [_image(image, severity="high", rule=f"CVE-2026-{i:04d}") for i in range(3)]
            + [_image("app:2", severity="critical", rule="CVE-2026-0099")],
            capability="containers",
        )
        run_compaction()

        summary = es.build(catalog, REPO)

        assert summary.basis_by_capability == {"containers": 4}
        top = {d.name: d for d in summary.drivers}
        assert top["team/db:1.0"].findings == 3 and top["team/db:1.0"].kind == "image"
        # Critical first, whatever the size.
        assert summary.drivers[0].name == "app:2"

    def test_only_lower_severities_open_says_so(self, client, catalog, run_compaction) -> None:
        _scan(client, "run-1", [finding_payload(severity="medium")])
        run_compaction()

        summary = es.build(catalog, REPO)

        assert summary.drivers_basis == "all_open"
        assert summary.drivers_basis_total == 1

    def test_image_name(self) -> None:
        assert es.image_name("192.0.2.1:5000/thehub-postgres:1@sha256:ff") == "thehub-postgres:1"
        assert es.image_name("localhost/app:1") == "app:1"
        assert es.image_name("team/app:1") == "team/app:1"
        assert es.image_name("postgres:15.19@sha256:c9") == "postgres:15.19"


class TestFixability:
    def test_open_findings_split_by_whether_anyone_can_act(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(
            client,
            "run-c",
            [
                _image("db:1", severity="high", fixed="1.2.3", rule="CVE-2026-0001"),
                _image("db:1", severity="high", rule="CVE-2026-0002"),
                _image("db:1", severity="low", rule="CVE-2026-0003"),
            ],
            capability="containers",
        )
        _scan(client, "run-s", [finding_payload(severity="high")])
        run_compaction()

        buckets = {b.key: b for b in es.build(catalog, REPO).fixability}

        assert (buckets["fixable_now"].findings, buckets["fixable_now"].serious) == (1, 1)
        assert (buckets["no_vendor_fix"].findings, buckets["no_vendor_fix"].serious) == (2, 1)
        assert (buckets["needs_review"].findings, buckets["needs_review"].serious) == (1, 1)
        assert sum(b.findings for b in buckets.values()) == 4


class TestAccepted:
    def test_expiries_are_the_nearest_dates_and_overdue_is_apart(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(
            client,
            "run-1",
            [finding_payload(rule_id=f"R{i}", line_start=i * 10) for i in range(4)],
        )
        run_compaction()
        today = utcnow().date()
        ids = _ids(catalog)
        dates: list[date | None] = [
            today + timedelta(days=40),
            today + timedelta(days=10),
            today - timedelta(days=1),
            None,
        ]
        for finding_id, until in zip(ids, dates, strict=True):
            _set(
                catalog,
                finding_id,
                "status = ?, accepted_until = ?, accepted_reason_code = ?",
                ["accepted_risk", until, "cost_exceeds_risk"],
            )

        accepted = es.build(
            catalog,
            REPO,
            acceptance_records=[
                {"status": "active", "expires_at": today + timedelta(days=12)},
                {"status": "review_due", "expires_at": today + timedelta(days=3)},
                {"status": "revoked", "expires_at": today + timedelta(days=1)},
            ],
        ).accepted

        assert accepted.findings == 4
        assert [e.on for e in accepted.next_expiries] == [dates[1], dates[0]]
        assert accepted.overdue == 1
        assert accepted.no_review_date == 1
        assert (accepted.decisions_active, accepted.decisions_review_due) == (1, 1)
        # A revoked decision expires nothing.
        assert accepted.nearest_decision_expiry == today + timedelta(days=3)


class TestLanes:
    def test_a_failing_lane_is_named_beside_what_it_holds_open(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(client, "run-1", [finding_payload()])
        run_compaction()
        _scan(client, "run-2", [], status="failure")
        run_compaction()

        lanes = {lane.capability: lane for lane in es.build(catalog, REPO).lanes}

        assert lanes["sast"].status == "failing"
        assert lanes["sast"].consecutive_failures == 1
        assert lanes["sast"].open_findings == 1
        assert lanes["sast"].last_run_status == "failure"
        assert lanes["sast"].last_success_at is not None

    def test_a_lane_that_stopped_is_stale_not_clean(
        self, client, catalog, run_compaction
    ) -> None:
        for index in range(4):
            _scan(client, f"run-{index}", [])
        run_compaction()

        lanes = es.build(catalog, REPO, now=utcnow() + timedelta(days=30)).lanes

        assert [(lane.capability, lane.status) for lane in lanes] == [("sast", "silent")]

    def test_an_enabled_lane_that_never_ran_is_a_gap(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(client, "run-1", [])
        run_compaction()

        summary = es.build(catalog, REPO, enabled={"sast", "dast", "unit", "oracle"})

        lanes = {lane.capability: lane.status for lane in summary.lanes}
        # Quality stages and non-scanning capabilities are not scan lanes.
        assert lanes == {"sast": "ok", "dast": "never_ran"}
        assert any("never run: dast" in gap for gap in summary.gaps)


class TestProgress:
    def test_fixed_and_dismissed_count_apart_from_reidentified(
        self, client, catalog, run_compaction
    ) -> None:
        _scan(
            client,
            "run-1",
            [
                finding_payload(rule_id=f"R{i}", severity="high", line_start=i * 10)
                for i in range(4)
            ],
        )
        run_compaction()
        now = utcnow()
        fixed, dismissed, withdrawn, _ = _ids(catalog)
        _set(catalog, fixed, "status = ?, resolved_at = ?", ["fixed", now])
        _set(catalog, dismissed, "status = ?, resolved_at = ?", ["false_positive", now])
        _set(catalog, withdrawn, "status = ?, resolved_at = ?", ["superseded", now])

        progress = es.build(catalog, REPO, now=now + timedelta(minutes=1)).progress

        assert (progress.fixed, progress.fixed_serious) == (1, 1)
        assert progress.false_positive == 1
        assert progress.reidentified == 1
        # Superseded records are not new arrivals.
        assert progress.new == 3


def _onboard(client: TestClient, repo: str = REPO) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        org = Organization(github_org_login=repo.split("/")[0])
        session.add(org)
        session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=repo,
            github_installation_id=1,
            status="active",
            scanned_by="github_actions",
            enabled_capabilities=["sast", "dast"],
            default_branch="main",
            onboarded_by="test",
        )
        session.add(row)
        session.flush()
        return str(row.id)


class TestTheRoute:
    def test_it_serves_the_summary_with_what_waits_on_a_person(
        self, client, catalog, run_compaction, viewer_auth
    ) -> None:
        repo_id = _onboard(client)
        _scan(client, "run-1", [finding_payload(severity="critical")])
        run_compaction()
        now = utcnow()
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            session.add_all(
                [
                    ApprovalRequest(
                        duty="pull_request_merge",
                        subject_ref=f"{REPO}#7@abc",
                        evidence={"repo": REPO, "number": 7, "title": "Bump"},
                        state="pending",
                        expires_at=now + timedelta(days=2),
                    ),
                    # Another repository's request is not this one's decision.
                    ApprovalRequest(
                        duty="pull_request_merge",
                        subject_ref="example-org/other#1@abc",
                        evidence={"repo": "example-org/other", "number": 1},
                        state="pending",
                        expires_at=now + timedelta(days=2),
                    ),
                    RiskAcceptance(
                        repo_full_name=REPO,
                        status="review_due",
                        justification="No vendor fix yet",
                        expires_at=now.date() + timedelta(days=5),
                    ),
                ]
            )

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/executive-summary", headers=viewer_auth
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["repo_full_name"] == REPO
        assert body["open_by_severity"]["critical"] == 1
        assert [(d["kind"], d["summary"]) for d in body["decisions"]] == [
            ("approval", "#7 Bump"),
            ("acceptance_review", "No vendor fix yet"),
        ]
        assert body["accepted"]["decisions_review_due"] == 1
        assert {lane["capability"]: lane["status"] for lane in body["lanes"]} == {
            "sast": "ok",
            "dast": "never_ran",
        }

    def test_an_unknown_repository_is_a_404(self, client, viewer_auth) -> None:
        response = client.get(
            "/api/dashboard/repos/nope/executive-summary", headers=viewer_auth
        )
        assert response.status_code == 404
