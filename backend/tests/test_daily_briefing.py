"""`GET /api/briefing/daily`, overall and per product (TheHub #60860).

The acceptance criterion: every overall section comes back with a source and
an as-of time, and each section has a test of its "could not read" state as
well as its ordinary one. An unreadable source must say so; it must never
look like an empty section that is fine.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from mykronos import briefing, briefing_sources, daily_briefing
from mykronos.briefing import FailingLane, ProductionLag
from mykronos.db.models import EnvironmentalScore, RiskAcceptance, ThreatIntelMatch
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard

OVERALL = [
    "needs_you_today",
    "production_truth",
    "trust",
    "risk_delta",
    "acceptances",
    "sprint_health",
    "suggested_focus",
]
PRODUCT = ["deploy_and_health", "findings_delta", "capability_lanes", "next_sprint_candidates"]


def _everything_read(**overrides: Any) -> briefing_sources.OperationalInputs:
    values: dict[str, Any] = {
        "paused_jobs": [],
        "failing_jobs": [],
        "blocked_jobs": [],
        "workflow_blocked_jobs": [],
        "unhealthy_jobs": [],
        "tokens": [],
        "toxic_combinations": [],
        "toxic_coverage": {},
        "exposure": [],
        "production_lag": [],
    }
    values.update(overrides)
    return briefing_sources.OperationalInputs(**values)


@pytest.fixture
def gathered(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub the non-lake reads; a test swaps `holder["inputs"]` to change them."""
    holder: dict[str, Any] = {"inputs": _everything_read()}
    monkeypatch.setattr(briefing_sources, "gather", lambda *_args: holder["inputs"])
    return holder


def _get(client: Any, auth: dict[str, str], **params: str) -> dict[str, Any]:
    response = client.get("/api/briefing/daily", params=params, headers=auth)
    assert response.status_code == 200, response.text
    return dict(response.json())


def _section(body: dict[str, Any], key: str) -> dict[str, Any]:
    return next(s for s in body["sections"] if s["key"] == key)


def _scan(client: Any, auth: dict[str, str], run_id: str, findings: list[dict[str, Any]],
          *, status: str = "success") -> None:
    post_scan(client, auth, scan_run_id=run_id, scan_status=status)
    post_findings(client, auth, findings, scan_run_id=run_id)


def _ids(catalog: Any) -> list[str]:
    return sorted(str(row[0]) for row in catalog.query("SELECT finding_id FROM findings"))


def _close(catalog: Any, finding_ids: list[str], status: str = "fixed", *,
           first_seen_days_ago: int = 10, **extra: str) -> None:
    """Close findings yesterday that were introduced well before the window."""
    now = utcnow()
    sets = ["status = ?", "resolved_at = ?", "first_seen_at = ?"]
    params: list[Any] = [
        status,
        now - timedelta(hours=1),
        now - timedelta(days=first_seen_days_ago),
    ]
    for column, value in extra.items():
        sets.append(f"{column} = ?")
        params.append(value)
    update_findings(catalog, locate_findings(catalog, finding_ids), ", ".join(sets), params)


def _many(prefix: str, count: int) -> list[dict[str, Any]]:
    return [
        finding_payload(rule_id=f"{prefix}-{i}", file_path=f"src/{prefix}{i}.py", line_start=i + 1)
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# The shape
# ---------------------------------------------------------------------------


class TestShape:
    def test_every_overall_section_in_order_with_a_source_and_an_as_of(
        self, client, admin_auth, gathered
    ) -> None:
        body = _get(client, admin_auth)

        assert body["scope"] == "overall"
        assert [s["key"] for s in body["sections"]] == OVERALL
        for section in body["sections"]:
            assert section["source"], section["key"]
            assert "as_of" in section, section["key"]
            assert section["status"] in daily_briefing.STATUSES
            if section["status"] != "ok":
                assert section["reason"], f"{section['key']} must say why it is not ok"

    def test_the_board_sections_are_named_and_empty_until_b3(
        self, client, admin_auth, gathered
    ) -> None:
        body = _get(client, admin_auth)
        for key in ("needs_you_today", "sprint_health"):
            section = _section(body, key)
            assert section["status"] == "not_available"
            assert "B3" in section["reason"]
            assert section["lines"] == []
            assert section["as_of"] is None

    def test_a_viewer_may_read_it(self, client, viewer_auth, gathered) -> None:
        assert client.get("/api/briefing/daily", headers=viewer_auth).status_code == 200

    def test_no_credential_is_refused(self, client, gathered) -> None:
        assert client.get("/api/briefing/daily").status_code == 401

    def test_a_line_must_be_work(self) -> None:
        with pytest.raises(ValueError):
            daily_briefing.Line(what="x", so_what="y", work="fyi")

    def test_a_section_that_is_not_ok_must_say_why(self) -> None:
        with pytest.raises(ValueError):
            daily_briefing.Section(
                key="k", title="t", status="unavailable", source="s", as_of=None
            )

    def test_per_product_by_onboarding_id(self, client, admin_auth, auth, gathered) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        _scan(client, auth, "run-1", [finding_payload()])

        body = _get(client, admin_auth, repo_id=repo_id)

        assert body["scope"] == "product"
        assert body["repo_full_name"] == REPO
        assert [s["key"] for s in body["sections"]] == PRODUCT
        for section in body["sections"]:
            assert section["source"]
            assert "as_of" in section

    def test_an_unknown_product_is_404(self, client, admin_auth, gathered) -> None:
        response = client.get(
            "/api/briefing/daily", params={"repo_id": "nope"}, headers=admin_auth
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Production truth
# ---------------------------------------------------------------------------


class TestProductionTruth:
    def test_production_behind_with_undeployed_fixes_is_a_decision(
        self, client, admin_auth, gathered
    ) -> None:
        checked = datetime(2026, 10, 20, 6, 0)
        gathered["inputs"] = _everything_read(
            production_lag=[
                ProductionLag(
                    repo_full_name=REPO,
                    status="behind",
                    branch="main",
                    behind_by=40,
                    checked_at=checked,
                    undeployed_fixes=[{"finding_id": "f-1"}],
                ),
                ProductionLag(repo_full_name="o/current", status="at_head", checked_at=checked),
            ]
        )
        section = _section(_get(client, admin_auth), "production_truth")

        assert section["status"] == "ok"
        assert section["as_of"].startswith("2026-10-20T06:00")
        assert len(section["lines"]) == 1, "a current deployment is not work"
        line = section["lines"][0]
        assert line["work"] == "decision"
        assert "40 commit" in line["what"]
        assert "1 merged fix" in line["so_what"]

    def test_aware_and_naive_stamps_compare(self, client, admin_auth, gathered) -> None:
        """The probe sweep and the endpoint probes store their stamps
        differently; the oldest of them is the section's as-of either way."""
        gathered["inputs"] = _everything_read(
            production_lag=[
                ProductionLag(
                    repo_full_name=REPO, status="at_head", checked_at=datetime(2026, 10, 20, 6)
                )
            ],
            exposure=[
                {
                    "url": "https://example.test",
                    "repo_full_name": REPO,
                    "last_status": "probed",
                    "last_probed_at": "2026-10-20T05:00:00+00:00",
                    "observations": [{"severity": "high", "title": "Schema served"}],
                }
            ],
        )
        section = _section(_get(client, admin_auth), "production_truth")
        assert section["as_of"].startswith("2026-10-20T05:00")
        assert [line["work"] for line in section["lines"]] == ["story"]

    def test_could_not_read_either_store(self, client, admin_auth, gathered) -> None:
        gathered["inputs"] = _everything_read(production_lag=None, exposure=None)
        section = _section(_get(client, admin_auth), "production_truth")
        assert section["status"] == "unavailable"
        assert "could not be read" in section["reason"]

    def test_could_not_read_the_deployment_record(self, client, admin_auth, gathered) -> None:
        gathered["inputs"] = _everything_read(production_lag=None)
        section = _section(_get(client, admin_auth), "production_truth")
        assert section["status"] == "partial"
        assert "deployment record" in section["reason"]


# ---------------------------------------------------------------------------
# Can we trust our signals
# ---------------------------------------------------------------------------


class TestTrust:
    def test_a_failing_lane_and_its_held_findings(
        self, client, admin_auth, auth, run_compaction, gathered
    ) -> None:
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        _scan(client, auth, "run-2", [], status="failure")
        run_compaction()

        section = _section(_get(client, admin_auth), "trust")

        assert section["status"] == "ok"
        assert section["as_of"] is not None, "the lake's newest scan"
        assert section["data"]["stalled_lanes"] == 1
        assert any("cannot close" in line["so_what"] for line in section["lines"])

    def test_ci_that_could_not_be_asked_is_partial(self, client, admin_auth, gathered) -> None:
        gathered["inputs"] = _everything_read(
            paused_jobs=None, failing_jobs=None, blocked_jobs=None
        )
        section = _section(_get(client, admin_auth), "trust")
        assert section["status"] == "partial"
        assert "CI could not be asked" in section["reason"]

    def test_a_failing_ci_job_is_a_story(self, client, admin_auth, gathered) -> None:
        gathered["inputs"] = _everything_read(
            failing_jobs=[FailingLane(pipeline="soc", job="netassess", last_status="errored")]
        )
        section = _section(_get(client, admin_auth), "trust")
        assert [line["work"] for line in section["lines"]] == ["story"]

    def test_the_lake_could_not_be_read(
        self, client, admin_auth, gathered, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _broken(*_args: Any, **_kwargs: Any) -> Any:
            raise OSError("/secret/path/lake")

        monkeypatch.setattr(briefing, "build", _broken)
        body = _get(client, admin_auth)

        trust = _section(body, "trust")
        assert trust["status"] == "unavailable"
        assert "OSError" in trust["reason"]
        assert "/secret" not in trust["reason"], "the reason names the kind, not the text"
        assert _section(body, "production_truth")["status"] == "unavailable"
        # One store failing does not take the rest of the page.
        assert _section(body, "acceptances")["status"] == "ok"


# ---------------------------------------------------------------------------
# Risk delta
# ---------------------------------------------------------------------------


class TestRiskDelta:
    def test_introduced_and_closed_by_severity(
        self, client, admin_auth, auth, catalog, run_compaction, gathered
    ) -> None:
        _scan(client, auth, "run-1", [
            finding_payload(rule_id="A", severity="critical", file_path="a.py"),
            finding_payload(rule_id="B", severity="low", file_path="b.py"),
            finding_payload(rule_id="C", severity="high", file_path="c.py"),
        ])
        run_compaction()
        closed_id = next(
            str(r[0]) for r in catalog.query("SELECT finding_id FROM findings WHERE rule_id = 'B'")
        )
        _close(catalog, [closed_id])

        section = _section(_get(client, admin_auth), "risk_delta")

        assert section["status"] == "ok"
        assert section["as_of"] is not None
        data = section["data"]
        assert data["introduced"]["total"] == 2
        assert data["introduced"]["by_severity"] == {"critical": 1, "high": 1}
        assert data["closed"]["by_severity"] == {"low": 1}
        assert data["closed"]["by_status"] == {"fixed": 1}
        assert data["introduced"]["unscored"] == 2, "no vector, so not guessed"

    def test_base_against_environmental_severity(
        self, client, admin_auth, auth, catalog, run_compaction, gathered
    ) -> None:
        _scan(client, auth, "run-1", [finding_payload(severity="critical")])
        run_compaction()
        fid = _ids(catalog)[0]
        with client.app.state.db.session() as session:
            session.add(EnvironmentalScore(
                finding_id=fid, repo_full_name=REPO, base=9.8, environmental=5.1,
                base_band="critical", env_band="medium", scanner_severity="critical",
                effective_severity="medium",
            ))

        section = _section(_get(client, admin_auth), "risk_delta")

        intro = section["data"]["introduced"]
        assert intro["by_base_severity"] == {"critical": 1}
        assert intro["by_environmental_severity"] == {"medium": 1}
        # Medium here: not a critical/high story.
        assert section["lines"] == []

    def test_kev_and_epss_matches_on_introduced_findings(
        self, client, admin_auth, auth, run_compaction, gathered
    ) -> None:
        _scan(client, auth, "run-1", [
            finding_payload(rule_id="CVE-2024-10001", severity="medium", file_path="a.py"),
            finding_payload(rule_id="CVE-2024-10002", severity="low", file_path="b.py"),
            finding_payload(rule_id="CVE-2024-10003", severity="low", file_path="c.py"),
        ])
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-10001", in_kev=True, epss_score=0.2))
            session.add(ThreatIntelMatch(cve_id="CVE-2024-10002", in_kev=False, epss_score=0.9))
            session.add(ThreatIntelMatch(cve_id="CVE-2024-10003", in_kev=False, epss_score=0.01))

        section = _section(_get(client, admin_auth), "risk_delta")

        assert len(section["data"]["kev"]) == 1
        assert [e["epss"] for e in section["data"]["epss"]] == [0.9]
        whys = [line["so_what"] for line in section["lines"]]
        assert any("Known Exploited" in w for w in whys)
        assert any("EPSS 90%" in w for w in whys)
        assert all(line["work"] == "story" for line in section["lines"])

    def test_the_lake_could_not_be_read(
        self, client, admin_auth, gathered, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _broken(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("duckdb")

        monkeypatch.setattr(daily_briefing, "read_risk_delta", _broken)
        section = _section(_get(client, admin_auth), "risk_delta")
        assert section["status"] == "unavailable"
        assert section["as_of"] is None
        assert "RuntimeError" in section["reason"]

    def test_environmental_scores_unreadable_is_partial(
        self, client, admin_auth, auth, run_compaction, gathered,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        def _broken(*_args: Any) -> Any:
            raise RuntimeError("db")

        monkeypatch.setattr(daily_briefing, "_environmental", _broken)
        section = _section(_get(client, admin_auth), "risk_delta")
        assert section["status"] == "partial"
        assert "environmental scores" in section["reason"].lower()

    def test_the_current_row_per_finding_is_what_counts(self, catalog) -> None:
        """A duplicate row for one finding must not count its closure twice."""
        assert "PARTITION BY finding_id" in daily_briefing.CURRENT_FINDINGS


class TestMassClosures:
    def test_unexplained_mass_closure_is_a_trust_signal(
        self, client, admin_auth, auth, catalog, run_compaction, gathered,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(daily_briefing, "MASS_CLOSURE_THRESHOLD", 3)
        _scan(client, auth, "run-1", _many("R", 4))
        run_compaction()
        _close(catalog, _ids(catalog))

        body = _get(client, admin_auth)

        trust = _section(body, "trust")
        flagged = [line for line in trust["lines"] if "no merged fix" in line["what"]]
        assert len(flagged) == 1
        assert flagged[0]["work"] == "decision"
        assert "4 finding" in flagged[0]["what"]
        assert _section(body, "risk_delta")["data"]["mass_closures"][0]["unexplained"] == 4

    def test_closures_an_acceptance_covers_are_explained(
        self, client, admin_auth, auth, catalog, run_compaction, gathered,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(daily_briefing, "MASS_CLOSURE_THRESHOLD", 3)
        _scan(client, auth, "run-1", _many("R", 4))
        run_compaction()
        ids = _ids(catalog)
        _close(catalog, ids, "accepted_risk")
        with client.app.state.db.session() as session:
            session.add(_acceptance(covered_finding_ids=ids))

        trust = _section(_get(client, admin_auth), "trust")
        assert not [line for line in trust["lines"] if "no merged fix" in line["what"]]

    def test_a_named_withdrawal_is_explained_and_an_unnamed_one_is_not(self) -> None:
        def changed(fid: str, source: str) -> daily_briefing.ChangedFinding:
            return daily_briefing.ChangedFinding(
                finding_id=fid, repo_full_name=REPO, capability="sast", rule_id="r",
                title="t", severity="low", status="superseded", superseded_source=source,
                introduced=False, closed=True,
            )

        named = [changed(f"n{i}", "reprocess") for i in range(5)]
        unnamed = [changed(f"u{i}", "") for i in range(5)]
        assert daily_briefing.mass_closures(named, set(), set(), threshold=3) == []
        assert daily_briefing.mass_closures(unnamed, set(), set(), threshold=3)[0].unexplained == 5

    def test_a_merged_fix_explains_its_closures(self) -> None:
        closed = [
            daily_briefing.ChangedFinding(
                finding_id=f"f{i}", repo_full_name=REPO, capability="atlas", rule_id="r",
                title="t", severity="high", status="fixed", superseded_source="",
                introduced=False, closed=True,
            )
            for i in range(5)
        ]
        merged = {f"f{i}" for i in range(5)}
        assert daily_briefing.mass_closures(closed, set(), merged, threshold=3) == []


# ---------------------------------------------------------------------------
# Acceptances
# ---------------------------------------------------------------------------


def _acceptance(**fields: Any) -> RiskAcceptance:
    today = utcnow().date()
    values: dict[str, Any] = {
        "repo_full_name": REPO,
        "scope": {"capability": "containers"},
        "covered_finding_ids": ["a", "b"],
        "deviation_type": "risk_adjustment",
        "justification": "Bound to loopback.",
        "residual_severity": "low",
        "risk_owner": "tgb",
        "requested_by": "agent:test",
        "approved_by": "admin",
        "status": "active",
        "expires_at": today + timedelta(days=80),
    }
    values.update(fields)
    return RiskAcceptance(**values)


class TestAcceptances:
    def test_expiring_within_a_week_and_premise_failed(
        self, client, admin_auth, gathered
    ) -> None:
        today = utcnow().date()
        with client.app.state.db.session() as session:
            session.add(_acceptance(expires_at=today + timedelta(days=3)))
            session.add(_acceptance(expires_at=today + timedelta(days=20)))
            session.add(_acceptance(status="premise_failed"))
            session.add(_acceptance(status="revoked", expires_at=today))

        section = _section(_get(client, admin_auth), "acceptances")

        assert section["status"] == "ok"
        assert section["as_of"] is not None
        assert len(section["data"]["expiring"]) == 1
        assert len(section["data"]["premise_failed"]) == 1
        assert section["data"]["live"] == 2
        assert [line["work"] for line in section["lines"]] == ["decision", "decision"]
        assert "failed its premise" in section["lines"][0]["what"]
        assert "in 3 day" in section["lines"][1]["what"]

    def test_could_not_read_the_store(self, client, admin_auth, gathered) -> None:
        class _Broken:
            def session(self) -> Any:
                raise RuntimeError("database is locked")

        section = daily_briefing.acceptances_section(_Broken(), now=utcnow())
        assert section.status == "unavailable"
        assert section.as_of is None
        assert "RuntimeError" in section.reason


# ---------------------------------------------------------------------------
# Suggested focus
# ---------------------------------------------------------------------------


class TestFocus:
    def test_decisions_first_and_always_partial_in_b2(self) -> None:
        now = utcnow()
        story = daily_briefing.Line(what="s", so_what="s", work="story")
        decision = daily_briefing.Line(what="d", so_what="d", work="decision")
        sections = [
            daily_briefing.Section(key="a", title="A", status="ok", source="x", as_of=now,
                                   lines=[story]),
            daily_briefing.Section(key="b", title="B", status="ok", source="x", as_of=now,
                                   lines=[decision]),
        ]
        focus = daily_briefing.focus_section(sections, now=now)
        assert focus.status == "partial"
        assert "B3" in focus.reason
        assert [line.work for line in focus.lines] == ["decision", "story"]

    def test_names_the_sections_it_ranked_without(self) -> None:
        now = utcnow()
        sections = [
            daily_briefing.Section(key="a", title="A", status="ok", source="x", as_of=now),
            daily_briefing.unavailable("b", "Risk delta", "x", "broken"),
        ]
        focus = daily_briefing.focus_section(sections, now=now)
        assert "Ranked without: Risk delta" in focus.reason

    def test_nothing_readable(self) -> None:
        sections = [daily_briefing.unavailable("b", "B", "x", "broken")]
        focus = daily_briefing.focus_section(sections, now=utcnow())
        assert focus.status == "unavailable"


# ---------------------------------------------------------------------------
# Per product
# ---------------------------------------------------------------------------


class TestProduct:
    def test_lane_strip_and_candidates(
        self, client, admin_auth, auth, run_compaction, gathered
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        _scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        _scan(client, auth, "run-2", [], status="failure")
        run_compaction()

        body = _get(client, admin_auth, repo_id=repo_id)

        lanes = _section(body, "capability_lanes")
        assert lanes["status"] == "ok"
        assert lanes["as_of"] is not None
        cell = lanes["data"]["lanes"][0]
        assert cell["capability"] == "sast"
        assert cell["state"] == "failing"
        assert cell["open_findings_held"] == 1
        assert lanes["lines"][0]["work"] == "story"

        candidates = _section(body, "next_sprint_candidates")
        assert candidates["status"] == "partial"
        assert "B3" in candidates["reason"]
        assert candidates["lines"][0]["what"].startswith("Repair the sast lane")
        assert candidates["data"]["fix_groups"] >= 1

        delta = _section(body, "findings_delta")
        assert delta["status"] == "ok"
        assert delta["data"]["introduced"]["total"] == 1

    def test_no_probe_is_partial_not_current(self, client, admin_auth, gathered) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        section = _section(_get(client, admin_auth, repo_id=repo_id), "deploy_and_health")
        assert section["status"] == "partial"
        assert "no deployment probe" in section["reason"]
        assert section["data"]["probe_configured"] is False

    def test_deploy_record_unreadable(self, client, admin_auth, gathered) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        gathered["inputs"] = _everything_read(production_lag=None, exposure=None)
        section = _section(_get(client, admin_auth, repo_id=repo_id), "deploy_and_health")
        assert section["status"] == "unavailable"

    def test_lanes_unreadable(self, catalog) -> None:
        class _Broken:
            def query(self, *_args: Any) -> Any:
                raise RuntimeError("io")

        section = daily_briefing.lane_strip(_Broken(), None, REPO, as_of=None)  # type: ignore[arg-type]
        assert section.status == "unavailable"
        assert "RuntimeError" in section.reason

    def test_candidates_unreadable(self, monkeypatch: pytest.MonkeyPatch, catalog) -> None:
        from mykronos import guidance

        def _broken(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("io")

        monkeypatch.setattr(guidance, "fix_groups", _broken)
        section = daily_briefing.next_sprint_candidates(catalog, None, REPO, as_of=None)
        assert section.status == "unavailable"
