"""Next-sprint candidates, measured honestly (TheHub #61348, ARRI D2.0).

What the daily `briefing-signal` filings got wrong, one class per fault:

- **Exposure was repository-wide.** One public endpoint made every finding in
  the repository x3, a libstdc++ CVE in an image nobody publishes included.
  Exposure is now per finding: internet only where *this* finding sits in a
  surface the internet was observed to reach.
- **No-fix groups were filed as "make the change".** They cannot be made. They
  are acceptance candidates, and the job never files them.
- **Risk removed used the scanner's band.** It now uses the contextual band
  (a stored environmental score in force), and shows both.
- **Titles were cut mid-word.**
- **The weekly metric credited the risk a story claimed**, not what MyKronos
  verified removed by closing findings.

All data is synthetic.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from mykronos import daily_briefing, guidance, sprint_signal
from mykronos.briefing import Briefing, ProductionLag
from mykronos.db.models import EnvironmentalScore, PublicEndpoint, RepoSurface
from mykronos.delivery_sources import BoardRead
from mykronos.lake.mutate import locate_findings, update_findings
from mykronos.schemas import utcnow
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.po_support import story
from tests.test_onboarding import onboard

#: Pinned: the weekly metric reads a time window (memory: pin the clock).
NOW = datetime(2031, 3, 12, 12, 0, 0)  # a Wednesday, UTC, naive like the lake


def _report(**overrides: Any) -> Briefing:
    values: dict[str, Any] = {"generated_at": utcnow(), "total_open": 0}
    values.update(overrides)
    return Briefing(**values)


#: A repository with a public endpoint, deployed: the case that used to give
#: every finding in it the internet factor.
EXPOSED = {
    "exposure": [{"repo_full_name": REPO, "url": "https://app.example.test"}],
    "production_lag": [ProductionLag(repo_full_name=REPO, status="at_head")],
}


def _post(client: Any, capability: str, findings: list[dict[str, Any]], run: str) -> None:
    auth = {"Authorization": f"Bearer {issue_token(client, REPO, capability)}"}
    post_scan(client, auth, scan_run_id=run)
    post_findings(client, auth, findings, scan_run_id=run, capability=capability)


def _container_cve(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "image": "registry.example.test/team/worker:1.4",
        "PkgName": "libstdc++6",
        "fixed_version": "12.2.0-14+deb12u1",
    }
    raw.update(overrides.pop("raw", {}))
    payload = finding_payload(
        rule_id="CVE-2031-1111",
        title="libstdc++6: integer wrap in std::basic_string",
        severity="high",
        file_path=None,
        line_start=None,
        line_end=None,
        symbol=None,
        code_snippet=None,
        package_name="libstdc++6",
        package_version="12.2.0-14",
        raw_finding_json=raw,
    )
    payload.update(overrides)
    return payload


def _fix_candidates(ranked: list[sprint_signal.Candidate]) -> list[sprint_signal.Candidate]:
    return [c for c in ranked if c.kind == "fix"]


# ---------------------------------------------------------------------------
# Exposure per finding
# ---------------------------------------------------------------------------


class TestExposureIsPerFinding:
    def test_a_container_cve_with_no_observed_published_port_is_not_internet(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        """The #61334/#61335 shape: the repository has a public endpoint, the
        image is not placed behind it, and nothing observed its port."""
        onboard(client, admin_auth)
        _post(client, "containers", [_container_cve()], "run-c1")
        run_compaction()

        ranked = sprint_signal.rank(
            catalog, _report(**EXPOSED), [REPO], db=client.app.state.db
        )

        fix = _fix_candidates(ranked)
        assert fix, "the container CVE ranks as a fix"
        assert fix[0].exposure != sprint_signal.INTERNET
        assert fix[0].exposure == sprint_signal.DEPLOYED
        assert fix[0].exposure_state == "deployed"
        assert "not placed behind" in fix[0].exposure_basis

    def test_a_finding_behind_a_probed_public_endpoint_is_internet(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        with client.app.state.db.session() as session:
            surface = RepoSurface(
                repo_full_name=REPO,
                kind="entry_point",
                name="Public web app",
                exposure="internet",
                selectors={"paths": ["orders/**"]},
            )
            session.add(surface)
            session.flush()
            session.add(
                PublicEndpoint(
                    url="https://app.example.test",
                    repo_full_name=REPO,
                    surface_id=surface.id,
                    last_status="probed",
                    last_probed_at=utcnow(),
                )
            )
        _post(client, "sast", [finding_payload(severity="high")], "run-s1")
        run_compaction()

        ranked = sprint_signal.rank(
            catalog, _report(**EXPOSED), [REPO], db=client.app.state.db
        )

        fix = _fix_candidates(ranked)[0]
        assert fix.exposure == sprint_signal.INTERNET
        assert fix.exposure_state == "internet_observed"
        assert "Public web app" in fix.exposure_basis

    def test_a_declared_internet_surface_alone_does_not_raise_it(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        """Declared is shown as declared and does not move the factor (D2.5)."""
        onboard(client, admin_auth)
        with client.app.state.db.session() as session:
            session.add(
                RepoSurface(
                    repo_full_name=REPO,
                    kind="entry_point",
                    name="Public web app",
                    exposure="internet",
                    selectors={"paths": ["orders/**"]},
                )
            )
        _post(client, "sast", [finding_payload(severity="high")], "run-s2")
        run_compaction()

        ranked = sprint_signal.rank(
            catalog,
            _report(production_lag=[ProductionLag(repo_full_name=REPO, status="at_head")]),
            [REPO],
            db=client.app.state.db,
        )

        fix = _fix_candidates(ranked)[0]
        assert fix.exposure == sprint_signal.DEPLOYED
        assert fix.exposure_state == "declared_internet"
        assert "declared" in fix.exposure_basis

    def test_without_the_database_exposure_is_not_measured(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="high")], "run-s3")
        run_compaction()

        ranked = sprint_signal.rank(catalog, _report(**EXPOSED), [REPO])

        fix = _fix_candidates(ranked)[0]
        assert fix.exposure != sprint_signal.INTERNET


# ---------------------------------------------------------------------------
# No fix: an acceptance candidate, never a story
# ---------------------------------------------------------------------------


class TestNoFixGoesToAcceptance:
    def _seed(self, client: Any, admin_auth: dict[str, str], run_compaction: Any) -> None:
        onboard(client, admin_auth)
        # No `fixed_version` on a container finding: the scanner says no fix
        # is published, which `guidance` reads as effort `no_fix`.
        _post(client, "containers", [_container_cve(raw={"fixed_version": None})], "run-n1")
        run_compaction()

    def test_a_no_fix_group_is_an_acceptance_candidate(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        ranked = sprint_signal.rank(catalog, _report(), [REPO], db=client.app.state.db)

        assert not _fix_candidates(ranked)
        accept = [c for c in ranked if c.kind == "acceptance"]
        assert len(accept) == 1
        assert "no_vendor_fix" in accept[0].title

    def test_it_is_never_a_story_payload(self) -> None:
        candidate = sprint_signal.Candidate(
            signal_key="a" * 16,
            kind="acceptance",
            repo_full_name=REPO,
            capability="containers",
            title="Accept with no_vendor_fix",
            ref="rule:CVE-2031-1111",
            findings=1,
            risk_removed=5.0,
            risk_basis={"high": 1},
            exposure=1.0,
            exposure_basis="x",
            effort=5.0,
            effort_basis="no_fix",
            score=1.0,
        )
        with pytest.raises(ValueError, match="acceptance"):
            sprint_signal.story_payload(candidate, rank_at=1)

    def test_the_section_lists_it_apart_from_the_stories(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        self._seed(client, admin_auth, run_compaction)

        section = daily_briefing.next_sprint_section(
            catalog,
            client.app.state.db,
            _report(),
            now=utcnow(),
            as_of=None,
            board=BoardRead(stories={}, as_of=utcnow()),
        )

        assert not [c for c in section.data["candidates"] if c["kind"] == "acceptance"]
        assert section.data["acceptance_candidates"]
        assert section.data["acceptance_candidates"][0]["kind"] == "acceptance"


# ---------------------------------------------------------------------------
# Contextual band in risk removed
# ---------------------------------------------------------------------------


class TestContextualBand:
    def test_risk_removed_uses_the_environmental_band_in_force(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="medium")], "run-e1")
        run_compaction()
        finding_id = str(catalog.query("SELECT finding_id FROM findings")[0][0])
        with client.app.state.db.session() as session:
            session.add(
                EnvironmentalScore(
                    finding_id=finding_id,
                    repo_full_name=REPO,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base=6.5,
                    environmental=9.8,
                    base_band="medium",
                    env_band="critical",
                    scanner_severity="medium",
                    effective_severity="critical",
                    facts_json=[],
                )
            )

        ranked = sprint_signal.rank(catalog, _report(), [REPO], db=client.app.state.db)

        fix = _fix_candidates(ranked)[0]
        assert fix.risk_basis == {"medium": 1}
        assert fix.contextual_basis == {"critical": 1}
        assert fix.risk_removed == sprint_signal.SEVERITY_WEIGHT["critical"]
        assert "contextual" in fix.explain()

    def test_with_no_score_the_contextual_band_is_the_scanners_and_says_so(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(severity="medium")], "run-e2")
        run_compaction()

        ranked = sprint_signal.rank(catalog, _report(), [REPO], db=client.app.state.db)

        fix = _fix_candidates(ranked)[0]
        assert fix.contextual_basis == {"medium": 1}
        assert fix.risk_removed == sprint_signal.SEVERITY_WEIGHT["medium"]
        assert "no environmental score" in fix.explain()


# ---------------------------------------------------------------------------
# Full titles
# ---------------------------------------------------------------------------


LONG = (
    "gcc: Integer wrap in std::basic_string::_M_replace_aux when the requested "
    "length overflows size_type on a thirty-two bit target"
)


class TestFullTitles:
    def test_a_candidate_carries_the_whole_title(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        assert len(LONG) > 90
        onboard(client, admin_auth)
        _post(client, "sast", [finding_payload(rule_id="LONG-1", title=LONG)], "run-t1")
        run_compaction()

        ranked = sprint_signal.rank(catalog, _report(), [REPO], db=client.app.state.db)

        assert _fix_candidates(ranked)[0].title == LONG

    def test_a_story_title_over_the_limit_is_cut_at_a_word(self) -> None:
        words = " ".join(f"word{i:03d}" for i in range(60))  # 479 characters
        title = sprint_signal.story_title(words)
        assert len(title) <= 255
        assert title.endswith("…")
        assert words.startswith(title[:-1].rstrip())
        assert words[len(title[:-1].rstrip())] == " "

    def test_a_short_title_is_untouched(self) -> None:
        assert sprint_signal.story_title(LONG) == LONG


# ---------------------------------------------------------------------------
# Verified removed, beside claimed
# ---------------------------------------------------------------------------


class TestVerifiedRemoved:
    def test_the_metric_reports_findings_closed_by_absence(
        self, client: Any, admin_auth: dict[str, str], run_compaction: Any, catalog: Any
    ) -> None:
        onboard(client, admin_auth)
        _post(
            client,
            "sast",
            [
                finding_payload(rule_id="CWE-89", severity="high", symbol="a"),
                finding_payload(rule_id="CWE-89", severity="high", symbol="b",
                                file_path="orders/other.py"),
            ],
            "run-v1",
        )
        run_compaction()
        ids = [str(r[0]) for r in catalog.query("SELECT finding_id FROM findings")]
        # One of the two closed by absence after the story was filed; the
        # other is still open.
        update_findings(
            catalog,
            locate_findings(catalog, ids[:1]),
            "status = ?, resolved_at = ?",
            ["fixed", NOW - timedelta(days=1)],
        )
        group = next(g for g in guidance.fix_groups(catalog, asset_id=REPO)
                     if g.fix_id.startswith("rule:CWE-89"))
        key = sprint_signal.signal_key(REPO, "fix", group.fix_id)
        done = story(
            id=9,
            bucket="done",
            closed_at=(NOW - timedelta(days=1)).isoformat(),
            created_at=(NOW - timedelta(days=6)).isoformat(),
            tags=[sprint_signal.SIGNAL_TAG, sprint_signal.key_tag(key), f"repo:{REPO}"],
            detail=f"MyKronos signal `{key}`; risk removed 10.",
            acceptance_criteria=[
                f"A re-scan of {REPO} no longer reports the 2 sast finding(s) this "
                f"change covers ({group.fix_id})."
            ],
        )
        board = BoardRead(stories={"done": [done]}, as_of=NOW)

        week = sprint_signal.weekly_metric(board, now=NOW, catalog=catalog)["weeks"][0]

        assert week["risk_removed"] == 10.0  # claimed at filing
        assert week["risk_claimed"] == 10.0
        assert week["risk_verified_removed"] == sprint_signal.SEVERITY_WEIGHT["high"]
        assert week["findings_verified_closed"] == 1

    def test_without_the_lake_verified_is_not_measured_not_zero(self) -> None:
        board = BoardRead(stories={}, as_of=NOW)
        week = sprint_signal.weekly_metric(board, now=NOW)["weeks"][0]
        assert week["risk_verified_removed"] is None
