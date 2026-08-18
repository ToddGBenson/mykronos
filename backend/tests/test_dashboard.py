"""Dashboard query service and API — spec 10 §2, §4, §5, §7; spec 12 §5."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.schemas import Severity
from tests.conftest import (
    CAPABILITY,
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard


@pytest.fixture
def seeded(client: TestClient, admin_auth: dict[str, str], run_compaction):
    """An onboarded repo with sast enabled and a few findings in the lake."""
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast"]},
        headers=admin_auth,
    )

    token = issue_token(client, REPO, CAPABILITY)
    auth = {"Authorization": f"Bearer {token}"}
    post_scan(client, auth, scan_run_id="run-1")
    post_findings(
        client,
        auth,
        [
            finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
            finding_payload(rule_id="CWE-79", severity="high", symbol="b"),
            finding_payload(rule_id="CWE-22", severity="low", symbol="c"),
        ],
        scan_run_id="run-1",
    )
    run_compaction()
    return repo_id


class TestPortfolio:
    def test_counts_open_findings_by_severity(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get("/api/dashboard/portfolio", headers=admin_auth).json()

        row = body["repos"][0]
        assert row["repo_full_name"] == REPO
        assert row["severity_counts"]["critical"] == 1
        assert row["severity_counts"]["high"] == 1
        assert row["total_open"] == 3

    def test_summary_cards_aggregate_the_portfolio(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        summary = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["summary"]
        assert summary["open_critical"] == 1
        assert summary["open_high"] == 1

    def test_a_freshly_onboarded_repo_says_awaiting_first_scan(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """spec 10 §7: not a blank "0 findings", which reads as clean."""
        onboard(client, admin_auth)

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["awaiting_first_scan"] is True
        assert row["last_scan_at"] is None

    def test_per_capability_scan_state_is_reported(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """A repo can have one capability scanning and another that has never
        run; a single repo-level flag would hide that."""
        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        # sast is pending until its PR merges, so enabled_capabilities is still
        # empty and there is nothing to report per capability yet.
        assert row["pending_capabilities"] == ["sast"]
        assert row["enabled_capabilities"] == []

    def test_a_concourse_repo_is_enabled_by_its_grants(
        self, client: TestClient, admin_auth: dict[str, str], auth
    ) -> None:
        """`enabled_capabilities` is the Actions installer's ledger, and a
        Concourse-scanned repo never merges an install PR - the landing page
        showed three capabilities per repo while eleven were reporting
        (2026-08-15). The grants are what enabled means for those repos."""
        onboard(client, admin_auth, scanned_by="concourse")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        # The auth fixture grants sast when it issues the token.
        assert "sast" in row["enabled_capabilities"]
        assert any(s["capability"] == "sast" for s in row["capability_states"]), (
            "granted capabilities get a per-capability state row"
        )

    def test_an_actions_repo_still_reads_from_the_installer_ledger(
        self, client: TestClient, admin_auth: dict[str, str], auth
    ) -> None:
        """For Actions repos the install PR is real, and a grant without a
        merged workflow is genuinely not-yet-enabled."""
        onboard(client, admin_auth, scanned_by="github_actions")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["enabled_capabilities"] == []

    def test_risk_score_is_null_not_zero(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """Oracle lands in Phase 3. Zero would read as "assessed, no risk"."""
        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        assert row["risk_score"] is None
        assert row["recommendation"] is None

    def test_agrees_with_open_findings_when_asset_id_is_missing(
        self, client: TestClient, admin_auth: dict[str, str], catalog, seeded
    ) -> None:
        """spec 18 §1, D-061. Before the fix, this exact drift made the
        portfolio's count and the Findings tab's count disagree: the portfolio
        counted findings by `repo_full_name` (present on every row) while
        every other repo-scoped query, including this repo's own Findings
        tab, counted by `asset_id` (absent on an unmigrated row) — so an
        unmigrated finding was visible in one count and not the other. Both
        now key on asset_id, so both drop it, consistently."""
        from mykronos.lake.mutate import locate_findings, update_findings

        ids = [
            str(r[0])
            for r in catalog.query(
                "SELECT finding_id FROM findings WHERE severity = 'critical'"
            )
        ]
        update_findings(
            catalog, locate_findings(catalog, ids), "asset_id = NULL", []
        )

        portfolio_row = client.get(
            "/api/dashboard/portfolio", headers=admin_auth
        ).json()["repos"][0]
        open_findings_page = client.get(
            f"/api/dashboard/repos/{seeded}/open-findings", headers=admin_auth
        ).json()

        assert portfolio_row["total_open"] == 2
        assert open_findings_page["total"] == 2

    def test_offboarded_repos_are_hidden_but_retrievable(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 10 §7: excluded by default, available for audit."""
        client.delete(f"/api/repos/{seeded}", headers=admin_auth)

        assert client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"] == []

        including = client.get(
            "/api/dashboard/portfolio",
            params={"include_removed": True},
            headers=admin_auth,
        ).json()
        assert including["repos"][0]["status"] == "removed"

    def test_an_empty_portfolio_is_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        body = client.get("/api/dashboard/portfolio", headers=admin_auth).json()
        assert body["repos"] == []
        assert body["summary"]["open_critical"] == 0


class TestFindings:
    def test_lists_findings_worst_first(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """The top of the list should be what to work on."""
        body = client.get(f"/api/dashboard/repos/{seeded}/findings", headers=admin_auth).json()

        assert body["total"] == 3
        assert [f["severity"] for f in body["findings"]] == ["critical", "high", "low"]

    def test_filters_by_severity(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"severity": "critical"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 1

    def test_paginates(self, client: TestClient, admin_auth: dict[str, str], seeded) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"limit": 2, "offset": 2},
            headers=admin_auth,
        ).json()
        assert body["total"] == 3
        assert len(body["findings"]) == 1

    def test_a_repo_name_is_not_a_valid_path_id(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """`owner/repo` has a slash in it, so it cannot be one path segment.
        The endpoint takes the onboarding id and says so."""
        response = client.get(f"/api/dashboard/repos/{REPO}/findings", headers=admin_auth)
        assert response.status_code == 404

    def test_an_unknown_repo_is_404(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        assert (
            client.get("/api/dashboard/repos/nope/findings", headers=admin_auth).status_code == 404
        )

    def test_filters_by_rule_id_substring(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """Spec 17 §3 — free-text, case-insensitive, matched against rule_id
        or title, not a category filter with a count on a button."""
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"rule_id": "cwe-89"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 1
        assert body["findings"][0]["rule_id"] == "CWE-89"

    def test_an_unmatched_rule_id_is_zero_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"rule_id": "nothing-matches-this"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 0
        assert body["findings"] == []

    def test_a_future_first_seen_after_excludes_everything(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """Spec 17 §3 date-range filter — a bound nothing can satisfy yet."""
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"first_seen_after": "2099-01-01T00:00:00Z"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 0

    def test_a_far_past_first_seen_before_excludes_everything(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"first_seen_before": "2000-01-01T00:00:00Z"},
            headers=admin_auth,
        ).json()
        assert body["total"] == 0

    def test_a_superseded_finding_names_its_replacement(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """Spec 17 §5.1 — `superseded_by` is selected now, so a re-fingerprinted
        finding's prior identity can be followed to what replaced it. Nothing
        in `seeded` is actually superseded, so this only pins the shape: the
        field is present, and null rather than absent, for an ordinary open
        finding."""
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            headers=admin_auth,
        ).json()
        assert all(f["superseded_by"] is None for f in body["findings"])


class TestRawOutputIsAdminOnly:
    """spec 12 §5 — a Secrets finding's raw record quotes the secret."""

    def test_admins_receive_raw_output(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(f"/api/dashboard/repos/{seeded}/findings", headers=admin_auth).json()
        assert body["raw_output_included"] is True
        assert body["findings"][0]["raw_finding_json"] is not None

    def test_viewers_do_not(self, client: TestClient, viewer_auth: dict[str, str], seeded) -> None:
        """Withheld at the query layer, not hidden in the UI — "not rendered"
        is not "not sent"."""
        body = client.get(f"/api/dashboard/repos/{seeded}/findings", headers=viewer_auth).json()

        assert body["raw_output_included"] is False
        # Null, not absent: the value is what must not be transmitted, and a
        # stable key shape spares every caller an optional-property dance.
        assert body["findings"][0]["raw_finding_json"] is None
        assert body["findings"][0]["code_snippet"] is None

    def test_viewers_can_still_see_the_findings_themselves(
        self, client: TestClient, viewer_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(f"/api/dashboard/repos/{seeded}/findings", headers=viewer_auth).json()
        assert body["total"] == 3
        assert body["findings"][0]["severity"] == "critical"


class TestStatusWriteBack:
    def _first_finding(self, client: TestClient, auth: dict[str, str], repo_id: str) -> str:
        body = client.get(f"/api/dashboard/repos/{repo_id}/findings", headers=auth).json()
        return str(body["findings"][0]["finding_id"])

    def test_marking_a_false_positive_persists(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "generated code directory"},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json()["reason_supplied"] is True

        after = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"finding_status": "false_positive"},
            headers=admin_auth,
        ).json()
        assert after["total"] == 1

    def test_a_reason_free_dismissal_is_recorded_but_flagged(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 11 §4: reasons are what make a learning actionable rather than
        a statistic, so a bare click is low-confidence."""
        finding_id = self._first_finding(client, admin_auth, seeded)

        body = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive"},
            headers=admin_auth,
        ).json()

        assert body["reason_supplied"] is False
        assert "low-confidence" in body["retro_signal"]

    def test_a_human_cannot_hand_set_fixed(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """That would put a claim in the lake no scan supports, and MTTF would
        start measuring opinions."""
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "fixed"},
            headers=admin_auth,
        )

        assert response.status_code == 422
        assert "observations" in response.json()["detail"]

    def test_viewers_cannot_change_status(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth, seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)

        response = client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "x"},
            headers=viewer_auth,
        )
        assert response.status_code == 403

    def test_the_change_is_audited(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """spec 12 §7."""
        from mykronos.db.models import AuditLogEntry

        finding_id = self._first_finding(client, admin_auth, seeded)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "accepted_risk", "reason": "staging only"},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            entry = (
                session.query(AuditLogEntry).filter(AuditLogEntry.action == "finding.status").one()
            )
        assert entry.detail["reason"] == "staging only"
        assert entry.detail["new_status"] == "accepted_risk"

    def test_an_unknown_finding_is_404(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        assert (
            client.patch(
                "/api/dashboard/findings/nope/status",
                json={"status": "false_positive"},
                headers=admin_auth,
            ).status_code
            == 404
        )

    def test_a_dismissed_finding_leaves_the_open_counts(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        finding_id = self._first_finding(client, admin_auth, seeded)
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive", "reason": "x"},
            headers=admin_auth,
        )

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        assert row["severity_counts"]["critical"] == 0
        assert row["total_open"] == 2


@pytest.fixture
def outstanding(client: TestClient, admin_auth: dict[str, str], run_compaction):
    """A repo carrying each thing the open-findings view exists to handle.

    One rule firing in three files, one CVE reported by two different
    scanners, and a pair of findings that are only dangerous together.
    """
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": ["sast", "atlas", "containers"]},
        headers=admin_auth,
    )
    token = issue_token(client, REPO, "sast", "atlas", "containers")
    auth = {"Authorization": f"Bearer {token}"}

    post_scan(client, auth, scan_run_id="run-sast")
    post_findings(
        client,
        auth,
        [
            finding_payload(
                rule_id="CWE-79",
                title="Reflected cross-site scripting",
                severity="high",
                file_path=f"web/{name}.py",
                symbol=name,
            )
            for name in ("a", "b", "c")
        ]
        + [
            finding_payload(rule_id="CWE-89", severity="critical"),
            finding_payload(
                rule_id="CWE-306",
                title="Missing authentication check",
                severity="medium",
                symbol="handler",
            ),
        ],
        scan_run_id="run-sast",
    )

    for capability, severity in (("atlas", "high"), ("containers", "critical")):
        post_scan(client, auth, scan_run_id=f"run-{capability}", capability=capability)
        post_findings(
            client,
            auth,
            [dependency_finding(severity=severity)],
            scan_run_id=f"run-{capability}",
            capability=capability,
        )

    run_compaction()
    return repo_id


class TestOpenFindings:
    """The outstanding-work view: open only, deduplicated, triaged, correlated."""

    def _page(self, client: TestClient, auth: dict[str, str], repo_id: str, **params):
        return client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings", params=params, headers=auth
        ).json()

    def _group(self, page, rule_id: str):
        return next(g for g in page["groups"] if g["rule_id"] == rule_id)

    def test_one_rule_in_three_files_is_one_row(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """One decision, three places to change it. The flat list makes that
        look like three problems and inflates every count taken off it."""
        page = self._page(client, admin_auth, outstanding)

        xss = self._group(page, "CWE-79")
        assert xss["occurrences"] == 3
        assert sorted(loc["file_path"] for loc in xss["locations"]) == [
            "web/a.py",
            "web/b.py",
            "web/c.py",
        ]
        # Nothing is hidden: every occurrence keeps its own finding_id, because
        # a disposition is recorded against a finding and not against a group.
        assert len({loc["finding_id"] for loc in xss["locations"]}) == 3

    def test_the_same_cve_from_two_scanners_is_one_row(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """The dependency scan and the container scan both see urllib3. That
        is one vulnerability reported twice, not two vulnerabilities."""
        cve = self._group(self._page(client, admin_auth, outstanding), "CVE-2024-4812")

        assert cve["occurrences"] == 2
        assert sorted(cve["capabilities"]) == ["atlas", "containers"]
        # The worst member's severity. Scanners disagree about one CVE all the
        # time, and the lower number is never the safe one to display.
        assert cve["severity"] == "critical"

    def test_it_says_how_much_it_collapsed(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Silent deduplication is indistinguishable from losing rows."""
        page = self._page(client, admin_auth, outstanding)

        assert page["total"] == 7
        assert len(page["groups"]) == 4
        assert page["deduplicated"] == 3

    def test_only_open_findings_are_shown(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        page = self._page(client, admin_auth, outstanding)
        accepted = self._group(page, "CWE-79")["locations"][0]["finding_id"]

        client.patch(
            f"/api/dashboard/findings/{accepted}/status",
            json={"status": "accepted_risk", "reason": "behind the VPN"},
            headers=admin_auth,
        )

        after = self._page(client, admin_auth, outstanding)
        assert after["total"] == 6
        assert self._group(after, "CWE-79")["occurrences"] == 2

    def test_a_dispositioned_finding_is_still_reachable_by_name(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Open-only is the default, not a wall. An accepted risk is a decision
        somebody has to be able to revisit — spec 10's own reason for keeping
        the reason with it."""
        page = self._page(client, admin_auth, outstanding)
        accepted = self._group(page, "CWE-79")["locations"][0]["finding_id"]
        client.patch(
            f"/api/dashboard/findings/{accepted}/status",
            json={"status": "accepted_risk", "reason": "behind the VPN"},
            headers=admin_auth,
        )

        body = self._page(
            client, admin_auth, outstanding, finding_status="accepted_risk"
        )
        assert body["finding_status"] == "accepted_risk"
        assert body["total"] == 1

    def test_a_toxic_combination_is_named(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Detected from the findings themselves, not read out of
        `remediation_events` — those only exist where Patchwork has run, and a
        repo that never enabled auto-remediation is exactly the one nobody has
        told about its unauthenticated database."""
        page = self._page(client, admin_auth, outstanding)

        assert len(page["toxic_combinations"]) == 1
        combination = page["toxic_combinations"][0]
        assert combination["name"] == "Unauthenticated injectable endpoint"
        assert sorted(m["rule_id"] for m in combination["members"]) == [
            "CWE-306",
            "CWE-89",
        ]

    def test_a_member_is_not_triaged_on_its_own(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Each half being individually unremarkable is what a toxic
        combination *is*. Triaging the halves is how one gets waved through
        twice — the medium especially, which alone is 'needs human judgment'."""
        page = self._page(client, admin_auth, outstanding)

        missing_auth = self._group(page, "CWE-306")
        assert missing_auth["triage"] == "toxic_combination"
        assert missing_auth["toxic_combination_ids"] == [
            page["toxic_combinations"][0]["combination_id"]
        ]

    def test_a_filtered_view_still_reports_the_combination(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Half a combination is routinely a medium from another scanner. A
        view filtered to `critical` that reported no combinations would be
        silent at exactly the moment somebody is looking at the worst row."""
        page = self._page(client, admin_auth, outstanding, severity="critical")

        assert [g["rule_id"] for g in page["groups"]] == ["CWE-89", "CVE-2024-4812"]
        assert len(page["toxic_combinations"]) == 1

    def test_an_unfixable_rule_is_labelled_as_needing_a_person(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """The same vocabulary Patchwork triages with, so the platform cannot
        call a rule one thing here and another on the remediation tab."""
        page = self._page(client, admin_auth, outstanding)

        assert self._group(page, "CWE-79")["triage"] == "true_positive"
        assert "no prior dismissal" in self._group(page, "CWE-79")["triage_rationale"]

    def test_a_dismissed_rule_reads_as_a_likely_false_positive(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """The Knowledge Store's whole purpose is that the platform does not
        ask twice. Dismissing one occurrence with a written reason has to
        colour the ones still open, and with the same words Patchwork uses —
        otherwise the platform calls a rule a false positive on one page while
        generating a fix for it on another."""
        page = self._page(client, admin_auth, outstanding)
        dismissed = self._group(page, "CWE-79")["locations"][0]["finding_id"]

        client.patch(
            f"/api/dashboard/findings/{dismissed}/status",
            json={"status": "false_positive", "reason": "the template escapes on render"},
            headers=admin_auth,
        )

        after = self._group(self._page(client, admin_auth, outstanding), "CWE-79")
        assert after["occurrences"] == 2
        assert after["triage"] == "likely_false_positive"
        assert "the template escapes on render" in after["triage_rationale"]

    def test_raw_output_is_never_served_here(
        self, client: TestClient, viewer_auth: dict[str, str], outstanding
    ) -> None:
        """A group is a decision to make; the bytes of a secrets finding belong
        on the detail pane, behind the admin check that always guarded them."""
        response = client.get(
            f"/api/dashboard/repos/{outstanding}/open-findings", headers=viewer_auth
        )

        assert response.status_code == 200
        assert "code_snippet" not in response.text
        assert response.json()["total"] == 7

    def test_an_unknown_repo_is_404(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        assert (
            client.get(
                "/api/dashboard/repos/nope/open-findings", headers=admin_auth
            ).status_code
            == 404
        )

    def test_filters_by_rule_id_without_touching_the_correlation_pool(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """Spec 17 §3. `rule_id` narrows what's on screen the same way severity
        and capability already do — and, like them, must not narrow the
        correlation pool, or a filtered view could stop reporting a toxic
        combination it still contains half of."""
        page = self._page(client, admin_auth, outstanding, rule_id="cwe-79")
        assert {g["rule_id"] for g in page["groups"]} == {"CWE-79"}
        assert page["matching"] == 3  # the three CWE-79 occurrences, not 7


class TestThreatIntel:
    """Spec 17 §4.4 — public exploitation data matched against open findings."""

    def test_a_cve_naming_finding_appears_with_no_match_row_yet(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        """'Not yet fetched' and 'fetched, not exploited' must not look the
        same — a CVE-naming finding is returned even before the refresh job
        has ever run, with an honest `in_kev: false` rather than omitted."""
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-cve")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="CVE-2024-0001", severity="high", symbol="cve-a")],
            scan_run_id="run-cve",
        )
        run_compaction()

        body = client.get("/api/dashboard/threat-intel", headers=admin_auth).json()
        entry = next(e for e in body if e["cve_id"] == "CVE-2024-0001")
        assert entry["in_kev"] is False
        assert entry["epss_score"] is None
        assert entry["worst_severity"] == "high"
        assert REPO in entry["repo_full_names"]

    def test_kev_sorts_before_a_higher_epss(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        from mykronos.db.models import ThreatIntelMatch

        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-cve-2")
        post_findings(
            client,
            auth,
            [
                finding_payload(rule_id="CVE-2024-0001", severity="high", symbol="a"),
                finding_payload(rule_id="CVE-2024-0002", severity="high", symbol="b"),
            ],
            scan_run_id="run-cve-2",
        )
        run_compaction()

        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-0001", in_kev=False, epss_score=0.95))
            session.add(ThreatIntelMatch(cve_id="CVE-2024-0002", in_kev=True, epss_score=0.1))

        body = client.get("/api/dashboard/threat-intel", headers=admin_auth).json()
        ordered = [e["cve_id"] for e in body if e["cve_id"] in {"CVE-2024-0001", "CVE-2024-0002"}]
        assert ordered == ["CVE-2024-0002", "CVE-2024-0001"]  # KEV first, regardless of EPSS

    def test_a_finding_with_no_cve_contributes_nothing(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        """`seeded` is all CWE rule_ids — no CVE anywhere in it."""
        body = client.get("/api/dashboard/threat-intel", headers=admin_auth).json()
        assert body == []

    def test_it_needs_authentication(self, client: TestClient) -> None:
        assert client.get("/api/dashboard/threat-intel").status_code == 401


class TestOpenFindingsKevBoost:
    """spec 17 §5.6 — a toxic combination naming a KEV-listed CVE says so."""

    def test_a_combination_member_naming_a_kev_cve_is_flagged(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        from mykronos.db.models import ThreatIntelMatch

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-combo")
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    rule_id="CWE-89", severity="high", symbol="a", file_path="web/a.py"
                ),
                finding_payload(
                    rule_id="CWE-306",
                    title="CVE-2024-55555 missing auth check",
                    severity="medium",
                    symbol="b",
                    file_path="web/a.py",
                ),
            ],
            scan_run_id="run-combo",
        )
        run_compaction()

        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-55555", in_kev=True))

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth
        ).json()

        assert len(body["toxic_combinations"]) == 1
        assert body["toxic_combinations"][0]["rationale"].startswith(
            "**Actively exploited.**"
        )


class TestOpenFindingsThreatIntelBadge:
    """spec 17 §4.4, #20 — cve_id/in_kev/epss_score stamped onto each group."""

    def _seed(self, client, admin_auth, run_compaction, rule_id, title=None):
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-badge")
        overrides: dict[str, Any] = {"rule_id": rule_id, "severity": "high", "symbol": "a"}
        if title is not None:
            overrides["title"] = title
        post_findings(client, auth, [finding_payload(**overrides)], scan_run_id="run-badge")
        run_compaction()
        return repo_id

    def _group(self, client, admin_auth, repo_id):
        page = client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth
        ).json()
        return page["groups"][0]

    def test_a_finding_with_no_cve_gets_null_fields(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed(client, admin_auth, run_compaction, "CWE-89")
        group = self._group(client, admin_auth, repo_id)

        assert group["cve_id"] is None
        assert group["in_kev"] is None
        assert group["epss_score"] is None

    def test_a_cve_with_no_match_row_is_checked_not_null(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """Distinct from the no-CVE case above: `in_kev` becomes `False`,
        not `None` — a CVE was found and looked up, it just isn't KEV-listed
        (or hasn't been fetched yet)."""
        repo_id = self._seed(client, admin_auth, run_compaction, "CVE-2024-77777")
        group = self._group(client, admin_auth, repo_id)

        assert group["cve_id"] == "CVE-2024-77777"
        assert group["in_kev"] is False
        assert group["epss_score"] is None

    def test_a_kev_listed_cve_is_flagged(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        from mykronos.db.models import ThreatIntelMatch

        repo_id = self._seed(client, admin_auth, run_compaction, "CVE-2024-88888")
        with client.app.state.db.session() as session:
            session.add(
                ThreatIntelMatch(cve_id="CVE-2024-88888", in_kev=True, epss_score=0.87)
            )

        group = self._group(client, admin_auth, repo_id)
        assert group["in_kev"] is True
        assert group["epss_score"] == pytest.approx(0.87)


class TestOpenFindingsThreatIntelFilters:
    """spec 17 §3 / #20 — min_epss/kev_only, applied against a different database
    than the SQL query that fetched the candidate rows."""

    def _seed_two(self, client, admin_auth, run_compaction):
        from mykronos.db.models import ThreatIntelMatch

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-filter")
        post_findings(
            client,
            auth,
            [
                finding_payload(rule_id="CVE-2024-10001", severity="high", symbol="a"),
                finding_payload(rule_id="CVE-2024-10002", severity="high", symbol="b"),
                finding_payload(rule_id="CWE-89", severity="high", symbol="c"),  # no CVE at all
            ],
            scan_run_id="run-filter",
        )
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-10001", in_kev=True, epss_score=0.2))
            session.add(ThreatIntelMatch(cve_id="CVE-2024-10002", in_kev=False, epss_score=0.9))
        return repo_id

    def _page(self, client, admin_auth, repo_id, **params):
        return client.get(
            f"/api/dashboard/repos/{repo_id}/open-findings", params=params, headers=admin_auth
        ).json()

    def test_kev_only_keeps_only_kev_listed(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_two(client, admin_auth, run_compaction)
        page = self._page(client, admin_auth, repo_id, kev_only=True)
        assert [g["cve_id"] for g in page["groups"]] == ["CVE-2024-10001"]
        assert page["matching"] == 1

    def test_min_epss_keeps_only_high_enough_scores(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_two(client, admin_auth, run_compaction)
        page = self._page(client, admin_auth, repo_id, min_epss=0.5)
        assert [g["cve_id"] for g in page["groups"]] == ["CVE-2024-10002"]

    def test_a_finding_with_no_cve_never_matches_either_filter(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_two(client, admin_auth, run_compaction)
        page = self._page(client, admin_auth, repo_id, min_epss=0.0)
        cve_ids = {g["cve_id"] for g in page["groups"]}
        assert "CWE-89" not in cve_ids  # its group_key, not its cve_id — sanity check below
        assert None not in cve_ids

    def test_no_filter_is_unaffected(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed_two(client, admin_auth, run_compaction)
        page = self._page(client, admin_auth, repo_id)
        assert len(page["groups"]) == 3


class TestScanHealth:
    def test_reports_runs_and_failure_rate(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-2", scan_status="failure")
        run_compaction()

        body = client.get(f"/api/dashboard/repos/{seeded}/scan-health", headers=admin_auth).json()

        sast = next(c for c in body["capabilities"] if c["capability"] == "sast")
        assert sast["runs"] == 2
        assert sast["failed"] == 1
        assert sast["failure_rate"] == 0.5

    def test_a_repo_with_no_scans_reports_nothing_rather_than_failing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        body = client.get(f"/api/dashboard/repos/{repo_id}/scan-health", headers=admin_auth).json()
        assert body["capabilities"] == []


class TestPortfolioCarriesOracleScores:
    """The Risk and Oracle columns, which were placeholders until Phase 3."""

    async def _score(self, client, service):
        from mykronos.jobs import score_portfolio

        return await score_portfolio(client.app.state.db, service)

    @pytest.mark.anyio
    async def test_the_standing_score_reaches_the_portfolio(
        self, client, admin_auth, run_compaction, settings
    ) -> None:
        from mykronos.oracle import load_policy
        from mykronos.oracle.service import OracleService
        from tests.test_portfolio_job import register, seed_findings

        register(client, REPO, capabilities=["sast", "oracle"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        await self._score(
            client,
            OracleService(
                client.app.state.catalog,
                client.app.state.buffer,
                load_policy(settings.oracle_policy_path),
            ),
        )
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["risk_score"] == 63
        assert row["recommendation"] == "review_recommended"
        assert row["raw_risk_score"] > 0
        assert row["risk_assessed_at"] is not None

    def test_an_unjudged_repo_reports_null_not_zero(
        self, client, admin_auth, run_compaction
    ) -> None:
        """Zero would read as 'assessed, no risk'. Oracle is opt-in, and a repo
        nobody enabled it on has not been looked at."""
        from tests.test_portfolio_job import register, seed_findings

        register(client, REPO, capabilities=["sast"])
        seed_findings(client, REPO, 3, "critical")
        run_compaction()

        body = client.get("/api/dashboard/portfolio", headers=admin_auth).json()

        assert body["repos"][0]["risk_score"] is None
        assert body["summary"]["repos_not_assessed"] == 1
        assert body["summary"]["repos_no_go"] == 0

    @pytest.mark.anyio
    async def test_a_pr_gate_decision_does_not_become_the_standing_score(
        self, client, admin_auth, run_compaction, settings
    ) -> None:
        """Otherwise the portfolio would move every time somebody opened a
        branch, and the column would stop meaning 'how risky is this repo'."""
        from tests.test_portfolio_job import register, seed_findings

        register(client, REPO, capabilities=["sast", "oracle"])
        seed_findings(client, REPO, 6, "critical")
        run_compaction()

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'oracle')}"}
        client.post(
            "/api/oracle/evaluate",
            json={"decision_type": "pr_gate", "commit_sha": "abc", "pr_number": 3},
            headers=auth,
        )
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]

        assert row["risk_score"] is None


class TestTriageQueue:
    """ "What do I do next", across every repo at once (spec 10 §2.1)."""

    def _activate(self, client, repo: str, capabilities: list[str]) -> str:
        from tests.test_portfolio_job import register

        return register(client, repo, capabilities=capabilities)

    def test_ranks_worst_first_across_repos(self, client, admin_auth, run_compaction) -> None:
        from tests.test_portfolio_job import seed_findings

        self._activate(client, REPO, ["sast"])
        self._activate(client, "example-org/ledger-core", ["sast"])
        seed_findings(client, REPO, 1, "low")
        seed_findings(client, "example-org/ledger-core", 1, "critical")
        run_compaction()

        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        assert [item["severity"] for item in body["items"]] == ["critical", "low"]
        assert body["items"][0]["repo_full_name"] == "example-org/ledger-core"
        assert body["total_open"] == 2
        assert body["open_by_severity"]["critical"] == 1

    def test_each_row_carries_its_repo_and_a_link_target(
        self, client, admin_auth, run_compaction
    ) -> None:
        from tests.test_portfolio_job import seed_findings

        repo_id = self._activate(client, REPO, ["sast"])
        seed_findings(client, REPO, 1, "high")
        run_compaction()

        item = client.get("/api/dashboard/triage", headers=admin_auth).json()["items"][0]

        assert item["repo_id"] == repo_id
        assert item["repo_full_name"] == REPO

    def test_the_repo_verdict_is_carried_per_row(
        self, client, admin_auth, run_compaction, settings
    ) -> None:
        """So the queue reads without cross-referencing the portfolio table."""
        import asyncio

        from mykronos.jobs import score_portfolio
        from mykronos.oracle import load_policy
        from mykronos.oracle.service import OracleService
        from tests.test_portfolio_job import seed_findings

        self._activate(client, REPO, ["sast", "oracle"])
        seed_findings(client, REPO, 6, "critical")
        run_compaction()
        asyncio.run(
            score_portfolio(
                client.app.state.db,
                OracleService(
                    client.app.state.catalog,
                    client.app.state.buffer,
                    load_policy(settings.oracle_policy_path),
                ),
            )
        )
        run_compaction()

        item = client.get("/api/dashboard/triage", headers=admin_auth).json()["items"][0]

        assert item["repo_recommendation"] == "no_go"

    def test_offboarded_repos_are_not_work(self, client, admin_auth, run_compaction) -> None:
        """Their findings are still in the lake and still on their own page.
        A queue is a list of work, and a repo nobody scans is not work."""
        from tests.test_portfolio_job import register, seed_findings

        register(client, REPO, capabilities=["sast"], status="removed")
        seed_findings(client, REPO, 3, "critical")
        run_compaction()

        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        assert body["items"] == []
        assert body["total_open"] == 0

    def test_filters_narrow_the_queue(self, client, admin_auth, run_compaction) -> None:
        from tests.test_portfolio_job import seed_findings

        self._activate(client, REPO, ["sast"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        assert (
            client.get("/api/dashboard/triage?severity=high", headers=admin_auth).json()["items"]
            == []
        )
        assert (
            len(
                client.get("/api/dashboard/triage?severity=critical", headers=admin_auth).json()[
                    "items"
                ]
            )
            == 2
        )

    def test_filters_by_rule_id(self, client, admin_auth, run_compaction) -> None:
        """Spec 17 §3 — the same free-text `rule_id` filter as the per-repo
        views, on the portfolio-wide queue."""
        from tests.test_portfolio_job import seed_findings

        self._activate(client, REPO, ["sast"])
        seed_findings(client, REPO, 2, "critical")
        run_compaction()

        body = client.get("/api/dashboard/triage?rule_id=R0", headers=admin_auth).json()
        assert [item["rule_id"] for item in body["items"]] == ["R0"]

    def test_truncation_is_declared(self, client, admin_auth, run_compaction) -> None:
        """A queue that silently stops at the limit reads as 'that is all'."""
        from tests.test_portfolio_job import seed_findings

        self._activate(client, REPO, ["sast"])
        seed_findings(client, REPO, 3, "critical")
        run_compaction()

        body = client.get("/api/dashboard/triage?limit=2", headers=admin_auth).json()

        assert len(body["items"]) == 2
        assert body["truncated"] is True
        assert body["total_open"] == 3, "the count is of everything, not of the page"

    def test_an_empty_portfolio_is_not_an_error(self, client, admin_auth) -> None:
        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        assert body == {
            "items": [],
            "open_by_severity": dict.fromkeys(["critical", "high", "medium", "low", "info"], 0),
            "total_open": 0,
            "truncated": False,
        }

    def test_it_needs_authentication(self, client) -> None:
        assert client.get("/api/dashboard/triage").status_code == 401


class TestTriageQueueThreatIntel:
    """spec 17 §3 / #20 — the same cve_id/in_kev/epss_score badge, and the same
    kev_only/min_epss filters, on the portfolio-wide queue."""

    def _seed(self, client, admin_auth, run_compaction) -> None:
        from mykronos.db.models import ThreatIntelMatch
        from tests.test_portfolio_job import register

        register(client, REPO, capabilities=["sast"])
        token = issue_token(client, REPO, "sast")
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(client, auth, scan_run_id="run-queue-ti")
        post_findings(
            client,
            auth,
            [
                finding_payload(rule_id="CVE-2024-20001", severity="critical", symbol="a"),
                finding_payload(rule_id="CWE-89", severity="critical", symbol="b"),
            ],
            scan_run_id="run-queue-ti",
        )
        run_compaction()
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id="CVE-2024-20001", in_kev=True, epss_score=0.6))

    def test_badge_is_stamped_on_every_row(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        self._seed(client, admin_auth, run_compaction)
        items = client.get("/api/dashboard/triage", headers=admin_auth).json()["items"]

        by_rule = {item["rule_id"]: item for item in items}
        assert by_rule["CVE-2024-20001"]["in_kev"] is True
        assert by_rule["CVE-2024-20001"]["epss_score"] == pytest.approx(0.6)
        assert by_rule["CWE-89"]["cve_id"] is None
        assert by_rule["CWE-89"]["in_kev"] is None

    def test_kev_only_narrows_the_queue(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        self._seed(client, admin_auth, run_compaction)
        items = client.get(
            "/api/dashboard/triage?kev_only=true", headers=admin_auth
        ).json()["items"]
        assert [item["rule_id"] for item in items] == ["CVE-2024-20001"]

    def test_min_epss_narrows_the_queue(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        self._seed(client, admin_auth, run_compaction)
        items = client.get(
            "/api/dashboard/triage?min_epss=0.5", headers=admin_auth
        ).json()["items"]
        assert [item["rule_id"] for item in items] == ["CVE-2024-20001"]

        none_match = client.get(
            "/api/dashboard/triage?min_epss=0.99", headers=admin_auth
        ).json()["items"]
        assert none_match == []


class TestThreatModel:
    """spec 18 §6: a STRIDE-categorized attack-surface inventory."""

    def _seed(self, client, admin_auth: dict[str, str], run_compaction) -> str:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["dast", "secrets", "atlas"]},
            headers=admin_auth,
        )
        token = issue_token(client, REPO, "dast", "secrets", "atlas")
        auth = {"Authorization": f"Bearer {token}"}

        post_scan(client, auth, scan_run_id="run-dast", capability="dast")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="exposed-admin-panel", severity="high", symbol="a")],
            scan_run_id="run-dast",
            capability="dast",
        )
        post_scan(client, auth, scan_run_id="run-secrets", capability="secrets")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id="hardcoded-api-key", severity="critical", symbol="b")],
            scan_run_id="run-secrets",
            capability="secrets",
        )
        run_compaction()
        return repo_id

    def test_findings_land_in_every_category_their_capability_maps_to(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed(client, admin_auth, run_compaction)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

        by_stride = {c["stride"]: c["findings"] for c in body["categories"]}
        assert {f["rule_id"] for f in by_stride["spoofing"]} == {"exposed-admin-panel"}
        assert {f["rule_id"] for f in by_stride["tampering"]} == {"exposed-admin-panel"}
        assert {f["rule_id"] for f in by_stride["information_disclosure"]} == {
            "hardcoded-api-key"
        }

    def test_a_category_with_no_capability_mapped_to_it_is_empty_not_absent(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """Repudiation has no capability behind it (spec 18 §6.2) — it should
        still appear, empty, rather than being missing from the response."""
        repo_id = self._seed(client, admin_auth, run_compaction)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

        stride_names = {c["stride"] for c in body["categories"]}
        assert "repudiation" in stride_names
        assert [c for c in body["categories"] if c["stride"] == "repudiation"][0][
            "findings"
        ] == []

    def test_the_mapping_resolution_is_disclosed(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed(client, admin_auth, run_compaction)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

        assert body["mapping_resolution"] == "capability"

    def test_a_repo_with_no_supply_chain_evidence_reports_none(
        self, client, admin_auth: dict[str, str], run_compaction
    ) -> None:
        repo_id = self._seed(client, admin_auth, run_compaction)

        body = client.get(
            f"/api/dashboard/repos/{repo_id}/threat-model", headers=admin_auth
        ).json()

        assert body["supply_chain"] is None


def test_severity_enum_covers_every_portfolio_bucket() -> None:
    """A new severity must not silently vanish from the summary."""
    from mykronos.dashboard import SEVERITIES

    assert set(SEVERITIES) == {s.value for s in Severity}
