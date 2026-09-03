"""Dashboard query service and API — spec 10 §2, §4, §5, §7; spec 12 §5."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.schemas import Severity, utcnow
from tests.conftest import (
    CAPABILITY,
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    later,
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

    def test_every_capability_gets_a_row_not_only_the_enabled_ones(
        self, client: TestClient, admin_auth: dict[str, str], auth
    ) -> None:
        """B-008. The list was built from `sorted(enabled)`, so a capability
        nobody turned on was simply absent — and so was one that was enabled
        and had never reported. Two different answers, one empty space."""
        from mykronos.schemas import Capability

        onboard(client, admin_auth, scanned_by="concourse")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        named = {s["capability"] for s in row["capability_states"]}

        assert named >= {c.value for c in Capability}, (
            f"missing rows for {sorted({c.value for c in Capability} - named)}; "
            "a stage with no row is a stage nobody can see is unconfigured"
        )

    def test_not_enabled_is_distinguishable_from_enabled_and_silent(
        self, client: TestClient, admin_auth: dict[str, str], auth
    ) -> None:
        """The distinction the entry was filed for. Both show no scan; only
        one of them is somebody's problem."""
        onboard(client, admin_auth, scanned_by="concourse")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        # The auth fixture grants sast, and nothing has scanned yet.
        assert states["sast"]["enabled"] is True
        assert states["sast"]["has_scanned"] is False

        # dast was never granted for this repo.
        assert states["dast"]["enabled"] is False
        assert states["dast"]["has_scanned"] is False

        assert states["sast"] != states["dast"], (
            "the two states must not be identical, or the page cannot tell "
            "'enabled and silent' from 'not configured here'"
        )

    def test_a_capability_that_scanned_is_reported_however_it_was_enabled(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        """`has_scanned` is read for every capability rather than assumed
        false for the disabled ones: a repo can report under a capability its
        installer ledger never listed, and dropping that row would hide a scan
        that actually happened."""
        onboard(client, admin_auth, scanned_by="concourse")
        post_scan(client, auth)
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["sast"]["has_scanned"] is True
        assert states["sast"]["last_scan_at"] is not None

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

    def test_filters_to_what_a_pull_request_introduced(
        self,
        client: TestClient,
        admin_auth: dict[str, str],
        seeded,
        run_compaction,
    ) -> None:
        """`what did my change add?` — not `what does my branch reproduce?`

        A second scan run, on a pull request, sees the three findings that
        already existed *and* introduces one. Filtering by `pr_number` must
        return only the new one: attribution is on the scan run that FIRST saw
        a finding, never the most recent one. Matching on last-seen would hand
        the author every pre-existing finding their branch happens to
        reproduce, which on a repository with a backlog is nearly all of them.
        """
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(
            client,
            auth,
            scan_run_id="run-pr",
            commit_sha="deadbeefcafe1234",
            pr_number=42,
        )
        post_findings(
            client,
            auth,
            [
                # Already known — first seen by run-1, so not this PR's doing.
                finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
                # New on this branch.
                finding_payload(rule_id="CWE-798", severity="high", symbol="new"),
            ],
            scan_run_id="run-pr",
        )
        run_compaction()

        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"pr_number": 42},
            headers=admin_auth,
        ).json()

        assert body["total"] == 1
        assert body["findings"][0]["rule_id"] == "CWE-798"

        # The same answer by commit, because a check run has the sha and not
        # always the pull request number.
        by_sha = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"commit_sha": "deadbeefcafe1234"},
            headers=admin_auth,
        ).json()
        assert by_sha["total"] == 1
        assert by_sha["findings"][0]["rule_id"] == "CWE-798"

    def test_an_unknown_pull_request_is_zero_not_an_error(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/findings",
            params={"pr_number": 9999},
            headers=admin_auth,
        ).json()
        assert body["total"] == 0

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
            json={
                "status": "accepted_risk",
                "reason": "staging only",
                "accepted_reason_code": "not_exploitable_here",
                "indefinite": True,
            },
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

    def test_the_triage_filter_narrows_to_one_classification(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """spec 18 §5.1: the same classification already rendered per group,
        now also a filter — `classify()`'s output, not a new judgement."""
        page = self._page(client, admin_auth, outstanding, triage="true_positive")

        assert {g["rule_id"] for g in page["groups"]} == {"CWE-79", "CVE-2024-4812"}
        assert all(g["triage"] == "true_positive" for g in page["groups"])

    def test_the_triage_filter_reaches_toxic_combinations(
        self, client: TestClient, admin_auth: dict[str, str], outstanding
    ) -> None:
        """A combination overrides the per-finding verdict (`_group_findings`)
        — filtering for it should find exactly the findings that override."""
        page = self._page(client, admin_auth, outstanding, triage="toxic_combination")

        assert {g["rule_id"] for g in page["groups"]} == {"CWE-89", "CWE-306"}

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
            json={
                "status": "accepted_risk",
                "reason": "behind the VPN",
                "accepted_reason_code": "compensating_control",
                "indefinite": True,
            },
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
            json={
                "status": "accepted_risk",
                "reason": "behind the VPN",
                "accepted_reason_code": "compensating_control",
                "indefinite": True,
            },
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

    def test_the_most_recent_runs_detail_is_reported(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        """spec 19 §1.2 — the adapter's own message, not just scan_status."""
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        # An explicit later timestamp: "most recent" is resolved by
        # started_at, and two now() calls microseconds apart can tie, which
        # made this pass or fail depending on how fast the suite ran.
        post_scan(
            client,
            auth,
            scan_run_id="run-2",
            scan_status="failure",
            started_at=later(1),
            detail="3 of 10 test(s) failed (2 failure(s), 1 error(s)).",
        )
        run_compaction()

        body = client.get(f"/api/dashboard/repos/{seeded}/scan-health", headers=admin_auth).json()

        sast = next(c for c in body["capabilities"] if c["capability"] == "sast")
        assert sast["detail"] == "3 of 10 test(s) failed (2 failure(s), 1 error(s))."

    def test_a_lane_that_flips_on_the_same_commit_is_flaky(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        """spec 19 §1.3 — same commit, disagreeing status."""
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        # `seeded`'s own run is scan_run_id="run-1", commit_sha defaults the
        # same across calls unless overridden — exactly the "nothing about
        # the repo changed" case this signal exists for.
        post_scan(
            client, auth, scan_run_id="run-2", scan_status="failure", started_at=later(1)
        )
        run_compaction()

        body = client.get(f"/api/dashboard/repos/{seeded}/scan-health", headers=admin_auth).json()

        sast = next(c for c in body["capabilities"] if c["capability"] == "sast")
        assert sast["flaky"] is True

    def test_a_lane_that_fails_on_a_new_commit_is_not_flaky(
        self, client: TestClient, admin_auth: dict[str, str], seeded, run_compaction
    ) -> None:
        """A regression, not a flake — the repository actually changed."""
        token = issue_token(client, REPO, CAPABILITY)
        auth = {"Authorization": f"Bearer {token}"}
        post_scan(
            client,
            auth,
            scan_run_id="run-2",
            scan_status="failure",
            commit_sha="deadbeef",
            started_at=later(1),
        )
        run_compaction()

        body = client.get(f"/api/dashboard/repos/{seeded}/scan-health", headers=admin_auth).json()

        sast = next(c for c in body["capabilities"] if c["capability"] == "sast")
        assert sast["flaky"] is False


class TestScanRunTrend:
    """spec 19 §1.1 — a lane's pass rate over time, not just the current rate."""

    def test_a_run_lands_in_its_own_bucket(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/scan-runs/trend",
            params={"capability": "sast", "days": 7, "points": 7},
            headers=admin_auth,
        ).json()

        assert body["capability"] == "sast"
        assert len(body["points"]) == 7
        assert body["points"][-1]["runs"] == 1
        assert body["points"][-1]["success_rate"] == 1.0

    def test_a_window_with_no_runs_is_null_not_zero(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/scan-runs/trend",
            params={"capability": "sast", "days": 700, "points": 10},
            headers=admin_auth,
        ).json()

        # The one seeded run falls in the most recent bucket; every earlier
        # bucket has nothing in it, and null is the honest answer for that,
        # not a zero rate that would read as "ran and failed every time."
        assert body["points"][0]["success_rate"] is None
        assert body["points"][0]["runs"] == 0

    def test_an_unknown_capability_is_an_empty_but_valid_series(
        self, client: TestClient, admin_auth: dict[str, str], seeded
    ) -> None:
        body = client.get(
            f"/api/dashboard/repos/{seeded}/scan-runs/trend",
            params={"capability": "functional", "days": 7, "points": 3},
            headers=admin_auth,
        ).json()

        assert all(p["runs"] == 0 and p["success_rate"] is None for p in body["points"])


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

        assert body["items"] == []
        assert body["open_by_severity"] == dict.fromkeys(
            ["critical", "high", "medium", "low", "info"], 0
        )
        assert body["total_open"] == 0
        assert body["truncated"] is False
        # An empty estate has nothing to rank and nothing missing to say so
        # about, but the block is always present — a caller should never have
        # to handle "the queue forgot to mention what it ranked by" (B-033).
        assert body["ranking"]["not_consulted"] == []

    def test_it_says_what_it_could_not_rank_by(
        self, client, admin_auth, seeded
    ) -> None:
        """B-033 — the queue must not present itself as ordered by risk.

        The rank uses severity, threat intel, remediation targets and blast
        radius. It has never used internet exposure, data classification or
        business criticality: those live on a risk profile and are not terms in
        `rank_terms` at all. On an estate with no profiles this is not a
        degraded risk ranking, it is a threat-intel ranking, and saying so at
        the point of ranking is the difference between a number somebody can
        trust and one they will quietly stop believing.
        """
        body = client.get("/api/dashboard/triage", headers=admin_auth).json()

        gaps = body["ranking"]["not_consulted"]
        assert [g["input"] for g in gaps] == ["business context"]
        assert "no risk profile" in gaps[0]["reason"]
        assert body["ranking"]["repos_without_a_risk_profile"] == [REPO]
        # And it is explicit about what it *did* use, so the two lists are
        # read together rather than the absence being inferred.
        assert "severity" in body["ranking"]["consulted"]

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


class TestSbomDownload:
    """spec 18 §8.2: the archived SBOM itself, not just its trust-score row."""

    def _seed(self, client, admin_auth, run_compaction, sbom_ref="raw/example/sbom.json"):
        from tests.conftest import issue_token
        from tests.test_atlas import post

        repo_id = onboard(client, admin_auth).json()["id"]
        atlas_auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}
        post(client, atlas_auth, sbom_ref=sbom_ref)
        run_compaction()

        evidence_id = client.app.state.catalog.query(
            "SELECT evidence_id FROM sscs_evidence"
        )[0][0]
        return repo_id, str(evidence_id)

    def test_downloads_the_archived_file(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id, evidence_id = self._seed(client, admin_auth, run_compaction)
        settings = client.app.state.settings
        sbom_path = settings.datalake_dir / "raw" / "example" / "sbom.json"
        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        sbom_path.write_text('{"bomFormat": "CycloneDX"}')

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": evidence_id},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json() == {"bomFormat": "CycloneDX"}

    def test_a_viewer_is_refused(
        self, client, admin_auth, viewer_auth, run_compaction
    ) -> None:
        repo_id, evidence_id = self._seed(client, admin_auth, run_compaction)

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": evidence_id},
            headers=viewer_auth,
        )

        assert response.status_code == 403

    def test_an_unknown_evidence_id_is_404(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": "does-not-exist"},
            headers=admin_auth,
        )

        assert response.status_code == 404

    def test_a_row_naming_no_sbom_is_404_and_says_so(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id, evidence_id = self._seed(client, admin_auth, run_compaction, sbom_ref=None)

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": evidence_id},
            headers=admin_auth,
        )

        assert response.status_code == 404
        assert "never captured" in response.json()["detail"]

    def test_a_pruned_file_is_404_and_distinguished_from_never_had_one(
        self, client, admin_auth, run_compaction
    ) -> None:
        """The row survives retention; the archived bytes do not (spec 05 §7).
        Those are different facts and the message says which one is true."""
        repo_id, evidence_id = self._seed(client, admin_auth, run_compaction)

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": evidence_id},
            headers=admin_auth,
        )

        assert response.status_code == 404
        assert "pruned" in response.json()["detail"]

    def test_a_path_that_would_escape_the_lake_is_refused(
        self, client, admin_auth, run_compaction
    ) -> None:
        repo_id, evidence_id = self._seed(
            client, admin_auth, run_compaction, sbom_ref="../../etc/passwd"
        )

        response = client.get(
            f"/api/dashboard/repos/{repo_id}/sscs/sbom",
            params={"evidence_id": evidence_id},
            headers=admin_auth,
        )

        assert response.status_code == 404
        assert "invalid" in response.json()["detail"].lower()


def test_severity_enum_covers_every_portfolio_bucket() -> None:
    """A new severity must not silently vanish from the summary."""
    from mykronos.dashboard import SEVERITIES

    assert set(SEVERITIES) == {s.value for s in Severity}


class TestVulnerabilityManagement:
    """The management half of vulnerability management (B-010, PIP-9).

    "What is open" was answerable from the beginning. "How long has it been
    open, what did we decide not to fix, and on what grounds" is the part a
    programme is actually made of, and the grounds are the part that decays.
    """

    def _page(self, client: TestClient, admin_auth: dict[str, str]) -> Any:
        response = client.get(
            "/api/dashboard/vulnerability-management", headers=admin_auth
        )
        assert response.status_code == 200
        return response.json()

    def test_aging_carries_the_capability(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        """Severity and age say how bad; capability says where to go. Sixty
        high findings older than ninety days is a number to be alarmed by;
        "they are all container CVEs from one base image" is the thing to
        act on, and without this the reader opens every one to find out."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(severity="high")])
        run_compaction()

        page = self._page(client, admin_auth)

        assert page["aging"], "an open finding should produce an aging row"
        row = page["aging"][0]
        assert set(row) == {"severity", "capability", "age_band", "count"}
        assert row["capability"] == "sast"

    def test_an_acceptance_is_listed_with_its_grounds_not_just_counted(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction, catalog
    ) -> None:
        """Counts cannot say what was accepted or why, and the why is the
        half that stops being true."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()
        finding_id = str(catalog.query("SELECT finding_id FROM findings")[0][0])

        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={
                "status": "accepted_risk",
                "reason": "no upstream patch yet",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": "2027-01-01",
            },
            headers=admin_auth,
        )
        run_compaction()

        page = self._page(client, admin_auth)

        assert page["accepted_risk"], "the count breakdown still stands"
        detail = page["accepted_risk_detail"]
        assert len(detail) == 1
        assert detail[0]["accepted_reason_code"] == "no_vendor_fix"
        assert str(detail[0]["accepted_until"]).startswith("2027-01-01")
        assert detail[0]["finding_id"] == finding_id

    def test_an_acceptance_whose_premise_expired_is_flagged_fixable(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction, catalog
    ) -> None:
        """`no_vendor_fix` is the one premise a scan can contradict, which is
        why the sweep re-opens that and nothing else (spec 24 §3.2). A row
        here is mid-flight or on grounds the sweep cannot check — either way
        it is what a person should be looking at."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    package_name="lodash",
                    # The advisory's fix travels in the raw record, not as a
                    # column -- which is where the sweep reads it from too.
                    raw_finding_json={"ruleId": "CWE-89", "fixed_version": "4.17.22"},
                )
            ],
        )
        run_compaction()
        finding_id = str(catalog.query("SELECT finding_id FROM findings")[0][0])

        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={
                "status": "accepted_risk",
                "reason": "no upstream patch",
                "accepted_reason_code": "no_vendor_fix",
                "accepted_until": "2027-01-01",
            },
            headers=admin_auth,
        )
        run_compaction()

        detail = self._page(client, admin_auth)["accepted_risk_detail"]

        assert detail[0]["fixed_version"] == "4.17.22"
        assert detail[0]["now_fixable"] is True

    def test_an_acceptance_on_other_grounds_is_not_called_fixable(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction, catalog
    ) -> None:
        """A fix existing does not contradict "not exploitable here". Calling
        it fixable would send somebody to re-litigate a decision that is still
        true, which is how a review queue becomes noise."""
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(
                    package_name="lodash",
                    raw_finding_json={"ruleId": "CWE-89", "fixed_version": "4.17.22"},
                )
            ],
        )
        run_compaction()
        finding_id = str(catalog.query("SELECT finding_id FROM findings")[0][0])

        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={
                "status": "accepted_risk",
                "reason": "the parser is never reached from an entry point",
                "accepted_reason_code": "not_exploitable_here",
                "accepted_until": "2027-01-01",
            },
            headers=admin_auth,
        )
        run_compaction()

        detail = self._page(client, admin_auth)["accepted_risk_detail"]

        assert detail[0]["fixed_version"] == "4.17.22"
        assert detail[0]["now_fixable"] is False

    def test_a_viewer_may_read_it(
        self, client: TestClient, admin_auth: dict[str, str], viewer_auth
    ) -> None:
        """A read. The person asking what is outstanding is not always an
        admin, and making them one to answer it would be the wrong trade."""
        onboard(client, admin_auth)

        assert (
            client.get(
                "/api/dashboard/vulnerability-management", headers=viewer_auth
            ).status_code
            == 200
        )


class TestCapabilitiesThatReportElsewhere:
    """Three capabilities never write a ScanRun, and never will (B-015).

    Aegis assesses a pull request and writes an `InsiderRiskSignal` (spec 06
    §3); Oracle writes a `RiskDecision`; Patchwork writes a
    `RemediationEvent`. Reading only `scan_runs` reported all three silent on
    every repository for ever — the kind of permanent false alarm the codebase
    already names in `last_successful_scan_at`, which special-cases aegis for
    exactly this reason.

    It became worth fixing when B-008 turned "enabled and silent" from an
    absence a caller inferred into a state a caller is invited to act on.
    """

    def test_aegis_reports_through_its_own_table(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction, buffer
    ) -> None:
        onboard(client, admin_auth, scanned_by="concourse")
        buffer.append(
            "insider_risk_signals",
            [
                {
                    "signal_id": "s1",
                    "repo_full_name": REPO,
                    "pr_number": 7,
                    "evaluated_at": utcnow(),
                }
            ],
        )
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["aegis"]["has_scanned"] is True, (
            "aegis assessed a pull request and the portfolio still reports it "
            "as having never reported"
        )
        assert states["aegis"]["last_scan_at"] is not None

    def test_a_capability_with_nothing_recorded_is_still_silent(
        self, client: TestClient, admin_auth: dict[str, str], auth
    ) -> None:
        """The fix must not make everything look busy. `cloud` genuinely has
        produced nothing, and that zero has to keep reading as a real zero
        (B-018)."""
        onboard(client, admin_auth, scanned_by="concourse")

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        assert states["cloud"]["has_scanned"] is False
        assert states["aegis"]["has_scanned"] is False, (
            "with no signal recorded, aegis is silent like anything else"
        )

    def test_no_capability_is_permanently_silent(self) -> None:
        """The guard that survives the next capability.

        Every capability must be able to set `has_scanned` *somehow* — either
        by writing a ScanRun, or by appearing in `REPORTS_ELSEWHERE`. A new
        capability that reports through a table of its own and is not listed
        here would be silent for ever, which is the defect this class exists
        to close, and it would be silent quietly.
        """
        from mykronos.adapters.registry import supported_tools
        from mykronos.dashboard import REPORTS_ELSEWHERE
        from mykronos.schemas import Capability

        for capability in Capability:
            name = capability.value
            writes_scan_runs = bool(supported_tools(name))
            if writes_scan_runs or name in REPORTS_ELSEWHERE:
                continue
            raise AssertionError(
                f"{name!r} has no adapter (so writes no ScanRun) and is not in "
                "REPORTS_ELSEWHERE, so the portfolio will report it silent on "
                "every repository for ever. Add the table it does write."
            )

    def test_a_real_scan_run_wins_over_the_weaker_signal(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction, buffer
    ) -> None:
        """If one of these ever starts writing runs too, the run is the better
        answer. The overlay must not overwrite it."""
        onboard(client, admin_auth, scanned_by="concourse")
        post_scan(client, auth)
        run_compaction()

        row = client.get("/api/dashboard/portfolio", headers=admin_auth).json()["repos"][0]
        states = {s["capability"]: s for s in row["capability_states"]}

        # The auth fixture posts a sast run; sast is not in REPORTS_ELSEWHERE
        # and must keep its real status rather than gaining a synthetic one.
        assert states["sast"]["last_scan_status"] == "success"


class TestTheQueueCarriesTheClassification:
    """B-019. The ranked, portfolio-wide queue took nine filters and not the
    one that says what the machine concluded.

    The per-repository findings view has had a `triage` filter since spec 18.
    So the classification existed, was displayed and was filterable — on the
    one surface that can only show a single repository at a time. "Show me
    everything the machine could not judge" meant one request per repository,
    which is not a worklist.
    """

    @staticmethod
    def _activate(client: TestClient) -> None:
        """The queue only shows repositories whose status is `active`, and
        `onboard` leaves one pending. Same step `test_worklist_state` takes."""
        from sqlalchemy import select as _select

        from mykronos.db.models import RepoOnboarding as _RepoOnboarding

        with client.app.state.db.session() as session:
            row = session.execute(
                _select(_RepoOnboarding).where(
                    _RepoOnboarding.github_repo_full_name == REPO
                )
            ).scalars().one()
            row.status = "active"

    def _queue(self, client: TestClient, admin_auth: dict[str, str], **params):
        response = client.get(
            "/api/dashboard/triage", headers=admin_auth, params=params
        )
        assert response.status_code == 200
        return response.json()["items"]

    def test_every_row_carries_a_classification_and_a_reason(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        """Stamped whether or not anybody filtered, the same contract the KEV
        badge has. A caller should not need a second request to render it."""
        onboard(client, admin_auth)
        self._activate(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(severity="critical")])
        run_compaction()

        items = self._queue(client, admin_auth)

        assert items, "expected the seeded finding in the queue"
        for item in items:
            assert item["triage"]
            assert item["triage_rationale"], (
                "spec 01 §6 makes an unexplained verdict a bug, and a row "
                "labelled 'needs human judgment' with no reason is one"
            )

    def test_it_filters_to_one_classification(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        onboard(client, admin_auth)
        self._activate(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(severity="critical")])
        run_compaction()

        everything = self._queue(client, admin_auth)
        classification = everything[0]["triage"]
        filtered = self._queue(client, admin_auth, triage=classification)

        assert filtered
        assert {i["triage"] for i in filtered} == {classification}

    def test_filtering_to_another_classification_excludes_it(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        """The filter has to exclude as well as include, or it is decoration."""
        onboard(client, admin_auth)
        self._activate(client)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(severity="critical")])
        run_compaction()

        mine = self._queue(client, admin_auth)[0]["triage"]
        other = (
            "true_positive" if mine != "true_positive" else "likely_false_positive"
        )

        assert self._queue(client, admin_auth, triage=other) == []

    def test_an_unknown_classification_is_refused(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """A typo must not silently return the whole queue, which is what an
        unvalidated filter does — the same fall-through B-006 fixed on the
        repo page's tab parameter."""
        onboard(client, admin_auth)
        self._activate(client)

        response = client.get(
            "/api/dashboard/triage",
            headers=admin_auth,
            params={"triage": "definitely-not-a-classification"},
        )

        assert response.status_code == 422

    def test_the_filter_composes_with_ranking(
        self, client: TestClient, admin_auth: dict[str, str], auth, run_compaction
    ) -> None:
        """Filtering must narrow the queue, not replace its order. A
        needs-human-judgment critical should still outrank a low."""
        onboard(client, admin_auth)
        self._activate(client)
        post_scan(client, auth)
        post_findings(
            client,
            auth,
            [
                finding_payload(severity="critical", symbol="a", code_snippet="a"),
                finding_payload(severity="low", symbol="b", code_snippet="b"),
            ],
        )
        run_compaction()

        ranked = self._queue(client, admin_auth, order="rank")
        classification = ranked[0]["triage"]
        filtered = self._queue(
            client, admin_auth, order="rank", triage=classification
        )

        assert filtered
        assert [i["finding_id"] for i in filtered] == [
            i["finding_id"] for i in ranked if i["triage"] == classification
        ]


class TestReviewingWhatTheClassifierConcluded:
    """B-020. The classifier labels findings and deliberately cannot act on
    them: a machine that could set `false_positive` would eventually dismiss a
    real finding, silently.

    So the label waits for a person, and until this existed the only way to
    answer it was to open the right repository and disposition by hand. The
    evidence that this was not happening: 43 false positives ever recorded,
    all of them sast and secrets, against 234 open container findings.
    """

    def _seed(self, client, admin_auth, auth, run_compaction, **overrides):
        onboard(client, admin_auth)
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload(**overrides)])
        run_compaction()
        return str(
            client.app.state.catalog.query("SELECT finding_id FROM findings")[0][0]
        )

    def _review(self, client, admin_auth, finding_id, **body):
        return client.post(
            f"/api/dashboard/findings/{finding_id}/classification-review",
            json=body,
            headers=admin_auth,
        )

    def _status(self, client, finding_id) -> str:
        return str(
            client.app.state.catalog.query(
                "SELECT status FROM findings WHERE finding_id = ?", [finding_id]
            )[0][0]
        )

    def test_rejecting_the_classifier_leaves_the_finding_open(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """The half that recorded nothing before. Agreement already left a
        trace; disagreement did not, so a classifier calling real findings
        false positives looked exactly like one nobody had reviewed."""
        finding_id = self._seed(client, admin_auth, auth, run_compaction)

        response = self._review(
            client, admin_auth, finding_id, agrees=False, reason="reachable from the API"
        )

        assert response.status_code == 200
        assert response.json()["agreed"] is False
        assert response.json()["recorded"] == "classifier rejection"
        assert self._status(client, finding_id) == "open"

    def test_a_rejection_is_written_to_the_knowledge_store(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A verdict nothing ever contradicts is a verdict nobody is
        checking, so the contradiction has to be recorded somewhere."""
        finding_id = self._seed(client, admin_auth, auth, run_compaction)

        self._review(
            client, admin_auth, finding_id, agrees=False, reason="reachable from the API"
        )

        entries = client.app.state.knowledge.active_entries()
        assert any(
            entry.source_type == "classification_rejected" for entry, _ in entries
        )

    def test_a_rejection_does_not_dampen_the_rule(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """It teaches about the classifier, not about the rule. Quietening a
        rule because somebody said its finding was real would invert the whole
        loop."""
        from mykronos.knowledge.capture import TEACHES_ABOUT_THE_RULE

        assert "classification_rejected" not in TEACHES_ABOUT_THE_RULE

        finding_id = self._seed(client, admin_auth, auth, run_compaction)
        self._review(client, admin_auth, finding_id, agrees=False, reason="real")

        entries = {
            entry.source_type for entry, _ in client.app.state.knowledge.active_entries()
        }
        assert "finding_dismissal" not in entries, (
            "a rejection must not be recorded as a dismissal, which is what "
            "dampening reads"
        )

    def test_agreeing_needs_a_reason(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """A bare click is recorded low-confidence and barred from promotion
        (spec 11 §4), and dampening reads the reason rather than the count."""
        finding_id = self._seed(client, admin_auth, auth, run_compaction)

        response = self._review(client, admin_auth, finding_id, agrees=True, reason="  ")

        assert response.status_code in (409, 422)
        assert self._status(client, finding_id) == "open"

    def test_it_refuses_to_dismiss_what_the_machine_declined_to_judge(
        self, client: TestClient, admin_auth, auth, run_compaction
    ) -> None:
        """The one thing this endpoint must not become a shortcut for.
        Agreeing with `needs_human_judgment` would dismiss a finding the
        classifier explicitly did not call a false positive."""
        finding_id = self._seed(client, admin_auth, auth, run_compaction)

        response = self._review(
            client, admin_auth, finding_id, agrees=True, reason="looks fine to me"
        )

        assert response.status_code == 409
        assert "not 'likely_false_positive'" in response.json()["detail"]
        assert self._status(client, finding_id) == "open"

    def test_a_viewer_cannot_review(
        self, client: TestClient, admin_auth, viewer_auth, auth, run_compaction
    ) -> None:
        """No path lets a classification become a disposition without a person
        entitled to make one."""
        finding_id = self._seed(client, admin_auth, auth, run_compaction)

        response = client.post(
            f"/api/dashboard/findings/{finding_id}/classification-review",
            json={"agrees": False, "reason": "real"},
            headers=viewer_auth,
        )

        assert response.status_code == 403

    def test_an_unknown_finding_is_a_404(
        self, client: TestClient, admin_auth
    ) -> None:
        onboard(client, admin_auth)

        assert self._review(
            client, admin_auth, "f" * 64, agrees=False, reason="x"
        ).status_code == 404
