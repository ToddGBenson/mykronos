"""i2i story building — spec 17 §7."""

from __future__ import annotations

from datetime import UTC, datetime

from mykronos.knowledge.store import KnowledgeEntry
from mykronos.triage_story import (
    LABEL_DEV_READY,
    LABEL_NEEDS_TRIAGE,
    OracleContext,
    TriageStory,
    acceptance_criterion,
    false_positive_precedent,
    story_id,
)


def _story(**overrides) -> TriageStory:
    defaults: dict = {
        "subject_id": "finding-1",
        "subject_type": "finding",
        "repo_full_name": "example-org/payments-api",
        "title": "SQL injection via string concatenation",
        "description": "User input is concatenated into a SQL statement.",
        "severity": "critical",
        "capability": "sast",
        "location": "orders/query.py:214",
        "oracle": None,
        "reachability": "unknown",
        "cve_id": None,
        "in_kev": None,
        "epss_score": None,
        "dedup_count": 0,
        "false_positive_note": None,
        "suggested_fix": "no_fix_available",
        "acceptance_criteria": ["The flagged line no longer matches CWE-89 on a re-scan."],
    }
    defaults.update(overrides)
    return TriageStory(**defaults)


class TestStoryId:
    def test_deterministic(self) -> None:
        assert story_id("org/repo", "finding-1") == story_id("org/repo", "finding-1")

    def test_differs_by_repo(self) -> None:
        assert story_id("org/repo-a", "finding-1") != story_id("org/repo-b", "finding-1")

    def test_differs_by_subject(self) -> None:
        assert story_id("org/repo", "finding-1") != story_id("org/repo", "finding-2")


class TestAcceptanceCriterion:
    def test_a_known_capability_uses_its_template(self) -> None:
        text = acceptance_criterion("CWE-89", "sast", "orders/query.py:214")
        assert "CWE-89" in text
        assert "orders/query.py:214" in text

    def test_an_unknown_capability_falls_back(self) -> None:
        text = acceptance_criterion("XYZ", "some-future-capability", "somewhere")
        assert "no longer appears on a re-scan" in text

    def test_a_missing_location_is_still_readable(self) -> None:
        text = acceptance_criterion("CWE-89", "sast", "")
        assert "the flagged location" in text


class TestFalsePositivePrecedent:
    def _entry(self, **overrides) -> KnowledgeEntry:
        defaults = dict(
            entry_id="e1",
            tier="personal",
            repo_full_name="example-org/payments-api",
            source_type="finding_dismissal",
            subject="CWE-89",
            source_ref="finding-1",
            text="dismissed",
            confidence=0.9,
            sensitivity="public",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
            last_confirmed_at=datetime(2026, 1, 1, tzinfo=UTC),
            observations=3,
            reasons=["generated code, not user input"],
        )
        defaults.update(overrides)
        return KnowledgeEntry(**defaults)

    def test_a_reasoned_dismissal_is_surfaced(self) -> None:
        note = false_positive_precedent(
            [(self._entry(), 0.9)], "CWE-89", "example-org/payments-api"
        )
        assert note is not None
        assert "3 time(s)" in note
        assert "generated code, not user input" in note

    def test_no_matching_entry_is_none(self) -> None:
        assert false_positive_precedent([], "CWE-89", "example-org/payments-api") is None

    def test_a_reason_free_dismissal_does_not_count(self) -> None:
        """Same gate as Oracle dampening (spec 11 §6.1) — a click with no
        reason is not evidence."""
        entry = self._entry(reasons=[])
        assert false_positive_precedent(
            [(entry, 0.9)], "CWE-89", "example-org/payments-api"
        ) is None

    def test_a_different_repos_dismissal_does_not_leak_in(self) -> None:
        entry = self._entry(repo_full_name="other-org/other-repo")
        assert false_positive_precedent(
            [(entry, 0.9)], "CWE-89", "example-org/payments-api"
        ) is None

    def test_an_org_tier_entry_with_no_repo_applies_everywhere(self) -> None:
        entry = self._entry(repo_full_name=None, tier="org")
        assert (
            false_positive_precedent([(entry, 0.9)], "CWE-89", "example-org/payments-api")
            is not None
        )


class TestDevReady:
    def test_a_complete_story_is_dev_ready(self) -> None:
        story = _story()
        assert story.dev_ready is True
        assert story.missing_fields == []
        # Membership, not equality: a story also carries a priority label
        # derived from its severity (spec 19 §4.3), and this test is about
        # dev-readiness, not the whole label set.
        assert LABEL_DEV_READY in story.labels

    def test_no_acceptance_criteria_blocks_dev_ready(self) -> None:
        story = _story(acceptance_criteria=[])
        assert story.dev_ready is False
        assert "acceptance_criteria" in story.missing_fields
        assert LABEL_NEEDS_TRIAGE in story.labels

    def test_unknown_reachability_does_not_block_dev_ready(self) -> None:
        """spec 17 §7.1 — unknown is a valid, honest value."""
        story = _story(reachability="unknown")
        assert story.dev_ready is True

    def test_no_cve_does_not_block_dev_ready(self) -> None:
        story = _story(cve_id=None, in_kev=None, epss_score=None)
        assert story.dev_ready is True

    def test_zero_dedup_count_does_not_block_dev_ready(self) -> None:
        story = _story(dedup_count=0)
        assert story.dev_ready is True

    def test_no_false_positive_precedent_does_not_block_dev_ready(self) -> None:
        story = _story(false_positive_note=None)
        assert story.dev_ready is True


class TestRenderIssueBody:
    def test_includes_the_description_and_criteria(self) -> None:
        story = _story()
        body = story.render_issue_body()
        assert story.description in body
        assert "CWE-89" in body
        assert "- [ ]" in body

    def test_a_kev_listed_cve_is_called_out(self) -> None:
        story = _story(cve_id="CVE-2024-12345", in_kev=True, epss_score=0.9)
        body = story.render_issue_body()
        assert "CVE-2024-12345" in body
        assert "Known Exploited Vulnerabilities" in body

    def test_a_non_kev_cve_is_still_named(self) -> None:
        story = _story(cve_id="CVE-2024-12345", in_kev=False, epss_score=0.1)
        body = story.render_issue_body()
        assert "CVE-2024-12345" in body
        assert "not KEV-listed" in body

    def test_no_cve_says_so_honestly(self) -> None:
        story = _story(cve_id=None)
        body = story.render_issue_body()
        assert "names no CVE" in body

    def test_reachability_is_always_named_as_unknown(self) -> None:
        body = _story().render_issue_body()
        assert "Reachability:** unknown" in body

    def test_a_false_positive_precedent_gets_its_own_section(self) -> None:
        story = _story(false_positive_note="Dismissed twice before.")
        body = story.render_issue_body()
        assert "## False-positive precedent" in body
        assert "Dismissed twice before." in body

    def test_no_precedent_omits_the_section(self) -> None:
        body = _story(false_positive_note=None).render_issue_body()
        assert "## False-positive precedent" not in body

    def test_oracle_context_is_rendered_when_present(self) -> None:
        story = _story(
            oracle=OracleContext(
                overall_risk_score=62,
                recommendation="review_recommended",
                band_contribution=63.0,
                band_detail="40 x log2(1 + 2) = 63.0",
            )
        )
        body = story.render_issue_body()
        assert "review_recommended (62/100)" in body
        assert "+63.0" in body

    def test_no_oracle_decision_says_not_assessed(self) -> None:
        body = _story(oracle=None).render_issue_body()
        assert "not assessed" in body

    def test_an_incomplete_story_says_so_in_the_body(self) -> None:
        body = _story(acceptance_criteria=[]).render_issue_body()
        assert "not dev-ready" in body

    def test_ends_with_a_pointer_to_the_subject(self) -> None:
        body = _story().render_issue_body()
        assert "finding `finding-1`" in body


class TestWhetherAFixExistsAtAll:
    """"Patchwork has no fixer" and "nobody has a fix" are different, and the
    story used to say only the first (D-076).

    Sixteen critical Perl CVEs on TheHub read as a backlog for a week on that
    ambiguity — I told the operator twice that one base-image rebase would
    close them. Every one had `fixed_version: null`: Debian had shipped
    nothing, and no rebuild, bump or fixer would have closed any of them.
    """

    def note(self, catalog, finding_id):
        from mykronos.triage_story import _upstream_fix_note

        return _upstream_fix_note(catalog, finding_id)

    def seed(self, client, auth, run_compaction, catalog, *, fixed):
        from tests.conftest import dependency_finding, post_findings, post_scan
        from tests.test_onboarding import onboard

        onboard(client, {"Authorization": "Bearer test-admin-token"})
        payload = dependency_finding(rule_id="CVE-2026-13221", package_name="perl")
        payload["package_version"] = "5.40.1-6"
        payload["raw_finding_json"] = {"fixed_version": fixed} if fixed else {}
        post_scan(client, auth, scan_run_id="fixnote")
        post_findings(client, auth, [payload], scan_run_id="fixnote")
        run_compaction()
        return catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = 'CVE-2026-13221'"
        )[0][0]

    def test_no_fixed_version_says_so_plainly(
        self, client, auth, run_compaction, catalog
    ) -> None:
        finding_id = self.seed(client, auth, run_compaction, catalog, fixed=None)

        note = self.note(catalog, finding_id)

        assert "No upstream fix exists yet" in note
        assert "perl" in note

    def test_it_names_the_dispositions_that_are_actually_available(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """A developer handed an unfixable CVE needs to know that accepting
        the risk *is* the action, not a way of dodging one."""
        finding_id = self.seed(client, auth, run_compaction, catalog, fixed=None)

        note = self.note(catalog, finding_id)

        assert "accept the risk" in note
        assert "cannot be remediated" in note

    def test_a_real_fixed_version_is_reported_as_such(
        self, client, auth, run_compaction, catalog
    ) -> None:
        finding_id = self.seed(client, auth, run_compaction, catalog, fixed="5.40.1-7")

        note = self.note(catalog, finding_id)

        assert "Upstream has a fix" in note
        assert "5.40.1-7" in note

    def test_it_says_nothing_when_there_is_no_package(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """A SAST finding has no package and no upstream. Appending "no
        upstream fix exists" to a SQL-injection story would be false — that
        one is entirely fixable, by the person reading it."""
        from tests.conftest import finding_payload, post_findings, post_scan
        from tests.test_onboarding import onboard

        onboard(client, {"Authorization": "Bearer test-admin-token"})
        post_scan(client, auth, scan_run_id="sastnote")
        post_findings(
            client, auth, [finding_payload(rule_id="CWE-89")], scan_run_id="sastnote"
        )
        run_compaction()
        finding_id = catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = 'CWE-89'"
        )[0][0]

        assert self.note(catalog, finding_id) == ""

    def test_an_unknown_finding_says_nothing(self, catalog) -> None:
        assert self.note(catalog, "not-a-finding") == ""

    def test_it_reaches_the_story_body(
        self, client, auth, run_compaction, catalog
    ) -> None:
        """The whole point: the sentence has to be in what a developer opens,
        not only in a helper."""
        from mykronos.triage_story import _suggested_fix

        finding_id = self.seed(client, auth, run_compaction, catalog, fixed=None)

        suggested = _suggested_fix(catalog, finding_id=finding_id, combination_id=None)

        assert "No upstream fix exists yet" in suggested
