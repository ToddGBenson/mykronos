"""Toxic-combination partial remediation — spec 19 §3.3.

Spec 08 §8 stops Patchwork fixing any half of a combination, and it is right
to: closing one half usually closes the *finding* without closing the *risk*.
That is a good default and this does not change it.

It carves out one rule. A committed credential is worth removing whether or
not the unauthenticated surface beside it is ever fixed — the danger is a
leaked credential somebody can find a use for, and pulling the credential
closes that half outright rather than hiding it.

Per rule and reviewed, deliberately. A generic "fix half a combination"
switch would repeat spec 08 §8's mistake for nine rules to get it right for
one, so most of these tests are about the other nine staying untouched.
"""

from __future__ import annotations

from mykronos.patchwork import correlate
from mykronos.schemas import utcnow


def finding(finding_id, rule_id, capability, *, path="src/app.py", severity="high"):
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "title": rule_id,
        "file_path": path,
        "capability": capability,
        "severity": severity,
    }


CREDENTIAL_COMBO = [
    finding("s1", "generic-api-key", "secrets"),
    finding("c1", "CWE-306", "sast"),
]


class TestTheOneRuleThatHasOne:
    def test_the_credential_half_is_named(self) -> None:
        combos = correlate.detect(CREDENTIAL_COMBO)

        assert len(combos) == 1
        assert combos[0].rule_id == "secret-and-public-surface"
        assert combos[0].partial_fix_finding_id == "s1"

    def test_it_names_the_secrets_finding_not_the_sast_one(self) -> None:
        """The credential is the half that is safe to pull. The
        unauthenticated surface is a design question a person has to answer,
        and fixing it blind is how a combination gets closed without being
        understood."""
        combos = correlate.detect(CREDENTIAL_COMBO)

        assert combos[0].partial_fix_finding_id != "c1"

    def test_the_combination_still_needs_a_person(self) -> None:
        """The partial fix does not resolve the combination. Both halves are
        still in `finding_ids`, and the pipeline still records
        `needs_human_judgment` for the set."""
        combos = correlate.detect(CREDENTIAL_COMBO)

        assert combos[0].finding_ids == frozenset({"s1", "c1"})

    def test_the_rationale_says_what_was_attempted(self) -> None:
        """A reviewer reading "needs human judgment" next to an open pull
        request has to be told why both are true, or the two read as a
        contradiction."""
        rationale = correlate.detect(CREDENTIAL_COMBO)[0].rationale

        assert "still needs a person" in rationale
        assert "correct to fix regardless" in rationale


class TestEveryOtherRule:
    def test_no_other_built_in_rule_has_a_partial_fix(self) -> None:
        """The property that keeps this narrow. Adding one to a second rule
        is a reviewed decision, and this test is what makes somebody make
        it."""
        with_partial = [
            rule.rule_id for rule in correlate.BUILT_IN_RULES if rule.safe_partial_fix
        ]

        assert with_partial == ["secret-and-public-surface"]

    def test_a_rule_without_one_names_no_finding(self) -> None:
        combos = correlate.detect(
            [
                finding("a1", "CWE-89", "sast"),
                finding("a2", "CWE-306", "sast"),
            ]
        )

        assert combos[0].rule_id == "unauth-injectable"
        assert combos[0].partial_fix_finding_id is None

    def test_the_default_rationale_is_unchanged(self) -> None:
        """spec 08 §8's sentence, still the answer for nine rules out of
        ten."""
        combos = correlate.detect(
            [finding("a1", "CWE-89", "sast"), finding("a2", "CWE-306", "sast")]
        )

        assert "fixing one in isolation" in combos[0].rationale


class TestThePipelineReleasesIt:
    """`claimed` is what stops a combination member reaching the fixer. The
    partial-fix finding is removed from it, and nothing else is."""

    def test_only_the_named_finding_is_released(self) -> None:
        combos = correlate.detect(CREDENTIAL_COMBO)
        claimed = {fid for combo in combos for fid in combo.finding_ids}
        partial = {
            combo.partial_fix_finding_id
            for combo in combos
            if combo.partial_fix_finding_id
        }

        assert claimed - partial == {"c1"}

    def test_nothing_is_released_for_an_ordinary_combination(self) -> None:
        combos = correlate.detect(
            [finding("a1", "CWE-89", "sast"), finding("a2", "CWE-306", "sast")]
        )
        partial = {
            combo.partial_fix_finding_id
            for combo in combos
            if combo.partial_fix_finding_id
        }

        assert partial == set()


class TestTheFixerBehindIt:
    def test_a_real_fixer_exists_for_the_released_half(self) -> None:
        """A `safe_partial_fix` naming a capability with no fixer behind it
        would release a finding into a path that does nothing with it — a
        combination reported as partially handled when nothing was
        attempted."""
        from mykronos.patchwork import fixers

        assert "remove-committed-secret" in {name for name, _ in fixers.FIXERS}


class TestTheCrossRepoDigest:
    """spec 19 §3.4. Grouped for the reviewer, never merged for the machine."""

    def rows(self, client, run_compaction, entries):
        """Write the events and findings the digest joins across."""
        from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
        from tests.test_onboarding import onboard

        repo_id = onboard(client, {"Authorization": "Bearer test-admin-token"}).json()["id"]
        auth = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
        post_scan(client, auth, scan_run_id="run-digest")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id=rule, title=rule) for rule, _ in entries],
            scan_run_id="run-digest",
        )
        run_compaction()

        found = {
            row[1]: row[0]
            for row in client.app.state.catalog.query(
                "SELECT finding_id, rule_id FROM findings"
            )
        }
        events = []
        for index, (rule, repo) in enumerate(entries):
            events.append(
                {
                    "event_id": f"event-{index}",
                    "repo_full_name": repo,
                    "finding_id": found[rule],
                    "toxic_combination_id": None,
                    "contributing_finding_ids": None,
                    "pipeline_stage_reached": "pr_opened",
                    "triage_classification": "true_positive",
                    "fix_pr_number": 100 + index,
                    "fix_pr_url": f"https://github.com/{repo}/pull/{100 + index}",
                    "pr_status": "draft_open",
                    "rationale": f"Pin {rule}.",
                    # Real timestamps: `updated_at` is the compaction sort
                    # key, and a null one drops the row silently.
                    "created_at": utcnow(),
                    "updated_at": utcnow(),
                }
            )
        client.app.state.buffer.append("remediation_events", events)
        run_compaction()
        return repo_id

    def test_one_rule_across_repos_is_one_group(
        self, client, admin_auth, run_compaction
    ) -> None:
        self.rows(client, run_compaction, [("CWE-89", "acme/a")])

        body = client.get("/api/patchwork/digest", headers=admin_auth).json()

        assert len(body["groups"]) == 1
        assert body["groups"][0]["rule_id"] == "CWE-89"
        assert body["total_open_prs"] == 1

    def test_different_rules_are_different_groups(
        self, client, admin_auth, run_compaction
    ) -> None:
        self.rows(client, run_compaction, [("CWE-89", "acme/a"), ("CWE-79", "acme/b")])

        body = client.get("/api/patchwork/digest", headers=admin_auth).json()

        assert sorted(g["rule_id"] for g in body["groups"]) == ["CWE-79", "CWE-89"]

    def test_an_event_with_no_pr_is_not_in_the_digest(
        self, client, admin_auth, run_compaction
    ) -> None:
        """This page is a review queue. A finding Patchwork declined to fix
        has nothing here for a reviewer to open."""
        self.rows(client, run_compaction, [("CWE-89", "acme/a")])
        client.app.state.buffer.append(
            "remediation_events",
            [
                {
                    "event_id": "event-refused",
                    "repo_full_name": "acme/c",
                    "finding_id": "unknown",
                    "toxic_combination_id": None,
                    "contributing_finding_ids": None,
                    "pipeline_stage_reached": "no_fix_available",
                    "triage_classification": "true_positive",
                    "fix_pr_number": None,
                    "fix_pr_url": None,
                    "pr_status": None,
                    "rationale": "No fixer applies.",
                    "created_at": utcnow(),
                    "updated_at": utcnow(),
                }
            ],
        )
        run_compaction()

        body = client.get("/api/patchwork/digest", headers=admin_auth).json()

        assert body["total_open_prs"] == 1

    def test_the_note_says_they_stay_separate(self, client, admin_auth) -> None:
        """The thing a reader might otherwise assume this page is offering."""
        body = client.get("/api/patchwork/digest", headers=admin_auth).json()

        assert "separate pull request" in body["note"]

    def test_an_empty_portfolio_is_an_empty_digest(self, client, admin_auth) -> None:
        body = client.get("/api/patchwork/digest", headers=admin_auth).json()

        assert body["groups"] == []
        assert body["total_open_prs"] == 0
