"""Patchwork — spec 08.

`TestTheHardConstraint` comes first because it is the one thing in this
capability that must never regress. Everything else is a quality question;
that is a trust question.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mykronos.github.client import FakeGitHubClient, GitHubClient
from mykronos.patchwork import correlate, fixers
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

REQUIREMENTS = "requirements.txt"


class TestTheHardConstraint:
    """spec 08 §3. Patchwork never merges anything.

    Not enforceable by GitHub permission — merging needs `contents: write`,
    which the App holds so the Workflow Installer can commit workflow files at
    all (D-008). So the guarantee lives here: there is no method to call.
    """

    def test_the_client_exposes_no_merge_operation(self) -> None:
        for name in dir(GitHubClient):
            assert "merge" not in name.lower(), (
                f"GitHubClient.{name} exists. spec 08 §3 makes 'Patchwork "
                "never merges' a hard constraint enforced by the absence of "
                "this capability from the interface. Adding it needs a "
                "separately-reviewed design change, not a passing test."
            )

    def test_neither_implementation_has_one_either(self) -> None:
        from mykronos.github.client import RestGitHubClient

        for implementation in (FakeGitHubClient, RestGitHubClient):
            for name in dir(implementation):
                assert "merge" not in name.lower(), (
                    f"{implementation.__name__}.{name} exists."
                )

    def test_every_patchwork_pull_request_is_a_draft(self) -> None:
        """Not a parameter the pipeline passes through from config — written
        once at the call site so there is nowhere for it to be got wrong."""
        import inspect

        from mykronos.patchwork import pipeline

        source = inspect.getsource(pipeline.PatchworkPipeline._open_draft_pr)

        assert "draft=True" in source
        assert "draft=False" not in source


class TestDeterministicFixers:
    def test_it_pins_a_vulnerable_dependency(self) -> None:
        finding = {
            "package_name": "urllib3",
            "file_path": REQUIREMENTS,
            "raw_finding_json": {"fixed_version": "2.2.2"},
        }
        content = "requests==2.31.0\nurllib3==2.0.4\n"

        fix = fixers.pin_python_requirement(finding, content)

        assert fix is not None
        assert fix.files[REQUIREMENTS] == "requests==2.31.0\nurllib3==2.2.2\n"

    def test_it_leaves_a_range_alone(self) -> None:
        """Narrowing `urllib3>=2.0` to an exact pin is a change to the
        project's dependency policy, not a security fix, and not Patchwork's
        call to make."""
        finding = {
            "package_name": "urllib3",
            "file_path": REQUIREMENTS,
            "raw_finding_json": {"fixed_version": "2.2.2"},
        }

        assert fixers.pin_python_requirement(finding, "urllib3>=2.0\n") is None

    def test_it_does_nothing_without_a_fixed_version(self) -> None:
        """An advisory with no known fix cannot be fixed by pinning."""
        finding = {"package_name": "urllib3", "file_path": REQUIREMENTS}

        assert fixers.pin_python_requirement(finding, "urllib3==2.0.4\n") is None

    def test_it_is_deterministic(self) -> None:
        finding = {
            "package_name": "urllib3",
            "file_path": REQUIREMENTS,
            "raw_finding_json": {"fixed_version": "2.2.2"},
        }
        content = "urllib3==2.0.4\n"

        first = fixers.pin_python_requirement(finding, content)
        second = fixers.pin_python_requirement(finding, content)

        assert first is not None and second is not None
        assert first.files == second.files

    def test_the_review_notes_are_specific(self) -> None:
        """"Review this" with no specifics is a disclaimer, not guidance."""
        fix = fixers.pin_python_requirement(
            {
                "package_name": "urllib3",
                "file_path": REQUIREMENTS,
                "raw_finding_json": {"fixed_version": "2.2.2"},
            },
            "urllib3==2.0.4\n",
        )

        assert fix is not None
        assert any("test suite" in note for note in fix.review_notes)
        assert any("2.2.2" in note for note in fix.review_notes)


class TestSecretFixer:
    def _finding(self, **overrides):
        payload = {
            "capability": "secrets",
            "file_path": "app/config.py",
            "line_start": 2,
        }
        payload.update(overrides)
        return payload

    def test_it_replaces_the_literal_with_an_environment_lookup(self) -> None:
        content = 'import sys\nAPI_TOKEN = "hunter2"\n'

        fix = fixers.remove_committed_secret(self._finding(), content)

        assert fix is not None
        assert 'API_TOKEN = os.environ["API_TOKEN"]' in fix.files["app/config.py"]
        assert "hunter2" not in fix.files["app/config.py"]

    def test_it_leads_with_rotation(self) -> None:
        """A fix that made the repository look clean while the credential
        stayed valid would be worse than no fix."""
        fix = fixers.remove_committed_secret(
            self._finding(), 'x = 1\nTOKEN = "abc"\n'
        )

        assert fix is not None
        assert "Rotate the credential first" in fix.review_notes[0]
        assert "git history" in fix.review_notes[0]

    def test_it_refuses_anything_more_structured(self) -> None:
        """A regex rewriting arbitrary code around a secret turns a leaked
        credential into a leaked credential *and* a broken build."""
        content = 'x = 1\nconn = connect(token="abc", retries=3)\n'

        assert fixers.remove_committed_secret(self._finding(), content) is None

    def test_it_only_touches_secrets_findings(self) -> None:
        assert (
            fixers.remove_committed_secret(
                self._finding(capability="sast"), 'x = 1\nT = "a"\n'
            )
            is None
        )


class TestCorrelation:
    def _finding(
        self, finding_id, rule_id, path="src/api.py", title="", capability="sast"
    ):
        # `capability` is not optional in real data and these fixtures used to
        # omit it, which is how the secrets rule reached production able to
        # match container CVE titles.
        return {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "title": title or rule_id,
            "file_path": path,
            "capability": capability,
            "severity": "high",
        }

    def test_a_container_cve_is_not_a_committed_credential(self) -> None:
        """Found in production, twice. Grouped by `file_path` - which for a
        container finding is the image name - libcurl's "failure to clear
        proxy authentication credentials" matched `credential` and libssh2's
        "publickey attribute allocation" matched `public`, so two unrelated
        CVEs in one image were reported as a committed credential on a public
        surface. Nothing about the words was wrong; the rule simply never said
        which scanner it meant."""
        findings = [
            self._finding(
                "c1",
                "CVE-2026-9079",
                path="library/mykronos-scan",
                title="libcurl: Information disclosure due to failure to clear "
                "proxy authentication credentials",
                capability="containers",
            ),
            self._finding(
                "c2",
                "CVE-2026-58050",
                path="library/mykronos-scan",
                title="libssh2: Heap buffer overflow via integer overflow in "
                "publickey attribute allocation",
                capability="containers",
            ),
        ]

        assert correlate.detect(findings) == []

    def test_it_detects_an_unauthenticated_injectable_endpoint(self) -> None:
        findings = [
            self._finding("f1", "CWE-89"),
            self._finding("f2", "CWE-306"),
        ]

        combos = correlate.detect(findings)

        assert len(combos) == 1
        assert combos[0].finding_ids == frozenset({"f1", "f2"})
        assert "unauthenticated path to the database" in combos[0].rationale

    def test_proximity_matters(self) -> None:
        """The default scope is one file, because proximity is most of what
        makes a combination toxic rather than coincidental."""
        findings = [
            self._finding("f1", "CWE-89", path="src/a.py"),
            self._finding("f2", "CWE-306", path="src/b.py"),
        ]

        assert correlate.detect(findings) == []

    def test_a_finding_appears_in_at_most_one_combination(self) -> None:
        """Overlap would mean one finding generating several draft pull
        requests — the flooding backpressure exists to prevent, by another
        route."""
        findings = [
            self._finding("f1", "CWE-89"),
            self._finding("f2", "CWE-306"),
            self._finding("f3", "generic-api-key"),
        ]

        combos = correlate.detect(findings)
        seen = [fid for combo in combos for fid in combo.finding_ids]

        assert len(seen) == len(set(seen))

    def test_the_id_is_derived_from_its_members(self) -> None:
        first = correlate.combination_id("r", frozenset({"a", "b"}))
        same = correlate.combination_id("r", frozenset({"b", "a"}))
        different = correlate.combination_id("r", frozenset({"a", "c"}))

        assert first == same
        assert first != different

    def test_a_lone_finding_is_not_a_combination(self) -> None:
        assert correlate.detect([self._finding("f1", "CWE-89")]) == []


@pytest.fixture
def patchwork_auth(client: TestClient) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'secrets', 'patchwork')}"
    }


def put_file(github, path: str, content: str, branch: str = "main") -> None:
    """Write a file the fake will serve.

    The fake resolves a ref to `branches[ref]` when that branch exists and
    only falls back to `files` when it does not — which is right, and is why
    writing to `files` alone silently produced "the file no longer exists".
    """
    repo = github.repos[REPO]
    repo.files[path] = content
    repo.branches.setdefault(branch, {})[path] = content


def seed(client, auth, run_compaction, findings):
    post_scan(client, auth, scan_run_id="scan-1")
    post_findings(client, auth, findings, scan_run_id="scan-1")
    run_compaction()


def dependency_finding(**overrides):
    payload = {
        "rule_id": "CVE-2024-4812",
        "title": "urllib3 redirect handling flaw",
        "severity": "critical",
        "file_path": REQUIREMENTS,
        "package_name": "urllib3",
        "package_version": "2.0.4",
        "symbol": None,
        "code_snippet": None,
        "raw_finding_json": {"fixed_version": "2.2.2"},
    }
    payload.update(overrides)
    return finding_payload(**payload)


class TestKevBoost:
    """spec 17 §5.6 — a combination naming a KEV-listed CVE says so."""

    def _finding(self, finding_id, rule_id, path="src/api.py", title="", capability="sast"):
        return {
            "finding_id": finding_id,
            "rule_id": rule_id,
            "title": title or rule_id,
            "file_path": path,
            "capability": capability,
            "severity": "high",
        }

    def test_no_kev_ids_is_a_no_op(self) -> None:
        findings = [self._finding("f1", "CWE-89"), self._finding("f2", "CWE-306")]
        combos = correlate.detect(findings)
        by_id = {f["finding_id"]: f for f in findings}

        assert correlate.kev_boosted(combos, by_id, set()) == combos

    def test_a_member_naming_a_kev_cve_gets_a_prefixed_rationale(self) -> None:
        findings = [
            self._finding("f1", "CWE-89"),
            self._finding("f2", "CWE-306", title="CVE-2024-12345 missing auth check"),
        ]
        combos = correlate.detect(findings)
        by_id = {f["finding_id"]: f for f in findings}
        assert len(combos) == 1

        boosted = correlate.kev_boosted(combos, by_id, {"CVE-2024-12345"})

        assert len(boosted) == 1
        assert boosted[0].finding_ids == combos[0].finding_ids
        assert boosted[0].rationale.startswith("**Actively exploited.**")
        assert "CVE-2024-12345" in boosted[0].rationale
        # The original explanation still follows the prefix — the boost adds
        # urgency, it doesn't replace the reason the rule fired.
        assert combos[0].rationale in boosted[0].rationale

    def test_a_combination_with_no_kev_member_is_unchanged(self) -> None:
        findings = [self._finding("f1", "CWE-89"), self._finding("f2", "CWE-306")]
        combos = correlate.detect(findings)
        by_id = {f["finding_id"]: f for f in findings}

        boosted = correlate.kev_boosted(combos, by_id, {"CVE-2024-99999"})
        assert boosted == combos


class TestPipeline:
    def _run(self, client, patchwork_auth, **body):
        return client.post("/api/patchwork/run", json=body, headers=patchwork_auth)

    def test_it_opens_a_draft_pull_request(
        self, client, admin_auth, patchwork_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        body = self._run(client, patchwork_auth).json()

        assert body["draft_prs_opened"] == 1
        pr = github.repos[REPO].pull_requests[-1]
        assert pr.draft is True

    def test_the_fix_is_actually_committed(
        self, client, admin_auth, patchwork_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        self._run(client, patchwork_auth)

        branch = github.repos[REPO].pull_requests[-1].head_branch
        assert "2.2.2" in github.repos[REPO].branches[branch][REQUIREMENTS]

    def test_the_pr_body_leads_with_what_to_check(
        self, client, admin_auth, patchwork_auth, run_compaction, github
    ) -> None:
        """A reviewer's job on a machine-generated PR is to find what the
        machine got wrong."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        self._run(client, patchwork_auth)
        number = github.repos[REPO].pull_requests[-1].number
        body = github.pull_request_bodies[number]

        assert "Before you approve" in body
        assert body.index("Before you approve") < body.index("What this addresses")
        assert "has no ability to merge" in body

    def test_every_routed_finding_produces_an_event(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        """spec 08 §7, including the ones where nothing happened."""
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [
                dependency_finding(),
                finding_payload(rule_id="CWE-79", severity="low", symbol="a"),
            ],
        )

        self._run(client, patchwork_auth)
        run_compaction()

        assert catalog.count("remediation_events") == 2

    def test_a_finding_with_no_fixer_says_so(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        # The file has to exist, or the pipeline correctly reports the finding
        # as superseded rather than unfixable — a different and better answer.
        put_file(github, "orders/query.py", "def get_order(order_id):\n    pass\n")
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [finding_payload(rule_id="CWE-89", severity="critical")],
        )

        self._run(client, patchwork_auth)
        run_compaction()

        stage, rationale = catalog.query(
            "SELECT pipeline_stage_reached, rationale FROM remediation_events"
        )[0]
        assert stage == "no_fix_available"
        assert "no fix generator endpoint is configured" in rationale

    def test_a_low_finding_is_not_worth_a_draft_pr(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [finding_payload(rule_id="CWE-79", severity="low")],
        )

        self._run(client, patchwork_auth)
        run_compaction()

        stage, classification = catalog.query(
            "SELECT pipeline_stage_reached, triage_classification "
            "FROM remediation_events"
        )[0]
        assert stage == "triaged"
        assert classification == "needs_human_judgment"

    def test_re_running_upserts_rather_than_appending(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """The pipeline runs on every push to a pull request; §7 wants exactly
        one event per finding."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        self._run(client, patchwork_auth)
        run_compaction()
        self._run(client, patchwork_auth)
        run_compaction()

        assert catalog.count("remediation_events") == 1

    def test_the_pr_it_opened_is_not_blanked_by_a_later_run(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        self._run(client, patchwork_auth)
        run_compaction()
        self._run(client, patchwork_auth)
        run_compaction()

        number, status = catalog.query(
            "SELECT fix_pr_number, pr_status FROM remediation_events"
        )[0]
        assert number is not None
        assert status == "draft_open"


class TestBackpressure:
    def test_over_the_limit_a_candidate_queues(
        self, client, admin_auth, run_compaction, catalog, github
    ) -> None:
        """spec 08 §5. A repository that wakes up to forty draft pull requests
        does not triage them, it turns the capability off."""
        from mykronos.db.models import CapabilityConfig

        repo_id = onboard(client, admin_auth).json()["id"]
        with client.app.state.db.session() as session:
            session.add(
                CapabilityConfig(
                    repo_onboarding_id=repo_id,
                    capability="patchwork",
                    config_json={"max_open_draft_prs_per_repo": 1},
                )
            )

        auth = {
            "Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'patchwork')}"
        }
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\nrequests==2.0.0\n")
        seed(
            client,
            auth,
            run_compaction,
            [
                dependency_finding(symbol="a", code_snippet="a()"),
                dependency_finding(
                    package_name="requests",
                    symbol="b",
                    code_snippet="b()",
                    raw_finding_json={"fixed_version": "2.32.0"},
                ),
            ],
        )

        body = client.post("/api/patchwork/run", json={}, headers=auth).json()
        run_compaction()

        assert body["draft_prs_opened"] == 1
        assert body["queued"] == 1
        stages = dict(
            catalog.query(
                "SELECT pipeline_stage_reached, count(*) FROM remediation_events "
                "GROUP BY 1"
            )
        )
        assert stages == {"pr_opened": 1, "queued": 1}


class TestTriageUsesTheKnowledgeStore:
    def test_a_dismissed_rule_is_not_auto_fixed(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """The store is what stops the pipeline repeating a mistake somebody
        has already corrected."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        client.app.state.knowledge.add_entry(
            source_type="finding_dismissal",
            subject="CVE-2024-4812",
            source_ref="f",
            text="noise",
            repo_full_name=REPO,
            reason="we do not use the affected code path",
        )

        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()

        stage, classification, rationale = catalog.query(
            "SELECT pipeline_stage_reached, triage_classification, rationale "
            "FROM remediation_events"
        )[0]
        assert stage == "triaged"
        assert classification == "likely_false_positive"
        assert "do not use the affected code path" in rationale


class TestCrossCapabilityCombinations:
    """Combinations spanning a running application and its source (spec 08 §5a).

    These are the ones neither scanner can see alone: DAST knows an endpoint
    answers without credentials but not what the handler contains; SAST knows
    the handler is injectable but not whether anything can reach it.
    """

    def _f(self, fid, capability, rule_id, severity="high", title=""):
        return {
            "finding_id": fid,
            "rule_id": rule_id,
            "title": title or rule_id,
            "capability": capability,
            "severity": severity,
            "file_path": "",
        }

    def test_every_built_in_rule_can_actually_fire(self) -> None:
        """The bug this exists for: the first draft of these rules matched on
        `^dast:` against a haystack of rule_id and title. Nothing puts a
        capability there - ZAP emits `ZAP-10202-CWE-352`, Trivy emits
        `CVE-2023-45853` - so all four rules would have matched nothing, for
        ever, and a correlation engine that finds nothing looks exactly like
        a codebase with no toxic combinations."""
        for rule in correlate.BUILT_IN_RULES:
            findings = [
                self._f(
                    f"f{i}",
                    requirement.capability or "sast",
                    self._sample_for(requirement.pattern),
                    severity="critical",
                )
                for i, requirement in enumerate(rule.requires)
            ]
            for finding in findings:
                finding["file_path"] = "src/api.py"

            combos = correlate.detect(findings, rules=(rule,))

            assert len(combos) == 1, f"{rule.rule_id} cannot fire"

    @staticmethod
    def _sample_for(pattern: str) -> str:
        """A literal that satisfies the first alternative of a rule pattern."""
        first = pattern.split("|")[0]
        return first.replace(".?", "-").replace(r"\.", ".").lstrip("^")

    def test_a_reachable_endpoint_plus_injectable_code(self) -> None:
        findings = [
            self._f("d1", "dast", "ZAP-10202", title="Missing anti-CSRF / auth token"),
            self._f("s1", "sast", "CWE-89", title="SQL injection"),
        ]

        combos = correlate.detect(findings)

        assert len(combos) == 1
        assert combos[0].finding_ids == frozenset({"d1", "s1"})
        assert "unauthenticated path to the database" in combos[0].rationale

    def test_capability_is_required_not_just_the_pattern(self) -> None:
        """Both halves matching the words is not enough - a SAST finding that
        mentions authentication is not evidence the endpoint is reachable."""
        findings = [
            self._f("s0", "sast", "CWE-306", title="missing auth check"),
            self._f("s1", "sast", "CWE-89", title="SQL injection"),
        ]

        combos = correlate.detect(findings, rules=(correlate.BUILT_IN_RULES[2],))

        assert combos == []

    def test_a_low_severity_cve_does_not_qualify(self) -> None:
        """Every image carries low-severity CVEs - this repository accepted
        243 of them. Without the floor the rule fires on every repository
        that runs a web server."""
        rule = next(
            r for r in correlate.BUILT_IN_RULES if r.rule_id == "vulnerable-image-and-live-service"
        )
        low = [
            self._f("c1", "containers", "CVE-2023-45853", severity="low"),
            self._f("d1", "dast", "ZAP-10096", title="Server version disclosure"),
        ]
        high = [
            self._f("c1", "containers", "CVE-2023-45853", severity="critical"),
            self._f("d1", "dast", "ZAP-10096", title="Server version disclosure"),
        ]

        assert correlate.detect(low, rules=(rule,)) == []
        assert len(correlate.detect(high, rules=(rule,))) == 1

    def test_every_capability_a_rule_names_is_in_the_correlation_pool(self) -> None:
        """A rule naming a capability the pool does not fetch cannot fire, and
        fails silently - the same shape as the `^dast:` patterns that matched
        nothing. This has now been the failure mode twice, so it is a test
        rather than something to remember."""
        from mykronos.patchwork.pipeline import DEFAULT_CORRELATION_CAPABILITIES

        named = {
            requirement.capability
            for rule in correlate.BUILT_IN_RULES
            for requirement in rule.requires
            if requirement.capability
        }

        assert named <= set(DEFAULT_CORRELATION_CAPABILITIES), (
            f"{sorted(named - set(DEFAULT_CORRELATION_CAPABILITIES))} are named by a "
            "rule but never fetched, so those rules cannot fire"
        )

    def test_a_dast_finding_can_be_half_of_a_combination(self) -> None:
        """The point of spec 08 §5a. Patchwork will never write a patch for a
        DAST finding, and that is not a reason for it to be invisible to
        correlation."""
        from mykronos.patchwork.pipeline import (
            DEFAULT_CORRELATION_CAPABILITIES,
            DEFAULT_SOURCE_CAPABILITIES,
        )

        assert "dast" not in DEFAULT_SOURCE_CAPABILITIES
        assert "dast" in DEFAULT_CORRELATION_CAPABILITIES


class TestCombinationEvents:
    def test_a_combination_records_its_members(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        """spec 08 §7: one event referencing all contributing findings."""
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [
                finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
                finding_payload(rule_id="CWE-306", severity="high", symbol="b"),
            ],
        )

        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()

        rows = catalog.query(
            "SELECT toxic_combination_id, contributing_finding_ids "
            "FROM remediation_events WHERE toxic_combination_id IS NOT NULL"
        )
        assert len(rows) == 1
        assert len(json.loads(rows[0][1])) == 2

    def test_members_are_not_fixed_in_isolation(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        """Fixing one half of a toxic pair closes the finding without closing
        the risk."""
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [
                finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
                finding_payload(rule_id="CWE-306", severity="high", symbol="b"),
            ],
        )

        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()

        assert catalog.count("remediation_events") == 1


class TestApi:
    def test_the_patchwork_grant_is_required(self, client, admin_auth) -> None:
        onboard(client, admin_auth)
        other = {
            "Authorization": f"Bearer {issue_token(client, 'example-org/x', 'sast')}"
        }

        assert (
            client.post("/api/patchwork/run", json={}, headers=other).status_code == 403
        )

    def test_events_are_listed_for_a_repo(
        self, client, admin_auth, patchwork_auth, run_compaction, github
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()

        body = client.get(
            f"/api/patchwork/repos/{repo_id}", headers=admin_auth
        ).json()

        assert body["open_draft_prs"] == 1
        assert body["events"][0]["pipeline_stage_reached"] == "pr_opened"
        assert "never merges" in body["note"]

    def test_it_needs_authentication(self, client) -> None:
        assert client.post("/api/patchwork/run", json={}).status_code == 401


class TestPerFindingRemediation:
    """spec 18 §7: a person clicking one finding, not CI sweeping a repo."""

    def _finding_id(self, catalog, rule_id: str) -> str:
        rows = catalog.query(
            "SELECT finding_id FROM findings WHERE rule_id = ? LIMIT 1", [rule_id]
        )
        return str(rows[0][0])

    def test_preview_identifies_a_fix_without_opening_anything(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        body = client.post(
            f"/api/patchwork/findings/{finding_id}/preview", headers=admin_auth
        ).json()

        assert body["stage"] == "would_fix"
        assert body["fixer_name"]
        assert REQUIREMENTS in body["fix_files"]
        assert "2.2.2" in body["fix_files"][REQUIREMENTS]
        assert github.repos[REPO].pull_requests == []

    def test_preview_writes_no_remediation_event(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """A preview nobody acts on should leave no trace (spec 18 §7.2)."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        client.post(f"/api/patchwork/findings/{finding_id}/preview", headers=admin_auth)
        run_compaction()

        assert catalog.count("remediation_events") == 0

    def test_fix_opens_exactly_one_draft_pr(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        body = client.post(
            f"/api/patchwork/findings/{finding_id}/fix", headers=admin_auth
        ).json()

        assert body["stage"] == "pr_opened"
        assert body["fix_pr_url"]
        pr = github.repos[REPO].pull_requests[-1]
        assert pr.draft is True

    def test_fix_writes_a_remediation_event(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        client.post(f"/api/patchwork/findings/{finding_id}/fix", headers=admin_auth)
        run_compaction()

        assert catalog.count("remediation_events") == 1

    def test_fix_requires_admin(
        self, client, admin_auth, viewer_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        response = client.post(
            f"/api/patchwork/findings/{finding_id}/fix", headers=viewer_auth
        )

        assert response.status_code == 403
        assert github.repos[REPO].pull_requests == []

    def test_preview_does_not_require_admin(
        self, client, admin_auth, viewer_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """Read-only, so a viewer can see it — the same standard every other
        finding detail is already held to."""
        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        response = client.post(
            f"/api/patchwork/findings/{finding_id}/preview", headers=viewer_auth
        )

        assert response.status_code == 200

    def test_an_unknown_finding_id_is_404(self, client, admin_auth) -> None:
        onboard(client, admin_auth)

        response = client.post(
            "/api/patchwork/findings/does-not-exist/preview", headers=admin_auth
        )

        assert response.status_code == 404

    def test_a_finding_on_a_human_edited_branch_is_refused(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """The permanent off-limits transition (spec 08 §3) applies to the
        on-demand path exactly as it does to the batch one."""
        from tests.test_onboarding import deliver

        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        finding_id = self._finding_id(catalog, "CVE-2024-4812")

        # First fix opens the branch; a human push to it marks it off limits
        # for every future run, batch or on-demand (spec 08 §3's own webhook
        # path — TestHumanEdits in test_patchwork_stewardship.py).
        client.post(f"/api/patchwork/findings/{finding_id}/fix", headers=admin_auth)
        run_compaction()
        branch = github.repos[REPO].pull_requests[-1].head_branch
        client.app.state.settings.github_bot_logins = ["mykronos-platform[bot]"]
        deliver(
            client,
            "push",
            {
                "ref": f"refs/heads/{branch}",
                "repository": {"full_name": REPO},
                "commits": [
                    {
                        "id": "abc123",
                        "author": {"username": "octocat", "name": "octocat"},
                        "committer": {"username": "octocat", "name": "octocat"},
                    }
                ],
            },
        )
        run_compaction()

        body = client.post(
            f"/api/patchwork/findings/{finding_id}/fix", headers=admin_auth
        ).json()

        assert body["stage"] == "no_fix_available"
        assert "already edited" in body["rationale"]

    def test_a_finding_claimed_by_a_toxic_combination_is_not_fixed_alone(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [
                finding_payload(rule_id="CWE-89", severity="critical", symbol="a"),
                finding_payload(
                    rule_id="CWE-306",
                    title="Missing authentication check",
                    severity="medium",
                    symbol="b",
                ),
            ],
        )
        finding_id = self._finding_id(catalog, "CWE-89")

        body = client.post(
            f"/api/patchwork/findings/{finding_id}/preview", headers=admin_auth
        ).json()

        assert body["stage"] == "correlated"
        assert body["toxic_combination_id"]

    def test_a_low_severity_finding_is_not_fixed_unprompted(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog
    ) -> None:
        onboard(client, admin_auth)
        seed(
            client,
            patchwork_auth,
            run_compaction,
            [finding_payload(rule_id="CWE-79", severity="low", symbol="a")],
        )
        finding_id = self._finding_id(catalog, "CWE-79")

        body = client.post(
            f"/api/patchwork/findings/{finding_id}/preview", headers=admin_auth
        ).json()

        assert body["stage"] == "triaged"
        assert body["classification"] == "needs_human_judgment"


class TestOracleSeesFixesInFlight:
    def test_a_finding_being_fixed_counts_for_less(
        self, client, admin_auth, patchwork_auth, run_compaction, catalog, github
    ) -> None:
        """spec 09 §5: a fix in flight lowers urgency, not risk."""
        from mykronos.config import get_settings
        from mykronos.oracle import load_policy
        from mykronos.oracle.engine import OracleEngine

        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])

        engine = OracleEngine(
            client.app.state.catalog, load_policy(get_settings().oracle_policy_path)
        )
        before = engine.evaluate(REPO).overall_risk_score

        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()
        after = engine.evaluate(REPO)

        assert after.overall_risk_score < before
        assert after.inputs_snapshot["remediation_in_flight"]["covered_findings"] == 1
        assert "fix in flight" in after.inputs_snapshot["terms"][0]["label"]

    def test_it_is_a_discount_not_an_exclusion(
        self, client, admin_auth, patchwork_auth, run_compaction, github
    ) -> None:
        """A repo with ten open auto-fixes is not a safe repo, it is a repo
        with ten unmerged fixes."""
        from mykronos.config import get_settings
        from mykronos.oracle import load_policy
        from mykronos.oracle.engine import OracleEngine

        onboard(client, admin_auth)
        put_file(github, REQUIREMENTS, "urllib3==2.0.4\n")
        seed(client, patchwork_auth, run_compaction, [dependency_finding()])
        client.post("/api/patchwork/run", json={}, headers=patchwork_auth)
        run_compaction()

        engine = OracleEngine(
            client.app.state.catalog, load_policy(get_settings().oracle_policy_path)
        )

        assert engine.evaluate(REPO).overall_risk_score > 0
