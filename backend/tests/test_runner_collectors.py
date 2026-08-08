"""Runner-side signal and count collection — specs 06 §2, 07 §4.

These run inside a customer's Actions runner, where they are hardest to debug
and where a wrong answer is least visible. The pure functions carry the
judgement, so they are tested directly rather than through a simulated
workflow.
"""

from __future__ import annotations

import json

from mykronos.aegis_signals import (
    PullRequestFacts,
    access_anomaly_signal,
    baseline_deviation_signal,
    collect,
    discloses_ai,
    sensitive_path_signal,
)
from mykronos.atlas_counts import summarise

DEFAULT_SENSITIVE = [
    "**/auth/**",
    "**/*secret*",
    "**/.github/workflows/**",
    "**/iam/**",
]


def facts(**overrides) -> PullRequestFacts:
    payload = {
        "author_login": "octocat",
        "changed_files": ["src/app.py"],
        "files_changed_count": 1,
        "author_prior_commits": 40,
        "author_median_files": 3.0,
        "pr_body": "",
    }
    payload.update(overrides)
    return PullRequestFacts(**payload)


class TestSensitivePaths:
    def test_it_fires_on_a_matching_glob(self) -> None:
        signal = sensitive_path_signal(
            ["src/auth/session.py", "README.md"], DEFAULT_SENSITIVE
        )

        assert signal is not None
        assert signal["key"] == "sensitive_path"
        assert "src/auth/session.py" in signal["rationale"]

    def test_it_names_what_matched(self) -> None:
        """spec 06 §6: a rationale, so a person can dispute a specific claim
        rather than a number."""
        signal = sensitive_path_signal([".github/workflows/ci.yml"], DEFAULT_SENSITIVE)

        assert signal is not None
        assert ".github/workflows/ci.yml" in signal["rationale"]

    def test_a_top_level_sensitive_path_matches(self) -> None:
        """`fnmatch` alone gets this wrong: `**/.github/workflows/**` needs a
        slash before `.github`, so the file that defines what CI runs — the
        single most sensitive path in any repo — would silently not match the
        default pattern that exists to catch it."""
        for path in (
            ".github/workflows/ci.yml",
            "secrets.yml",
            "auth/session.py",
            "iam/policy.tf",
        ):
            assert sensitive_path_signal([path], DEFAULT_SENSITIVE) is not None, path

    def test_nested_paths_still_match(self) -> None:
        for path in (
            "services/api/.github/workflows/deploy.yml",
            "backend/src/auth/session.py",
            "infra/iam/roles.tf",
        ):
            assert sensitive_path_signal([path], DEFAULT_SENSITIVE) is not None, path

    def test_many_matches_are_summarised_not_dumped(self) -> None:
        signal = sensitive_path_signal(
            [f"src/auth/mod{i}.py" for i in range(10)], DEFAULT_SENSITIVE
        )

        assert signal is not None
        assert "and 7 more" in signal["rationale"]

    def test_it_stays_silent_on_ordinary_changes(self) -> None:
        assert sensitive_path_signal(["README.md", "src/app.py"], DEFAULT_SENSITIVE) is None

    def test_an_empty_pattern_list_never_fires(self) -> None:
        """A repo that cleared its sensitive paths has opted out of the
        signal, not into matching everything."""
        assert sensitive_path_signal(["src/auth/x.py"], []) is None


class TestAccessAnomaly:
    def test_a_first_contribution_fires(self) -> None:
        signal = access_anomaly_signal(facts(author_prior_commits=0))

        assert signal is not None
        assert signal["key"] == "access_anomaly"

    def test_it_is_worded_as_a_prompt_not_an_accusation(self) -> None:
        signal = access_anomaly_signal(facts(author_prior_commits=0))

        assert signal is not None
        assert "everybody has a first pull request" in signal["rationale"]

    def test_an_established_contributor_does_not_fire(self) -> None:
        assert access_anomaly_signal(facts(author_prior_commits=1)) is None


class TestBaselineDeviation:
    def test_a_much_larger_change_than_usual_fires(self) -> None:
        signal = baseline_deviation_signal(
            facts(files_changed_count=60, author_median_files=3.0)
        )

        assert signal is not None
        assert "20×" in signal["rationale"]

    def test_an_ordinary_change_does_not(self) -> None:
        assert (
            baseline_deviation_signal(
                facts(files_changed_count=4, author_median_files=3.0)
            )
            is None
        )

    def test_too_little_history_skips_rather_than_guesses(self) -> None:
        """spec 06 §7: defaulting to an extreme score for a new contributor is
        the false positive this capability can least afford."""
        assert (
            baseline_deviation_signal(
                facts(
                    author_prior_commits=2,
                    author_median_files=1.0,
                    files_changed_count=90,
                )
            )
            is None
        )

    def test_a_missing_baseline_skips(self) -> None:
        """A shallow clone costs the signal, not the assessment."""
        assert (
            baseline_deviation_signal(
                facts(author_median_files=None, files_changed_count=90)
            )
            is None
        )


class TestCollect:
    def test_the_order_is_stable(self) -> None:
        """Two runs over the same facts must produce identical output — the
        same determinism requirement the rest of the platform has."""
        subject = facts(
            changed_files=["src/auth/x.py"],
            files_changed_count=60,
            author_prior_commits=0,
        )

        assert collect(subject, DEFAULT_SENSITIVE) == collect(subject, DEFAULT_SENSITIVE)

    def test_a_clean_pull_request_reports_nothing(self) -> None:
        assert collect(facts(), DEFAULT_SENSITIVE) == []

    def test_every_reported_signal_has_a_rationale(self) -> None:
        signals = collect(
            facts(
                changed_files=["src/auth/x.py", "iam/policy.tf"],
                files_changed_count=60,
                author_prior_commits=0,
            ),
            DEFAULT_SENSITIVE,
        )

        assert signals
        for signal in signals:
            assert signal["rationale"].strip()


class TestAiDisclosure:
    def test_common_phrasings_are_recognised(self) -> None:
        for body in (
            "Generated with Claude Code",
            "This was AI-assisted",
            "wrote most of this with Copilot",
            "used ChatGPT for the tests",
        ):
            assert discloses_ai(body), body

    def test_an_ordinary_description_is_not_a_disclosure(self) -> None:
        assert not discloses_ai("Fixes the session timeout bug. Adds a test.")

    def test_matching_is_generous_on_purpose(self) -> None:
        """The cost of a false 'yes' is a signal that does not fire. The cost
        of a false 'no' is telling a reviewer somebody concealed something."""
        assert discloses_ai("LLM helped here")


class TestAtlasCounts:
    def test_a_vulnerable_package_is_counted_once(self) -> None:
        """A dependency with four CVEs is one vulnerable dependency — spec 07
        §3's count is of packages, not advisories."""
        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "lodash",
                                "version": "4.17.15",
                            },
                            "vulnerabilities": [
                                {"severity": [{"score": "HIGH"}]},
                                {"severity": [{"score": "HIGH"}]},
                                {"severity": [{"score": "CRITICAL"}]},
                            ],
                        }
                    ]
                }
            ]
        }

        (npm,) = summarise(report)

        assert npm["dependency_count"] == 1
        assert npm["critical_vulns"] == 1, "counted once, at its worst severity"
        assert npm["high_vulns"] == 0

    def test_ecosystems_are_separated_and_sorted(self) -> None:
        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "PyPI",
                                "name": "urllib3",
                                "version": "2.0.4",
                            },
                            "vulnerabilities": [{"severity": [{"score": "HIGH"}]}],
                        },
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "left-pad",
                                "version": "1.0.0",
                            },
                            "vulnerabilities": [],
                        },
                    ]
                }
            ]
        }

        result = summarise(report)

        assert [e["ecosystem"] for e in result] == ["npm", "pypi"]

    def test_a_floating_version_is_noticed(self) -> None:
        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "react",
                                "version": "^18.0.0",
                            },
                            "vulnerabilities": [],
                        },
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "vue",
                                "version": "3.4.1",
                            },
                            "vulnerabilities": [],
                        },
                    ]
                }
            ]
        }

        (npm,) = summarise(report)

        assert npm["dependency_count"] == 2
        assert npm["floating_versions"] == 1

    def test_an_unrated_advisory_becomes_medium(self) -> None:
        """Dropping it would understate the tree; calling it critical would
        make every unrated advisory a release blocker."""
        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "x",
                                "version": "1.0.0",
                            },
                            "vulnerabilities": [{}],
                        }
                    ]
                }
            ]
        }

        (npm,) = summarise(report)

        assert npm["medium_vulns"] == 1

    def test_maintenance_data_is_reported_as_unknown(self) -> None:
        """osv-scanner does not report release recency, and null is how the
        API is told to fall back rather than to assume (spec 07 §8)."""
        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "x",
                                "version": "1.0.0",
                            },
                            "vulnerabilities": [],
                        }
                    ]
                }
            ]
        }

        (npm,) = summarise(report)

        assert npm["maintenance_data_available_for"] is None

    def test_an_empty_report_is_not_an_error(self) -> None:
        assert summarise({"results": []}) == []
        assert summarise({}) == []

    def test_the_output_is_a_valid_submission_fragment(self) -> None:
        """It is passed to `jq --argjson`, so it has to be JSON-serialisable
        and shaped like EcosystemEvidence."""
        from mykronos.schemas import EcosystemEvidence

        report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {
                                "ecosystem": "npm",
                                "name": "x",
                                "version": "1.0.0",
                            },
                            "vulnerabilities": [{"severity": [{"score": "LOW"}]}],
                        }
                    ]
                }
            ]
        }

        payload = json.loads(json.dumps(summarise(report)))

        assert [EcosystemEvidence(**item) for item in payload]
