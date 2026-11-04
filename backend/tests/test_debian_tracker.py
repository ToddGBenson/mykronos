"""Debian security-tracker states as cited false-positive evidence (TheHub #60744).

The rule this file holds the classifier to: a deterministic distribution
decision (no-dsa, not-affected, will-not-fix) may *label* an OS-package
finding `likely_false_positive`, with the tracker URL and state cited, and may
never close, dismiss or otherwise change the finding. A stale or missing copy
of the tracker changes nothing, and says so in the log.
"""

from __future__ import annotations

import copy
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mykronos import auto_triage, debian_tracker
from mykronos.debian_tracker import TrackerSnapshot
from mykronos.patchwork.triage import classify, classify_verdict

#: The clock every test runs on. Pinned: a 7-day window on the real clock
#: would make a fixture's fetch time go stale a week after it was written.
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)

#: The tracker's JSON shape (security-tracker.debian.org/tracker/data/json):
#: source package -> CVE -> releases -> codename -> state.
TRACKER: dict[str, Any] = {
    "openssl": {
        # no-dsa: open, but the security team will not issue an advisory.
        "CVE-2026-1001": {
            "releases": {
                "bookworm": {
                    "status": "open",
                    "urgency": "unimportant",
                    "nodsa": "Minor issue",
                    "nodsa_reason": "",
                    "repositories": {"bookworm": "3.0.15-1~deb12u1"},
                },
            },
        },
        # not-affected: resolved with fixed version "0".
        "CVE-2026-1002": {
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "0",
                    "urgency": "unimportant",
                    "repositories": {"bookworm": "3.0.15-1~deb12u1"},
                },
            },
        },
        # will-not-fix: no-dsa with the `ignored` reason.
        "CVE-2026-1003": {
            "releases": {
                "bookworm": {
                    "status": "open",
                    "urgency": "low",
                    "nodsa": "Not worth the churn",
                    "nodsa_reason": "ignored",
                    "repositories": {"bookworm": "3.0.15-1~deb12u1"},
                },
            },
        },
        # fixed in bookworm, still open in bullseye: neither is a "no" state.
        "CVE-2026-1004": {
            "releases": {
                "bookworm": {
                    "status": "resolved",
                    "fixed_version": "3.0.15-1~deb12u2",
                    "urgency": "high",
                    "repositories": {"bookworm": "3.0.15-1~deb12u2"},
                },
                "bullseye": {
                    "status": "open",
                    "urgency": "high",
                    "repositories": {"bullseye": "1.1.1w-0+deb11u1"},
                },
            },
        },
    },
}


def _snapshot(*, age: timedelta = timedelta(days=1)) -> TrackerSnapshot:
    return TrackerSnapshot(data=TRACKER, fetched_at=NOW - age)


def _finding(cve: str = "CVE-2026-1001", **overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "rule_id": cve,
        "severity": "high",
        "capability": "containers",
        "status": "open",
        "package_name": "openssl",
        "package_version": "3.0.15-1~deb12u1",
        "os_release": "debian 12.7",
        "raw_finding_json": {"fixed_version": "", "image": "example/app:1"},
    }
    finding.update(overrides)
    return finding


# -- AC1: a no-dsa / not-affected state is cited false-positive evidence ----


class TestTrackerStateIsCitedEvidence:
    @pytest.mark.parametrize(
        ("cve", "state"),
        [
            ("CVE-2026-1001", "no-dsa"),
            ("CVE-2026-1002", "not-affected"),
            ("CVE-2026-1003", "will-not-fix"),
        ],
    )
    def test_state_for_the_release_classifies_likely_false_positive(
        self, cve: str, state: str
    ) -> None:
        verdict = classify_verdict(_finding(cve), "o/r", tracker=_snapshot(), now=NOW)

        assert verdict.classification == "likely_false_positive"
        (evidence,) = verdict.evidence
        assert evidence["type"] == "debian_security_tracker"
        assert evidence["state"] == state
        assert evidence["release"] == "bookworm"
        assert evidence["url"] == f"https://security-tracker.debian.org/tracker/{cve}"
        # The sentence a person reads cites the same two facts.
        assert state in verdict.rationale
        assert evidence["url"] in verdict.rationale

    def test_classify_tuple_agrees_with_the_verdict(self) -> None:
        classification, rationale = classify(
            _finding(), "o/r", tracker=_snapshot(), now=NOW
        )
        assert classification == "likely_false_positive"
        assert "no-dsa" in rationale

    def test_binary_package_resolves_through_the_cve_to_its_source(self) -> None:
        # Trivy names the binary package (libssl3); the tracker is keyed by
        # source (openssl). A CVE tracked under exactly one source package
        # belongs to that source.
        verdict = classify_verdict(
            _finding(package_name="libssl3"), "o/r", tracker=_snapshot(), now=NOW
        )
        assert verdict.classification == "likely_false_positive"
        assert verdict.evidence[0]["source_package"] == "openssl"

    def test_codename_is_accepted_as_the_release(self) -> None:
        verdict = classify_verdict(
            _finding(os_release="bookworm"), "o/r", tracker=_snapshot(), now=NOW
        )
        assert verdict.classification == "likely_false_positive"

    def test_release_read_from_the_raw_base_os_stamp(self) -> None:
        finding = _finding()
        del finding["os_release"]
        finding["raw_finding_json"]["base_os"] = "debian 12.7"
        verdict = classify_verdict(finding, "o/r", tracker=_snapshot(), now=NOW)
        assert verdict.classification == "likely_false_positive"

    def test_other_release_is_not_evidence(self) -> None:
        # The image runs bullseye; the bookworm decision is not about it.
        verdict = classify_verdict(
            _finding(os_release="debian 11.9"), "o/r", tracker=_snapshot(), now=NOW
        )
        assert verdict.classification == "true_positive"
        assert verdict.evidence == []

    def test_open_or_fixed_state_is_not_evidence(self) -> None:
        for release in ("debian 12.7", "debian 11.9"):
            verdict = classify_verdict(
                _finding("CVE-2026-1004", os_release=release),
                "o/r",
                tracker=_snapshot(),
                now=NOW,
            )
            assert verdict.classification == "true_positive", release

    def test_unknown_release_or_non_debian_os_is_not_evidence(self) -> None:
        for release in (None, "", "alpine 3.20", "debian", "ubuntu 24.04"):
            verdict = classify_verdict(
                _finding(os_release=release), "o/r", tracker=_snapshot(), now=NOW
            )
            assert verdict.classification == "true_positive", release

    def test_no_tracker_means_today_s_behaviour(self) -> None:
        assert classify(_finding(), "o/r") == classify(_finding(), "o/r", tracker=None)
        assert classify(_finding(), "o/r")[0] == "true_positive"

    def test_a_prior_reasoned_dismissal_still_wins(self) -> None:
        # Ordering: the Knowledge Store's dismissal is checked first, so the
        # existing sentence is unchanged where it already applied.
        class _Entry:
            source_type = "finding_dismissal"
            subject = "CVE-2026-1001"
            repo_full_name = None
            has_reason = True
            observations = 2
            reasons = ["vendored, never loaded"]

        verdict = classify_verdict(
            _finding(),
            "o/r",
            entries=[(_Entry(), 0.9)],  # type: ignore[list-item]
            tracker=_snapshot(),
            now=NOW,
        )
        assert verdict.classification == "likely_false_positive"
        assert "dismissed" in verdict.rationale
        assert verdict.evidence == []


# -- AC2: the evidence never changes a finding's state ----------------------


class TestNeverClosesAFinding:
    def test_classifying_leaves_the_finding_untouched(self) -> None:
        finding = _finding()
        before = copy.deepcopy(finding)
        classify_verdict(finding, "o/r", tracker=_snapshot(), now=NOW)
        assert finding == before
        assert finding["status"] == "open"

    def test_auto_triage_has_no_rule_for_the_tracker(self) -> None:
        # Auto-triage is the only path that closes or dismisses without a
        # person; it must not learn a rule from this evidence.
        assert not any("debian" in rule or "tracker" in rule for rule in auto_triage.RULES)
        assert not any("debian" in rule for rule in auto_triage.SERIOUS_EVIDENCE)

    def test_the_verdict_says_it_closes_nothing(self) -> None:
        verdict = classify_verdict(_finding(), "o/r", tracker=_snapshot(), now=NOW)
        assert verdict.evidence[0]["closes_finding"] is False
        assert "never closes" in verdict.rationale


# -- AC3: unreachable or stale tracker data changes nothing, with a warning --


class TestStaleOrUnreachable:
    def test_copy_older_than_seven_days_is_ignored_with_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        stale = _snapshot(age=timedelta(days=7, seconds=1))
        with caplog.at_level(logging.WARNING, logger="mykronos.debian_tracker"):
            verdict = classify_verdict(_finding(), "o/r", tracker=stale, now=NOW)

        assert verdict.classification == "true_positive"
        assert verdict.evidence == []
        (record,) = [r for r in caplog.records if r.name == "mykronos.debian_tracker"]
        assert "stale" in record.getMessage()
        assert "7 days" in record.getMessage()

    def test_copy_exactly_seven_days_old_is_still_used(self) -> None:
        fresh = _snapshot(age=timedelta(days=7))
        verdict = classify_verdict(_finding(), "o/r", tracker=fresh, now=NOW)
        assert verdict.classification == "likely_false_positive"

    def test_missing_cache_file_returns_none_with_a_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="mykronos.debian_tracker"):
            assert debian_tracker.load_cached(tmp_path / "absent.json", now=NOW) is None
        assert any("no cached copy" in r.getMessage() for r in caplog.records)

    def test_stale_cache_file_returns_none_with_a_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "tracker.json"
        debian_tracker.save(_snapshot(age=timedelta(days=9)), path)
        with caplog.at_level(logging.WARNING, logger="mykronos.debian_tracker"):
            assert debian_tracker.load_cached(path, now=NOW) is None
        assert any("stale" in r.getMessage() for r in caplog.records)

    def test_fresh_cache_round_trips_with_its_fetch_time(self, tmp_path: Path) -> None:
        path = tmp_path / "tracker.json"
        snapshot = _snapshot(age=timedelta(hours=3))
        debian_tracker.save(snapshot, path)
        loaded = debian_tracker.load_cached(path, now=NOW)
        assert loaded is not None
        assert loaded.fetched_at == snapshot.fetched_at
        assert loaded.data == TRACKER

    def test_corrupt_cache_file_returns_none(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "tracker.json"
        path.write_text("{not json", encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="mykronos.debian_tracker"):
            assert debian_tracker.load_cached(path, now=NOW) is None
        assert caplog.records

    def test_unreachable_tracker_keeps_the_old_cache_and_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "tracker.json"
        debian_tracker.save(_snapshot(age=timedelta(days=2)), path)

        def _down() -> object:
            raise OSError("connection refused")

        with caplog.at_level(logging.WARNING, logger="mykronos.debian_tracker"):
            assert debian_tracker.refresh(path, fetch=_down, now=NOW) is False
        assert any("unreachable" in r.getMessage() for r in caplog.records)
        # The previous copy survives a failed fetch.
        assert json.loads(path.read_text(encoding="utf-8"))["data"] == TRACKER

    def test_refresh_writes_the_payload_with_the_fetch_time(self, tmp_path: Path) -> None:
        path = tmp_path / "tracker.json"
        assert debian_tracker.refresh(path, fetch=lambda: TRACKER, now=NOW) is True
        loaded = debian_tracker.load_cached(path, now=NOW)
        assert loaded is not None
        assert loaded.fetched_at == NOW

    def test_refresh_rejects_a_payload_of_the_wrong_shape(self, tmp_path: Path) -> None:
        path = tmp_path / "tracker.json"
        assert debian_tracker.refresh(path, fetch=lambda: ["nope"], now=NOW) is False
        assert not path.exists()

    def test_the_tracker_is_fetched_over_https(self) -> None:
        assert debian_tracker.TRACKER_URL.startswith("https://")


# -- AC4: fixed-version data that contradicts the tracker is not downgraded --


class TestContradictionIsNotDowngraded:
    def test_scanner_fixed_version_contradicts_a_no_dsa_state(self) -> None:
        # The scanner says this release has a fix; the tracker says it will
        # not get one. The two disagree, so the finding keeps its severity
        # verdict.
        finding = _finding(raw_finding_json={"fixed_version": "3.0.15-1~deb12u2"})
        verdict = classify_verdict(finding, "o/r", tracker=_snapshot(), now=NOW)
        assert verdict.classification == "true_positive"
        assert verdict.evidence == []

    def test_top_level_fixed_version_also_counts(self) -> None:
        finding = _finding(fixed_version="3.0.15-1~deb12u2")
        verdict = classify_verdict(finding, "o/r", tracker=_snapshot(), now=NOW)
        assert verdict.classification == "true_positive"

    def test_installed_at_or_above_a_real_fix_is_not_this_path(self) -> None:
        # A resolved entry with a real fixed version is "fixed", never a
        # false-positive state, whatever the installed version is.
        finding = _finding(
            "CVE-2026-1004", package_version="3.0.15-1~deb12u2", os_release="debian 12.7"
        )
        verdict = classify_verdict(finding, "o/r", tracker=_snapshot(), now=NOW)
        assert verdict.classification == "true_positive"
        assert verdict.evidence == []


class TestReleaseNames:
    @pytest.mark.parametrize(
        ("text", "codename"),
        [
            ("debian 12.7", "bookworm"),
            ("Debian 11", "bullseye"),
            ("debian 10.13", "buster"),
            ("debian 13.1", "trixie"),
            ("bookworm", "bookworm"),
            ("alpine 3.20", None),
            ("", None),
            (None, None),
        ],
    )
    def test_release_codename(self, text: str | None, codename: str | None) -> None:
        assert debian_tracker.release_codename(text) == codename
