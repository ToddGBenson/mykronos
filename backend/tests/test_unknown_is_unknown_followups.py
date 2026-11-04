"""Two more readers that turned "not checked" into False (Fable review of
#1119, TheHub #61349). Same class as D-176: no ThreatIntelMatch row means
nobody fetched the CVE, which is not the same as "not in KEV"."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from mykronos import agent_work
from mykronos.adminauth import ActorKind, Principal, Role
from mykronos.briefing import Briefing
from mykronos.db.models import ThreatIntelMatch
from mykronos.triage_story import TriageStory, _threat_intel_for

AGENT = Principal(actor="agent:test:abc", role=Role.AGENT, kind=ActorKind.AGENT)
CVE = "CVE-2031-3001"


def _story(**overrides: Any) -> TriageStory:
    values: dict[str, Any] = {
        "subject_id": "finding-1",
        "subject_type": "finding",
        "repo_full_name": "example-org/payments-api",
        "title": "libz overflow",
        "description": "A synthetic finding.",
        "severity": "high",
        "capability": "containers",
        "location": "libz",
        "oracle": None,
        "reachability": "unknown",
        "cve_id": CVE,
        "in_kev": None,
        "epss_score": None,
        "dedup_count": 0,
        "false_positive_note": None,
        "suggested_fix": "upgrade",
        "acceptance_criteria": ["gone on a re-scan"],
    }
    values.update(overrides)
    return TriageStory(**values)


def _row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "finding_id": "f-1",
        "repo_full_name": "example-org/payments-api",
        "capability": "containers",
        "rule_id": CVE,
        "severity": "high",
        "title": "libz overflow",
        "triage": "fix",
        "triage_rationale": "synthetic",
        "rank": 10,
        "first_seen_at": "2031-01-01T00:00:00",
        "in_kev": None,
        "epss_score": None,
        "state": {},
    }
    row.update(overrides)
    return row


def _evidence(row: dict[str, Any]) -> str:
    report = Briefing(generated_at=datetime(2031, 3, 12, tzinfo=UTC), total_open=1)
    items = agent_work._finding_items([row], report, AGENT)
    return items[0].evidence[0].detail


class TestTriageStoryThreatIntel:
    def test_no_match_row_is_not_checked_not_false(self, client: Any) -> None:
        with client.app.state.db.session() as session:
            assert _threat_intel_for(session, CVE) == (None, None)

    def test_a_fetched_unlisted_cve_is_false(self, client: Any) -> None:
        """Guard: a real row still reads False."""
        with client.app.state.db.session() as session:
            session.add(ThreatIntelMatch(cve_id=CVE, in_kev=False, epss_score=0.02))
        with client.app.state.db.session() as session:
            assert _threat_intel_for(session, CVE) == (False, 0.02)

    def test_the_issue_body_says_not_checked(self) -> None:
        body = _story(in_kev=None).render_issue_body()
        assert "KEV status not checked" in body
        assert "not KEV-listed" not in body

    def test_a_checked_cve_still_says_not_kev_listed(self) -> None:
        """Guard."""
        assert "not KEV-listed" in _story(in_kev=False).render_issue_body()


class TestAgentWorkEvidence:
    def test_an_unfetched_cve_is_kev_not_checked(self) -> None:
        detail = _evidence(_row(in_kev=None))
        assert "KEV not checked" in detail
        assert "KEV False" not in detail

    def test_a_checked_cve_reads_true_or_false(self) -> None:
        """Guard."""
        assert "KEV False" in _evidence(_row(in_kev=False))
        assert "KEV True" in _evidence(_row(in_kev=True))
