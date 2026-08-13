"""Re-scoring archived supply-chain evidence (spec 07 §5a).

The scorer changed, and twenty rows on the live lake still asserted the old
answer: a perfect 100 for scans that resolved no dependencies. A fix that only
applies to future scans leaves the dashboard reporting the bug.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from mykronos.rescore_sscs import rescore_sscs
from tests.conftest import REPO, issue_token
from tests.test_atlas import post
from tests.test_onboarding import onboard


@pytest.fixture
def atlas_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'atlas')}"}


def _rows(catalog):
    return catalog.query("SELECT trust_score, raw_trust_score, ecosystems_json FROM sscs_evidence")


def _stale_hundred(catalog, buffer, run_compaction, client, admin_auth, atlas_auth):
    """An evidence row exactly as the old scorer wrote it."""
    onboard(client, admin_auth)
    post(client, atlas_auth, ecosystems=[{"ecosystem": "npm", "dependency_count": 0}])
    run_compaction()

    # The current code writes null, so the pre-fix row has to be reinstated to
    # have anything to correct. Same evidence_id, so compaction updates it.
    names = [
        "evidence_id",
        "repo_full_name",
        "commit_sha",
        "trust_score",
        "raw_trust_score",
        "ecosystems_json",
        "evaluated_at",
    ]
    row = dict(
        zip(
            names,
            catalog.query(f"SELECT {', '.join(names)} FROM sscs_evidence")[0],
            strict=True,
        )
    )
    row["trust_score"] = 100
    row["raw_trust_score"] = 100.0
    buffer.append("sscs_evidence", [row])
    run_compaction()
    assert _rows(catalog)[0][0] == 100


class TestRescoring:
    def test_an_unearned_100_becomes_null(
        self, client, admin_auth, atlas_auth, run_compaction, catalog, buffer
    ) -> None:
        _stale_hundred(catalog, buffer, run_compaction, client, admin_auth, atlas_auth)

        result = rescore_sscs(catalog, buffer)
        run_compaction()

        assert result.wrote == 1
        assert result.changed[0].was == 100
        assert result.changed[0].now is None
        assert _rows(catalog)[0][:2] == (None, None)

    def test_the_reason_is_written_back_too(
        self, client, admin_auth, atlas_auth, run_compaction, catalog, buffer
    ) -> None:
        """A null score with no `not_assessed` term renders as a blank tile."""
        _stale_hundred(catalog, buffer, run_compaction, client, admin_auth, atlas_auth)

        rescore_sscs(catalog, buffer)
        run_compaction()

        detail = json.loads(_rows(catalog)[0][2])
        assert [t["key"] for t in detail["score_terms"]] == ["not_assessed"]

    def test_a_dry_run_writes_nothing(
        self, client, admin_auth, atlas_auth, run_compaction, catalog, buffer
    ) -> None:
        _stale_hundred(catalog, buffer, run_compaction, client, admin_auth, atlas_auth)

        result = rescore_sscs(catalog, buffer, dry_run=True)
        run_compaction()

        assert result.wrote == 1
        assert _rows(catalog)[0][0] == 100

    def test_a_correct_row_is_left_alone(
        self, client, admin_auth, atlas_auth, run_compaction, catalog, buffer
    ) -> None:
        """Only changed rows are written, so re-running is a no-op rather than
        a rewrite of every partition the evidence touches."""
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()

        result = rescore_sscs(catalog, buffer)

        assert result.examined == 1
        assert result.wrote == 0

    def test_a_row_with_no_counts_is_reported_not_guessed(
        self, client, admin_auth, atlas_auth, run_compaction, catalog, buffer
    ) -> None:
        """The inputs are gone, so the score cannot be re-derived. Saying so
        beats writing a number no evidence supports."""
        onboard(client, admin_auth)
        post(client, atlas_auth)
        run_compaction()

        names = ["evidence_id", "repo_full_name", "commit_sha", "trust_score"]
        row = dict(
            zip(
                names,
                catalog.query(f"SELECT {', '.join(names)} FROM sscs_evidence")[0],
                strict=True,
            )
        )
        row["ecosystems_json"] = None
        buffer.append("sscs_evidence", [row])
        run_compaction()

        result = rescore_sscs(catalog, buffer)

        assert result.wrote == 0
        assert len(result.unscoreable) == 1
