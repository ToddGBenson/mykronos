"""Which vector "severity here" is computed from, and saying so (TheHub #60824).

The finding record scored only NVD's v3 vector. A CVE NVD scored only in v4.0,
or a finding whose scanner published a vector NVD never did, showed no
severity block at all -- the same as a Semgrep pattern that has no CVSS by
nature. Now the record says which vector it used, where it came from, and,
when only v4.0 exists, shows it without rescoring it (D1).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.db.models import ThreatIntelMatch
from tests.conftest import (
    CAPABILITY,
    REPO,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
)
from tests.test_onboarding import onboard

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVE = "CVE-2025-12345"


@pytest.fixture
def seed(client: TestClient, admin_auth: dict[str, str], run_compaction):
    """Returns a function seeding one CVE finding and returning its id."""
    repo_id = onboard(client, admin_auth).json()["id"]
    client.patch(
        f"/api/repos/{repo_id}/capabilities",
        json={"capabilities": [CAPABILITY]},
        headers=admin_auth,
    )
    token = issue_token(client, REPO, CAPABILITY)
    auth = {"Authorization": f"Bearer {token}"}

    def _seed(
        *,
        match: ThreatIntelMatch | None = None,
        advisory: list[dict[str, Any]] | None = None,
        rule_id: str = CVE,
    ) -> str:
        if match is not None:
            with client.app.state.db.session() as session:
                session.add(match)
        raw: dict[str, Any] = {"ruleId": rule_id, "level": "error"}
        if advisory is not None:
            raw["cvss_vectors"] = advisory
        post_scan(client, auth, scan_run_id="run-1")
        post_findings(
            client,
            auth,
            [finding_payload(rule_id=rule_id, title=f"{rule_id} in x", raw_finding_json=raw)],
            scan_run_id="run-1",
        )
        run_compaction()
        listed = client.get(
            f"/api/dashboard/repos/{repo_id}/findings", headers=admin_auth
        ).json()["findings"]
        return str(listed[0]["finding_id"])

    return _seed


def _here(client: TestClient, auth: dict[str, str], finding_id: str) -> dict[str, Any] | None:
    response = client.get(f"/api/dashboard/findings/{finding_id}/record", headers=auth)
    assert response.status_code == 200, response.text
    return response.json()["severity_here"]


class TestTheVectorIsNamed:
    def test_nvd_v31_is_rescored_and_says_so(self, client, admin_auth, seed) -> None:
        finding_id = seed(match=ThreatIntelMatch(cve_id=CVE, cvss_vector=V31))

        here = _here(client, admin_auth, finding_id)

        assert here is not None
        assert here["vector"] == V31
        assert here["vector_source"] == "nvd"
        assert here["vector_version"] == "3.1"
        assert here["rescored"] is True
        assert here["base"] == 9.8

    def test_nvd_v3_beats_the_advisory(self, client, admin_auth, seed) -> None:
        finding_id = seed(
            match=ThreatIntelMatch(cve_id=CVE, cvss_vector=V30),
            advisory=[{"version": "3.1", "vector": V31, "source": "trivy"}],
        )

        here = _here(client, admin_auth, finding_id)

        assert here is not None
        assert (here["vector"], here["vector_source"]) == (V30, "nvd")

    def test_an_advisory_v31_is_used_when_nvd_has_none(
        self, client, admin_auth, seed
    ) -> None:
        finding_id = seed(
            match=ThreatIntelMatch(cve_id=CVE, cvss_v4_vector=V40),
            advisory=[{"version": "3.1", "vector": V31, "source": "trivy"}],
        )

        here = _here(client, admin_auth, finding_id)

        assert here is not None
        assert here["vector"] == V31
        assert here["vector_source"] == "advisory"
        assert here["rescored"] is True

    def test_a_viewer_gets_the_advisory_vector_too(
        self, client, admin_auth, viewer_auth, seed
    ) -> None:
        """The raw record is admin-only (spec 12 §5); the vectors inside it are
        public advisory data. Withholding the raw record must not quietly
        change a viewer's severity block."""
        finding_id = seed(advisory=[{"version": "3.1", "vector": V31, "source": "trivy"}])

        here = _here(client, viewer_auth, finding_id)

        assert here is not None and here["vector_source"] == "advisory"

    def test_a_finding_with_no_cve_can_still_use_its_advisory(
        self, client, admin_auth, seed
    ) -> None:
        """A GHSA-keyed match has no CVE to look up in NVD, but Trivy may still
        have published a vector for it."""
        finding_id = seed(
            rule_id="GHSA-6757-jp84-gxfx",
            advisory=[{"version": "3.1", "vector": V31, "source": "trivy"}],
        )

        here = _here(client, admin_auth, finding_id)

        assert here is not None and here["vector"] == V31


class TestV4IsShownNotRescored:
    def test_nvd_v4_only(self, client, admin_auth, seed) -> None:
        finding_id = seed(
            match=ThreatIntelMatch(cve_id=CVE, cvss_v4_vector=V40, cvss_v4_base_score=9.3)
        )

        here = _here(client, admin_auth, finding_id)

        assert here is not None
        assert here["vector"] == V40
        assert here["vector_version"] == "4.0"
        assert here["vector_source"] == "nvd"
        assert here["rescored"] is False
        assert here["base"] == 9.3
        # Not computed, and not copied from base: an equal pair would read as
        # "nothing about this system moves it", which nobody worked out.
        assert here["environmental"] is None
        assert here["moved"] is False

    def test_an_advisory_v4_without_a_published_score(
        self, client, admin_auth, seed
    ) -> None:
        finding_id = seed(advisory=[{"version": "4.0", "vector": V40, "source": "trivy"}])

        here = _here(client, admin_auth, finding_id)

        assert here is not None
        assert here["rescored"] is False
        assert here["base"] is None
        assert here["vector_source"] == "advisory"


class TestNothingIsStillNothing:
    def test_no_vector_anywhere_is_absent(self, client, admin_auth, seed) -> None:
        finding_id = seed(match=ThreatIntelMatch(cve_id=CVE))

        assert _here(client, admin_auth, finding_id) is None
