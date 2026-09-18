"""A Debian placeholder becoming a CVE must not silently re-ask the question (#280).

**Observed 2026-09-11, twice.** A Trivy database update between two container
scans retired four `TEMP-*` findings on `libpcre2-8-0` `10.46-1~deb13u1` — each
one accepted, with a written reason and a review date — and opened six
`CVE-2026-891xx` findings for the same package at the same version, on an image
that had not changed. Nothing linked the two sets, so the `apt-cache policy`
investigation behind the acceptance was done a second time and reached the same
conclusion.

These tests pin both halves of the fix, and the second half is the important
one:

- the new row **names** the decision already recorded under the retired
  identifier, so nobody re-investigates without being told they have already
  decided;
- the new row is still **open**. Four placeholders became *six* CVEs. There is
  no pairing to infer, and carrying an acceptance onto a vulnerability nobody
  has looked at would suppress real findings — the direction spec 04 §6
  refuses.

The noise boundary is pinned too. "Any prior acceptance on the same package and
version" would fire for genuinely distinct CVEs in the same OS package, which
is the common case; only an identifier that is *by construction* provisional
counts as evidence.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos.prior_disposition import is_provisional_advisory
from mykronos.schemas import utcnow
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

PLACEHOLDER = "TEMP-0000000-B05303"
ASSIGNED = "CVE-2026-89156"
PACKAGE = "libpcre2-8-0"
VERSION = "10.46-1~deb13u1"


def container_finding(rule_id: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": rule_id,
        "title": f"{PACKAGE}: {rule_id}",
        "severity": "high",
        "package_name": PACKAGE,
        "package_version": VERSION,
    }
    payload.update(overrides)
    return payload


def containers_scan(
    client: TestClient, run_id: str, findings: list[dict[str, Any]]
) -> None:
    token = issue_token(client, REPO, "containers")
    auth = {"Authorization": f"Bearer {token}"}
    post_scan(
        client,
        auth,
        scan_run_id=run_id,
        capability="containers",
        tool_name="trivy",
        branch="main",
    )
    post_findings(client, auth, findings, scan_run_id=run_id, capability="containers")


def accept(
    client: TestClient, admin_auth: dict[str, str], finding_id: str, **overrides: Any
) -> Any:
    body: dict[str, Any] = {
        "status": "accepted_risk",
        "reason": "apt-cache policy: Installed == Candidate, nothing upgradable",
        "accepted_reason_code": "no_vendor_fix",
        "accepted_until": (utcnow().date() + timedelta(days=80)).isoformat(),
    }
    body.update(overrides)
    response = client.patch(
        f"/api/dashboard/findings/{finding_id}/status", json=body, headers=admin_auth
    )
    assert response.status_code == 200, response.text
    return response


def finding_id_for(
    client: TestClient, admin_auth: dict[str, str], repo_id: str, rule_id: str
) -> str:
    listed = client.get(
        f"/api/dashboard/repos/{repo_id}/findings",
        params={"rule_id": rule_id},
        headers=admin_auth,
    ).json()["findings"]
    assert listed, f"no finding for {rule_id}"
    return str(listed[0]["finding_id"])


def group_for(
    client: TestClient, admin_auth: dict[str, str], repo_id: str, rule_id: str
) -> dict[str, Any]:
    page = client.get(
        f"/api/dashboard/repos/{repo_id}/open-findings", headers=admin_auth
    ).json()
    groups = [g for g in page["groups"] if g["rule_id"] == rule_id]
    assert groups, f"no open group for {rule_id}"
    return dict(groups[0])


@pytest.fixture
def renamed(client: TestClient, admin_auth: dict[str, str], run_compaction) -> str:
    """The estate as it stood at 21:11 on 2026-09-11.

    A placeholder finding, accepted by a person; then the advisory database
    assigns a CVE and the next scan reports the same package at the same
    version under the new name and stops reporting the old one.
    """
    repo_id = onboard(client, admin_auth).json()["id"]

    containers_scan(client, "run-1", [container_finding(PLACEHOLDER)])
    run_compaction()
    accept(client, admin_auth, finding_id_for(client, admin_auth, repo_id, PLACEHOLDER))

    containers_scan(client, "run-2", [container_finding(ASSIGNED)])
    run_compaction()
    return str(repo_id)


class TestTheRenamedFindingNamesTheDecisionItIsReAsking:
    def test_the_new_row_carries_the_prior_acceptance(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        """The whole defect, at its smallest: the new row arrived with no sign
        that the identical question had been answered ten days earlier."""
        group = group_for(client, admin_auth, renamed, ASSIGNED)

        prior = group["prior_disposition"]
        assert prior is not None
        assert prior["rule_id"] == PLACEHOLDER
        assert prior["status"] == "accepted_risk"
        assert prior["package_name"] == PACKAGE
        assert prior["package_version"] == VERSION

    def test_it_carries_the_reason_and_the_review_date(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        """An operator should be able to confirm in a second rather than
        re-running `apt-cache policy` inside a container."""
        prior = group_for(client, admin_auth, renamed, ASSIGNED)["prior_disposition"]

        assert prior["accepted_reason_code"] == "no_vendor_fix"
        assert prior["accepted_until"] is not None
        assert PLACEHOLDER in prior["summary"]
        assert "no_vendor_fix" in prior["summary"]

    def test_the_finding_record_carries_it_too(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        """B-032's page is where somebody decides about a single finding, so it
        is where the earlier decision has to be visible."""
        finding_id = finding_id_for(client, admin_auth, renamed, ASSIGNED)

        body = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()

        assert body["prior_disposition"]["rule_id"] == PLACEHOLDER


class TestTheDecisionIsNotMoved:
    """Flagging, not deciding.

    Four placeholders became six CVEs on the real incident. Nothing can pair
    them, and an acceptance applied to a vulnerability nobody has read would be
    a silent suppression — worse than the churn it would hide.
    """

    def test_the_renamed_finding_is_still_open(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        listed = client.get(
            f"/api/dashboard/repos/{renamed}/findings",
            params={"rule_id": ASSIGNED},
            headers=admin_auth,
        ).json()["findings"]

        assert [f["status"] for f in listed] == ["open"]

    def test_the_accepted_row_keeps_its_disposition(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        """The precedent is read, never consumed. Nothing retires the row the
        decision is recorded on."""
        listed = client.get(
            f"/api/dashboard/repos/{renamed}/findings",
            params={"rule_id": PLACEHOLDER},
            headers=admin_auth,
        ).json()["findings"]

        assert [f["status"] for f in listed] == ["accepted_risk"]
        assert listed[0]["superseded_by"] is None


class TestWhatIsNotEvidence:
    def test_a_different_version_is_a_different_decision(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """"Accepted for 10.46-1~deb13u1" says nothing about 10.47. Matching
        without the version would show an acceptance against a package that
        had since been upgraded."""
        repo_id = onboard(client, admin_auth).json()["id"]
        containers_scan(client, "run-1", [container_finding(PLACEHOLDER)])
        run_compaction()
        accept(client, admin_auth, finding_id_for(client, admin_auth, repo_id, PLACEHOLDER))

        containers_scan(
            client, "run-2", [container_finding(ASSIGNED, package_version="10.47-1")]
        )
        run_compaction()

        assert group_for(client, admin_auth, repo_id, ASSIGNED)["prior_disposition"] is None

    def test_an_acceptance_under_a_real_cve_is_not_a_rename(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """The noise boundary. An OS package routinely holds several unrelated
        CVEs at one version; reporting one as precedent for another would bury
        the signal this exists to raise."""
        repo_id = onboard(client, admin_auth).json()["id"]
        containers_scan(client, "run-1", [container_finding("CVE-2025-11111")])
        run_compaction()
        accept(
            client, admin_auth, finding_id_for(client, admin_auth, repo_id, "CVE-2025-11111")
        )

        containers_scan(client, "run-2", [container_finding(ASSIGNED)])
        run_compaction()

        assert group_for(client, admin_auth, repo_id, ASSIGNED)["prior_disposition"] is None

    def test_an_undecided_placeholder_is_not_precedent(
        self, client: TestClient, admin_auth: dict[str, str], run_compaction
    ) -> None:
        """A placeholder nobody ever triaged carries no decision, so there is
        nothing to re-ask and nothing to report."""
        repo_id = onboard(client, admin_auth).json()["id"]
        containers_scan(client, "run-1", [container_finding(PLACEHOLDER)])
        run_compaction()

        containers_scan(client, "run-2", [container_finding(ASSIGNED)])
        run_compaction()

        assert group_for(client, admin_auth, repo_id, ASSIGNED)["prior_disposition"] is None

    def test_an_ordinary_finding_reports_nothing(
        self, client: TestClient, admin_auth: dict[str, str], renamed: str
    ) -> None:
        """Null is the overwhelming majority, and has to stay that way for the
        flag to mean anything when it appears."""
        page = client.get(
            f"/api/dashboard/repos/{renamed}/open-findings", headers=admin_auth
        ).json()

        assert all(
            group["prior_disposition"] is None
            for group in page["groups"]
            if group["rule_id"] != ASSIGNED
        )


class TestWhichIdentifiersAreProvisional:
    @pytest.mark.parametrize(
        "rule_id",
        ["TEMP-0000000-B05303", "TEMP-0000000-21C4F8", "TEMP-1234567-ABCDEF"],
    )
    def test_debians_placeholder_form(self, rule_id: str) -> None:
        assert is_provisional_advisory(rule_id) is True

    @pytest.mark.parametrize(
        "rule_id",
        [
            "CVE-2026-89156",
            "GHSA-xxxx-yyyy-zzzz",
            # A rule a tool happens to name this way is not a placeholder, and
            # reading it as one would report precedent about SAST findings.
            "TEMPLATE-INJECTION",
            "TEMP-INJECTION",
            "",
            None,
        ],
    )
    def test_everything_else(self, rule_id: str | None) -> None:
        assert is_provisional_advisory(rule_id) is False
