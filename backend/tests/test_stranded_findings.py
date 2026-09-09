"""Disabling a capability says what it did to the findings (B-047).

TheHub held 32 open `dast` findings with `dast` switched off, and the briefing
reported that lane silent for fifteen days. None of them could close by any
path the platform offered: closure needs two consecutive successful scans that
no longer observe the finding, and a capability that cannot upload will never
produce one. They were not open because anything was unfixed -- they were open
because the only mechanism that could close them had been removed.

The closure rule is right and is not relaxed here. What changes is that the
removal is recorded, and reversed when a scan can decide again.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from mykronos.api.dashboard import HUMAN_DISPOSITIONS
from mykronos.grants import restore_stranded, strand_findings
from mykronos.schemas import TERMINAL_STATUSES, FindingStatus
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard


def statuses(catalog, capability: str = "sast") -> list[str]:
    rows = catalog.query(
        "SELECT status FROM findings WHERE repo_full_name = ? AND capability = ?",
        [REPO, capability],
    )
    return sorted(str(row[0]) for row in rows)


def seed(client: TestClient, auth: dict[str, str], run_compaction, count: int = 2) -> None:
    post_scan(client, auth, scan_run_id="seed-1")
    post_findings(
        client,
        auth,
        [finding_payload(rule_id=f"CWE-{89 + i}", title=f"finding {i}") for i in range(count)],
        scan_run_id="seed-1",
    )
    run_compaction()


class TestTheStatusItself:
    def test_stranded_is_not_a_disposition_a_person_can_set(self) -> None:
        """It is a statement about the pipeline, not a judgement about the
        risk. A person marking a finding stranded by hand would be claiming
        something about a capability rather than about a vulnerability."""
        assert FindingStatus.STRANDED not in HUMAN_DISPOSITIONS

    def test_stranded_is_not_outstanding_work_and_not_a_resolution(self) -> None:
        """The same shape as `superseded`: nothing can act on it while the
        capability is off, and it is not a fix either."""
        assert FindingStatus.STRANDED in TERMINAL_STATUSES
        assert FindingStatus.STRANDED is not FindingStatus.FIXED


class TestStrandingAndRestoring:
    def test_open_findings_are_stranded_when_the_grant_goes(
        self, client, auth, catalog, run_compaction
    ) -> None:
        seed(client, auth, run_compaction)

        count = strand_findings(catalog, REPO, {"sast"})

        assert count == 2
        assert statuses(catalog) == ["stranded", "stranded"]

    def test_restoring_the_grant_reopens_them(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """Back to `open` rather than to `fixed`: nothing observed their
        absence, and the next two successful scans are what decide."""
        seed(client, auth, run_compaction)
        strand_findings(catalog, REPO, {"sast"})

        count = restore_stranded(catalog, REPO, {"sast"})

        assert count == 2
        assert statuses(catalog) == ["open", "open"]

    def test_a_finding_a_person_dispositioned_is_left_alone(
        self, client, auth, catalog, run_compaction, admin_auth
    ) -> None:
        """Stranding is about findings with no exit. One somebody has already
        judged has an exit, and overwriting that judgement would lose it."""
        seed(client, auth, run_compaction, count=1)
        finding_id = catalog.query(
            "SELECT finding_id FROM findings WHERE repo_full_name = ?", [REPO]
        )[0][0]
        client.patch(
            f"/api/dashboard/findings/{finding_id}/status",
            json={"status": "false_positive"},
            headers=admin_auth,
        )

        assert strand_findings(catalog, REPO, {"sast"}) == 0
        assert statuses(catalog) == ["false_positive"]

    def test_another_capability_is_untouched(
        self, client, auth, catalog, run_compaction
    ) -> None:
        seed(client, auth, run_compaction)

        assert strand_findings(catalog, REPO, {"dast"}) == 0
        assert statuses(catalog) == ["open", "open"]

    def test_nothing_to_strand_is_not_an_error(self, catalog) -> None:
        assert strand_findings(catalog, REPO, {"sast"}) == 0
        assert restore_stranded(catalog, REPO, {"sast"}) == 0

    def test_no_capabilities_touches_nothing(
        self, client, auth, catalog, run_compaction
    ) -> None:
        seed(client, auth, run_compaction)

        assert strand_findings(catalog, REPO, set()) == 0
        assert statuses(catalog) == ["open", "open"]


class TestThroughTheApi:
    def _onboard_with(self, client, admin_auth, capabilities: list[str]) -> str:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": capabilities, "install_workflows": False},
            headers=admin_auth,
        )
        return str(repo_id)

    def test_disabling_a_capability_strands_and_says_so(
        self, client, auth, admin_auth, catalog, run_compaction
    ) -> None:
        """The 2026-09-03 shape, end to end: a capability switched off while
        it held open findings."""
        repo_id = self._onboard_with(client, admin_auth, ["sast", "dast"])
        seed(client, auth, run_compaction)

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["dast"], "install_workflows": False},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert "2 open finding(s) can no longer be closed" in response.json()["detail"]
        assert statuses(catalog) == ["stranded", "stranded"]

    def test_re_enabling_it_reopens_them_and_says_so(
        self, client, auth, admin_auth, catalog, run_compaction
    ) -> None:
        repo_id = self._onboard_with(client, admin_auth, ["sast", "dast"])
        seed(client, auth, run_compaction)
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["dast"], "install_workflows": False},
            headers=admin_auth,
        )

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "dast"], "install_workflows": False},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert "2 stranded finding(s) are open again" in response.json()["detail"]
        assert statuses(catalog) == ["open", "open"]

    def test_an_ordinary_change_says_nothing_about_findings(
        self, client, admin_auth
    ) -> None:
        """A sentence reporting "0 findings stranded" on every capability
        change is what gets the message skipped on the day it is not zero."""
        repo_id = self._onboard_with(client, admin_auth, ["sast"])

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "iac"], "install_workflows": False},
            headers=admin_auth,
        )

        assert "finding(s)" not in response.json()["detail"]

    def test_the_audit_records_the_counts(
        self, client, auth, admin_auth, catalog, run_compaction
    ) -> None:
        from sqlalchemy import select

        from mykronos.db.models import AuditLogEntry

        repo_id = self._onboard_with(client, admin_auth, ["sast", "dast"])
        seed(client, auth, run_compaction)
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["dast"], "install_workflows": False},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:
            entry = (
                session.execute(
                    select(AuditLogEntry)
                    .where(AuditLogEntry.action == "repo.capabilities")
                    .order_by(AuditLogEntry.created_at.desc())
                )
                .scalars()
                .first()
            )

        assert entry is not None
        assert entry.detail["findings_stranded"] == 2
        assert entry.detail["findings_restored"] == 0
