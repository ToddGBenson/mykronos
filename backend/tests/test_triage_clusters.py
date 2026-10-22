"""Clusters: one decision covering the findings it is about (TheHub #60887).

The rules are pure functions of a row, so most of them are pinned without an
app. The API tests pin the properties that matter to somebody deciding: a
cluster's id survives a rescan, the filters never trim the group a decision
covers, every member gets its own audit entry, and an agent's verdict on a
cluster holding a serious finding raises one approval request, not one per
member.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from mykronos import clusters
from mykronos.db.models import ApprovalRequest, AuditLogEntry, RepoOnboarding
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

OTHER = "example-org/ledger"
REASON = (
    "The vulnerable decoder is never reached: the image ships the library for a CLI "
    "that is not installed, confirmed against the package manifest."
)


def row(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "finding_id": fields.pop("finding_id", uuid.uuid4().hex),
        "repo_full_name": REPO,
        "capability": "containers",
        "rule_id": "CVE-2026-1000",
        "title": "",
        "severity": "high",
        "first_seen_at": datetime(2026, 10, 1),
    }
    base.update(fields)
    return base


# --------------------------------------------------------------------------
# The rules, without an app
# --------------------------------------------------------------------------


class TestAdvisoryRule:
    def test_one_cve_across_images_and_repositories_is_one_cluster(self) -> None:
        rows = [
            row(package_name="openssl", image="registry.lan:5000/app:abc"),
            row(package_name="openssl", image="registry.lan:5000/worker:abc"),
            row(package_name="OpenSSL", repo_full_name=OTHER, image="postgres:16"),
        ]

        [cluster] = clusters.build(rows)

        assert cluster.kind == clusters.ADVISORY
        assert len(cluster.members) == 3
        assert cluster.repos == sorted([REPO, OTHER])
        assert cluster.images == ["app", "library/postgres", "worker"]
        assert "CVE-2026-1000" in cluster.reason and "openssl" in cluster.reason
        assert "2 repositories and 3 images" in cluster.reason

    def test_a_ghsa_naming_a_cve_meets_the_cve(self) -> None:
        rows = [
            row(package_name="urllib3", capability="atlas", rule_id="GHSA-xxxx-yyyy",
                title="urllib3: CVE-2026-1000 redirect flaw"),
            row(package_name="urllib3"),
        ]

        assert len(clusters.build(rows)) == 1

    def test_the_same_cve_in_two_packages_is_two_decisions(self) -> None:
        rows = [row(package_name="openssl"), row(package_name="libssl3")]

        assert len(clusters.build(rows)) == 2


class TestLocationRule:
    def test_two_scanners_on_one_cwe_at_one_symbol_are_one_cluster(self) -> None:
        rows = [
            row(capability="sast", rule_id="py/sql-injection", file_path="orders/query.py",
                symbol="get_order", line_start=10, cwe_ids_json='["CWE-89"]'),
            row(capability="semgrep", rule_id="formatted-sql-query",
                file_path="./orders/query.py", symbol="get_order", line_start=11,
                cwe_ids_json='["cwe-89"]', severity="medium"),
        ]

        [cluster] = clusters.build(rows)

        assert cluster.kind == clusters.LOCATION
        assert "CWE-89" in cluster.reason and "orders/query.py" in cluster.reason
        assert "semgrep" in cluster.reason and "sast" in cluster.reason

    def test_a_different_symbol_is_a_different_cluster(self) -> None:
        rows = [
            row(capability="sast", rule_id="R1", file_path="a.py", symbol="one"),
            row(capability="sast", rule_id="R1", file_path="a.py", symbol="two"),
        ]

        assert len(clusters.build(rows)) == 2

    def test_without_a_symbol_the_line_is_the_location(self) -> None:
        rows = [
            row(capability="sast", rule_id="R1", file_path="a\\b.py", line_start=4),
            row(capability="iac", rule_id="R1", file_path="/a/b.py", line_start=4),
            row(capability="iac", rule_id="R1", file_path="a/b.py", line_start=9),
        ]

        sizes = sorted(len(c.members) for c in clusters.build(rows))

        assert sizes == [1, 2]

    def test_the_same_location_in_two_repositories_is_two_clusters(self) -> None:
        rows = [
            row(capability="sast", rule_id="R1", file_path="a.py", symbol="f"),
            row(capability="sast", rule_id="R1", file_path="a.py", symbol="f",
                repo_full_name=OTHER),
        ]

        assert len(clusters.build(rows)) == 2


class TestProvisionalFold:
    def test_a_placeholder_folds_into_the_only_cve_on_its_package(self) -> None:
        temp = row(rule_id="TEMP-0000000-B05303", package_name="libpcre2-8-0",
                   package_version="10.46-1", severity="low")
        cve = row(rule_id="CVE-2026-89101", package_name="libpcre2-8-0",
                  package_version="10.46-1")

        [cluster] = clusters.build([temp, cve])

        assert set(cluster.member_ids) == {temp["finding_id"], cve["finding_id"]}
        assert temp["finding_id"] in cluster.folded
        assert "TEMP-0000000-B05303" in cluster.reason
        assert cluster.cluster_id == clusters.key_for(cve).cluster_id

    def test_with_two_cves_open_there_is_nothing_to_infer(self) -> None:
        """Four placeholders became six CVEs on 2026-09-11 (`prior_disposition`)."""
        temp = row(rule_id="TEMP-0000000-B05303", package_name="libpcre2-8-0",
                   package_version="10.46-1")
        rows = [
            temp,
            row(rule_id="CVE-2026-89101", package_name="libpcre2-8-0", package_version="10.46-1"),
            row(rule_id="CVE-2026-89102", package_name="libpcre2-8-0", package_version="10.46-1"),
        ]

        built = clusters.build(rows)
        home = next(c for c in built if temp["finding_id"] in c.member_ids)

        assert len(built) == 3
        assert home.member_ids == [temp["finding_id"]]
        assert "not folded" in home.reason

    def test_a_different_version_does_not_fold(self) -> None:
        rows = [
            row(rule_id="TEMP-0000000-B05303", package_name="p", package_version="1"),
            row(rule_id="CVE-2026-89101", package_name="p", package_version="2"),
        ]

        assert len(clusters.build(rows)) == 2


class TestIdentity:
    def test_the_id_is_the_key_not_the_members(self) -> None:
        one = row(package_name="openssl", image="app")
        two = row(package_name="openssl", image="worker")

        alone = clusters.build([one])[0].cluster_id
        joined = clusters.build([one, two])[0].cluster_id
        left = clusters.build([two])[0].cluster_id

        assert alone == joined == left

    def test_a_finding_with_neither_package_nor_file_is_a_cluster_of_one(self) -> None:
        lone = row(capability="cloud", rule_id="S3-1")

        [cluster] = clusters.build([lone])

        assert cluster.kind == clusters.SINGLE
        assert cluster.member_ids == [lone["finding_id"]]
        assert "No other open finding" in cluster.reason

    def test_the_representative_is_worst_then_oldest(self) -> None:
        old_medium = row(package_name="p", severity="medium", first_seen_at=datetime(2026, 1, 1))
        new_high = row(package_name="p", severity="high", first_seen_at=datetime(2026, 9, 1))
        old_high = row(package_name="p", severity="high", first_seen_at=datetime(2026, 5, 1))

        [cluster] = clusters.build([old_medium, new_high, old_high])

        assert cluster.representative["finding_id"] == old_high["finding_id"]
        assert cluster.max_severity == "high"


# --------------------------------------------------------------------------
# Through the API
# --------------------------------------------------------------------------


def activate(client: TestClient, admin_auth: dict[str, str], repo: str) -> dict[str, str]:
    onboard(client, admin_auth, repo)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        record = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == repo)
        ).scalars().one()
        record.status = "active"
    token = issue_token(client, repo, "sast", "containers")
    return {"Authorization": f"Bearer {token}"}


def ingest(
    client: TestClient, auth: dict[str, str], repo: str, findings: list[dict[str, Any]],
    capability: str = "containers",
) -> None:
    run = str(uuid.uuid4())
    response = post_scan(
        client, auth, scan_run_id=run, repo_full_name=repo, capability=capability,
        tool_name="trivy" if capability == "containers" else "codeql",
        finding_count=len(findings),
    )
    assert response.status_code in (200, 201), response.text
    response = post_findings(client, auth, findings, scan_run_id=run, capability=capability)
    assert response.status_code in (200, 201), response.text


def container(image: str, severity: str = "high", **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "rule_id": "CVE-2026-1000",
        "title": "openssl: buffer overread",
        "severity": severity,
        "package_name": "openssl",
        "package_version": "3.0.1",
        "raw_finding_json": {"image": image},
    }
    payload.update(extra)
    return payload


def grouped(client: TestClient, headers: dict[str, str], **params: Any) -> dict[str, Any]:
    response = client.get("/api/dashboard/triage/clusters", params=params, headers=headers)
    assert response.status_code == 200, response.text
    return dict(response.json())


def statuses(client: TestClient) -> dict[str, str]:
    rows = client.app.state.catalog.query(  # type: ignore[attr-defined]
        "SELECT finding_id, status FROM findings"
    )
    return {str(r[0]): str(r[1]) for r in rows}


def seed_cluster(client, admin_auth, run_compaction, severities=("high", "medium")) -> str:
    auth = activate(client, admin_auth, REPO)
    other = activate(client, admin_auth, OTHER)
    ingest(client, auth, REPO, [
        container(f"app-{i}:sha", severity=s) for i, s in enumerate(severities)
    ])
    ingest(client, other, OTHER, [container("ledger:sha", severity="medium")])
    run_compaction()
    [cluster] = grouped(client, admin_auth)["clusters"]
    return str(cluster["cluster_id"])


def _agent(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    response = client.post(
        "/api/agents/credentials", json={"family": "claude-opus-5.5"}, headers=admin_auth
    )
    assert response.status_code == 201, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


class TestTheGroupedQueue:
    def test_one_cve_in_three_images_and_two_repos_is_one_row(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        seed_cluster(client, admin_auth, run_compaction)

        body = grouped(client, admin_auth)

        assert body["total_clusters"] == 1 and body["total_findings"] == 3
        [cluster] = body["clusters"]
        assert cluster["kind"] == "advisory" and cluster["count"] == 3
        assert cluster["max_severity"] == "high"
        assert cluster["representative"]["severity"] == "high"
        assert sorted(cluster["repos"]) == sorted([REPO, OTHER])
        assert len(cluster["members"]) == 3
        assert "CVE-2026-1000" in cluster["reason"]

    def test_a_filter_chooses_clusters_and_never_trims_members(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        """A person filtering to `high` must still see the mediums the
        disposition beside the cluster would close."""
        seed_cluster(client, admin_auth, run_compaction)

        [cluster] = grouped(client, admin_auth, severity="high")["clusters"]
        assert cluster["count"] == 3

        assert grouped(client, admin_auth, severity="critical")["clusters"] == []

    def test_the_id_survives_a_rescan_that_moves_lines_and_adds_an_image(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth, REPO)
        ingest(client, auth, REPO, [
            {"rule_id": "CWE-89", "title": "SQLi", "severity": "high",
             "file_path": "orders/query.py", "line_start": 10, "symbol": "get_order",
             "code_snippet": "cursor.execute(q + order_id)"},
            container("app:one"),
        ], capability="containers")
        run_compaction()
        before = {c["kind"]: c["cluster_id"] for c in grouped(client, admin_auth)["clusters"]}

        ingest(client, auth, REPO, [
            {"rule_id": "CWE-89", "title": "SQLi", "severity": "high",
             "file_path": "orders/query.py", "line_start": 42, "symbol": "get_order",
             "code_snippet": "cursor.execute(q + order_id)"},
            container("app:two"),
            container("worker:two"),
        ], capability="containers")
        run_compaction()
        after = {c["kind"]: c for c in grouped(client, admin_auth)["clusters"]}

        assert after["location"]["cluster_id"] == before["location"]
        assert after["advisory"]["cluster_id"] == before["advisory"]
        assert after["advisory"]["count"] == 2  # app (same image repository) + worker


class TestClusterDisposition:
    def test_a_person_closes_every_member_with_an_audit_row_each(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": REASON},
            headers=admin_auth,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "applied" and len(body["applied"]) == 3
        run_compaction()
        assert set(statuses(client).values()) == {"false_positive"}
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            entries = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "finding.status")
            ).scalars().all()
            assert {e.entity_id for e in entries} == set(body["applied"])
            assert all(e.detail["cluster_id"] == cluster_id for e in entries)
            assert all(e.detail["reason"] == REASON for e in entries)
            summary = session.execute(
                select(AuditLogEntry).where(
                    AuditLogEntry.action == "triage.cluster_disposition"
                )
            ).scalar_one()
            assert summary.entity_id == cluster_id

    def test_a_stale_view_of_the_members_is_refused(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": REASON, "member_ids": ["only-one"]},
            headers=admin_auth,
        )

        assert response.status_code == 409
        assert set(statuses(client).values()) == {"open"}

    def test_a_viewer_cannot(self, client: TestClient, admin_auth, viewer_auth, run_compaction):
        cluster_id = seed_cluster(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": REASON},
            headers=viewer_auth,
        )

        assert response.status_code == 403

    def test_an_unknown_cluster_is_404(self, client: TestClient, admin_auth, run_compaction):
        seed_cluster(client, admin_auth, run_compaction)

        response = client.post(
            "/api/dashboard/triage/clusters/cl_nope/disposition",
            json={"status": "false_positive", "reason": REASON},
            headers=admin_auth,
        )

        assert response.status_code == 404


class TestTheApprovalRule:
    def test_an_agent_on_a_cluster_with_a_high_raises_one_request(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(client, admin_auth, run_compaction)
        agent = _agent(client, admin_auth)

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": REASON},
            headers=agent,
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["outcome"] == "pending_approval" and body["tier"] == "high"
        assert set(statuses(client).values()) == {"open"}, "nothing applies before approval"
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            count = session.execute(select(func.count()).select_from(ApprovalRequest)).scalar()
            assert count == 1, "one decision, one request - not one per member"
            request_row = session.get(ApprovalRequest, body["approval_request_id"])
            assert request_row is not None
            assert request_row.subject_ref == cluster_id
            assert len(request_row.evidence["findings"]) == 3
            digest = request_row.evidence_digest

        decided = client.post(
            f"/api/approvals/{body['approval_request_id']}/decisions",
            json={
                "verdict": "approve",
                "rationale": "Checked every member's raw record against the agent's reason.",
                "evidence_digest": digest,
            },
            headers=admin_auth,
        )
        assert decided.status_code in (200, 201), decided.text
        run_compaction()

        assert set(statuses(client).values()) == {"false_positive"}
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            entries = session.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "finding.status")
            ).scalars().all()
            assert len(entries) == 3
            assert all(e.detail["approval_request_id"] == body["approval_request_id"]
                       for e in entries)
            assert all(e.detail["cluster_id"] == cluster_id for e in entries)

    def test_a_critical_member_sets_the_tier(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(
            client, admin_auth, run_compaction, severities=("critical", "low")
        )

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "suppressed", "reason": REASON},
            headers=_agent(client, admin_auth),
        )

        assert response.json()["tier"] == "critical"

    def test_an_agent_accepting_a_serious_cluster_is_sent_to_risk_acceptances(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(client, admin_auth, run_compaction)

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={
                "status": "accepted_risk", "reason": REASON, "indefinite": True,
                "accepted_reason_code": "not_exploitable_here",
            },
            headers=_agent(client, admin_auth),
        )

        assert response.status_code == 403
        assert "/api/risk-acceptances" in response.json()["detail"]

    def test_an_agent_on_a_cluster_of_mediums_applies_directly(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        cluster_id = seed_cluster(
            client, admin_auth, run_compaction, severities=("medium", "low")
        )

        response = client.post(
            f"/api/dashboard/triage/clusters/{cluster_id}/disposition",
            json={"status": "false_positive", "reason": REASON},
            headers=_agent(client, admin_auth),
        )

        assert response.status_code == 200, response.text
        assert response.json()["outcome"] == "applied"
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert session.execute(
                select(func.count()).select_from(ApprovalRequest)
            ).scalar() == 0
