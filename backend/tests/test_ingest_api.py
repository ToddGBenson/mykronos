"""Ingestion API contract — specs/05-datalake.md §4, §6; spec 12 §2."""

from __future__ import annotations

from fastapi.testclient import TestClient

from mykronos.auth import TokenRegistry
from tests.conftest import (
    CAPABILITY,
    REPO,
    dependency_finding,
    finding_payload,
    issue_token,
    post_findings,
    post_scan,
    scan_run_payload,
)


class TestAuth:
    def test_missing_token_is_401(self, client: TestClient) -> None:
        response = client.post("/api/ingest/scan-run", json=scan_run_payload())
        assert response.status_code == 401

    def test_unknown_token_is_401(self, client: TestClient) -> None:
        response = post_scan(client, {"Authorization": "Bearer not-a-real-token"})
        assert response.status_code == 401

    def test_revoked_token_is_rejected_immediately(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """spec 05 §9: offboarding a repo blocks the very next request."""
        assert post_scan(client, auth).status_code == 200

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            TokenRegistry(session).revoke_repo(REPO)

        assert post_scan(client, auth).status_code == 401

    def test_token_cannot_write_another_repo(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """The blast-radius property: a compromised runner reaches its own
        (repo, capability) pair and nothing else."""
        response = post_scan(client, auth, repo_full_name="example-org/ledger-core")
        assert response.status_code == 403
        assert "scoped to" in response.json()["detail"]

    def test_token_cannot_write_an_ungranted_capability(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """One token spans capabilities now (D-009), so the grant set is what
        enforces the boundary rather than the credential itself."""
        response = post_scan(client, auth, capability="secrets")
        assert response.status_code == 403
        assert "not enabled" in response.json()["detail"]

    def test_revoking_one_grant_leaves_the_others_working(
        self, client: TestClient
    ) -> None:
        """The property that makes a shared per-repo token acceptable: grants
        are revocable independently, immediately, and locally."""
        token = issue_token(client, REPO, "sast", "secrets")
        headers = {"Authorization": f"Bearer {token}"}

        assert post_findings(client, headers, [], capability="sast").status_code == 200
        assert post_findings(client, headers, [], capability="secrets").status_code == 200

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            TokenRegistry(session).revoke_grant(REPO, "secrets")

        assert post_findings(client, headers, [], capability="secrets").status_code == 403
        assert post_findings(client, headers, [], capability="sast").status_code == 200

    def test_findings_are_attributed_from_the_token_not_the_payload(
        self, client: TestClient, auth: dict[str, str], catalog, run_compaction
    ) -> None:
        """A findings batch carries no repo or capability field at all, so a
        workflow cannot file findings against someone else's repo."""
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        rows = catalog.query("SELECT repo_full_name, capability FROM findings")
        assert rows == [(REPO, CAPABILITY)]

    def test_health_requires_a_token(self, client: TestClient) -> None:
        assert client.get("/api/ingest/health").status_code == 401

    def test_unauthenticated_liveness_probe_reveals_nothing(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert set(response.json()) == {"status", "version"}


class TestValidation:
    def test_malformed_payload_is_422_not_partial_ingest(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """spec 05 §4: reject with a clear error rather than partially
        ingesting malformed data."""
        response = post_scan(client, auth, severity="nonsense", scan_status="not-a-status")
        assert response.status_code == 422

    def test_unknown_field_is_rejected(self, client: TestClient, auth: dict[str, str]) -> None:
        """extra='forbid' — a typo'd field name must not be silently dropped."""
        response = post_scan(client, auth, comit_sha="typo")
        assert response.status_code == 422

    def test_bad_repo_shape_is_rejected(self, client: TestClient, auth: dict[str, str]) -> None:
        assert post_scan(client, auth, repo_full_name="no-slash").status_code == 422

    def test_batch_over_ceiling_is_422(self, client: TestClient, auth: dict[str, str]) -> None:
        """spec 05 §6: 10,000 findings per request maximum."""
        oversized = [finding_payload(rule_id=f"R-{i}") for i in range(10_001)]
        assert post_findings(client, auth, oversized).status_code == 422

    def test_client_cannot_supply_finding_id(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """Identity is the server's to assign — an adapter that could name its
        own finding_id could silently fork or merge identities."""
        response = post_findings(client, auth, [finding_payload(finding_id="forged")])
        assert response.status_code == 422


class TestIngestion:
    def test_scan_run_then_findings(self, client: TestClient, auth: dict[str, str]) -> None:
        assert post_scan(client, auth).json()["accepted"] == 1

        response = post_findings(client, auth, [finding_payload(), dependency_finding()])
        assert response.status_code == 200
        assert response.json()["accepted"] == 2

    def test_empty_batch_is_valid(self, client: TestClient, auth: dict[str, str]) -> None:
        """spec 04 §6: "I ran and found nothing" is a real result, distinct
        from "never ran"."""
        response = post_findings(client, auth, [])
        assert response.status_code == 200
        assert response.json()["accepted"] == 0

    def test_200_means_already_on_disk(
        self, client: TestClient, auth: dict[str, str], buffer
    ) -> None:
        """spec 05 §4: a 200 is a durability guarantee, not an in-memory ack."""
        assert buffer.count_sealed() == 0
        post_findings(client, auth, [finding_payload()])
        assert buffer.count_sealed() == 1

        segment = buffer.sealed_segments("findings")[0]
        assert segment.stat().st_size > 0

    def test_health_reports_lake_writability(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        body = client.get("/api/ingest/health", headers=auth).json()
        assert body["status"] == "ok"
        assert body["datalake_writable"] is True

    def test_unimplemented_capability_route_is_501_not_404(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """The route is in spec 05 §4; its tables arrive in later phases.
        501 keeps the contract visible instead of looking like a routing bug."""
        token = issue_token(client, REPO, "aegis")
        response = client.post(
            "/api/ingest/aegis", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 501
        assert "not implemented yet" in response.json()["detail"]


class TestRawArchive:
    """spec 05 §7 — the original tool output, kept for dispute resolution."""

    def _post(self, client: TestClient, auth: dict[str, str], body: bytes, **params):
        query = {"scan_run_id": "run-1", "capability": CAPABILITY, "filename": "out.sarif"}
        query.update(params)
        return client.post("/api/ingest/raw", params=query, content=body, headers=auth)

    def test_stores_the_file_and_returns_its_reference(
        self, client: TestClient, auth: dict[str, str], settings
    ) -> None:
        response = self._post(client, auth, b'{"runs": []}')

        assert response.status_code == 200
        ref = response.json()["raw_output_ref"]
        assert (settings.datalake_dir / ref).read_bytes() == b'{"runs": []}'

    def test_archive_mirrors_the_repo_namespace(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        ref = self._post(client, auth, b"x").json()["raw_output_ref"]
        assert ref.startswith("raw/example-org/payments-api/run-1/")

    def test_a_traversal_filename_cannot_escape_the_archive(
        self, client: TestClient, auth: dict[str, str], settings
    ) -> None:
        """The archive stores attacker-influenceable names; it must not be a
        write primitive onto the host."""
        response = self._post(client, auth, b"x", filename="../../../../evil.txt")

        assert response.status_code == 200
        ref = response.json()["raw_output_ref"]
        assert ".." not in ref
        assert (settings.datalake_dir / ref).is_file()

    def test_a_traversal_scan_run_id_is_neutralised(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        ref = self._post(client, auth, b"x", scan_run_id="../../etc").json()[
            "raw_output_ref"
        ]
        assert ".." not in ref

    def test_an_ungranted_capability_is_refused(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        assert self._post(client, auth, b"x", capability="iac").status_code == 403

    def test_oversized_output_is_rejected_without_touching_findings(
        self, settings
    ) -> None:
        """Rejecting the archive copy must not imply the findings failed."""
        settings.max_raw_output_bytes = 16
        from mykronos.main import create_app

        with TestClient(create_app(settings)) as client:
            headers = {"Authorization": f"Bearer {issue_token(client, REPO, CAPABILITY)}"}
            response = client.post(
                "/api/ingest/raw",
                params={
                    "scan_run_id": "run-1",
                    "capability": CAPABILITY,
                    "filename": "out.sarif",
                },
                content=b"x" * 64,
                headers=headers,
            )

        assert response.status_code == 413
        assert "findings were still accepted" in response.json()["detail"].lower()


class TestRateLimiting:
    def test_exceeding_the_limit_returns_429_with_retry_after(
        self, settings, monkeypatch
    ) -> None:
        """spec 05 §6. The client contract is back off and retry — never drop
        findings — so the response must say when to come back."""
        settings.rate_limit_requests_per_minute = 3
        from mykronos.main import create_app

        with TestClient(create_app(settings)) as client:
            headers = {"Authorization": f"Bearer {issue_token(client, REPO, CAPABILITY)}"}

            for _ in range(3):
                assert post_findings(client, headers, []).status_code == 200

            response = post_findings(client, headers, [])
            assert response.status_code == 429
            assert int(response.headers["Retry-After"]) >= 1

    def test_limit_is_per_token_not_global(self, settings) -> None:
        settings.rate_limit_requests_per_minute = 2
        from mykronos.main import create_app

        with TestClient(create_app(settings)) as client:
            first = {"Authorization": f"Bearer {issue_token(client, REPO, 'sast')}"}
            second = {
                "Authorization": f"Bearer {issue_token(client, 'example-org/other', 'sast')}"
            }

            for _ in range(2):
                assert post_findings(client, first, []).status_code == 200
            assert post_findings(client, first, []).status_code == 429

            # A noisy neighbour must not consume another repo's budget.
            assert post_findings(client, second, []).status_code == 200
