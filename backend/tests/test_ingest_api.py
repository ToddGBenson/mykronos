"""Ingestion API contract — specs/05-datalake.md §4, §6; spec 12 §2."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import (
    CAPABILITY,
    REPO,
    dependency_finding,
    finding_payload,
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
        """spec 05 §9: revoking a capability's token blocks the very next
        request, with no grace period."""
        assert post_scan(client, auth).status_code == 200

        client.app.state.tokens.revoke(REPO, CAPABILITY)  # type: ignore[attr-defined]

        assert post_scan(client, auth).status_code == 401

    def test_token_cannot_write_another_repo(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        """The blast-radius property: a compromised runner reaches its own
        (repo, capability) pair and nothing else."""
        response = post_scan(client, auth, repo_full_name="example-org/ledger-core")
        assert response.status_code == 403
        assert "scoped to" in response.json()["detail"]

    def test_token_cannot_write_another_capability(
        self, client: TestClient, auth: dict[str, str]
    ) -> None:
        response = post_scan(client, auth, capability="secrets")
        assert response.status_code == 403

    def test_findings_are_attributed_from_the_token_not_the_payload(
        self, client: TestClient, auth: dict[str, str], run_compaction
    ) -> None:
        """A findings batch carries no repo or capability field at all, so a
        workflow cannot file findings against someone else's repo."""
        post_scan(client, auth)
        post_findings(client, auth, [finding_payload()])
        run_compaction()

        rows = client.app.state.catalog.query(  # type: ignore[attr-defined]
            "SELECT repo_full_name, capability FROM findings"
        )
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
        response = client.post("/api/ingest/aegis", headers=auth)
        assert response.status_code == 501
        assert "Phase 0" in response.json()["detail"]


class TestRateLimiting:
    def test_exceeding_the_limit_returns_429_with_retry_after(
        self, settings, monkeypatch
    ) -> None:
        """spec 05 §6. The client contract is back off and retry — never drop
        findings — so the response must say when to come back."""
        settings.rate_limit_requests_per_minute = 3
        from mykronos.main import create_app

        with TestClient(create_app(settings)) as client:
            token = client.app.state.tokens.issue(REPO, CAPABILITY)  # type: ignore[attr-defined]
            headers = {"Authorization": f"Bearer {token}"}

            for _ in range(3):
                assert post_findings(client, headers, []).status_code == 200

            response = post_findings(client, headers, [])
            assert response.status_code == 429
            assert int(response.headers["Retry-After"]) >= 1

    def test_limit_is_per_token_not_global(self, settings) -> None:
        settings.rate_limit_requests_per_minute = 2
        from mykronos.main import create_app

        with TestClient(create_app(settings)) as client:
            registry = client.app.state.tokens  # type: ignore[attr-defined]
            first = {"Authorization": f"Bearer {registry.issue(REPO, 'sast')}"}
            second = {"Authorization": f"Bearer {registry.issue('example-org/other', 'sast')}"}

            for _ in range(2):
                assert post_findings(client, first, []).status_code == 200
            assert post_findings(client, first, []).status_code == 429

            # A noisy neighbour must not consume another repo's budget.
            assert post_findings(client, second, []).status_code == 200
