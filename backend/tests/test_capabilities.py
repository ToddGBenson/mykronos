"""Capability configuration validation — spec 04 §5, §7.

spec 04 §7 is the requirement under test: a misconfigured tool fails at the
save, not silently at workflow run time.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mykronos.capabilities import (
    CONFIG_MODELS,
    CapabilityConfigError,
    config_schema,
    configurable_capabilities,
    validate_config,
)
from tests.conftest import REPO
from tests.test_onboarding import onboard


class TestValidation:
    def test_defaults_are_applied(self) -> None:
        config = validate_config("sast", {})
        assert config["severity_threshold"] == "low"
        assert config["blocking"] is False

    def test_blocking_is_off_by_default_for_every_capability(self) -> None:
        """Platform-wide default, not a per-capability accident (spec 04 §5)."""
        for capability in configurable_capabilities():
            assert validate_config(capability, {})["blocking"] is False

    def test_an_unsupported_tool_is_refused_with_the_alternatives(self) -> None:
        """The spec 04 §7 case: this would otherwise be a red pipeline hours
        later that nobody connects to the capability change."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("secrets", {"enabled_tool": "trufflehog"})

        assert "trufflehog" in str(excinfo.value)
        assert "gitleaks" in str(excinfo.value)

    def test_a_supported_alternative_tool_is_accepted(self) -> None:
        assert validate_config("sast", {"enabled_tool": "semgrep"})["enabled_tool"] == (
            "semgrep"
        )

    def test_an_unknown_field_is_refused_rather_than_dropped(self) -> None:
        """Silently ignoring a typo'd setting means the admin believes they
        configured something they did not."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("sast", {"severtiy_threshold": "high"})

        message = str(excinfo.value)
        assert "severtiy_threshold" in message
        assert "not a recognised setting" in message

    def test_a_bad_severity_is_refused(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("iac", {"severity_threshold": "catastrophic"})

    def test_prose_in_a_cron_field_is_refused(self) -> None:
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("containers", {"schedule_cron": "every day"})
        assert "cron expression" in str(excinfo.value)

    def test_a_valid_cron_passes(self) -> None:
        assert validate_config("containers", {"schedule_cron": "17 3 * * 1"})

    def test_dast_rejects_a_non_url_target(self) -> None:
        """DAST probes a running service; a repo path is a category error."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("dast", {"target_url": "src/app.py"})
        assert "http(s) URL" in str(excinfo.value)

    def test_dast_accepts_a_real_url(self) -> None:
        config = validate_config("dast", {"target_url": "https://staging.example.com"})
        assert config["target_url"] == "https://staging.example.com"

    def test_cloud_rejects_a_malformed_role_arn(self) -> None:
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("cloud", {"aws_role_arn": "my-role"})
        assert "arn:aws:iam::" in str(excinfo.value)

    def test_cloud_accepts_an_azure_subscription(self) -> None:
        """Spec 16 §9. Azure holds TheHub's backups and Prowler scans it, so
        the config has to be able to say which subscription."""
        config = validate_config(
            "cloud",
            {
                "azure_subscription_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
                "azure_tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47",
            },
        )
        assert config["azure_subscription_id"] == "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

    def test_cloud_rejects_a_subscription_that_is_not_a_guid(self) -> None:
        """The value reaches a `prowler azure --subscription-ids <it>` command
        line, so a subscription *name* -- the thing people actually have to
        hand -- has to fail the save rather than the scan."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("cloud", {"azure_subscription_id": "thehub-backups"})
        assert "GUID" in str(excinfo.value)

    def test_cloud_names_the_offending_azure_field(self) -> None:
        """Two fields share one validator; a message that cannot say which one
        was wrong sends the admin to check both."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("cloud", {"azure_tenant_id": "contoso.onmicrosoft.com"})
        assert "azure_tenant_id" in str(excinfo.value)

    def test_both_clouds_can_be_configured_at_once(self) -> None:
        """There is no `provider` field on purpose: the scan runs against
        whichever coordinates are populated, and a third setting that can
        disagree with the other two is a way to scan nothing."""
        config = validate_config(
            "cloud",
            {
                "aws_role_arn": "arn:aws:iam::123456789012:role/mykronos",
                "azure_subscription_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            },
        )
        assert config["aws_role_arn"] and config["azure_subscription_id"]

    def test_an_unknown_capability_is_refused_clearly(self) -> None:
        """Every real capability now has a schema, so the remaining case is a
        name nobody recognises — which must fail the save rather than be
        stored and silently ignored (spec 04 §7)."""
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("telepathy", {})
        assert "does not accept configuration yet" in str(excinfo.value)

    def test_every_capability_has_a_schema(self) -> None:
        """As of Phase 6 all ten do. A capability the API cannot configure is
        one whose settings can only be written by hand — which is how Oracle's
        `blocking` flag was unreachable through the API until Phase 6."""
        from mykronos.schemas import Capability

        missing = [c.value for c in Capability if c.value not in CONFIG_MODELS]

        assert missing == []

    def test_the_error_names_the_offending_field(self) -> None:
        with pytest.raises(CapabilityConfigError) as excinfo:
            validate_config("sast", {"timeout_minutes": 9999})
        assert "timeout_minutes" in str(excinfo.value)


class TestSchemaExposure:
    def test_every_configurable_capability_has_a_schema(self) -> None:
        for capability in configurable_capabilities():
            schema = config_schema(capability)
            assert schema["title"].startswith(capability)
            assert "properties" in schema

    def test_the_tool_enum_comes_from_the_adapter_registry(self) -> None:
        """So a form can never offer a tool the platform cannot parse."""
        assert config_schema("sast")["properties"]["enabled_tool"]["enum"] == [
            "codeql",
            "semgrep",
        ]
        assert config_schema("iac")["properties"]["enabled_tool"]["enum"] == ["checkov"]


class TestThroughTheApi:
    def test_the_schema_endpoint_serves_every_capability(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        response = client.get("/api/repos/-/capabilities", headers=admin_auth)

        assert response.status_code == 200
        assert set(response.json()) == set(configurable_capabilities())

    def test_the_schema_endpoint_needs_auth(self, client: TestClient) -> None:
        assert client.get("/api/repos/-/capabilities").status_code == 401

    def test_a_bad_tool_fails_the_save(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={
                "capabilities": ["secrets"],
                "config": {"secrets": {"enabled_tool": "trufflehog"}},
            },
            headers=admin_auth,
        )

        assert response.status_code == 422
        assert "gitleaks" in response.json()["detail"]

    def test_a_rejected_save_opens_no_pull_request(
        self, client: TestClient, admin_auth: dict[str, str], github
    ) -> None:
        """Validation happens before anything is written, so a bad config
        leaves no half-applied change behind."""
        repo_id = onboard(client, admin_auth).json()["id"]

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={
                "capabilities": ["dast"],
                "config": {"dast": {"target_url": "not-a-url"}},
            },
            headers=admin_auth,
        )

        assert github.repos[REPO].pull_requests == []

    def test_a_valid_config_is_stored_and_normalised(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]

        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={
                "capabilities": ["sast"],
                "config": {"sast": {"languages": ["python"]}},
            },
            headers=admin_auth,
        )

        stored = client.get(f"/api/repos/{repo_id}", headers=admin_auth).json()
        sast = stored["capability_config"]["sast"]
        assert sast["languages"] == ["python"]
        # Defaults filled in, so the rendered workflow is fully determined by
        # what is stored rather than by template fallbacks.
        assert sast["severity_threshold"] == "low"
        assert sast["blocking"] is False
