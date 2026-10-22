"""Which deployment probes are configured, and what each one is missing (TheHub #60918).

Every repository read `not_configured`. The probe asks a URL stored per
repository, which nobody had set; its token comes from
MYKRONOS_DEPLOYMENT_PROBE_TOKENS, which the deployed compose file never passed
into the container. And the briefing's "Production truth" left unprobed
repositories out entirely, so "nothing is behind" and "nothing is measured"
read the same.

Now: two probes are configured from what the platform already knows (this
process's own MYKRONOS_BUILD_SHA for mykronos, MYKRONOS_HUB_API_URL for
TheHub), every repository says what it is missing by setting name, and the
briefing names the repositories it cannot see.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos import briefing, daily_briefing, deployments
from mykronos.config import Settings

COMPOSE = Path(__file__).resolve().parents[2] / "deploy" / "mykronos" / "docker-compose.yml"
SHA = "61f1f13a2b8c4d5e6f7a8b9c0d1e2f3a4b5c6d7e"


class Row:
    def __init__(self, repo: str, url: str = "", rid: str = "onb-1") -> None:
        self.github_repo_full_name = repo
        self.deployment_probe_url = url
        self.id = rid
        self.default_branch = "main"
        self.github_installation_id = 1
        self.deployment_lag = None


def _settings(**kw: Any) -> Settings:
    base: dict[str, Any] = {
        "build_sha": "",
        "hub_api_url": "http://host.docker.internal:8000",
        "hub_api_token": "",
        "gate_token": "",
        "deployment_probe_tokens": {},
    }
    base.update(kw)
    return Settings(_env_file=None, **base)


class TestWhatEachRepositoryIsMissing:
    def test_mykronos_is_this_process(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/mykronos"), _settings(build_sha=SHA)
        )

        assert setup.configured
        assert setup.source == deployments.SOURCE_SELF
        assert setup.missing == []

    def test_mykronos_without_a_build_sha_says_so(self) -> None:
        setup = deployments.probe_setup_for(Row("ToddGBenson/mykronos"), _settings())

        assert setup.configured
        assert any("MYKRONOS_BUILD_SHA" in m for m in setup.missing)

    def test_thehub_is_derived_from_the_hub_api_url(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/TheHub"), _settings(hub_api_token="t")
        )

        assert setup.source == deployments.SOURCE_HUB
        assert setup.url == "http://host.docker.internal:8000/health"
        assert setup.missing == []

    def test_thehub_without_its_token_names_the_setting(self) -> None:
        setup = deployments.probe_setup_for(Row("ToddGBenson/TheHub"), _settings())

        assert setup.configured
        assert any("MYKRONOS_HUB_API_TOKEN" in m for m in setup.missing)

    def test_a_repo_with_nothing_names_the_route(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/keel", rid="onb-9"), _settings()
        )

        assert not setup.configured
        assert setup.source == ""
        assert any("/api/repos/onb-9/deployment-probe" in m for m in setup.missing)

    def test_a_configured_url_without_a_token_names_its_origin(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/personal-soc", url="http://soc:9000/health"), _settings()
        )

        assert setup.source == deployments.SOURCE_CONFIGURED
        assert any(
            "MYKRONOS_DEPLOYMENT_PROBE_TOKENS" in m and "http://soc:9000" in m
            for m in setup.missing
        )

    def test_an_alias_whose_token_is_unset_names_that_token(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/mykronos", url="http://mykronos-backend:8100/healthz"),
            _settings(deployment_probe_tokens={"http://mykronos-backend:8100": "@gate"}),
        )

        assert any("MYKRONOS_GATE_TOKEN" in m for m in setup.missing)

    def test_a_configured_url_wins_over_a_derived_one(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/TheHub", url="http://thehub-backend:8000/health"),
            _settings(
                hub_api_token="t",
                deployment_probe_tokens={"http://thehub-backend:8000": "@hub"},
            ),
        )

        assert setup.source == deployments.SOURCE_CONFIGURED
        assert setup.url == "http://thehub-backend:8000/health"
        assert setup.missing == []

    def test_the_public_form_carries_no_token(self) -> None:
        setup = deployments.probe_setup_for(
            Row("ToddGBenson/TheHub"), _settings(hub_api_token="secret-value")
        )

        assert "secret-value" not in repr(setup.public())
        assert "secret-value" not in repr(setup)


class TestTheSweepUsesWhatItDerived:
    @pytest.mark.asyncio
    async def test_self_and_hub_are_probed(self, monkeypatch) -> None:
        asked: list[tuple[str, str]] = []

        async def fake_probe(url: str, *, timeout: float, token: str = "") -> tuple:
            asked.append((url, token))
            return deployments.OK, SHA, ""

        monkeypatch.setattr(deployments, "probe", fake_probe)
        setups = [
            deployments.probe_setup_for(Row("ToddGBenson/mykronos"), _settings(build_sha=SHA)),
            deployments.probe_setup_for(
                Row("ToddGBenson/TheHub"), _settings(hub_api_token="hub-t")
            ),
            deployments.probe_setup_for(Row("ToddGBenson/keel"), _settings()),
        ]

        states = await deployments.sweep_setups(setups, {}, timeout=1.0, tokens={})

        by_repo = {s.repo_full_name: s for s in states}
        assert asked == [("http://host.docker.internal:8000/health", "hub-t")]
        assert by_repo["ToddGBenson/mykronos"].revision == SHA
        assert by_repo["ToddGBenson/mykronos"].status == deployments.OK
        assert by_repo["ToddGBenson/TheHub"].revision == SHA
        assert "ToddGBenson/keel" not in by_repo

    @pytest.mark.asyncio
    async def test_self_without_a_sha_is_unparsed_not_ok(self) -> None:
        setups = [deployments.probe_setup_for(Row("ToddGBenson/mykronos"), _settings())]

        [state] = await deployments.sweep_setups(setups, {}, timeout=1.0, tokens={})

        assert state.status == deployments.UNPARSED
        assert state.revision is None
        assert "MYKRONOS_BUILD_SHA" in state.detail


class TestTheBriefingNamesWhatItCannotSee:
    def _section(self, catalog, probe_setup: list[dict[str, Any]]) -> daily_briefing.Section:
        report = briefing.build(catalog, production_lag=[], probe_setup=probe_setup)
        return daily_briefing.production_section(report)

    def test_unprobed_repositories_are_named(self, catalog) -> None:
        section = self._section(
            catalog,
            [
                {"repo_full_name": "ToddGBenson/keel", "source": "", "missing": ["no URL"]},
                {"repo_full_name": "ToddGBenson/binnacle", "source": "", "missing": ["no URL"]},
                {"repo_full_name": "ToddGBenson/mykronos", "source": "self", "missing": []},
            ],
        )

        [line] = section.lines
        assert "1 of 3" in line.what
        assert "ToddGBenson/binnacle" in line.what and "ToddGBenson/keel" in line.what
        assert line.work == daily_briefing.DECISION
        assert section.data["deployments_not_configured"] == [
            "ToddGBenson/binnacle",
            "ToddGBenson/keel",
        ]
        assert section.data["probe_setup"][0]["missing"] == ["no URL"]

    def test_everything_probed_adds_no_line(self, catalog) -> None:
        section = self._section(
            catalog, [{"repo_full_name": "ToddGBenson/mykronos", "source": "self", "missing": []}]
        )

        assert section.lines == []


class TestTheTokensReachTheContainer:
    def test_compose_passes_the_probe_tokens(self) -> None:
        env = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["backend"][
            "environment"
        ]

        assert "MYKRONOS_DEPLOYMENT_PROBE_TOKENS" in env
        assert str(env["MYKRONOS_DEPLOYMENT_PROBE_TOKENS"]).startswith("${")


class TestTheEndpoint:
    def test_each_repository_says_what_it_is_missing(self, client, admin_auth) -> None:
        from tests.test_deployments import TestTheEndpointSaysWhatItCannotSee as T

        T._onboard(client, "ToddGBenson/keel")
        T._onboard(client, "ToddGBenson/TheHub")

        body = client.get("/api/dashboard/deployments", headers=admin_auth).json()

        rows = {r["repo_full_name"]: r for r in body["repos"]}
        assert rows["ToddGBenson/keel"]["probe_source"] == ""
        assert any("deployment-probe" in m for m in rows["ToddGBenson/keel"]["missing"])
        assert rows["ToddGBenson/TheHub"]["probe_source"] == deployments.SOURCE_HUB
        assert any("MYKRONOS_HUB_API_TOKEN" in m for m in rows["ToddGBenson/TheHub"]["missing"])
        assert body["not_configured"] == sum(1 for r in rows.values() if not r["probe_source"])
