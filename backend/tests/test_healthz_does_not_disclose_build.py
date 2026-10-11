"""The public `/healthz` says the process is up, and nothing else (TheHub #60722).

`/healthz` is exempt from the perimeter gate, so every key in its body is
published to the internet. Until D-154 that body carried `build.sha`, the
commit the running image was built from. A public SHA tells anyone which
commit to diff against the public repository to find what is unpatched.

The SHA is still there for a caller that presents the perimeter token
(`X-Hub-Token`, the `hub_token` cookie or `?_token=`), and the deploy script
reads it from the container's own stamp, `MYKRONOS_BUILD_SHA`, rather than
over HTTP. The status code is 200 for everyone: the healthchecks, the tunnel
check and the pipeline's curl only read the code.

TheHub fixed the same leak on `/health` in #60709.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mykronos.config import Settings
from mykronos.gate import TOKEN_COOKIE, TOKEN_HEADER, TOKEN_QUERY
from mykronos.main import create_app

SHA = "63714b61df3743b16ff72b4d1dc7f2c2011b4aed"
GATE = "gate-token-for-healthz"

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY_PS1 = REPO_ROOT / "deploy" / "mykronos" / "deploy.ps1"
DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"


def _client(settings: Settings, *, gate: str) -> TestClient:
    return TestClient(
        create_app(settings.model_copy(update={"build_sha": SHA, "gate_token": gate}))
    )


@pytest.fixture
def gated(settings: Settings):
    with _client(settings, gate=GATE) as client:
        yield client


@pytest.fixture
def ungated(settings: Settings):
    with _client(settings, gate="") as client:
        yield client


class TestThePublicBodyIsStatusOnly:
    def test_an_anonymous_caller_gets_status_and_nothing_else(self, gated) -> None:
        response = gated.get("/healthz")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert SHA not in response.text
        assert SHA[:7] not in response.text

    def test_a_wrong_token_is_the_same_as_none(self, gated) -> None:
        response = gated.get("/healthz", headers={TOKEN_HEADER: "not-the-token"})

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_an_ungated_host_does_not_publish_it_either(self, ungated) -> None:
        """No gate token means there is no credential to present, not that the
        caller is trusted. The demo and production both set one; a host that
        forgets to is exactly the one that should not be publishing more."""
        response = ungated.get("/healthz")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAnAuthorisedCallerStillGetsTheBuild:
    @pytest.mark.parametrize("carrier", ["header", "cookie", "query"])
    def test_every_gate_carrier_reveals_the_sha(self, gated, carrier: str) -> None:
        if carrier == "header":
            response = gated.get("/healthz", headers={TOKEN_HEADER: GATE})
        elif carrier == "cookie":
            gated.cookies.set(TOKEN_COOKIE, GATE)
            response = gated.get("/healthz")
        else:
            response = gated.get("/healthz", params={TOKEN_QUERY: GATE})

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["build"] == {"sha": SHA, "source": "image"}


class TestDeployPs1ReadsTheContainerStamp:
    """deploy.ps1 confirms the running commit after every deploy (#361, D-125).
    It used to read `.build.sha` from `/healthz`, which would now always come
    back empty and print "cannot confirm the tag took" forever."""

    def _deploy(self) -> str:
        return DEPLOY_PS1.read_text(encoding="utf-8")

    def test_it_no_longer_reads_the_sha_from_healthz(self) -> None:
        assert not re.search(r"healthz[^\n]*\)\.build\.sha", self._deploy())

    def test_it_reads_the_stamp_from_the_running_container(self) -> None:
        deploy = self._deploy()
        assert (
            "docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mykronos-backend"
            in deploy
        )
        assert "^MYKRONOS_BUILD_SHA=(.*)$" in deploy

    def test_the_stamp_it_reads_is_the_one_the_image_bakes(self) -> None:
        """The name deploy.ps1 parses must be the ENV the Dockerfile sets and
        the setting the backend serves, or the check reads nothing."""
        assert re.search(
            r"ENV MYKRONOS_BUILD_SHA=\$\{MYKRONOS_BUILD_SHA\}",
            DOCKERFILE.read_text(encoding="utf-8"),
        )
        assert Settings.model_config.get("env_prefix") == "MYKRONOS_"
        assert "build_sha" in Settings.model_fields

    def test_its_parse_extracts_the_sha_from_inspect_output(self) -> None:
        """The regex deploy.ps1 applies, run against the shape `docker inspect`
        prints: one `NAME=value` per line."""
        pattern = re.search(r"-match '([^']*MYKRONOS_BUILD_SHA[^']*)'", self._deploy())
        assert pattern, "deploy.ps1 no longer matches MYKRONOS_BUILD_SHA"
        inspect_output = f"PATH=/usr/bin\nMYKRONOS_BUILD_SHA={SHA}\nPYTHONUNBUFFERED=1\n"
        found = [
            m.group(1)
            for line in inspect_output.splitlines()
            if (m := re.match(pattern.group(1), line))
        ]
        assert found == [SHA]
