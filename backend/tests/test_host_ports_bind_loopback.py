"""The backend, MinIO's S3 API and the registry publish on loopback only (TheHub #60841).

All three used to publish on 0.0.0.0/[::] and relied on one Windows firewall
rule over 192.168.0.0/24 to keep the LAN out. They were on every interface for
one reason: Concourse garden task containers reached them by the host's LAN
address, 192.168.0.14, because they resolve through public DNS and cannot see
`host.docker.internal` or a compose service name.

They now dial 192.168.65.254 instead, the address Docker Desktop answers
`host.docker.internal` with. It lands on this machine's loopback, so a
127.0.0.1 publish answers there (measured 2026-10-18 from the worker's network
namespace) and refuses on 192.168.0.14. The two halves only work together: a
loopback bind with a pipeline still on the LAN address is a dead build, which
is what these tests stop.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
MYKRONOS_COMPOSE = ROOT / "deploy" / "mykronos" / "docker-compose.yml"
CONCOURSE_COMPOSE = CONCOURSE / "docker-compose.yml"

LAN_ADDRESS = "192.168.0.14"
HOST_GATEWAY = "192.168.65.254"

#: (compose file, service, container port). Each is reached by Concourse tasks.
LOOPBACK_ONLY = [
    (MYKRONOS_COMPOSE, "backend", 8100),
    (CONCOURSE_COMPOSE, "minio", 9000),
    (CONCOURSE_COMPOSE, "registry", 5000),
]

#: Every file a pipeline's host addresses come from.
PIPELINE_ADDRESS_SOURCES = [
    CONCOURSE / "vars" / "mykronos.yml",
    CONCOURSE / "vars" / "personal-soc.yml",
    CONCOURSE / "vars" / "thehub.yml",
    CONCOURSE / "set-pipeline.ps1",
    CONCOURSE / "set-personal-soc-pipeline.ps1",
    CONCOURSE / "set-thehub-pipeline.ps1",
]


def _ports(compose: Path, service: str) -> list[str]:
    services = yaml.safe_load(compose.read_text(encoding="utf-8"))["services"]
    return [str(p) for p in services[service].get("ports", [])]


@pytest.mark.parametrize(("compose", "service", "port"), LOOPBACK_ONLY)
def test_the_port_is_published_on_loopback_only(compose: Path, service: str, port: int) -> None:
    published = [p for p in _ports(compose, service) if p.rsplit(":", 1)[-1] == str(port)]
    assert published, f"{service} no longer publishes {port}; its consumers would lose it"
    for binding in published:
        assert binding.startswith("127.0.0.1:"), (
            f"{service} publishes {binding!r} beyond loopback (TheHub #60841)"
        )


@pytest.mark.parametrize("source", PIPELINE_ADDRESS_SOURCES, ids=lambda p: p.name)
def test_no_pipeline_dials_the_lan_address(source: Path) -> None:
    """A loopback publish refuses on 192.168.0.14, so a task dialling it fails."""
    text = source.read_text(encoding="utf-8")
    lan = re.escape(LAN_ADDRESS)
    # A URL, an address:port or a `*-host:` value; prose naming the address is fine.
    dialled = re.findall(rf"https?://{lan}|{lan}:\d+|-host:\s*{lan}", text)
    assert not dialled, (
        f"{source.name} still addresses this host as {dialled}; use {HOST_GATEWAY}, "
        "Docker Desktop's host gateway, which reaches loopback-published ports"
    )


def test_the_pipelines_reach_each_loopback_port_through_the_host_gateway() -> None:
    vars_text = "\n".join(
        (CONCOURSE / "vars" / f"{stem}.yml").read_text(encoding="utf-8")
        for stem in ("mykronos", "personal-soc", "thehub")
    )
    for _, service, port in LOOPBACK_ONLY:
        assert f"{HOST_GATEWAY}:{port}" in vars_text, (
            f"no pipeline var reaches {service} on {HOST_GATEWAY}:{port}"
        )
