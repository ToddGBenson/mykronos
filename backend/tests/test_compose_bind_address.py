"""D-178: published ports take a host-chosen bind address, loopback by default.

A YAML read, no containers: each published port is resolved the way compose
resolves `${NAME:-default}`, once with an empty environment and once with the
variable set to 0.0.0.0.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MYKRONOS = ROOT / "deploy" / "mykronos" / "docker-compose.yml"
CONCOURSE = ROOT / "deploy" / "concourse" / "docker-compose.yml"

#: (compose file, service, published port, variable)
CASES = (
    (MYKRONOS, "backend", "8100", "MYKRONOS_BIND"),
    (CONCOURSE, "concourse", "8080", "CONCOURSE_BIND"),
)


def _resolve(text: str, env: dict) -> str:
    return re.sub(
        r"\$\{(\w+):-([^}]*)\}", lambda m: env.get(m.group(1)) or m.group(2), text
    )


def _port_entry(path: Path, service: str, port: str) -> str:
    services = yaml.safe_load(path.read_text(encoding="utf-8"))["services"]
    matches = [
        str(p) for p in services[service]["ports"] if str(p).endswith(f":{port}:{port}")
    ]
    assert len(matches) == 1, (service, port, services[service]["ports"])
    return matches[0]


@pytest.mark.parametrize("path,service,port,var", CASES)
def test_default_is_loopback(path, service, port, var) -> None:
    assert _resolve(_port_entry(path, service, port), {}) == f"127.0.0.1:{port}:{port}"


@pytest.mark.parametrize("path,service,port,var", CASES)
def test_host_can_choose_the_bind_address(path, service, port, var) -> None:
    entry = _port_entry(path, service, port)
    assert f"${{{var}:-127.0.0.1}}" in entry
    assert _resolve(entry, {var: "0.0.0.0"}) == f"0.0.0.0:{port}:{port}"


def test_the_tsa_port_is_not_published_beyond_loopback_by_default() -> None:
    """2222 is published only as the TSA bind variable, loopback by default
    (D-181): a worker on another host needs it, and Add-LinuxWorker.ps1 sets
    the variable only once a block rule scopes the port."""
    services = yaml.safe_load(CONCOURSE.read_text(encoding="utf-8"))["services"]
    tsa = [
        (name, str(p))
        for name, svc in services.items()
        for p in svc.get("ports", [])
        if str(p).endswith(":2222")
    ]
    assert tsa == [("concourse", "${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222")], tsa
    for _, entry in tsa:
        assert _resolve(entry, {}) == "127.0.0.1:2222:2222"


def test_the_variables_are_documented() -> None:
    assert re.search(
        r"^MYKRONOS_BIND=127\.0\.0\.1\s*$",
        (ROOT / "backend" / ".env.example").read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert re.search(
        r"^CONCOURSE_BIND=127\.0\.0\.1\s*$",
        (ROOT / "deploy" / "concourse" / ".env.example").read_text(encoding="utf-8"),
        re.MULTILINE,
    )


def test_the_dashboard_stays_loopback_even_when_the_bind_is_opened() -> None:
    entry = _port_entry(MYKRONOS, "frontend", "3100")
    assert _resolve(entry, {"MYKRONOS_BIND": "0.0.0.0"}) == "127.0.0.1:3100:3100"
