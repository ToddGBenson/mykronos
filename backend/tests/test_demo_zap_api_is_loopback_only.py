"""The demo's ZAP API is reachable from this host only.

ZAP runs in daemon mode with `api.disablekey=true` and accepts any caller, and
its API can load and run scripts. Published on every interface, that is code
execution on the scan container for anyone on the LAN whenever a DAST run is
up. The lane that drives it, `demo-and-dast.yml`, calls it at localhost:8290.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "deploy" / "demo" / "docker-compose.yml"
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"


def _zap() -> dict:
    return yaml.safe_load(DEMO.read_text(encoding="utf-8"))["services"]["zap"]


def test_every_zap_port_binds_loopback() -> None:
    ports = [str(p) for p in _zap().get("ports", [])]
    assert ports, "ZAP publishes no port, so the lane cannot reach it"
    for port in ports:
        assert port.startswith("127.0.0.1:"), f"ZAP port {port!r} is published beyond loopback"


def test_the_lane_still_reaches_it_on_localhost() -> None:
    assert "ZAP_PROXY: http://localhost:8290" in WORKFLOW.read_text(encoding="utf-8")
