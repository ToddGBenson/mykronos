"""The demo frontend's healthcheck, and the DAST scan, get past the gate (TheHub #60735).

#753 put a perimeter gate in front of every frontend path but `/api/healthz`
and moved the image's HEALTHCHECK there. `deploy/demo/docker-compose.yml`
overrides that check, still fetched `/`, and sets `MYKRONOS_GATE_TOKEN`, so
the token-less check got 401 and the frontend never became healthy. Demo and
DAST failed on every main commit from 2026-10-05 to 2026-10-12 with "The demo
environment never became healthy."

Once it was healthy, the spider had the same problem: measured against the
demo stack, all 15 of its requests answered 401. The functional suite carries
its own cookie; ZAP's own requests carried nothing. So the scan was of the
gate, and a report of it would have closed every real DAST finding by
absence.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "deploy" / "demo" / "docker-compose.yml"
COMPOSES = [DEMO, ROOT / "deploy" / "mykronos" / "docker-compose.yml"]
WORKFLOW = ROOT / ".github" / "workflows" / "demo-and-dast.yml"
GATE = ROOT / "frontend" / "lib" / "gate.ts"


def _load(path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded


def _exempt_paths() -> set[str]:
    """What the gate lets through without a token, read from the gate itself
    so a change there is a change here."""
    body = re.search(
        r"function isExempt\(path: string\): boolean \{(.*?)\n\}",
        GATE.read_text(encoding="utf-8"),
        re.S,
    )
    assert body, "lib/gate.ts no longer declares isExempt"
    return set(re.findall(r'path === "([^"]+)"', body.group(1)))


def _healthcheck_paths(service: dict[str, Any]) -> list[str]:
    test = (service.get("healthcheck") or {}).get("test") or []
    command = " ".join(test) if isinstance(test, list) else str(test)
    return [urlparse(url).path or "/" for url in re.findall(r"https?://[^'\"\s)]+", command)]


def test_the_gate_still_exempts_only_the_healthcheck() -> None:
    assert _exempt_paths() == {"/api/healthz"}


@pytest.mark.parametrize("compose", COMPOSES, ids=lambda p: p.parent.name)
def test_a_gated_frontend_is_health_checked_on_an_ungated_route(compose: Path) -> None:
    """The story's AC4. Any route other than the gate's exemption answers a
    token-less healthcheck with 401 whenever the gate is on."""
    frontend = _load(compose)["services"]["frontend"]
    paths = _healthcheck_paths(frontend)
    if not paths:
        # No override: the image's own HEALTHCHECK applies, which is
        # `/api/healthz` (frontend/Dockerfile).
        assert "healthcheck" not in frontend
        return
    gated = [p for p in paths if p not in _exempt_paths()]
    assert not gated, (
        f"{compose.relative_to(ROOT)}: the frontend healthcheck fetches {gated}, which "
        "the perimeter gate answers with 401. Use /api/healthz."
    )


def _workflow_step(step_id: str) -> str:
    steps = _load(WORKFLOW)["jobs"]["demo-and-dast"]["steps"]
    run: str = next(s["run"] for s in steps if s.get("id") == step_id)
    return run


def test_the_workflow_token_is_the_demo_gate_token() -> None:
    env = _load(WORKFLOW)["jobs"]["demo-and-dast"]["env"]
    frontend = _load(DEMO)["services"]["frontend"]["environment"]
    assert env["DEMO_GATE_TOKEN"] == frontend["MYKRONOS_GATE_TOKEN"]


def test_the_spider_presents_the_gate_token() -> None:
    """Through the environment, never written into the script."""
    run = _workflow_step("zap")
    rule = run.index("matchString=X-Hub-Token")
    assert "replacement=${DEMO_GATE_TOKEN}" in run
    assert "demo-gate-token-not-a-secret" not in run
    assert rule < run.index("/JSON/spider/action/scan/")


def test_the_rule_is_added_after_the_functional_suite() -> None:
    """The suite's anonymous tests go through the same proxy; a header on
    every request would sign them in."""
    assert "replacer" not in _workflow_step("functional")


def test_a_scan_of_only_the_gate_writes_no_report() -> None:
    run = _workflow_step("zap")
    guard = run.index('if [ "$SPIDER_2XX" = "0" ]; then')
    assert guard < run.index("/OTHER/core/other/jsonreport/")
    assert "exit 1" in run[guard : run.index("fi", guard)]
