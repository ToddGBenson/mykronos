"""deploy.ps1 does not call a deploy done while the dashboard is down.

On 2026-10-22 `docker compose up -d` left mykronos-frontend in `created` and
never started it. The health loop waited for both containers, but only the
backend's result was ever checked, so the script printed "Deployed" and
mykronos-app.toddbenson.net answered 502.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "mykronos" / "deploy.ps1"
CODE = "\n".join(
    line for line in SCRIPT.read_text(encoding="utf-8").splitlines()
    if not line.lstrip().startswith("#")
)


def test_an_unhealthy_frontend_stops_the_deploy_before_it_says_deployed():
    refuse = CODE.index('throw "Frontend did not become healthy')
    assert refuse < CODE.index('Write-Host "`nDeployed.')


def test_a_created_but_never_started_frontend_is_started_once():
    check = CODE.index('if ($state -eq "created")')
    start = CODE.index("docker start mykronos-frontend", check)
    assert check < start < CODE.index('throw "Frontend did not become healthy')
