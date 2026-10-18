"""`Set-RegistryScope.ps1 -Remove` does not claim the registry is open while
other Block rules still cover port 5000 (#268).

The script owns one firewall rule, "Mykronos registry 5000 - deny the LAN".
This host also carries the older B-054 pair, "Block registry 5000 from the LAN
(B-054)", with this host's own address carved out (see test_host_controls.py's
NARROW_RULE). `-Remove` deleted its own rule and printed "The registry is open
to the LAN again", which was false while the pair remained.

The whole script runs here, the way test_deploy_gate_wait.py runs deploy.ps1:
`Get-NetFirewallRule`, `Get-NetFirewallPortFilter`, `Remove-NetFirewallRule`
and `New-NetFirewallRule` are shadowed by functions that play back a fixture
and record calls, so nothing touches the real firewall and no elevation is
needed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "concourse" / "Set-RegistryScope.ps1"

OURS = "Mykronos registry 5000 - deny the LAN"
B054 = "Block registry 5000 from the LAN (B-054)"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")


def rule(
    name: str,
    *,
    protocol: str = "TCP",
    port: Any = "5000",
    action: str = "Block",
    direction: str = "Inbound",
    enabled: bool = True,
) -> dict[str, Any]:
    return {
        "DisplayName": name,
        "Protocol": protocol,
        "LocalPort": port,
        "Action": action,
        "Direction": direction,
        "Enabled": enabled,
    }


def run(tmp_path: Path, rules: list[dict[str, Any]], *args: str) -> tuple[str, list[str]]:
    fixture = tmp_path / "rules.json"
    fixture.write_text(json.dumps(rules), encoding="utf-8")
    removed_log = tmp_path / "removed.txt"
    program = f"""
$global:Rules = [System.Collections.ArrayList]@(Get-Content -Raw '{fixture}' | ConvertFrom-Json)
$global:Removed = @()
function Get-NetFirewallRule {{
  param($DisplayName, $Direction, $Action, $Enabled, $ErrorAction)
  $global:Rules | Where-Object {{
    (-not $DisplayName -or $_.DisplayName -eq $DisplayName) -and
    (-not $Direction -or $_.Direction -eq $Direction) -and
    (-not $Action -or $_.Action -eq $Action) -and
    (-not $Enabled -or "$($_.Enabled)" -eq "$Enabled")
  }}
}}
function Get-NetFirewallPortFilter {{
  param($AssociatedNetFirewallRule)
  [pscustomobject]@{{
    Protocol = $AssociatedNetFirewallRule.Protocol
    LocalPort = $AssociatedNetFirewallRule.LocalPort
  }}
}}
function Remove-NetFirewallRule {{
  param($DisplayName)
  $global:Removed += $DisplayName
  $keep = @($global:Rules | Where-Object {{ $_.DisplayName -ne $DisplayName }})
  $global:Rules = [System.Collections.ArrayList]$keep
}}
function New-NetFirewallRule {{ }}
function Set-NetFirewallRule {{ }}
& '{SCRIPT}' {" ".join(args)} *>&1 | ForEach-Object {{ "$_" }}
$global:Removed | Set-Content -Path '{removed_log}'
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    removed = (
        [line for line in removed_log.read_text(encoding="utf-8").splitlines() if line]
        if removed_log.exists()
        else []
    )
    return out.stdout + out.stderr, removed


@needs_pwsh
class TestRemove:
    def test_other_block_rules_on_the_port_are_named_and_it_does_not_claim_open(
        self, tmp_path: Path
    ) -> None:
        output, removed = run(tmp_path, [rule(OURS), rule(B054), rule(B054)], "-Remove")

        assert removed == [OURS]
        assert "open to the LAN again" not in output
        assert "NOT open to the LAN" in output
        assert B054 in output
        assert "2 other enabled inbound Block rule(s) on TCP 5000" in output

    def test_with_nothing_else_on_the_port_it_says_open(self, tmp_path: Path) -> None:
        output, removed = run(tmp_path, [rule(OURS)], "-Remove")

        assert removed == [OURS]
        assert "open to the LAN again" in output
        assert "NOT open" not in output

    def test_rules_that_do_not_cover_the_port_are_not_counted(self, tmp_path: Path) -> None:
        unrelated = [
            rule("other port", port="8080"),
            rule("udp", protocol="UDP"),
            rule("an allow", action="Allow"),
            rule("outbound", direction="Outbound"),
            rule("disabled", enabled=False),
        ]
        output, _ = run(tmp_path, [rule(OURS), *unrelated], "-Remove")

        assert "open to the LAN again" in output
        assert "NOT open" not in output

    def test_a_range_or_any_port_counts(self, tmp_path: Path) -> None:
        output, _ = run(
            tmp_path,
            [rule(OURS), rule("a range", port="4000-6000"), rule("everything", port="Any")],
            "-Remove",
        )

        assert "NOT open to the LAN" in output
        assert "a range" in output and "everything" in output

    def test_with_our_rule_already_gone_the_others_are_still_reported(self, tmp_path: Path) -> None:
        output, removed = run(tmp_path, [rule(B054)], "-Remove")

        assert removed == []
        assert f"not present: {OURS}" in output
        assert "NOT open to the LAN" in output

    def test_whatif_removes_nothing_and_claims_nothing(self, tmp_path: Path) -> None:
        output, removed = run(tmp_path, [rule(OURS), rule(B054)], "-Remove", "-WhatIf")

        assert removed == []
        assert "open to the LAN again" not in output


@needs_pwsh
class TestApply:
    def test_the_plan_warns_about_other_block_rules(self, tmp_path: Path) -> None:
        output, _ = run(tmp_path, [rule(B054)], "-LanPrefix", "192.168.0.0/24", "-WhatIf")

        assert "1 other enabled inbound Block rule(s) on TCP 5000 also exist" in output
        assert B054 in output

    def test_no_warning_when_ours_is_the_only_one(self, tmp_path: Path) -> None:
        output, _ = run(tmp_path, [rule(OURS)], "-LanPrefix", "192.168.0.0/24", "-WhatIf")

        assert "also exist" not in output
