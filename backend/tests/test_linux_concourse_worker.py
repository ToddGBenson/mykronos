"""A Concourse worker on another host registers over the TSA (TheHub #61659, D-181).

The two compose workers reach the TSA as `concourse:2222` on the compose
network. A worker on a Linux box reaches it on this host's LAN address, which
the web node publishes only when .env names it; the install script on the
Linux side pins the release the compose workers run and carries the same
runtime shape. These tests hold the pieces together: the publish, the key
list, the pinned version, the order of the Windows steps and the bundle.

The tests marked `needs_pwsh` run the scripts' own code (the key-list lines
of setup.ps1, the firewall functions of Add-LinuxWorker.ps1) in pwsh and
skip where pwsh is not installed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
SETUP = CONCOURSE / "setup.ps1"
ADD = CONCOURSE / "Add-LinuxWorker.ps1"
INSTALL = CONCOURSE / "linux-worker" / "install-concourse-worker.sh"
README = CONCOURSE / "linux-worker" / "README.md"

PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")


def _compose() -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


def _compose_version() -> str:
    image = _compose()["x-worker"]["image"]
    match = re.search(r"concourse/concourse:(\d+\.\d+\.\d+)", image)
    assert match, image
    return match.group(1)


def _resolve_defaults(text: str) -> str:
    """`${NAME:-default}` as compose reads it with NAME unset."""
    return re.sub(r"\$\{(\w+):-([^}]*)\}", lambda m: m.group(2), text)


def _pwsh(script: str) -> Any:
    """Run `script` in pwsh and parse the JSON it prints last."""
    assert PWSH is not None
    done = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _functions_of(script: Path) -> str:
    """PowerShell that defines every function in `script` without running it."""
    path = str(script).replace("'", "''")
    return (
        "using namespace System.Management.Automation.Language\n"
        f"$ast = [Parser]::ParseFile('{path}', [ref]$null, [ref]$null); "
        "$ast.FindAll({ param($n) $n -is [FunctionDefinitionAst] }, $true) | "
        "ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }; "
    )


class TestTheWebNodePublishesTheTsa:
    def test_on_a_configurable_address_that_defaults_to_loopback(self) -> None:
        ports = [str(p) for p in _compose()["services"]["concourse"]["ports"]]
        tsa = [p for p in ports if p.endswith(":2222")]
        assert tsa == ["${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222"], ports

    def test_nothing_in_the_stack_publishes_beyond_loopback_by_default(self) -> None:
        """Every publish resolves to loopback with .env silent: the TSA's and
        #1166's `${CONCOURSE_BIND:-127.0.0.1}` included. The header's promise stands."""
        for name, service in _compose()["services"].items():
            for port in service.get("ports", []):
                host = _resolve_defaults(str(port)).rsplit(":", 2)[0]
                assert host == "127.0.0.1", (name, port)

    def test_the_tsa_bind_variable_is_documented_as_loopback(self) -> None:
        example = (CONCOURSE / ".env.example").read_text(encoding="utf-8")
        assert re.search(r"^CONCOURSE_TSA_BIND_IP=127\.0\.0\.1\s*$", example, re.M)
        header = SETUP.read_text(encoding="utf-8").split("#>")[0]
        assert "-Rotate also rewrites .env without CONCOURSE_BIND" in header
        assert "CONCOURSE_TSA_BIND_IP" in header

    def test_the_compose_workers_still_reach_the_tsa_on_the_compose_network(self) -> None:
        assert _compose()["x-worker"]["environment"]["CONCOURSE_TSA_HOST"] == "concourse:2222"


class TestSetupKeepsEveryWorkerKey:
    def test_authorized_keys_are_assembled_from_every_worker_pub(self) -> None:
        text = SETUP.read_text(encoding="utf-8")
        assert '-Filter "*_key.pub"' in text
        assert '$notWorkerKeys = @("tsa_host_key.pub", "session_signing_key.pub")' in text
        two_names = (
            'Get-Content (Join-Path $keyDir "worker_key.pub"), '
            '(Join-Path $keyDir "worker2_key.pub")'
        )
        assert two_names not in text

    @needs_pwsh
    def test_the_list_keeps_workers_and_drops_the_host_and_session_keys(
        self, tmp_path: Path
    ) -> None:
        """The exact lines from setup.ps1, run against a temp key directory."""
        text = SETUP.read_text(encoding="utf-8").replace("\r\n", "\n")
        start = text.index('$authorized = Join-Path $keyDir "authorized_worker_keys"')
        tail = "Set-Content -Path $authorized -Encoding ascii"
        end = text.index(tail, start) + len(tail)
        names = ("tsa_host_key", "session_signing_key", "worker_key", "worker2_key", "linux-1_key")
        for name in names:
            pub = f"ssh-ed25519 AAAA{name} {name}\n"
            (tmp_path / f"{name}.pub").write_text(pub, encoding="ascii")
        key_dir = str(tmp_path).replace("'", "''")
        listed = _pwsh(
            f"$keyDir = '{key_dir}'\n{text[start:end]}\n"
            "ConvertTo-Json -Compress @(Get-Content $authorized)"
        )
        kept = sorted(line.split()[-1] for line in listed)
        assert kept == ["linux-1_key", "worker2_key", "worker_key"]

    def test_setup_and_the_windows_script_generate_keys_with_the_pinned_image(self) -> None:
        version = _compose_version()
        for script in (SETUP, ADD):
            text = script.read_text(encoding="utf-8")
            images = set(re.findall(r"concourse/concourse:(\d+\.\d+\.\d+)", text))
            assert images == {version}, (script.name, images)


class TestTheInstallScript:
    def test_pins_the_version_the_compose_workers_run(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        match = re.search(r'^CONCOURSE_VERSION="(\d+\.\d+\.\d+)"$', text, re.M)
        assert match and match.group(1) == _compose_version(), match

    def test_reads_os_release_in_a_subshell(self) -> None:
        """os-release defines VERSION; sourced in place it renamed the install dir
        to "24.04.5 LTS (Noble Numbat)" (container test, 2026-11-13)."""
        text = INSTALL.read_text(encoding="utf-8")
        assert not re.search(r"^\s*\.\s+/etc/os-release", text, re.M)
        assert '$(. /etc/os-release' in text
        assert not re.search(r"(?<![A-Z_])VERSION=", text), "a bare VERSION is os-release's"

    def test_pins_a_sha256_for_each_architecture_it_installs(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        for arch in ("amd64", "arm64"):
            assert re.search(rf'^SHA256_{arch}="[0-9a-f]{{64}}"$', text, re.M), arch
        assert "sha256sum" in text and "sha256 mismatch" in text

    def test_is_strict_bash_with_lf_endings(self) -> None:
        raw = INSTALL.read_bytes()
        assert b"\r" not in raw, "bash on Linux fails on a CRLF line ending"
        assert raw.startswith(b"#!/usr/bin/env bash\n")
        assert b"set -euo pipefail" in raw
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        assert "deploy/concourse/linux-worker/*.sh text eol=lf" in attributes

    def test_the_worker_has_the_compose_workers_shape(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        for setting in (
            'TAG="linux"',
            "CONCOURSE_TSA_PUBLIC_KEY=",
            "CONCOURSE_TSA_WORKER_PRIVATE_KEY=",
            "CONCOURSE_BAGGAGECLAIM_DRIVER=overlay",
            "CONCOURSE_BAGGAGECLAIM_VOLUME_SWEEPER_MAX_IN_FLIGHT=5",
            "CONCOURSE_HEALTHCHECK_BIND_IP=127.0.0.1",
            'DEFAULT_DNS="1.1.1.1,8.8.8.8"',
            "CONCOURSE_CONTAINERD_DNS_SERVER=$DNS_SERVERS",
            "CONCOURSE_GARDEN_DNS_SERVER=$DNS_SERVERS",
        ):
            assert setting in text, setting

    def test_the_resolvers_are_a_setting_and_named_in_the_readme(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        assert '--dns)        DNS_SERVERS="$2"' in text
        assert 'DNS_SERVERS) DNS_SERVERS="$value"' in text
        before_default = text.split('DNS_SERVERS="${DNS_SERVERS:-$DEFAULT_DNS}"')[0]
        assert '"$CONF_DIR/worker.env"' in before_default, "a re-run keeps the installed value"
        readme = README.read_text(encoding="utf-8")
        assert "1.1.1.1 and 8.8.8.8" in readme and "--dns" in readme

    def test_the_work_dir_must_be_on_a_real_filesystem(self) -> None:
        """Overlay volumes on overlayfs fail every task with "failed to create
        volume"; the script names the cause instead (container test, 2026-11-13)."""
        text = INSTALL.read_text(encoding="utf-8")
        assert 'stat -f -c %T "$WORK_DIR"' in text
        assert "overlayfs|tmpfs" in text

    def test_the_unit_retires_the_worker_on_stop_and_owns_its_cgroup(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        assert "KillSignal=SIGUSR2" in text
        assert "KillMode=mixed" in text, "control-group sends SIGUSR2 to containerd and every task"
        assert "Delegate=yes" in text
        assert "Restart=on-failure" in text

    def test_uninstall_keeps_the_work_dir_unless_asked(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        block = text[text.index('if [ "$UNINSTALL" = "yes" ]') : text.index("# ── 1. host checks")]
        guard = block.index('if [ "$REMOVE_WORK_DIR" = "yes" ]')
        assert '"$WORK_DIR"' not in block[:guard]
        assert 'rm -rf "$WORK_DIR"' in block[guard:]

    def test_the_private_key_lands_with_owner_only_permissions(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        assert re.search(r'install -m 0600 "\$KEYS_DIR/worker_key"', text)
        assert 'install -d -m 0700 "$CONF_DIR"' in text


class TestTheWindowsScript:
    def test_is_ascii_like_the_other_setup_scripts(self) -> None:
        raw = ADD.read_bytes()
        assert all(b < 0x80 for b in raw), "Windows PowerShell 5.1 reads a BOM-less file as CP1252"

    def test_supports_whatif(self) -> None:
        assert "SupportsShouldProcess = $true" in ADD.read_text(encoding="utf-8")

    def test_the_firewall_comes_before_anything_that_can_publish_2222(self) -> None:
        text = ADD.read_text(encoding="utf-8")
        order = [
            "# -- 1. the firewall scope",
            "# -- 2. the worker's key pair",
            "# -- 3. the TSA's list",
            "# -- 4. the TSA on the LAN address",
            "# -- 5. the web node",
            "# -- 6. the rest of the bundle",
        ]
        positions = [text.index(marker) for marker in order]
        assert positions == sorted(positions)
        firewall = text[positions[0] : positions[1]]
        assert "nothing was changed" in firewall
        assert "$IUnderstandLanExposure" in firewall
        assert "if ($SkipFirewall -and -not $IUnderstandLanExposure)" in text

    def test_an_existing_rule_that_already_scopes_2222_is_reused(self) -> None:
        text = ADD.read_text(encoding="utf-8")
        start = text.index("# -- 1. the firewall scope")
        firewall = text[start : text.index("# -- 2. the worker's key pair")]
        assert "Get-InboundBlockRule -Port $tsaPort" in firewall
        assert "Test-RangesCovered -Ranges $deny" in firewall
        assert "no rule added" in firewall

    def test_bundles_the_install_script_the_tsa_host_key_and_the_worker_key(self) -> None:
        text = ADD.read_text(encoding="utf-8")
        assert "linux-worker\\install-concourse-worker.sh" in text
        bundle = (
            "'worker_key'",
            "'tsa_host_key.pub'",
            "'install-concourse-worker.sh'",
            "'worker.conf'",
        )
        for item in bundle:
            assert item in text, item
        assert "TSA_HOST=$TsaBindIp`:2222" in text

    def test_the_private_key_is_generated_into_the_bundle_never_keys(self) -> None:
        """keys/ is mounted read-only into the web node and both compose workers."""
        text = ADD.read_text(encoding="utf-8")
        assert "generate-key -t ssh -f /out/worker_key" in text
        assert '-v "${bundle}:/out"' in text
        assert '-v "${KeyDir}:' not in text
        assert "[string]$BundleRoot = (Join-Path $PSScriptRoot 'bundles')" in text
        assert "deploy/concourse/bundles/" in (ROOT / ".gitignore").read_text(encoding="utf-8")
        # A private key the first version left in keys/ is moved out on a re-run.
        assert "Move-Item -LiteralPath $legacyKey -Destination $bundleKey" in text

    def test_scopes_2222_with_a_block_rule_not_an_allow(self) -> None:
        text = ADD.read_text(encoding="utf-8")
        assert "-Direction Inbound -Action Block -Protocol TCP -LocalPort 2222" in text
        assert "Get-DenyRanges" in text

    def test_never_reads_a_private_key_or_env_into_output(self) -> None:
        """Only the .pub is read; .env is rewritten line by line and never echoed."""
        text = ADD.read_text(encoding="utf-8")
        reads = re.findall(r"Get-Content\s+([^\s|)]+)", text)
        for target in reads:
            assert "_key" not in target or target.endswith('.pub"'), target
        assert not re.search(r"Write-Host[^\n]*\$envLines", text)
        assert not re.search(r"Write-Host[^\n]*\$pubLine", text)
        printed = re.search(r"(Write-Host|ShouldProcess)[^\n]*\$wanted", text)
        assert not printed, "prints the .env line"

    def test_the_readme_names_the_three_steps_and_the_limits(self) -> None:
        text = README.read_text(encoding="utf-8")
        for needle in (
            "Add-LinuxWorker.ps1 -LinuxIp",
            "install-concourse-worker.sh",
            "Remove-Item -Recurse .\\bundles\\linux-1-bundle",
            "fly -t mykronos workers",
            "cannot upload a result",
            "--remove-work-dir",
            "KillMode=mixed",
            "D-181",
        ):
            assert needle in text, needle


@needs_pwsh
class TestTheWindowsScriptsFirewallArithmetic:
    """The functions of Add-LinuxWorker.ps1, defined from its AST and run."""

    def _run(self, body: str) -> Any:
        return _pwsh(_functions_of(ADD) + body)

    def test_the_deny_ranges_leave_exactly_the_worker_out(self) -> None:
        got = self._run(
            "ConvertTo-Json -Compress @("
            "Get-DenyRanges -Address 192.0.2.10 -PrefixLength 24 -Except 192.0.2.50)"
        )
        assert got == ["192.0.2.1-192.0.2.49", "192.0.2.51-192.0.2.254"]

    def test_an_existing_rule_that_carves_the_runner_out_is_recognised(self) -> None:
        """A rule like the operator's app-ports rule, as Windows reports it."""
        got = self._run(
            "$deny = @(Get-DenyRanges -Address 192.0.2.10 -PrefixLength 24 -Except 192.0.2.50); "
            "$carved = @('192.0.2.0-192.0.2.49', '192.0.2.51-192.0.2.255'); "
            "$whole = @('192.0.2.0/255.255.255.0'); "
            "$other = @('198.51.100.0/24'); "
            "ConvertTo-Json -Compress @("
            "(Test-RangesCovered -Ranges $deny -Entries $carved), "
            "(Test-AddressInEntries -Address 192.0.2.50 -Entries $carved), "
            "(Test-RangesCovered -Ranges $deny -Entries $whole), "
            "(Test-AddressInEntries -Address 192.0.2.50 -Entries $whole), "
            "(Test-RangesCovered -Ranges $deny -Entries $other), "
            "(Test-RangesCovered -Ranges $deny -Entries @('LocalSubnet')))"
        )
        assert got == [True, False, True, True, False, False]

    def test_ports_and_profiles_are_read_as_windows_reports_them(self) -> None:
        got = self._run(
            "ConvertTo-Json -Compress @("
            "(Test-PortEntriesInclude -Port 2222 -Entries @('8000', '2222', '9000')), "
            "(Test-PortEntriesInclude -Port 2222 -Entries @('2000-3000')), "
            "(Test-PortEntriesInclude -Port 2222 -Entries @('Any')), "
            "(Test-PortEntriesInclude -Port 2222 -Entries @('8000', '8100')), "
            "(Test-ProfileApplies -RuleProfile 'Any' -Category 'Public'), "
            "(Test-ProfileApplies -RuleProfile 'Private, Public' -Category 'Private'), "
            "(Test-ProfileApplies -RuleProfile 'Domain' -Category 'Private'))"
        )
        assert got == [True, True, True, False, True, True, False]
