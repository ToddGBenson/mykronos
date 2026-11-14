"""A Concourse worker on another host registers over the TSA (TheHub #61659, D-178).

The two compose workers reach the TSA as `concourse:2222` on the compose
network. A worker on a Linux box reaches it on this host's LAN address, which
the web node publishes only when .env names it; the install script on the
Linux side pins the release the compose workers run and carries the same
runtime shape. These tests hold the pieces together: the publish, the key
list, the pinned version and the bundle the Windows script writes.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
SETUP = CONCOURSE / "setup.ps1"
ADD = CONCOURSE / "Add-LinuxWorker.ps1"
INSTALL = CONCOURSE / "linux-worker" / "install-concourse-worker.sh"
README = CONCOURSE / "linux-worker" / "README.md"


def _compose() -> dict[str, Any]:
    return cast("dict[str, Any]", yaml.safe_load(COMPOSE.read_text(encoding="utf-8")))


def _compose_version() -> str:
    image = _compose()["x-worker"]["image"]
    match = re.search(r"concourse/concourse:(\d+\.\d+\.\d+)", image)
    assert match, image
    return match.group(1)


class TestTheWebNodePublishesTheTsa:
    def test_on_a_configurable_address_that_defaults_to_loopback(self) -> None:
        ports = [str(p) for p in _compose()["services"]["concourse"]["ports"]]
        tsa = [p for p in ports if p.endswith(":2222")]
        assert tsa == ["${CONCOURSE_TSA_BIND_IP:-127.0.0.1}:2222:2222"], ports

    def test_nothing_else_in_the_stack_publishes_beyond_loopback_by_default(self) -> None:
        """The LAN-facing publish is the TSA alone; the header's promise stands."""
        for name, service in _compose()["services"].items():
            for port in service.get("ports", []):
                host = str(port).rsplit(":", 2)[0]
                assert host in ("127.0.0.1", "${CONCOURSE_TSA_BIND_IP:-127.0.0.1}"), (name, port)

    def test_the_compose_workers_still_reach_the_tsa_on_the_compose_network(self) -> None:
        assert _compose()["x-worker"]["environment"]["CONCOURSE_TSA_HOST"] == "concourse:2222"


class TestSetupKeepsEveryWorkerKey:
    def test_authorized_keys_are_assembled_from_every_worker_pub(self) -> None:
        text = SETUP.read_text(encoding="utf-8")
        assert '-Filter "*_key.pub"' in text
        assert '$_.Name -ne "tsa_host_key.pub"' in text
        two_names = (
            'Get-Content (Join-Path $keyDir "worker_key.pub"), '
            '(Join-Path $keyDir "worker2_key.pub")'
        )
        assert two_names not in text

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
            "CONCOURSE_CONTAINERD_DNS_SERVER=1.1.1.1,8.8.8.8",
            "CONCOURSE_GARDEN_DNS_SERVER=1.1.1.1,8.8.8.8",
        ):
            assert setting in text, setting

    def test_the_work_dir_must_be_on_a_real_filesystem(self) -> None:
        """Overlay volumes on overlayfs fail every task with "failed to create
        volume"; the script names the cause instead (container test, 2026-11-13)."""
        text = INSTALL.read_text(encoding="utf-8")
        assert 'stat -f -c %T "$WORK_DIR"' in text
        assert "overlayfs|tmpfs" in text

    def test_the_unit_retires_the_worker_on_stop_and_owns_its_cgroup(self) -> None:
        text = INSTALL.read_text(encoding="utf-8")
        assert "KillSignal=SIGUSR2" in text
        assert "Delegate=yes" in text
        assert "Restart=on-failure" in text

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

    def test_the_readme_names_the_three_steps_and_the_limits(self) -> None:
        text = README.read_text(encoding="utf-8")
        for needle in (
            "Add-LinuxWorker.ps1 -LinuxIp",
            "install-concourse-worker.sh",
            "fly -t mykronos workers",
            "cannot upload a result",
            "D-178",
        ):
            assert needle in text, needle
