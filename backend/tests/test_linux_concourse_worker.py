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
import sys
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
WRAPPER = CONCOURSE / "linux-worker" / "cgroup-wrapper.sh"
WORKER_COMPOSE = CONCOURSE / "linux-worker" / "docker-compose.yml"
WORKER_ENV_EXAMPLE = CONCOURSE / "linux-worker" / ".env.example"
DNS_CHECK_TASK = CONCOURSE / "linux-worker" / "check-job-dns.yml"

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
            'DEFAULT_DNS="8.8.8.8,1.1.1.1"',
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
        assert "8.8.8.8 and 1.1.1.1, in that order" in readme and "--dns" in readme

    def test_the_first_default_resolver_is_one_this_lan_answers(self) -> None:
        """UDP/53 to 1.1.1.1 timed out from a Linux box on this LAN (2026-11-16)
        while 8.8.8.8 answered; with 1.1.1.1 first, every task-container lookup
        waited out a timeout before the second resolver."""
        text = INSTALL.read_text(encoding="utf-8")
        default = text.split('DEFAULT_DNS="', 1)[1].split('"', 1)[0].split(",")
        assert default[0] == "8.8.8.8", default
        assert "1.1.1.1" in default, "the second resolver is kept as a fallback"
        readme = README.read_text(encoding="utf-8")
        assert "timed out" in readme and "8.8.8.8 comes first" in readme

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


class TestTheDockerWorkerWrapper:
    """[#62024] The Docker-run worker's entrypoint wrapper lives in the repo.

    linux-3 restart-looped 1775 times because /run/containerd outlived a
    reboot in the container's writable layer. The wrapper clears it on every
    start, and it carries the cgroup delegation of #61894, so every Docker-run
    worker gets both from one file instead of a hand-kept copy per host.
    """

    def test_is_posix_sh_with_lf_endings_and_ascii(self) -> None:
        raw = WRAPPER.read_bytes()
        assert raw.startswith(b"#!/bin/sh\n"), "the image has no bash at dumb-init time"
        assert b"\r" not in raw
        assert all(b < 0x80 for b in raw)
        assert b"\nset -eu\n" in raw

    def test_clears_the_containerd_state_before_the_image_entrypoint(self) -> None:
        lines = [ln.strip() for ln in WRAPPER.read_text(encoding="utf-8").splitlines()]
        clear = next(i for i, ln in enumerate(lines) if ln.startswith("rm -rf /run/containerd"))
        start = lines.index('exec /usr/local/bin/entrypoint.sh "$@"')
        assert clear < start
        assert start == max(i for i, ln in enumerate(lines) if ln), "exec is the last step"

    def test_delegates_every_controller_from_an_emptied_root(self) -> None:
        text = WRAPPER.read_text(encoding="utf-8")
        assert "/sys/fs/cgroup/init/cgroup.procs" in text
        assert "/sys/fs/cgroup/cgroup.subtree_control" in text

    def test_the_readme_names_the_wrapper_the_stale_state_and_the_rollout(self) -> None:
        readme = README.read_text(encoding="utf-8")
        assert '"/cgroup-wrapper.sh"' in readme
        assert "/run/containerd" in readme and "--force-recreate" in readme
        assert "hand-kept" in readme and "linux-3" in readme


class TestTheDockerWorkersResolveThroughTheRouterFirst:
    """[#62067] Job containers on the Docker-run workers ask the LAN resolver first.

    With only Docker's embedded resolver (127.0.0.11) the job containers fell
    through to 8.8.8.8 with no local cache, and every upstream loss failed a
    `pip install` with NameResolutionError. The reference compose in the repo
    takes the router, the ISP resolver and 8.8.8.8 from a local `.env`, in that
    order, for all of linux-1, linux-2 and linux-3. The mykronos repo is
    public, so no LAN address may be committed: the file names variables only.
    """

    def _services(self) -> dict[str, Any]:
        doc = cast("dict[str, Any]", yaml.safe_load(WORKER_COMPOSE.read_text(encoding="utf-8")))
        return cast("dict[str, Any]", doc["services"])

    def test_the_reference_files_exist(self) -> None:
        for path in (WORKER_COMPOSE, WORKER_ENV_EXAMPLE, DNS_CHECK_TASK):
            assert path.is_file(), path

    def test_each_worker_hands_its_task_containers_the_three_resolvers_in_order(self) -> None:
        services = self._services()
        assert set(services) == {"worker-1", "worker-2"}
        for name, service in services.items():
            servers = service["environment"]["CONCOURSE_CONTAINERD_DNS_SERVER"]
            expected = "${WORKER_DNS_1:?},${WORKER_DNS_2:?},${WORKER_DNS_3:-8.8.8.8}"
            assert servers == expected, name
            assert service["dns"] == [
                "${WORKER_DNS_1:?}",
                "${WORKER_DNS_2:?}",
                "${WORKER_DNS_3:-8.8.8.8}",
            ], name

    def test_resolved_with_a_local_env_the_router_is_first_and_google_last(self) -> None:
        local = {"WORKER_DNS_1": "router.example", "WORKER_DNS_2": "isp.example"}

        def fill(text: str) -> str:
            return re.sub(
                r"\$\{(\w+)(?::-([^}]*)|:\?[^}]*)?\}",
                lambda m: local.get(m.group(1), m.group(2) or ""),
                text,
            )

        service = self._services()["worker-1"]
        assert [fill(d) for d in service["dns"]] == ["router.example", "isp.example", "8.8.8.8"]
        env = fill(service["environment"]["CONCOURSE_CONTAINERD_DNS_SERVER"])
        assert env == "router.example,isp.example,8.8.8.8"

    def test_the_resolvers_have_no_default_so_an_unset_env_fails_loudly(self) -> None:
        """A `.env` that is missing must stop `docker compose up`, not fall back to
        Google alone, which is the defect this file removes."""
        text = WORKER_COMPOSE.read_text(encoding="utf-8")
        assert "${WORKER_DNS_1:?" in text and "${WORKER_DNS_2:?" in text
        assert "WORKER_DNS_1:-" not in text and "WORKER_DNS_2:-" not in text

    def test_the_dns_proxy_is_not_used(self) -> None:
        """The proxy forwards to Docker's resolver, which is the path that fell
        through to 8.8.8.8; explicit servers replace it."""
        text = WORKER_COMPOSE.read_text(encoding="utf-8")
        assert "DNS_PROXY" not in text

    def test_the_worker_runs_the_image_and_wrapper_the_compose_workers_run(self) -> None:
        compose_image = _compose()["x-worker"]["image"]
        for name, service in self._services().items():
            assert service["image"] == compose_image, name
            assert service["entrypoint"] == ["dumb-init", "/cgroup-wrapper.sh"], name
            assert "./cgroup-wrapper.sh:/cgroup-wrapper.sh:ro" in service["volumes"], name
            assert service["privileged"] is True, name
            assert service["environment"]["CONCOURSE_TAG"] == "linux", name
            assert service["environment"]["CONCOURSE_RUNTIME"] == "containerd", name

    def test_the_second_worker_is_opt_in_and_has_its_own_name_key_and_state(self) -> None:
        one, two = self._services()["worker-1"], self._services()["worker-2"]
        assert two["profiles"] == ["pair"] and "profiles" not in one
        assert one["environment"]["CONCOURSE_NAME"] != two["environment"]["CONCOURSE_NAME"]
        key = "CONCOURSE_TSA_WORKER_PRIVATE_KEY"
        assert one["environment"][key] != two["environment"][key]
        assert set(one["volumes"]) & set(two["volumes"]) == {
            "./cgroup-wrapper.sh:/cgroup-wrapper.sh:ro",
            "./keys/tsa_host_key.pub:/keys/tsa_host_key.pub:ro",
        }

    def test_the_example_env_names_the_three_resolvers_and_commits_no_lan_address(self) -> None:
        values = dict(
            line.split("=", 1)
            for line in WORKER_ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        )
        assert values["WORKER_DNS_1"] == "" and values["WORKER_DNS_2"] == ""
        assert values["WORKER_DNS_3"] == "8.8.8.8"
        assert values["CHECK_HOSTS"] == ""

    def test_no_file_of_the_worker_config_commits_a_lan_address(self) -> None:
        """mykronos is public. Only loopback and the public resolvers may appear."""
        allowed = {"8.8.8.8", "1.1.1.1", "8.8.4.4", "127.0.0.1", "127.0.0.11", "127.0.0.53"}
        allowed.add("0.0.0.0")  # noqa: S104 - a bind address named in the README, not a listener
        for path in (WORKER_COMPOSE, WORKER_ENV_EXAMPLE, DNS_CHECK_TASK, README, INSTALL):
            text = path.read_text(encoding="utf-8")
            found = set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text))
            assert found <= allowed, (path.name, sorted(found - allowed))

    def test_the_env_file_itself_is_never_tracked(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert ".env" in ignore and "!.env.example" in ignore
        assert not (CONCOURSE / "linux-worker" / ".env").exists()

    def test_the_check_task_prints_the_job_resolver_order_and_resolves_each_host(self) -> None:
        task = cast("dict[str, Any]", yaml.safe_load(DNS_CHECK_TASK.read_text(encoding="utf-8")))
        assert task["platform"] == "linux"
        assert "CHECK_HOSTS" in task["params"]
        script = "\n".join(task["run"]["args"])
        assert "/etc/resolv.conf" in script, "the job container's own resolver list is shown"
        assert "nslookup" in script and "CHECK_HOSTS" in script
        assert "registry-1.docker.io" in script, "the Docker Hub name is always checked"
        source = task["image_resource"]["source"]
        assert source["repository"] == "curlimages/curl" and source["tag"] == "8.11.1"

    def test_the_readme_documents_one_config_for_all_three_workers(self) -> None:
        readme = README.read_text(encoding="utf-8")
        for needle in (
            "WORKER_DNS_1",
            "WORKER_DNS_3",
            "linux-1",
            "linux-2",
            "linux-3",
            "docker compose config",
            "execute --tag linux",
            "check-job-dns.yml",
            "NameResolutionError",
            "router first",
        ):
            assert needle in readme, needle
        assert "linux-1 and linux-2 use the proxy since 2026-11-16" not in readme


# The wrapper only ever runs in a Linux container. On Windows, Git Bash's sh
# gets backslash paths from tmp_path and cannot exec the fake entrypoint, so
# the runs are skipped there, visibly, rather than reported as wrapper defects.
needs_posix_sh = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="runs the wrapper under a POSIX sh; the wrapper is Linux-only",
)


class _FakeWorker:
    """A fake container start: cgroup root, /run/containerd, /proc, mounts."""

    def __init__(self, tmp_path: Path, controllers: str = "cpu memory pids") -> None:
        self.cg = tmp_path / "cgroup"
        self.cg.mkdir()
        (self.cg / "cgroup.controllers").write_text(controllers + "\n", encoding="utf-8")
        (self.cg / "cgroup.procs").write_text("", encoding="utf-8")
        self.run = tmp_path / "run" / "containerd"
        task = self.run / "io.containerd.runtime.v2.task" / "concourse" / "dead"
        task.mkdir(parents=True)
        (task / "init.pid").write_text("4242\n", encoding="utf-8")
        self.proc = tmp_path / "proc"
        (self.proc / "1").mkdir(parents=True)
        (self.proc / "1" / "comm").write_text("dumb-init\n", encoding="utf-8")
        self.mounts = tmp_path / "mounts"
        self.mounts.write_text("overlay / overlay rw 0 0\n", encoding="utf-8")
        self.entry = tmp_path / "entrypoint.sh"
        self.entry.write_text(
            f'#!/bin/sh\n[ -e "{self.run}/io.containerd.runtime.v2.task" ]'
            ' && echo STALE || echo CLEAN\necho "args=$*"\n',
            encoding="utf-8",
        )
        self.entry.chmod(0o755)

    def start(self) -> subprocess.CompletedProcess[str]:
        script = (
            WRAPPER.read_text(encoding="utf-8")
            .replace("/sys/fs/cgroup", str(self.cg))
            .replace("/run/containerd", str(self.run))
            .replace("/proc/[0-9]*/comm", f"{self.proc}/[0-9]*/comm")
            .replace("/proc/self/mounts", str(self.mounts))
            .replace("/usr/local/bin/entrypoint.sh", str(self.entry))
        )
        return subprocess.run(
            ["sh", "-c", script, "cgroup-wrapper.sh", "worker"],
            capture_output=True,
            text=True,
            check=True,
        )


@needs_posix_sh
class TestTheDockerWorkerWrapperRuns:
    def test_a_start_removes_stale_state_and_hands_over_its_arguments(self, tmp_path: Path) -> None:
        w = _FakeWorker(tmp_path)
        run = w.start()
        assert "CLEAN" in run.stdout and "args=worker" in run.stdout
        assert not w.run.exists()
        assert run.stderr == ""
        assert (w.cg / "cgroup.subtree_control").read_text(encoding="utf-8").split() == [
            "+cpu",
            "+memory",
            "+pids",
        ]

    def test_every_root_pid_is_moved_and_a_root_that_keeps_one_is_reported(
        self, tmp_path: Path
    ) -> None:
        w = _FakeWorker(tmp_path)
        # A plain file never drains the way the kernel's cgroup.procs does, so
        # the root keeps its pids: the loop runs all five passes, then warns.
        (w.cg / "cgroup.procs").write_text("7\n8\n", encoding="utf-8")
        run = w.start()
        assert (w.cg / "init" / "cgroup.procs").read_text(encoding="utf-8").split() == ["8"]
        assert "still holds pids 7 8" in run.stderr

    def test_empty_controllers_are_reported_not_written_as_a_bare_plus(
        self, tmp_path: Path
    ) -> None:
        w = _FakeWorker(tmp_path, controllers="")
        run = w.start()
        assert "cgroup.controllers is empty" in run.stderr
        assert not (w.cg / "cgroup.subtree_control").exists()
        assert "CLEAN" in run.stdout

    def test_a_live_containerd_keeps_its_state(self, tmp_path: Path) -> None:
        w = _FakeWorker(tmp_path)
        (w.proc / "99").mkdir()
        (w.proc / "99" / "comm").write_text("containerd\n", encoding="utf-8")
        run = w.start()
        assert "STALE" in run.stdout, "a hand run in a live worker must not delete live state"
        assert "containerd is running" in run.stderr

    def test_a_mountpoint_is_emptied_not_removed(self, tmp_path: Path) -> None:
        w = _FakeWorker(tmp_path)
        w.mounts.write_text(
            f"overlay / overlay rw 0 0\ntmpfs {w.run} tmpfs rw 0 0\n", encoding="utf-8"
        )
        run = w.start()
        assert "CLEAN" in run.stdout and "emptied" in run.stdout
        assert w.run.is_dir() and not any(w.run.iterdir())


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
