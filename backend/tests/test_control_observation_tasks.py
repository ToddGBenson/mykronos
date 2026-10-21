"""The scheduled host and LAN collectors keep their tokens out of the task (TheHub #60834).

An observation lowers an environmental score only while it is fresh (14 days,
`control_observations.FRESH_DAYS`), so the host and LAN collectors run daily
from Scheduled Tasks that `Register-ControlObservationTasks.ps1` registers, and
each task runs `Invoke-ControlObservationCollector.ps1`. These pin:

  * the task's argument line names the `.env` KEY of each token, never a value;
  * the collector reads the tokens from that file at run time and sends them as
    headers, and neither the console nor its log file ever holds one;
  * a missing token, or a LAN run without a range or an authorization
    (spec 14 section 3), is a refusal (exit 2) before anything is collected;
  * the in-process internet collector (`exposure`) runs well inside the window.

`docker` is shadowed by a function, as in test_backup_scripts.py, and the
observations are posted to a local stub server, so nothing real is read or
written.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mykronos import control_observations, exposure, main
from mykronos.config import Settings

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
INVOKE = CONCOURSE / "Invoke-ControlObservationCollector.ps1"
REGISTER = CONCOURSE / "Register-ControlObservationTasks.ps1"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")
needs_scheduled_tasks = pytest.mark.skipif(
    sys.platform != "win32", reason="New-ScheduledTask* exists only on Windows"
)

# Test-only values. If either appears in any output, a token leaked.
TOKEN = "test-ingestion-token-7f3a9c"
GATE = "test-gate-token-51be02"

CONTAINER = (
    '[{"Name": "/mykronos-backend", "NetworkSettings": {"Ports": '
    '{"8100/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8100"}]}}}]'
)

DOCKER_MOCK = r"""
function global:docker {
  $global:LASTEXITCODE = 0
  switch ($args[0]) {
    'ps'      { 'mykronos-backend' }
    'inspect' { 'CONTAINER' }
    default   { $global:LASTEXITCODE = 99; 'unexpected docker call' }
  }
}
""".replace("CONTAINER", CONTAINER)


def pwsh(program: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("MYKRONOS_")}
    # The publisher defaults its cloudflared config to %USERPROFILE%; point it
    # at an empty directory so a developer's real tunnel config is never read.
    env["USERPROFILE"] = str(tmp_path)
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        env=env,
    )


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / "backend.env"
    path.write_text(
        f'# comment\nMYKRONOS_CONCOURSE_TOKEN={TOKEN}\nMYKRONOS_GATE_TOKEN="{GATE}"\n',
        encoding="ascii",
    )
    return path


def invoke(
    tmp_path: Path, env_file: Path, *args: str, url: str = "http://127.0.0.1:9"
) -> tuple[int, str]:
    program = (
        DOCKER_MOCK
        + f"& '{INVOKE}' -EnvFile '{env_file}' -LogDir '{tmp_path / 'logs'}' -MykronosUrl '{url}' "
        + " ".join(args)
        + ' *>&1 | ForEach-Object { "$_" }\nexit $LASTEXITCODE\n'
    )
    out = pwsh(program, tmp_path)
    return out.returncode, out.stdout + out.stderr


def assert_no_token(text: str) -> None:
    assert TOKEN not in text and GATE not in text


@needs_pwsh
class TestTheCollector:
    def test_a_dry_run_checks_the_keys_and_prints_no_token(
        self, tmp_path: Path, env_file: Path
    ) -> None:
        code, output = invoke(
            tmp_path,
            env_file,
            "-Collector host -Repo ToddGBenson/mykronos",
            "-TokenKey MYKRONOS_CONCOURSE_TOKEN -DryRun",
        )
        assert code == 0, output
        assert "MYKRONOS_CONCOURSE_TOKEN (present)" in output
        assert "MYKRONOS_GATE_TOKEN (present)" in output
        assert_no_token(output)
        assert not (tmp_path / "logs").exists(), "a dry run writes nothing"

    def test_a_missing_token_key_is_a_refusal(self, tmp_path: Path, env_file: Path) -> None:
        code, output = invoke(
            tmp_path,
            env_file,
            "-Collector host -Repo ToddGBenson/TheHub",
            "-TokenKey MYKRONOS_THEHUB_CONCOURSE_TOKEN",
        )
        assert code == 2, output
        assert "MYKRONOS_THEHUB_CONCOURSE_TOKEN is not set" in output
        log = (tmp_path / "logs" / "last-host-ToddGBenson_TheHub.log").read_text(encoding="ascii")
        assert "refused" in log

    @pytest.mark.parametrize(
        "lan_args, reason",
        [
            ("-Cidr 192.168.0.14/32", "no -AuthorizationReference"),
            ("-AuthorizationReference 'CHG-1: test'", "no -Cidr"),
        ],
    )
    def test_the_lan_scan_refuses_without_a_range_and_an_authorization(
        self, tmp_path: Path, env_file: Path, lan_args: str, reason: str
    ) -> None:
        code, output = invoke(
            tmp_path,
            env_file,
            "-Collector lan -Repo ToddGBenson/mykronos",
            f"-TokenKey MYKRONOS_CONCOURSE_TOKEN {lan_args}",
        )
        assert code == 2, output
        assert reason in output

    def test_one_comma_separated_cidr_argument_is_several_ranges(
        self, tmp_path: Path, env_file: Path
    ) -> None:
        # How the scheduled task passes them: one quoted argument.
        code, output = invoke(
            tmp_path,
            env_file,
            "-Collector lan -Repo ToddGBenson/mykronos",
            "-TokenKey MYKRONOS_CONCOURSE_TOKEN -AuthorizationReference 'CHG-1: test'",
            "-Cidr '192.168.0.14/32,192.168.0.20/32' -DryRun",
        )
        assert "would scan: 192.168.0.14/32, 192.168.0.20/32" in output, output

    def test_the_host_run_sends_the_tokens_as_headers_and_logs_neither(
        self, tmp_path: Path, env_file: Path, stub: dict[str, Any]
    ) -> None:
        code, output = invoke(
            tmp_path,
            env_file,
            "-Collector host -Repo ToddGBenson/mykronos",
            "-TokenKey MYKRONOS_CONCOURSE_TOKEN -ContainerFilter 'mykronos-*'",
            url=stub["url"],
        )
        assert code == 0, output
        assert stub["path"] == "/api/ingest/control-observations"
        assert stub["headers"]["Authorization"] == f"Bearer {TOKEN}"
        assert stub["headers"]["X-Hub-Token"] == GATE
        body = stub["body"]
        assert body["host_document"]["schema"] == "mykronos.host-observations/1"
        assert [c["name"] for c in body["host_document"]["docker"]["containers"]] == [
            "mykronos-backend"
        ]
        log = (tmp_path / "logs" / "last-host-ToddGBenson_mykronos.log").read_text(encoding="ascii")
        assert "result: ok" in log
        assert_no_token(output)
        assert_no_token(log)


@pytest.fixture
def stub() -> Iterator[dict[str, Any]]:
    """A local HTTP server that records one POST and answers like ingest."""
    seen: dict[str, Any] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - the stdlib's name
            length = int(self.headers.get("Content-Length") or 0)
            seen["path"] = self.path
            seen["headers"] = dict(self.headers)
            seen["body"] = json.loads(self.rfile.read(length) or b"{}")
            payload = b'{"recorded": 1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    seen["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield seen
    finally:
        server.shutdown()
        server.server_close()


@needs_pwsh
@needs_scheduled_tasks
class TestTheRegistration:
    def register(self, tmp_path: Path, env_file: Path, *args: str) -> tuple[int, str]:
        program = (
            DOCKER_MOCK
            + f"& '{REGISTER}' -WhatIf -Verbose -EnvFile '{env_file}' "
            + " ".join(args)
            + ' *>&1 | ForEach-Object { "$_" }\nexit $LASTEXITCODE\n'
        )
        out = pwsh(program, tmp_path)
        return out.returncode, out.stdout + out.stderr

    def test_the_task_names_the_key_and_never_the_token(
        self, tmp_path: Path, env_file: Path
    ) -> None:
        code, output = self.register(
            tmp_path,
            env_file,
            "-LanCidr 192.168.0.14/32 -LanAuthorizationReference 'CHG-1: test'",
        )
        assert code == 0, output
        assert "What if" in output
        assert "Mykronos Observations (host, ToddGBenson_mykronos)" in output
        assert "Mykronos Observations (LAN, ToddGBenson_mykronos)" in output
        assert '-TokenKey "MYKRONOS_CONCOURSE_TOKEN"' in output
        assert_no_token(output)

    def test_no_task_name_carries_a_slash(
        self, tmp_path: Path, env_file: Path
    ) -> None:
        # Task Scheduler refuses '/' in a name, and -WhatIf never asks it, so
        # "(host, ToddGBenson/mykronos)" passed here and failed on the first
        # real registration (2026-10-20).
        code, output = self.register(
            tmp_path,
            env_file,
            "-HostRepo ToddGBenson/mykronos,ToddGBenson/TheHub "
            "-LanCidr 192.168.0.14/32 -LanAuthorizationReference 'CHG-1: test'",
        )
        assert code == 0, output
        names = re.findall(r'on target "([^"]+)"', output)
        assert len(names) == 3, output
        for name in names:
            assert "/" not in name and "\\" not in name, name

    def test_no_range_means_no_lan_task(self, tmp_path: Path, env_file: Path) -> None:
        code, output = self.register(tmp_path, env_file)
        assert code == 0, output
        assert "LAN task: not registered" in output
        assert "(LAN," not in output

    def test_a_range_without_an_authorization_is_refused(
        self, tmp_path: Path, env_file: Path
    ) -> None:
        code, output = self.register(tmp_path, env_file, "-LanCidr 192.168.0.14/32")
        assert code != 0
        assert "spec 14 section 3" in output


class TestTheInternetCollectorIsScheduled:
    def test_exposure_runs_every_six_hours_and_sweeps(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, Any] = {}

        async def record(name: str, interval: int, job: Any, db: Any = None) -> None:
            captured[name] = (interval, job, db)

        monkeypatch.setattr(main, "_every", record)
        swept: list[Any] = []

        async def fake_sweep(db: Any, **_: Any) -> list[dict[str, Any]]:
            swept.append(db)
            return []

        monkeypatch.setattr(exposure, "run_sweep", fake_sweep)
        settings = settings.model_copy(update={"run_jobs_in_background": True})
        with TestClient(main.create_app(settings)) as client:
            interval, job, db = captured["exposure"]
            # Four runs a day; a lowering lapses only after FRESH_DAYS of none.
            assert interval == 21_600 < control_observations.FRESH_DAYS * 86_400
            assert db is client.app.state.db
            asyncio.run(job())
        assert len(swept) == 1
