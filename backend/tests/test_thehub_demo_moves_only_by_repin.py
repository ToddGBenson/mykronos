"""The demo's images move only by a reviewed re-pin of production (TheHub #62399).

The demo (gate off, tunnelled) ran TheHub's patched postgres and redis by TAG,
and the image-refresh lane redeployed it on newer tags by publishing
`<sha>+p<date>`, which the host poller turned into
`Invoke-TheHubDeploy -PatchDate`. TheHub #784 (#61949) pins the demo's patched
images to production's `<tag>@sha256` pins and adds
`publish-patched-images.sh --check-demo`, which refuses a moved, missing or
unpinned tag. Operator decision 2026-11-28, option (a): the lane stops
redeploying the demo, and the demo gets newer images only when production's
pin moves by a reviewed change.

So, here:

1. image-refresh builds, scans and publishes, and deploys nothing; no job
   requests a `+p<date>` deploy.
2. The poller never passes a patch date. A `+p<date>` pointer left in the
   bucket is refused once, recorded so it is not retried, and never deployed;
   one the host already serves is acknowledged as before.
3. `Invoke-TheHubDeploy -Environment demo` runs `--check-demo` before it
   changes anything and stops on non-zero, refuses a script that predates the
   mode (its default mode builds and pushes), and runs the backend by digest.

The scripts are driven in pwsh the way test_backup_scripts.py drives its own:
`docker` and Git Bash are stubs that record their calls, and the release
bucket is a fake S3 endpoint on loopback. Nothing here deploys.
"""

from __future__ import annotations

import http.server
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"
POLLER = ROOT / "deploy" / "thehub" / "Invoke-RegistryPullDeploy.ps1"
DEPLOYER = ROOT / "deploy" / "thehub" / "Invoke-TheHubDeploy.ps1"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")

SHA = "8affe0c2b37f4a8bccb99ff8324f2d57e19cf176"
REGISTRY = "registry.test:5000"
DIGEST = "sha256:" + "d" * 64
IMAGE_ID = "sha256:" + "e" * 64


# -- 1. the lane --------------------------------------------------------------


def _jobs() -> dict[str, dict[str, Any]]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return {j["name"]: j for j in doc["jobs"]}


def _steps(plan: Any) -> Iterator[dict[str, Any]]:
    for step in plan or []:
        if not isinstance(step, dict):
            continue
        yield step
        for key in ("do", "in_parallel", "aggregate"):
            inner = step.get(key)
            if isinstance(inner, dict):
                inner = inner.get("steps")
            yield from _steps(inner)
        for key in ("try", "ensure"):
            if isinstance(step.get(key), dict):
                yield from _steps([step[key]])


def test_image_refresh_publishes_and_deploys_nothing():
    job = _jobs()["image-refresh"]
    tasks = [s["task"] for s in _steps(job["plan"]) if "task" in s]
    # Still the lane it was: rebuild, scan, judge, publish.
    assert {"plan", "build", "scan", "decide", "publish"} <= set(tasks), tasks
    assert "deploy-demo" not in tasks, "image-refresh redeploys the demo again (TheHub #62399)"
    plan = yaml.safe_dump(job["plan"])
    assert "demo.requested" not in plan
    # The release bucket's credential is what writes a deploy pointer; a job
    # that requests no deploy holds none.
    assert "((minio-" not in plan and "RELEASE_BUCKET" not in plan


def test_no_job_requests_a_patch_date_deploy():
    """`<sha>+p<date>` was the image-refresh lane's demo request."""
    for name, job in _jobs().items():
        text = yaml.safe_dump(job.get("plan"))
        assert not re.search(r"\+p\$\{?DATE", text), f"{name} still requests a +p<date> deploy"


def test_neither_script_carries_a_patch_date_path():
    """Code, not prose: the behaviour is driven in sections 2 and 3."""
    for path in (POLLER, DEPLOYER):
        src = path.read_text(encoding="ascii")
        for code in ("$PatchDate", '["PatchDate"]', "$env:THEHUB_DEMO_PATCH_DATE", "Set-PatchDate"):
            assert code not in src, f"{path.name} still carries {code}"


# -- 2. the poller ------------------------------------------------------------


class _Bucket(http.server.BaseHTTPRequestHandler):
    """The release bucket: GET and PUT of `/thehub-releases/<name>`."""

    store: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 -- http.server's name
        body = self.store.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.store[self.path] = self.rfile.read(length).decode()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def bucket() -> Iterator[tuple[str, dict[str, str]]]:
    store: dict[str, str] = {}
    handler = type("Bucket", (_Bucket,), {"store": store})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", store
    finally:
        server.shutdown()
        server.server_close()


# Stands in for Invoke-TheHubDeploy.ps1 next to the poller: records how it
# was called. PatchDate is declared so the poller as it was can bind it.
DEPLOY_STUB = """param(
    [string]$Environment, [string]$Sha, [int]$TimeoutMinutes,
    [switch]$Rebuild, [string]$PatchDate
)
$line = "env={0} sha={1} rebuild={2} patchdate={3}" -f $Environment, $Sha, [bool]$Rebuild,
    $PatchDate
Add-Content -Path (Join-Path $PSScriptRoot 'deploy-calls.log') -Value $line
exit 0
"""


def _poller(tmp_path: Path) -> Path:
    here = tmp_path / "deploy" / "thehub"
    here.mkdir(parents=True)
    (tmp_path / "deploy" / "concourse").mkdir()
    (tmp_path / "deploy" / "concourse" / ".env").write_text(
        "MINIO_ROOT_USER=poller-test\nMINIO_ROOT_PASSWORD=poller-test\n", encoding="ascii"
    )
    shutil.copy(POLLER, here / POLLER.name)
    (here / DEPLOYER.name).write_text(DEPLOY_STUB, encoding="ascii")
    return here


def _cycle(here: Path, endpoint: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(here / POLLER.name),
         "-Once", "-Endpoint", endpoint],
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )


def _deploys(here: Path) -> list[str]:
    log = here / "deploy-calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


@needs_pwsh
def test_a_patch_date_pointer_is_refused_once_and_never_deployed(tmp_path, bucket):
    endpoint, store = bucket
    here = _poller(tmp_path)
    store["/thehub-releases/demo.requested"] = f"{SHA}+p20261124"

    first = _cycle(here, endpoint)
    assert _deploys(here) == [], "a +p<date> pointer reached the deploy script"
    assert first.returncode == 1, first.stdout + first.stderr
    assert "#62399" in first.stdout, first.stdout
    assert (here / ".failed-demo").read_text(encoding="ascii") == f"{SHA}+p20261124"
    assert "/thehub-releases/demo.deployed" not in store

    # Recorded, so the next cycle neither retries it nor goes red again.
    second = _cycle(here, endpoint)
    assert second.returncode == 0, second.stdout + second.stderr
    assert _deploys(here) == []


@needs_pwsh
def test_a_patch_date_the_host_already_serves_is_acknowledged_not_redeployed(tmp_path, bucket):
    """The host's state on 2026-11-28: the last refresh is what demo runs."""
    endpoint, store = bucket
    here = _poller(tmp_path)
    store["/thehub-releases/demo.requested"] = f"{SHA}+p20261124"
    (here / ".deployed-demo").write_text(f"{SHA}+p20261124", encoding="ascii")

    out = _cycle(here, endpoint)
    assert out.returncode == 0, out.stdout + out.stderr
    assert _deploys(here) == []
    assert store["/thehub-releases/demo.deployed"] == f"{SHA}+p20261124"


@needs_pwsh
def test_a_plain_sha_still_rebuilds_the_demo_with_no_patch_date(tmp_path, bucket):
    endpoint, store = bucket
    here = _poller(tmp_path)
    store["/thehub-releases/demo.requested"] = SHA

    out = _cycle(here, endpoint)
    assert out.returncode == 0, out.stdout + out.stderr
    assert _deploys(here) == [f"env=demo sha={SHA} rebuild=True patchdate="]
    assert store["/thehub-releases/demo.deployed"] == SHA


# -- 3. the demo deploy -------------------------------------------------------

# An excerpt that names the mode, which is all the deploy reads of the script
# before it runs it. The script itself never runs here: THEHUB_BASH is a stub.
CHECK_DEMO_SCRIPT = 'MODE="${1:-publish}"\nif [ "$MODE" = "--check-demo" ]; then :; fi\n'
# publish-patched-images.sh before TheHub #784: its default mode builds and pushes.
PRE_784_SCRIPT = 'MODE="${1:-publish}"\nif [ "$MODE" = "--check" ]; then :; fi\n'

# Stands in for Git Bash: records the call, answers with the chosen exit code.
BASH_STUB = """Add-Content -Path $env:DEPLOY_CALLS -Value ('bash ' + ($args -join ' '))
exit [int]$env:CHECK_EXIT
"""

# `docker`, the health probe and the poll interval, shadowed in the caller's
# scope so the script resolves them before the real commands.
DOCKER_STUB = r"""
function global:docker {
    $a = $args -join ' '
    $line = "docker $a"
    if ($args -contains 'up') { $line += " THEHUB_IMAGE=$env:THEHUB_IMAGE" }
    Add-Content -Path $env:DEPLOY_CALLS -Value $line
    $global:LASTEXITCODE = 0
    switch -Regex ($a) {
        '^image inspect --format \{\{\.Id\}\}' { return $env:STUB_IMAGE_ID }
        '^image inspect --format \{\{range \.RepoDigests' { return $env:STUB_REPO_DIGEST }
        ' ps --quiet$' { return 'c0ffee000001' }
        '^inspect --format \{\{\.Image\}\}' { return $env:STUB_IMAGE_ID }
        '^inspect -f \{\{if \.State\.Health' { return 'healthy' }
        '^inspect -f \{\{\.Config\.Image\}\}' { return 'registry.test:5000/thehub' }
        'python -c from run_migrations import engine' { return '5' }
    }
}
function global:Invoke-WebRequest { }
function global:Start-Sleep { }
"""


def _ps(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _deploy(
    tmp_path: Path,
    *,
    check_exit: int = 0,
    script: str | None = CHECK_DEMO_SCRIPT,
    repo_digest: str = f"{REGISTRY}/thehub@{DIGEST}",
    extra: str = "",
) -> tuple[str, list[str], Path]:
    here = tmp_path / "deploy"
    here.mkdir()
    shutil.copy(DEPLOYER, here / DEPLOYER.name)
    thehub = tmp_path / "thehub"
    (thehub / "scripts").mkdir(parents=True)
    compose = thehub / "docker-compose.demo.yml"
    compose.write_text("services: {}\n", encoding="ascii")
    if script is not None:
        (thehub / "scripts" / "publish-patched-images.sh").write_text(script, encoding="ascii")
    stub = tmp_path / "bash-stub.ps1"
    stub.write_text(BASH_STUB, encoding="ascii")
    (here / ".env").write_text(
        f"THEHUB_REGISTRY={REGISTRY}\n"
        f"THEHUB_DEMO_COMPOSE={compose}\n"
        "THEHUB_DEMO_PROJECT=thehub-demo\n"
        "THEHUB_DEMO_URL=http://127.0.0.1:9/health\n"
        f"THEHUB_BASH={stub}\n",
        encoding="ascii",
    )
    calls = tmp_path / "calls.log"
    env = {k: v for k, v in os.environ.items() if not k.startswith("THEHUB_")}
    env.update({
        "DEPLOY_CALLS": str(calls), "CHECK_EXIT": str(check_exit),
        "STUB_IMAGE_ID": IMAGE_ID, "STUB_REPO_DIGEST": repo_digest,
    })
    program = (
        "$ErrorActionPreference = 'Stop'\n" + DOCKER_STUB +
        f"try {{ & {_ps(here / DEPLOYER.name)} -Environment demo -Sha {SHA} -Rebuild "
        f"-TimeoutMinutes 1 {extra}\n"
        '  "EXIT=$LASTEXITCODE" } catch { "THROWN=" + $_.Exception.Message }\n'
    )
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True, text=True, encoding="utf-8", timeout=120, env=env,
    )
    lines = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return out.stdout + out.stderr, lines, here


def _docker(lines: list[str]) -> list[str]:
    return [line for line in lines if line.startswith("docker ")]


@needs_pwsh
def test_a_refused_check_stops_the_demo_deploy_before_anything_changes(tmp_path):
    out, lines, here = _deploy(tmp_path, check_exit=1)
    assert "THROWN=" in out and "--check-demo" in out, out
    assert len(lines) == 1, lines
    assert lines[0].startswith("bash ") and lines[0].endswith(" --check-demo"), lines
    assert "publish-patched-images.sh" in lines[0]
    # No wipe, no pull, no compose up: the demo is left exactly as it was.
    assert _docker(lines) == [], lines
    assert not (here / ".deployed-demo").exists()


@needs_pwsh
def test_the_check_runs_first_and_the_backend_runs_by_digest(tmp_path):
    out, lines, here = _deploy(tmp_path)
    assert "EXIT=0" in out, out
    assert lines[0].endswith(" --check-demo"), lines
    ups = [line for line in lines if " up -d " in line]
    assert ups == [
        "docker compose --project-name thehub-demo --file "
        f"{tmp_path / 'thehub' / 'docker-compose.demo.yml'} up -d --remove-orphans "
        f"THEHUB_IMAGE={REGISTRY}/thehub:{SHA}@{DIGEST}"
    ], lines
    assert (here / ".deployed-demo").read_text(encoding="ascii").strip() == SHA


@needs_pwsh
def test_a_backend_without_a_registry_digest_never_runs_on_the_tag(tmp_path):
    out, lines, _ = _deploy(tmp_path, repo_digest="")
    assert "THROWN=" in out and "refusing to run demo on a tag" in out, out
    assert not [line for line in lines if " up -d " in line], lines


@needs_pwsh
def test_a_check_script_that_predates_the_mode_is_refused_unrun(tmp_path):
    """Run with an argument it does not know, it would build and push."""
    out, lines, _ = _deploy(tmp_path, script=PRE_784_SCRIPT)
    assert "THROWN=" in out and "#61949" in out, out
    assert lines == [], lines


@needs_pwsh
def test_a_missing_check_script_is_refused(tmp_path):
    out, lines, _ = _deploy(tmp_path, script=None)
    assert "THROWN=" in out and "publish-patched-images.sh" in out, out
    assert lines == [], lines


@needs_pwsh
def test_a_patch_date_is_no_longer_accepted(tmp_path):
    out, lines, _ = _deploy(tmp_path, extra="-PatchDate 20261124")
    assert "EXIT=0" not in out, out
    assert _docker(lines) == [], lines
