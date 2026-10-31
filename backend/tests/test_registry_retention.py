"""`Invoke-RegistryRetention.ps1` frees the local registry's disk without ever
turning its DELETE API on (disk incident #36314).

The registry has no `auth:` block, so `REGISTRY_STORAGE_DELETE_ENABLED` stays
"false" in compose and the script works on the volume offline instead: it
removes dropped tags' `_manifests/tags/<tag>` directories in a throwaway
container with no network, then runs `registry garbage-collect`.

The whole script runs here in pwsh, the way test_registry_scope_remove.py runs
Set-RegistryScope.ps1: `docker` is shadowed by a function that plays back a
fixture and records every call, the registry layout is a fixture directory
(`-RegistryRoot`), and pinned refs come from a throwaway git repository, so
nothing touches the real registry, Docker or a real checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "concourse" / "Invoke-RegistryRetention.ps1"
COMPOSE = ROOT / "deploy" / "concourse" / "docker-compose.yml"

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh is not on PATH")
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")

BASE_TIME = 1_790_000_000  # 2026-09; only the order matters


def sha(n: int) -> str:
    return hashlib.sha1(str(n).encode()).hexdigest()


def digest(name: str) -> str:
    return "sha256:" + hashlib.sha256(name.encode()).hexdigest()


def manifest(layer: str, size: int) -> dict[str, Any]:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": digest(layer + "-config"), "size": 10},
        "layers": [{"digest": digest(layer), "size": size}],
    }


def make_registry(root: Path, repos: dict[str, list[tuple[str, int]]]) -> dict[str, str]:
    """Lay out docker/registry/v2 like the volume. Each tag gets its own
    manifest and one 1 MB layer; the int is the tag's age rank (bigger is
    newer). Returns tag -> digest, keyed "repo:tag"."""
    v2 = root / "docker" / "registry" / "v2"
    digests: dict[str, str] = {}
    for repo, tags in repos.items():
        for tag, rank in tags:
            m = manifest(f"{repo}-{tag}", 1_000_000)
            body = json.dumps(m).encode()
            d = digest(f"m-{repo}-{tag}")
            h = d.split(":", 1)[1]
            blob = v2 / "blobs" / "sha256" / h[:2] / h / "data"
            blob.parent.mkdir(parents=True, exist_ok=True)
            blob.write_bytes(body)
            rev = v2 / "repositories" / repo / "_manifests" / "revisions" / "sha256" / h / "link"
            rev.parent.mkdir(parents=True, exist_ok=True)
            rev.write_text(d, encoding="utf-8")
            link = v2 / "repositories" / repo / "_manifests" / "tags" / tag / "current" / "link"
            link.parent.mkdir(parents=True, exist_ok=True)
            link.write_text(d, encoding="utf-8")
            os.utime(link, (BASE_TIME + rank * 60, BASE_TIME + rank * 60))
            digests[f"{repo}:{tag}"] = d
    return digests


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def make_checkout(
    path: Path, committed: dict[str, str], working_tree: dict[str, str] | None = None
) -> Path:
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.invalid")
    git(path, "config", "user.name", "test")
    git(path, "config", "core.autocrlf", "false")
    for name, text in committed.items():
        f = path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "fixture")
    for name, text in (working_tree or {}).items():
        (path / name).write_text(text, encoding="utf-8")
    return path


DOCKER_SHADOW = r"""
$global:Fx = Get-Content -Raw '__FIXTURE__' | ConvertFrom-Json
function docker {
  $line = ($args | ForEach-Object { "$_" }) -join ' '
  Add-Content -LiteralPath '__CALLS__' -Value ($line -replace "`r?`n", ' \n ')
  $global:LASTEXITCODE = 0
  $a = @($args | ForEach-Object { "$_" })
  switch ($a[0]) {
    'inspect' {
      if ($line -match 'State.Running') {
        if ($global:Fx.exists) { return $global:Fx.running.ToString().ToLower() }
        $global:LASTEXITCODE = 1; return
      }
      if ($line -match 'Config.Image') { return $global:Fx.image }
      return @($global:Fx.container_images)
    }
    'ps' {
      if ($a -contains '--quiet') { return @($global:Fx.volume_users) }
      return @($global:Fx.ps_rows)
    }
    'image' { return @($global:Fx.image_rows) }
    'run' {
      if ($line -match 'retention:list-tags') { return @($global:Fx.tag_lines) }
      if ($line -match 'retention:list-manifests') { return @('@@BLOBKB 4096') }
      if ($line -match 'retention:remove-tags') {
        $i = [array]::IndexOf($a, '--volume', [array]::IndexOf($a, '--volume') + 1)
        $src = $a[$i + 1] -replace ':/retention:ro$', ''
        Copy-Item -LiteralPath (Join-Path $src 'drop.txt') -Destination '__DROPCOPY__'
        return 'removed 2 tag directories'
      }
      if ($a -contains '--entrypoint' -and $a -contains 'du') { return "1024`t/var/lib/registry" }
      return 'garbage-collect: done'
    }
    default { return }
  }
}
"""


def ps_arg(a: str | list[str]) -> str:
    if isinstance(a, list):
        return ",".join(ps_arg(x) for x in a)
    return a if a.startswith("-") else "'" + a.replace("'", "''") + "'"


def run(
    tmp_path: Path,
    *args: str | list[str],
    docker: dict[str, Any] | None = None,
    use_root: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[str], dict[str, Any] | None]:
    fx = {
        "exists": True,
        "running": False,
        "image": "localhost:5000/library/registry:3-p20261019",
        "container_images": [],
        "volume_users": [],
        "ps_rows": [],
        "image_rows": [],
        "tag_lines": [],
    } | (docker or {})
    fixture = tmp_path / "docker.json"
    fixture.write_text(json.dumps(fx), encoding="utf-8")
    calls = tmp_path / "calls.txt"
    calls.write_text("", encoding="utf-8")
    report = tmp_path / "report.json"
    shadow = (
        DOCKER_SHADOW.replace("__FIXTURE__", str(fixture))
        .replace("__CALLS__", str(calls))
        .replace("__DROPCOPY__", str(tmp_path / "drop-copy.txt"))
    )
    quoted = " ".join(ps_arg(a) for a in args)
    root_arg = f"-RegistryRoot '{use_root}'" if use_root else ""
    program = f"""
{shadow}
& '{SCRIPT}' {root_arg} -ReportPath '{report}' {quoted} *>&1 | ForEach-Object {{ "$_" }}
exit $LASTEXITCODE
"""
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", program],
        capture_output=True,
        text=True,
        timeout=180,
    )
    logged = [c for c in calls.read_text(encoding="utf-8").splitlines() if c]
    data = json.loads(report.read_text(encoding="utf-8-sig")) if report.exists() else None
    return out, logged, data


def kept(report: dict[str, Any], repo: str) -> dict[str, list[str]]:
    return {k["tag"]: k["reasons"] for k in report["kept"] if k["repo"] == repo}


def dropped(report: dict[str, Any], repo: str) -> set[str]:
    return {d["tag"] for d in report["dropped"] if d["repo"] == repo}


# ------------------------------------------------------------------ static ---


FORBIDDEN_RUN_FLAGS = r"(^|\s)(-p|-P|--publish|--publish-all|-e|--env|--env-file)(\s|=|$)"


def docker_run_commands() -> list[str]:
    """Each `docker run` invocation in the script, continuation lines joined."""
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    commands, i = [], 0
    while i < len(lines):
        if re.search(r"^\s*(\$\w+\s*=\s*)?docker run\b", lines[i]):
            cmd = lines[i]
            while cmd.rstrip().endswith("`") and i + 1 < len(lines):
                i += 1
                cmd = cmd.rstrip()[:-1] + " " + lines[i].strip()
            commands.append(cmd)
        i += 1
    return commands


def script_code() -> str:
    """The script without its comment-based help and # comments."""
    text = re.sub(r"<#.*?#>", "", SCRIPT.read_text(encoding="utf-8"), flags=re.S)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_script_never_touches_the_delete_setting() -> None:
    code = script_code()
    assert "REGISTRY_STORAGE_DELETE_ENABLED" not in code
    assert "DELETE_ENABLED" not in code.upper()
    assert "delete:" not in code


def test_every_throwaway_container_has_no_network_and_no_published_port() -> None:
    commands = docker_run_commands()
    # list-tags/list-manifests reader, du, remove-tags, garbage-collect
    assert len(commands) >= 4, commands
    for cmd in commands:
        assert "--network none" in cmd, cmd
        assert "--pull never" in cmd, cmd
        assert not re.search(FORBIDDEN_RUN_FLAGS, cmd), cmd
    text = SCRIPT.read_text(encoding="utf-8")
    assert "--publish" not in text
    assert "garbage-collect --delete-untagged /etc/distribution/config.yml" in text


def test_compose_keeps_registry_deletes_off() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    env = compose["services"]["registry"]["environment"]
    assert env["REGISTRY_STORAGE_DELETE_ENABLED"] == "false"


# ------------------------------------------------------------------ guards ---


@needs_pwsh
def test_apply_refuses_while_the_registry_runs(tmp_path: Path) -> None:
    out, calls, _ = run(
        tmp_path, "-Apply", "-ConfirmCiQuiet", "-TheHubCheckout", str(tmp_path),
        "-DeployLockPath", str(tmp_path / "no-lock"), docker={"running": True},
    )
    assert out.returncode == 3, out.stdout + out.stderr
    assert "REFUSED: the registry container mykronos-registry is running" in out.stdout
    assert not [c for c in calls if c.startswith(("run", "exec"))], calls


@needs_pwsh
def test_apply_refuses_while_the_thehub_deploy_lock_exists(tmp_path: Path) -> None:
    lock = tmp_path / "thehub-deploy.lock"
    lock.mkdir()  # the deploy takes it with mkdir
    out, calls, _ = run(
        tmp_path, "-Apply", "-ConfirmCiQuiet", "-TheHubCheckout", str(tmp_path),
        "-DeployLockPath", str(lock),
    )
    assert out.returncode == 3, out.stdout + out.stderr
    assert "REFUSED: the TheHub deploy lock exists" in out.stdout
    assert calls == []


@needs_pwsh
def test_apply_refuses_without_confirm_ci_quiet(tmp_path: Path) -> None:
    out, calls, _ = run(tmp_path, "-Apply", "-TheHubCheckout", str(tmp_path),
                        "-DeployLockPath", str(tmp_path / "no-lock"))
    assert out.returncode == 3
    assert "-ConfirmCiQuiet" in out.stdout
    assert calls == []


@needs_pwsh
def test_apply_refuses_while_any_container_mounts_the_volume(tmp_path: Path) -> None:
    out, calls, _ = run(
        tmp_path, "-Apply", "-ConfirmCiQuiet", "-TheHubCheckout", str(tmp_path),
        "-DeployLockPath", str(tmp_path / "no-lock"), docker={"volume_users": ["abc123"]},
    )
    assert out.returncode == 3
    assert "a running container mounts mykronos-concourse_registry-data" in out.stdout
    assert not [c for c in calls if c.startswith(("run", "exec"))]


@needs_pwsh
def test_apply_refuses_a_fixture_root(tmp_path: Path) -> None:
    out, calls, _ = run(tmp_path, "-Apply", "-ConfirmCiQuiet", use_root=tmp_path)
    assert out.returncode == 3
    assert "-RegistryRoot is a read-only source" in out.stdout
    assert calls == []


@needs_pwsh
def test_keep_shas_must_be_a_real_prefix(tmp_path: Path) -> None:
    out, _, _ = run(tmp_path, "-KeepShas", "3", use_root=tmp_path)
    assert out.returncode == 3
    assert "is not 7-40 hex characters" in out.stdout


# ---------------------------------------------------------------- the flow ---


@needs_pwsh
@needs_git
def test_apply_removes_only_dropped_tags_then_collects_offline(tmp_path: Path) -> None:
    checkout = make_checkout(tmp_path / "mk", {"docker-compose.yml": "services: {}\n"})
    tag_lines = [
        f"{BASE_TIME + 3}\t./app/_manifests/tags/{sha(3)}/current/link\t{digest('a3')}",
        f"{BASE_TIME + 2}\t./app/_manifests/tags/{sha(2)}/current/link\t{digest('a2')}",
        f"{BASE_TIME + 1}\t./app/_manifests/tags/{sha(1)}/current/link\t{digest('a1')}",
        f"{BASE_TIME + 0}\t./app/_manifests/tags/{sha(0)}/current/link\t{digest('a0')}",
    ]
    out, calls, report = run(
        tmp_path, "-Apply", "-ConfirmCiQuiet", "-KeepNewest", "2",
        "-MykronosCheckout", str(checkout), "-MykronosRefs", "main",
        "-TheHubCheckout", str(checkout), "-TheHubRefs", "main",
        "-DeployLockPath", str(tmp_path / "no-lock"),
        docker={"tag_lines": tag_lines},
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert report and report["mode"] == "apply"
    assert dropped(report, "app") == {sha(1), sha(0)}
    drop_file = (tmp_path / "drop-copy.txt").read_bytes()
    assert b"\r" not in drop_file and drop_file.endswith(b"\n")
    assert set(drop_file.decode().splitlines()) == {f"app {sha(0)}", f"app {sha(1)}"}

    runs = [c for c in calls if c.startswith("run ")]
    # a stopped registry is read from a throwaway container, never exec'd into
    assert not [c for c in calls if c.startswith("exec ")]
    for c in runs:
        assert "--network none" in c and "--pull never" in c, c
        assert not re.search(FORBIDDEN_RUN_FLAGS, c), c
        assert "localhost:5000/library/registry:3-p20261019" in c, c
    remove = [c for c in runs if "retention:remove-tags" in c]
    gc = [c for c in runs if "garbage-collect" in c]
    assert len(remove) == 1 and len(gc) == 1
    assert "--delete-untagged /etc/distribution/config.yml" in gc[0]
    assert runs.index(remove[0]) < runs.index(gc[0])
    assert "mykronos-concourse_registry-data:/var/lib/registry " in gc[0]
    assert "up -d --no-deps registry" in out.stdout
    assert "Volume before" in out.stdout and "Volume after" in out.stdout


# ------------------------------------------------------------ keep-set rules ---


@needs_pwsh
@needs_git
def test_keep_set_rules_on_a_fixture_layout(tmp_path: Path) -> None:
    reg = tmp_path / "reg"
    repos = {
        # 20 commits, oldest first; sha(5) also has a -deploy tag
        "app": [(sha(i), i) for i in range(20)]
        + [(sha(5) + "-deploy", 5), (sha(16) + "-deploy", 3), ("latest", 0)],
        # dated base image: two lines, eight dates on one
        "base": [(f"1.2-p202610{d:02d}", d) for d in range(1, 9)] + [("2.0-p20261001", 1)],
        "solo": [(sha(100 + i), i) for i in range(20)],
    }
    digests = make_registry(reg, repos)
    checkout = make_checkout(
        tmp_path / "mk",
        {
            "deploy/docker-compose.yml": (
                "services:\n  b:\n    image: ${REGISTRY:-localhost:5000}/base:1.2-p20261002\n"
            ),
            "deploy/pipelines/p.yml": f"image: 127.0.0.1:5000/app:{sha(2)}\n",
            "notes.txt": f"localhost:5000/app:{sha(3)}\n",  # not a tracked config type
        },
        working_tree={"deploy/pipelines/p.yml": f"image: localhost:5000/app:{sha(4)}\n"},
    )
    hub = make_checkout(
        tmp_path / "hub",
        {"Dockerfile": f"FROM localhost:5000/solo@{digests['solo:' + sha(101)]}\n"},
    )
    used_digest = digests[f"solo:{sha(102)}"]
    docker = {
        "ps_rows": [f"c1\tweb\tlocalhost:5000/app:{sha(6)}", "c2\tdb\t0123abcd"],
        "container_images": ["c1\tsha256:img1", "c2\tsha256:img2"],
        "image_rows": [
            'sha256:img1\t["localhost:5000/app:' + sha(6) + '"]\t[]',
            f'sha256:img2\t[]\t["localhost:5000/solo@{used_digest}"]',
        ],
    }
    out, _, report = run(
        tmp_path, "-KeepNewest", "3", "-KeepShas", [sha(7)[:12], sha(8)],
        "-MykronosCheckout", str(checkout), "-MykronosRefs", "main",
        "-TheHubCheckout", str(hub), "-TheHubRefs", ["main", "origin/develop"],
        docker=docker, use_root=reg,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert report is not None
    app = kept(report, "app")

    # newest-N by link mtime (sha(19..17)); sha(16)-deploy shares its commit with nothing kept
    for i in (19, 18, 17):
        assert "newest 3" in app[sha(i)]
    assert sha(16) not in app and sha(16) + "-deploy" not in app
    # pinned at the git ref, not in the working tree, not in an untracked-type file
    assert any("pinned in mykronos@main" in r for r in app[sha(2)])
    assert sha(4) not in app
    assert sha(3) not in app
    # in use by a container
    assert any("container web" in r for r in app[sha(6)])
    # -KeepShas prefix matching, short and full
    assert any("-KeepShas" in r for r in app[sha(7)])
    assert any("-KeepShas" in r for r in app[sha(8)])
    # a named tag is never aged out
    assert "named tag" in app["latest"]
    # dropped: everything else
    assert dropped(report, "app") == {sha(i) for i in range(20)} - {
        sha(i) for i in (19, 18, 17, 2, 6, 7, 8)
    } | {sha(5) + "-deploy", sha(16) + "-deploy"}

    base = kept(report, "base")
    assert {t for t in base if t.startswith("1.2-")} == {
        "1.2-p20261008", "1.2-p20261007", "1.2-p20261006", "1.2-p20261005", "1.2-p20261004",
        "1.2-p20261002",  # older than the newest 5, but compose pins it
    }
    assert any("pinned in mykronos@main" in r for r in base["1.2-p20261002"])
    assert "2.0-p20261001" in base  # its own line keeps its newest 5
    assert dropped(report, "base") == {"1.2-p20261001", "1.2-p20261003"}

    solo = kept(report, "solo")
    assert any("by digest in TheHub@main" in r for r in solo[sha(101)])
    assert any("image digest of container db" in r for r in solo[sha(102)])
    # TheHub's missing ref is a warning in a dry run
    assert any("origin/develop does not resolve" in w for w in report["warnings"])
    # each dropped tag carries what a rebuild needs
    d0 = next(d for d in report["dropped"] if d["repo"] == "app" and d["tag"] == sha(0))
    assert d0["sha"] == sha(0) and d0["digest"] == digests[f"app:{sha(0)}"]
    # sizes: each dropped tag owns one 1 MB layer
    for d in report["dropped"]:
        assert d["sha"] == (None if d["repo"] == "base" else d["tag"][:40]), d
    est = report["estimate"]
    assert est["only_in_dropped_bytes"] >= 1_000_000 * len(report["dropped"])


@needs_pwsh
@needs_git
def test_a_kept_commit_keeps_its_deploy_tag(tmp_path: Path) -> None:
    reg = tmp_path / "reg"
    make_registry(reg, {"hub": [(sha(1), 1), (sha(1) + "-deploy", 0), (sha(2), 2), (sha(3), 3)]})
    checkout = make_checkout(tmp_path / "mk", {"a.yml": "x: 1\n"})
    out, _, report = run(
        tmp_path, "-KeepNewest", "1", "-KeepShas", sha(1)[:7],
        "-MykronosCheckout", str(checkout), "-MykronosRefs", "main",
        "-TheHubCheckout", str(checkout), "-TheHubRefs", "main",
        use_root=reg,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert report is not None
    hub = kept(report, "hub")
    assert set(hub) == {sha(3), sha(1), sha(1) + "-deploy"}
    assert dropped(report, "hub") == {sha(2)}
