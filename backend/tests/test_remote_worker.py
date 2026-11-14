"""A remote worker can join (D-180, TheHub #61659).

Three things are held here, none of which starts a container:

- The pipelines name no host address. Every address a task dials comes in
  through a `((var))` (`((registry))` for the image registry), so a worker on
  another machine changes a value, not a pipeline. The literal Docker Desktop
  gateway or a `localhost:5000` in a pipeline would be reachable from the two
  local workers and from nothing else.
- A step tagged `linux` (the remote worker's tag) belongs to a job that reads
  no Vault-held credential and dials no host address but `((registry))`.
  Nothing carries the tag yet; this is the rule the second PR is held to.
- `docker compose config`, fed an env file built from `.env.example` (never
  the host's `.env`), keeps the registry on loopback by default and opens it
  only through REGISTRY_BIND. (The TSA's publish is PR #1167's.)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CONCOURSE = ROOT / "deploy" / "concourse"
COMPOSE = CONCOURSE / "docker-compose.yml"
RUNBOOK = CONCOURSE / "REMOTE-WORKER.md"
PIPELINES = ("mykronos", "thehub", "personal-soc")
REMOTE_TAG = "linux"

#: Addresses that only a worker on this host can reach. Matched against the
#: parsed pipeline, so a comment that names one is not a hit.
HOST_ONLY = re.compile(
    r"localhost:5000|127\.0\.0\.1:5000|192\.168\.65\.254|host\.docker\.internal"
)
VAR = re.compile(r"\(\(([a-z0-9_.:-]+)\)\)")


def _load(stem: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(
        (CONCOURSE / "pipelines" / f"{stem}.yml").read_text(encoding="utf-8")
    )
    return data


def _nonsecret(stem: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(
        (CONCOURSE / "vars" / f"{stem}.yml").read_text(encoding="utf-8")
    )
    return data


def _steps(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        if any(k in node for k in ("task", "get", "put")):
            yield node
        for v in node.values():
            yield from _steps(v)
    elif isinstance(node, list):
        for v in node:
            yield from _steps(v)


def host_only_addresses(pipeline: dict[str, Any]) -> list[str]:
    return sorted(set(HOST_ONLY.findall(json.dumps(pipeline))))


def placement(pipeline: dict[str, Any], nonsecret: dict[str, Any]) -> dict[str, list[str]]:
    """Per job, why it must stay on a local worker ([] = it may go remote).

    A job's vars are those in its plan (anchors resolved) plus those in the
    source of every resource it gets or puts, since a tagged get runs on the
    tagged worker. A var not in the committed vars file is resolved from
    Vault by the web node and handed to the task, so it would land on the
    remote machine; a var whose value is a Docker Desktop gateway address
    names a host service the remote worker cannot reach. `((registry))` is
    the one host address a remote job may use: it is the worker-visible
    registry variable.
    """
    hostvars = {k for k, v in nonsecret.items() if HOST_ONLY.search(str(v))}
    resources = {r["name"]: r for r in pipeline.get("resources", [])}
    types = {t["name"]: t for t in pipeline.get("resource_types", [])}
    out: dict[str, list[str]] = {}
    for job in pipeline["jobs"]:
        used = set(VAR.findall(json.dumps(job)))
        for step in _steps(job):
            name = step.get("get") or step.get("put")
            res = resources.get(step.get("resource", name)) if name else None
            if res:
                used |= set(VAR.findall(json.dumps(res.get("source", {}))))
                if res.get("type") in types:
                    used |= set(VAR.findall(json.dumps(types[res["type"]])))
        used = {u for u in used if not u.startswith(".") and u != "var"}
        reasons = [f"vault:{u}" for u in sorted(used - set(nonsecret))]
        reasons += [f"host:{u}" for u in sorted(used & hostvars) if u != "registry"]
        out[job["name"]] = reasons
    return out


def _tagged(job: dict[str, Any], tag: str) -> bool:
    return any(tag in (s.get("tags") or []) for s in _steps(job))


# ── the pipelines name no host address ────────────────────────────────────


@pytest.mark.parametrize("stem", PIPELINES)
def test_no_pipeline_hard_codes_a_host_only_address(stem: str) -> None:
    assert host_only_addresses(_load(stem)) == [], (
        f"{stem}.yml names a host-only address; route it through a var "
        "(((registry)) for the registry) so a remote worker can be given its own"
    )


def test_the_address_check_can_fail() -> None:
    bad = {
        "jobs": [
            {
                "name": "j",
                "plan": [
                    {"task": "t", "params": {"REGISTRY": "localhost:5000"}},
                    {"put": "s3", "params": {"endpoint": "http://192.168.65.254:9000"}},
                ],
            }
        ]
    }
    assert host_only_addresses(bad) == ["192.168.65.254", "localhost:5000"]
    # a var is what the check wants, and a comment never reaches the parse
    good = yaml.safe_load(
        "# localhost:5000\njobs: [{name: j, plan: [{task: t, params: {R: ((registry))}}]}]"
    )
    assert host_only_addresses(good) == []


def test_the_registry_var_is_the_one_the_image_steps_use() -> None:
    """`((registry))` is the worker-visible registry variable D-180 names; its
    committed value is today's gateway address, so local workers are unchanged."""
    for stem in ("mykronos", "thehub"):
        assert "((registry))" in json.dumps(_load(stem)), stem
        assert _nonsecret(stem)["registry"] == "192.168.65.254:5000", stem


# ── a linux-tagged job reads no Vault credential and no host service ──────


@pytest.mark.parametrize("stem", PIPELINES)
def test_a_remote_job_reads_no_vault_credential_and_no_host_service(stem: str) -> None:
    pipeline = _load(stem)
    reasons = placement(pipeline, _nonsecret(stem))
    wrong = {
        job["name"]: reasons[job["name"]]
        for job in pipeline["jobs"]
        if _tagged(job, REMOTE_TAG) and reasons[job["name"]]
    }
    assert not wrong, f"{stem}: these jobs are tagged {REMOTE_TAG} but must stay local: {wrong}"


def test_the_placement_rule_can_fail() -> None:
    pipeline = {
        "resources": [{"name": "src", "type": "git", "source": {"private_key": "((deploy-key))"}}],
        "jobs": [
            {"name": "push", "plan": [{"task": "t", "params": {"R": "((registry))"}}]},
            {"name": "keyed", "plan": [{"get": "src"}, {"task": "t"}]},
            {"name": "upload", "plan": [{"task": "t", "params": {"U": "((mykronos-url))"}}]},
        ],
    }
    nonsecret = {"registry": "192.168.65.254:5000", "mykronos-url": "http://192.168.65.254:8100"}
    assert placement(pipeline, nonsecret) == {
        "push": [],
        "keyed": ["vault:deploy-key"],
        "upload": ["host:mykronos-url"],
    }


def _runbook_list() -> dict[str, set[str]]:
    text = RUNBOOK.read_text(encoding="utf-8")
    block = re.search(
        r"<!-- remote-candidates:begin -->(.*?)<!-- remote-candidates:end -->", text, re.S
    )
    assert block, "REMOTE-WORKER.md lost its remote-candidates block"
    out: dict[str, set[str]] = {stem: set() for stem in PIPELINES}
    for stem, job in re.findall(r"^\|\s*`?([a-z-]+)`?\s*\|\s*`([a-z0-9-]+)`", block.group(1), re.M):
        out[stem].add(job)
    return out


def test_the_runbook_lists_exactly_the_jobs_that_may_go_remote() -> None:
    """The placement list in the runbook is derived, so it is checked: a job
    that gains a credential leaves the list here before it can be tagged."""
    listed = _runbook_list()
    for stem in PIPELINES:
        derived = {n for n, why in placement(_load(stem), _nonsecret(stem)).items() if not why}
        assert listed[stem] == derived, (stem, sorted(listed[stem]), sorted(derived))


# ── compose: loopback by default, opened only by the variables ────────────

REQUIRED = (
    "CONCOURSE_POSTGRES_PASSWORD",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "CONCOURSE_LOCAL_USER",
    "CONCOURSE_LOCAL_PASSWORD",
    "CONCOURSE_VAULT_TOKEN",
)
BIND_VARS = ("CONCOURSE_BIND", "REGISTRY_BIND", "REGISTRY")


def _compose_config(tmp_path: Path, overrides: dict[str, str]) -> dict[str, Any]:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH")
    lines = (CONCOURSE / ".env.example").read_text(encoding="utf-8").splitlines()
    lines += [f"{name}=dummy" for name in REQUIRED]
    lines += [f"{k}={v}" for k, v in overrides.items()]
    env_file = tmp_path / "compose.env"
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # An explicit --env-file replaces the default .env, so the host's real
    # one is never read; the process env is scrubbed of the same names.
    env = {k: v for k, v in os.environ.items() if k not in BIND_VARS + REQUIRED}
    try:
        proc = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE), "--env-file", str(env_file),
             "config", "--format", "json"],
            capture_output=True, text=True, env=env, timeout=60, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker compose unavailable: {exc}")
    if proc.returncode != 0 and "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin not installed")
    assert proc.returncode == 0, proc.stderr
    config: dict[str, Any] = json.loads(proc.stdout)
    return config


def _published(config: dict[str, Any], service: str, port: int) -> str:
    hits = [p for p in config["services"][service].get("ports", []) if int(p["target"]) == port]
    assert len(hits) == 1, (service, port, hits)
    assert str(hits[0]["published"]) == str(port)
    return str(hits[0].get("host_ip", ""))


def test_compose_keeps_the_registry_on_loopback_by_default(tmp_path: Path) -> None:
    config = _compose_config(tmp_path, {})
    assert _published(config, "registry", 5000) == "127.0.0.1"


def test_compose_opens_the_registry_only_through_its_variable(tmp_path: Path) -> None:
    config = _compose_config(tmp_path, {"REGISTRY_BIND": "0.0.0.0"})
    assert _published(config, "registry", 5000) == "0.0.0.0"
    # the rest stays where it was
    assert _published(config, "concourse", 8080) == "127.0.0.1"
    assert _published(config, "minio", 9000) == "127.0.0.1"
    assert _published(config, "vault", 8200) == "127.0.0.1"
