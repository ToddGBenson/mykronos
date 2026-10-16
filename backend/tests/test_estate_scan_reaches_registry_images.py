"""TheHub's patched images live in the estate registry, not on Docker Hub.

The estate scan must (1) derive their names with the real registry, not the
compose default `localhost:5000` -- inside a worker that is the worker itself --
and (2) pull them with --insecure, because the registry is plain HTTP, exactly as
the backend image scan already does.
"""
from pathlib import Path

import yaml

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"


def _containers_tasks() -> dict:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in doc["jobs"] if j["name"] == "containers")
    tasks: dict = {}

    def walk(steps):
        for s in steps or []:
            if "task" in s:
                tasks[s["task"]] = s
            for k in ("do", "in_parallel", "aggregate"):
                v = s.get(k)
                walk(v.get("steps") if isinstance(v, dict) else v)

    walk(job["plan"])
    return tasks


def test_estate_image_derivation_is_given_the_registry():
    params = _containers_tasks()["derive-estate-images"]["params"]
    assert params["REGISTRY"] == "((registry))"
    # The merge keeps the shared env, rather than replacing it.
    assert "MYKRONOS_URL" in params or len(params) > 1


def test_registry_hosted_estate_images_are_scanned_insecure():
    text = PIPELINE.read_text(encoding="utf-8")
    assert 'case "${estate_image}" in "${REGISTRY}"/*) insecure="--insecure"' in text
    assert 'trivy image ${insecure} "${estate_image}"' in text


def test_the_derive_command_resolves_the_registry(tmp_path: Path) -> None:
    """Run the pipeline's own command line, not a reading of its params.

    The params above were in place from #764 (2026-10-10) and containers 189
    (2026-10-15) still asked for `localhost:5000/thehub-*` -- five images,
    none scanned -- because estate_images reads the process environment only
    under --use-process-env, which the command never passed. A REGISTRY param
    that nothing reads looks exactly like a fix.
    """
    import os
    import re
    import shlex
    import subprocess
    import sys

    script = _containers_tasks()["derive-estate-images"]["config"]["run"]["args"][-1]
    command = next(
        line.strip() for line in script.splitlines()
        if line.strip().startswith("python -m mykronos.estate_images")
    )
    source = tmp_path / "source"
    source.mkdir()
    (source / "docker-compose.yml").write_text(
        "services:\n"
        "  redis:\n"
        "    image: ${REGISTRY:-localhost:5000}/thehub-redis:7.4.11-alpine-p20261011\n",
        encoding="utf-8",
    )
    (tmp_path / "estate").mkdir()
    env = {
        **os.environ,
        "REGISTRY": "192.0.2.10:5000",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
    }
    # What bash does to the line: split it, then expand ${NAME} from the task's
    # params. The same environment reaches the process, so a command that only
    # *could* read REGISTRY from it still fails here.
    argv = [re.sub(r"\$\{(\w+)\}", lambda m: env[m.group(1)], a) for a in shlex.split(command)]
    subprocess.run([sys.executable, *argv[1:]], cwd=tmp_path, env=env, check=True)
    images = (tmp_path / "estate" / "images.txt").read_text(encoding="utf-8")
    assert "192.0.2.10:5000/thehub-redis:7.4.11-alpine-p20261011" in images
    assert "localhost:5000" not in images
