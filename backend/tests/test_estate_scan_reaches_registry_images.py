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
