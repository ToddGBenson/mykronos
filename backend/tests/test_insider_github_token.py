"""TheHub #60867: the insider lane calls GitHub with a read-only token.

Anonymous, the collaborator-role call (`/collaborators/<author>/permission`)
can never answer, so Aegis never learns the author's role, and every call
shares the host's 60-an-hour limit. The operator stores a fine-grained,
read-only token for this repository at concourse/main/mykronos/github_read_token
(Apply-Decisions-1121.ps1); the aegis task reads it as GITHUB_TOKEN, which its
script already sends when set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PIPELINE = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"


def _aegis_task() -> dict[str, Any]:
    document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in document["jobs"] if j["name"] == "insider")
    return next(step for step in job["plan"] if step.get("task") == "aegis")


def test_the_aegis_task_reads_the_read_token_from_vault() -> None:
    params = _aegis_task()["params"]
    assert params.get("GITHUB_TOKEN") == "((github_read_token))"
    # The shared environment is still merged in, not replaced.
    assert params.get("MYKRONOS_TOKEN") == "((mykronos-ingestion-token))"


def test_the_token_is_not_named_inside_the_script_text() -> None:
    """Concourse resolves a ((var)) anywhere in the task config, including the
    bash body, so naming it there would put the value into the script."""
    script = "\n".join(str(a) for a in _aegis_task()["config"]["run"]["args"])
    assert "((github_read_token))" not in script
    assert 'GH_AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}")' in script
