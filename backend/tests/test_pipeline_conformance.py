"""The pipeline standard, enforced by the quality gate (D-078).

`docs/pipeline-standard.md` is eleven rules, each written because something failed
silently for long enough that a human had to notice it by accident. Rules held
only by a document decay exactly the way the `mykronos-ref` pin did — twice,
D-051 and D-074 — so the checker runs here, in the suite the `unit` lane runs,
which every scanning lane waits on.

Which means a pipeline edit that breaks the standard fails the quality gate
before a single scanner starts, rather than producing a lane that looks green
and reports nothing.

The rules themselves live in `scripts/check_pipeline_conformance.py`. These
tests assert two different things: that the pipelines conform *now*, and that
the checker would actually notice if they stopped — a green checker that
cannot fail is the thing it exists to prevent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_pipeline_conformance.py"


def _load_checker():
    """Import the script by path.

    It lives in `scripts/` rather than in the package because it is a
    repository tool, not something a scanning task installs — the same place
    and for the same reason as `check_pinned_ref.py`.
    """
    spec = importlib.util.spec_from_file_location("check_pipeline_conformance", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


@pytest.mark.parametrize("relative", checker.PIPELINES)
def test_pipeline_follows_the_standard(relative: str) -> None:
    problems, rows = checker.check_pipeline(REPO_ROOT / relative)
    assert rows, f"{relative} parsed to no jobs at all"
    assert not problems, "\n".join([f"{relative} breaks docs/pipeline-standard.md:", *problems])


def test_every_reporting_job_is_cross_checked() -> None:
    """PS-1's second half: reporting without being checked is half the point.

    A job that uploads a capability and is absent from `CAPABILITY_BY_JOB`
    produces scan runs nothing compares against a build, so `silent` and
    `never_reported` can never be detected for it (spec 15 §4a.1). That is the
    state L0003 is about, and it is invisible by construction.
    """
    from mykronos.ci import CAPABILITY_BY_JOB

    missing: list[str] = []
    for relative in checker.PIPELINES:
        document = yaml.safe_load((REPO_ROOT / relative).read_text(encoding="utf-8"))
        for job in document["jobs"]:
            body = checker._scripts(job)
            if "--capability" not in body:
                continue
            if job["name"] not in CAPABILITY_BY_JOB:
                missing.append(f"{Path(relative).name}:{job['name']}")

    assert not missing, (
        "These jobs upload a capability but are not in CAPABILITY_BY_JOB, so the "
        "coverage cross-check cannot see them: " + ", ".join(missing)
    )


def test_the_checker_can_actually_fail(tmp_path: Path) -> None:
    """Strip a timeout and a preflight; the checker must object to both."""
    source = REPO_ROOT / checker.PIPELINES[0]
    document = yaml.safe_load(source.read_text(encoding="utf-8"))

    for job in document["jobs"]:
        if job["name"] != "sast":
            continue
        job["plan"] = [step for step in job["plan"] if step.get("task") != "preflight"]
        for step in job["plan"]:
            step.pop("timeout", None)

    broken = tmp_path / "mykronos.yml"
    broken.write_text(yaml.safe_dump(document), encoding="utf-8")

    problems, _ = checker.check_pipeline(broken)
    assert any("PS-2" in problem and "sast" in problem for problem in problems), problems
    assert any("PS-7" in problem and "sast" in problem for problem in problems), problems
