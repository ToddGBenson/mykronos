"""The promotion gate is asserted here, and the two drift detectors are run (#59999).

`scripts/check_pipeline_gates.py` (B-055) and `scripts/check_applied_pipelines.py`
(D-081) were both written for the defect they report, and until this file
existed **nothing called either of them**. Not a workflow, not a hook, not a
Makefile -- the repository has none. Their existing tests
(`test_pipeline_gates_check.py`, `test_applied_pipelines_check.py`) exercise the
pure comparison helpers against inline fixtures and never read
`deploy/concourse/pipelines/thehub.yml`, so the gate could regress in the file
with both test modules green. It did, twice.

`check-gha-enabled.sh` sat uncalled through a 34-day outage. A detector nobody
runs is not a control, and writing a second one does not help; calling them is
the whole fix.

Three layers, deliberately, because they fail for different reasons:

* **The gate itself** -- read straight out of the committed file, no network.
  This is the layer that cannot be skipped, and it is the one that would have
  caught both regressions. It states the security property twice: once as the
  exact `passed:` edges, and once as "what must transitively precede
  `deploy-prod`", so a rename or a re-plumbing of the middle of the chain does
  not quietly drop a lane.

* **The cross-repo check** -- our copy against the repository that owns it,
  over `gh`.

* **The applied check** -- the running pipeline against our copy, over `fly`.

The last two need a network and are skipped without one, which is the same
fail-soft the scripts themselves choose: "no network here" is not drift. The
first layer is what makes that acceptable, because the regression this story is
about is a change to the *file*, and the file is readable everywhere.

Every layer asserts a floor before it asserts a conclusion. A discovery step
that finds no pipelines, or a job map with no jobs, is a failure and not a
clean run -- a check that inspects nothing passes everything, which is the
failure mode this whole file exists to rule out.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
THEHUB = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"

#: Every pipeline the applied-drift check knows about must exist on disk. Named
#: here rather than globbed, so deleting a pipeline file fails this instead of
#: silently shrinking what is checked.
PIPELINE_FILES = (
    "deploy/concourse/pipelines/mykronos.yml",
    "deploy/concourse/pipelines/thehub.yml",
    "deploy/concourse/pipelines/personal-soc.yml",
)

#: The six static security lanes. `deploy-demo` gates on exactly these, so
#: anything gated on `deploy-demo` requires all six transitively.
ANALYSERS = ("containers", "dependencies", "iac", "prompt-evals", "sast", "secrets")

#: The promotion chain, as `job -> {resource: passed}`, exactly as
#: `check_pipeline_gates.gates()` reports it (sorted, by resource).
#:
#: Exact equality rather than "contains", in both directions. A narrowing is
#: the regression #55167 fixed and #59100 reintroduced. A *widening* nobody
#: wrote down is how the chain becomes something no one can reason about, and
#: it is equally worth a failed test and a sentence of explanation here.
REQUIRED_GATE: dict[str, dict[str, list[str]]] = {
    "deploy-demo": {"source": sorted(ANALYSERS)},
    "oracle-gate": {"source": ["deploy-demo"]},
    "api-inventory": {"source": ["deploy-demo"]},
    "dast-demo": {"source": ["deploy-demo"]},
    "insider": {"source": sorted(["oracle-gate", "api-inventory", "dast-demo"])},
    "deploy-prod": {"source": ["insider"]},
}

#: Must have passed before anything reaches production. Asserted against the
#: transitive closure of `passed:` edges behind `deploy-prod` rather than
#: against one job's list, so the property survives the chain being re-plumbed.
MUST_PRECEDE_PROD = frozenset(
    {"deploy-demo", "oracle-gate", "api-inventory", "dast-demo", *ANALYSERS}
)

#: Differences between our copy and TheHub's that are deliberate, with the
#: reason. Anything NOT in here fails the cross-repo check, which is the point:
#: a new divergence is unexplained until somebody explains it here.
EXPLAINED_DIVERGENCE = {
    "functional-dast": (
        "retired by #468 and deliberately left retired by #491 -- its only "
        "image resource (`playwright`) went with it and nothing else in the "
        "file runs a browser"
    ),
    "set-pipeline": (
        "ours only. It is the job that applies these pipelines, so it exists "
        "in the applying repository and has nothing to correspond to in the "
        "repository being applied"
    ),
    "dast-prod": (
        "our copy is time-triggered and ungated where TheHub's is gated on "
        "`deploy-prod`; see #59999, routed to the operator as a decision "
        "rather than settled here. Remove this entry when that lands"
    ),
}


def _load(name: str) -> Any:
    """Import a `scripts/` checker by path, the way its own tests do."""
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before executing: `@dataclass` resolves annotations through
    # `sys.modules[cls.__module__]`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gates_check = _load("check_pipeline_gates")
applied_check = _load("check_applied_pipelines")


def committed_gates() -> dict[str, dict[str, list[str]]]:
    config = yaml.safe_load(THEHUB.read_text(encoding="utf-8"))
    found = gates_check.gates(config)
    # The floor. `gates()` returns `{}` for a file with no `jobs:`, and every
    # assertion below would then pass vacuously.
    assert len(found) >= 20, (
        f"only {len(found)} jobs read from {THEHUB.name}; expected the full pipeline"
    )
    return found


def closure(gate: dict[str, dict[str, list[str]]], job: str) -> set[str]:
    """Every job that must have passed before `job` can run."""
    seen: set[str] = set()
    stack = [job]
    while stack:
        current = stack.pop()
        for upstream in sorted({p for passed in gate.get(current, {}).values() for p in passed}):
            if upstream not in seen:
                seen.add(upstream)
                stack.append(upstream)
    return seen


class TestTheCommittedGate:
    """No network. This is the layer that catches the regression."""

    def test_the_pipeline_file_is_there_and_is_a_pipeline(self) -> None:
        for relative in PIPELINE_FILES:
            path = REPO_ROOT / relative
            assert path.is_file(), f"{relative} is missing"
            config = yaml.safe_load(path.read_text(encoding="utf-8"))
            assert config.get("jobs"), f"{relative} declares no jobs"

    def test_every_gated_job_exists(self) -> None:
        gate = committed_gates()
        for job in REQUIRED_GATE:
            assert job in gate, f"`{job}` is not a job in {THEHUB.name}"

    @pytest.mark.parametrize("job", sorted(REQUIRED_GATE))
    def test_the_promotion_edge_is_exactly_what_was_agreed(self, job: str) -> None:
        gate = committed_gates()
        assert gate[job] == REQUIRED_GATE[job], (
            f"`{job}`'s promotion gate is not what this repository agreed to.\n"
            f"  committed: {gate.get(job)}\n"
            f"  required : {REQUIRED_GATE[job]}\n"
            "Narrowing it lets a version reach production having failed a lane "
            "that was supposed to stop it (#55167, #59999). Widening it is "
            "fine, and belongs in REQUIRED_GATE with a reason."
        )

    def test_nothing_reaches_production_without_these(self) -> None:
        gate = committed_gates()
        behind_prod = closure(gate, "deploy-prod")
        assert behind_prod, "`deploy-prod` has no upstream at all -- it is ungated"
        missing = sorted(MUST_PRECEDE_PROD - behind_prod)
        assert not missing, (
            f"these can no longer stop a production deploy: {missing}. "
            "A security scan that cannot stop a release is advisory decoration."
        )

    def test_the_demo_dast_specifically_gates_production(self) -> None:
        """The exact hole #59999 was filed for, stated on its own.

        `api-inventory` failed builds #34 and #35 on 2026-09-17 while
        `oracle-gate` #36-#38 went green. Under `passed: [oracle-gate]` that
        version is promotable carrying a failed API-contract check.
        """
        behind_prod = closure(committed_gates(), "deploy-prod")
        for job in ("dast-demo", "api-inventory"):
            assert job in behind_prod, (
                f"a commit whose `{job}` failed is still eligible for deploy-prod"
            )


class TestTheCrossRepoCheckRuns:
    """Our copy against the repository that owns it, over `gh` (B-055)."""

    @pytest.mark.parametrize("pipeline,source", sorted(gates_check.SOURCES.items()))
    def test_it_agrees_except_where_we_have_explained_why(
        self, pipeline: str, source: dict[str, Any]
    ) -> None:
        if not shutil.which("gh"):
            pytest.skip("`gh` is not on PATH; the committed-gate layer still ran")
        raw = gates_check.fetch(
            str(source["repo"]), str(source["path"]), str(source["gate_ref"])
        )
        if raw is None:
            pytest.skip("GitHub is not reachable; 'no network here' is not drift")

        theirs = yaml.safe_load(raw)
        assert len(gates_check.gates(theirs)) >= 20, "read a pipeline with almost no jobs"

        ours = yaml.safe_load((REPO_ROOT / str(source["ours"])).read_text(encoding="utf-8"))
        report = gates_check.compare(ours, theirs)

        unexplained = [
            line
            for line in [*report.missing_here, *report.missing_there, *report.gate]
            if not any(job in line for job in EXPLAINED_DIVERGENCE)
        ]
        assert not unexplained, (
            f"{pipeline} disagrees with {source['repo']}@{source['gate_ref']} about what "
            f"gates promotion, and the difference is not written down:\n  "
            + "\n  ".join(unexplained)
            + "\nAdd it to EXPLAINED_DIVERGENCE with the reason, or fix the file."
        )

    def test_the_explanations_are_still_needed(self) -> None:
        """An allowlist nobody prunes becomes the hole it was meant to document."""
        assert EXPLAINED_DIVERGENCE, "the allowlist is empty; delete it rather than keep it"
        for job, reason in EXPLAINED_DIVERGENCE.items():
            assert reason.strip(), f"`{job}` is allowlisted with no reason given"


class TestTheAppliedCheckRuns:
    """The running pipeline against our copy, over `fly` (D-081)."""

    def test_every_pipeline_it_checks_is_a_file_we_have(self) -> None:
        assert applied_check.PIPELINES, "the applied check knows about no pipelines"
        assert set(applied_check.PIPELINES.values()) == set(PIPELINE_FILES), (
            "the applied check and this test disagree about which pipelines exist"
        )
        for relative in applied_check.PIPELINES.values():
            assert (REPO_ROOT / relative).is_file(), f"{relative} is missing"

    def test_the_applied_gate_is_the_one_on_the_default_branch(self) -> None:
        """D-081's actual question: did somebody apply from a different checkout?

        Compared against `origin/main` rather than the working tree, and that
        distinction is the whole design of this test. A branch that changes the
        gate -- this one did -- differs from the server by construction until
        it merges and `set-pipeline` runs. Asserting the working tree here
        would make every such branch red for doing its job, and a check that is
        red for the expected case is one nobody reads.

        What it still catches is exactly what D-081 was written for: a hand
        edit to a live pipeline, or an apply from a stale checkout, both of
        which show up as the server disagreeing with the branch it was applied
        from (L0004). The *contents* of the gate are pinned offline against the
        working tree in `TestTheCommittedGate`, so the pair closes the loop:
        `main` must carry the right gate, and the server must be running
        `main`.
        """
        fly = applied_check.FLY
        if not (shutil.which(fly) or Path(fly).exists()):
            pytest.skip("`fly` is not available; the committed-gate layer still ran")

        merged = subprocess.run(
            ["git", "show", "origin/main:deploy/concourse/pipelines/thehub.yml"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=False,
        )
        if merged.returncode != 0:
            pytest.skip("`origin/main` is not fetched here; nothing to compare the server to")

        live = applied_check.fetch("thehub")
        if live is None:
            pytest.skip("Concourse is not reachable; 'not running here' is not drift")

        applied = gates_check.gates(live)
        on_main = gates_check.gates(yaml.safe_load(merged.stdout))
        assert len(applied) >= 20, "read an applied pipeline with almost no jobs"
        assert len(on_main) >= 20, "read a pipeline from origin/main with almost no jobs"

        for job in sorted(set(applied) & set(on_main)):
            assert applied[job] == on_main[job], (
                f"the applied `{job}` is not what `origin/main` says it is.\n"
                f"  applied    : {applied[job]}\n"
                f"  origin/main: {on_main[job]}\n"
                "Re-apply from a checkout at that commit, or find out who applied "
                "from where -- the deployment checkout is not necessarily this one "
                "(L0004)."
            )


class TestTheDetectorsAreActuallyInvokable:
    """They were unrunnable for weeks behind a hardcoded path into another project (#368)."""

    @pytest.mark.parametrize("script", ["check_pipeline_gates.py", "check_applied_pipelines.py"])
    def test_it_runs_and_reports_rather_than_crashing(self, script: str) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPTS / script), "--quiet"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
            cwd=REPO_ROOT,
        )
        assert result.returncode in (0, 1), (
            f"{script} exited {result.returncode} rather than reporting.\n"
            "A drift check that crashes reports no drift, which is "
            f"indistinguishable from finding none.\n{result.stderr[-2000:]}"
        )
