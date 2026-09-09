"""The cross-repo gate check reads what governs, and can fail (B-055).

`check_applied_pipelines.py` compares the applied pipeline to our file. This
compares the *owning repository's* copy to ours, which is the direction that
was missing when TheHub's promotion-gate fix sat in TheHub's repository for two
weeks while the pipeline that runs was applied from a copy that never got it.

`fetch()` shells out to `gh`, so it is not covered here. What can silently go
wrong is the gate extraction and the comparison, and both are pure.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_pipeline_gates.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("check_pipeline_gates", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before executing: `@dataclass` resolves its annotations
    # through `sys.modules[cls.__module__]`, so a module loaded by path alone
    # raises AttributeError the moment the decorator runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load()


def config(text: str) -> dict[str, Any]:
    return yaml.safe_load(text)


class TestReadingTheGate:
    def test_a_passed_constraint_is_read(self) -> None:
        gates = checker.gates(
            config(
                """
                jobs:
                - name: insider
                  plan:
                  - get: source
                    passed: [oracle-gate, api-inventory, dast-demo]
                """
            )
        )

        assert gates == {"insider": {"source": ["api-inventory", "dast-demo", "oracle-gate"]}}

    def test_a_job_with_no_constraint_is_still_named(self) -> None:
        """Otherwise a job deleted from one copy and a job that simply gates
        on nothing look the same, and only one of those is a problem."""
        gates = checker.gates(config("jobs:\n- name: build\n  plan:\n  - get: source\n"))

        assert gates == {"build": {}}

    def test_a_constraint_nested_in_parallel_is_not_missed(self) -> None:
        """A `get` inside `in_parallel` gates promotion exactly as much as one
        written flat. Reading only the outer list is how a check misses the
        constraint it exists to read."""
        gates = checker.gates(
            config(
                """
                jobs:
                - name: deploy-prod
                  plan:
                  - in_parallel:
                    - get: source
                      passed: [insider]
                    - get: python
                """
            )
        )

        assert gates == {"deploy-prod": {"source": ["insider"]}}

    def test_a_constraint_nested_in_a_do_block_is_not_missed(self) -> None:
        gates = checker.gates(
            config(
                """
                jobs:
                - name: deploy-prod
                  plan:
                  - do:
                    - get: source
                      passed: [insider]
                """
            )
        )

        assert gates == {"deploy-prod": {"source": ["insider"]}}

    def test_in_parallel_written_as_a_mapping_is_walked(self) -> None:
        """Concourse accepts both spellings, and `fly get-pipeline` returns
        the mapping form."""
        gates = checker.gates(
            config(
                """
                jobs:
                - name: deploy-prod
                  plan:
                  - in_parallel:
                      steps:
                      - get: source
                        passed: [insider]
                """
            )
        )

        assert gates == {"deploy-prod": {"source": ["insider"]}}


class TestComparing:
    def test_identical_gates_do_not_differ(self) -> None:
        text = "jobs:\n- name: insider\n  plan:\n  - get: source\n    passed: [oracle-gate]\n"

        assert not checker.compare(config(text), config(text)).differs

    def test_the_regression_this_exists_for_is_caught(self) -> None:
        """The 2026-08-20 state, exactly: theirs gates on three jobs, ours on
        one, and a commit whose demo DAST failed stays eligible for prod."""
        ours = config(
            "jobs:\n- name: insider\n  plan:\n  - get: source\n    passed: [oracle-gate]\n"
        )
        theirs = config(
            "jobs:\n- name: insider\n  plan:\n  - get: source\n"
            "    passed: [oracle-gate, api-inventory, dast-demo]\n"
        )

        report = checker.compare(ours, theirs)

        assert report.differs
        assert len(report.gate) == 1
        assert "insider" in report.gate[0]
        assert "api-inventory" in report.gate[0]

    def test_a_constraint_only_we_have_is_reported_too(self) -> None:
        """Ours being stricter is still a disagreement worth reading: it means
        the owning repository is about to apply something looser."""
        ours = config(
            "jobs:\n- name: insider\n  plan:\n  - get: source\n    passed: [oracle-gate]\n"
        )
        theirs = config("jobs:\n- name: insider\n  plan:\n  - get: source\n")

        report = checker.compare(ours, theirs)

        assert report.differs
        assert "theirs=(none)" in report.gate[0]

    def test_a_job_missing_from_our_copy_is_named(self) -> None:
        ours = config("jobs:\n- name: build\n  plan:\n  - get: source\n")
        theirs = config(
            "jobs:\n- name: build\n  plan:\n  - get: source\n"
            "- name: dast-demo\n  plan:\n  - get: source\n"
        )

        report = checker.compare(ours, theirs)

        assert report.missing_here == ["dast-demo"]
        assert report.missing_there == []
        assert report.differs

    def test_a_job_missing_from_theirs_is_named_separately(self) -> None:
        """`main` lags `develop` here and is missing `dast-staging`; the two
        directions read differently and must not be merged."""
        ours = config(
            "jobs:\n- name: build\n  plan:\n  - get: source\n"
            "- name: dast-staging\n  plan:\n  - get: source\n"
        )
        theirs = config("jobs:\n- name: build\n  plan:\n  - get: source\n")

        report = checker.compare(ours, theirs)

        assert report.missing_there == ["dast-staging"]
        assert report.missing_here == []


class TestTheConfiguredSource:
    def test_thehub_is_checked_against_the_branch_commits_land_on(self) -> None:
        """B-045: TheHub is scanned on `develop`, so that is the copy whose
        disagreement means something is about to run ungated. `main` lags by
        design and must not fail the check."""
        source = checker.SOURCES["thehub"]

        assert source["gate_ref"] == "develop"
        assert "main" in source["also_report"]

    def test_our_copy_of_every_source_exists(self) -> None:
        for source in checker.SOURCES.values():
            assert (REPO_ROOT / str(source["ours"])).is_file()

    def test_the_live_copies_agree_about_the_gate(self) -> None:
        """Not a network test: this reads the file in this repository against
        itself, so it asserts the extractor finds a gate at all in the real
        pipeline. A refactor that made `gates()` return nothing would pass
        every test above and fail this one."""
        ours = yaml.safe_load(
            (REPO_ROOT / "deploy/concourse/pipelines/thehub.yml").read_text(encoding="utf-8")
        )
        gates = checker.gates(ours)

        assert gates["insider"]["source"] == ["api-inventory", "dast-demo", "oracle-gate"], (
            "the promotion gate B-055 restored must stay restored"
        )
        assert sum(1 for job in gates.values() if job) >= 10
