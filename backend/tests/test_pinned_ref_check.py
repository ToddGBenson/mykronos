"""The guard against a stale `mykronos-ref` — D-074.

The pin has gone stale twice in a way that mattered (D-051 at 53 commits,
D-074 at 61), and both times a human found it days later by noticing a lane
behaving oddly. The unit tests could not: they run the working tree, CI runs
the tag, and nothing compared the two.

`scripts/check_pinned_ref.py` is what compares them. These tests are about the
comparison being *honest* — a guard that passes when it cannot tell is worse
than no guard, because it converts an open question into a green tick.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_pinned_ref.py"


@pytest.fixture(scope="module")
def checker():
    spec = importlib.util.spec_from_file_location("check_pinned_ref", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_pinned_ref"] = module
    spec.loader.exec_module(module)
    return module


class TestItPassesAgainstTheWorkingTree:
    def test_every_declared_module_exists_here(self, checker) -> None:
        """The requirements list describes this commit. If it does not, the
        check would fail against a tag cut from this commit — which is the
        one thing that must never happen, since it would make the guard
        unsatisfiable."""
        assert checker.check() == []

    def test_the_list_is_not_empty(self, checker) -> None:
        """A guard checking nothing passes forever."""
        assert len(checker.REQUIRED_MODULES) >= 5
        assert checker.REQUIRED_FLAGS


class TestItFailsWhenTheThingIsActuallyMissing:
    def test_a_missing_module_is_reported(self, checker, monkeypatch) -> None:
        monkeypatch.setattr(
            checker, "REQUIRED_MODULES", ("mykronos.upload", "mykronos.not_a_module")
        )
        monkeypatch.setattr(checker, "REQUIRED_FLAGS", {})

        problems = checker.check()

        assert len(problems) == 1
        assert "not_a_module" in problems[0]

    def test_a_missing_flag_is_reported(self, checker, monkeypatch) -> None:
        """The worse of the two failures: argparse exits non-zero and takes
        the pipeline step with it, where a missing module at least fails on
        an import line somebody can read."""
        monkeypatch.setattr(checker, "REQUIRED_MODULES", ())
        monkeypatch.setattr(
            checker, "REQUIRED_FLAGS", {"mykronos.reachability": ("--not-a-flag",)}
        )

        problems = checker.check()

        assert len(problems) == 1
        assert "--not-a-flag" in problems[0]

    def test_a_module_whose_help_cannot_be_read_is_not_silently_passed(
        self, checker, monkeypatch
    ) -> None:
        """"I could not determine this" must not render as "this is fine".
        A guard that goes quiet when it cannot tell is how the pin got stale
        without anybody noticing in the first place."""
        monkeypatch.setattr(checker, "REQUIRED_MODULES", ())
        monkeypatch.setattr(checker, "REQUIRED_FLAGS", {"mykronos.logsafe": ("--x",)})

        problems = checker.check()

        assert problems
        assert "cannot be checked" in problems[0]

    def test_the_exit_code_carries_the_verdict(self, checker, monkeypatch, capsys) -> None:
        """Concourse reads the exit code, not the prose."""
        monkeypatch.setattr(checker, "REQUIRED_MODULES", ("mykronos.not_a_module",))
        monkeypatch.setattr(checker, "REQUIRED_FLAGS", {})

        assert checker.main([]) == 1
        assert "Cut a new tag" in capsys.readouterr().out


class TestTheRequirementsMatchWhatIsActuallyInvoked:
    """The failure mode this class exists for: somebody adds a `python -m`
    call to a pipeline and does not add it to `REQUIRED_MODULES`, so the
    guard stays green while the new call is the next thing to go stale."""

    @staticmethod
    def _pipeline_text() -> str:
        root = Path(__file__).resolve().parents[2]
        parts = [
            (root / "deploy" / "concourse" / "pipelines" / name).read_text(encoding="utf-8")
            for name in ("mykronos.yml", "thehub.yml", "personal-soc.yml")
        ]
        templates = root / "workflow-templates"
        parts += [p.read_text(encoding="utf-8") for p in templates.glob("*.j2")]
        return "\n".join(parts)

    def test_every_module_the_pipelines_invoke_is_declared(self, checker) -> None:
        import re

        invoked = set(re.findall(r"python -m (mykronos\.[a-z_]+)", self._pipeline_text()))
        undeclared = invoked - set(checker.REQUIRED_MODULES)

        assert not undeclared, (
            f"{sorted(undeclared)} are invoked by a pipeline or workflow template "
            "but not declared in REQUIRED_MODULES, so a stale pin would not be "
            "caught for them"
        )

    def test_the_pin_check_job_is_in_the_pipeline(self) -> None:
        root = Path(__file__).resolve().parents[2]
        document = yaml.safe_load(
            (root / "deploy" / "concourse" / "pipelines" / "mykronos.yml").read_text(
                encoding="utf-8"
            )
        )

        assert "pin-check" in [job["name"] for job in document["jobs"]]

    def test_pin_check_gates_nothing(self) -> None:
        """A stale pin should be a loud red job, not a stopped fleet. The
        scans still running are producing real results; they are only missing
        what was added after the tag."""
        root = Path(__file__).resolve().parents[2]
        document = yaml.safe_load(
            (root / "deploy" / "concourse" / "pipelines" / "mykronos.yml").read_text(
                encoding="utf-8"
            )
        )

        for job in document["jobs"]:
            for step in job.get("plan", []):
                assert "pin-check" not in (step.get("passed") or []), (
                    f"{job['name']} gates on pin-check"
                )

    def test_all_three_set_pipeline_scripts_pin_the_same_ref(self) -> None:
        """Three scripts, one platform. A pipeline left on the old tag is the
        same bug in a quieter place."""
        import re

        root = Path(__file__).resolve().parents[2] / "deploy" / "concourse"
        refs = {
            path.name: re.search(
                r'"mykronos-ref:\s*([^"]+)"', path.read_text(encoding="utf-8")
            ).group(1)
            for path in root.glob("set-*pipeline.ps1")
        }

        assert len(set(refs.values())) == 1, refs
