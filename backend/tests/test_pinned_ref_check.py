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


class TestItDoesNotClaimWhatItSkipped:
    """The summary named scripts it had not looked at.

    `_installed_commit()` returns `unknown` whenever the package has no
    readable `direct_url.json` — which is every run on a checkout where
    mykronos is not pip-installed from git. The script half then skips, says
    so, and the final line reported:

        The pin supports all 8 runner modules, their flags, and all 2
        raw-fetched scripts.

    A clean bill of health for a check that did not happen, in the one script
    whose entire purpose is catching a pin that has gone quietly stale. That
    has bitten twice — 53 commits at D-051, 61 at D-074 — and both times a
    person found it late.

    Exit 0 is unchanged and deliberate. Failing open is argued in the module
    docstring and the argument holds: an unresolvable pin on somebody's laptop
    is not a broken pipeline, and a check that goes red on a slow network is
    one people pause. Saying less is the fix, not saying no.
    """

    @pytest.mark.parametrize(
        "commit", ["", "unknown", "not installed", "local install", "unreadable"]
    )
    def test_an_unresolvable_commit_cannot_check_scripts(self, checker, commit) -> None:
        assert checker.can_check_scripts(commit) is False

    def test_a_real_commit_can(self, checker) -> None:
        assert checker.can_check_scripts("9cae400d75a8") is True

    def test_the_summary_says_the_scripts_were_not_checked(
        self, checker, monkeypatch, capsys
    ) -> None:
        monkeypatch.setattr(checker, "_installed_commit", lambda: "unknown")
        monkeypatch.setattr(checker, "check", lambda commit="": [])

        assert checker.main([]) == 0

        out = capsys.readouterr().out
        assert "NOT checked" in out
        assert "raw-fetched scripts." not in out, (
            "the summary still asserts the scripts are supported"
        )

    def test_a_resolvable_pin_still_gets_the_full_claim(
        self, checker, monkeypatch, capsys
    ) -> None:
        """The guard that this did not turn every pass into a hedge."""
        monkeypatch.setattr(checker, "_installed_commit", lambda: "9cae400d75a8")
        monkeypatch.setattr(checker, "check", lambda commit="": [])

        assert checker.main([]) == 0
        out = capsys.readouterr().out
        # Asserted on the hedge rather than the wording. The summary gained a
        # clause when the adapter check was added, and pinning the exact
        # sentence made this fail for a reason that had nothing to do with
        # what it is guarding.
        assert "NOT checked" not in out
        assert "raw-fetched scripts" in out
        assert "adapter pairs" in out


class TestTheRegistryIsCheckedToo:
    """The third way the pin goes stale, and the one that was not checked.

    Modules, flags and raw-fetched scripts were all asserted. The adapter
    registry was not — so a repository could point a lane at a new tool, the
    pinned runner could be unable to normalise its output, and this check
    stayed green. It did: `pin-check` succeeded at 2026-09-15 04:09 while
    keel's ShellCheck lane failed every run with

        ERROR No adapter for capability 'sast' with tool 'shellcheck'.
              Supported for 'sast': codeql, semgrep.

    `sast_shellcheck.py` landed 2026-09-09; v8, the newest tag, is from
    2026-08-30. The adapter exists on main and in no release.
    """

    def test_every_declared_pair_resolves_against_this_checkout(self, checker) -> None:
        """The working tree is the thing tags are cut from, so a pair that
        cannot resolve here is a typo rather than a stale pin."""
        assert checker._missing_adapters() == []

    def test_the_list_is_not_empty(self, checker) -> None:
        assert checker.REQUIRED_ADAPTERS

    def test_an_unsupported_pair_is_reported(self, checker, monkeypatch) -> None:
        monkeypatch.setattr(
            checker,
            "REQUIRED_ADAPTERS",
            checker.REQUIRED_ADAPTERS + (("sast", "not-a-real-tool"),),
        )

        problems = checker._missing_adapters()

        assert len(problems) == 1
        assert "not-a-real-tool" in problems[0]

    def test_the_message_names_what_the_pin_does_support(
        self, checker, monkeypatch
    ) -> None:
        """"No adapter" on its own sends the reader to the wrong place. The
        supported list is what distinguishes a typo from a stale pin."""
        monkeypatch.setattr(
            checker, "REQUIRED_ADAPTERS", (("sast", "not-a-real-tool"),)
        )

        problem = checker._missing_adapters()[0]

        assert "the pin supports:" in problem
        assert "codeql" in problem

    def test_a_registry_that_will_not_import_is_one_problem_not_fifteen(
        self, checker, monkeypatch
    ) -> None:
        """A pin whose registry is unimportable is unusable, and repeating that
        once per pair buries the sentence that matters."""
        import builtins

        real_import = builtins.__import__

        def fail_registry(name, *args, **kwargs):
            if name == "mykronos.adapters":
                raise ImportError("no registry in this pin")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fail_registry)

        problems = checker._missing_adapters()

        assert len(problems) == 1
        assert "registry will not import" in problems[0]

    def test_the_pairs_the_pipelines_upload_are_declared(self, checker) -> None:
        """The same discipline the module list keeps: a lane that uploads a
        pair nobody declared is a pair nothing checks."""
        root = SCRIPT.resolve().parents[1]
        declared = set(checker.REQUIRED_ADAPTERS)
        import re

        used = set()
        for path in (root / "deploy" / "concourse" / "pipelines").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            for cap, tool in re.findall(
                r"--capability ([a-z-]+) --tool ([a-z0-9_-]+)", text
            ):
                used.add((cap, tool))

        assert used, "found no --capability/--tool pairs to check against"
        assert used <= declared, f"undeclared pairs: {sorted(used - declared)}"
