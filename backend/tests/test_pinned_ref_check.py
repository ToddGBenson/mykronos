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


#: v8, the commit both Actions pins named until #337. No ShellCheck adapter,
#: no PSScriptAnalyzer adapter.
V8 = "cce7495afafb3f22b014847bd91624ced9b8e2dd"


class TestTheActionsPinsAreCheckedToo:
    """#337: the GitHub Actions workflows install the runner from
    `config.py`'s pins, not from the Concourse `mykronos-ref` this script
    introspects. Concourse moved to v14 and pin-check went green while the
    Actions pins stayed on v8, which has neither the ShellCheck nor the
    PSScriptAnalyzer adapter the `sast-shell` and `sast-powershell`
    templates upload under."""

    @staticmethod
    def _template_pairs() -> set[tuple[str, str]]:
        """Render every template with its defaults and read what its upload
        step declares. YAML, not a regex, so a reordered `with:` block still
        counts."""
        from mykronos.installer.templates import TemplateLibrary

        ref = "ToddGBenson/mykronos/actions/upload-results@" + "a" * 40
        library = TemplateLibrary(SCRIPT.resolve().parents[1] / "workflow-templates")
        pairs: set[tuple[str, str]] = set()
        for capability in sorted(library.available):
            rendered = library.render(
                capability,
                repo_full_name="o/r",
                default_branch="main",
                ingestion_api_url="https://mykronos.test",
                token_secret_name="MYKRONOS_TOKEN",
                upload_action_ref=ref,
                mykronos_package_spec="mykronos",
            )
            document = yaml.safe_load(rendered.content)
            for job in (document.get("jobs") or {}).values():
                for step in job.get("steps") or []:
                    if step.get("uses") == ref:
                        pairs.add((step["with"]["capability"], step["with"]["tool"]))
        return pairs

    def test_the_declared_pairs_are_what_the_templates_upload(self, checker) -> None:
        """The list the check enforces must be the templates' own; a template
        added without its pair here is a pair nothing checks."""
        rendered = self._template_pairs()

        assert ("sast", "shellcheck") in rendered
        assert ("sast", "psscriptanalyzer") in rendered
        assert rendered == set(checker.ACTIONS_TEMPLATE_ADAPTERS)

    def test_both_settings_are_found_and_name_one_commit(self, checker) -> None:
        """`config.py` says to keep them on the same tag: they install one
        package into one job, and the first install wins."""
        pins = checker.actions_pins()

        assert set(pins) == set(checker.ACTIONS_PIN_SETTINGS)
        assert len(set(pins.values())) == 1, pins

    def test_the_pins_match_the_settings_the_installer_uses(self, checker) -> None:
        """The source file is parsed, so check the parse against the loaded
        settings: a refactor of `config.py` must not leave this reading
        nothing."""
        from mykronos.config import Settings

        fields = Settings.model_fields
        pins = checker.actions_pins()
        for setting in checker.ACTIONS_PIN_SETTINGS:
            assert pins[setting] in str(fields[setting].default)

    def test_the_registry_parse_agrees_with_the_live_registry(self, checker) -> None:
        from mykronos.adapters import registry

        source = SCRIPT.resolve().parents[1] / "backend" / "mykronos" / "adapters" / "registry.py"
        assert checker.registry_pairs(source.read_text(encoding="utf-8")) == set(registry.REGISTRY)

    def test_the_pins_carry_every_template_adapter(self, checker) -> None:
        """The assertion #337 asks for. Read from the local object store, or
        the raw URL; skipped only when neither can reach the commit."""
        for setting, commit in checker.actions_pins().items():
            source = checker.registry_source_at(commit)
            if source is None:
                pytest.skip(f"cannot read registry.py at {commit[:12]} here")
            missing = set(checker.ACTIONS_TEMPLATE_ADAPTERS) - checker.registry_pairs(source)
            assert not missing, f"{setting} pins {commit[:12]}, missing {sorted(missing)}"

    def test_v8_would_have_been_caught(self, checker, monkeypatch) -> None:
        """The control: the commit the pins named before this fix fails."""
        source = checker.registry_source_at(V8)
        if source is None:
            pytest.skip("cannot read registry.py at v8 here")
        monkeypatch.setattr(
            checker, "actions_pins", lambda: dict.fromkeys(checker.ACTIONS_PIN_SETTINGS, V8)
        )

        problems = checker._actions_pin_problems()

        assert any("'shellcheck'" in p and "upload_action_ref" in p for p in problems)
        assert any("'psscriptanalyzer'" in p and "mykronos_package_spec" in p for p in problems)

    def test_an_unreadable_pin_is_skipped_not_failed(self, checker, monkeypatch, capsys) -> None:
        """Fails open, as the raw-script check does: an unreachable GitHub is
        not a stale pin."""
        monkeypatch.setattr(checker, "registry_source_at", lambda commit: None)

        assert checker._actions_pin_problems() == []
        assert "skipping" in capsys.readouterr().out


#: `atlas_osv._fixed_versions` as the v16 tag shipped it, before #1036: keyed
#: on the table row's id only, and stopping every rule after the first at the
#: blank line under its own heading. Kept verbatim so the control below is the
#: code TheHub's lanes actually ran, not a paraphrase of it.
def _fixed_versions_v16(raw_output: bytes) -> dict[tuple[str, str], str]:
    import json

    try:
        document = json.loads(raw_output.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    table: dict[tuple[str, str], str] = {}
    for run in document.get("runs") or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            markdown = (rule.get("help") or {}).get("markdown") or ""
            start = markdown.find("### Fixed Versions")
            if start < 0:
                continue
            for line in markdown[start:].splitlines()[1:]:
                line = line.strip()
                if not line.startswith("|"):
                    if table:
                        break
                    continue
                cells = [cell.strip() for cell in line.strip("|").split("|")]
                if len(cells) < 3:
                    continue
                if cells[0] == "Vulnerability ID" or set(cells[0]) <= set("- "):
                    continue
                table[(cells[0], cells[1])] = cells[2]
    return table


class TestBehaviourIsCheckedToo:
    """The fifth way the pin goes stale, and the one that cost a critical.

    Modules, flags, scripts and adapters were all checked, and every one of
    them was present at v16. What v16 did not have was #1036: osv-scanner
    names a rule after the CVE or PYSEC id and writes the fix under the GHSA
    alias, and v16's parser keyed on the alias only. #1036 merged and the
    backend deployed it, but normalising happens in the *uploader*, installed
    from `mykronos-ref`. So TheHub's atlas findings kept arriving with no
    `fixed_version` (pypdf x9 on 2026-11-01, `fixable=false` while OSV named
    6.21.2-6.21.4), and `pin-check` stayed green the whole time (TheHub
    #60909).

    A bug fix changes no module, flag or adapter name, so only running the
    pinned code on a known input can tell a fixed pin from a stale one.
    """

    def test_this_checkout_passes_every_probe(self, checker) -> None:
        assert checker._behaviour_problems() == []

    def test_the_probes_are_not_empty(self, checker) -> None:
        assert checker.REQUIRED_BEHAVIOURS

    def test_the_v16_osv_parser_is_caught(self, checker, monkeypatch) -> None:
        """The control: the parser TheHub's lanes ran before this fails."""
        from mykronos.adapters import atlas_osv

        monkeypatch.setattr(atlas_osv, "_fixed_versions", _fixed_versions_v16)

        problems = checker._behaviour_problems()

        assert len(problems) == 1
        assert "#60909" in problems[0]
        assert "fixed version" in problems[0]

    def test_check_reports_a_failed_probe(self, checker, monkeypatch) -> None:
        from mykronos.adapters import atlas_osv

        monkeypatch.setattr(atlas_osv, "_fixed_versions", _fixed_versions_v16)
        monkeypatch.setattr(checker, "_missing_scripts", lambda commit: [])
        monkeypatch.setattr(checker, "_actions_pin_problems", lambda: [])

        assert any("#60909" in p for p in checker.check("unknown"))

    def test_a_probe_that_cannot_run_is_a_problem_not_a_pass(
        self, checker, monkeypatch
    ) -> None:
        """A pin whose code cannot be asked has not shown it has the fix. This
        is the module docstring's own rule: a guard that passes when it cannot
        tell converts an open question into a green tick."""
        from mykronos.adapters import atlas_osv

        monkeypatch.delattr(atlas_osv, "_fixed_versions")

        problems = checker._behaviour_problems()

        assert len(problems) == 1
        assert "could not be run" in problems[0]

    def test_the_summary_names_the_probes(self, checker, monkeypatch, capsys) -> None:
        monkeypatch.setattr(checker, "_installed_commit", lambda: "9cae400d75a8")
        monkeypatch.setattr(checker, "check", lambda commit="": [])

        assert checker.main([]) == 0
        assert "behaviour probe" in capsys.readouterr().out


#: v14, the commit both Actions pins named after #337 and before TheHub
#: #61212. It has every template adapter, so the registry check passes it, and
#: it predates #1036, so every keel and binnacle atlas finding it normalised
#: arrived with no fixed version.
V14 = "8e2e41261b9f3695a1ab3616be2db7d8095cd486"

#: #1036's merge commit: the atlas fixed-version-under-aliases fix.
FIX_1036 = "13f5ab19ce9141b13832412e7d95a7402e9944b0"


class TestTheActionsPinsCarryTheBehaviourFixes:
    """TheHub #61212. The behaviour probes run the *installed* package, which
    is the Concourse pin. The GitHub Actions workflows install the commit
    `config.py` names instead, and that one cannot be imported here. So for
    the Actions pins each probe is backed by the commit that fixed it, and the
    pin must contain that commit. v14 passed the registry check (every
    adapter was there) while lacking #1036, which is how keel's and
    binnacle's atlas findings kept reading as unfixable after #1079 moved
    Concourse to v17."""

    def test_every_probe_names_its_fix_commit(self, checker) -> None:
        """A probe added without its commit is a fix nothing checks the
        Actions pins for."""
        names = {name for name, _ in checker.REQUIRED_BEHAVIOURS}

        assert set(checker.BEHAVIOUR_FIX_COMMITS) == names
        assert checker.BEHAVIOUR_FIX_COMMITS[
            "atlas osv-scanner fixed versions under aliases (#1036)"
        ] == FIX_1036
        for commit in checker.BEHAVIOUR_FIX_COMMITS.values():
            assert len(commit) == 40, commit

    def test_the_pins_contain_every_fix(self, checker) -> None:
        """The assertion #61212 asks for, on the pins this checkout ships."""
        for setting, commit in checker.actions_pins().items():
            for name, fix in checker.BEHAVIOUR_FIX_COMMITS.items():
                contains = checker.commit_contains(commit, fix)
                if contains is None:
                    pytest.skip(f"cannot compare {commit[:12]} with {fix[:12]} here")
                assert contains, f"{setting} pins {commit[:12]}, which lacks {name}"

    def test_v14_would_have_been_caught(self, checker, monkeypatch) -> None:
        """The control: the commit the pins named before this fix fails."""
        if checker.commit_contains(V14, FIX_1036) is None:
            pytest.skip("cannot compare v14 with #1036 here")
        monkeypatch.setattr(
            checker, "actions_pins", lambda: dict.fromkeys(checker.ACTIONS_PIN_SETTINGS, V14)
        )

        problems = checker._actions_behaviour_problems()

        assert len(problems) == 2
        assert any("upload_action_ref" in p and "#1036" in p for p in problems)
        assert any("mykronos_package_spec" in p and "8e2e41261b9f" in p for p in problems)

    def test_a_fix_is_contained_in_itself(self, checker) -> None:
        assert checker.commit_contains(FIX_1036, FIX_1036) in (True, None)

    def test_an_uncomparable_pin_is_skipped_not_failed(
        self, checker, monkeypatch, capsys
    ) -> None:
        """Fails open, as the registry check does: an unreachable GitHub is
        not a stale pin."""
        monkeypatch.setattr(checker, "commit_contains", lambda pin, fix: None)

        assert checker._actions_behaviour_problems() == []
        assert "skipping" in capsys.readouterr().out

    def test_a_shallow_clone_is_not_asked(self, checker, monkeypatch) -> None:
        """In a shallow clone `merge-base --is-ancestor` answers "no" for any
        fix below the cut, which would turn a fine pin red. The local answer
        is only trusted from a full history."""
        calls: list[list[str]] = []

        class Done:
            def __init__(self, returncode: int, stdout: str = "") -> None:
                self.returncode = returncode
                self.stdout = stdout

        def fake_run(args, **kwargs):
            calls.append(list(args))
            if "--is-shallow-repository" in args:
                return Done(0, "true
")
            return Done(1)

        monkeypatch.setattr(checker.subprocess, "run", fake_run)
        monkeypatch.setattr(checker, "_github_contains", lambda pin, fix: None)

        assert checker.commit_contains(V14, FIX_1036) is None
        assert not any("merge-base" in c for c in calls)

    def test_check_reports_a_pin_without_the_fix(self, checker, monkeypatch) -> None:
        monkeypatch.setattr(checker, "_missing_scripts", lambda commit: [])
        monkeypatch.setattr(checker, "_actions_pin_problems", lambda: [])
        monkeypatch.setattr(checker, "commit_contains", lambda pin, fix: False)

        assert any("#1036" in p and "config.py" in p for p in checker.check("unknown"))


class TestEveryPinNamesOneRef:
    """`mykronos-ref` is written in six places: three set-pipeline scripts and
    the three vars files the in-pipeline `set-pipeline` jobs apply. The
    scripts were compared with each other; the vars files, which are what a
    merge actually applies, were not compared with anything."""

    def test_the_vars_files_pin_what_the_scripts_pin(self) -> None:
        import re

        root = Path(__file__).resolve().parents[2] / "deploy" / "concourse"
        refs = {
            path.name: re.search(
                r'"mykronos-ref:\s*([^"]+)"', path.read_text(encoding="utf-8")
            ).group(1)
            for path in root.glob("set-*pipeline.ps1")
        }
        for name in ("mykronos.yml", "thehub.yml", "personal-soc.yml"):
            document = yaml.safe_load((root / "vars" / name).read_text(encoding="utf-8"))
            refs[f"vars/{name}"] = str(document["mykronos-ref"])

        assert len(set(refs.values())) == 1, refs
