"""AI supply-chain and prompt-safety checks (D-047).

Every rule here must be shown to fire. A checker that finds nothing looks
exactly like a clean repository, and this one has already been wrong in that
direction: its first draft matched any quoted model name and reported three
findings against this repository, all false.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_ai.py"
_spec = importlib.util.spec_from_file_location("check_ai", _SCRIPT)
assert _spec and _spec.loader
check_ai = importlib.util.module_from_spec(_spec)
sys.modules["check_ai"] = check_ai
_spec.loader.exec_module(check_ai)


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


class TestModelProvenance:
    def test_an_unpinned_model_is_a_finding(self, tmp_path: Path) -> None:
        write(tmp_path, "app.py", 'client.create(model="claude-sonnet-4-5")\n')

        findings, uses = check_ai.check(tmp_path)

        assert uses is True
        assert [f.rule_id for f in findings if f.rule_id == "ai-model-unpinned"]

    @pytest.mark.parametrize(
        "identifier",
        ["claude-sonnet-4-5-20260101", "gpt-4o-2024-11-20", "claude-3:5"],
    )
    def test_a_pinned_model_is_not(self, tmp_path: Path, identifier: str) -> None:
        write(tmp_path, "app.py", f'model = "{identifier}"\nevals/\n')
        write(tmp_path, "evals/case.py", "x = 1\n")

        findings, _ = check_ai.check(tmp_path)

        assert [f for f in findings if f.rule_id == "ai-model-unpinned"] == []

    def test_a_model_named_in_prose_is_not_a_finding(self, tmp_path: Path) -> None:
        """The false positive that changed the rule. A keyword list detecting
        AI mentions in pull request bodies, and a docstring giving an example,
        are documentation about models rather than calls to one."""
        write(
            tmp_path,
            "aegis_signals.py",
            'KEYWORDS = ("copilot", "claude-3", "gpt-4", "llm")\n'
            '"""Mentions claude-sonnet-4-5 as an example."""\n',
        )

        findings, uses = check_ai.check(tmp_path)

        assert uses is False
        assert findings == []


class TestPromptInjectionSurface:
    def test_untrusted_input_in_a_prompt_is_an_error(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "handler.py",
            'prompt = f"Summarise this: {request.body}"\n',
        )

        findings, _ = check_ai.check(tmp_path)
        injection = [f for f in findings if f.rule_id == "ai-prompt-injection-surface"]

        assert injection and injection[0].level == "error"

    def test_a_template_literal_counts_too(self, tmp_path: Path) -> None:
        write(tmp_path, "handler.ts", "const prompt = `Answer: ${req.query.q}`;\n")

        findings, _ = check_ai.check(tmp_path)

        assert [f for f in findings if f.rule_id == "ai-prompt-injection-surface"]

    def test_a_constant_prompt_is_not_a_finding(self, tmp_path: Path) -> None:
        write(tmp_path, "handler.py", 'prompt = "Summarise the attached document."\n')

        findings, _ = check_ai.check(tmp_path)

        assert findings == []

    def test_it_admits_the_heuristic(self, tmp_path: Path) -> None:
        """It matched a shape. It has not proved the input is reachable, and
        saying so is the difference between a lead and a claim."""
        write(tmp_path, "h.py", 'prompt = f"x {user.input}"\n')

        findings, _ = check_ai.check(tmp_path)

        assert "not proved" in findings[0].message


class TestEvaluationCoverage:
    def test_a_model_caller_with_no_evals_is_a_finding(self, tmp_path: Path) -> None:
        write(tmp_path, "app.py", 'model="claude-sonnet-4-5-20260101"\n')

        findings, _ = check_ai.check(tmp_path)

        assert [f for f in findings if f.rule_id == "ai-no-evaluation-suite"]

    def test_an_eval_suite_satisfies_it(self, tmp_path: Path) -> None:
        write(tmp_path, "app.py", 'model="claude-sonnet-4-5-20260101"\n')
        write(tmp_path, "evals/test_quality.py", "x = 1\n")

        findings, _ = check_ai.check(tmp_path)

        assert [f for f in findings if f.rule_id == "ai-no-evaluation-suite"] == []

    def test_a_repository_with_no_model_is_not_asked_for_evals(
        self, tmp_path: Path
    ) -> None:
        """Nothing to evaluate, and demanding an eval suite would be noise.
        (Not mykronos's own state any more: its reviewer names a model - see
        TestModelsGivenAsDefaultsAndFallbacks.)"""
        write(tmp_path, "app.py", "x = 1\n")

        findings, uses = check_ai.check(tmp_path)

        assert uses is False
        assert findings == []


class TestSarif:
    def test_it_emits_valid_sarif(self, tmp_path: Path) -> None:
        write(tmp_path, "app.py", 'prompt = f"{request.body}"\nmodel="claude-x"\n')
        findings, _ = check_ai.check(tmp_path)

        document = check_ai.sarif(findings)

        assert document["version"] == "2.1.0"
        run = document["runs"][0]
        assert run["tool"]["driver"]["name"] == "mykronos-ai-checks"
        assert len(run["results"]) == len(findings)
        assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]

    def test_every_rule_the_checker_can_emit_appears_in_sarif(
        self, tmp_path: Path
    ) -> None:
        """The guard that has been needed three times today: a rule that
        cannot reach the report is a rule that silently does nothing."""
        write(tmp_path, "app.py", 'prompt = f"{request.body}"\nmodel="claude-x"\n')
        findings, _ = check_ai.check(tmp_path)

        emitted = {r["id"] for r in check_ai.sarif(findings)["runs"][0]["tool"]["driver"]["rules"]}

        assert emitted == {
            "ai-prompt-injection-surface",
            "ai-model-unpinned",
            "ai-no-evaluation-suite",
        }


class TestARootWithNothingInIt:
    """"Nothing to check" and "nothing was there" printed the same sentence.

    `main` used to print `No model references found - nothing to check.` and
    exit 0 for both a repository that calls no model — a result — and a path
    with no source in it — the absence of an input.

    TheHub's `ai-models` job has reported 0 findings on all 74 of its builds.
    The same checker, at the same pinned commit (`7e23c9b1`, byte-identical to
    `main`), run the same way (`check_ai.py source`) against a clean clone of
    the branch that job scans, finds **seven**. The build log shows the
    checker printing the "nothing to check" line while `check.py` — same
    container, same working directory — had listed model references out of
    `source/` two lines earlier.

    I have not established what puts the checker in front of an empty tree.
    This is the part that is fixable without knowing: it must not be possible
    for that to look like a pass.

    personal-soc's PSScriptAnalyzer task already says exactly this and exits 1
    when it finds no `.ps1` files — "A check that examined nothing has not
    passed - it has lost track of what it was pointed at." This brings the
    same rule here.
    """

    def test_a_missing_root_is_an_error_not_a_pass(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = check_ai.main([str(tmp_path / "does-not-exist")])

        assert code == 2, "a path that is not there must not exit 0"
        assert "examined nothing" in capsys.readouterr().err

    def test_an_empty_root_is_an_error_too(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The shape the pipeline hits: the directory exists and is empty.

        A missing path and an empty one fail for the same reason and must
        report the same way. Only one of them is a typo.
        """
        (tmp_path / "source").mkdir()

        assert check_ai.main([str(tmp_path / "source")]) == 2
        assert "examined nothing" in capsys.readouterr().err

    def test_a_repository_with_source_and_no_models_still_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The guard that this did not turn a real clean result into an error.

        A repository that calls no model is a genuine pass, and the sentence
        that says so has to survive — it is what keeps a clean report from
        reading as evidence of anything.
        """
        write(tmp_path, "util.py", "def add(a, b):\n    return a + b\n")

        assert check_ai.main([str(tmp_path)]) == 0
        assert "No model references found" in capsys.readouterr().out


class TestARootUnderADirectoryNamedLikeAVendorTree:
    """A directory ABOVE the root must not disqualify the scan.

    `_files` tested `SKIP_DIRS` against `p.parts` — the absolute path, because
    `main` resolves the root. Concourse runs every task in `/tmp/build/<guid>/`
    and `build` is in `SKIP_DIRS`, so on TheHub's `ai-models` job every file
    came out as `/tmp/build/<guid>/source/backend/config.py` and was skipped.

    74 consecutive builds reported a clean repository. `check.py`, in the same
    task and the same working directory, used a relative `Path("source")` and
    listed the model references this checker missed. The two differed by
    `.resolve()`.

    Reproduced by copying a clone under a directory named `build`: seven
    findings became zero, and back to seven with the fix.
    """

    @pytest.mark.parametrize("wrapper", ["build", "dist", "node_modules", ".venv"])
    def test_the_scan_survives_its_own_absolute_path(
        self, tmp_path: Path, wrapper: str
    ) -> None:
        root = tmp_path / wrapper / "abc123" / "source"
        root.mkdir(parents=True)
        write(root, "app.py", 'model = "claude-sonnet-4-6"\n')

        findings, uses = check_ai.check(root.resolve())

        assert uses, f"a root under {wrapper}/ was skipped entirely"
        assert "ai-model-unpinned" in [f.rule_id for f in findings]

    def test_a_vendor_tree_inside_the_project_is_still_skipped(
        self, tmp_path: Path
    ) -> None:
        """The guard that this did not simply disable SKIP_DIRS.

        Vendored code is somebody else's unpinned model and not this
        repository's finding, which is the whole reason the list exists.
        """
        write(tmp_path, "app.py", 'model = "claude-sonnet-4-6-20260101"\n')
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        write(vendored, "vendored.py", 'model = "claude-3-opus"\n')

        findings, _ = check_ai.check(tmp_path.resolve())

        # The repository's own model is pinned, so the only thing that could
        # produce an `ai-model-unpinned` here is the vendored copy.
        assert "ai-model-unpinned" not in [f.rule_id for f in findings], (
            "a vendored model reference became this repository's finding"
        )
        assert not [f for f in findings if "node_modules" in f.file]
class TestTheCheckerDoesNotFlagItsOwnCorpus:
    """A detector's tests contain the thing it detects.

    `check_ai.py` had an absolute-path bug that made it skip every file
    (#308). Fixing that turned the scan on for the first time, and the first
    thing it found was this file: five `ai-prompt-injection-surface` findings
    at `error`, every one of them a fixture written as a string literal a few
    lines above the assertion that `check()` flags it. That took `oracle-gate`
    red and blocked `promote` behind it.

    Excluding test directories is the fix. This pins it, because the failure
    is invisible when running the checker against a temp path -- which is
    exactly what every other test in this file does.
    """

    def test_a_test_directory_is_not_scanned(self, tmp_path: Path) -> None:
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "test_thing.py").write_text(
            'prompt = f"Summarise this: {request.body}"\n', encoding="utf-8"
        )

        findings, _ = check_ai.check(tmp_path)

        assert not [
            f for f in findings if f.rule_id == "ai-prompt-injection-surface"
        ], "a fixture inside tests/ must not be reported as a production surface"

    def test_the_same_file_outside_tests_is_still_scanned(self, tmp_path: Path) -> None:
        """The exclusion is about location, not about the pattern."""
        write(tmp_path, "handler.py", 'prompt = f"Summarise this: {request.body}"\n')

        findings, _ = check_ai.check(tmp_path)

        assert [f for f in findings if f.rule_id == "ai-prompt-injection-surface"]

    def test_this_repository_scans_clean(self) -> None:
        """The regression itself: run the checker over the real tree."""
        root = Path(__file__).resolve().parents[2]
        findings, _ = check_ai.check(root)

        offenders = [
            f for f in findings
            if f.rule_id == "ai-prompt-injection-surface"
            and "test" in str(getattr(f, "file_path", "")).lower()
        ]
        assert not offenders, f"checker flags its own test material: {offenders[:3]}"


class TestModelsGivenAsDefaultsAndFallbacks:
    """The audit of 2026-10-20: the `ai` lane said "No model references found
    - nothing to check." against this repository, which configures its own
    independent reviewer's model in `config.py` (a pydantic `default=`) and
    falls back to it in `approvals/reviewer.py` (`... or "<id>"`).
    MODEL_REFERENCE only knew `model = "..."`, so neither was seen.
    """

    @pytest.mark.parametrize(
        "line",
        [
            '    default="claude-opus-5",\n',
            '    model = str(getattr(settings, "reviewer_model", "") or "claude-opus-5")\n',
            'reviewer_model: str = "claude-opus-5"\n',
            'REVIEWER_MODEL = "gpt-5"\n',
            'name = os.environ.get("REVIEWER", "claude-opus-5")\n',
            'name = getattr(settings, "reviewer", "claude-opus-5")\n',
            "const m = process.env.MODEL ?? 'claude-opus-5';\n",
            "const m = cfg.reviewer || 'claude-opus-5';\n",
            "      MYKRONOS_REVIEWER_MODEL: ${MYKRONOS_REVIEWER_MODEL:-claude-opus-5}\n",
            "  default: 'gemini-2-pro'\n",
        ],
    )
    def test_a_default_or_fallback_model_is_seen(self, tmp_path: Path, line: str) -> None:
        write(tmp_path, "app.py", line)

        findings, uses = check_ai.check(tmp_path)

        assert uses is True, f"not seen as a model reference: {line!r}"
        assert [f for f in findings if f.rule_id == "ai-model-unpinned"]

    @pytest.mark.parametrize(
        "line",
        [
            'KEYWORDS = ("copilot", "claude-3", "gpt-4", "llm")\n',
            '"""Reviewed by gpt-4 or claude-3 in the example."""\n',
            '    description="Only this model family, e.g. claude-opus-5.5.",\n',
            "#: `claude-opus-5` reviewing `claude-opus-5.5` passed as a different family.\n",
            'family: str = Field(description="e.g. `claude-opus-5.5`")\n',
        ],
    )
    def test_documentation_about_models_is_still_not_a_reference(
        self, tmp_path: Path, line: str
    ) -> None:
        """The widening must not reopen the first draft's false positives."""
        write(tmp_path, "aegis_signals.py", line)

        findings, uses = check_ai.check(tmp_path)

        assert uses is False, f"prose read as a model reference: {line!r}"
        assert findings == []

    def test_a_pinned_default_is_seen_and_not_flagged(self, tmp_path: Path) -> None:
        write(tmp_path, "config.py", '    default="claude-sonnet-4-5-20250929",\n')
        write(tmp_path, "evals/case.py", "x = 1\n")

        findings, uses = check_ai.check(tmp_path)

        assert uses is True
        assert findings == []

    def test_this_repository_is_not_reported_as_calling_no_model(self) -> None:
        """The regression itself, against the real tree.

        This repository runs a model (spec 34 §4.3's independent reviewer), so
        "No model references found - nothing to check." is a false statement
        about it. If the reviewer is ever removed, this test should be deleted
        with it, not loosened.
        """
        root = Path(__file__).resolve().parents[2]

        findings, uses = check_ai.check(root)

        assert uses is True
        flagged = {f.file for f in findings if f.rule_id == "ai-model-unpinned"}
        assert "backend/mykronos/config.py" in flagged
        assert "backend/mykronos/approvals/reviewer.py" in flagged
