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
        """Nothing to evaluate. This is the state mykronos itself is in, and
        demanding an eval suite of it would be noise."""
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
