"""AI supply-chain and prompt-safety checks, emitting SARIF (D-047).

Three of the four concerns D-047 names. The fourth — whether a pull request
discloses that a model wrote it — stays in Aegis, because that is a question
about a person and this is a question about a repository.

**1. Model provenance.** Which model, pinned to what. An unpinned identifier
is the same class of problem as an unpinned dependency, which Atlas already
treats as a finding: `claude-sonnet-4-5` silently becomes a different model
when the vendor moves the alias, and the behaviour a repository was evaluated
against is not the behaviour it ships.

**2. Prompt-injection surface.** Untrusted input reaching a prompt without
separation. Heuristic by construction — it looks for interpolation of
request-shaped data into prompt-shaped strings — and it says so rather than
claiming to have proved reachability.

**3. Evaluation coverage.** A repository that calls a model and has no
evaluation suite has no way to notice the model getting worse.

Emits SARIF because the platform's `ai` capability accepts SARIF from any
tool (D-047). A capability that only reads its own tool's output is a
capability with one tool for ever.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".next",
    "dist",
    "build",
}

CODE_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".jsx", ".yml", ".yaml", ".toml"}

#: A pinned Anthropic or OpenAI identifier carries a date or an explicit
#: version. `-latest`, or a bare family name, resolves to whatever the vendor
#: is serving today.
#: Must be *assigned to something model-shaped*, not merely mentioned. The
#: first draft matched any quoted `claude-*` or `gpt-*` string and reported
#: three findings against this repository, all false: a keyword list in Aegis
#: that detects AI mentions in pull request bodies, and this file's own
#: docstring. A rule that fires on documentation about models teaches people
#: that AI findings are noise.
MODEL_REFERENCE = re.compile(
    r"""\bmodel(?:_name|_id)?["']?\s*[=:]\s*["'`]"""
    r"""((?:claude|gpt|o1|o3|gemini|llama|mistral)[a-z0-9.\-]*)["'`]""",
    re.IGNORECASE,
)
PINNED = re.compile(r"(\d{8}|\d{4}-\d{2}-\d{2}|@\d|:\d)")

#: Interpolation of caller-shaped data into a prompt-shaped string. Deliberately
#: narrow: `prompt`/`system`/`messages` near an f-string or template literal
#: carrying something that reads like request input.
PROMPT_SINK = re.compile(
    r"(prompt|system_prompt|messages|instructions)\s*[=:]\s*[fr]?['\"`]",
    re.IGNORECASE,
)
UNTRUSTED = re.compile(
    r"\{[^}]*\b(request|body|query|params|input|user|message|content|payload|args)\b[^}]*\}"
    r"|\$\{[^}]*\b(req|body|query|params|input|user|message|content|payload)\b[^}]*\}",
    re.IGNORECASE,
)

EVAL_HINTS = ("eval", "evals", "evaluation", "rubric", "golden", "fixture")


@dataclass
class Finding:
    rule_id: str
    level: str
    message: str
    file: str
    line: int


def _files(root: Path) -> list[Path]:
    return [
        p
        for p in sorted(root.rglob("*"))
        if p.suffix in CODE_SUFFIXES
        and p.is_file()
        and not any(part in SKIP_DIRS for part in p.parts)
    ]


def check(root: Path) -> tuple[list[Finding], bool]:
    """Returns the findings and whether any model reference was seen at all."""
    findings: list[Finding] = []
    uses_a_model = False
    has_evals = False

    for path in _files(root):
        relative = path.relative_to(root).as_posix()
        if any(hint in relative.lower() for hint in EVAL_HINTS):
            has_evals = True
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for number, line in enumerate(lines, 1):
            for match in MODEL_REFERENCE.finditer(line):
                identifier = match.group(1)
                # A bare family word is prose, not a model reference. Requiring
                # a hyphen keeps "claude" in a comment out of the results.
                if "-" not in identifier:
                    continue
                uses_a_model = True
                if not PINNED.search(identifier):
                    findings.append(
                        Finding(
                            rule_id="ai-model-unpinned",
                            level="warning",
                            message=(
                                f"Model '{identifier}' is not pinned to a version or "
                                "date. The vendor moves these aliases, so the model "
                                "evaluated against is not necessarily the model that "
                                "ships - the same problem as an unpinned dependency."
                            ),
                            file=relative,
                            line=number,
                        )
                    )

            if PROMPT_SINK.search(line) and UNTRUSTED.search(line):
                findings.append(
                    Finding(
                        rule_id="ai-prompt-injection-surface",
                        level="error",
                        message=(
                            "Caller-controlled data is interpolated into a prompt. "
                            "A model cannot distinguish instructions from content, so "
                            "text arriving here is executed as intent. Separate it - "
                            "put untrusted input in its own message or delimited block "
                            "and state that it is data. Heuristic: this matched the "
                            "shape, it has not proved the input is reachable."
                        ),
                        file=relative,
                        line=number,
                    )
                )

    if uses_a_model and not has_evals:
        findings.append(
            Finding(
                rule_id="ai-no-evaluation-suite",
                level="warning",
                message=(
                    "This repository calls a model and has no evaluation suite. "
                    "Without one there is no way to notice the model getting worse "
                    "- a regression in an AI feature is silent by default, because "
                    "it still returns something."
                ),
                file=".",
                line=1,
            )
        )

    return findings, uses_a_model


def sarif(findings: list[Finding]) -> dict:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mykronos-ai-checks",
                        "informationUri": "https://github.com/ToddGBenson/mykronos",
                        "rules": [
                            {"id": rule}
                            for rule in sorted({f.rule_id for f in findings})
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": f.level,
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file},
                                    "region": {"startLine": f.line},
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--sarif", default="", help="Write SARIF here.")
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help=(
            "Exit non-zero when an error-level finding is present. Off by "
            "default: the findings reach Mykronos either way, and Oracle "
            "decides what blocks (spec 09)."
        ),
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    findings, uses_a_model = check(root)

    if args.sarif:
        destination = Path(args.sarif)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(sarif(findings), indent=2), encoding="utf-8")

    if not uses_a_model:
        # Said out loud. A clean report from a repository that calls no model
        # is not evidence of anything, and reads identically to a clean report
        # from one that does.
        print("No model references found - nothing to check.")
    for finding in findings:
        print(f"{finding.file}:{finding.line}: {finding.rule_id}: {finding.message[:90]}")
    print(f"\n{len(findings)} AI finding(s).")

    errors = [f for f in findings if f.level == "error"]
    return 1 if (args.fail_on_error and errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
