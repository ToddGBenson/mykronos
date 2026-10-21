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

#: Directories whose contents are test material rather than shipped code.
#:
#: Separate from SKIP_DIRS, which lists vendored trees this project did not
#: write. These are ours, and they are excluded for a different reason: a test
#: for a detector contains, by construction, the thing the detector looks for.
#:
#: `backend/tests/test_ai_checks.py` builds an interpolated-prompt example as
#: a STRING LITERAL, writes it to a temp file, and asserts that `check()` flags
#: it. Scanning the test source therefore reports the fixture as a real
#: injection surface. Five of them, at `error`, which is what took
#: `oracle-gate` red on 2026-09-13 and blocked `promote` behind it.
#:
#: The example is deliberately NOT reproduced here. Writing it out put the
#: pattern in this file, and the first run after that flagged this comment --
#: a detector cannot quote its own signature in its own source.
#:
#: This is a scope decision and not a suppression: a prompt assembled from
#: untrusted input inside a test is not a production surface, and every SAST
#: tool this pipeline runs already excludes tests for the same reason. The
#: cost is that a genuine injection surface in a test *helper* goes unseen,
#: which is the cheaper of the two mistakes.
TEST_DIRS = {"tests", "test", "__tests__", "testdata", "fixtures"}

#: A pinned Anthropic or OpenAI identifier carries a date or an explicit
#: version. `-latest`, or a bare family name, resolves to whatever the vendor
#: is serving today.
#: Must be *assigned to something model-shaped*, not merely mentioned. The
#: first draft matched any quoted `claude-*` or `gpt-*` string and reported
#: three findings against this repository, all false: a keyword list in Aegis
#: that detects AI mentions in pull request bodies, and this file's own
#: docstring. A rule that fires on documentation about models teaches people
#: that AI findings are noise.
#:
#: One model identifier. Shared by both patterns below so they cannot
#: disagree about what a model id looks like.
_MODEL_ID = r"((?:claude|gpt|o1|o3|gemini|llama|mistral)[a-z0-9.\-]*)"

#: Assigned to a model-shaped name: `model=`, `model_id:`, and -- since the
#: audit of 2026-10-20 -- any name *ending* in one, with or without a type
#: annotation (`reviewer_model: str = "..."`, `REVIEWER_MODEL = "..."`).
#: `\bmodel` alone missed every prefixed name, because `_` is a word
#: character and `reviewer_model` has no boundary before `model`.
MODEL_REFERENCE = re.compile(
    r"""\b\w*model(?:_name|_id)?["']?\s*(?::\s*[\w\[\]|. ]+?\s*=|[=:])\s*["'`]"""
    + _MODEL_ID
    + r"""["'`]""",
    re.IGNORECASE,
)

#: A model id given as a DEFAULT or a FALLBACK rather than assigned to a
#: model-named variable. This repository's own reviewer model is configured
#: exactly this way -- a pydantic `Field(default=<id>)` in `config.py`, and an
#: `or <id>` fallback after a `getattr` in `approvals/reviewer.py` -- and
#: MODEL_REFERENCE saw neither (written without the literal here: a detector
#: cannot quote its own signature in its own source, see TEST_DIRS), so the
#: `ai` lane printed "No model references found - nothing to check." against a
#: repository that ships a model call.
#:
#: Still a *code shape*, never a bare mention, for the reason MODEL_REFERENCE
#: gives: a keyword tuple (`("claude-3", "gpt-4")`) or a docstring example is
#: documentation about models, not a call to one. Each alternative needs
#: syntax only code has:
#:
#: * `default="…"` / `default: "…"` -- a keyword or YAML default;
#: * `or "…"`, `?? "…"`, `|| "…"` -- a fallback (quoted, so prose such as
#:   "gpt-4 or claude-3" does not count);
#: * `getattr(x, "y", "…")`, `.get("y", "…")`, `getenv("Y", "…")` -- the
#:   last argument of a lookup;
#: * `${VAR:-…}` -- a shell or compose default.
MODEL_DEFAULT = re.compile(
    r"""(?:\bdefault\s*[=:]\s*|\bor\s+|\?\?\s*|\|\|\s*)["'`]"""
    + _MODEL_ID
    + r"""["'`]"""
    + r"""|(?:\bgetattr|\.get|\bgetenv)\([^()]*,\s*["'`]"""
    + _MODEL_ID
    + r"""["'`]\s*\)"""
    + r"""|:-"""
    + _MODEL_ID
    + r"""(?=[}\s"'`]|$)""",
    re.IGNORECASE,
)


def model_references(line: str) -> list[str]:
    """Every model identifier on `line`, once each, in order of appearance.

    A bare family word is prose, not a model reference: requiring a hyphen
    keeps "claude" in a comment out of the results.
    """
    seen: dict[int, str] = {}
    for pattern in (MODEL_REFERENCE, MODEL_DEFAULT):
        for match in pattern.finditer(line):
            for index, group in enumerate(match.groups(), 1):
                if group and "-" in group:
                    seen.setdefault(match.start(index), group)
    return [seen[start] for start in sorted(seen)]


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
    """Every scannable file under `root`, skipping the usual vendored trees.

    `relative_to(root)`, not `p.parts`. `SKIP_DIRS` is a statement about
    directories *inside* the project — `node_modules`, `dist`, `.venv` — and
    testing it against the absolute path lets a directory ABOVE the root
    disqualify the entire scan.

    That is not hypothetical. Concourse runs every task in `/tmp/build/<guid>/`
    and `main` resolves the root to an absolute path, so on TheHub's
    `ai-models` job every file came out as
    `/tmp/build/<guid>/source/backend/config.py` — whose parts contain
    `build`, which is in `SKIP_DIRS`. Nothing was ever scanned, on 74
    consecutive builds, and the checker reported a clean repository each time.

    `check.py`, in the same task and the same directory, uses a relative
    `Path("source")` and found the model references this one missed. The two
    scripts differed by `.resolve()`.
    """
    return [
        p
        for p in sorted(root.rglob("*"))
        if p.suffix in CODE_SUFFIXES
        and p.is_file()
        and not any(
            part in SKIP_DIRS or part in TEST_DIRS
            for part in p.relative_to(root).parts
        )
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
            for identifier in model_references(line):
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

    # A check that examined nothing has not passed; it has lost track of what
    # it was pointed at. personal-soc's PSScriptAnalyzer task says exactly
    # that and exits 1 when it finds no .ps1 files. This one printed "No
    # model references found - nothing to check." and exited 0 — the same
    # sentence, and the same exit code, as a repository that genuinely calls
    # no model.
    #
    # Those two states were indistinguishable, and the difference mattered:
    # TheHub's `ai-models` job has reported 0 findings on every one of its 74
    # builds, while this same checker — at the same pinned commit, run the
    # same way — finds seven in a clean clone of the branch that job scans.
    # Whatever puts the checker in front of an empty tree, it should say so
    # rather than pass.
    #
    # `any()` rather than a count: it stops at the first file, so this costs
    # one directory entry on a repository that has any source at all.
    if not any(_files(root)):
        print(
            f"ERROR: no source files under {root}. A check that examined "
            "nothing has not passed - it has lost track of what it was "
            "pointed at.",
            file=sys.stderr,
        )
        return 2

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
