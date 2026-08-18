"""The `ai` capability's first default tool (spec 17 §6, D-047).

D-047 split "AI" into four concerns and put three of them — prompt-injection
surface, model/dependency provenance, and evaluation regression — into a
`ai`/`ai-checks` capability that accepts SARIF from any tool
(`adapters/registry.py`'s `AdapterSpec("ai", "mykronos-ai-checks", ...)`).
That capability existed with no tool behind it: a slot, not a running check.

This is the provenance third, and only the third — deterministic, matching
D-047's own framing verbatim: "an unpinned model is treated like an unpinned
dependency." It scans dependency manifests for an LLM SDK pinned to a
floating version (`>=`, `^`, `~`, no version at all) rather than an exact one,
the same class of finding Atlas already produces for ordinary dependencies
(spec 07), scoped to the AI-specific package set.

**Prompt-injection detection and evaluation-regression detection are
deliberately not here.** The first needs a semantic classifier, the second a
runtime eval harness — neither is a pattern a script can honestly claim to
do, and stubbing either with a check that always passes (or always finds
nothing) would produce false confidence rather than an honest "not yet
built." The capability accepts SARIF from any tool; a future one can add
either without this module changing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Package names this checks for, per ecosystem. Deliberately a short,
#: named list rather than "anything with 'ai' in the name" — that would
#: false-positive on `fairness`, `aiohttp`, `paint`, and a hundred others
#: that have nothing to do with an LLM SDK.
#: `boto3` deliberately absent — Bedrock's SDK *is* boto3, and boto3 is used
#: for enough non-AI purposes that flagging it here would be mostly noise
#: about S3 buckets and IAM roles, not about a model.
PYTHON_AI_PACKAGES = frozenset(
    {
        "anthropic",
        "openai",
        "google-generativeai",
        "google-genai",
        "cohere",
        "langchain",
        "langchain-anthropic",
        "langchain-openai",
        "langchain-google-genai",
        "mistralai",
    }
)

NPM_AI_PACKAGES = frozenset(
    {
        "@anthropic-ai/sdk",
        "openai",
        "@google/generative-ai",
        "@google-cloud/vertexai",
        "cohere-ai",
        "langchain",
        "@langchain/anthropic",
        "@langchain/openai",
    }
)

#: A pinned Python requirement is `==x.y.z`, nothing else. `>=`, `~=`, `^`,
#: a bare name, or a URL/VCS reference are all floating for this purpose —
#: the point is "will this install a different version tomorrow than today."
_PY_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9_.\-+]*)\s*(?:#.*)?$"
)

_NPM_FLOATING_PREFIX = re.compile(r"^[\^~>=<*]|^latest$|^\*$")


@dataclass(frozen=True)
class PinFinding:
    package: str
    ecosystem: str
    file_path: str
    line: int
    declared_version: str
    reason: str

    @property
    def rule_id(self) -> str:
        return f"mykronos-ai-pin/{self.ecosystem}-unpinned"


def _scan_requirements_txt(path: Path, repo_root: Path) -> list[PinFinding]:
    findings: list[PinFinding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = _PY_REQUIREMENT.match(line)
        if not match:
            continue
        name, operator, version = match.groups()
        package = name.lower()
        if package not in PYTHON_AI_PACKAGES:
            continue
        if operator == "==" and version:
            continue  # Pinned. Nothing to report.
        findings.append(
            PinFinding(
                package=name,
                ecosystem="pip",
                file_path=str(path.relative_to(repo_root)),
                line=lineno,
                declared_version=line,
                reason=(
                    f"'{name}' has no exact pin ('{operator or 'none'}' "
                    "constraint) — an LLM SDK update can silently change "
                    "model defaults, request shapes, or safety behaviour."
                ),
            )
        )
    return findings


def _scan_package_json(path: Path, repo_root: Path) -> list[PinFinding]:
    findings: list[PinFinding] = []
    try:
        document = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return findings
    if not isinstance(document, dict):
        return findings

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = document.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if name not in NPM_AI_PACKAGES or not isinstance(version, str):
                continue
            if not _NPM_FLOATING_PREFIX.match(version.strip()) and version.strip():
                continue  # An exact version, no range operator. Pinned.
            findings.append(
                PinFinding(
                    package=name,
                    ecosystem="npm",
                    file_path=str(path.relative_to(repo_root)),
                    # package.json has no line-per-dependency once parsed as
                    # JSON; 1 is honest rather than a fabricated location.
                    line=1,
                    declared_version=version,
                    reason=(
                        f"'{name}' is pinned to a range ('{version}'), not an "
                        "exact version — an LLM SDK update can silently "
                        "change model defaults, request shapes, or safety "
                        "behaviour."
                    ),
                )
            )
    return findings


def scan(repo_root: Path) -> list[PinFinding]:
    """Every unpinned AI-SDK reference under `repo_root`."""
    findings: list[PinFinding] = []
    for path in repo_root.rglob("requirements*.txt"):
        if "node_modules" in path.parts or ".git" in path.parts:
            continue
        findings.extend(_scan_requirements_txt(path, repo_root))
    for path in repo_root.rglob("package.json"):
        if "node_modules" in path.parts or ".git" in path.parts:
            continue
        findings.extend(_scan_package_json(path, repo_root))
    return sorted(findings, key=lambda f: (f.file_path, f.line, f.package))


def to_sarif(findings: list[PinFinding]) -> dict[str, Any]:
    """SARIF 2.1.0, ingested by the shared `sarif_to_findings` converter
    (spec 04 §4) — this tool writes no bespoke format, on purpose (spec 17
    §6): the `ai` capability already accepts SARIF from anything."""
    rules = {
        f.rule_id: {
            "id": f.rule_id,
            "name": f"Unpinned {f.ecosystem} AI SDK",
            "shortDescription": {"text": "An AI SDK dependency has no exact version pin."},
            "properties": {"security-severity": "5.0"},  # medium — see module docstring
        }
        for f in findings
    }
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mykronos-ai-pin-check",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/ToddGBenson/mykronos",
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "message": {"text": f.reason},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.file_path},
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
    parser = argparse.ArgumentParser(
        description=(
            "Scan dependency manifests for unpinned AI SDK references and "
            "emit SARIF (spec 17 §6)."
        )
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    findings = scan(args.repo_root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
    print(f"mykronos-ai-pin-check: {len(findings)} unpinned AI SDK reference(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
