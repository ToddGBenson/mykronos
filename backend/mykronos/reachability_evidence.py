"""Matching stored dataflow reachability to findings (TheHub #60891).

The runner (`mykronos.reachability_dataflow`) produces verdicts; this is the
platform's half: what ingest keeps, and which verdict, if any, speaks for a
given finding. Both the finding record and the auto-triage `unreachable` lane
read through here, so "this finding is reachable" means one thing on the page
and in the lane.

A package verdict speaks for a dependency finding only when the finding's
manifest is of the verdict's ecosystem: `certifi` in a `uv.lock` is the PyPI
package, and a verdict about it says nothing of an npm package of the same
name, or of a copy inside a container image. A location verdict speaks for a
code finding with the same rule, file and line.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from mykronos.reachability_dataflow import (
    LANGUAGES,
    normalise_package,
    normalise_path,
    unreachable_gaps,
)

#: Manifest and lockfile names -> the ecosystem a finding on them is about.
_NPM = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
}
_PYPI = {
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "setup.py",
    "setup.cfg",
    "pdm.lock",
}

#: Capabilities whose package findings come from this repository's manifests.
#: A container image's packages are not what the repository's code imports.
PACKAGE_CAPABILITIES = frozenset({"atlas"})


def manifest_ecosystem(file_path: Any) -> str | None:
    name = PurePosixPath(normalise_path(file_path)).name.lower()
    if not name:
        return None
    if name in _NPM:
        return "npm"
    if name in _PYPI or (name.startswith("requirements") and name.endswith(".txt")):
        return "pypi"
    return None


def downgrade(verdicts: Iterable[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Every verdict as it may be stored, and how many were downgraded.

    An `unreachable` whose evidence does not prove it is kept as `unknown`,
    with the shortfall in its reason, rather than refused: the rest of the
    submission is still good, and the runner's claim is still worth showing
    for what it is.
    """
    kept: list[dict[str, Any]] = []
    downgraded = 0
    for verdict in verdicts:
        item = dict(verdict)
        if item.get("verdict") == "unreachable":
            gaps = unreachable_gaps(item.get("evidence"))
            if gaps:
                downgraded += 1
                item["verdict"] = "unknown"
                item["reason"] = (
                    "Submitted as unreachable, but the evidence falls short: "
                    + "; ".join(gaps)
                    + "."
                )[:1000]
        kept.append(item)
    return kept, downgraded


@dataclass
class Index:
    """One repository's dataflow verdicts, keyed the way findings ask."""

    #: (ecosystem, normalised package) -> (report, verdict)
    packages: dict[tuple[str, str], tuple[Any, dict[str, Any]]] = field(default_factory=dict)
    #: (rule_id, path, line) -> (report, verdict)
    locations: dict[tuple[str, str, int | None], tuple[Any, dict[str, Any]]] = field(
        default_factory=dict
    )
    #: Every file a recorded reachable path passes through.
    reached_files: set[str] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)


def index(reports: Iterable[Any]) -> Index:
    """Index `DataflowReachabilityReport` rows (any objects with its fields)."""
    found = Index()
    for report in reports:
        found.languages.add(str(report.language))
        expected = LANGUAGES.get(str(report.language))
        for verdict in report.verdicts or []:
            if not isinstance(verdict, dict):
                continue
            if verdict.get("verdict") == "reachable":
                for step in verdict.get("path") or []:
                    if isinstance(step, dict) and step.get("file_path"):
                        found.reached_files.add(normalise_path(step["file_path"]))
            if verdict.get("target") == "package":
                ecosystem = str(verdict.get("ecosystem") or "")
                if ecosystem != expected:
                    continue
                key = (ecosystem, normalise_package(ecosystem, str(verdict.get("package_name"))))
                found.packages[key] = (report, verdict)
            elif verdict.get("target") == "location":
                line = verdict.get("line")
                key_l = (
                    str(verdict.get("rule_id") or ""),
                    normalise_path(verdict.get("file_path")),
                    int(line) if isinstance(line, int) else None,
                )
                found.locations[key_l] = (report, verdict)
    return found


def for_finding(found: Index, row: Mapping[str, Any]) -> tuple[Any, dict[str, Any]] | None:
    """The stored verdict that speaks for this finding, if one does."""
    package = row.get("package_name")
    if package:
        if str(row.get("capability") or "") not in PACKAGE_CAPABILITIES:
            return None
        ecosystem = manifest_ecosystem(row.get("file_path"))
        if ecosystem is None:
            return None
        return found.packages.get((ecosystem, normalise_package(ecosystem, str(package))))
    line = row.get("line_start")
    key = (
        str(row.get("rule_id") or ""),
        normalise_path(row.get("file_path")),
        int(line) if isinstance(line, int) else None,
    )
    return found.locations.get(key)


def as_record(report: Any, verdict: Mapping[str, Any]) -> dict[str, Any]:
    """The finding record's `reachability` block."""
    return {
        "verdict": verdict.get("verdict"),
        "reason": verdict.get("reason") or "",
        "path": list(verdict.get("path") or []),
        "evidence": dict(verdict.get("evidence") or {}),
        "language": report.language,
        "analyser": report.analyser,
        "analyser_version": report.analyser_version,
        "commit_sha": report.commit_sha,
        "analysed_at": report.updated_at,
    }
