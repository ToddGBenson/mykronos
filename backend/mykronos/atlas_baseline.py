"""What an atlas finding's commit actually changed (TheHub #61063).

The commit gate refuses a commit that *introduced* a critical or a high
(D-048), and "introduced" has meant first seen in a scan of that commit. For a
dependency that is not the same thing. An advisory published this morning
against a version the repository has carried for a month is first seen by
whichever commit happens to be scanning, and TheHub's gate refused a commit
for three pypdf highs read out of a committed SBOM of the running production
backend - in the very commit that pinned the fixed pypdf.

Two facts settle it, and both need the checkout, so they are established here,
on the runner, and written onto the finding's raw record for the platform to
read:

- **`baseline_commits`**: the first-parent ancestors of the scanned commit,
  newest first, whose copy of the finding's file already carried this package
  at this version - stopping at the first that did not. The platform compares
  it with the commit of the previous scan: if that commit is in the list, the
  component was already there at the baseline and the finding is newly
  disclosed, not introduced. An empty list is the answer "the parent did not
  have it", and absent is "could not tell" (no git, a shallow clone, a file
  outside the checkout); both count as introduced.

- **`remediated_by`**: for a finding read out of an SBOM - a record of what is
  installed, not what this commit declares - the manifest constraint in this
  commit's tree that excludes the vulnerable version and requires the fixed
  one. That commit is remediating the finding, whatever the SBOM of the
  running system still says, and it must never be charged for it.

Neither is a judgement of severity, and neither closes anything: the finding
stays open and still scores. They only decide which commit answers for it.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from mykronos import atlas_constraints
from mykronos.adapters.base import ScanContext
from mykronos.schemas import FindingSubmission

logger = logging.getLogger(__name__)

#: How far back the walk goes. The baseline is the previous scan, normally a
#: handful of commits behind; a commit further back than this simply is not
#: matched, which answers "introduced" - the safe direction.
MAX_COMMITS = 50

_SBOM_SUFFIXES = (".cdx.json", ".spdx.json")
_SBOM_NAMES = frozenset({"bom.json", "sbom.json"})


def is_sbom(file_path: str) -> bool:
    name = PurePosixPath(file_path.replace("\\", "/")).name.lower()
    return name in _SBOM_NAMES or name.endswith(_SBOM_SUFFIXES)


def _git(workspace: Path, *args: str, stdin: str | None = None) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(workspace), *args],  # noqa: S607
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.returncode == 0 else None


def _sbom_carries(text: str, package: str, version: str) -> bool:
    try:
        document = json.loads(text)
    except ValueError:
        return False
    if not isinstance(document, dict):
        return False
    for ecosystem in ("pypi", "npm"):
        wanted = atlas_constraints.normalise_name(ecosystem, package)
        for component in atlas_constraints._walk_components(  # noqa: SLF001
            document.get("components") or []
        ):
            if str(component.get("version") or "").strip() != version:
                continue
            named = atlas_constraints.normalise_name(ecosystem, str(component.get("name") or ""))
            keyed = atlas_constraints._component_ecosystem(component)  # noqa: SLF001
            if named == wanted or (keyed is not None and keyed[1] == wanted):
                return True
    return False


def _text_carries(text: str, package: str, version: str) -> bool:
    """A line naming the package and the version, for a manifest.

    A line rather than a parse: osv-scanner `--no-resolve` assesses the
    version a requirement writes down, so the version is on the package's own
    line in every manifest format it reads. A format that splits them across
    lines (poetry.lock) answers False - "introduced", the safe direction.
    """
    name = re.compile(r"(?<![\w.-])" + re.escape(package) + r"(?![\w.-])", re.IGNORECASE)
    number = re.compile(r"(?<![\w.])" + re.escape(version) + r"(?![\w.])")
    return any(name.search(line) and number.search(line) for line in text.splitlines())


def carries(text: str, file_path: str, package: str, version: str) -> bool:
    """Whether this file content records `package` at `version`."""
    if is_sbom(file_path):
        return _sbom_carries(text, package, version)
    return _text_carries(text, package, version)


class _History:
    """The scanned commit's first-parent ancestry, read once per upload."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        listing = _git(
            workspace, "rev-list", "--first-parent", f"--max-count={MAX_COMMITS + 1}", "HEAD"
        )
        prefix = _git(workspace, "rev-parse", "--show-prefix")
        self.commits = listing.split() if listing is not None else []
        self.prefix = (prefix or "").strip()
        self.ok = listing is not None and prefix is not None
        self._blobs: dict[str, list[str | None]] = {}
        self._content: dict[str, str | None] = {}

    def blobs(self, file_path: str) -> list[str | None]:
        """The file's blob id at each ancestor (not HEAD), None where absent."""
        if file_path not in self._blobs:
            ancestors = self.commits[1:]
            path = self.prefix + file_path.replace("\\", "/")
            out = _git(
                self.workspace,
                "cat-file",
                "--batch-check=%(objectname) %(objecttype)",
                stdin="".join(f"{commit}:{path}\n" for commit in ancestors),
            )
            ids: list[str | None] = []
            for line in (out or "").splitlines()[: len(ancestors)]:
                parts = line.split()
                ids.append(parts[0] if len(parts) == 2 and parts[1] == "blob" else None)
            self._blobs[file_path] = ids
        return self._blobs[file_path]

    def content(self, blob: str) -> str | None:
        if blob not in self._content:
            self._content[blob] = _git(self.workspace, "cat-file", "blob", blob)
        return self._content[blob]


def baseline_commits(
    history: _History, file_path: str, package: str, version: str
) -> list[str] | None:
    """Ancestors, newest first, whose copy of the file already carried
    `package` at `version`. None when it cannot be told."""
    if not history.ok or not history.commits:
        return None
    blobs = history.blobs(file_path)
    found: list[str] = []
    verdicts: dict[str, bool] = {}
    for commit, blob in zip(history.commits[1:], blobs, strict=False):
        if blob is None:
            break
        if blob not in verdicts:
            text = history.content(blob)
            verdicts[blob] = text is not None and carries(text, file_path, package, version)
        if not verdicts[blob]:
            break
        found.append(commit)
    return found


def _floor_reaches(ecosystem: str, spec: str, fixed: str) -> bool:
    """Whether every version `spec` admits is at or above `fixed`, read from
    its lower bound. Unparseable answers False."""
    if ecosystem == "pypi":
        try:
            specifiers = SpecifierSet(spec)
            target = Version(fixed)
        except (InvalidSpecifier, InvalidVersion):
            return False
        for specifier in specifiers:
            if specifier.operator not in ("==", "===", ">=", "~=", ">"):
                continue
            try:
                bound = Version(specifier.version)
            except InvalidVersion:
                continue
            if bound >= target:
                return True
        return False
    if ecosystem == "npm":
        target_sem = atlas_constraints.SemVer.parse(fixed)
        bound_sem = atlas_constraints.SemVer.parse(spec.strip().lstrip("^~>=v").strip())
        return target_sem is not None and bound_sem is not None and bound_sem >= target_sem
    return False


def remediated_by(
    declared: list[atlas_constraints.Declared], package: str, version: str, fixed: str
) -> dict[str, str] | None:
    """The constraint in this commit's tree that moves `package` off `version`
    onto `fixed` or later, or None."""
    if not fixed:
        return None
    for constraint in declared:
        if constraint.name != atlas_constraints.normalise_name(constraint.ecosystem, package):
            continue
        if atlas_constraints.satisfies(constraint.ecosystem, version, constraint.spec) is not False:
            continue
        if _floor_reaches(constraint.ecosystem, constraint.spec, fixed):
            return {"file": constraint.file, "spec": constraint.spec}
    return None


def annotate(findings: list[FindingSubmission], context: ScanContext) -> None:
    """Write `baseline_commits` and `remediated_by` onto each finding's raw
    record. Best effort: anything this cannot establish is left absent, which
    the platform reads as "introduced"."""
    if context.workspace is None or not findings:
        return
    workspace = context.workspace
    try:
        history = _History(workspace)
        declared: list[atlas_constraints.Declared] | None = None
        for finding in findings:
            package, version = finding.package_name, finding.package_version
            raw: dict[str, Any] = finding.raw_finding_json
            if not package or not version or not finding.file_path:
                continue
            commits = baseline_commits(history, finding.file_path, package, version)
            if commits is not None:
                raw["baseline_commits"] = commits
            fixed = str(raw.get("fixed_version") or "")
            if fixed and is_sbom(finding.file_path):
                if declared is None:
                    declared = atlas_constraints.declared_constraints(workspace)
                remedy = remediated_by(declared, package, version, fixed)
                if remedy is not None:
                    raw["remediated_by"] = remedy
    except Exception:  # noqa: BLE001 - no evidence means "introduced"
        logger.warning(
            "Could not compare atlas findings with the commit's history; every "
            "finding counts as introduced.",
            exc_info=True,
        )
