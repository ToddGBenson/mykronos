"""Installed versions against declared constraints (mykronos#322).

osv-scanner runs `--no-resolve` in this estate, so an atlas finding names the
version a requirement *declares* (B-063). That is usually discussed as a false
positive -- a floor behind what runs. It also runs the other way: TheHub
declared `redis>=8.1.0` while a transitive cap (`kombu` requires `<6.5`) left
6.4.0 installed. Atlas assessed 8.1.0; production ran 6.4.0; nothing compared
the two, so an advisory against 6.4.0 fixed before 8.1.0 would have read as
not applicable.

This module is that comparison. It reads the declared constraints from the
manifests in a checkout and the installed versions from one or more CycloneDX
SBOMs, and reports every package whose installed version does not satisfy
what the repository declares. The result is a lane-health fact, not a finding:
it is a statement about the repository, not about a line of a file, and a
broken constraint is not itself a vulnerability. It never gates.

Drift inside the constraint -- a floor behind what runs -- is normal and is
deliberately *not* reported. Eighteen of TheHub's requirements are exactly
that, and flagging them would bury the one that matters.

Scope, stated rather than implied:

* **Python** -- `requirements*.txt` and `pyproject.toml` (`[project]`
  dependencies and optional dependencies), compared under PEP 440 via
  `packaging`. Environment markers are not evaluated: the comparison is only
  made for packages the SBOM says are installed.
* **npm** -- `package.json` `dependencies`, `devDependencies` and
  `optionalDependencies`, compared under node-semver range rules (`^`, `~`,
  x-ranges, hyphen ranges, `||`). npm's rule that a prerelease only satisfies
  a range naming the same `[major, minor, patch]` with a prerelease is not
  applied; prereleases are ordered by plain semver precedence. Specs that are
  not ranges (`git+…`, `file:`, `npm:` aliases, dist-tags) are skipped.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

#: Files whose versions are declarations, not installations. An SBOM component
#: Syft read out of one of these -- it records `==` pins from requirements.txt
#: with the file as its location -- says what the repository asked for, which
#: is the very thing being checked, so it cannot also stand as evidence of what
#: is installed.
MANIFEST_NAMES = frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "package.json",
        "go.mod",
        "cargo.toml",
        "gemfile",
        "composer.json",
        "build.gradle",
        "pom.xml",
    }
)

#: Directories that hold someone else's manifests, not this repository's.
_SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "vendor", "site-packages", "__pycache__", ".tox"}
)

#: Enough to describe the estate's repositories several times over; a walk
#: that finds more is walking something it should not.
_MAX_MANIFESTS = 200

_PURL = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^@?#]+)")


def is_manifest(path: str) -> bool:
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    return name in MANIFEST_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def normalise_name(ecosystem: str, name: str) -> str:
    """PEP 503 for PyPI, which is case- and separator-insensitive; npm as is."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


# ---------------------------------------------------------------------------
# npm semver
# ---------------------------------------------------------------------------

_SEMVER = re.compile(
    r"^v?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
#: A possibly-partial version as written in a range: `1`, `1.2`, `1.x`, `1.2.*`.
_PARTIAL = re.compile(
    r"^v?(?P<major>\d+|[xX*])(?:\.(?P<minor>\d+|[xX*]))?(?:\.(?P<patch>\d+|[xX*]))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)
_COMPARATOR = re.compile(r"^(?P<op><=|>=|<|>|=|\^|~>|~)?\s*(?P<ver>.*)$")


@dataclass(frozen=True, order=True)
class SemVer:
    """A full semver, ordered by precedence (semver.org §11)."""

    key: tuple[Any, ...]

    @classmethod
    def of(cls, major: int, minor: int, patch: int, pre: str | None = None) -> SemVer:
        if pre is None:
            # A release outranks every prerelease of the same triple.
            return cls((major, minor, patch, 1, ()))
        identifiers = tuple(
            (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")
        )
        return cls((major, minor, patch, 0, identifiers))

    @classmethod
    def parse(cls, text: str) -> SemVer | None:
        match = _SEMVER.match(text.strip())
        if not match:
            return None
        return cls.of(int(match["major"]), int(match["minor"]), int(match["patch"]), match["pre"])


def _floor(major: int, minor: int = 0, patch: int = 0) -> SemVer:
    """The lowest version on a line, prereleases included: `X.Y.Z-0`."""
    return SemVer.of(major, minor, patch, "0")


Comparator = tuple[str, SemVer]


def _is_wild(part: str | None) -> bool:
    return part is None or part in ("x", "X", "*")


def _expand(op: str, text: str) -> list[Comparator] | None:
    """One comparator token -> the primitive comparators it means."""
    if text in ("", "*", "x", "X"):
        return []
    match = _PARTIAL.match(text)
    if not match:
        return None
    if _is_wild(match["major"]):
        return []  # `*`-equivalent, whatever the operator in front of it.
    major = int(match["major"])
    minor = None if _is_wild(match["minor"]) else int(match["minor"])
    patch = None if minor is None or _is_wild(match["patch"]) else int(match["patch"])
    pre = match["pre"] if patch is not None else None

    if op == "^":
        low = SemVer.of(major, minor or 0, patch or 0, pre)
        if major > 0 or minor is None:
            high = _floor(major + 1)
        elif minor > 0 or patch is None:
            high = _floor(0, minor + 1)
        else:
            high = _floor(0, 0, patch + 1)
        return [(">=", low), ("<", high)]
    if op in ("~", "~>"):
        low = SemVer.of(major, minor or 0, patch or 0, pre)
        high = _floor(major + 1) if minor is None else _floor(major, minor + 1)
        return [(">=", low), ("<", high)]

    if patch is not None:
        exact = SemVer.of(major, minor or 0, patch, pre)
        return [("=" if op in ("", "=") else op, exact)]

    # A partial version: `1` or `1.2`, which is a whole line rather than a point.
    low = _floor(major, minor or 0)
    high = _floor(major + 1) if minor is None else _floor(major, minor + 1)
    if op in ("", "="):
        return [(">=", low), ("<", high)]
    if op == ">=":
        return [(">=", low)]
    if op == ">":
        return [(">=", high)]
    if op == "<":
        return [("<", low)]
    if op == "<=":
        return [("<", high)]
    return None


def _comparator_set(text: str) -> list[Comparator] | None:
    hyphen = re.match(r"^\s*(\S+)\s+-\s+(\S+)\s*$", text)
    if hyphen:
        low = _expand(">=", hyphen.group(1))
        upper = _PARTIAL.match(hyphen.group(2))
        if low is None or upper is None:
            return None
        # `1.2.3 - 2.3` means `<2.4.0-0`; `1.2.3 - 2.3.4` means `<=2.3.4`.
        high = _expand("<=", hyphen.group(2))
        if high is None:
            return None
        return low + high

    # `>= 1.2.3` is legal: glue an operator to the version that follows it.
    tokens = re.sub(r"(<=|>=|<|>|=|\^|~>|~)\s+", r"\1", text.strip()).split()
    comparators: list[Comparator] = []
    for token in tokens:
        match = _COMPARATOR.match(token)
        if not match:
            return None
        expanded = _expand(match["op"] or "", match["ver"])
        if expanded is None:
            return None
        comparators.extend(expanded)
    return comparators


def _holds(version: SemVer, comparator: Comparator) -> bool:
    op, bound = comparator
    return {
        "=": version == bound,
        ">": version > bound,
        ">=": version >= bound,
        "<": version < bound,
        "<=": version <= bound,
    }[op]


def npm_satisfies(installed: str, spec: str) -> bool | None:
    """Whether `installed` satisfies the npm range `spec`; None if unknowable.

    None for anything that is not a version range -- a git URL, a tarball, a
    `file:` or `workspace:` path, an `npm:` alias, a dist-tag such as
    `latest` -- and for an installed version that is not semver. An unknown
    answer is never reported as a violation.
    """
    version = SemVer.parse(installed)
    if version is None:
        return None
    spec = spec.strip()
    if re.match(r"^[a-z+]+:|/", spec, re.IGNORECASE):
        return None
    for alternative in spec.split("||"):
        comparators = _comparator_set(alternative)
        if comparators is None:
            return None
        if all(_holds(version, c) for c in comparators):
            return True
    return False


def pep440_satisfies(installed: str, spec: str) -> bool | None:
    """Whether `installed` satisfies the PEP 440 specifier set `spec`.

    Prereleases are admitted: the question is whether this specific installed
    version lies inside the declared range, not whether pip would choose it.
    """
    try:
        return SpecifierSet(spec).contains(Version(installed), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return None


def satisfies(ecosystem: str, installed: str, spec: str) -> bool | None:
    if ecosystem == "pypi":
        return pep440_satisfies(installed, spec)
    if ecosystem == "npm":
        return npm_satisfies(installed, spec)
    return None


# ---------------------------------------------------------------------------
# Reading the two sides
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Declared:
    ecosystem: str
    name: str
    spec: str
    file: str


@dataclass(frozen=True)
class Violation:
    ecosystem: str
    name: str
    spec: str
    file: str
    installed: tuple[str, ...]
    sbom: str

    def fact(self, repo: str = "") -> str:
        """One line, front-loaded: only the first warning reaches the ScanRun's
        `detail`, and it is cut at 200 characters."""
        where = f" in {repo}" if repo else ""
        return (
            f"Installed {self.name} {', '.join(self.installed)} violates the declared "
            f"`{self.spec}` ({self.file}){where}. Atlas assessed the declared version, so "
            f"advisories against what is installed can be missed (#322). Source: "
            f"{self.sbom}. A lane-health fact, not a finding; it does not gate."
        )


def _component_ecosystem(component: dict[str, Any]) -> tuple[str, str] | None:
    match = _PURL.match(str(component.get("purl") or ""))
    if not match:
        return None
    ecosystem = match["type"].lower()
    rest = match["rest"]
    # npm scopes are percent-encoded in a purl: pkg:npm/%40scope/name.
    name = rest.replace("%40", "@").replace("%2F", "/").replace("%2f", "/")
    if ecosystem == "npm" and "/" in name and not name.startswith("@"):
        name = "@" + name  # pkg:npm/scope/name, the older spelling
    return ecosystem, normalise_name(ecosystem, name)


def _locations(component: dict[str, Any]) -> list[str]:
    return [
        str(prop.get("value") or "")
        for prop in component.get("properties") or []
        if isinstance(prop, dict) and re.match(r"^syft:location:\d+:path$", str(prop.get("name")))
    ]


def _walk_components(components: Iterable[Any]) -> Iterator[dict[str, Any]]:
    for component in components or []:
        if not isinstance(component, dict):
            continue
        yield component
        yield from _walk_components(component.get("components") or [])


def installed_versions(document: dict[str, Any]) -> dict[tuple[str, str], set[str]]:
    """(ecosystem, normalised name) -> versions the SBOM says are installed.

    A component whose every recorded location is a manifest is left out: it
    is a declaration Syft transcribed, not an installation (see
    `MANIFEST_NAMES`). One with no location at all -- an SBOM generated from
    an installed environment, as TheHub's `docs/sbom/latest-python.cdx.json`
    is -- counts as installed.
    """
    found: dict[tuple[str, str], set[str]] = {}
    for component in _walk_components(document.get("components") or []):
        version = str(component.get("version") or "").strip()
        if not version:
            continue
        key = _component_ecosystem(component)
        if key is None:
            continue
        locations = _locations(component)
        if locations and all(is_manifest(path) for path in locations):
            continue
        found.setdefault(key, set()).add(version)
    return found


def load_sbom(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.info("SBOM %s unreadable, skipped: %s", path, exc)
        return None
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        # SPDX carries versions too, but nothing in the estate produces it for
        # Atlas; reading one wrongly would be worse than skipping it.
        return None
    return document


def _manifest_files(workspace: Path) -> list[Path]:
    files: list[Path] = []
    for root, dirs, names in os.walk(workspace):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for name in sorted(names):
            lower = name.lower()
            if lower in ("pyproject.toml", "package.json") or (
                lower.startswith("requirements") and lower.endswith(".txt")
            ):
                files.append(Path(root) / name)
                if len(files) >= _MAX_MANIFESTS:
                    return files
    return files


def _requirement(line: str) -> Requirement | None:
    line = line.split(" #", 1)[0].split("\t#", 1)[0].strip()
    if not line or line.startswith(("#", "-")):
        return None  # comments, -r / -c / -e / --hash continuations
    try:
        return Requirement(line.rstrip("\\").strip())
    except InvalidRequirement:
        return None


def _python_declared(requirements: Iterable[Requirement], file: str) -> Iterator[Declared]:
    for req in requirements:
        spec = str(req.specifier)
        if spec and req.url is None:
            yield Declared("pypi", normalise_name("pypi", req.name), spec, file)


def declared_constraints(workspace: Path) -> list[Declared]:
    """Every version constraint the repository's manifests declare."""
    declared: list[Declared] = []
    for path in _manifest_files(workspace):
        relative = path.relative_to(workspace).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = path.name.lower()
        if name.endswith(".txt"):
            reqs = [r for r in (_requirement(line) for line in text.splitlines()) if r]
            declared.extend(_python_declared(reqs, relative))
        elif name == "pyproject.toml":
            try:
                project = tomllib.loads(text).get("project") or {}
            except tomllib.TOMLDecodeError:
                continue
            lines = list(project.get("dependencies") or [])
            for group in (project.get("optional-dependencies") or {}).values():
                lines.extend(group or [])
            reqs = [r for r in (_requirement(str(line)) for line in lines) if r]
            declared.extend(_python_declared(reqs, relative))
        else:
            try:
                manifest = json.loads(text)
            except ValueError:
                continue
            if not isinstance(manifest, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for package, spec in (manifest.get(section) or {}).items():
                    if isinstance(spec, str):
                        declared.append(Declared("npm", package, spec, relative))
    return declared


def constraint_violations(workspace: Path | None, sboms: Iterable[Path]) -> list[Violation]:
    """Packages whose installed version breaks the declared constraint.

    `sboms` is in order of preference: a package's installed versions are
    taken from the first SBOM that records it as installed, so a fresher SBOM
    the job generated outranks one committed to the repository. Returns
    nothing -- the check is skipped -- when there is no workspace or no
    readable SBOM.

    A package with several installed versions (npm nests copies) violates
    only if *none* of them satisfies the constraint: the copy the declaration
    governs is one of them, and which one is not recorded in the SBOM.
    """
    if workspace is None:
        return []
    installed: dict[tuple[str, str], tuple[set[str], str]] = {}
    for path in sboms:
        document = load_sbom(path)
        if document is None:
            continue
        for key, versions in installed_versions(document).items():
            installed.setdefault(key, (versions, path.name))
    if not installed:
        return []

    violations: list[Violation] = []
    seen: set[tuple[str, str, str, str]] = set()
    for declared in declared_constraints(workspace):
        entry = installed.get((declared.ecosystem, declared.name))
        if entry is None:
            continue
        versions, source = entry
        answers = [satisfies(declared.ecosystem, v, declared.spec) for v in versions]
        if any(answer is None for answer in answers) or any(answers):
            continue
        marker = (declared.ecosystem, declared.name, declared.spec, declared.file)
        if marker in seen:
            continue
        seen.add(marker)
        violations.append(
            Violation(
                declared.ecosystem,
                declared.name,
                declared.spec,
                declared.file,
                tuple(sorted(versions)),
                source,
            )
        )
    return violations
