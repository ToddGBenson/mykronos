"""Deterministic fix generators (spec 08 §2, stage 4).

Not a fallback for the LLM path — the primary path for every class of finding
where the correct change is mechanical. These need no model, produce identical
output every run, and are reviewable line by line by somebody who does not
trust the tool that wrote them.

The bar for adding a fixer here is high and worth stating: a fixer belongs in
this module only if the change it makes is *provably* the right shape given
the finding, with no judgement about the surrounding code. Pinning a
dependency to a patched version is that. Parameterising a query is not — it
needs to understand what the query does, and getting it subtly wrong produces
a diff that looks right and breaks at runtime.

Every fixer returns the file content it wants written, never a patch. A patch
that fails to apply cleanly is a failure mode with no good handling; a full
file is either written or it is not.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ProposedFix:
    """A change Patchwork is prepared to open a draft pull request for."""

    #: path -> new content. A dict rather than a diff so the write is atomic
    #: per file and there is no "patch did not apply" state to handle.
    files: dict[str, str]
    summary: str
    #: What a reviewer should check. Every fixer must say something here —
    #: "review this" with no specifics is not review guidance, it is a
    #: disclaimer.
    review_notes: list[str] = field(default_factory=list)
    confidence: float = 1.0

    @property
    def touched(self) -> list[str]:
        return sorted(self.files)


#: A fixer takes the finding and the current file content, and returns a fix
#: or None. None means "this fixer does not apply", never "this finding has no
#: fix" — the pipeline distinguishes the two.
Fixer = Callable[[dict[str, Any], str], ProposedFix | None]


# --------------------------------------------------------------------------
# Dependency pinning
# --------------------------------------------------------------------------

_REQUIREMENT = re.compile(
    r"^(?P<prefix>\s*)(?P<name>[A-Za-z0-9._-]+)\s*(?P<op>[=><~!]{1,2})\s*(?P<version>[^\s;#]+)"
)

#: An npm version that is already an exact pin. Anything carrying a range
#: operator, a tag, a URL or a workspace protocol is deliberately not matched.
_EXACT_NPM_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

#: One `require` line in a go.mod, with the trailing `// indirect` comment
#: preserved: dropping it would change what `go mod tidy` believes about the
#: module and produce a diff that is not only the version.
_GO_REQUIREMENT = re.compile(
    r"^(?P<prefix>\s*(?:require\s+)?)(?P<module>[^\s]+)\s+v[^\s]+(?P<suffix>\s*//.*)?$"
)


def pin_python_requirement(finding: dict[str, Any], content: str) -> ProposedFix | None:
    """Pin a vulnerable Python dependency to its fixed version.

    Only acts when the finding names both the package and a fixed version, and
    only when the requirement line pins an exact version already. A range like
    `urllib3>=2.0` is deliberately left alone: replacing it with an exact pin
    is a change to the project's dependency *policy*, not a security fix, and
    it is not Patchwork's call to make.
    """
    package = str(finding.get("package_name") or "")
    fixed = _fixed_version(finding)
    if not package or not fixed:
        return None

    path = str(finding.get("file_path") or "")
    if not path.endswith((".txt", ".in")):
        return None

    lines = content.splitlines()
    changed = False
    for index, line in enumerate(lines):
        match = _REQUIREMENT.match(line)
        if not match or match.group("name").lower() != package.lower():
            continue
        if match.group("op") != "==":
            logger.info(
                "Leaving %s alone: it is a range (%s), and narrowing it is a "
                "dependency-policy change rather than a security fix",
                package,
                line.strip(),
            )
            return None
        lines[index] = f"{match.group('prefix')}{match.group('name')}=={fixed}"
        changed = True

    if not changed:
        return None

    return ProposedFix(
        files={path: "\n".join(lines) + ("\n" if content.endswith("\n") else "")},
        summary=f"Pin `{package}` to {fixed}",
        review_notes=[
            f"Confirm {fixed} is the version you want — it is the lowest "
            "version the advisory reports as fixed, which is the safest "
            "assumption but not always the one a project wants.",
            "Run the test suite. A patch release can still change behaviour "
            "the project depends on.",
        ],
    )


def _fixed_version(finding: dict[str, Any]) -> str | None:
    """The fixed version an advisory reports, if the record carries one."""
    raw = finding.get("raw_finding_json")
    if isinstance(raw, dict):
        for key in ("fixed_version", "fixed", "patched_version"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


# --------------------------------------------------------------------------
# Committed credentials
# --------------------------------------------------------------------------


def remove_committed_secret(finding: dict[str, Any], content: str) -> ProposedFix | None:
    """Replace a committed credential with an environment lookup.

    Deliberately conservative about what it claims. Removing the literal from
    the working tree does *not* remove it from history and does not un-leak it,
    so the review notes lead with rotation. A fix that made a repository look
    clean while the credential stayed valid would be worse than no fix.
    """
    if finding.get("capability") != "secrets":
        return None

    line_number = finding.get("line_start")
    path = str(finding.get("file_path") or "")
    if not path or not isinstance(line_number, int) or line_number < 1:
        return None

    lines = content.splitlines()
    if line_number > len(lines):
        return None

    original = lines[line_number - 1]
    assignment = re.match(
        r"^(?P<indent>\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"'][^\"']+[\"']\s*$",
        original,
    )
    if not assignment:
        # Anything more structured than a plain string assignment is left to a
        # human. A regex rewriting arbitrary code around a secret is how you
        # turn a leaked credential into a leaked credential *and* a broken
        # build.
        return None

    name = assignment.group("name")
    env_var = name.upper()
    lines[line_number - 1] = (
        f'{assignment.group("indent")}{name} = os.environ["{env_var}"]'
    )
    body = "\n".join(lines) + ("\n" if content.endswith("\n") else "")
    if "import os" not in body:
        body = "import os\n\n" + body

    return ProposedFix(
        files={path: body},
        summary=f"Read `{name}` from the environment instead of the source",
        review_notes=[
            "**Rotate the credential first.** It is in git history and in "
            "every clone; this change removes it from the working tree and "
            "from nothing else.",
            f"Set `{env_var}` wherever this runs — this change will break the "
            "process until you do.",
            "Consider whether the value belongs in a secret manager rather "
            "than an environment variable.",
        ],
        confidence=0.9,
    )


# --------------------------------------------------------------------------
# npm and Go dependency pinning (spec 19 §3.1)
# --------------------------------------------------------------------------
#
# One fixer per manifest format rather than one generic dependency fixer,
# matching `pin_python_requirement`'s shape. The formats disagree about
# almost everything that matters here — where the version lives, what a range
# looks like, whether the exact-pin rule even applies — and a single function
# branching on file extension would be three fixers wearing one name, with
# one set of tests covering whichever branch was written last.


def pin_npm_dependency(finding: dict[str, Any], content: str) -> ProposedFix | None:
    """Pin a vulnerable npm dependency to its fixed version.

    Same restraint as the Python fixer: only an already-exact pin is
    rewritten. `^1.2.3` and `~1.2.3` are a project's stated tolerance for
    updates, and narrowing that to an exact version is a dependency-policy
    change rather than a security fix — even when it happens to also fix the
    advisory.
    """
    package = str(finding.get("package_name") or "")
    fixed = _fixed_version(finding)
    if not package or not fixed:
        return None

    path = str(finding.get("file_path") or "")
    if not path.endswith("package.json"):
        return None

    try:
        document = json.loads(content)
    except json.JSONDecodeError:
        # Unparseable package.json: not this fixer's problem to guess at.
        return None

    changed = False
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = document.get(section)
        if not isinstance(block, dict) or package not in block:
            continue
        current = str(block[package])
        if not _EXACT_NPM_VERSION.match(current):
            logger.info(
                "Leaving %s alone: %s is a range, and narrowing it is a "
                "dependency-policy change rather than a security fix",
                package,
                current,
            )
            continue
        block[package] = fixed
        changed = True

    if not changed:
        return None

    # Two spaces and a trailing newline is what npm itself writes, so the
    # diff is the version line and nothing else.
    rewritten = json.dumps(document, indent=2) + ("\n" if content.endswith("\n") else "")
    return ProposedFix(
        files={path: rewritten},
        summary=f"Pin `{package}` to {fixed}",
        review_notes=[
            f"Confirm {fixed} is the version you want — it is the lowest "
            "version the advisory reports as fixed, which is the safest "
            "assumption but not always the one a project wants.",
            "The lockfile is not updated here. Run `npm install` so "
            "package-lock.json matches, or this pin changes nothing at "
            "install time.",
        ],
    )


def pin_go_module(finding: dict[str, Any], content: str) -> ProposedFix | None:
    """Pin a vulnerable Go module to its fixed version in `go.mod`.

    Go versions are already exact by construction — there is no range syntax
    to preserve — so unlike npm and Python there is no policy question here,
    only whether the line is found.
    """
    package = str(finding.get("package_name") or "")
    fixed = _fixed_version(finding)
    if not package or not fixed:
        return None

    path = str(finding.get("file_path") or "")
    if not path.endswith("go.mod"):
        return None

    lines = content.splitlines()
    changed = False
    for index, line in enumerate(lines):
        match = _GO_REQUIREMENT.match(line)
        if not match or match.group("module") != package:
            continue
        lines[index] = (
            f"{match.group('prefix')}{match.group('module')} {fixed}"
            f"{match.group('suffix') or ''}"
        )
        changed = True

    if not changed:
        return None

    return ProposedFix(
        files={path: "\n".join(lines) + ("\n" if content.endswith("\n") else "")},
        summary=f"Pin `{package}` to {fixed}",
        review_notes=[
            f"Confirm {fixed} is the version you want — it is the lowest "
            "version the advisory reports as fixed.",
            "`go.sum` is not updated here. Run `go mod tidy` before merging, "
            "or the build will refuse the new version's checksum.",
        ],
    )


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

#: Ordered. The first fixer that returns a fix wins, so more specific fixers
#: come first.
FIXERS: list[tuple[str, Fixer]] = [
    ("pin-python-requirement", pin_python_requirement),
    ("pin-npm-dependency", pin_npm_dependency),
    ("pin-go-module", pin_go_module),
    ("remove-committed-secret", remove_committed_secret),
]


#: What the deterministic fixers can actually fix, in the words a reader of the
#: Remediation tab needs (B-021).
#:
#: Stated rather than inferred, because the alternative is a page reporting
#: zero fixes with nothing saying whether that means "nothing was fixable" or
#: "the fixer is broken". Across 560 remediation events on this estate nothing
#: has ever reached `fix_generated`, and that is correct: the open backlog is
#: overwhelmingly container, DAST and SAST findings, and none of those is a
#: class any fixer here covers.
#:
#: `test_coverage_names_every_fixer` fails if a fixer is added without a line
#: here, so the page cannot silently fall behind the code.
COVERAGE: tuple[dict[str, str], ...] = (
    {
        "fixer": "pin-python-requirement",
        "capability": "atlas",
        "handles": "A vulnerable Python dependency with a known fixed version, "
        "declared in a requirements file.",
    },
    {
        "fixer": "pin-npm-dependency",
        "capability": "atlas",
        "handles": "A vulnerable npm dependency with a known fixed version, "
        "declared in package.json.",
    },
    {
        "fixer": "pin-go-module",
        "capability": "atlas",
        "handles": "A vulnerable Go module with a known fixed version, "
        "declared in go.mod.",
    },
    {
        "fixer": "remove-committed-secret",
        "capability": "secrets",
        "handles": "A credential committed to the repository, replaced with an "
        "environment lookup.",
    },
)

#: Capabilities with no deterministic fixer at all, and why not.
#:
#: An absence stated is a different thing from an absence inferred from a blank
#: table. Each of these is a class where a correct fix needs a judgement the
#: platform will not make on its own -- which is the same reason spec 08 §2
#: ships deterministic fixers only.
NOT_COVERED: tuple[dict[str, str], ...] = (
    {
        "capability": "sast",
        "why": "A code defect's fix depends on what the code is for. A "
        "deterministic rewrite that compiles is not thereby correct.",
    },
    {
        "capability": "dast",
        "why": "A finding against a running service names a symptom at an "
        "endpoint, not a line to change.",
    },
    {
        "capability": "containers",
        "why": "A CVE in a base image is fixed by moving image, which is a "
        "decision about the platform rather than an edit to a file.",
    },
    {
        "capability": "iac",
        "why": "Infrastructure defaults are frequently deliberate. Changing "
        "one without knowing why it was set is how a fix causes an outage.",
    },
    {
        "capability": "cloud",
        "why": "A live cloud posture finding is remediated in the cloud "
        "account, which this platform deliberately cannot reach.",
    },
)


def coverage_summary() -> dict[str, Any]:
    """What can and cannot be auto-fixed, for the Remediation tab."""
    return {
        "covered": [dict(entry) for entry in COVERAGE],
        "not_covered": [dict(entry) for entry in NOT_COVERED],
        "fixer_count": len(FIXERS),
    }


def generate(finding: dict[str, Any], content: str) -> tuple[str, ProposedFix] | None:
    """Try every fixer. Returns (fixer_name, fix) or None."""
    for name, fixer in FIXERS:
        try:
            fix = fixer(finding, content)
        except Exception as exc:  # noqa: BLE001
            # One broken fixer must not stop the others, and must not take
            # down a pipeline run that would otherwise record its events
            # (spec 08 §8).
            logger.warning("Fixer %s raised on %s: %s", name, finding.get("finding_id"), exc)
            continue
        if fix is not None:
            return name, fix
    return None
