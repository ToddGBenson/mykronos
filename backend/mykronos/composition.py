"""What a repository is made of, and therefore what cannot apply to it (B-058).

`ssdf.summarise` counted four statuses and the fourth, `not_applicable`, was
zero across every onboarded repository because nothing set it. A practice a
repository cannot possibly evidence and one it simply has not done were the
same row.

That understates two repositories badly, and on a compliance view an
understatement is not the safe direction to be wrong in -- it is the one that
gets somebody told to build what they do not need. `keel` was marked down on
PW.4 for having no containers, on PW.8 for having almost no tests, and on RV.1
for not running DAST against an application that does not exist.
`personal-soc` is PowerShell with no build artifact at all.

**The pressure that creates is the actual risk.** The obvious way to move
those numbers is to enable `containers`, `dast` and `unit` anyway. Each would
produce a lane that runs, finds nothing because there is nothing, and reports
success -- a green lane over an empty target, which is exactly what the
maturity model refuses when it separates `reporting_capabilities` from
`enabled_capabilities` so a repository cannot claim coverage by flipping a
toggle.

**So the determination is evidenced, never declared.** It is read from the
repository's own file listing, not from a per-repo checkbox, which would be a
toggle again wearing a different hat.

**And it only ever says "no" when the evidence is unambiguous.** Every
inference here is one-directional: an absence of Dockerfiles is strong
evidence that no container image is built, while their presence proves
nothing about the rest. Anything not positively established is applicable,
because on this view a wrong `not_applicable` converts "we did not look" into
"this does not apply to us", which is the one transformation the module this
feeds refuses to make.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

#: Files that build a container image. Both spellings, anywhere in the tree,
#: with or without a suffix (`Dockerfile.prod`, `docker/Dockerfile`).
_CONTAINER = re.compile(r"(^|/)(dockerfile|containerfile)(\..+)?$", re.IGNORECASE)

#: Infrastructure and configuration checkov reads. GitHub Actions workflows are
#: in here deliberately: `CKV_GHA_*` is where this platform's own IaC findings
#: come from, and a repository with ten workflows and no Terraform still has a
#: real IaC surface.
_IAC = (
    re.compile(r"\.tf(\.json)?$", re.IGNORECASE),
    re.compile(r"(^|/)\.github/workflows/.+\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)(docker-)?compose(\..+)?\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)(kustomization|chart)\.ya?ml$", re.IGNORECASE),
    re.compile(r"(^|/)templates/.+\.ya?ml$", re.IGNORECASE),
    re.compile(r"\.bicep$", re.IGNORECASE),
    re.compile(r"(^|/)(cloudformation|cfn)/.+\.(ya?ml|json)$", re.IGNORECASE),
)

#: Manifests that declare dependencies for a package ecosystem osv-scanner or
#: syft can read.
_DEPENDENCIES = frozenset(
    {
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "pipfile",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "cargo.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gemfile",
        "composer.json",
        "*.csproj",
        "paket.dependencies",
    }
)

#: Deliberately generous. Claiming a repository has no tests is the inference
#: most likely to be wrong -- every language and framework spells them
#: differently -- and being wrong here tells a team their tests do not count.
#: Anything that looks remotely like a test makes the practice applicable.
_TESTS = (
    re.compile(r"(^|/)tests?/", re.IGNORECASE),
    re.compile(r"(^|/)spec/", re.IGNORECASE),
    re.compile(r"(^|/)__tests__/", re.IGNORECASE),
    re.compile(r"(^|/)test_[^/]+\.py$", re.IGNORECASE),
    re.compile(r"[^/]+_test\.(py|go|rb)$", re.IGNORECASE),
    re.compile(r"[^/]+\.(test|spec)\.(js|jsx|ts|tsx)$", re.IGNORECASE),
    re.compile(r"[^/]+\.tests?\.ps1$", re.IGNORECASE),
    re.compile(r"[^/]+Test(s)?\.(java|kt|cs)$", re.IGNORECASE),
    re.compile(r"(^|/)conftest\.py$", re.IGNORECASE),
)


@dataclass(frozen=True)
class Composition:
    """What was observed in a repository's file listing.

    `unknown` is its own state and is not "nothing found". A tree this
    platform could not read, or one GitHub truncated, must claim nothing at
    all -- the difference between "we looked and there are no Dockerfiles" and
    "we did not look" is the whole point of this module.
    """

    unknown: bool = True
    files: int = 0
    builds_container: bool = False
    has_iac: bool = False
    declares_dependencies: bool = False
    has_tests: bool = False

    @property
    def deployable_web_app(self) -> bool:
        """Something DAST could be pointed at.

        Keyed on a container build, which is what this estate deploys. It is
        the narrow reading on purpose: a repository that builds an image might
        still not serve HTTP, so this can only ever rule DAST *in*, never rule
        it out on its own.
        """
        return self.builds_container


def read(paths: list[str] | None) -> Composition:
    """What the file listing says. `None` in, unknown out."""
    if paths is None:
        return Composition(unknown=True)

    composition = Composition(unknown=False, files=len(paths))
    builds_container = has_iac = declares = has_tests = False

    for path in paths:
        name = posixpath.basename(path).lower()
        if not builds_container and _CONTAINER.search(path):
            builds_container = True
        if not has_iac and any(pattern.search(path) for pattern in _IAC):
            has_iac = True
        if not declares and (
            name in _DEPENDENCIES or name.endswith(".csproj") or name.endswith(".sln")
        ):
            declares = True
        if not has_tests and any(pattern.search(path) for pattern in _TESTS):
            has_tests = True

    return Composition(
        unknown=False,
        files=composition.files,
        builds_container=builds_container,
        has_iac=has_iac,
        declares_dependencies=declares,
        has_tests=has_tests,
    )


def inapplicable(composition: Composition) -> dict[str, str]:
    """Capabilities with nothing to act on here, and why, in a person's words.

    The reason is the point. "No container image is built here" reads
    differently from "the container lane has never run", and a compliance view
    that cannot tell those apart is the defect B-058 describes.

    An unknown composition yields nothing: a practice stays applicable until
    something is observed that says otherwise.
    """
    if composition.unknown:
        return {}

    out: dict[str, str] = {}
    if not composition.builds_container:
        out["containers"] = "no container image is built here — no Dockerfile in the tree"
        # DAST needs something running to point at. A repository that builds no
        # image in an estate that deploys images has nothing to scan; that is
        # weaker evidence than the Dockerfile inference above, so it is stated
        # as what was observed rather than as a claim about the application.
        out["dast"] = (
            "nothing here is deployed as a running application — no container image is built"
        )
    if not composition.declares_dependencies:
        out["atlas"] = "no dependency manifest is declared here"
    if not composition.has_iac:
        out["iac"] = "no infrastructure, workflow or deployment configuration is defined here"
    if not composition.has_tests:
        for capability in ("unit", "functional", "qa"):
            out[capability] = "no test suite is present in this repository"
    return out
