"""Which images does this repository actually run? (#427)

The containers lane scans images it **builds**: the workflow template finds
every Dockerfile and builds it, and the Concourse jobs scan the tags `publish`
pushed. That is a complete answer to "is the application image vulnerable" and
no answer at all to "is the estate vulnerable" — this estate runs fifteen
distinct images and four of them are built from source. Vault, MinIO,
Concourse, Postgres, Redis, nginx and a `registry:2` built in 2023 have never
been looked at by anything, which is visible in the lake as a negative: across
every container scan ever recorded, for any repository, not one `musl`,
`busybox`, `apk-tools`, `nginx`, `redis` or `postgres` package appears.

**The list is derived, never written down.** A hand-maintained list of fifteen
images is the next defect: it is correct on the day it is written and silently
wrong the first time somebody adds a service. The source of truth used here is
the repository's own compose files, which are what actually start the
containers — so an image joins the scan by being deployed, which is the only
event that matters, and leaves it the same way.

**Deriving from compose also answers the ownership question** #427 raises and
declines to settle. A `redis:7-alpine` finding is not naturally "TheHub's" or
"mykronos's", and filing it against a repository because a human guessed would
be worse than not filing it. The compose file that runs it is a fact rather
than a guess: the image belongs to the repository whose stack starts it, and
it lands in that repository's existing containers lane rather than in a new
capability with new grants and a new set of ways to be silently off.

**What `tag_kind` is for, and why it is not a severity.** A container finding
usually reads as "rebuild on a current base image". That is true for a *third*
of this estate and false for most of it, which was measured rather than
assumed: re-pulling every tag this estate runs removes about 13% of its
HIGH/CRITICAL findings, because the bulk sit on exact-version pins where a
pull is a no-op by definition. `tag_kind` records which case an image is in,
so the work is sortable into "refresh this" and "decide about this version" by
something other than a person reading each tag. It is derived from the tag
string alone and claims nothing more:

    digest      pinned by content    a pull cannot change anything
    pinned      two or more numbers  1.21.4, 7.14, 3.19 — a pull is a no-op
    major_line  one number           15, pg16, 7-alpine — a pull moves the base
    floating    no number            latest, alpine — a pull can change all of it

Note what this cannot see. `registry:2` classifies as `major_line`, and a pull
of it buys nothing, because upstream stopped rebuilding that tag in 2023.
Whether an upstream is still maintained is not in the tag; it is in the scan
results, which is the argument for scanning rather than for a cleverer regex.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

logger = logging.getLogger(__name__)

#: Where a compose file may be called something. Both spellings of the YAML
#: extension, and both the historical `docker-compose.yml` and the name the
#: Compose Specification prefers.
COMPOSE_GLOBS: tuple[str, ...] = (
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
)

#: Directories never searched. The same exclusions the containers template
#: applies to Dockerfile discovery, and for the same reason: a compose file
#: inside a vendored dependency or a test fixture describes a stack this
#: repository does not run, and scanning its images reports vulnerabilities
#: nobody here can act on or fix.
PRUNED_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "vendor", "testdata", "__pycache__", "site-packages"}
)

Origin = Literal["built_here", "upstream", "unresolved"]
TagKind = Literal["digest", "pinned", "major_line", "floating"]

#: `${NAME}`, `${NAME:-default}`, `${NAME-default}`, and the bare `$NAME`.
#: Compose supports `:?` and `?` (error if unset) too; those are treated as
#: "no default", which is what they mean.
_INTERPOLATION = re.compile(
    r"""
    \$(?:
        \{ (?P<braced>[A-Za-z_][A-Za-z0-9_]*) (?P<op>:-|-|:\?|\?)? (?P<default>[^}]*) \}
      | (?P<bare>[A-Za-z_][A-Za-z0-9_]*)
    )
    """,
    re.VERBOSE,
)

_DIGIT_RUN = re.compile(r"\d+")

#: An `image:` that is *entirely* one substitution, which is the deploy-time
#: override shape. `${REGISTRY}/redis:7-alpine` is deliberately not this: a
#: configurable registry in front of an upstream image is still an upstream
#: image, and treating it as first-party would skip it silently.
_WHOLE_SUBSTITUTION = re.compile(
    r"^\$(?:\{[A-Za-z_][A-Za-z0-9_]*(?::-|-|:\?|\?)?[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)$"
)


def interpolate(raw: str, env: Mapping[str, str]) -> tuple[str, list[str]]:
    """Resolve `${VAR:-default}` the way compose does, and say what it could not.

    The unresolved names are returned rather than swallowed. A reference that
    still contains a variable is not scannable, and reporting it as an image
    called `${SOMETHING}` would produce a scan failure whose cause is three
    steps from the message.
    """
    unresolved: list[str] = []

    def substitute(match: re.Match[str]) -> str:
        name = match.group("braced") or match.group("bare")
        value = env.get(name)
        if value:
            return value
        # `:-` and `-` differ on the empty string; both fall back when the
        # variable is absent, which is the case that matters here.
        if match.group("op") in (":-", "-"):
            return match.group("default") or ""
        unresolved.append(name)
        return ""

    return _INTERPOLATION.sub(substitute, raw).strip(), unresolved


def split_reference(reference: str) -> tuple[str, str]:
    """Split an image reference into (repository, tag-or-digest).

    The tag separator is the last colon *after* the last slash, so
    `localhost:5000/mykronos-backend` is a registry on a port rather than an
    image called `localhost` at tag `5000/mykronos-backend`.
    """
    if "@" in reference:
        repository, _, digest = reference.partition("@")
        return repository, digest

    head, slash, tail = reference.rpartition("/")
    name, colon, tag = tail.partition(":")
    if not colon:
        return reference, ""
    return f"{head}{slash}{name}", tag


def classify_tag(reference: str) -> TagKind:
    """How much a `docker pull` of this reference could possibly change."""
    _, tag = split_reference(reference)

    if tag.startswith("sha256:"):
        return "digest"
    if not tag or tag == "latest":
        return "floating"

    # Counting digit runs rather than dotted components, because the tags this
    # estate runs are not all dotted: `RELEASE.2025-04-22T22-12-26Z` and
    # `7.14` are both fully-specified versions, and `7-alpine` and `pg16` are
    # both a major line with a variant bolted on.
    runs = len(_DIGIT_RUN.findall(tag))
    if runs == 0:
        return "floating"
    if runs == 1:
        return "major_line"
    return "pinned"


@dataclass(frozen=True)
class ComposeService:
    """One `image:` line, and what this module concluded about it."""

    compose_path: str
    service: str
    raw_image: str
    reference: str
    origin: Origin
    #: Why `origin` is what it is, in a form that can be printed beside the
    #: image. A classification nobody can audit is a classification nobody
    #: should act on.
    reason: str
    unresolved_vars: tuple[str, ...] = ()

    @property
    def tag_kind(self) -> TagKind:
        return classify_tag(self.reference)


@dataclass
class Derivation:
    """Every `image:` in a tree, sorted into what this lane should scan."""

    services: list[ComposeService] = field(default_factory=list)
    compose_files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def of_origin(self, origin: Origin) -> list[ComposeService]:
        return [service for service in self.services if service.origin == origin]

    def images(self) -> list[str]:
        """The upstream references to scan: deduplicated and ordered.

        Deduplicated because four of TheHub's containers run the same
        `pgvector/pgvector:pg16`, and scanning it four times would produce
        four copies of one finding under one path — the identity collapse
        spec 05 §5 warns about, arrived at from the other direction.
        """
        return sorted({service.reference for service in self.of_origin("upstream")})

    def as_dict(self) -> dict[str, Any]:
        return {
            "compose_files": self.compose_files,
            "images": [
                {
                    "reference": reference,
                    "tag_kind": classify_tag(reference),
                    "run_by": sorted(
                        f"{service.compose_path}::{service.service}"
                        for service in self.of_origin("upstream")
                        if service.reference == reference
                    ),
                }
                for reference in self.images()
            ],
            "built_here": sorted(
                f"{service.compose_path}::{service.service}"
                for service in self.of_origin("built_here")
            ),
            "unresolved": sorted(
                f"{service.compose_path}::{service.service} ({service.raw_image})"
                for service in self.of_origin("unresolved")
            ),
            "warnings": self.warnings,
        }


def _origin_of(
    definition: Mapping[str, Any], raw_image: str, unresolved: Sequence[str]
) -> tuple[Origin, str]:
    """Is this image built by the repository that declares it?

    Two signals, and both are facts in the file rather than a name-shaped
    guess. Structure cannot tell `postgres:15` from `mykronos-backend:latest`
    — an unqualified single-segment name with a tag, both of them — so this
    does not try.

    A `build:` key is the unambiguous case. The other is the deploy-time
    override, `${MYKRONOS_IMAGE_BACKEND:-mykronos-backend:latest}`: a service
    whose image a publish pipeline substitutes is that pipeline's own
    artefact, already scanned by tag before it was ever promoted. An upstream
    image is written literally, because there is nothing to substitute.
    """
    if definition.get("build") is not None:
        return "built_here", "the service declares `build:`"
    if unresolved:
        return "unresolved", f"unset variable(s): {', '.join(sorted(set(unresolved)))}"
    if _WHOLE_SUBSTITUTION.match(raw_image):
        return (
            "built_here",
            "the image is a deploy-time override, so a publish pipeline supplies the tag",
        )
    return "upstream", "a literal reference to an image this repository does not build"


def services_from_compose(
    text: str, compose_path: str, env: Mapping[str, str] | None = None
) -> tuple[list[ComposeService], list[str]]:
    """Read one compose file. Returns (services, warnings)."""
    env = env if env is not None else {}
    warnings: list[str] = []

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        # Not raised. One unparseable compose file must not cost the estate
        # its whole scan, and a lane that goes red on a YAML error in a file
        # it merely reads is a lane people switch off.
        return [], [f"{compose_path}: could not be parsed as YAML ({error})"]

    if not isinstance(document, dict):
        return [], [f"{compose_path}: is not a compose document"]

    raw_services = document.get("services")
    if not isinstance(raw_services, dict):
        return [], []

    found: list[ComposeService] = []
    for name, definition in raw_services.items():
        if not isinstance(definition, dict):
            continue
        raw_image = definition.get("image")
        if not isinstance(raw_image, str) or not raw_image.strip():
            if definition.get("build") is None:
                warnings.append(f"{compose_path}::{name}: no `image:` and no `build:`")
            continue

        reference, unresolved = interpolate(raw_image.strip(), env)
        origin, reason = _origin_of(definition, raw_image, unresolved)
        if origin == "upstream" and not reference:
            origin, reason = "unresolved", "the image resolved to an empty reference"

        found.append(
            ComposeService(
                compose_path=compose_path,
                service=str(name),
                raw_image=raw_image.strip(),
                reference=reference,
                origin=origin,
                reason=reason,
                unresolved_vars=tuple(unresolved),
            )
        )

    return found, warnings


def discover_compose_files(root: Path) -> list[Path]:
    """Every compose file under `root`, excluding vendored and fixture trees."""
    found: set[Path] = set()
    for directory, subdirectories, _ in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in PRUNED_DIRS]
        here = Path(directory)
        for pattern in COMPOSE_GLOBS:
            found.update(path for path in here.glob(pattern) if path.is_file())
    return sorted(found)


def derive(root: Path, env: Mapping[str, str] | None = None) -> Derivation:
    """Every image this repository's compose files run."""
    derivation = Derivation()

    for path in discover_compose_files(root):
        relative = path.relative_to(root).as_posix()
        derivation.compose_files.append(relative)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as error:
            derivation.warnings.append(f"{relative}: could not be read ({error})")
            continue
        services, warnings = services_from_compose(text, relative, env)
        derivation.services.extend(services)
        derivation.warnings.extend(warnings)

    if not derivation.compose_files:
        # Not an error, and said out loud. A repository with no compose file
        # runs no stack here, and "scanned, nothing to scan" has to stay
        # distinguishable from "nothing looked" — the same distinction the
        # containers template draws for a repository with no Dockerfile.
        derivation.warnings.append("no compose file found; this repository declares no stack")

    return derivation


def summarise(derivation: Derivation) -> str:
    """The human-readable half, for a build log."""
    lines = [
        f"Compose files read: {len(derivation.compose_files)}"
        + (f" ({', '.join(derivation.compose_files)})" if derivation.compose_files else ""),
        f"Images to scan: {len(derivation.images())}",
    ]
    by_reference = {
        service.reference: service
        for service in sorted(derivation.of_origin("upstream"), key=lambda s: s.reference)
    }
    for reference, service in sorted(by_reference.items()):
        lines.append(f"  {reference}  [{service.tag_kind}]")
    for service in derivation.of_origin("built_here"):
        lines.append(
            f"  (skipped) {service.compose_path}::{service.service} "
            f"-> {service.raw_image}: {service.reason}"
        )
    for service in derivation.of_origin("unresolved"):
        lines.append(
            f"  (unresolved) {service.compose_path}::{service.service} "
            f"-> {service.raw_image}: {service.reason}"
        )
    lines.extend(f"  (warning) {warning}" for warning in derivation.warnings)
    return "\n".join(lines)


def _environment(pairs: Iterable[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for pair in pairs:
        name, _, value = pair.partition("=")
        env[name] = value
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mykronos.estate_images",
        description=(
            "List the images this repository's compose files run, so the "
            "containers lane can scan what is deployed rather than only what "
            "it builds (#427)."
        ),
    )
    parser.add_argument("--root", default=".", help="Repository root to search (default: .)")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="`text` is one image reference per line, for a shell loop. `json` carries "
        "the provenance, the tag kind and everything that was skipped.",
    )
    parser.add_argument(
        "--output", default="-", help="Write to this file instead of stdout ('-' for stdout)"
    )
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="A compose variable, repeatable. The process environment is used as well.",
    )
    parser.add_argument(
        "--use-process-env",
        action="store_true",
        help="Also resolve compose variables from this process's environment. Off by "
        "default so the same tree derives the same list wherever it runs.",
    )
    arguments = parser.parse_args(argv)

    root = Path(arguments.root).resolve()
    if not root.is_dir():
        print(f"error: --root {root} is not a directory", file=sys.stderr)
        return 2

    env: dict[str, str] = dict(os.environ) if arguments.use_process_env else {}
    env.update(_environment(arguments.set))

    derivation = derive(root, env)

    # The summary goes to stderr so `--output -` stays pipeable while the
    # build log still shows what was decided and why.
    print(summarise(derivation), file=sys.stderr)

    if arguments.format == "json":
        payload = json.dumps(derivation.as_dict(), indent=2) + "\n"
    else:
        payload = "".join(f"{reference}\n" for reference in derivation.images())

    if arguments.output == "-":
        sys.stdout.write(payload)
    else:
        Path(arguments.output).write_text(payload, encoding="utf-8")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
