"""Rebuild a repository's patched third-party images and say whether it helped.

TheHub runs redis, nginx, docker-socket-proxy and Postgres as patched
derivatives of the vendor image: an `apk upgrade` / `apt-get upgrade` layer,
declared under the compose extension field `x-thehub-build` and published as
`<registry>/thehub-<name>:<vendor-version>-p<YYYYMMDD>`. The date is the
package snapshot, so a newer date is the same recipe on newer packages - and
until this, a newer date only ever happened when somebody bumped it by hand.
Fixes the distribution had already shipped sat unused for as long as nobody
did.

This is the deterministic half of the `image-refresh` job:

    plan     every distinct recipe, its current reference and the candidate
             reference for a new date, as a tab-separated build list
    decide   given Trivy JSON for each current and candidate image, whether
             the candidate set is strictly better

**"Better" is per finding, not per count.** A candidate that removes three
HIGH and introduces a different one has the same count shape as progress and
is a regression in the one way that matters: something exploitable that was
not there yesterday. So the verdict is `improved` only when no image gains a
HIGH/CRITICAL (vulnerability, package) pair and at least one is removed;
`regressed` when any image gains one; `unchanged` otherwise. A scan that did
not produce a report is `failed`, never a zero.

The verdict authorises the demo only. Production keeps the date its compose
file pins, and moving it is a reviewed one-line change.

**MyKronos's own images (`x-mykronos-build`).** The same lane, out of band,
for the estate this repository runs: Concourse, Postgres, the registry, Vault
and the ZAP scanner. Their recipes differ from TheHub's in one way: they are
declared before they are adopted, so the service's `image:` can still be the
vendor's. A recipe therefore names what it publishes rather than deriving it
from `image:`:

    x-mykronos-build:
      context: ../images/apt-upgrade        # relative to the compose file
      base: postgres:15.19@sha256:...       # passed as BASE_IMAGE, optional
      publish: library/postgres:15.19       # repository:tag on the registry
      refresh_arg: APT_REFRESH              # gets the date, optional
      args: {RUN_AS: vault}                 # more build args, optional
      baseline: ...                         # compare against, optional

The candidate is `<registry>/<publish>-p<date>`. Keeping the vendor's
repository path matters: container finding identity drops the registry host
and the tag (`fingerprint.image_repository`), so the derivative's findings
are the vendor image's findings, and the risk acceptances recorded against
them keep covering whatever the rebuild did not fix. The baseline is the
service's `image:` - the vendor image before adoption, the pinned derivative
after - unless the recipe names one, which an image compose builds locally
(ZAP) must, since a local tag cannot be pulled to scan.

`decide` also judges each image on its own (`outcome`) and lists the
candidates worth publishing (`publish`): independent infrastructure should
not wait on each other, so one image that regresses holds back only itself.
The set-level `verdict` keeps its meaning for TheHub's lane.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from mykronos.estate_images import interpolate

COMPOSE_FILES = ("docker-compose.yml", "docker-compose.demo.yml")
GATED = ("CRITICAL", "HIGH")
_DATE_SUFFIX = re.compile(r"-p(\d{8})$")
_DATE = re.compile(r"^\d{8}$")

Verdict = Literal["improved", "unchanged", "regressed", "failed"]


@dataclass(frozen=True)
class Recipe:
    """One patched image: what runs now, and what a rebuild would publish."""

    current: str
    candidate: str
    context: str
    build_args: tuple[tuple[str, str], ...]
    services: tuple[str, ...]

    def tsv(self) -> str:
        args = " ".join(f"--build-arg={k}={v}" for k, v in self.build_args)
        return f"{self.candidate}\t{self.context}\t{args}"


def _registry_path(reference: str, registry: str) -> str:
    """Put the reference on `registry`, keeping its repository and tag."""
    _, _, rest = reference.partition("/")
    return f"{registry}/{rest}"


def plan(
    root: Path,
    date: str,
    registry: str,
    env: dict[str, str] | None = None,
    files: tuple[str, ...] = COMPOSE_FILES,
) -> list[Recipe]:
    """Every distinct `x-thehub-build` recipe in `files`, rebased on `date`."""
    if not _DATE.match(date):
        raise ValueError(f"date {date!r} is not YYYYMMDD")
    found: dict[str, Recipe] = {}
    for name in files:
        path = root / name
        if not path.is_file():
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for service, definition in (document.get("services") or {}).items():
            build = (definition or {}).get("x-thehub-build")
            if not build:
                continue
            reference, unresolved = interpolate(str(definition.get("image", "")), env or {})
            if unresolved:
                raise ValueError(f"{name}::{service}: unset {', '.join(unresolved)}")
            if not _DATE_SUFFIX.search(reference):
                raise ValueError(f"{name}::{service}: {reference!r} has no -pYYYYMMDD suffix")
            current = _registry_path(reference, registry)
            args = [(str(k), str(v)) for k, v in (build.get("args") or {}).items()]
            if build.get("refresh_arg"):
                args.append((str(build["refresh_arg"]), date))
            where = f"{name}::{service}"
            if current in found:
                previous = found[current]
                found[current] = Recipe(
                    previous.current,
                    previous.candidate,
                    previous.context,
                    previous.build_args,
                    (*previous.services, where),
                )
                continue
            found[current] = Recipe(
                current=current,
                candidate=_DATE_SUFFIX.sub(f"-p{date}", current),
                context=str(build["context"]).removeprefix("./"),
                build_args=tuple(args),
                services=(where,),
            )
    return sorted(found.values(), key=lambda r: r.current)


#: The compose files that declare MyKronos's own recipes, relative to the root.
MYKRONOS_COMPOSE_FILES = ("deploy/concourse/docker-compose.yml", "deploy/demo/docker-compose.yml")
_TAGGED = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9._-]*$")


def plan_mykronos(
    root: Path,
    date: str,
    registry: str,
    env: dict[str, str] | None = None,
    files: tuple[str, ...] = MYKRONOS_COMPOSE_FILES,
) -> list[Recipe]:
    """Every distinct `x-mykronos-build` recipe in `files`, built for `date`.

    Two services sharing one `publish` (Concourse's web and worker) are one
    recipe; they must agree on everything else, or the plan refuses.
    """
    if not _DATE.match(date):
        raise ValueError(f"date {date!r} is not YYYYMMDD")
    found: dict[str, tuple[Recipe, tuple[Any, ...]]] = {}
    for name in files:
        path = root / name
        if not path.is_file():
            continue
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for service, definition in (document.get("services") or {}).items():
            build = (definition or {}).get("x-mykronos-build")
            if not build:
                continue
            where = f"{name}::{service}"
            publish = str(build.get("publish", ""))
            if not _TAGGED.match(publish):
                raise ValueError(f"{where}: publish {publish!r} must be repository:tag")
            if _DATE_SUFFIX.search(publish):
                raise ValueError(f"{where}: publish {publish!r} must not carry a -p date")
            baseline_ref = str(build.get("baseline") or definition.get("image", ""))
            baseline, unresolved = interpolate(baseline_ref, env or {})
            if unresolved:
                raise ValueError(f"{where}: unset {', '.join(unresolved)}")
            if not baseline:
                raise ValueError(f"{where}: no image: and no baseline to compare against")
            context = (path.parent / str(build["context"])).resolve()
            try:
                relative = context.relative_to(root.resolve()).as_posix()
            except ValueError as exc:
                raise ValueError(
                    f"{where}: context {build['context']!r} leaves the repository"
                ) from exc
            if not (context / "Dockerfile").is_file():
                raise ValueError(f"{where}: no Dockerfile in {relative}")
            args = [(str(k), str(v)) for k, v in (build.get("args") or {}).items()]
            if build.get("base"):
                args.append(("BASE_IMAGE", str(build["base"])))
            if build.get("refresh_arg"):
                args.append((str(build["refresh_arg"]), date))
            recipe = Recipe(
                current=baseline,
                candidate=f"{registry}/{publish}-p{date}",
                context=relative,
                build_args=tuple(args),
                services=(where,),
            )
            shape = (recipe.current, recipe.context, recipe.build_args)
            if publish in found:
                previous, previous_shape = found[publish]
                if previous_shape != shape:
                    raise ValueError(
                        f"{where}: publishes {publish} like {previous.services[0]} "
                        "but with a different recipe"
                    )
                found[publish] = (
                    Recipe(
                        previous.current,
                        previous.candidate,
                        previous.context,
                        previous.build_args,
                        (*previous.services, where),
                    ),
                    previous_shape,
                )
                continue
            found[publish] = (recipe, shape)
    return sorted((r for r, _ in found.values()), key=lambda r: r.candidate)


def gated_findings(report: dict[str, Any]) -> set[tuple[str, str]]:
    """The HIGH/CRITICAL (vulnerability, package) pairs in one Trivy JSON report."""
    pairs: set[tuple[str, str]] = set()
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") in GATED:
                pairs.add((str(vuln.get("VulnerabilityID")), str(vuln.get("PkgName"))))
    return pairs


@dataclass
class Comparison:
    current: str
    candidate: str
    removed: list[tuple[str, str]] = field(default_factory=list)
    added: list[tuple[str, str]] = field(default_factory=list)
    kept: int = 0
    error: str | None = None


def compare(
    current: str,
    candidate: str,
    current_report: dict[str, Any] | None,
    candidate_report: dict[str, Any] | None,
) -> Comparison:
    for which, report in (("current", current_report), ("candidate", candidate_report)):
        if report is None:
            return Comparison(current, candidate, error=f"no Trivy report for the {which} image")
        # A report with no result sets means Trivy identified nothing to scan
        # (no OS, no packages). That is "could not look", not "clean".
        if not report.get("Results"):
            return Comparison(current, candidate, error=f"the {which} image's report is empty")
    assert current_report is not None and candidate_report is not None
    before, after = gated_findings(current_report), gated_findings(candidate_report)
    return Comparison(
        current,
        candidate,
        removed=sorted(before - after),
        added=sorted(after - before),
        kept=len(before & after),
    )


def decide(comparisons: list[Comparison]) -> Verdict:
    if not comparisons or any(c.error for c in comparisons):
        return "failed"
    if any(c.added for c in comparisons):
        return "regressed"
    if any(c.removed for c in comparisons):
        return "improved"
    return "unchanged"


def outcome(comparison: Comparison) -> Verdict:
    """`decide` for one image: what publishing this candidate alone would mean."""
    return decide([comparison])


def report_name(reference: str) -> str:
    """A filesystem-safe name for one image's Trivy report."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", reference) + ".json"


def _load(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mykronos.image_refresh")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("plan", help="List the recipes and the candidate reference for DATE")
    p.add_argument("--root", default=".")
    p.add_argument("--date", required=True, help="YYYYMMDD package snapshot to build")
    p.add_argument("--registry", required=True, help="host:port the pipeline pushes to")
    p.add_argument(
        "--recipes",
        choices=("thehub", "mykronos"),
        default="thehub",
        help="`x-thehub-build` in TheHub's compose files, or `x-mykronos-build` in this one's",
    )
    p.add_argument("--output", default="-")

    d = sub.add_parser("decide", help="Compare current and candidate Trivy reports")
    d.add_argument("--plan", required=True, help="the build list `plan` wrote")
    d.add_argument("--reports", required=True, help="directory of Trivy JSON reports")
    d.add_argument("--output", required=True, help="where to write the verdict JSON")
    d.add_argument(
        "--publish-list",
        help="also write the candidates to publish, one per line (empty if none)",
    )

    arguments = parser.parse_args(argv)

    if arguments.command == "plan":
        planner = plan_mykronos if arguments.recipes == "mykronos" else plan
        recipes = planner(Path(arguments.root), arguments.date, arguments.registry)
        lines = [f"{r.current}\t{r.tsv()}" for r in recipes]
        text = "\n".join(lines) + ("\n" if lines else "")
        if arguments.output == "-":
            sys.stdout.write(text)
        else:
            Path(arguments.output).write_text(text, encoding="utf-8")
        for r in recipes:
            print(f"[plan] {r.current} -> {r.candidate} ({', '.join(r.services)})", file=sys.stderr)
        return 0

    reports = Path(arguments.reports)
    comparisons = []
    for line in Path(arguments.plan).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        current, candidate = line.split("\t")[:2]
        comparisons.append(
            compare(
                current,
                candidate,
                _load(reports / report_name(current)),
                _load(reports / report_name(candidate)),
            )
        )
    verdict = decide(comparisons)
    # Per image as `outcome`, never as a second `verdict` key: TheHub's
    # publish step greps the file for `"verdict": "improved"`, and an image
    # that improved inside a set that regressed must not satisfy it.
    document = {
        "verdict": verdict,
        "publish": [c.candidate for c in comparisons if outcome(c) == "improved"],
        "images": [
            {
                "current": c.current,
                "candidate": c.candidate,
                "outcome": outcome(c),
                "removed": [list(x) for x in c.removed],
                "added": [list(x) for x in c.added],
                "kept": c.kept,
                "error": c.error,
            }
            for c in comparisons
        ],
    }
    Path(arguments.output).write_text(json.dumps(document, indent=2), encoding="utf-8")
    if arguments.publish_list:
        Path(arguments.publish_list).write_text(
            "".join(f"{c}\n" for c in document["publish"]), encoding="utf-8"
        )
    for c in comparisons:
        state = c.error or f"-{len(c.removed)} +{len(c.added)} ={c.kept} HIGH/CRITICAL"
        print(f"[decide] {c.candidate}: {state} ({outcome(c)})", file=sys.stderr)
        for vuln, package in c.added:
            print(f"[decide]   NEW {vuln} in {package}", file=sys.stderr)
    print(f"[decide] verdict: {verdict}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
