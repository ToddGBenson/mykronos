"""Can a published image name the commit it was built from? (#382)

Every image this platform publishes is *tagged* with its commit, and a tag is
a label on the outside of the box: a container cannot read the tag it was
started from. What it can read is its own environment, so the build passes the
SHA in as `MYKRONOS_BUILD_SHA` (#361 for the backend, #895 for the frontend).
On 2026-09-15 two of the three published images could not say it, nothing
failed, and one of them cost five days of frozen lanes (TheHub#343).

This is the check, made where the artifact is already in hand: the containers
lane pulls each image it publishes to scan it. Trivy's JSON report carries the
image config, including `config.Env`, so the lane writes JSON, converts it to
the SARIF it always uploaded (`trivy convert`, no second scan), and the upload
step runs `--annotate` here to copy the recorded SHA onto each SARIF run as
`properties.mykronosBuildSha`. The Trivy adapter turns that into a finding.

**Three answers, not two** -- the #367 precedent of a three-state
`matches_scan`. "This image does not record its commit" is a Dockerfile or
build-arg fix; "this image records the wrong commit" means the tag is lying or
the build reused a stale layer, and is the worse of the two because every
reader downstream trusts it. They are different rules at different severities
and must not be collapsed. A match is silent. A run with no stamp at all was
never checked (a third-party image, or a report from before this) and is also
silent, because "not asked" is not "absent".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

#: The environment variables an image records its commit in, first match wins.
#: `HUB_BUILD_SHA` is TheHub's spelling of the same stamp (#381).
BUILD_SHA_VARIABLES: tuple[str, ...] = ("MYKRONOS_BUILD_SHA", "HUB_BUILD_SHA")

#: Values that are present and say nothing. `""` is what `ARG X=""` leaves
#: when the build arg is not passed; `unknown` is what TheHub's images carried
#: for exactly that reason (#382's table counts it as MISSING).
_PLACEHOLDERS = frozenset({"", "unknown"})

#: The SARIF run property `--annotate` writes and the adapter reads.
PROPERTY = "mykronosBuildSha"

#: A commit SHA as a tag or a stamp spells it: abbreviated or full.
_SHA = re.compile(r"^[0-9a-f]{7,64}$")

RULE_ABSENT = "mykronos-image-build-sha-absent"
RULE_MISMATCH = "mykronos-image-build-sha-mismatch"

Verdict = Literal["absent", "mismatch", "match"]


@dataclass(frozen=True)
class Provenance:
    """What one image says about itself, and what it was published as."""

    verdict: Verdict
    #: The variable that was read, or the first one looked for when none was.
    variable: str
    #: The value the image records; None when it records nothing usable.
    recorded: str | None
    #: The commit it should name: the image's tag, or the scanned commit.
    expected: str


def recorded_build_sha(config: Mapping[str, Any]) -> tuple[str, str | None]:
    """`(variable, value)` from an image config, or from a Trivy JSON report.

    Accepts the OCI image config (`{"config": {"Env": [...]}}`, what `crane
    config` and `docker inspect` print) and Trivy's report, which nests the
    same object at `Metadata.ImageConfig`. A placeholder value is returned as
    None: an image whose stamp says `unknown` cannot name its commit any more
    than one with no stamp at all.
    """
    metadata = config.get("Metadata")
    if isinstance(metadata, Mapping) and isinstance(metadata.get("ImageConfig"), Mapping):
        config = metadata["ImageConfig"]
    inner = config.get("config") or config.get("Config") or {}
    env = inner.get("Env") if isinstance(inner, Mapping) else None
    values: dict[str, str] = {}
    for entry in env if isinstance(env, list) else []:
        if isinstance(entry, str) and "=" in entry:
            name, _, value = entry.partition("=")
            values.setdefault(name, value)
    for variable in BUILD_SHA_VARIABLES:
        if variable in values:
            value = values[variable].strip()
            return variable, (None if value.lower() in _PLACEHOLDERS else value)
    return BUILD_SHA_VARIABLES[0], None


def tag_of(reference: str) -> str:
    """The tag of `registry:5000/name:tag`, ignoring a digest; "" if none."""
    reference = reference.split("@", 1)[0]
    last = reference.rsplit("/", 1)[-1]
    return last.rsplit(":", 1)[1] if ":" in last else ""


def _same_commit(a: str, b: str) -> bool:
    """Equal, or one an abbreviation (7+ characters) of the other."""
    a, b = a.strip().lower(), b.strip().lower()
    if not a or not b:
        return False
    short, long_ = sorted((a, b), key=len)
    return len(short) >= 7 and long_.startswith(short)


def assess(image: str, variable: str, recorded: str | None, commit_sha: str) -> Provenance:
    """Compare what an image records with the commit it was published as.

    The tag is the claim being checked -- "mismatch with the tag" is the
    defect #382 names -- so it is the expected value whenever it looks like a
    commit. An image tagged `latest` makes no claim about a commit, and is
    compared with the commit the lane scanned instead.
    """
    tag = tag_of(image).lower()
    expected = tag if _SHA.match(tag) else commit_sha
    if recorded is None:
        return Provenance("absent", variable, None, expected)
    if _same_commit(recorded, expected):
        return Provenance("match", variable, recorded, expected)
    return Provenance("mismatch", variable, recorded, expected)


def stamp(run_properties: dict[str, Any], config: Mapping[str, Any]) -> None:
    """Write what the image records onto a SARIF run's properties."""
    variable, value = recorded_build_sha(config)
    run_properties[PROPERTY] = {"variable": variable, "recorded": value}


def stamped(run_properties: Mapping[str, Any]) -> tuple[str, str | None] | None:
    """`(variable, recorded)` from a stamped run; None when it was not checked."""
    entry = run_properties.get(PROPERTY)
    if not isinstance(entry, Mapping):
        return None
    variable = str(entry.get("variable") or BUILD_SHA_VARIABLES[0])
    recorded = entry.get("recorded")
    value = recorded.strip() if isinstance(recorded, str) else ""
    return variable, (value if value and value.lower() not in _PLACEHOLDERS else None)


def annotate_reports(directory: Path) -> dict[str, int]:
    """Stamp each `X.sarif` from the Trivy JSON report beside it, `X.json`.

    Only reports with a JSON twin are stamped, and the lane writes one only
    for the images it publishes. A third-party image records no commit of
    ours, so it is never asked -- and never reported absent.
    """
    counts = {"reports": 0, "stamped": 0}
    for sarif_path in sorted(directory.glob("*.sarif")):
        counts["reports"] += 1
        json_path = sarif_path.with_suffix(".json")
        if not json_path.is_file():
            continue
        try:
            config = json.loads(json_path.read_text(encoding="utf-8"))
            document = json.loads(sarif_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(config, dict) or not isinstance(document, dict):
            continue
        changed = False
        for run in document.get("runs") or []:
            if not isinstance(run, dict):
                continue
            properties = run.setdefault("properties", {})
            if isinstance(properties, dict):
                stamp(properties, config)
                changed = True
        if changed:
            sarif_path.write_text(json.dumps(document), encoding="utf-8")
            counts["stamped"] += 1
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m mykronos.image_provenance",
        description=(
            "Copy the build SHA each published image records (MYKRONOS_BUILD_SHA) "
            "from Trivy's JSON report onto its SARIF report, for the containers "
            "adapter to check against the image's tag (#382)."
        ),
    )
    parser.add_argument(
        "--annotate",
        metavar="DIR",
        required=True,
        help="Directory holding trivy-*.sarif reports and their trivy-*.json twins.",
    )
    arguments = parser.parse_args(argv)
    directory = Path(arguments.annotate)
    if not directory.is_dir():
        print(f"error: --annotate {directory} is not a directory", file=sys.stderr)
        return 2
    counts = annotate_reports(directory)
    print(
        f"Stamped the recorded build SHA onto {counts['stamped']} of "
        f"{counts['reports']} report(s) (#382).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
