"""Is the pipeline that is running the pipeline in this repository? (D-081)

The pipelines that actually run are applied from a working copy, and on
2026-08-20 that copy was eighteen commits behind `main` with uncommitted edits
to five files — including a disabled Oracle gate that existed nowhere in git.
Nothing compared the two, and the divergence was found by accident while
looking for a missing `.env` (L0004).

This is that comparison. `fly get-pipeline` returns the configuration Concourse
is actually running; the repository has the file it was supposed to come from.
Where they disagree, somebody applied from a different checkout, hand-edited a
live pipeline, or forgot to re-apply after a merge.

Three differences are expected and are not drift:

* **`anchors:`** — a YAML convenience the schema has no field for, so Concourse
  drops it after expanding the aliases. Both sides are compared expanded.
* **Job and resource order** — Concourse returns them in its own order, so
  everything is matched by name rather than by position.
* **`((var))` positions** — the committed file references a variable; the
  applied config holds either the same reference (resolved from Vault at
  runtime) or the literal value (supplied through `--load-vars-from`). The
  value is never compared, but *which of the two* is reported, because a
  literal here is exactly what PS-9 is about: `fly get-pipeline` hands it to
  anyone on the team.

No value from the applied config is ever printed. It contains resolved secrets
for anything not yet in Vault, and a drift report that leaks them would be a
worse problem than the drift.

    python scripts/check_applied_pipelines.py            # report
    python scripts/check_applied_pipelines.py --quiet    # exit code only

Exit 0 when every pipeline matches its file, 1 when one has drifted. Fails soft
when Concourse cannot be reached, so this runs on a laptop as well as the host.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

FLY = os.environ.get(
    "FLY", str(Path.home() / "Documents/Projects/PDSO2/deploy/concourse/bin/fly.exe")
)
TARGET = os.environ.get("FLY_TARGET", "mykronos")

PIPELINES = {
    "mykronos": "deploy/concourse/pipelines/mykronos.yml",
    "thehub": "deploy/concourse/pipelines/thehub.yml",
    "personal-soc": "deploy/concourse/pipelines/personal-soc.yml",
}

VAR = re.compile(r"\(\([a-zA-Z0-9_.-]+\)\)")

#: Keys whose lists are identified by a `name` field, so they can be matched
#: rather than compared positionally.
BY_NAME = {"jobs", "resources", "resource_types", "groups"}

#: Concourse normalises the config it stores, and those differences are its
#: own rather than anybody's drift. It names every anonymous `image_resource`,
#: so that key is in the applied config and in no file.
ADDED_BY_CONCOURSE = (".image_resource.name",)

#: A variable supplied through the vars file rather than resolved from Vault is
#: only a *finding* when it is a credential. `((registry))` and
#: `((scanned-branch))` are configuration and belong there; a token does not.
#: Suffix matching rather than a list, so a new credential is caught the day it
#: is added rather than the day somebody remembers to update this.
SECRET_SUFFIXES = ("-token", "-key", "-secret", "-password", "-webhook", "-webhook-url")


def is_secret(name: str) -> bool:
    """Does this variable name look like a credential rather than a setting?"""
    return any(name.strip("()").endswith(suffix) for suffix in SECRET_SUFFIXES)


def fetch(pipeline: str) -> dict[str, Any] | None:
    result = subprocess.run(
        [FLY, "--target", TARGET, "get-pipeline", "-p", pipeline],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode != 0:
        return None
    return yaml.safe_load(result.stdout)


def index(items: list[Any]) -> dict[str, Any] | None:
    """Turn a list of named things into a mapping, or None if it is not one."""
    if not all(isinstance(i, dict) and isinstance(i.get("name"), str) for i in items):
        return None
    names = [i["name"] for i in items]
    if len(set(names)) != len(names):
        return None
    return {i["name"]: i for i in items}


class Report:
    def __init__(self) -> None:
        self.drift: list[str] = []
        self.from_vault: list[str] = []
        self.in_config: list[str] = []


def compare(live: Any, disk: Any, report: Report, path: str = "", key: str = "") -> None:
    # A `((var))` on the committed side: the value is not comparable, but which
    # form the applied config holds is the thing worth knowing.
    if isinstance(disk, str) and VAR.search(disk):
        for name in VAR.findall(disk):
            target = report.from_vault if isinstance(live, str) and name in live else report.in_config
            if name not in target:
                target.append(name)
        return

    if type(live) is not type(disk):
        report.drift.append(f"{path}: {type(disk).__name__} in the file, {type(live).__name__} applied")
        return

    if isinstance(disk, dict):
        for k in sorted(set(disk) | set(live)):
            if any(f"{path}.{k}".endswith(added) for added in ADDED_BY_CONCOURSE):
                continue
            if k not in live and not disk.get(k):
                # Concourse stores its defaults by omitting them, so `public:
                # false`, `passed: []` and `serial: false` are absent from the
                # applied config while being perfectly present in the file.
                # Reporting those would give the check a permanent backlog of
                # findings that mean nothing, which is how a check gets ignored.
                continue
            if k not in live:
                report.drift.append(f"{path}.{k}: in the file, not applied")
            elif k not in disk:
                report.drift.append(f"{path}.{k}: applied, not in the file")
            else:
                compare(live[k], disk[k], report, f"{path}.{k}", k)
        return

    if isinstance(disk, list):
        if key in BY_NAME:
            by_disk, by_live = index(disk), index(live)
            if by_disk is not None and by_live is not None:
                for name in sorted(set(by_disk) | set(by_live)):
                    if name not in by_live:
                        report.drift.append(f"{path}: `{name}` is in the file and not applied")
                    elif name not in by_disk:
                        report.drift.append(f"{path}: `{name}` is applied and not in the file")
                    else:
                        compare(by_live[name], by_disk[name], report, f"{path}[{name}]")
                return
        if len(live) != len(disk):
            report.drift.append(f"{path}: {len(disk)} item(s) in the file, {len(live)} applied")
            return
        for i, (x, y) in enumerate(zip(live, disk)):
            compare(x, y, report, f"{path}[{i}]")
        return

    if live != disk:
        # Values are summarised, never printed: a task's script can be a
        # hundred lines and a param can be a credential.
        report.drift.append(f"{path}: differs")


def check(pipeline: str, relative: str) -> Report | None:
    live = fetch(pipeline)
    if live is None:
        return None
    disk = yaml.safe_load((REPO_ROOT / relative).read_text(encoding="utf-8"))
    # `anchors:` is ours, not Concourse's. PyYAML has already expanded every
    # alias that referenced it, so dropping the block loses nothing.
    disk.pop("anchors", None)
    report = Report()
    compare(live, disk, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-applied-pipelines", description=__doc__)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    unreachable, drifted = [], []
    for pipeline, relative in PIPELINES.items():
        report = check(pipeline, relative)
        if report is None:
            unreachable.append(pipeline)
            continue
        if report.drift:
            drifted.append(pipeline)
        if args.quiet:
            continue

        print("=" * 70)
        print(f"{pipeline}  ({relative})")
        print("=" * 70)
        if report.from_vault:
            print(f"  resolved from Vault : {', '.join(sorted(report.from_vault))}")
        if report.in_config:
            plain = sorted(n for n in report.in_config if not is_secret(n))
            secrets = sorted(n for n in report.in_config if is_secret(n))
            if plain:
                print(f"  supplied inline     : {', '.join(plain)}")
            if secrets:
                print(f"  CREDENTIALS INLINE  : {', '.join(secrets)}")
                print("                        readable by anyone who can run `fly get-pipeline` (PS-9)")
        if not report.drift:
            print("  the applied pipeline matches the committed file")
        else:
            print(f"  DRIFT -- {len(report.drift)} difference(s):")
            for line in report.drift[:25]:
                print(f"    {line}")
            if len(report.drift) > 25:
                print(f"    ... and {len(report.drift) - 25} more")
        print()

    if unreachable:
        # Fails open: this is a drift check, and "Concourse is not running
        # here" is not drift.
        print(f"Could not read from Concourse, so not checked: {', '.join(unreachable)}")

    if drifted:
        print("These pipelines are not running what this repository says they run:")
        for pipeline in drifted:
            print(f"  - {pipeline}")
        print()
        print("Re-apply from a checkout at this commit, or find out who applied from where.")
        print("The deployment checkout is not necessarily this one -- L0004.")
        return 1

    if not args.quiet and not unreachable:
        print("Every pipeline is running what this repository says it runs.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
