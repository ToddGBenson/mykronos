#!/usr/bin/env python3
"""Move the workflow templates' action pins forward to what the estate runs.

    python scripts/refresh_template_pins.py                 # from this repo's own pins
    python scripts/refresh_template_pins.py --source ../keel --source ../binnacle
    python scripts/refresh_template_pins.py --check         # exit 1 if anything would move

Dependabot keeps rendered workflows current and never touches the `.j2`
templates they come from, so an install kept rendering pins the target had
already moved past (#376, TheHub #60876). This reads every `*.yml`/`*.yaml`
under each `--source` (default: this repository's `.github/workflows/` and
`actions/`) and moves each template pin to the newest same-major release found
there. A source can be a checkout of an onboarded repository, whose generated
`mykronos-*.yml` its own Dependabot keeps current.

Forward only, same major unless `--allow-major`, and a release pinned to two
different SHAs is reported and left alone. The rules and their reasons are in
`backend/mykronos/installer/template_pins.py`.

Needs the backend importable: run it with the backend's environment.
`backend/tests/test_template_pins.py` fails while any template is behind this
repository's own pins; this script is the fix.

When it changes a template, bump that template's `version` in
`workflow-templates/manifest.json` -- that is what tells a resync, and the
person reviewing its pull request, that the rendered file changed.

Exit codes: 0 nothing to do (or written), 1 `--check` found drift, 2 bad input.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from mykronos.installer.template_pins import refresh_templates  # noqa: E402

DEFAULT_SOURCES = (ROOT / ".github" / "workflows", ROOT / "actions")


def _read_sources(paths: list[Path]) -> dict[str, str] | None:
    sources: dict[str, str] = {}
    for base in paths:
        if not base.exists():
            print(f"error: source {base} does not exist", file=sys.stderr)
            return None
        files = [base] if base.is_file() else sorted(
            p for p in base.rglob("*") if p.suffix in (".yml", ".yaml") and p.is_file()
        )
        for path in files:
            sources[str(path)] = path.read_text(encoding="utf-8")
    return sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--source",
        action="append",
        type=Path,
        help="a workflow file or directory whose pins are current (repeatable)",
    )
    parser.add_argument("--templates", type=Path, default=ROOT / "workflow-templates")
    parser.add_argument(
        "--allow-major", action="store_true", help="also apply a new major release"
    )
    parser.add_argument(
        "--check", action="store_true", help="report drift and exit 1; write nothing"
    )
    args = parser.parse_args(argv)

    sources = _read_sources(args.source or list(DEFAULT_SOURCES))
    if sources is None:
        return 2
    if not args.templates.is_dir():
        print(f"error: templates directory {args.templates} does not exist", file=sys.stderr)
        return 2

    paths = {p.name: p for p in sorted(args.templates.glob("*.j2"))}
    templates = {name: p.read_text(encoding="utf-8") for name, p in paths.items()}
    refreshed, changes, skips, conflicts = refresh_templates(
        templates, sources, allow_major=args.allow_major
    )

    for conflict in conflicts:
        print(f"conflict: {conflict}")
    for skip in skips:
        print(f"skipped: {skip.describe()}")
    for change in changes:
        print(f"{'drift' if args.check else 'moved'}: {change.describe()}")

    if args.check:
        return 1 if changes else 0
    for name, content in refreshed.items():
        if content != templates[name]:
            paths[name].write_text(content, encoding="utf-8", newline="\n")
    if not changes:
        print("templates are current with the sources read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
