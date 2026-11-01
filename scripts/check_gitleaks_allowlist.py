"""Does gitleaks honour every allowlist entry in `.gitleaks.toml`? (TheHub #61011)

#1014 added an allowlist entry, and the structural test of its shape passed,
while gitleaks 8.28 ignored it: the allowlist on `main` suppressed nothing
until #1016. The only way to know an entry works is to run gitleaks.

So this runs gitleaks once with the whole config, then once per allowlist entry
with that entry removed. Removing an entry that suppresses something surfaces
at least one finding the whole config does not report. An entry whose removal
surfaces nothing matches nothing: it was written for a fixture that has gone,
it is in a form gitleaks ignores, or another entry already covers everything
it does. Each of those is a reason to change the file, so the check fails.

    python scripts/check_gitleaks_allowlist.py --config .gitleaks.toml \\
        --source . --mode git --log-opts="--full-history --all"

`--mode git` scans history, which is where the fixtures an entry is written for
live (a branch commit and its squash-merge); `--mode dir` scans files on disk.

Exit 0 when every entry suppresses at least one finding, 1 when one does not
(each is named), 2 when gitleaks itself fails, so a broken scanner never reads
as a pass. Findings are compared by gitleaks' fingerprint and printed by rule,
file and line, always with `--redact`: no secret is printed.

Standard library only: the `secret-hygiene` job installs nothing but pytest.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import shlex
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

Scanner = Callable[[dict[str, Any]], set[str]]


class ScanError(RuntimeError):
    """gitleaks did not produce a report."""


# --------------------------------------------------------------------------
# The entries
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Entry:
    """Where one allowlist entry sits in the parsed config."""

    #: ("rules", rule index, entry index), ("allowlists", entry index) or ("allowlist",)
    where: tuple[Any, ...]
    label: str
    allowlist: dict[str, Any]


def _label(base: str, allowlist: dict[str, Any]) -> str:
    description = str(allowlist.get("description", "")).strip()
    return f"{base} ({description})" if description else base


def entries(config: dict[str, Any]) -> list[Entry]:
    """Every allowlist entry, in every form gitleaks has accepted.

    The rule-scoped `[[rules.allowlists]]`, the top-level `[[allowlists]]` (the
    form #1014 used, which gitleaks 8.28 with `useDefault` loads and ignores),
    and the legacy single `[allowlist]` table.
    """
    found: list[Entry] = []
    for r, rule in enumerate(config.get("rules", [])):
        for a, allowlist in enumerate(rule.get("allowlists", [])):
            base = f"rules[{rule.get('id', r)}].allowlists[{a}]"
            found.append(Entry(("rules", r, a), _label(base, allowlist), allowlist))
    for a, allowlist in enumerate(config.get("allowlists", [])):
        found.append(Entry(("allowlists", a), _label(f"allowlists[{a}]", allowlist), allowlist))
    if isinstance(config.get("allowlist"), dict):
        allowlist = config["allowlist"]
        found.append(Entry(("allowlist",), _label("allowlist", allowlist), allowlist))
    return found


def without(config: dict[str, Any], entry: Entry) -> dict[str, Any]:
    """A deep copy of `config` with `entry` removed.

    A `[[rules]]` left with nothing but its `id` is dropped too: it existed to
    hang the allowlist off a default rule, and an id-only redeclaration is a
    different config from the one the repository would have without the entry.
    """
    result = copy.deepcopy(config)
    kind = entry.where[0]
    if kind == "rules":
        _, r, a = entry.where
        rule = result["rules"][r]
        del rule["allowlists"][a]
        if not rule["allowlists"]:
            del rule["allowlists"]
        if set(rule) <= {"id"}:
            del result["rules"][r]
        if not result["rules"]:
            del result["rules"]
    elif kind == "allowlists":
        del result["allowlists"][entry.where[1]]
        if not result["allowlists"]:
            del result["allowlists"]
    else:
        del result["allowlist"]
    return result


# --------------------------------------------------------------------------
# Writing TOML back (the standard library reads it but cannot write it)
# --------------------------------------------------------------------------

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def _key(key: str) -> str:
    return key if _BARE_KEY.fullmatch(key) else json.dumps(key)


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        # A JSON string with ASCII escapes is a valid TOML basic string.
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, list) and not any(isinstance(item, dict) for item in value):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    raise TypeError(f"cannot write {type(value).__name__} as a TOML value")


def _is_table_array(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(i, dict) for i in value)


def _table(table: dict[str, Any], path: str, lines: list[str]) -> None:
    for key, value in table.items():
        if not isinstance(value, dict) and not _is_table_array(value):
            lines.append(f"{_key(key)} = {_value(value)}")
    for key, value in table.items():
        name = f"{path}.{_key(key)}" if path else _key(key)
        if isinstance(value, dict):
            lines.extend(["", f"[{name}]"])
            _table(value, name, lines)
        elif _is_table_array(value):
            for item in value:
                lines.extend(["", f"[[{name}]]"])
                _table(item, name, lines)


def dumps(config: dict[str, Any]) -> str:
    lines: list[str] = []
    _table(config, "", lines)
    return "\n".join(lines).lstrip("\n") + "\n"


# --------------------------------------------------------------------------
# The verdict
# --------------------------------------------------------------------------


def unused_entries(config: dict[str, Any], scan: Scanner) -> list[Entry]:
    """Every entry whose removal surfaces no finding the whole config hides."""
    declared = entries(config)
    if not declared:
        return []
    baseline = scan(config)
    return [entry for entry in declared if not (scan(without(config, entry)) - baseline)]


def gitleaks_scanner(
    gitleaks: str, source: Path, mode: str, log_opts: str | None
) -> Callable[[dict[str, Any]], set[str]]:
    """A scanner that runs gitleaks with a given config and returns fingerprints."""

    def scan(config: dict[str, Any]) -> set[str]:
        with tempfile.TemporaryDirectory(prefix="gitleaks-allowlist-") as scratch:
            config_path = Path(scratch) / "gitleaks.toml"
            report_path = Path(scratch) / "report.json"
            config_path.write_text(dumps(config), encoding="utf-8")
            command = [*shlex.split(gitleaks), mode, str(source)]
            if mode == "git" and log_opts:
                command.append(f"--log-opts={log_opts}")
            command += [
                "--config", str(config_path),
                "--report-format", "json",
                "--report-path", str(report_path),
                "--redact",
                "--exit-code", "0",
                "--no-banner",
                "--log-level", "error",
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0 or not report_path.exists():
                raise ScanError(
                    f"gitleaks exited {result.returncode}: {result.stderr.strip()[-2000:]}"
                )
            report = json.loads(report_path.read_text(encoding="utf-8") or "[]")
            return {
                finding.get("Fingerprint")
                or f"{finding.get('File')}:{finding.get('RuleID')}:{finding.get('StartLine')}"
                for finding in report
            }

    return scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", type=Path, default=Path(".gitleaks.toml"))
    parser.add_argument("--source", type=Path, default=Path("."))
    parser.add_argument("--mode", choices=("git", "dir"), default="git")
    parser.add_argument("--log-opts", default=None, help="passed to gitleaks in git mode")
    parser.add_argument("--gitleaks", default="gitleaks", help="the gitleaks command")
    args = parser.parse_args(argv)

    try:
        config = tomllib.loads(args.config.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"::error::cannot read {args.config}: {exc}")
        return 2

    declared = entries(config)
    print(f"{args.config}: {len(declared)} allowlist entr{'y' if len(declared) == 1 else 'ies'}")
    scan = gitleaks_scanner(args.gitleaks, args.source, args.mode, args.log_opts)
    try:
        unused = unused_entries(config, scan)
    except (OSError, ScanError) as exc:
        print(f"::error::gitleaks could not run, so no entry is proved: {exc}")
        return 2

    for entry in declared:
        print(f"  {'UNUSED' if entry in unused else 'ok    '}  {entry.label}")
    if unused:
        for entry in unused:
            print(
                f"::error::{args.config}: {entry.label} suppresses no finding gitleaks reports "
                f"without it ({args.mode} scan of {args.source}). It matches nothing, is in a "
                "form gitleaks ignores, or another entry already covers what it does; fix or "
                "remove it."
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
