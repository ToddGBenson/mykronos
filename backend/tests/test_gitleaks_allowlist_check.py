"""Every allowlist entry in `.gitleaks.toml` is proved by gitleaks itself (TheHub #61011).

#1014 added an allowlist entry and merged. `test_gitleaks_allowlist.py`
passed, because the entry had the right shape, while gitleaks 8.28 ignored it
(the top-level `[[allowlists]]` + `targetRules` form under `useDefault`): the
allowlist on `main` suppressed nothing until #1016. A structural test cannot
see that. Only a gitleaks run can.

`scripts/check_gitleaks_allowlist.py` runs gitleaks once with the whole
config, then once per entry with that entry removed. An entry whose removal
surfaces no new finding matches nothing, and the check fails. The
`secret-hygiene` job in backend-pr.yml, a required check, runs it on every
pull request against the config the pull request carries.

The leave-one-out logic is tested here with a fake gitleaks. The tests at the
bottom run the real binary on a planted fixture; they skip when gitleaks is not
on PATH, unless MYKRONOS_REQUIRE_GITLEAKS is set, which `secret-hygiene` does,
so the job can never pass them by skipping.

Standard library and pytest only: `secret-hygiene` runs this file with
`--noconftest` and nothing else installed.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_gitleaks_allowlist.py"

_spec = importlib.util.spec_from_file_location("check_gitleaks_allowlist", SCRIPT)
assert _spec is not None and _spec.loader is not None
check = importlib.util.module_from_spec(_spec)
sys.modules["check_gitleaks_allowlist"] = check
_spec.loader.exec_module(check)


# --------------------------------------------------------------------------
# Finding the entries, and writing a config without one of them
# --------------------------------------------------------------------------

RULE_SCOPED = """
[extend]
useDefault = true

[[rules]]
id = "generic-api-key"

[[rules.allowlists]]
description = "first"
condition = "AND"
paths = ['''(^|/)a\\.py$''']
regexTarget = "match"
regexes = ['''^x$''']

[[rules.allowlists]]
description = "second"
paths = ['''(^|/)b\\.py$''']

[[rules]]
id = "custom"
regex = '''zz[0-9]+'''
keywords = ["zz"]

[[rules.allowlists]]
description = "third"
stopwords = ["zz0"]

[[allowlists]]
description = "fourth, the #1014 shape"
targetRules = ["generic-api-key"]
paths = ['''(^|/)c\\.py$''']

[allowlist]
description = "fifth, the legacy single global form"
paths = ['''(^|/)d\\.py$''']
"""


def test_every_entry_is_found_in_every_form() -> None:
    config = tomllib.loads(RULE_SCOPED)
    names = [entry.label for entry in check.entries(config)]
    assert names == [
        "rules[generic-api-key].allowlists[0] (first)",
        "rules[generic-api-key].allowlists[1] (second)",
        "rules[custom].allowlists[0] (third)",
        "allowlists[0] (fourth, the #1014 shape)",
        "allowlist (fifth, the legacy single global form)",
    ]


def test_removing_an_entry_removes_that_entry_and_nothing_else() -> None:
    config = tomllib.loads(RULE_SCOPED)
    first, second, third, fourth, fifth = check.entries(config)

    without = tomllib.loads(check.dumps(check.without(config, second)))
    assert [a["description"] for a in without["rules"][0]["allowlists"]] == ["first"]
    assert without["rules"][1] == config["rules"][1]
    assert without["allowlists"] == config["allowlists"]

    # A rule left carrying only its id is dropped: it was there to hang the
    # allowlist off, and an empty redeclaration is not something to test.
    without = tomllib.loads(check.dumps(check.without(config, third)))
    assert without["rules"][1] == {"id": "custom", "regex": "zz[0-9]+", "keywords": ["zz"]}

    once = check.without(config, first)
    twice = tomllib.loads(check.dumps(check.without(once, check.entries(once)[0])))
    assert [rule["id"] for rule in twice["rules"]] == ["custom"]

    assert "allowlists" not in tomllib.loads(check.dumps(check.without(config, fourth)))
    assert "allowlist" not in tomllib.loads(check.dumps(check.without(config, fifth)))

    # The original is untouched.
    assert config == tomllib.loads(RULE_SCOPED)


def test_the_writer_round_trips_the_repository_config() -> None:
    config = tomllib.loads((REPO_ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))
    assert tomllib.loads(check.dumps(config)) == config


def test_the_writer_round_trips_awkward_strings() -> None:
    config = {"a": {"s": "quote \" back \\ tab \t new\nline '''", "u": "é", "n": [1, True, 2.5]}}
    assert tomllib.loads(check.dumps(config)) == config


# --------------------------------------------------------------------------
# The verdict, with a fake gitleaks
# --------------------------------------------------------------------------


def fake_scanner(
    suppresses: dict[str, set[str]], findings: set[str]
) -> Callable[[dict[str, Any]], set[str]]:
    """A gitleaks stand-in: an entry, keyed by description, hides findings."""

    def scan(config: dict[str, Any]) -> set[str]:
        hidden: set[str] = set()
        for entry in check.entries(config):
            hidden |= suppresses.get(entry.allowlist.get("description", ""), set())
        return findings - hidden

    return scan


TWO = """
[extend]
useDefault = true

[[rules]]
id = "generic-api-key"

[[rules.allowlists]]
description = "used"
paths = ['''a''']

[[rules.allowlists]]
description = "unused"
paths = ['''b''']
"""


def test_an_entry_that_hides_a_finding_passes() -> None:
    config = tomllib.loads(TWO)
    scan = fake_scanner({"used": {"f1"}, "unused": {"f2"}}, {"f1", "f2", "f3"})
    assert check.unused_entries(config, scan) == []


def test_an_entry_that_matches_no_fixture_fails() -> None:
    config = tomllib.loads(TWO)
    scan = fake_scanner({"used": {"f1"}}, {"f1", "f3"})
    assert [entry.label for entry in check.unused_entries(config, scan)] == [
        "rules[generic-api-key].allowlists[1] (unused)"
    ]


def test_two_entries_covering_only_the_same_finding_both_fail() -> None:
    # Either could go; leave-one-out cannot tell which one gitleaks needs.
    config = tomllib.loads(TWO)
    scan = fake_scanner({"used": {"f1"}, "unused": {"f1"}}, {"f1"})
    assert len(check.unused_entries(config, scan)) == 2


def test_a_config_with_no_entries_passes_without_scanning() -> None:
    def scan(config: dict[str, Any]) -> set[str]:
        raise AssertionError("nothing to prove, so nothing to run")

    assert check.unused_entries({"extend": {"useDefault": True}}, scan) == []


# --------------------------------------------------------------------------
# The real gitleaks, on a planted fixture
# --------------------------------------------------------------------------

GITLEAKS = os.environ.get("GITLEAKS", "gitleaks")
HAVE_GITLEAKS = shutil.which(GITLEAKS) is not None
if not HAVE_GITLEAKS and os.environ.get("MYKRONOS_REQUIRE_GITLEAKS"):
    raise RuntimeError(f"MYKRONOS_REQUIRE_GITLEAKS is set and {GITLEAKS!r} is not on PATH")
needs_gitleaks = pytest.mark.skipif(not HAVE_GITLEAKS, reason="gitleaks is not on PATH")

# Assembled at runtime so this file holds no line generic-api-key fires on.
VALUE = "".join("Qm4Tz8Kd2W"[i % 10] for i in range(32))
FIXTURE_LINE = 'service_key = "' + VALUE + '"\n'


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "fixture.py").write_text(FIXTURE_LINE, encoding="utf-8")
    return source


def config_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "gitleaks.toml"
    path.write_text(body, encoding="utf-8")
    return path


USED = """
[extend]
useDefault = true

[[rules]]
id = "generic-api-key"

[[rules.allowlists]]
description = "the planted fixture"
condition = "AND"
paths = ['''(^|/)fixture\\.py$''']
"""

MATCHES_NOTHING = """
[[rules.allowlists]]
description = "a file that does not exist"
condition = "AND"
paths = ['''(^|/)no_such_fixture\\.py$''']
"""

# The #1014 shape: loads without error under gitleaks 8.28 and suppresses
# nothing. The structural test refuses it by name; this proves it by running.
IGNORED_FORM = """
[extend]
useDefault = true

[[allowlists]]
description = "the planted fixture, by the top-level form"
targetRules = ["generic-api-key"]
paths = ['''(^|/)fixture\\.py$''']
"""


def run_check(tmp_path: Path, source: Path, body: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--config",
            str(config_file(tmp_path, body)),
            "--source",
            str(source),
            "--mode",
            "dir",
            "--gitleaks",
            GITLEAKS,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


@needs_gitleaks
def test_gitleaks_reports_the_fixture_with_no_allowlist(tmp_path: Path, planted: Path) -> None:
    # Without this, every test below could pass on a scanner that found nothing.
    scan = check.gitleaks_scanner(GITLEAKS, planted, "dir", None)
    assert scan({"extend": {"useDefault": True}}), "gitleaks did not fire on the fixture"


@needs_gitleaks
def test_an_entry_gitleaks_honours_passes(tmp_path: Path, planted: Path) -> None:
    result = run_check(tmp_path, planted, USED)
    assert result.returncode == 0, result.stdout + result.stderr


@needs_gitleaks
def test_an_entry_matching_no_fixture_fails_the_check(tmp_path: Path, planted: Path) -> None:
    result = run_check(tmp_path, planted, USED + MATCHES_NOTHING)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "a file that does not exist" in result.stdout
    assert "the planted fixture" not in result.stdout.replace("a file that does not exist", "")


@needs_gitleaks
def test_an_entry_gitleaks_ignores_fails_the_check(tmp_path: Path, planted: Path) -> None:
    result = run_check(tmp_path, planted, IGNORED_FORM)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "the top-level form" in result.stdout


@needs_gitleaks
def test_a_config_gitleaks_refuses_is_an_error_not_a_pass(tmp_path: Path, planted: Path) -> None:
    result = run_check(tmp_path, planted, USED + "\n[[rules]]\nid = 'x'\nregex = '''('''\n")
    assert result.returncode == 2, result.stdout + result.stderr
