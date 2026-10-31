"""The repository's gitleaks allowlist stays narrow.

`.gitleaks.toml` at the repository root is picked up by every gitleaks run
that scans this repository without a `--config` flag, including the full
history scan in the Concourse pipeline. A rule in it silences findings across
every commit and every branch, so the file is held to these properties:

* it extends the default ruleset rather than replacing it;
* every allowlist hangs off the one default rule it applies to (a
  `[[rules]]` entry that carries only `id` and `allowlists`, so the rule's
  detection is inherited, not redefined);
* every allowlist names the one file it applies to and a regex anchored over
  the rule's whole match - both must hold (`condition = "AND"`), so no entry
  is a path allowlist;
* each regex matches the fixture it was written for, and does not match a
  credential-shaped value on the same key.

Why not a top-level `[[allowlists]]` with `targetRules`: under gitleaks
8.28.0, the version the pipelines pin, combined with `useDefault`, that form
loads without error and suppresses nothing. A test below refuses it.

These are structural checks. Whether gitleaks itself honours the file is
proved by running gitleaks; the pull request that added each entry records
that run.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / ".gitleaks.toml"

# A value with the length and alphabet of a real key, built at runtime so the
# source holds no credential-shaped literal for the scanner to find.
LOOKALIKE = "".join("Zq7Xw2Lp9R"[i % 10] for i in range(40))


def load() -> dict:
    with CONFIG.open("rb") as handle:
        return tomllib.load(handle)


def allowlists() -> list[tuple[str, dict]]:
    """Every (rule id, allowlist) pair declared under `[[rules]]`.

    Also called at collection time to parametrize; a missing file is reported
    by the tests below, not as a collection error.
    """
    if not CONFIG.exists():
        return []
    return [
        (rule.get("id", "?"), entry)
        for rule in load().get("rules", [])
        for entry in rule.get("allowlists", [])
    ]


def test_the_config_exists_and_extends_the_default_ruleset() -> None:
    config = load()
    assert config.get("extend", {}).get("useDefault") is True, (
        "without [extend] useDefault = true the file replaces gitleaks' "
        "default rules and the scan stops looking for almost everything"
    )


def test_there_is_no_global_allowlist() -> None:
    # `[allowlist]` (singular) applies to every rule.
    assert "allowlist" not in load()


def test_there_is_no_top_level_allowlists_table() -> None:
    # `[[allowlists]]` with `targetRules` is the documented form, but under
    # gitleaks 8.28.0 with `useDefault` it suppresses nothing: the entry would
    # look like a fix while the finding stays open. Allowlists go under the
    # rule they apply to instead.
    assert "allowlists" not in load()


def test_rules_only_attach_allowlists_to_default_rules() -> None:
    rules = load().get("rules", [])
    assert rules, "no [[rules]] entry carries an allowlist"
    for rule in rules:
        assert set(rule) <= {"id", "allowlists"}, (
            f"{rule.get('id')}: a [[rules]] entry here may only name a default "
            "rule and add allowlists; any other key redefines its detection"
        )
        assert rule.get("id") and rule.get("allowlists"), rule


@pytest.mark.parametrize(
    ("rule_id", "entry"), allowlists(), ids=lambda v: v if isinstance(v, str) else "allowlist"
)
class TestEveryAllowlist:
    def test_requires_path_and_regex_together(self, rule_id: str, entry: dict) -> None:
        assert entry.get("condition") == "AND"
        assert entry.get("paths") and entry.get("regexes")

    def test_has_no_other_escape_hatch(self, rule_id: str, entry: dict) -> None:
        # commits/stopwords would widen the entry past "this match in this
        # file"; targetRules is ignored under a rule and only misleads.
        assert not entry.get("commits")
        assert not entry.get("stopwords")
        assert not entry.get("targetRules")

    def test_each_path_is_one_file(self, rule_id: str, entry: dict) -> None:
        for path in entry["paths"]:
            assert path.endswith("$"), path
            assert ".*" not in path and ".+" not in path, f"{path} matches more than one file"
            assert "*" not in path.replace(r"\*", ""), f"{path} has a wildcard"

    def test_regexes_are_anchored_over_the_whole_match(self, rule_id: str, entry: dict) -> None:
        # "match" is the rule's full match (key name through value). An
        # unanchored regex would also cover a longer match that contains it.
        assert entry.get("regexTarget") == "match"
        for pattern in entry["regexes"]:
            assert pattern.startswith("^") and pattern.endswith("$"), pattern
            assert not re.search(pattern, LOOKALIKE), pattern

    def test_has_a_reason(self, rule_id: str, entry: dict) -> None:
        assert len(entry.get("description", "")) > 20


# --------------------------------------------------------------------------
# The netassess run_key fixture
# --------------------------------------------------------------------------

FIXTURE = "backend/tests/test_network_lanes.py"
# The fixture's value, assembled so this file does not carry the same line.
RUN_KEY = "netassess-" + "2026.10.18" + ".zip"


def fixture_entries() -> list[tuple[str, dict]]:
    return [
        (rule_id, entry)
        for rule_id, entry in allowlists()
        if any(re.search(p, FIXTURE) for p in entry["paths"])
    ]


def fixture_entry() -> dict:
    matches = fixture_entries()
    assert len(matches) == 1, f"expected one allowlist covering {FIXTURE}"
    return matches[0][1]


def test_the_fixture_entry_is_scoped_to_generic_api_key() -> None:
    assert [rule_id for rule_id, _ in fixture_entries()] == ["generic-api-key"]


def test_the_fixture_entry_covers_no_other_test_file() -> None:
    entry = fixture_entry()
    for other in (
        "backend/tests/test_network_lanes_extra.py",
        "backend/tests/conftest.py",
        "backend/mykronos/network.py",
        "tests/test_network_lanes.py.bak",
    ):
        assert not any(re.search(p, other) for p in entry["paths"]), other


def suppressed(match: str) -> bool:
    return any(re.search(p, match) for p in fixture_entry()["regexes"])


def test_the_fixture_is_still_in_the_file() -> None:
    source = (REPO_ROOT / FIXTURE).read_text(encoding="utf-8")
    assert f'"run_key": "{RUN_KEY}"' in source, (
        "the fixture changed; the allowlist entry is stale and should go"
    )


def test_the_fixture_match_is_suppressed() -> None:
    # What generic-api-key matches on the fixture line: the key name through
    # the value's closing quote.
    assert suppressed(f'run_key": "{RUN_KEY}"')


@pytest.mark.parametrize(
    "match",
    [
        f'run_key": "{LOOKALIKE}"',
        f'api_key": "{LOOKALIKE}"',
        f'run_key": "netassess-{LOOKALIKE}.zip"',
        f'run_key": "{RUN_KEY}x"',
        f'my_run_key": "{RUN_KEY}"',
        f'run_key": "{RUN_KEY}", "api_key": "{LOOKALIKE}"',
    ],
)
def test_any_other_match_is_reported(match: str) -> None:
    assert not suppressed(match), match
