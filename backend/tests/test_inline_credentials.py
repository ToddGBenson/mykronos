"""An inline empty string is not an exposed credential (B-065).

`check_applied_pipelines.py` asked whether a variable resolved from Vault,
which is the right question for configuration and the wrong one for exposure.
On 2026-09-05 it reported six credentials inline: three held nothing, one was
a deliberate one-hour token, and two were real.

A warning that overstates gets discounted, and the parts of it that matter get
discounted with it. `fly get-pipeline` handing back an empty string is not the
same event as it handing back a live model key.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_applied_pipelines.py"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("check_applied_pipelines", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load()


def classify(disk: Any, live: Any) -> Any:
    report = checker.Report()
    checker.compare(live, disk, report)
    return report


class TestWhatTheAppliedConfigHolds:
    def test_a_resolved_reference_is_from_vault(self) -> None:
        report = classify({"KEY": "((anthropic-api-key))"}, {"KEY": "((anthropic-api-key))"})

        assert report.from_vault == ["((anthropic-api-key))"]
        assert report.in_config == []
        assert report.empty == []

    def test_a_literal_value_is_an_exposure(self) -> None:
        """The one this check exists for: `fly get-pipeline` hands it to
        anyone who can reach this Concourse."""
        report = classify({"KEY": "((anthropic-api-key))"}, {"KEY": "sk-ant-not-a-real-key"})

        assert report.in_config == ["((anthropic-api-key))"]
        assert report.empty == []

    def test_an_empty_literal_is_not_an_exposure(self) -> None:
        """Three of the six reported on 2026-09-05 were this."""
        report = classify({"KEY": "((azure-client-secret))"}, {"KEY": ""})

        assert report.empty == ["((azure-client-secret))"]
        assert report.in_config == []

    def test_whitespace_is_still_empty(self) -> None:
        report = classify({"KEY": "((hibp-api-key))"}, {"KEY": "   "})

        assert report.empty == ["((hibp-api-key))"]

    def test_a_missing_value_is_empty_rather_than_secret(self) -> None:
        report = classify({"KEY": "((hibp-api-key))"}, {"KEY": None})

        assert report.empty == ["((hibp-api-key))"]

    def test_a_variable_inside_a_longer_string_is_not_guessed(self) -> None:
        """The value cannot be isolated from the text around it, and guessing
        there would be the same overstatement in the other direction."""
        report = classify({"CMD": "auth ((github-token)) --now"}, {"CMD": "auth  --now"})

        assert report.empty == []
        assert report.in_config == ["((github-token))"]


class TestSayingWhichIsWhich:
    def test_the_deliberate_one_is_named_with_its_reason(self) -> None:
        """`github-token` is minted per run and dead in an hour. Reporting it
        beside two accidental literals is how the accidental ones stop being
        read."""
        assert "github-token" in checker.DELIBERATE
        assert len(checker.DELIBERATE["github-token"].split()) >= 10

    def test_a_setting_is_not_treated_as_a_credential(self) -> None:
        """`((registry))` and `((scanned-branch))` belong in the vars file."""
        assert checker.is_secret("((registry))") is False
        assert checker.is_secret("((anthropic-api-key))") is True
        assert checker.is_secret("((personal-soc-ingestion-token))") is True
