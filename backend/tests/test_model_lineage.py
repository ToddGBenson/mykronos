"""`different_family` compares model lineage, not model id strings (spec 34 §2)."""

from __future__ import annotations

import pytest

from mykronos.approvals.engine import model_lineage


@pytest.mark.parametrize(
    ("model", "lineage"),
    [
        ("claude-opus-5", "anthropic"),
        ("claude-opus-5.5", "anthropic"),
        ("Claude-Sonnet-5-5", "anthropic"),
        ("claude-haiku-5-5[1m]", "anthropic"),
        ("gpt-5", "openai"),
        ("o3-mini", "openai"),
        ("gemini-2.5-pro", "google"),
        ("llama-4-maverick", "meta"),
        ("mistral-large-3", "mistral"),
        ("some-new-model-7", "some"),
        ("", ""),
    ],
)
def test_lineage(model: str, lineage: str) -> None:
    assert model_lineage(model) == lineage


def test_two_versions_of_one_model_share_a_lineage() -> None:
    assert model_lineage("claude-opus-5") == model_lineage("claude-opus-5.5")


def test_two_vendors_do_not() -> None:
    assert model_lineage("claude-opus-5") != model_lineage("gpt-5")
