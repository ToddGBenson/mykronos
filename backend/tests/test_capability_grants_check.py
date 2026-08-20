"""The grant check reads both sides correctly, and can fail.

The failure it exists to catch is quiet by construction: TheHub was given a
`qa` lane while the repo had no `qa` grant, every upload was refused 403, and
the job went green because the quality lanes write their upload with `|| true`.
A check for that must itself be checked, or it becomes another green thing
nobody has exercised.

`granted()` shells out to the container, so it is not covered here — the parts
that can silently go wrong are the pipeline parsing and the comparison, and
both are pure.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_capability_grants.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_capability_grants", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load()


def test_reads_the_repo_from_the_pipeline_rather_than_the_filename() -> None:
    text = """
      --repo ToddGBenson/personal-soc \\
      --capability secrets
    """
    assert checker.uploads(text) == {"ToddGBenson/personal-soc": {"secrets"}}


def test_counts_capabilities_that_never_pass_the_flag() -> None:
    """Aegis, Oracle and Patchwork post their own shapes, not findings.

    All three are enforced by the same `_require_capability`, so a check that
    only greps `--capability` would call a repo fully granted while three of
    its lanes 403.
    """
    text = """
      --repo ToddGBenson/x --capability sast
      curl -X POST "$MYKRONOS_URL/api/ingest/aegis"
      curl -X POST "$MYKRONOS_URL/api/oracle/evaluate"
      curl -X POST "$MYKRONOS_URL/api/patchwork/run"
    """
    assert checker.uploads(text)["ToddGBenson/x"] == {"sast", "aegis", "oracle", "patchwork"}


def test_flags_a_capability_that_is_uploaded_but_not_granted() -> None:
    problems = checker.compare(
        {"ToddGBenson/TheHub": {"qa", "unit"}},
        {"ToddGBenson/TheHub": {"unit"}},
    )
    assert len(problems) == 1
    assert "`qa`" in problems[0]
    # The message has to carry the fix, or it is a puzzle rather than a report.
    assert "mykronos.cli grant ToddGBenson/TheHub qa" in problems[0]


def test_a_grant_with_no_lane_is_not_a_failure() -> None:
    """That is the cross-check's `no_job`, reported per repository already."""
    assert checker.compare(
        {"ToddGBenson/x": {"sast"}},
        {"ToddGBenson/x": {"sast", "cloud", "network"}},
    ) == []


def test_a_repo_with_no_active_token_is_flagged() -> None:
    problems = checker.compare({"ToddGBenson/x": {"sast"}}, {})
    assert len(problems) == 1
    assert "no active token" in problems[0]


def test_the_real_pipelines_declare_a_repo_and_upload_something() -> None:
    """Guards the parsing against a pipeline that stops matching the regex."""
    for relative in checker.PIPELINES:
        text = (REPO_ROOT / relative).read_text(encoding="utf-8")
        sent = checker.uploads(text)
        assert sent, f"{relative}: no `--repo` found, so nothing can be checked"
        for repo, capabilities in sent.items():
            assert "/" in repo, f"{relative}: {repo!r} is not owner/name"
            assert capabilities, f"{relative}: {repo} uploads nothing, which cannot be right"
