"""The drift check tells drift from Concourse's own normalisation (D-081).

A check that reports differences nobody can act on gets ignored, and then it is
worth less than nothing — it looks like coverage. Concourse stores a config it
has normalised: it drops `anchors:`, drops falsy defaults, reorders jobs, and
names every anonymous `image_resource`. All four look like drift to a naive
comparison, and all four appeared on the first run.

`fetch()` shells out to `fly`, so it is not covered here. What is covered is
every rule that decides whether a difference is real.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_applied_pipelines.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_applied_pipelines", CHECKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load()


def run(live, disk):
    report = checker.Report()
    checker.compare(live, disk, report)
    return report


# -- what must NOT be reported --------------------------------------------

def test_falsy_defaults_are_not_drift() -> None:
    """`public: false` and `passed: []` are stored by being left out."""
    disk = {"jobs": [{"name": "a", "public": False, "plan": [{"get": "source", "passed": []}]}]}
    live = {"jobs": [{"name": "a", "plan": [{"get": "source"}]}]}
    assert run(live, disk).drift == []


def test_a_name_concourse_adds_to_an_image_resource_is_not_drift() -> None:
    disk = {"jobs": [{"name": "a", "image_resource": {"type": "registry-image"}}]}
    live = {"jobs": [{"name": "a", "image_resource": {"type": "registry-image", "name": "image"}}]}
    assert run(live, disk).drift == []


def test_job_order_is_not_drift() -> None:
    disk = {"jobs": [{"name": "a", "serial": True}, {"name": "b", "serial": True}]}
    live = {"jobs": [{"name": "b", "serial": True}, {"name": "a", "serial": True}]}
    assert run(live, disk).drift == []


def test_a_var_resolved_from_vault_is_not_drift() -> None:
    report = run({"params": {"T": "((my-token))"}}, {"params": {"T": "((my-token))"}})
    assert report.drift == []
    assert report.from_vault == ["((my-token))"]
    assert report.in_config == []


def test_a_var_supplied_inline_is_not_drift_but_is_recorded() -> None:
    """The value is never compared - only which form the applied config holds."""
    report = run({"params": {"T": "s3cr3t-value"}}, {"params": {"T": "((my-token))"}})
    assert report.drift == []
    assert report.in_config == ["((my-token))"]
    assert report.from_vault == []


# -- what MUST be reported -------------------------------------------------

def test_a_changed_value_is_drift() -> None:
    assert run({"jobs": [{"name": "a", "serial": False}]},
               {"jobs": [{"name": "a", "serial": True}]}).drift


def test_a_missing_job_is_drift() -> None:
    drift = run({"jobs": [{"name": "a"}]}, {"jobs": [{"name": "a"}, {"name": "b"}]}).drift
    assert len(drift) == 1
    assert "`b`" in drift[0]


def test_an_extra_job_is_drift() -> None:
    """The shape of somebody applying from an older checkout."""
    drift = run({"jobs": [{"name": "a"}, {"name": "gone"}]}, {"jobs": [{"name": "a"}]}).drift
    assert len(drift) == 1
    assert "`gone`" in drift[0]


def test_a_truthy_key_missing_from_the_applied_config_is_drift() -> None:
    """`public: false` is a default; `public: true` being dropped is not."""
    assert run({"jobs": [{"name": "a"}]}, {"jobs": [{"name": "a", "public": True}]}).drift


def test_an_edited_task_script_is_drift() -> None:
    """The Oracle gate that was disabled in a working tree looked like this."""
    disk = {"jobs": [{"name": "gate", "plan": [{"task": "evaluate", "run": {"args": ["exit 1"]}}]}]}
    live = {"jobs": [{"name": "gate", "plan": [{"task": "evaluate", "run": {"args": ["exit 0"]}}]}]}
    drift = run(live, disk).drift
    assert len(drift) == 1
    # The value itself is never printed - it can be a credential or 100 lines.
    assert "exit 0" not in drift[0] and "exit 1" not in drift[0]


# -- the credential classification ----------------------------------------

def test_credentials_are_told_from_settings() -> None:
    for name in ("((my-token))", "((minio-secret-key))", "((db-password))", "((x-webhook))"):
        assert checker.is_secret(name), name
    for name in ("((registry))", "((scanned-branch))", "((mykronos-url))", "((prowler-version))"):
        assert not checker.is_secret(name), name


def test_every_pipeline_in_the_map_exists() -> None:
    for relative in checker.PIPELINES.values():
        assert (REPO_ROOT / relative).is_file(), relative
