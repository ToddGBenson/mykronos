"""`urlopen` honours `file://`, and both of these parse the answer as JSON.

Semgrep's `dynamic-urllib-use-detected` on `audit_pipeline_timeouts.py:43`
is the kind of finding that is easy to wave away -- a developer script,
reading an environment variable, on a machine the developer already owns.
The reason to fix it rather than disposition it is that the waving-away is
a statement about today's caller, and the code is a statement about every
caller. `CONCOURSE_URL=file:///etc/passwd` is a local file read wearing an
API call's clothes, and the guard costs two lines.

`seed.py` has the same shape through `--url` and is fixed here too, because
this codebase has already paid for fixing one instance of a defect and
missing its sibling (#335, and the note in `test_applied_pipelines_check`).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AUDIT = REPO_ROOT / "scripts" / "audit_pipeline_timeouts.py"
SEED = REPO_ROOT / "deploy" / "demo" / "seed.py"


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestTheAuditRefusesANonHttpConcourse:
    """The base is read from the environment at import, so the check is too."""

    @pytest.mark.parametrize(
        "value",
        [
            "file:///etc/passwd",
            "file://./deploy/concourse/pipelines/mykronos.yml",
            "/var/run/nothing",
            "ftp://example.invalid",
        ],
    )
    def test_a_non_http_base_stops_the_script(self, monkeypatch, value) -> None:
        monkeypatch.setenv("CONCOURSE_URL", value)
        monkeypatch.delitem(sys.modules, "audit_timeouts_under_test", raising=False)

        with pytest.raises(SystemExit) as exit_info:
            _load(AUDIT, "audit_timeouts_under_test")

        assert "http" in str(exit_info.value)

    def test_an_http_base_is_accepted_and_normalised(self, monkeypatch) -> None:
        monkeypatch.setenv("CONCOURSE_URL", "http://concourse.example:8080/")
        monkeypatch.delitem(sys.modules, "audit_timeouts_under_test", raising=False)

        module = _load(AUDIT, "audit_timeouts_under_test")

        assert module.CONCOURSE == "http://concourse.example:8080"

    def test_the_default_is_still_the_local_concourse(self, monkeypatch) -> None:
        """The guard must not have changed where an unconfigured run points."""
        monkeypatch.delenv("CONCOURSE_URL", raising=False)
        monkeypatch.delitem(sys.modules, "audit_timeouts_under_test", raising=False)

        module = _load(AUDIT, "audit_timeouts_under_test")

        assert module.CONCOURSE == "http://127.0.0.1:8080"


class TestTheSeederRefusesANonHttpBase:
    def test_a_file_url_is_refused_at_construction(self) -> None:
        seed = _load(SEED, "demo_seed_under_test")

        with pytest.raises(ValueError, match="http"):
            seed.Client("file:///etc/passwd", "admin", "gate")

    def test_an_http_base_is_accepted_and_normalised(self) -> None:
        seed = _load(SEED, "demo_seed_under_test")

        client = seed.Client("http://backend:8100/", "admin", "gate")

        assert client.base == "http://backend:8100"
