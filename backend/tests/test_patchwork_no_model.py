"""No code path in deterministic remediation calls a language model
(TheHub #60746, D-032, D-096).

Two checks, because each misses what the other catches:

- statically, nothing the fixers, the pipeline or the branch rescan import,
  transitively within this package, imports a model SDK or the one module
  that reaches one (`approvals.reviewer`);
- at run time, a fix pull request is opened and its branch rescanned with
  every model client constructor replaced by one that fails the test.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
from datetime import timedelta
from pathlib import Path

import pytest

import mykronos
from tests.test_patchwork import patchwork_auth  # noqa: F401 - fixture

#: The story's code paths: what produces a fix, opens it, and verifies it.
ENTRY_POINTS = (
    "mykronos.patchwork.fixers",
    "mykronos.patchwork.semgrep_fix",
    "mykronos.patchwork.base_image",
    "mykronos.patchwork.image_date",
    "mykronos.patchwork.pipeline",
    "mykronos.patchwork.branch_rescan",
)

#: Top-level packages that are model SDKs.
MODEL_SDKS = frozenset(
    {"anthropic", "openai", "google", "cohere", "mistralai", "ollama", "litellm"}
)

#: In-package modules that call a model.
MODEL_MODULES = frozenset({"mykronos.approvals.reviewer"})

PACKAGE_ROOT = Path(mykronos.__file__).resolve().parent


def _source(module: str) -> Path | None:
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        # `pkg.module.Name` from `from pkg.module import Name`: not a module.
        return None
    if spec is None or spec.origin is None or not spec.origin.endswith(".py"):
        return None
    return Path(spec.origin)


def _imports(module: str) -> set[str]:
    path = _source(module)
    if path is None:
        return set()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")[: len(package.split(".")) - node.level + 1]
                prefix = ".".join(base)
                target = f"{prefix}.{node.module}" if node.module else prefix
            else:
                target = node.module or ""
            found.add(target)
            for alias in node.names:
                found.add(f"{target}.{alias.name}")
    return found


def _closure() -> dict[str, set[str]]:
    """Every in-package module reachable from the entry points, with its imports."""
    seen: dict[str, set[str]] = {}
    pending = list(ENTRY_POINTS)
    while pending:
        module = pending.pop()
        if module in seen:
            continue
        imports = _imports(module)
        seen[module] = imports
        for name in imports:
            if name.startswith("mykronos.") and _source(name) is not None and name not in seen:
                pending.append(name)
    return seen


class TestStatically:
    def test_the_closure_is_not_empty(self) -> None:
        """A closure of one module would pass for the wrong reason."""
        closure = _closure()
        assert set(ENTRY_POINTS) <= set(closure)
        assert "mykronos.github.client" in closure

    def test_no_module_on_the_path_imports_a_model(self) -> None:
        offenders = {
            module: sorted(
                name
                for name in imports
                if name.split(".")[0] in MODEL_SDKS or name in MODEL_MODULES
            )
            for module, imports in _closure().items()
        }
        assert {m: names for m, names in offenders.items() if names} == {}


class TestAtRunTime:
    def test_a_fix_is_opened_and_rescanned_with_no_model_call(
        self,
        monkeypatch,
        client,
        admin_auth,
        patchwork_auth,  # noqa: F811 - fixture
        run_compaction,
        github,
    ) -> None:
        anthropic = pytest.importorskip("anthropic")

        def refuse(*args, **kwargs):
            raise AssertionError("a model client was constructed")

        monkeypatch.setattr(anthropic, "Anthropic", refuse)
        monkeypatch.setattr(anthropic, "AsyncAnthropic", refuse)

        from mykronos.patchwork import branch_rescan
        from tests.conftest import REPO, post_findings, post_scan
        from tests.test_onboarding import onboard
        from tests.test_patchwork_branch_rescan import HEAD, OPENED, _branch_scan
        from tests.test_patchwork_semgrep_fix import FIXTURE_FILES, _findings, _read

        onboard(client, admin_auth)
        rule = "mykronos-pyyaml-load-to-safe-load"
        path = FIXTURE_FILES[rule]
        repo = github.repos[REPO]
        repo.files[path] = _read(path)
        repo.branches.setdefault("main", {})[path] = _read(path)
        finding = _findings()[rule]
        finding["severity"] = "high"
        finding.pop("capability")
        post_scan(
            client,
            patchwork_auth,
            scan_run_id="scan-main-1",
            tool_name="semgrep",
            started_at=(OPENED - timedelta(hours=1)).isoformat(),
        )
        post_findings(client, patchwork_auth, [finding], scan_run_id="scan-main-1")
        run_compaction()

        body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()
        assert body["draft_prs_opened"] == 1, body
        (pr,) = repo.pull_requests
        pr.head_sha, pr.created_at = HEAD, OPENED
        run_compaction()
        _branch_scan(client, {"pr": pr, "finding": finding, "auth": patchwork_auth})
        run_compaction()

        result = asyncio.run(
            branch_rescan.rescan_open_fixes(
                client.app.state.catalog, {REPO: github}, now=OPENED + timedelta(hours=1)
            )
        )
        assert result.recorded == 1, result

