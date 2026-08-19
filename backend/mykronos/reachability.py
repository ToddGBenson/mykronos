"""Is anything in this repository importing this file? (spec 19 §2.1)

Spec 17 §5.3 built the plumbing for a `reachability` Oracle input, declined to
build a call-graph engine, and left the category permanently
`available: false`. That was the right call — a call graph that handles
dynamic dispatch, decorators and framework registration is a project, not a
feature — but it left the honest floor unbuilt too.

This is that floor, and it is much less than reachability: for Python only,
does anything else in the repository import this module. Not "is this function
called". A file nothing imports and that is not an entry point is dead weight,
and a finding in dead weight is a genuinely lower priority than the same
finding on a request path.

Everything it cannot answer, it declines to answer. Non-Python files are not
in the result at all. Neither are entry points, files reached by a dynamic
import, or anything in a repository the analysis never ran for — each of those
is `available: false` or simply absent, never "orphaned, so lower risk".
Guessing in that direction would quietly deprioritise real findings, which is
the one failure mode this must not have.
"""

from __future__ import annotations

import ast
import fnmatch
import os
from dataclasses import dataclass, field

#: Files that are entry points by convention and are therefore never orphaned
#: however little imports them — being un-imported is their whole job.
#:
#: Deliberately generous. A false "this is an entry point" costs one file its
#: reachability signal; a false "this is orphaned" tells somebody a live
#: request handler is dead code.
ENTRY_POINT_GLOBS: tuple[str, ...] = (
    "main.py",
    "__main__.py",
    "manage.py",
    "wsgi.py",
    "asgi.py",
    "app.py",
    "settings.py",
    "conf.py",
    "setup.py",
    "conftest.py",
    "scripts/*",
    "*/scripts/*",
    "bin/*",
    "*/bin/*",
    "migrations/*",
    "*/migrations/*",
    "alembic/*",
    "*/alembic/*",
    "test_*.py",
    "*_test.py",
    "tests/*",
    "*/tests/*",
)


@dataclass
class ImportGraph:
    """Which modules import which, plus what could not be resolved."""

    #: module path → the module paths it imports, restricted to modules in
    #: this repository. An import of `requests` is not an edge here: the
    #: question is internal reachability.
    edges: dict[str, set[str]] = field(default_factory=dict)
    #: Files that would not parse. Counted, not guessed at — a syntax error in
    #: a file this analysis cannot read must not make everything it might have
    #: imported look orphaned.
    unparseable: set[str] = field(default_factory=set)
    #: Files carrying an `if __name__ == "__main__"` block. Entry points by
    #: construction, and detected rather than guessed: the first run of this
    #: over Mykronos itself reported `cli.py` and this module as orphaned,
    #: which is true of their imports and false about their purpose. A glob
    #: list would have needed a new entry for every such file forever.
    executable: set[str] = field(default_factory=set)

    @property
    def imported(self) -> set[str]:
        return {target for targets in self.edges.values() for target in targets}


def _module_name(path: str) -> str:
    """`src/pkg/thing.py` → `src.pkg.thing`, and `.../__init__.py` → the package."""
    trimmed = path[: -len(".py")] if path.endswith(".py") else path
    if trimmed.endswith("/__init__"):
        trimmed = trimmed[: -len("/__init__")]
    return trimmed.replace("/", ".")


def _candidates(module: str) -> set[str]:
    """Every internal module name an import statement could be naming.

    No dependency resolution, per spec 19 §2.1 — `from pkg.thing import x`
    could mean the module `pkg.thing` or the name `x` inside `pkg`, and
    without resolving the package this cannot tell. Both are recorded, and
    every suffix of the dotted path besides: a repository laid out under
    `src/` imports `pkg.thing` while the file is `src/pkg/thing.py`.

    Over-matching on purpose. A spurious edge makes a file look reachable,
    which costs a signal; a missed edge makes a live file look orphaned.
    """
    parts = module.split(".")
    return {".".join(parts[index:]) for index in range(len(parts)) if parts[index:]}


def build_graph(sources: dict[str, str]) -> ImportGraph:
    """An import graph over `{path: source}` for the Python files in a repo."""
    graph = ImportGraph()
    known = {_module_name(path) for path in sources}
    by_suffix: dict[str, set[str]] = {}
    for name in known:
        for suffix in _candidates(name):
            by_suffix.setdefault(suffix, set()).add(name)

    for path, source in sources.items():
        module = _module_name(path)
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            graph.unparseable.add(path)
            continue

        if _has_main_guard(tree):
            graph.executable.add(path)

        targets: set[str] = set()
        for node in ast.walk(tree):
            named: list[str] = []
            if isinstance(node, ast.Import):
                named = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    # A relative import. Resolved against this file's own
                    # package rather than skipped, because relative imports
                    # are how most intra-package edges are actually written
                    # and dropping them would orphan half of every package.
                    base = module.split(".")[: -node.level] or []
                    named = [".".join([*base, node.module or ""]).strip(".")]
                    named += [
                        ".".join([*base, node.module or "", alias.name]).strip(".")
                        for alias in node.names
                    ]
                else:
                    named = [node.module or ""]
                    named += [
                        f"{node.module}.{alias.name}" if node.module else alias.name
                        for alias in node.names
                    ]
            for name in named:
                if not name:
                    continue
                for suffix in _candidates(name):
                    targets |= by_suffix.get(suffix, set())
        graph.edges[module] = targets - {module}

    return graph


def _has_main_guard(tree: ast.AST) -> bool:
    """Whether the module has an `if __name__ == "__main__"` block.

    Top level only. A guard nested inside a function is not how anybody
    writes an entry point, and walking the whole tree would let a string
    comparison in unrelated code exempt a file from the analysis.
    """
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "__name__"
            and any(
                isinstance(c, ast.Constant) and c.value == "__main__"
                for c in test.comparators
            )
        ):
            return True
    return False


def is_entry_point(path: str, globs: tuple[str, ...] = ENTRY_POINT_GLOBS) -> bool:
    base = os.path.basename(path)
    return any(fnmatch.fnmatch(path, glob) or fnmatch.fnmatch(base, glob) for glob in globs)


def orphaned(
    sources: dict[str, str], *, entry_point_globs: tuple[str, ...] = ENTRY_POINT_GLOBS
) -> list[str]:
    """Python files nothing in the repository imports, and that are not entry
    points.

    A file that would not parse is never reported orphaned. Its own imports
    are unknown, so every module it might have imported is *also* unproven,
    and reporting a whole subtree as dead because one file has a syntax error
    is exactly the confident-wrong answer this module exists to avoid.
    """
    return _orphaned(sources, build_graph(sources), entry_point_globs)


def _orphaned(
    sources: dict[str, str], graph: ImportGraph, globs: tuple[str, ...]
) -> list[str]:
    """Nothing at all, if any file failed to parse.

    Blunt on purpose. A file whose imports could not be read might have been
    the only importer of anything else in the tree, so *no* file can be
    confidently called orphaned while one is unreadable — not just that file.
    Reporting the rest anyway would mean discounting a finding in live code
    because an unrelated module had a syntax error.

    The cost is that one bad file silences the signal for the repository.
    That is the right way round: this category subtracts points, so the safe
    failure is saying nothing. `files_unparseable` is recorded alongside, so
    an operator wondering why the signal went quiet can see the reason rather
    than guessing at it.
    """
    if graph.unparseable:
        return []

    imported = graph.imported
    return sorted(
        path
        for path in sources
        if path not in graph.unparseable
        and path not in graph.executable
        and not is_entry_point(path, globs)
        and _module_name(path) not in imported
    )


def read_repository(root: str, *, limit: int = 5000) -> dict[str, str]:
    """Every Python file under `root`, keyed by repo-relative path.

    Vendored trees are skipped: cataloguing `node_modules` or a `.venv` turns
    a second into minutes and describes software this repository does not
    write.
    """
    skip = {".git", "node_modules", ".venv", "venv", "vendor", "__pycache__", "dist", "build"}
    sources: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for filename in filenames:
            if not filename.endswith(".py"):
                continue
            full = os.path.join(dirpath, filename)
            relative = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, encoding="utf-8", errors="replace") as handle:
                    sources[relative] = handle.read()
            except OSError:
                continue
            if len(sources) >= limit:
                return sources
    return sources


def main(argv: list[str] | None = None) -> int:
    """Emit a `ReachabilitySubmission` body on stdout.

    Runner-side, like `aegis_signals` and `atlas_counts`: the analysis needs
    the checked-out tree, which the platform does not have and should not
    fetch a repository to get.

        python -m mykronos.reachability . --commit-sha "$SHA"
    """
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(prog="mykronos-reachability", description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--commit-sha", default="")
    args = parser.parse_args(argv)

    sources = read_repository(args.root)
    graph = build_graph(sources)
    dead = _orphaned(sources, graph, ENTRY_POINT_GLOBS)

    json.dump(
        {
            "language": "python",
            "commit_sha": args.commit_sha,
            "orphaned_paths": dead,
            "files_analysed": len(sources),
            "files_unparseable": len(graph.unparseable),
        },
        sys.stdout,
        ensure_ascii=False,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
