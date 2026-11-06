"""Reachability from CodeQL dataflow, for Python and JS/TS (TheHub #60891).

The import graph (`mykronos.reachability`, spec 19 §2.1) answers one narrow
question: does anything in the repository import this Python file. This module
answers the two questions a triager actually asks of a dependency finding --
*is the vulnerable package called from somewhere a request or a process
starts*, and *is it used at all* -- using the CodeQL database the `sast` lane
already builds, so no second analyser is installed and nothing is fetched.

**Three verdicts, and only one of them lowers anything.**

- `reachable` - a call path from an entry point (a request handler, a scope a
  remote flow source is read in, or a module's top level, which runs whenever
  the module loads) to a call into the package. The path is recorded, step by
  step, as the evidence. A CodeQL security result that carries a code flow is
  `reachable` too, with that flow as its path.
- `unreachable` - the package is never imported. Not "no call path was
  found": CodeQL's call graph is incomplete (decorators, framework
  registration, dynamic dispatch) and absence of a path proves nothing. Never
  imported is a statement about every file in the database, and it is only
  made when all of the evidence in `unreachable_gaps` holds: the database was
  not empty, no import of any name the package is imported under exists, no
  dynamic import exists, the package's import name is known, it is a direct
  runtime dependency, and a lockfile's dependency graph shows nothing else in
  the tree requires it -- because a package nothing in *this* code imports is
  still loaded by the dependency that does (`urllib3` under `requests`). It
  is also never said of a package that runs without being imported (a server
  or worker started by name, a database driver loaded from a URL, an npm
  executable), nor when CodeQL extracted only part of the tree.
- `unknown` - everything else, with the reason. Imported but no path found,
  transitive, a development dependency, an import name this module cannot
  confirm (PyPI's `PyYAML` is imported as `yaml`), no lockfile. Saying so is
  the answer; guessing `unreachable` would suppress a live finding, which is
  the one failure this must not have.

The platform re-checks every `unreachable` it receives against the same
`unreachable_gaps` (ingest downgrades a short one to `unknown`), and the
auto-triage `unreachable` lane (T8, TheHub #60888) re-checks again before it
suppresses anything. The import graph stays the floor beneath all of this.

Runner-side, like `mykronos.reachability`:

    python -m mykronos.reachability_dataflow --language python --write-queries q/
    codeql database analyze <db> q/ --format=sarif-latest --output=reach.sarif
    python -m mykronos.reachability_dataflow --language python \\
        --sarif reach.sarif --analysis-sarif-dir results/ --root . \\
        --commit-sha "$SHA"
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

#: CodeQL language -> the package ecosystem its dependency findings come from.
LANGUAGES: dict[str, str] = {"python": "pypi", "javascript": "npm"}

#: Bounds on what a submission may carry. A path longer than this is cut, and
#: says so; a repository with more verdicts than this is cut too.
MAX_PATH_STEPS = 64
MAX_VERDICTS = 5000

VERDICTS = ("reachable", "unreachable", "unknown")

#: Never descended into when reading manifests and lockfiles: vendored trees
#: describe software this repository does not declare.
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "vendor", "__pycache__", "dist", "build"}

# --------------------------------------------------------------------------
# The queries
# --------------------------------------------------------------------------

_PY_REACHABLE = """\
/**
 * @name Package API reachable from an entry point
 * @description A call into a third-party package that a call path from an
 *              entry point reaches (Mykronos, TheHub #60891).
 * @kind path-problem
 * @problem.severity recommendation
 * @id mykronos/reachability/python/package-api-reachable
 */

import python
import semmle.python.ApiGraphs
import semmle.python.Concepts
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.internal.DataFlowDispatch as Dispatch

/** An API graph node reached from an import of top-level module `pkg`. */
API::Node fromPackage(string pkg) {
  result = API::moduleImport(pkg)
  or
  result = fromPackage(pkg).getAMember()
  or
  result = fromPackage(pkg).getReturn()
}

/** A call into package `pkg`. */
class PackageCall extends DataFlow::CallCfgNode {
  string pkg;

  PackageCall() { this = fromPackage(pkg).getACall() }

  string getPackage() { result = pkg }
}

newtype TNode =
  TScopeNode(Scope s) { s instanceof Function or s instanceof Module } or
  TCallNode(PackageCall c)

class Node extends TNode {
  string toString() {
    exists(Scope s | this = TScopeNode(s) |
      result = "function " + s.(Function).getName()
      or
      result = "module " + s.(Module).getName()
    )
    or
    exists(PackageCall c | this = TCallNode(c) | result = "call into " + c.getPackage())
  }

  Location getLocation() {
    exists(Scope s | this = TScopeNode(s) | result = s.getLocation())
    or
    exists(PackageCall c | this = TCallNode(c) | result = c.getLocation())
  }
}

/**
 * An entry point: a request handler, a scope a remote flow source is read in,
 * or a module's top level, which runs whenever the module is loaded.
 */
predicate isEntry(Node n) {
  exists(Scope s | n = TScopeNode(s) |
    s instanceof Http::Server::RequestHandler
    or
    exists(RemoteFlowSource src | src.getScope() = s)
    or
    s instanceof Module
  )
}

query predicate edges(Node a, Node b) {
  exists(Scope caller, Function callee, CallNode call |
    a = TScopeNode(caller) and
    b = TScopeNode(callee) and
    call.getScope() = caller and
    Dispatch::resolveCall(call, callee, _)
  )
  or
  exists(Scope s, PackageCall c |
    a = TScopeNode(s) and
    b = TCallNode(c) and
    c.getScope() = s
  )
}

from Node source, Node sink, PackageCall call
where
  isEntry(source) and
  sink = TCallNode(call) and
  edges+(source, sink)
select call, source, sink, "Call into package " + call.getPackage() + " reachable from $@.",
  source, source.toString()
"""

_PY_IMPORTS = """\
/**
 * @name Imported top-level modules
 * @description Every top-level module the analysed code imports, so an absent
 *              package is a recorded absence rather than a guess.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/python/package-import
 */

import python

from ImportExpr imp, string top
where
  top = imp.getImportedModuleName().splitAt(".", 0) and
  imp.getLocation().getFile().fromSource()
select imp, "Imports module " + top + "."
"""

_PY_DYNAMIC = """\
/**
 * @name Dynamic imports
 * @description An import whose module name is computed at run time. While one
 *              exists, no package can be called unimported.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/python/dynamic-import
 */

import python
import semmle.python.ApiGraphs

from DataFlow::CallCfgNode call
where
  (
    call = API::moduleImport("importlib").getMember("import_module").getACall()
    or
    call = API::builtin("__import__").getACall()
  ) and
  not call.getArg(0).asExpr() instanceof StringLiteral
select call, "Dynamic import: the module name is computed at run time."
"""

_PY_FILES = """\
/**
 * @name Analysed source files
 * @description How many source files the database holds: the denominator for
 *              every absence the other queries report.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/python/source-files
 */

import python

from File first, int n
where
  n = count(File f | f.fromSource() and f.getExtension() = "py") and
  first =
    rank[1](File f | f.fromSource() and f.getExtension() = "py" | f order by f.getAbsolutePath())
select first, "Analysed " + n + " source files."
"""

_JS_REACHABLE = """\
/**
 * @name Package API reachable from an entry point
 * @description A call into an npm package that a call path from an entry
 *              point reaches (Mykronos, TheHub #60891).
 * @kind path-problem
 * @problem.severity recommendation
 * @id mykronos/reachability/javascript/package-api-reachable
 */

import javascript

/** An API graph node reached from an import of module `pkg`. */
API::Node fromPackage(string pkg) {
  result = API::moduleImport(pkg)
  or
  result = fromPackage(pkg).getAMember()
  or
  result = fromPackage(pkg).getReturn()
  or
  result = fromPackage(pkg).getInstance()
}

/** A call into package `pkg`. */
class PackageCall extends DataFlow::InvokeNode {
  string pkg;

  PackageCall() { this = fromPackage(pkg).getAnInvocation() }

  string getPackage() { result = pkg }
}

newtype TNode =
  TContainerNode(StmtContainer s) { s instanceof Function or s instanceof TopLevel } or
  TCallNode(PackageCall c)

class Node extends TNode {
  string toString() {
    exists(StmtContainer s | this = TContainerNode(s) |
      result = s.(Function).describe()
      or
      s instanceof TopLevel and result = "top level of " + s.getFile().getBaseName()
    )
    or
    exists(PackageCall c | this = TCallNode(c) | result = "call into " + c.getPackage())
  }

  Location getLocation() {
    exists(StmtContainer s | this = TContainerNode(s) | result = s.getLocation())
    or
    exists(PackageCall c | this = TCallNode(c) | result = c.getAstNode().getLocation())
  }
}

/**
 * An entry point: a route handler, a function a remote flow source is read
 * in, or a file's top level, which runs whenever the module is loaded.
 */
predicate isEntry(Node n) {
  exists(StmtContainer s | n = TContainerNode(s) |
    s = any(Http::RouteHandler h).(DataFlow::FunctionNode).getFunction()
    or
    exists(RemoteFlowSource src | src.getContainer() = s)
    or
    s instanceof TopLevel
  )
}

query predicate edges(Node a, Node b) {
  exists(StmtContainer caller, Function callee, DataFlow::InvokeNode call |
    a = TContainerNode(caller) and
    b = TContainerNode(callee) and
    call.getContainer() = caller and
    callee = call.getACallee()
  )
  or
  exists(StmtContainer s, PackageCall c |
    a = TContainerNode(s) and
    b = TCallNode(c) and
    c.getContainer() = s
  )
}

from Node source, Node sink, PackageCall call
where
  isEntry(source) and
  sink = TCallNode(call) and
  edges+(source, sink)
select call, source, sink, "Call into package " + call.getPackage() + " reachable from $@.",
  source, source.toString()
"""

_JS_IMPORTS = """\
/**
 * @name Imported modules
 * @description Every module path the analysed code imports or requires, so an
 *              absent package is a recorded absence rather than a guess.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/javascript/package-import
 */

import javascript

from Import imp
where not imp.getTopLevel().isExterns()
select imp, "Imports module " + imp.getImportedPathString() + "."
"""

_JS_DYNAMIC = """\
/**
 * @name Dynamic imports
 * @description An import or require whose path is computed at run time. While
 *              one exists, no package can be called unimported.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/javascript/dynamic-import
 */

import javascript

from Import imp
where not imp.getTopLevel().isExterns() and not exists(imp.getImportedPathString())
select imp, "Dynamic import: the module path is computed at run time."
"""

_JS_FILES = """\
/**
 * @name Analysed source files
 * @description How many source files the database holds: the denominator for
 *              every absence the other queries report.
 * @kind problem
 * @problem.severity recommendation
 * @id mykronos/reachability/javascript/source-files
 */

import javascript

predicate analysed(File f) { exists(TopLevel t | t.getFile() = f and not t.isExterns()) }

from File first, int n
where
  n = count(File f | analysed(f)) and
  first = rank[1](File f | analysed(f) | f order by f.getAbsolutePath())
select first, "Analysed " + n + " source files."
"""

#: language -> {file name: contents}. Shipped as strings rather than package
#: data so the pinned `pip install` that brings this module brings exactly the
#: queries it parses the output of. The library packs come from the CodeQL
#: bundle the `sast` lane already downloaded; nothing else is fetched.
QUERIES: dict[str, dict[str, str]] = {
    "python": {
        "qlpack.yml": (
            "name: mykronos/reachability-python\nversion: 0.1.0\n"
            'dependencies:\n  codeql/python-all: "*"\n'
        ),
        "PackageApiReachable.ql": _PY_REACHABLE,
        "PackageImports.ql": _PY_IMPORTS,
        "DynamicImports.ql": _PY_DYNAMIC,
        "SourceFiles.ql": _PY_FILES,
    },
    "javascript": {
        "qlpack.yml": (
            "name: mykronos/reachability-javascript\nversion: 0.1.0\n"
            'dependencies:\n  codeql/javascript-all: "*"\n'
        ),
        "PackageApiReachable.ql": _JS_REACHABLE,
        "PackageImports.ql": _JS_IMPORTS,
        "DynamicImports.ql": _JS_DYNAMIC,
        "SourceFiles.ql": _JS_FILES,
    },
}


def write_queries(language: str, out_dir: Path) -> Path:
    """Write the query pack for `language` into `out_dir` and return it."""
    pack = QUERIES[canonical_language(language)]
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in pack.items():
        (out_dir / name).write_text(text, encoding="utf-8")
    return out_dir


def canonical_language(language: str) -> str:
    """`javascript-typescript` (the Actions matrix name) is `javascript`."""
    value = (language or "").strip().lower()
    if value in {"javascript-typescript", "typescript", "js", "ts"}:
        return "javascript"
    if value not in QUERIES:
        raise ValueError(f"no dataflow reachability for language {language!r}")
    return value


# --------------------------------------------------------------------------
# Names
# --------------------------------------------------------------------------


def normalise_package(ecosystem: str, name: str) -> str:
    """PEP 503 for PyPI, which is case- and separator-insensitive; npm as is."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name.strip()).lower()
    return name.strip()


def normalise_path(path: Any) -> str:
    """The same rule `clusters.normalise_path` applies to a finding's path."""
    text = str(path or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


#: PyPI distribution -> the top-level modules it is imported under, where that
#: is known. A distribution absent from here and not installed beside this
#: module has an *unconfirmed* import name, and is never called unreachable:
#: `PyYAML` is imported as `yaml`, and assuming the distribution's own name
#: would report every PyYAML user as never importing it.
KNOWN_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "aiohttp": ("aiohttp",),
    "attrs": ("attr", "attrs"),
    "beautifulsoup4": ("bs4",),
    "boto3": ("boto3",),
    "botocore": ("botocore",),
    "celery": ("celery",),
    "certifi": ("certifi",),
    "cryptography": ("cryptography",),
    "django": ("django",),
    "fastapi": ("fastapi",),
    "flask": ("flask",),
    "gunicorn": ("gunicorn",),
    "httpx": ("httpx",),
    "idna": ("idna",),
    "jinja2": ("jinja2",),
    "lxml": ("lxml",),
    "markupsafe": ("markupsafe",),
    "numpy": ("numpy",),
    "pandas": ("pandas",),
    "paramiko": ("paramiko",),
    "pillow": ("PIL",),
    "protobuf": ("google",),
    "pycryptodome": ("Crypto",),
    "pydantic": ("pydantic",),
    "pyjwt": ("jwt",),
    "pyopenssl": ("OpenSSL",),
    "python-dateutil": ("dateutil",),
    "python-jose": ("jose",),
    "python-multipart": ("multipart", "python_multipart"),
    "pyyaml": ("yaml",),
    "redis": ("redis",),
    "requests": ("requests",),
    "scikit-learn": ("sklearn",),
    "setuptools": ("setuptools", "pkg_resources", "distutils"),
    "sqlalchemy": ("sqlalchemy",),
    "starlette": ("starlette",),
    "urllib3": ("urllib3",),
    "uvicorn": ("uvicorn",),
    "werkzeug": ("werkzeug",),
}


def import_names(ecosystem: str, package: str) -> tuple[set[str], str | None]:
    """The names `package` is imported under, and how that is known.

    The basis is None where it is not known. npm is always known: the import
    specifier *is* the package name.
    """
    if ecosystem == "npm":
        return {package}, "npm_package_name"
    key = normalise_package("pypi", package)
    if key in KNOWN_IMPORT_NAMES:
        return set(KNOWN_IMPORT_NAMES[key]), "known_mapping"
    installed = _installed_import_names().get(key)
    if installed:
        return installed, "installed_metadata"
    # A guess good enough to *find* an import (which only ever makes a package
    # look used), never good enough to prove an absence.
    return {key.replace("-", "_")}, None


_INSTALLED: dict[str, set[str]] | None = None


def _installed_import_names() -> dict[str, set[str]]:
    global _INSTALLED
    if _INSTALLED is None:
        from importlib import metadata

        found: dict[str, set[str]] = {}
        try:
            for module, dists in metadata.packages_distributions().items():
                for dist in dists:
                    found.setdefault(normalise_package("pypi", dist), set()).add(module)
        except Exception:  # noqa: BLE001 - unreadable metadata confirms nothing
            found = {}
        _INSTALLED = found
    return _INSTALLED


#: Packages that run without the code importing them: a server or worker
#: started by name (`gunicorn app:app`, `celery -A app worker`), the libraries
#: such a server loads for itself, and database drivers SQLAlchemy or an ORM
#: loads from a connection URL. Never imported is not never executed, so none
#: of these is ever `unreachable` (review of #1102). For npm, any locked
#: package with a `bin` counts as well: package.json's scripts can run it.
LOADED_WITHOUT_IMPORT: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "aiomysql",
            "aiosqlite",
            "alembic",
            "asyncpg",
            "celery",
            "circus",
            "cx-oracle",
            "daphne",
            "eventlet",
            "flower",
            "gevent",
            "granian",
            "gunicorn",
            "honcho",
            "httptools",
            "hypercorn",
            "mysqlclient",
            "oracledb",
            "psycopg",
            "psycopg-binary",
            "psycopg2",
            "psycopg2-binary",
            "pymssql",
            "pymysql",
            "pyodbc",
            "supervisor",
            "uvicorn",
            "uvloop",
            "waitress",
            "watchfiles",
        }
    ),
    "npm": frozenset(
        {
            "better-sqlite3",
            "concurrently",
            "cross-env",
            "forever",
            "http-server",
            "mysql",
            "mysql2",
            "next",
            "nodemon",
            "npm-run-all",
            "oracledb",
            "pg",
            "pg-native",
            "pm2",
            "react-scripts",
            "serve",
            "sqlite3",
            "tedious",
            "ts-node",
            "tsx",
            "vite",
        }
    ),
}


def loaded_without_import(ecosystem: str, package: str, graph: DependencyGraph) -> bool:
    """Whether `package` can run, or be loaded, without any import of it."""
    key = normalise_package(ecosystem, package)
    return key in LOADED_WITHOUT_IMPORT.get(ecosystem, frozenset()) or key in graph.executables


def _imports_package(ecosystem: str, names: Iterable[str], imported: Iterable[str]) -> bool:
    """Whether any imported module or specifier is one of `names`."""
    wanted = set(names)
    for spec in imported:
        if ecosystem == "npm":
            if any(spec == name or spec.startswith(name + "/") for name in wanted):
                return True
        elif spec.split(".", 1)[0] in wanted:
            return True
    return False


# --------------------------------------------------------------------------
# Lockfiles and manifests
# --------------------------------------------------------------------------


@dataclass
class DependencyGraph:
    """What the lockfiles say about the dependency tree, for one ecosystem."""

    #: Direct runtime dependencies of the repository's own project(s).
    direct: set[str] = field(default_factory=set)
    #: Direct development-only dependencies: run by tooling, rarely imported,
    #: so never importing one proves nothing.
    dev: set[str] = field(default_factory=set)
    #: package -> the locked packages that require it.
    dependents: dict[str, set[str]] = field(default_factory=dict)
    #: The lockfiles read. Empty means there is no graph, and so no proof that
    #: anything is not transitive.
    lockfiles: list[str] = field(default_factory=list)
    #: Packages a manifest declares, lockfile or not.
    declared: set[str] = field(default_factory=set)
    #: Locked packages that install an executable (npm's `bin`), which a
    #: script can run without anything importing them.
    executables: set[str] = field(default_factory=set)


def _walk(root: Path, names: set[str]) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for filename in sorted(filenames):
            if filename in names or (
                "requirements" in names
                and filename.startswith("requirements")
                and filename.endswith(".txt")
            ):
                found.append(Path(dirpath) / filename)
    return found


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(spec: str) -> str | None:
    match = _REQ_NAME.match(spec or "")
    return normalise_package("pypi", match.group(1)) if match else None


def npm_graph(root: Path) -> DependencyGraph:
    """`package.json` declarations and the `package-lock.json` graph."""
    graph = DependencyGraph()
    for manifest in _walk(root, {"package.json"}):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                graph.declared |= {str(n) for n in section}

    for lockfile in _walk(root, {"package-lock.json", "npm-shrinkwrap.json"}):
        try:
            data = json.loads(lockfile.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        packages = data.get("packages") if isinstance(data, dict) else None
        if not isinstance(packages, dict):
            # lockfileVersion 1 has no root entry to tell direct from
            # transitive by; it is not read rather than read half-way.
            continue
        graph.lockfiles.append(_rel(root, lockfile))
        root_entry = packages.get("") or {}
        if isinstance(root_entry, dict):
            for key in ("dependencies", "optionalDependencies", "peerDependencies"):
                section = root_entry.get(key)
                if isinstance(section, dict):
                    graph.direct |= {str(n) for n in section}
            section = root_entry.get("devDependencies")
            if isinstance(section, dict):
                graph.dev |= {str(n) for n in section}
        for location, entry in packages.items():
            if not location or not isinstance(entry, dict):
                continue
            # `node_modules/a/node_modules/@s/b` -> `@s/b`
            name = str(entry.get("name") or location.rsplit("node_modules/", 1)[-1])
            if entry.get("bin"):
                graph.executables.add(name)
            if not location.startswith("node_modules/") and "node_modules/" not in location:
                # A workspace member: its own declarations are direct too.
                for key in ("dependencies", "optionalDependencies", "peerDependencies"):
                    section = entry.get(key)
                    if isinstance(section, dict):
                        graph.direct |= {str(n) for n in section}
                continue
            for key in ("dependencies", "optionalDependencies", "peerDependencies"):
                section = entry.get(key)
                if isinstance(section, dict):
                    for dep in section:
                        graph.dependents.setdefault(str(dep), set()).add(name)
    return graph


def pypi_graph(root: Path) -> DependencyGraph:
    """Manifest declarations, and the `uv.lock` or `poetry.lock` graph."""
    graph = DependencyGraph()
    runtime_from_pyproject: set[str] = set()
    for manifest in _walk(root, {"requirements", "pyproject.toml"}):
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if manifest.name == "pyproject.toml":
            try:
                data = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            project = data.get("project") or {}
            for spec in project.get("dependencies") or []:
                if (name := _req_name(str(spec))) is not None:
                    runtime_from_pyproject.add(name)
            for specs in (project.get("optional-dependencies") or {}).values():
                for spec in specs or []:
                    if (name := _req_name(str(spec))) is not None:
                        graph.declared.add(name)
            poetry = (data.get("tool") or {}).get("poetry") or {}
            for name in poetry.get("dependencies") or {}:
                if str(name).lower() != "python":
                    runtime_from_pyproject.add(normalise_package("pypi", str(name)))
            for name in poetry.get("dev-dependencies") or {}:
                graph.dev.add(normalise_package("pypi", str(name)))
            for group in (poetry.get("group") or {}).values():
                for name in (group or {}).get("dependencies") or {}:
                    graph.dev.add(normalise_package("pypi", str(name)))
        else:
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                if (name := _req_name(line)) is not None:
                    graph.declared.add(name)
    graph.declared |= runtime_from_pyproject

    for lockfile in _walk(root, {"uv.lock", "poetry.lock"}):
        try:
            data = tomllib.loads(lockfile.read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        packages = data.get("package")
        if not isinstance(packages, list):
            continue
        graph.lockfiles.append(_rel(root, lockfile))
        for entry in packages:
            if not isinstance(entry, dict):
                continue
            name = normalise_package("pypi", str(entry.get("name") or ""))
            source = entry.get("source") or {}
            is_root = isinstance(source, dict) and (
                "editable" in source or "virtual" in source
            )
            deps = entry.get("dependencies") or []
            if isinstance(deps, dict):  # poetry.lock
                dep_names = [normalise_package("pypi", str(d)) for d in deps]
            else:  # uv.lock
                dep_names = [
                    normalise_package("pypi", str(d.get("name") or ""))
                    for d in deps
                    if isinstance(d, dict)
                ]
            # An extra is an edge too: `celery[redis]` beside a direct `redis`
            # means celery loads redis at run time. uv.lock records it under
            # `[package.optional-dependencies]`, poetry.lock under
            # `[package.extras]` as requirement strings.
            extras: list[str] = []
            for table in ("optional-dependencies", "extras"):
                section = entry.get(table)
                if not isinstance(section, dict):
                    continue
                for specs in section.values():
                    for spec in specs if isinstance(specs, list) else []:
                        raw = spec.get("name") if isinstance(spec, dict) else spec
                        if (extra := _req_name(str(raw or ""))) is not None:
                            extras.append(extra)
            if is_root:
                graph.direct |= set(dep_names)
                for group in (entry.get("dev-dependencies") or {}).values():
                    for d in group or []:
                        if isinstance(d, dict):
                            graph.dev.add(normalise_package("pypi", str(d.get("name") or "")))
                continue
            for dep in [*dep_names, *extras]:
                if dep != name:
                    graph.dependents.setdefault(dep, set()).add(name)
    if graph.lockfiles and not graph.direct:
        # poetry.lock has no root entry; its direct runtime set is pyproject's.
        graph.direct |= runtime_from_pyproject
    graph.declared |= graph.direct | graph.dev
    return graph


def dependency_graph(root: Path, ecosystem: str) -> DependencyGraph:
    return npm_graph(root) if ecosystem == "npm" else pypi_graph(root)


# --------------------------------------------------------------------------
# Reading CodeQL's output
# --------------------------------------------------------------------------

_CALL = re.compile(r"^Call into package (?P<pkg>\S+) reachable from ")
_IMPORT = re.compile(r"^Imports module (?P<mod>.+)\.$")
_FILES = re.compile(r"^Analysed (?P<n>\d+) source files\.$")


@dataclass
class Observations:
    """What the reachability queries found, in one language's database."""

    language: str
    analyser_version: str = ""
    #: Whether the source-files query ran. Without it there is no denominator,
    #: and every absence is unproven.
    counted: bool = False
    files_analysed: int = 0
    imports: set[str] = field(default_factory=set)
    dynamic_imports: int = 0
    #: package (as imported) -> the shortest path found to a call into it.
    paths: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def _location(loc: Mapping[str, Any]) -> tuple[str, int | None]:
    physical = loc.get("physicalLocation") or {}
    uri = ((physical.get("artifactLocation") or {}).get("uri")) or ""
    line = (physical.get("region") or {}).get("startLine")
    return normalise_path(uri), int(line) if isinstance(line, int) else None


def _thread_path(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The first thread flow of a result, as `{file_path, line, label}` steps."""
    for flow in result.get("codeFlows") or []:
        for thread in (flow or {}).get("threadFlows") or []:
            steps: list[dict[str, Any]] = []
            for item in (thread or {}).get("locations") or []:
                loc = (item or {}).get("location") or {}
                path, line = _location(loc)
                label = str(((loc.get("message") or {}).get("text")) or "")[:200]
                steps.append({"file_path": path, "line": line, "label": label})
            if steps:
                return _cap(steps)
    return []


def _cap(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(steps) <= MAX_PATH_STEPS:
        return steps
    # Keep the entry point and the call; the middle is what gets cut.
    head = steps[: MAX_PATH_STEPS // 2]
    tail = steps[-(MAX_PATH_STEPS // 2 - 1) :]
    dropped = len(steps) - len(head) - len(tail)
    cut = {"file_path": "", "line": None, "label": f"... {dropped} steps cut"}
    return [*head, cut, *tail]


def _results(document: Mapping[str, Any]) -> Iterable[tuple[str, Mapping[str, Any]]]:
    for run in document.get("runs") or []:
        for result in (run or {}).get("results") or []:
            if isinstance(result, dict):
                yield str(result.get("ruleId") or ""), result


def read_observations(document: Mapping[str, Any], language: str) -> Observations:
    """Parse the SARIF `codeql database analyze` wrote for the query pack."""
    lang = canonical_language(language)
    seen = Observations(language=lang)
    for run in document.get("runs") or []:
        driver = ((run or {}).get("tool") or {}).get("driver") or {}
        seen.analyser_version = str(driver.get("semanticVersion") or driver.get("version") or "")
        break
    prefix = f"mykronos/reachability/{lang}/"
    for rule_id, result in _results(document):
        if not rule_id.startswith(prefix):
            continue
        kind = rule_id[len(prefix) :]
        text = str((result.get("message") or {}).get("text") or "")
        if kind == "source-files":
            match = _FILES.match(text)
            if match:
                seen.counted = True
                seen.files_analysed = int(match.group("n"))
        elif kind == "package-import":
            match = _IMPORT.match(text)
            if match:
                seen.imports.add(match.group("mod"))
        elif kind == "dynamic-import":
            seen.dynamic_imports += 1
        elif kind == "package-api-reachable":
            match = _CALL.match(text)
            if not match:
                continue
            path = _thread_path(result)
            if not path:
                continue
            package = match.group("pkg")
            current = seen.paths.get(package)
            if current is None or len(path) < len(current):
                seen.paths[package] = path
    return seen


def location_verdicts(documents: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """A `reachable` verdict for every CodeQL security result with a code flow.

    A path-problem result's flow runs from a source to the sink the finding
    is about, and that flow is the recorded path. Not every stock query's
    source is a remote one, so the verdict claims a traced flow and no more:
    its basis is `codeql_code_flow`, its source is named, and the finding
    page shows it as a traced flow rather than as remote reach. It only ever
    vetoes a suppression. A result without a flow gets no verdict: its
    absence says nothing about reachability.
    """
    verdicts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    for document in documents:
        for rule_id, result in _results(document):
            if not rule_id or rule_id.startswith("mykronos/reachability/"):
                continue
            path = _thread_path(result)
            locations = result.get("locations") or []
            if not path or not locations:
                continue
            file_path, line = _location(locations[0])
            key = (rule_id, file_path, line)
            if not file_path or key in seen:
                continue
            seen.add(key)
            verdicts.append(
                {
                    "target": "location",
                    "rule_id": rule_id,
                    "file_path": file_path,
                    "line": line,
                    "verdict": "reachable",
                    "reason": (
                        f"CodeQL traced a flow of {len(path)} step(s) from "
                        f"{path[0]['label'] or 'a source'} to this result. The query "
                        "decides what counts as a source, and it may be local."
                    )[:1000],
                    "path": path,
                    "evidence": {"basis": "codeql_code_flow", "source_label": path[0]["label"]},
                }
            )
    return verdicts


# --------------------------------------------------------------------------
# Verdicts
# --------------------------------------------------------------------------


def unreachable_gaps(evidence: Mapping[str, Any] | None) -> list[str]:
    """Why `evidence` does not prove a package unreachable. Empty when it does.

    The one gate every `unreachable` passes through -- here, at ingest, and
    in the auto-triage lane -- so the three cannot drift apart.
    """
    ev = evidence or {}
    gaps: list[str] = []
    if not isinstance(ev.get("files_analysed"), int) or ev.get("files_analysed", 0) <= 0:
        gaps.append("no source files were analysed")
    if ev.get("import_count") != 0:
        gaps.append("the package is imported")
    if ev.get("dynamic_imports") != 0:
        gaps.append("the code imports modules by computed name")
    if not ev.get("import_names"):
        gaps.append("no import name was checked")
    if not ev.get("import_name_basis"):
        gaps.append("the package's import name is not confirmed")
    if ev.get("direct_runtime_dependency") is not True:
        gaps.append("not shown to be a direct runtime dependency")
    if not ev.get("lockfiles"):
        gaps.append("no lockfile dependency graph was read")
    if ev.get("dependents") != []:
        gaps.append("another package in the dependency tree requires it")
    if ev.get("loaded_without_import") is not False:
        gaps.append("it can run without being imported (a server, worker, driver or CLI)")
    if ev.get("scoped") is not False:
        gaps.append("CodeQL analysed only part of the repository (paths_include/paths_exclude)")
    return gaps


def entry_kind(path: list[dict[str, Any]]) -> str:
    """What kind of entry point a reachable path starts at.

    A module's top level runs whenever the module loads, which includes a
    test or a one-off script, so a path that starts there says less than
    one that starts in a function a request or a call reaches.
    """
    label = str((path[0] if path else {}).get("label") or "")
    if label.startswith(("module ", "top level of ")):
        return "module_top_level"
    if label:
        return "function"
    return "unknown"


def package_verdict(
    package: str,
    ecosystem: str,
    seen: Observations,
    graph: DependencyGraph,
    *,
    scoped: bool = False,
) -> dict[str, Any]:
    """One package's verdict, with its path or its evidence."""
    names, basis = import_names(ecosystem, package)
    path: list[dict[str, Any]] = []
    for called in sorted(seen.paths):
        candidate = seen.paths[called]
        if not _imports_package(ecosystem, names, [called]):
            continue
        if not path or len(candidate) < len(path):
            path = candidate
    import_count = sum(
        1 for spec in seen.imports if _imports_package(ecosystem, names, [spec])
    )
    base = {
        "target": "package",
        "package_name": package,
        "ecosystem": ecosystem,
    }
    if path:
        return {
            **base,
            "verdict": "reachable",
            "reason": f"A call path from an entry point reaches a call into {package}.",
            "path": path,
            "evidence": {
                "basis": "codeql_call_path",
                "import_names": sorted(names),
                "entry_kind": entry_kind(path),
            },
        }

    dependents = sorted(graph.dependents.get(package, set()))
    evidence = {
        "basis": "codeql_imports",
        "files_analysed": seen.files_analysed if seen.counted else 0,
        "import_count": import_count,
        "import_names": sorted(names),
        "import_name_basis": basis,
        "dynamic_imports": seen.dynamic_imports,
        "direct_runtime_dependency": package in graph.direct and package not in graph.dev,
        "lockfiles": list(graph.lockfiles),
        "dependents": dependents,
        "loaded_without_import": loaded_without_import(ecosystem, package, graph),
        "scoped": bool(scoped),
    }
    gaps = unreachable_gaps(evidence)
    if not gaps:
        return {
            **base,
            "verdict": "unreachable",
            "reason": (
                f"Nothing in {seen.files_analysed} analysed file(s) imports {package} "
                f"(as {', '.join(sorted(names))}), and no other locked package requires it."
            ),
            "path": [],
            "evidence": evidence,
        }
    if import_count:
        reason = (
            f"{package} is imported, but no call path from an entry point to it was "
            "found. CodeQL's call graph is incomplete, so that is not proof it is unused."
        )
    elif dependents:
        reason = (
            f"Required by {', '.join(dependents[:5])}"
            f"{' and others' if len(dependents) > 5 else ''}: it is reached through "
            "them, which this analysis does not follow."
        )
    elif evidence["loaded_without_import"]:
        reason = (
            f"{package} runs without being imported (a server or worker started by "
            "name, a driver loaded from a URL, or an executable), so not importing it "
            "proves nothing."
        )
    elif package in graph.dev:
        reason = "A development dependency: run by tooling, so not importing it proves nothing."
    elif scoped:
        reason = (
            "CodeQL analysed only the configured paths, so an import elsewhere in the "
            "repository would not be seen."
        )
    else:
        reason = "Not proven unreachable: " + "; ".join(gaps) + "."
    return {**base, "verdict": "unknown", "reason": reason, "path": [], "evidence": evidence}


def build_submission(
    language: str,
    reach_document: Mapping[str, Any],
    root: Path,
    *,
    commit_sha: str = "",
    analysis_documents: Iterable[Mapping[str, Any]] = (),
    scoped: bool = False,
) -> dict[str, Any]:
    """The body `POST /api/ingest/reachability/dataflow` takes.

    `scoped` is set when the CodeQL config limited extraction to some paths:
    the source-file count then covers only those, and no absence is proven.
    """
    lang = canonical_language(language)
    ecosystem = LANGUAGES[lang]
    seen = read_observations(reach_document, lang)
    graph = dependency_graph(root, ecosystem)
    packages = sorted(graph.declared | graph.direct | graph.dev)
    verdicts = [package_verdict(p, ecosystem, seen, graph, scoped=scoped) for p in packages]
    verdicts += location_verdicts(analysis_documents)
    return {
        "language": lang,
        "analyser": "codeql",
        "analyser_version": seen.analyser_version,
        "commit_sha": commit_sha,
        "files_analysed": seen.files_analysed if seen.counted else 0,
        "dynamic_imports": seen.dynamic_imports,
        "lockfiles": list(graph.lockfiles),
        "scoped": bool(scoped),
        "verdicts": verdicts[:MAX_VERDICTS],
    }


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return data if isinstance(data, dict) else {}


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    # One flat parser rather than subcommands, so `--help` lists every flag
    # and the template-matches-CLI test can read them all off it.
    parser = argparse.ArgumentParser(
        prog="mykronos-reachability-dataflow",
        description=(
            "Write the CodeQL query pack (--write-queries), or read what it "
            "found (--sarif) and print the submission body on stdout."
        ),
    )
    parser.add_argument("--language", required=True, help="python or javascript")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write-queries", metavar="DIR", help="write the query pack here")
    mode.add_argument("--sarif", help="the SARIF the query pack produced")
    parser.add_argument("--analysis-sarif-dir", default="", help="the scan's own SARIF")
    parser.add_argument("--root", default=".", help="the checkout, for its lockfiles")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument(
        "--scoped",
        action="store_true",
        help="CodeQL extracted only configured paths, so no absence is proven",
    )
    args = parser.parse_args(argv)

    if args.write_queries:
        print(write_queries(args.language, Path(args.write_queries)))
        return 0

    analysis: list[dict[str, Any]] = []
    if args.analysis_sarif_dir:
        for sarif in sorted(Path(args.analysis_sarif_dir).rglob("*.sarif")):
            try:
                analysis.append(_load(sarif))
            except (OSError, ValueError):
                continue
    body = build_submission(
        args.language,
        _load(Path(args.sarif)),
        Path(args.root),
        commit_sha=args.commit_sha,
        analysis_documents=analysis,
        scoped=args.scoped,
    )
    json.dump(body, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
