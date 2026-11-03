"""Reachability from CodeQL dataflow, for Python and JS/TS (TheHub #60891).

Acceptance criteria, each with its own class:

- reachable or unreachable, with a recorded path (`TestPython`,
  `TestJavaScript`, `TestIngest`, `TestTheFindingRecord`);
- Python and JS/TS both (`TestPython`, `TestJavaScript`);
- unreachable feeds T8 only with evidence (`TestUnreachableNeedsEvidence`,
  `TestIngest`, and the dataflow tests in `test_auto_triage.py`).

The SARIF under `tests/data/reachability_dataflow/` is real CodeQL 2.27.2
output, trimmed: the query pack this module ships run over the fixture trees
below, plus one stock security query each (py/unsafe-deserialization,
js/reflected-xss) for a result with a code flow. The trees are written to a
temporary directory rather than checked in, so this repository's own scanners
never see a deliberately vulnerable file or a lockfile pinning old packages.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import reachability_dataflow as dataflow
from mykronos.db.models import DataflowReachabilityReport, RepoOnboarding
from tests.conftest import REPO, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

DATA = Path(__file__).resolve().parent / "data" / "reachability_dataflow"

PY_TREE: dict[str, str] = {
    "app/__init__.py": "",
    "app/web.py": (
        "from flask import Flask, request\n"
        "import yaml\n"
        "from app import helpers\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "\n"
        '@app.route("/load")\n'
        "def load():\n"
        '    return helpers.parse(request.args["doc"])\n'
    ),
    "app/helpers.py": (
        "import yaml\n"
        "import requests\n"
        "\n"
        "\n"
        "def parse(text):\n"
        "    return yaml.load(text, Loader=yaml.Loader)\n"
        "\n"
        "\n"
        "def never_called():\n"
        '    return requests.get("https://example.invalid")\n'
    ),
    "pyproject.toml": (
        "[project]\n"
        'name = "fixture-app"\n'
        'version = "0.1.0"\n'
        'dependencies = ["flask>=3", "PyYAML==5.3", "requests>=2.31", "certifi", '
        '"acme-widgets"]\n'
        "\n"
        "[dependency-groups]\n"
        'dev = ["pytest"]\n'
    ),
    "uv.lock": (
        "version = 1\n"
        'requires-python = ">=3.11"\n'
        "\n"
        "[[package]]\n"
        'name = "fixture-app"\n'
        'version = "0.1.0"\n'
        'source = { editable = "." }\n'
        "dependencies = [\n"
        '    { name = "acme-widgets" },\n'
        '    { name = "certifi" },\n'
        '    { name = "flask" },\n'
        '    { name = "pyyaml" },\n'
        '    { name = "requests" },\n'
        "]\n"
        "\n"
        "[package.dev-dependencies]\n"
        'dev = [{ name = "pytest" }]\n'
        "\n"
        + "".join(
            f'[[package]]\nname = "{name}"\nversion = "1.0.0"\n'
            f'source = {{ registry = "https://pypi.org/simple" }}\n{deps}\n'
            for name, deps in [
                ("acme-widgets", ""),
                ("certifi", ""),
                ("flask", 'dependencies = [{ name = "werkzeug" }]\n'),
                ("pytest", ""),
                ("pyyaml", ""),
                ("requests", 'dependencies = [{ name = "urllib3" }]\n'),
                ("urllib3", ""),
                ("werkzeug", ""),
            ]
        )
    ),
}

JS_TREE: dict[str, str] = {
    "src/server.js": (
        "const express = require('express');\n"
        "const { render } = require('./render');\n"
        "const app = express();\n"
        "app.get('/x', (req, res) => { res.send(render(req.query.t)); });\n"
        "app.get('/echo', (req, res) => { res.send('<p>' + req.query.name + '</p>'); });\n"
        "app.listen(3000);\n"
    ),
    "src/render.js": (
        "const _ = require('lodash');\n"
        "const moment = require('moment');\n"
        "function render(t) { return _.template(t)({}); }\n"
        "function unused() { return moment().format(); }\n"
        "module.exports = { render, unused };\n"
    ),
    "package.json": json.dumps(
        {
            "name": "fixture-app",
            "dependencies": {
                "express": "4.17.0",
                "left-pad": "1.3.0",
                "lodash": "4.17.15",
                "moment": "2.29.0",
                "qs": "6.7.0",
            },
            "devDependencies": {"jest": "29.0.0"},
        }
    ),
    "package-lock.json": json.dumps(
        {
            "name": "fixture-app",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "fixture-app",
                    "dependencies": {
                        "express": "4.17.0",
                        "left-pad": "1.3.0",
                        "lodash": "4.17.15",
                        "moment": "2.29.0",
                        "qs": "6.7.0",
                    },
                    "devDependencies": {"jest": "29.0.0"},
                },
                "node_modules/express": {"version": "4.17.0", "dependencies": {"qs": "6.7.0"}},
                "node_modules/jest": {"version": "29.0.0", "dev": True},
                "node_modules/left-pad": {"version": "1.3.0"},
                "node_modules/lodash": {"version": "4.17.15"},
                "node_modules/moment": {"version": "2.29.0"},
                "node_modules/qs": {"version": "6.7.0"},
            },
        }
    ),
}


def write_tree(root: Path, tree: dict[str, str], drop: tuple[str, ...] = ()) -> Path:
    for name, text in tree.items():
        if name in drop:
            continue
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def sarif(name: str) -> dict[str, Any]:
    return dict(json.loads((DATA / f"{name}.sarif.json").read_text(encoding="utf-8")))


def submission(
    language: str, root: Path, reach: dict[str, Any] | None = None
) -> dict[str, Any]:
    prefix = "py" if language == "python" else "js"
    return dataflow.build_submission(
        language,
        reach if reach is not None else sarif(f"{prefix}-reach"),
        root,
        commit_sha="abc123def456",
        analysis_documents=[sarif(f"{prefix}-analysis")],
    )


def by_package(body: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {v["package_name"]: v for v in body["verdicts"] if v["target"] == "package"}


def with_dynamic_import(document: dict[str, Any], language: str) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    changed["runs"][0]["results"].append(
        {
            "ruleId": f"mykronos/reachability/{language}/dynamic-import",
            "message": {"text": "Dynamic import: the module name is computed at run time."},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": "plugins.py"},
                                      "region": {"startLine": 4}}}
            ],
        }
    )
    return changed


def py_tree_with(
    direct: tuple[str, ...] = (), locked: tuple[tuple[str, str], ...] = ()
) -> dict[str, str]:
    """PY_TREE plus direct runtime dependencies `direct`, and extra locked
    `[[package]]` entries `locked` as (name, body) pairs."""
    tree = dict(PY_TREE)
    names = "".join(f', "{name}"' for name in direct)
    tree["pyproject.toml"] = tree["pyproject.toml"].replace(
        '"acme-widgets"]', f'"acme-widgets"{names}]'
    )
    roots = "".join(f'    {{ name = "{name}" }},\n' for name in direct)
    tree["uv.lock"] = tree["uv.lock"].replace(
        '    { name = "requests" },\n]\n', f'    {{ name = "requests" }},\n{roots}]\n', 1
    )
    for name in direct:
        if all(name != other for other, _ in locked):
            locked = (*locked, (name, ""))
    tree["uv.lock"] += "".join(
        f'[[package]]\nname = "{name}"\nversion = "1.0.0"\n'
        f'source = {{ registry = "https://pypi.org/simple" }}\n{body}\n'
        for name, body in locked
    )
    return tree


def js_tree_with(direct: dict[str, dict[str, Any]]) -> dict[str, str]:
    """JS_TREE plus direct dependencies, each with its lockfile entry."""
    tree = dict(JS_TREE)
    manifest = json.loads(tree["package.json"])
    lock = json.loads(tree["package-lock.json"])
    for name, entry in direct.items():
        manifest["dependencies"][name] = "1.0.0"
        lock["packages"][""]["dependencies"][name] = "1.0.0"
        lock["packages"][f"node_modules/{name}"] = {"version": "1.0.0", **entry}
    tree["package.json"] = json.dumps(manifest)
    tree["package-lock.json"] = json.dumps(lock)
    return tree


# --------------------------------------------------------------------------
# The runner
# --------------------------------------------------------------------------


class TestPython:
    def test_a_called_package_is_reachable_with_the_path_from_the_handler(
        self, tmp_path: Path
    ) -> None:
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["pyyaml"]

        assert verdict["verdict"] == "reachable"
        steps = [(s["file_path"], s["line"]) for s in verdict["path"]]
        # The Flask handler, the helper it calls, the yaml.load call.
        assert steps == [("app/web.py", 9), ("app/helpers.py", 5), ("app/helpers.py", 6)]
        assert verdict["path"][0]["label"] == "function load"

    def test_a_direct_dependency_nothing_imports_is_unreachable_with_its_evidence(
        self, tmp_path: Path
    ) -> None:
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["certifi"]

        assert verdict["verdict"] == "unreachable"
        assert verdict["path"] == []
        evidence = verdict["evidence"]
        assert evidence["files_analysed"] == 3
        assert evidence["import_count"] == 0
        assert evidence["import_names"] == ["certifi"]
        assert evidence["lockfiles"] == ["uv.lock"]
        assert evidence["dependents"] == []
        assert dataflow.unreachable_gaps(evidence) == []

    def test_imported_but_no_path_is_unknown_not_unreachable(self, tmp_path: Path) -> None:
        """`requests` is imported and only called from a function nothing calls.
        No path found is not proof: the call graph is incomplete."""
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["requests"]

        assert verdict["verdict"] == "unknown"
        assert "imported" in verdict["reason"]

    def test_a_package_whose_import_name_is_unconfirmed_is_unknown(
        self, tmp_path: Path
    ) -> None:
        """PyPI's `PyYAML` is imported as `yaml`; a distribution this module
        cannot map would be called unused by every project that uses it."""
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))[
            "acme-widgets"
        ]

        assert verdict["verdict"] == "unknown"
        assert "import name" in verdict["reason"]

    def test_a_development_dependency_is_unknown(self, tmp_path: Path) -> None:
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["pytest"]

        assert verdict["verdict"] == "unknown"

    def test_a_transitive_package_gets_no_verdict(self, tmp_path: Path) -> None:
        body = submission("python", write_tree(tmp_path, PY_TREE))

        assert "urllib3" not in by_package(body)

    def test_a_pinned_transitive_package_is_not_unreachable(self, tmp_path: Path) -> None:
        """`pip freeze` writes urllib3 into requirements.txt beside requests.
        Nothing imports it, and requests loads it."""
        write_tree(tmp_path, PY_TREE)
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nurllib3==1.26.0\n", encoding="utf-8"
        )

        verdict = by_package(submission("python", tmp_path))["urllib3"]

        assert verdict["verdict"] == "unknown"
        assert "requests" in verdict["reason"]

    def test_without_a_lockfile_nothing_is_unreachable(self, tmp_path: Path) -> None:
        body = submission("python", write_tree(tmp_path, PY_TREE, drop=("uv.lock",)))

        assert by_package(body)["certifi"]["verdict"] == "unknown"
        assert all(v["verdict"] != "unreachable" for v in body["verdicts"])

    def test_a_dynamic_import_silences_every_unreachable(self, tmp_path: Path) -> None:
        reach = with_dynamic_import(sarif("py-reach"), "python")

        body = submission("python", write_tree(tmp_path, PY_TREE), reach)

        assert by_package(body)["certifi"]["verdict"] == "unknown"
        assert body["dynamic_imports"] == 1

    def test_a_security_result_with_a_code_flow_is_reachable_at_its_location(
        self, tmp_path: Path
    ) -> None:
        body = submission("python", write_tree(tmp_path, PY_TREE))

        [location] = [v for v in body["verdicts"] if v["target"] == "location"]
        assert location["rule_id"] == "py/unsafe-deserialization"
        assert (location["file_path"], location["line"]) == ("app/helpers.py", 6)
        assert location["verdict"] == "reachable"
        assert location["path"][0]["file_path"] == "app/web.py"

    def test_the_submission_names_what_ran(self, tmp_path: Path) -> None:
        body = submission("python", write_tree(tmp_path, PY_TREE))

        assert body["language"] == "python"
        assert body["analyser"] == "codeql"
        assert body["analyser_version"] == "2.27.2"
        assert body["files_analysed"] == 3

    @pytest.mark.parametrize("server", ["gunicorn", "uvicorn", "celery", "alembic"])
    def test_a_package_run_by_name_is_never_unreachable(
        self, tmp_path: Path, server: str
    ) -> None:
        """`gunicorn app:app` runs gunicorn, and nothing in the code imports
        it. Never imported is not never executed (review of #1102)."""
        tree = write_tree(tmp_path, py_tree_with(direct=(server,)))

        verdict = by_package(submission("python", tree))[server]

        assert verdict["verdict"] == "unknown"
        assert verdict["evidence"]["loaded_without_import"] is True
        assert "without being imported" in verdict["reason"]

    def test_a_database_driver_loaded_by_url_is_never_unreachable(
        self, tmp_path: Path
    ) -> None:
        """SQLAlchemy loads psycopg2 from a `postgresql://` URL; the code
        never imports it."""
        tree = write_tree(tmp_path, py_tree_with(direct=("psycopg2-binary",)))

        verdict = by_package(submission("python", tree))["psycopg2-binary"]

        assert verdict["verdict"] == "unknown"

    def test_an_ordinary_unimported_package_still_says_so(self, tmp_path: Path) -> None:
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["certifi"]

        assert verdict["evidence"]["loaded_without_import"] is False
        assert verdict["evidence"]["scoped"] is False

    def test_a_package_another_requires_through_an_extra_is_not_unreachable(
        self, tmp_path: Path
    ) -> None:
        """`celery[redis]` plus a direct `redis`: uv.lock records the edge
        under the package's `[package.optional-dependencies]`, and that
        package loads redis at run time."""
        tree = py_tree_with(
            direct=("redis",),
            locked=(
                (
                    "kombu",
                    '[package.optional-dependencies]\nredis = [{ name = "redis" }]\n',
                ),
            ),
        )

        verdict = by_package(submission("python", write_tree(tmp_path, tree)))["redis"]

        assert verdict["verdict"] == "unknown"
        assert verdict["evidence"]["dependents"] == ["kombu"]

    def test_a_poetry_extra_is_a_dependency_edge(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "app"\n\n[tool.poetry.dependencies]\n'
            'python = "^3.11"\nredis = "*"\nkombu = "*"\n',
            encoding="utf-8",
        )
        (tmp_path / "poetry.lock").write_text(
            '[[package]]\nname = "kombu"\nversion = "5.0.0"\n\n'
            '[package.extras]\nredis = ["redis (>=4.5.2)"]\n\n'
            '[[package]]\nname = "redis"\nversion = "5.0.0"\n',
            encoding="utf-8",
        )

        graph = dataflow.pypi_graph(tmp_path)

        assert graph.dependents.get("redis") == {"kombu"}

    def test_a_scoped_analysis_proves_no_absence(self, tmp_path: Path) -> None:
        """paths_include limits what CodeQL extracts, so an import outside
        those paths is invisible (review of #1102)."""
        body = dataflow.build_submission(
            "python",
            sarif("py-reach"),
            write_tree(tmp_path, PY_TREE),
            commit_sha="abc123def456",
            scoped=True,
        )

        certifi = by_package(body)["certifi"]
        assert certifi["verdict"] == "unknown"
        assert certifi["evidence"]["scoped"] is True
        assert body["scoped"] is True

    def test_the_cli_takes_scoped(self, tmp_path: Path, capsys) -> None:
        reach = tmp_path / "reach.sarif"
        reach.write_text(json.dumps(sarif("py-reach")), encoding="utf-8")
        root = write_tree(tmp_path / "tree", PY_TREE)

        dataflow.main(
            ["--language", "python", "--sarif", str(reach), "--root", str(root), "--scoped"]
        )

        body = json.loads(capsys.readouterr().out)
        assert by_package(body)["certifi"]["verdict"] == "unknown"

    def test_a_reachable_path_says_what_kind_of_entry_it_starts_at(
        self, tmp_path: Path
    ) -> None:
        verdict = by_package(submission("python", write_tree(tmp_path, PY_TREE)))["pyyaml"]

        assert verdict["evidence"]["entry_kind"] == "function"

    @pytest.mark.parametrize(
        ("label", "kind"),
        [
            ("function load", "function"),
            ("module app.cli", "module_top_level"),
            ("top level of cli.js", "module_top_level"),
            ("", "unknown"),
        ],
    )
    def test_entry_kind_is_read_off_the_first_step(self, label: str, kind: str) -> None:
        assert dataflow.entry_kind([{"file_path": "a.py", "line": 1, "label": label}]) == kind

    def test_a_flow_result_does_not_claim_its_source_is_remote(self, tmp_path: Path) -> None:
        """Some stock path-problem queries start from a local source, so a
        code flow is a traced flow, not proof of remote reach."""
        body = submission("python", write_tree(tmp_path, PY_TREE))

        [location] = [v for v in body["verdicts"] if v["target"] == "location"]
        assert location["evidence"]["basis"] == "codeql_code_flow"
        assert location["evidence"]["source_label"] == location["path"][0]["label"]
        assert "may be local" in location["reason"]


class TestJavaScript:
    def test_a_called_package_is_reachable_across_modules(self, tmp_path: Path) -> None:
        verdict = by_package(submission("javascript", write_tree(tmp_path, JS_TREE)))["lodash"]

        assert verdict["verdict"] == "reachable"
        steps = [(s["file_path"], s["line"]) for s in verdict["path"]]
        assert steps == [("src/server.js", 4), ("src/render.js", 3), ("src/render.js", 3)]

    def test_a_direct_dependency_nothing_requires_is_unreachable(self, tmp_path: Path) -> None:
        verdict = by_package(submission("javascript", write_tree(tmp_path, JS_TREE)))[
            "left-pad"
        ]

        assert verdict["verdict"] == "unreachable"
        assert verdict["evidence"]["import_name_basis"] == "npm_package_name"
        assert verdict["evidence"]["lockfiles"] == ["package-lock.json"]

    def test_a_direct_dependency_another_package_requires_is_unknown(
        self, tmp_path: Path
    ) -> None:
        verdict = by_package(submission("javascript", write_tree(tmp_path, JS_TREE)))["qs"]

        assert verdict["verdict"] == "unknown"
        assert "express" in verdict["reason"]

    def test_imported_but_uncalled_is_unknown(self, tmp_path: Path) -> None:
        verdict = by_package(submission("javascript", write_tree(tmp_path, JS_TREE)))["moment"]

        assert verdict["verdict"] == "unknown"

    def test_a_dev_dependency_is_unknown(self, tmp_path: Path) -> None:
        verdict = by_package(submission("javascript", write_tree(tmp_path, JS_TREE)))["jest"]

        assert verdict["verdict"] == "unknown"

    def test_a_subpath_import_counts_as_importing_the_package(self) -> None:
        assert dataflow._imports_package("npm", {"lodash"}, ["lodash/merge"])
        assert not dataflow._imports_package("npm", {"lodash"}, ["lodash-es"])

    def test_the_actions_matrix_name_is_accepted(self, tmp_path: Path) -> None:
        body = dataflow.build_submission(
            "javascript-typescript", sarif("js-reach"), write_tree(tmp_path, JS_TREE)
        )

        assert body["language"] == "javascript"

    def test_a_security_result_with_a_code_flow_is_reachable(self, tmp_path: Path) -> None:
        body = submission("javascript", write_tree(tmp_path, JS_TREE))

        [location] = [v for v in body["verdicts"] if v["target"] == "location"]
        assert location["rule_id"] == "js/reflected-xss"
        assert (location["file_path"], location["line"]) == ("src/server.js", 5)

    @pytest.mark.parametrize("cli", ["pm2", "serve"])
    def test_a_cli_run_from_a_script_is_never_unreachable(
        self, tmp_path: Path, cli: str
    ) -> None:
        tree = write_tree(tmp_path, js_tree_with({cli: {}}))

        verdict = by_package(submission("javascript", tree))[cli]

        assert verdict["verdict"] == "unknown"
        assert verdict["evidence"]["loaded_without_import"] is True

    def test_a_package_with_an_executable_is_never_unreachable(self, tmp_path: Path) -> None:
        """Any locked package with a `bin` can be run from package.json's
        scripts without being imported."""
        tree = write_tree(tmp_path, js_tree_with({"acme-cli": {"bin": {"acme": "cli.js"}}}))

        verdict = by_package(submission("javascript", tree))["acme-cli"]

        assert verdict["verdict"] == "unknown"
        assert verdict["evidence"]["loaded_without_import"] is True


class TestTheQueries:
    @pytest.mark.parametrize("language", ["python", "javascript"])
    def test_every_query_is_one_the_reader_parses(self, language: str, tmp_path: Path) -> None:
        out = dataflow.write_queries(language, tmp_path / language)

        ids = set()
        for query in sorted(out.glob("*.ql")):
            match = re.search(r"@id (\S+)", query.read_text(encoding="utf-8"))
            assert match, query.name
            ids.add(match.group(1))
        assert ids == {
            f"mykronos/reachability/{language}/{kind}"
            for kind in ("package-api-reachable", "package-import", "dynamic-import",
                         "source-files")
        }
        assert (out / "qlpack.yml").is_file()

    def test_an_unsupported_language_is_refused(self) -> None:
        with pytest.raises(ValueError):
            dataflow.canonical_language("go")


class TestUnreachableNeedsEvidence:
    COMPLETE: dict[str, Any] = {
        "files_analysed": 12,
        "import_count": 0,
        "import_names": ["certifi"],
        "import_name_basis": "known_mapping",
        "dynamic_imports": 0,
        "direct_runtime_dependency": True,
        "lockfiles": ["uv.lock"],
        "dependents": [],
        "loaded_without_import": False,
        "scoped": False,
    }

    def test_complete_evidence_has_no_gaps(self) -> None:
        assert dataflow.unreachable_gaps(self.COMPLETE) == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("files_analysed", 0),
            ("import_count", 1),
            ("import_names", []),
            ("import_name_basis", None),
            ("dynamic_imports", 2),
            ("direct_runtime_dependency", False),
            ("lockfiles", []),
            ("dependents", ["requests"]),
            ("loaded_without_import", True),
            ("scoped", True),
        ],
    )
    def test_each_missing_piece_is_a_gap(self, field: str, value: Any) -> None:
        assert dataflow.unreachable_gaps({**self.COMPLETE, field: value}) != []

    @pytest.mark.parametrize("field", list(COMPLETE))
    def test_an_absent_field_is_a_gap(self, field: str) -> None:
        evidence = {k: v for k, v in self.COMPLETE.items() if k != field}

        assert dataflow.unreachable_gaps(evidence) != []

    def test_no_evidence_at_all_is_a_gap(self) -> None:
        assert dataflow.unreachable_gaps(None) != []


# --------------------------------------------------------------------------
# The platform
# --------------------------------------------------------------------------


def activate(client: TestClient, admin_auth: dict[str, str]) -> dict[str, str]:
    onboard(client, admin_auth, REPO)
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        record = session.execute(
            select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
        ).scalars().one()
        record.status = "active"
    return {"Authorization": f"Bearer {issue_token(client, REPO, 'sast', 'atlas')}"}


def post_dataflow(client: TestClient, auth: dict[str, str], body: dict[str, Any]) -> Any:
    return client.post("/api/ingest/reachability/dataflow", json=body, headers=auth)


def repo_id(client: TestClient) -> str:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        return str(
            session.execute(
                select(RepoOnboarding.id).where(RepoOnboarding.github_repo_full_name == REPO)
            ).scalar_one()
        )


def stored(client: TestClient) -> list[DataflowReachabilityReport]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        rows = list(session.execute(select(DataflowReachabilityReport)).scalars())
        for row in rows:
            session.expunge(row)
        return rows


class TestIngest:
    def test_a_submission_is_stored_per_language(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        auth = activate(client, admin_auth)
        py = submission("python", write_tree(tmp_path / "py", PY_TREE))
        js = submission("javascript", write_tree(tmp_path / "js", JS_TREE))

        first = post_dataflow(client, auth, py)
        second = post_dataflow(client, auth, js)

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        assert first.json()["unreachable"] == 1
        assert {r.language for r in stored(client)} == {"python", "javascript"}

    def test_a_second_submission_replaces_the_first(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        auth = activate(client, admin_auth)
        body = submission("python", write_tree(tmp_path, PY_TREE))
        post_dataflow(client, auth, body)

        post_dataflow(client, auth, {**body, "commit_sha": "fedcba987654"})

        [row] = stored(client)
        assert row.commit_sha == "fedcba987654"

    def test_the_path_is_recorded(self, client: TestClient, admin_auth, tmp_path: Path) -> None:
        auth = activate(client, admin_auth)
        post_dataflow(client, auth, submission("python", write_tree(tmp_path, PY_TREE)))

        [row] = stored(client)
        verdict = next(v for v in row.verdicts if v.get("package_name") == "pyyaml")
        assert [s["file_path"] for s in verdict["path"]] == [
            "app/web.py", "app/helpers.py", "app/helpers.py"
        ]

    def test_an_unreachable_without_evidence_is_stored_as_unknown(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        """A runner that claims `unreachable` and shows nothing does not get
        to have it believed: the platform downgrades it and says why."""
        auth = activate(client, admin_auth)
        body = submission("python", write_tree(tmp_path, PY_TREE))
        forged = next(v for v in body["verdicts"] if v.get("package_name") == "requests")
        forged["verdict"] = "unreachable"

        response = post_dataflow(client, auth, body)

        assert response.status_code == 200, response.text
        assert response.json()["downgraded"] == 1
        [row] = stored(client)
        kept = next(v for v in row.verdicts if v.get("package_name") == "requests")
        assert kept["verdict"] == "unknown"
        assert "falls short" in kept["reason"]

    def test_a_reachable_without_a_path_is_refused(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        auth = activate(client, admin_auth)
        body = submission("python", write_tree(tmp_path, PY_TREE))
        claimed = next(v for v in body["verdicts"] if v.get("package_name") == "pyyaml")
        claimed["path"] = []

        assert post_dataflow(client, auth, body).status_code == 422

    def test_it_needs_the_sast_capability(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        # Grants are per repository, so this one is onboarded without `sast`.
        onboard(client, admin_auth, REPO)
        other = {"Authorization": f"Bearer {issue_token(client, REPO, 'containers')}"}

        response = post_dataflow(
            client, other, submission("python", write_tree(tmp_path, PY_TREE))
        )

        assert response.status_code == 403

    def test_the_repository_view_lists_each_language(
        self, client: TestClient, admin_auth, tmp_path: Path
    ) -> None:
        auth = activate(client, admin_auth)
        post_dataflow(client, auth, submission("python", write_tree(tmp_path, PY_TREE)))

        body = client.get(f"/api/repos/{repo_id(client)}/reachability", headers=admin_auth)

        assert body.status_code == 200, body.text
        [python] = body.json()["dataflow"]
        assert python["language"] == "python"
        assert python["analyser"] == "codeql"
        assert python["reachable"] == 3
        assert python["unreachable"] == 1


class TestTheFindingRecord:
    def _sast_finding(self, client: TestClient, auth: dict[str, str], run_compaction) -> str:
        post_scan(client, auth, capability="sast", tool_name="codeql", finding_count=1)
        response = post_findings(
            client,
            auth,
            [
                {
                    "rule_id": "py/unsafe-deserialization",
                    "title": "Deserialization of user-controlled data",
                    "severity": "medium",
                    "file_path": "app/helpers.py",
                    "line_start": 6,
                    "symbol": "parse",
                    "code_snippet": "return yaml.load(text, Loader=yaml.Loader)",
                }
            ],
            capability="sast",
        )
        assert response.status_code in (200, 201), response.text
        run_compaction()
        [finding_id] = [
            str(r[0])
            for r in client.app.state.catalog.query(  # type: ignore[attr-defined]
                "SELECT finding_id FROM findings"
            )
        ]
        return finding_id

    def test_a_finding_on_a_traced_flow_shows_its_path(
        self, client: TestClient, admin_auth, run_compaction, tmp_path: Path
    ) -> None:
        auth = activate(client, admin_auth)
        finding_id = self._sast_finding(client, auth, run_compaction)
        post_dataflow(client, auth, submission("python", write_tree(tmp_path, PY_TREE)))

        body = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()

        reach = body["reachability"]
        assert reach["verdict"] == "reachable"
        assert reach["language"] == "python"
        assert reach["commit_sha"] == "abc123def456"
        assert reach["path"][0]["file_path"] == "app/web.py"
        assert "reachability" not in {gap["input"] for gap in body["missing_context"]}

    def test_without_an_analysis_it_says_so(
        self, client: TestClient, admin_auth, run_compaction
    ) -> None:
        auth = activate(client, admin_auth)
        finding_id = self._sast_finding(client, auth, run_compaction)

        body = client.get(
            f"/api/dashboard/findings/{finding_id}/record", headers=admin_auth
        ).json()

        assert body["reachability"] is None
        assert "reachability" in {gap["input"] for gap in body["missing_context"]}


# --------------------------------------------------------------------------
# The workflow
# --------------------------------------------------------------------------


def render_sast(config: dict[str, Any] | None = None) -> str:
    import yaml

    from mykronos.config import get_settings
    from mykronos.installer import TemplateLibrary

    library = TemplateLibrary(get_settings().workflow_templates_dir)
    content = library.render(
        "sast",
        repo_full_name="example-org/repo",
        default_branch="main",
        ingestion_api_url="https://example.invalid",
        token_secret_name="MYKRONOS_INGESTION_TOKEN",
        upload_action_ref="example-org/repo/actions/upload-results@v1",
        mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
        config=config or {},
    ).content
    yaml.safe_load(content)  # it must still be a workflow
    return content


class TestTheWorkflow:
    def _step(self, rendered: str) -> str:
        assert "- name: Dataflow reachability" in rendered
        step = rendered.split("- name: Dataflow reachability", 1)[1]
        return step.split("\n      - name:", 1)[0]

    def test_it_runs_the_pack_against_the_database_codeql_already_built(self) -> None:
        step = self._step(render_sast())

        assert "steps.init.outputs.codeql-path" in step
        assert "python -m mykronos.reachability_dataflow" in step
        assert "--write-queries" in step
        assert "database analyze" in step
        assert "--sarif" in step and "--analysis-sarif-dir" in step
        assert "/api/ingest/reachability/dataflow" in step

    def test_it_never_fails_the_scan(self) -> None:
        step = self._step(render_sast())

        assert "continue-on-error: true" in step

    def test_only_python_and_javascript_run_it(self) -> None:
        step = self._step(render_sast())

        assert "matrix.language == 'python'" in step
        assert "matrix.language == 'javascript-typescript'" in step

    def test_the_init_step_has_the_id_the_step_reads(self) -> None:
        rendered = render_sast()

        init = rendered.split("- name: Initialize CodeQL", 1)[1].split("\n      - name:", 1)[0]
        assert "\n        id: init\n" in init

    def test_it_can_be_turned_off(self) -> None:
        assert "Dataflow reachability" not in render_sast({"dataflow_reachability": False})

    def test_it_reports_only_from_the_default_branch(self) -> None:
        """The report is one row per (repo, language) with no ref, so a pull
        request's tree would overwrite the default branch's verdicts and T8
        would act on a branch (review of #1102)."""
        step = self._step(render_sast())

        condition = next(line for line in step.splitlines() if line.strip().startswith("if:"))
        assert "github.event_name != 'pull_request'" in condition
        assert "github.ref == 'refs/heads/main'" in condition

    @pytest.mark.parametrize(
        "config",
        [{"paths_include": ["src"]}, {"paths_exclude": ["legacy"]}],
    )
    def test_a_path_scoped_analysis_is_submitted_as_scoped(
        self, config: dict[str, Any]
    ) -> None:
        step = self._step(render_sast(config))

        assert "--scoped" in step

    def test_an_unscoped_analysis_is_not(self) -> None:
        assert "--scoped" not in self._step(render_sast())

    def test_the_step_has_its_own_time_limit(self) -> None:
        """A dataflow pass over a large database must not run the job into its
        own limit after the findings were uploaded."""
        step = self._step(render_sast())

        match = re.search(r"\n        timeout-minutes: (\d+)\r?\n", step)
        assert match and 0 < int(match.group(1)) < 30
