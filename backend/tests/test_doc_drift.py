"""The sprint-end doc drift check (TheHub #61166).

`scripts/doc_drift.py` reads a repository's README and its `docs/` tree and
checks every claim a machine can check against the tree it runs in: each
relative link and each backticked repository path must name a file or folder
that exists. The Docs agent runs it against a fresh clone of each repository's
main branch at every sprint end, and the counts go into the retro's Docs drift
section. Records (decisions, retros, lessons, dated reports) describe the past,
so their paths are not drift and they are counted as skipped.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import doc_drift as d  # noqa: E402


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


class TestWhichDocuments:
    def test_readme_and_docs_tree_are_living_docs(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {
                "README.md": "x",
                "docs/GUIDE.md": "x",
                "docs/runbooks/vault.md": "x",
                "backend/README.md": "x",
                "src/notes.md": "x",
            },
        )
        living, records = d.documents(root)
        names = [p.relative_to(root).as_posix() for p in living]
        assert names == ["README.md", "backend/README.md", "docs/GUIDE.md", "docs/runbooks/vault.md"]
        assert records == []

    def test_records_are_skipped_not_checked(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {
                "docs/decisions/D-001-x.md": "`gone/file.py`",
                "docs/retros/2026-09-03.md": "x",
                "docs/lessons/a.md": "x",
                "docs/adr/0001-x.md": "x",
                "docs/reports/weekly.md": "x",
                "docs/audit-2026-04-24.md": "x",
                "docs/GUIDE.md": "x",
            },
        )
        living, records = d.documents(root)
        assert [p.name for p in living] == ["GUIDE.md"]
        assert len(records) == 6


class TestClaims:
    def test_a_relative_link_to_a_missing_file_is_drift(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {
                "README.md": "See [the guide](docs/GUIDE.md) and [setup](docs/SETUP.md#top).",
                "docs/GUIDE.md": "x",
            },
        )
        report = d.check(root)
        assert report.claims_checked == 2
        assert [(x.document, x.claim) for x in report.drift] == [("README.md", "docs/SETUP.md")]
        assert report.drift[0].kind == "link"

    def test_links_resolve_from_the_documents_own_folder(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {"docs/runbooks/a.md": "[b](../GUIDE.md) [c](./b.md)", "docs/GUIDE.md": "x", "docs/runbooks/b.md": "x"},
        )
        assert d.check(root).drift == []

    def test_external_links_and_anchors_are_not_claims_about_the_tree(self, tmp_path: Path) -> None:
        root = _repo(tmp_path, {"README.md": "[a](https://example.com/x.md) [b](#status) [c](mailto:a@b)"})
        report = d.check(root)
        assert report.claims_checked == 0

    def test_a_backticked_repo_path_must_exist(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {
                "README.md": "Run `scripts/check.py`, then `scripts/gone.py --fix`. Edit `backend/app/`.",
                "scripts/check.py": "",
                "backend/app/__init__.py": "",
            },
        )
        report = d.check(root)
        assert report.claims_checked == 3
        assert [(x.claim, x.kind) for x in report.drift] == [("scripts/gone.py", "path")]

    def test_backticks_that_are_not_repo_paths_are_ignored(self, tmp_path: Path) -> None:
        # Only a path whose first segment is a top-level entry of the repo is
        # a claim about the tree; a URL path, a glob or a container path is not.
        root = _repo(
            tmp_path,
            {
                "README.md": "`GET /api/x` `/etc/passwd` `docs/*.md` `nothere/x.py` `<repo>/x` `docs/{a,b}.md`",
                "docs/a.md": "x",
            },
        )
        assert d.check(root).claims_checked == 0

    def test_a_numbered_prefix_names_the_numbered_document(self, tmp_path: Path) -> None:
        # keel's docs say "`docs/09`" for docs/09-retrospective-and-improvement.md.
        root = _repo(tmp_path, {"README.md": "`docs/09` and `docs/12`", "docs/09-retro.md": "x"})
        assert [x.claim for x in d.check(root).drift] == ["docs/12"]

    def test_an_action_ref_is_not_a_path(self, tmp_path: Path) -> None:
        root = _repo(tmp_path, {"README.md": "`actions/checkout@v4`", "actions/a.yml": ""})
        assert d.check(root).claims_checked == 0

    def test_a_gitignored_runtime_file_is_not_drift(self, tmp_path: Path) -> None:
        # `backend/.env` is named by every operator doc and is never committed.
        root = _repo(
            tmp_path,
            {".gitignore": ".env\n*.jsonl\n", "README.md": "Set it in `backend/.env` and `deploy/log.jsonl`.",
             "backend/app.py": "", "deploy/x": ""},
        )
        assert d.check(root).drift == []

    def test_backlog_decision_log_and_changelog_are_records(self, tmp_path: Path) -> None:
        root = _repo(
            tmp_path,
            {"docs/BACKLOG.md": "x", "docs/DECISIONS.md": "x", "CHANGELOG.md": "x", "docs/GUIDE.md": "x"},
        )
        living, records = d.documents(root)
        assert [p.name for p in living] == ["GUIDE.md"]
        assert sorted(p.name for p in records) == ["BACKLOG.md", "DECISIONS.md"]

    def test_the_line_number_is_reported(self, tmp_path: Path) -> None:
        root = _repo(tmp_path, {"README.md": "one\ntwo\n[x](missing.md)\n", "docs/a.md": "x"})
        (item,) = d.check(root).drift
        assert item.line == 3

    def test_fenced_code_is_still_checked_for_paths(self, tmp_path: Path) -> None:
        root = _repo(tmp_path, {"README.md": "```\npython `scripts/gone.py`\n```\n", "scripts/a.py": ""})
        assert [x.claim for x in d.check(root).drift] == ["scripts/gone.py"]


class TestOutput:
    def test_json_summary_carries_the_retro_counts(self, tmp_path: Path, capsys) -> None:
        root = _repo(
            tmp_path,
            {"README.md": "[ok](docs/a.md) [bad](docs/b.md)", "docs/a.md": "x", "docs/decisions/D-1.md": "x"},
        )
        code = d.main([str(root), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert code == 1, "drift exits 1, so a scheduled run can tell"
        assert out["documents_checked"] == 2
        assert out["records_skipped"] == 1
        assert out["claims_checked"] == 2
        assert out["drifted"] == 1
        assert out["drift"][0] == {"document": "README.md", "line": 1, "kind": "link", "claim": "docs/b.md"}

    def test_a_clean_tree_exits_zero(self, tmp_path: Path, capsys) -> None:
        root = _repo(tmp_path, {"README.md": "[ok](docs/a.md)", "docs/a.md": "x"})
        assert d.main([str(root)]) == 0
        assert "0 drifted" in capsys.readouterr().out
