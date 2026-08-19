"""Import reachability — spec 19 §2.1.

Spec 17 §5.3 built the plumbing for this Oracle category, declined to build a
call-graph engine, and left it permanently `available: false`. Declining was
right. What it also left unbuilt was the honest floor underneath: for Python
only, does anything in this repository import this file.

The category is a *discount*, which makes the direction of a wrong answer the
thing to test. A file wrongly called orphaned quietly lowers the score on a
real finding. So almost everything here is about the analysis refusing to
claim a file is dead — unparseable, an entry point, a `python -m` module, a
relative import it had to resolve.
"""

from __future__ import annotations

import pytest

from mykronos import reachability
from mykronos.oracle.policy import load_policy


class TestTheImportGraph:
    def test_an_imported_module_is_not_orphaned(self) -> None:
        files = {
            "pkg/__init__.py": "",
            "pkg/helper.py": "def go(): pass",
            "pkg/service.py": "from pkg.helper import go",
        }

        assert "pkg/helper.py" not in reachability.orphaned(files)

    def test_a_module_nothing_imports_is(self) -> None:
        files = {
            "pkg/__init__.py": "",
            "pkg/lonely.py": "def go(): pass",
            "pkg/service.py": "x = 1",
        }

        assert "pkg/lonely.py" in reachability.orphaned(files)

    def test_a_relative_import_counts(self) -> None:
        """Most intra-package edges are written this way. Dropping them would
        report half of every package as dead code."""
        files = {
            "pkg/__init__.py": "",
            "pkg/helper.py": "def go(): pass",
            "pkg/service.py": "from .helper import go",
        }

        assert "pkg/helper.py" not in reachability.orphaned(files)

    def test_a_src_layout_still_resolves(self) -> None:
        """The file is `src/pkg/thing.py` and the import says `pkg.thing`.
        Matching only the full dotted path would orphan every module in every
        src-layout project."""
        files = {
            "src/pkg/__init__.py": "",
            "src/pkg/helper.py": "def go(): pass",
            "src/pkg/service.py": "import pkg.helper",
        }

        assert "src/pkg/helper.py" not in reachability.orphaned(files)

    def test_a_third_party_import_is_not_an_edge(self) -> None:
        """The question is internal reachability. An import of `requests`
        tells you nothing about which of your own files are live."""
        graph = reachability.build_graph({"a.py": "import requests"})

        assert graph.edges["a"] == set()


class TestItRefusesToGuess:
    def test_an_unparseable_file_is_never_orphaned(self) -> None:
        """Its own imports are unknown, so everything it might have imported
        is unproven too. Reporting a subtree as dead because one file has a
        syntax error is the confident-wrong answer this exists to avoid."""
        files = {"broken.py": "def (", "other.py": "x = 1"}

        assert "broken.py" not in reachability.orphaned(files)

    def test_an_unparseable_file_does_not_orphan_what_it_imports(self) -> None:
        files = {
            "broken.py": "import helper\ndef (",
            "helper.py": "def go(): pass",
        }

        # `helper` may well be imported only from the broken file. The
        # analysis cannot tell, so it must not claim it is dead.
        assert reachability.orphaned(files) == []

    @pytest.mark.parametrize(
        "path", ["main.py", "manage.py", "wsgi.py", "conftest.py", "scripts/seed.py"]
    )
    def test_entry_points_are_never_orphaned(self, path: str) -> None:
        """Being un-imported is their whole job."""
        assert reachability.orphaned({path: "x = 1", "other.py": "y = 2"}) == [
            "other.py"
        ]

    def test_a_module_with_a_main_guard_is_an_entry_point(self) -> None:
        """Detected from the AST, not from a glob. The first run of this over
        Mykronos itself reported `cli.py` and the analysis module as orphaned
        — true of their imports, false about their purpose — and a glob list
        would have needed a new entry for every such file forever."""
        files = {"tool.py": 'if __name__ == "__main__":\n    print(1)\n'}

        assert reachability.orphaned(files) == []

    def test_a_nested_main_guard_does_not_count(self) -> None:
        """Top level only. Walking the whole tree would let a string
        comparison buried in unrelated code exempt a file."""
        files = {
            "tool.py": 'def f():\n    if __name__ == "__main__":\n        pass\n',
        }

        assert reachability.orphaned(files) == ["tool.py"]

    def test_tests_are_not_orphaned(self) -> None:
        """Nothing imports a test module and nothing should. Reporting the
        whole test suite as dead code would make the signal useless on the
        first repository it ran against."""
        assert reachability.orphaned({"tests/test_thing.py": "x = 1"}) == []


class TestAgainstThisRepository:
    def test_mykronos_has_no_orphaned_modules(self) -> None:
        """A real corpus rather than a fixture, and a live regression test: a
        module added here with nothing importing it is either dead code or a
        gap in this analysis, and both are worth a failing test."""
        from pathlib import Path

        # The backend root, not the package directory: module names are
        # derived from the path, so an import of "mykronos.atlas" only
        # resolves when the walk starts one level above the package.
        root = Path(__file__).resolve().parent.parent
        files = reachability.read_repository(str(root))

        assert len(files) > 20
        assert reachability.orphaned(files) == []


class TestTheOracleCategory:
    def test_no_analysis_is_unavailable(self) -> None:
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)
        snapshot, terms = reachability_snapshot(None, 0, policy)

        assert snapshot["available"] is False
        assert terms == []

    def test_an_analysis_with_nothing_orphaned_is_available(self) -> None:
        """A different statement from "not computed", and it should read
        differently: we looked, and every file is imported from somewhere."""
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)
        snapshot, terms = reachability_snapshot(
            {"orphaned_paths": [], "files_analysed": 40}, 0, policy
        )

        assert snapshot["available"] is True
        assert snapshot["contribution"] == 0.0
        assert terms == []

    def test_findings_in_dead_files_are_discounted(self) -> None:
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)
        _, terms = reachability_snapshot(
            {"orphaned_paths": ["pkg/dead.py"], "files_analysed": 40}, 2, policy
        )

        assert len(terms) == 1
        assert terms[0].contribution < 0

    def test_the_discount_is_capped(self) -> None:
        """The analysis is Python-only and answers "does anything import
        this", not "does this run". A discount big enough to move a verdict
        would be trusting it further than it can see."""
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)
        _, terms = reachability_snapshot(
            {"orphaned_paths": ["a.py"], "files_analysed": 10}, 500, policy
        )

        assert abs(terms[0].contribution) == policy.reachability.discount_cap

    def test_the_cap_cannot_clear_a_threshold_gap(self) -> None:
        from mykronos.config import get_settings

        policy = load_policy(get_settings().oracle_policy_path)

        assert policy.reachability.discount_cap < policy.no_go - policy.review_recommended

    def test_a_policy_without_the_block_still_loads(self, tmp_path) -> None:
        import yaml

        from mykronos.config import get_settings

        document = yaml.safe_load(
            get_settings().oracle_policy_path.read_text(encoding="utf-8")
        )
        del document["modifiers"]["reachability"]
        path = tmp_path / "old-policy.yaml"
        path.write_text(yaml.safe_dump(document), encoding="utf-8")

        assert load_policy(path).reachability.orphaned_discount_per_finding == 0


def reachability_snapshot(report, orphaned_findings, policy):
    from mykronos.oracle.engine import _reachability_snapshot

    return _reachability_snapshot(report, orphaned_findings, policy)


class TestIngestion:
    def post(self, client, body, capability="sast"):
        from tests.conftest import REPO, issue_token

        auth = {"Authorization": f"Bearer {issue_token(client, REPO, capability)}"}
        return client.post("/api/ingest/reachability", json=body, headers=auth)

    def test_it_records_a_report(self, client, admin_auth) -> None:
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)

        response = self.post(
            client,
            {
                "language": "python",
                "commit_sha": "abc123",
                "orphaned_paths": ["pkg/dead.py"],
                "files_analysed": 40,
                "files_unparseable": 1,
            },
        )

        assert response.status_code == 200
        assert response.json()["orphaned"] == 1

    def test_a_second_post_replaces_the_first(self, client, admin_auth) -> None:
        """Current state, not history. The previous analysis is superseded
        outright and nothing reads the old one."""
        from mykronos.db.models import ReachabilityReport
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)
        self.post(client, {"orphaned_paths": ["a.py"], "files_analysed": 10})
        self.post(client, {"orphaned_paths": [], "files_analysed": 12})

        with client.app.state.db.session() as session:
            rows = session.query(ReachabilityReport).all()
            assert len(rows) == 1
            assert rows[0].orphaned_paths == []

    def test_an_empty_list_is_a_real_answer(self, client, admin_auth) -> None:
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)

        response = self.post(client, {"orphaned_paths": [], "files_analysed": 40})

        assert response.status_code == 200
        assert response.json()["files_analysed"] == 40

    def test_the_note_says_what_this_is_not(self, client, admin_auth) -> None:
        """The one misreading that matters: a file not listed is not proven
        reachable, only not proven dead."""
        from tests.test_onboarding import onboard

        onboard(client, admin_auth)

        body = self.post(client, {"orphaned_paths": [], "files_analysed": 1}).json()

        assert "not whether a function is called" in body["note"]

    def test_a_token_for_another_capability_is_refused(
        self, client, admin_auth
    ) -> None:
        from tests.test_onboarding import onboard

        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["atlas"], "install_workflows": False},
            headers=admin_auth,
        )

        response = self.post(client, {"orphaned_paths": []}, capability="atlas")

        assert response.status_code == 403
