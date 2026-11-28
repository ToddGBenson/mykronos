"""`pr-gates` judges a pull request with the BASE branch's gate scripts (TheHub #61113).

The independent review of TheHub #559 found that `pr-gates` ran the pull
request head's own scripts/pr_deploy_gates.sh, which runs that head's
harden_findings_report.py and pipeline-shape tests. Anyone who could push a
TheHub branch could edit them to exit 0 and turn `Concourse / thehub` green on
their own pull request.

Now `pick` (which holds the deploy key and runs nothing from the branch)
extracts the base commit's whole tree, and `gates` lays only the pull
request's DATA over it, backend/requirements.txt and the pipeline mirror, and
runs develop's script there. pip-audit is asked to run as an unprivileged uid
(`--audit-as`), because resolving the pull request's requirements runs sdist
build code, and the task keeps no pip cache between runs.

The pick's input block and the gates task's script are EXECUTED as they stand
in the pipeline, against real git repositories built here (the harness of
test_thehub_pr_process_gates.py), not grepped.
"""

from __future__ import annotations

import json
import sys
import textwrap

import pytest

from tests.pipeline_steps import find
from tests.test_thehub_pr_process_gates import _develop, _inputs_block, _job, _judge, _script

# A stand-in for develop's scripts/pr_deploy_gates.sh: it says whose it is,
# shows what it was given to judge, and fails on a "fixable" requirement the
# way the real pip-audit gate does.
DEVELOP_GATES = textwrap.dedent("""\
    #!/usr/bin/env bash
    # develop's gates; understands --mykronos, --only and --audit-as
    cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
    echo "JUDGE=develop ARGS=$*"
    echo "REQS=$(cat backend/requirements.txt 2>/dev/null)"
    echo "MIRROR=$(cat concourse/pipelines/thehub.yml 2>/dev/null)"
    echo "PARSER=$(cat scripts/harden_findings_report.py)"
    echo "SHAPE=$(cat backend/tests/unit/scripts/test_export_concourse_pipeline.py)"
    echo "LOCK=$(cat scripts/pr_deploy_gates.requirements.txt)"
    if grep -q 'pypdf==6.21.2' backend/requirements.txt 2>/dev/null; then
      echo "pip-audit: 1 dep(s) with a published fix."
      exit 1
    fi
    exit 0
""")

DEVELOP_FILES = {
    "scripts/pr_deploy_gates.sh": DEVELOP_GATES,
    "scripts/harden_findings_report.py": "develop-parser\n",
    "backend/tests/unit/scripts/test_export_concourse_pipeline.py": "develop-shape-tests\n",
    "scripts/pr_deploy_gates.requirements.txt": "develop-lock\n",
    "backend/requirements.txt": "requests==2.33.0\n",
    "concourse/pipelines/thehub.yml": "jobs: [develop-mirror]\n",
}

NEUTERED = "#!/usr/bin/env bash\necho 'JUDGE=branch'\nexit 0\n"


def _setup(tmp_path, **extra):
    repo, base = _develop(tmp_path, **{**DEVELOP_FILES, **extra})
    repo.branch("feat/x", base)
    return repo, base


# -- AC1: develop's copies judge -----------------------------------------------

def test_a_pr_that_neuters_the_deploy_gates_script_is_judged_by_develops(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("chore: bump pypdf, and make the check green", {
        "backend/requirements.txt": "pypdf==6.21.2\n",
        "scripts/pr_deploy_gates.sh": NEUTERED,
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "JUDGE=develop" in log, log
    assert "JUDGE=branch" not in log, log


def test_a_pr_that_deletes_the_deploy_gates_script_is_still_judged(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("chore: drop the check", {
        "backend/requirements.txt": "pypdf==6.21.2\n",
        "scripts/pr_deploy_gates.sh": None,
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "JUDGE=develop" in log, log


def test_the_parser_shape_tests_and_tool_lock_are_develops(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("chore: edit the judges", {
        "scripts/harden_findings_report.py": "branch-parser\n",
        "backend/tests/unit/scripts/test_export_concourse_pipeline.py": "branch-shape-tests\n",
        "scripts/pr_deploy_gates.requirements.txt": "branch-lock\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "PARSER=develop-parser" in log and "branch-parser" not in log, log
    assert "SHAPE=develop-shape-tests" in log and "branch-shape-tests" not in log, log
    assert "LOCK=develop-lock" in log and "branch-lock" not in log, log


def test_the_prs_requirements_and_mirror_are_what_is_judged(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("feat: a dependency and a re-exported mirror", {
        "backend/requirements.txt": "requests==2.33.0\nhttpx==0.28.1\n",
        "concourse/pipelines/thehub.yml": "jobs: [branch-mirror]\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "httpx==0.28.1" in log, log
    assert "MIRROR=jobs: [branch-mirror]" in log, log


def test_pip_audit_is_asked_to_run_as_an_unprivileged_uid(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("docs", {"docs/a.md": "a\n"})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "--audit-as 65534" in log, log
    assert "--mykronos" in log, log


def test_a_develop_whose_script_cannot_drop_privileges_fails_closed(tmp_path) -> None:
    """Until TheHub's half of #61113 is on develop, the check says why it is
    red rather than running pip-audit with the judge's privileges."""
    old = "#!/usr/bin/env bash\necho 'JUDGE=develop'\nexit 0\n"
    repo, base = _setup(tmp_path, **{"scripts/pr_deploy_gates.sh": old})
    head = repo.commit("docs", {"docs/a.md": "a\n"})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "--audit-as" in log and "#61113" in log, log


@pytest.mark.skipif(sys.platform == "win32", reason="git checks symlinks out as files on Windows")
def test_a_symlinked_requirements_file_is_refused(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    repo.git("rm", "-q", "backend/requirements.txt")
    (repo.dir / "backend" / "requirements.txt").symlink_to("/etc/hostname")
    repo.git("add", "backend/requirements.txt")
    repo.git("commit", "-q", "-m", "chore: link")
    head = repo.git("rev-parse", "HEAD")
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "not a regular file" in log, log


# -- AC2: no pip cache shared between runs ------------------------------------

def test_the_gates_task_keeps_no_pip_cache_between_runs() -> None:
    gates = find(_job()["plan"], "gates")
    assert "PIP_CACHE_DIR" not in json.dumps(gates.get("params") or {})
    assert not gates["config"].get("caches"), gates["config"].get("caches")


# -- wiring --------------------------------------------------------------------

def test_the_judge_tree_is_the_base_commit_extracted_by_the_pick() -> None:
    assert 'git -C pr archive "$BASE_SHA"' in _inputs_block()
    gates = _script("gates")
    assert "bash pr/scripts/pr_deploy_gates.sh" not in gates
    assert '"$JUDGE/scripts/pr_deploy_gates.sh"' in gates


# -- the committed SBOM, judged in `gates` (TheHub #62416) ---------------------
#
# From #61636 to #62416 the committed-SBOM test ran in pr-gates' integration
# task, from the branch's own checkout. That task left the pull request with
# the integration tier (dev process v2 step 4); the check stays on the pull
# request, in `gates`: DEVELOP's copy of the test, over the branch's
# requirements.txt and SBOM laid on the judge tree.

SBOM_TEST = "backend/tests/unit/scripts/test_the_committed_sbom_satisfies_requirements.py"
SBOM = "docs/sbom/latest-python.cdx.json"
# A stand-in for develop's test: every requirement line must be in the SBOM.
DEVELOP_SBOM_TEST = textwrap.dedent("""\
    from pathlib import Path


    def test_every_requirement_is_in_the_sbom():
        root = Path(__file__).resolve().parents[4]
        sbom = (root / "docs" / "sbom" / "latest-python.cdx.json").read_text()
        for line in (root / "backend" / "requirements.txt").read_text().splitlines():
            assert line in sbom, "develop's SBOM test: not in the SBOM: " + line
""")
SBOM_FILES = {SBOM_TEST: DEVELOP_SBOM_TEST, SBOM: '{"c": ["requests==2.33.0"]}\n'}
WITH_HTTPX = "requests==2.33.0\nhttpx==0.28.1\n"
SBOM_RAN = "== the committed SBOM against this pull request's requirements.txt =="


def test_a_requirements_change_with_a_stale_sbom_is_refused(tmp_path) -> None:
    """#692's shape: a new requirement and no regenerated SBOM."""
    repo, base = _setup(tmp_path, **SBOM_FILES)
    head = repo.commit("feat: httpx", {"backend/requirements.txt": WITH_HTTPX})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert SBOM_RAN in log, log
    assert "develop's SBOM test: not in the SBOM: httpx==0.28.1" in log, log
    assert "regenerate the SBOM in the same pull request" in log, log


def test_a_requirements_change_with_its_sbom_passes(tmp_path) -> None:
    repo, base = _setup(tmp_path, **SBOM_FILES)
    head = repo.commit("feat: httpx, and its SBOM", {
        "backend/requirements.txt": WITH_HTTPX,
        SBOM: '{"c": ["requests==2.33.0", "httpx==0.28.1"]}\n',
    })
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert SBOM_RAN in log and "1 passed" in log, log


def test_an_sbom_only_change_is_checked_too(tmp_path) -> None:
    repo, base = _setup(tmp_path, **SBOM_FILES)
    head = repo.commit("chore: hand-edit the SBOM", {SBOM: '{"c": []}\n'})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "not in the SBOM: requests==2.33.0" in log, log


def test_the_branch_cannot_edit_the_sbom_test_to_pass(tmp_path) -> None:
    repo, base = _setup(tmp_path, **SBOM_FILES)
    head = repo.commit("feat: httpx, and a test that passes", {
        "backend/requirements.txt": WITH_HTTPX,
        SBOM_TEST: "def test_ok():\n    pass\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "develop's SBOM test" in log, log


def test_a_pull_request_that_changes_neither_runs_no_sbom_test(tmp_path) -> None:
    repo, base = _setup(tmp_path, **SBOM_FILES)
    head = repo.commit("docs", {"docs/a.md": "a\n"})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert SBOM_RAN not in log, log


def test_a_base_without_the_sbom_test_says_so(tmp_path) -> None:
    repo, base = _setup(tmp_path)
    head = repo.commit("feat: httpx", {"backend/requirements.txt": WITH_HTTPX})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "::warning::the base branch has no " + SBOM_TEST in log, log


@pytest.mark.skipif(sys.platform == "win32", reason="git checks symlinks out as files on Windows")
def test_a_symlinked_sbom_is_refused(tmp_path) -> None:
    repo, base = _setup(tmp_path, **SBOM_FILES)
    repo.git("rm", "-q", SBOM)
    (repo.dir / SBOM).symlink_to("/etc/hostname")
    repo.git("add", SBOM)
    repo.git("commit", "-q", "-m", "chore: link")
    head = repo.git("rev-parse", "HEAD")
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "not a regular file" in log, log
