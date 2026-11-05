"""`pr-gates` runs deploy.sh's process gates on every TheHub pull request (TheHub #61159).

TheHub #531 merged green with two new backend/services modules tested in one
combined file. deploy.sh's DEV-D ("Step 2.5: Process gates") wants a
test_<name>.py for each new .py under backend/services or backend/api, so the
first place that failed was production deploy 6710, after the merge. #547 split
the tests and needed another CI round and another deploy window.

DEV-B (a Threat-Model-MD: or Bypass-Process-Gate: trailer on a diff touching a
sensitive path) and DEV-D now run in `pr-gates` against the pull request's own
range, merge-base..head, graded the way a squash merge lands: the combined diff
against the bodies of every branch commit, which is the squash commit deploy.sh
grades.

The gate logic is never the pull request's own. DEV-B is develop's
scripts/lib/devb_gate.py, read out of the BASE commit's tree by the `pick` task
(which holds the only credential, and runs nothing from the branch). DEV-D is
this pipeline's port of deploy.sh's inline block, and develop's deploy.sh is
checked for the lines it ports, so a change there turns the check red instead
of letting the two drift.

The pick's input block and the gates task's script are EXECUTED as they stand
in the pipeline, against real git repositories built here, not grepped.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "pr-gates"

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and shutil.which("bash")), reason="git and bash are required"
)


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _script(task: str) -> str:
    step = next(s for s in _job()["plan"] if s.get("task") == task)
    return step["config"]["run"]["args"][-1]


def _inputs_block() -> str:
    """The lines of `pick` that turn a fetched head into the gates' inputs."""
    body = re.search(
        r"\n([ \t]*# -- process-gate inputs, begin\n.*?# -- process-gate inputs, end)\n",
        _script("pick"), re.S)
    assert body, "the pick's process-gate input block moved"
    return textwrap.dedent(body.group(1))


# -- the fixture: a TheHub-shaped repository ----------------------------------

# A stand-in for develop's scripts/lib/devb_gate.py, speaking its stdin
# protocol: paths on stdin, the message in DEVB_COMMIT_MESSAGE, exit 1 on a
# sensitive path with neither trailer.
BASE_DEVB_GATE = textwrap.dedent('''\
    import os, re, sys
    files = [ln.strip() for ln in sys.stdin.read().splitlines()]
    message = os.environ.get("DEVB_COMMIT_MESSAGE", "")
    sensitive = [f for f in files if re.match(
        r"^(backend/main\\.py$|backend/models/.+\\.py$|scripts/deploy\\.sh$)", f)]
    if not sensitive:
        sys.exit(0)
    if re.search(r"^Threat-Model-MD:", message, re.M):
        print("DEV-B: sensitive files touched + Threat-Model-MD: trailer present")
        sys.exit(0)
    if re.search(r"^Bypass-Process-Gate:", message, re.M):
        print("DEV-B: sensitive files touched WITHOUT threat-model -- bypassed")
        sys.exit(0)
    print("DEV-B (#4944): sensitive files staged with no Threat-Model-MD: trailer.")
    for f in sensitive:
        print("  " + f)
    sys.exit(1)
''')

# The lines of deploy.sh's Step 2.5 that the pipeline's DEV-D ports, verbatim.
BASE_DEPLOY_SH = textwrap.dedent('''\
    #!/usr/bin/env bash
    # Step 2.5: Process gates (DEV-B + DEV-D)
    {
      COMMIT_BODY=$(git log -1 --format=%B 2>/dev/null || echo "")
      if echo "$COMMIT_BODY" | grep -qE "^Bypass-Process-Gate:"; then
        HAS_BYPASS=true
      fi
      DEVB_POST_OUT=$(echo "$CHANGED_FILES" \\
        | DEVB_COMMIT_MESSAGE="$COMMIT_BODY" DEVB_TELEMETRY_FILE="$DEVB_POST_TELEMETRY" \\
          python3 scripts/lib/devb_gate.py) || {
        fail "DEV-B"
      }
      @NEW_PY@
      while IFS= read -r f; do
        base=$(basename "$f" .py)
        @TEST_LINE@
          MISSING="${MISSING}\\n  ${f}"
        fi
      done <<< "$NEW_PY"
    }
''').replace(
    "@NEW_PY@",
    "NEW_PY=$(git diff --name-only --diff-filter=A HEAD~1 HEAD 2>/dev/null"
    " | grep -E '^backend/(services|api)/.+\\.py$' || true)",
).replace(
    "@TEST_LINE@",
    'if ! echo "$CHANGED_FILES" | grep -qE'
    ' "tests/.+/test_${base}\\.py$|tests/test_${base}\\.py$"; then',
)


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.dir = root / "pr"
        self.dir.mkdir(parents=True)
        self.git("init", "-q", "-b", "develop")
        self.git("config", "user.email", "builder@example.test")
        self.git("config", "user.name", "builder")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args: str) -> str:
        r = subprocess.run(["git", "-C", str(self.dir), *args], capture_output=True,
                           text=True, check=True)
        return r.stdout.strip()

    def commit(self, message: str, files: dict[str, str | None]) -> str:
        for path, content in files.items():
            target = self.dir / path
            if content is None:
                self.git("rm", "-q", path)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
            self.git("add", path)
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def branch(self, name: str, at: str) -> None:
        self.git("checkout", "-q", "-b", name, at)


def _develop(tmp_path: Path, **extra: str | None) -> tuple[Repo, str]:
    repo = Repo(tmp_path)
    files: dict[str, str | None] = {
        "scripts/lib/devb_gate.py": BASE_DEVB_GATE,
        "scripts/deploy.sh": BASE_DEPLOY_SH,
        # A stand-in for the pip-audit and shape gates, which this file does not judge.
        # [TheHub #61113] It takes --audit-as, as develop's has since then.
        "scripts/pr_deploy_gates.sh": "#!/usr/bin/env bash\n# --audit-as\necho 'deploy gates: ok'\n",
        "backend/main.py": "app = None\n",
        "backend/api/notifications.py": "ROUTES = []\n",
        "backend/api/binnacle.py": "ROUTES = []\n",
        "backend/tests/unit/test_approval_spine.py": "def test_old(): pass\n",
    }
    files.update(extra)
    base = repo.commit("develop", files)
    return repo, base


def _python3_shim(tmp_path: Path) -> str:
    """The task image's `python3`, as this interpreter, ahead of anything else."""
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "python3"
    exe = Path(sys.executable).as_posix()
    shim.write_text(f'#!/usr/bin/env bash\nexec "{exe}" "$@"\n', encoding="utf-8", newline="\n")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(shim_dir)


def _judge(repo: Repo, base: str, head: str) -> tuple[int, str]:
    """`pick`'s input block, then the whole `gates` task, as Concourse runs them."""
    root = repo.root
    repo.git("checkout", "-q", "--detach", head)
    merge_base = repo.git("merge-base", head, base)
    env = {**os.environ, "BASE_SHA": base, "MERGE_BASE": merge_base, "SHA": head}
    made = subprocess.run(["bash", "-euo", "pipefail", "-c", _inputs_block()], env=env, cwd=root,
                          capture_output=True, text=True, timeout=60)
    assert made.returncode == 0, made.stdout + made.stderr
    (root / "pr" / ".git" / "pr-number").write_text("531\n", encoding="utf-8")
    for d in ("hub_log", "live-pipeline"):
        (root / d).mkdir(exist_ok=True)
    path = _python3_shim(root) + os.pathsep + os.environ.get("PATH", "")
    r = subprocess.run(["bash", "-ec", _script("gates")], env={**os.environ, "PATH": path},
                       cwd=root, capture_output=True, text=True, timeout=120)
    log = (root / "hub_log" / "output.log").read_text(encoding="utf-8")
    return r.returncode, log


# -- AC1: DEV-D, a new module with no test of its own -------------------------

def test_531s_range_is_red_and_names_each_untested_module(tmp_path) -> None:
    """#531's shape: two new spine modules and one modified, one combined test
    file. binnacle_spine.py was already on develop with its test, so, as in
    deploy.sh, a modified module owes nothing."""
    repo, base = _develop(tmp_path, **{
        "backend/services/binnacle_spine.py": "x = 0\n",
        "backend/tests/unit/test_binnacle_spine.py": "def test(): pass\n",
    })
    repo.branch("feat/spine", base)
    repo.commit("feat(binnacle): approval queues and the bell as event-spine producers", {
        "backend/services/approval_spine.py": "x = 1\n",
        "backend/services/bell_spine.py": "x = 1\n",
        "backend/services/binnacle_spine.py": "x = 1\n",
        "backend/api/binnacle.py": "ROUTES = [1]\n",
        "backend/api/notifications.py": "ROUTES = [1]\n",
        "backend/tests/unit/test_spine_approval_and_bell_producers.py": "def test(): pass\n",
    })
    head = repo.commit("fix(binnacle): re-raise an approval that returns to pending",
                       {"backend/services/approval_spine.py": "x = 2\n"})

    rc, log = _judge(repo, base, head)

    assert rc != 0, log
    for module in ("approval_spine", "bell_spine"):
        assert f"backend/services/{module}.py has no test_{module}.py" in log, log
    assert "binnacle_spine.py has no" not in log, log
    assert "deploy gates: ok" in log, "the deploy gates still run when DEV-D fails"


def test_547s_range_is_green(tmp_path) -> None:
    """#547's shape, on a develop that already holds #531: tests only."""
    repo, base = _develop(tmp_path, **{
        "backend/services/approval_spine.py": "x = 2\n",
        "backend/services/bell_spine.py": "x = 1\n",
        "backend/services/binnacle_spine.py": "x = 1\n",
        "backend/tests/unit/test_binnacle_spine.py": "def test(): pass\n",
        "backend/tests/unit/test_spine_approval_and_bell_producers.py": "def test(): pass\n",
    })
    repo.branch("test/split", base)
    head = repo.commit("test: split #531's spine tests per module so DEV-D finds them", {
        "backend/tests/unit/spine_producer_fixtures.py": "F = 1\n",
        "backend/tests/unit/test_approval_spine.py": "def test_new(): pass\n",
        "backend/tests/unit/test_bell_spine.py": "def test(): pass\n",
    })

    rc, log = _judge(repo, base, head)

    assert rc == 0, log
    assert "DEV-D" in log and "no new module" in log, log


def test_the_same_pr_with_the_test_passes_and_api_counts_too(tmp_path) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/x", base)
    head = repo.commit("feat: two new modules", {
        "backend/services/ledger.py": "x = 1\n",
        "backend/api/ledger_routes.py": "x = 1\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0
    assert "backend/services/ledger.py has no test_ledger.py" in log, log
    assert "backend/api/ledger_routes.py has no test_ledger_routes.py" in log, log

    head = repo.commit("test: the modules' tests", {
        "backend/tests/unit/test_ledger.py": "def test(): pass\n",
        "backend/tests/test_ledger_routes.py": "def test(): pass\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "DEV-D: 2 new module(s), each with its test_<name>.py" in log, log


def test_a_bypass_trailer_on_any_branch_commit_waives_dev_d_and_says_so(tmp_path) -> None:
    """The squash body carries every branch commit's message, so deploy.sh reads
    a trailer from any of them."""
    repo, base = _develop(tmp_path)
    repo.branch("feat/x", base)
    repo.commit("feat: a module\n\nBypass-Process-Gate: covered by test_other.py", {
        "backend/services/ledger.py": "x = 1\n"})
    head = repo.commit("docs: notes", {"docs/notes.md": "n\n"})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log
    assert "BYPASSED" in log and "backend/services/ledger.py" in log, log


# -- AC2: DEV-B, a sensitive path with no trailer -----------------------------

def test_a_sensitive_path_with_no_trailer_on_any_branch_commit_is_red(tmp_path) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/x", base)
    head = repo.commit("feat: wire a router", {"backend/main.py": "app = 1\n"})
    rc, log = _judge(repo, base, head)
    assert rc != 0
    assert "DEV-B" in log and "backend/main.py" in log, log


@pytest.mark.parametrize("trailer", [
    "Threat-Model-MD: docs/threat-models/router.md",
    "Bypass-Process-Gate: a comment-only change",
])
def test_either_trailer_on_an_earlier_branch_commit_satisfies_dev_b(tmp_path, trailer) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/x", base)
    repo.commit(f"feat: wire a router\n\n{trailer}", {"backend/main.py": "app = 1\n"})
    head = repo.commit("chore: tidy", {"docs/notes.md": "n\n"})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log


def test_only_the_pull_requests_own_commits_are_graded(tmp_path) -> None:
    """A sensitive change already on develop is develop's, not this PR's."""
    repo, base0 = _develop(tmp_path)
    repo.branch("feat/x", base0)
    head = repo.commit("feat: docs", {"docs/a.md": "a\n"})
    repo.git("checkout", "-q", "develop")
    base = repo.commit("feat: develop moved, untrailered", {"backend/main.py": "app = 2\n"})
    rc, log = _judge(repo, base, head)
    assert rc == 0, log


# -- AC3: the verdict comes from the base branch ------------------------------

def test_a_pr_that_neuters_the_gate_script_is_judged_by_develops(tmp_path) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/sneaky", base)
    head = repo.commit("feat: wire a router", {
        "backend/main.py": "app = 1\n",
        "scripts/lib/devb_gate.py": "raise SystemExit(0)\n",
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "backend/main.py" in log, log


def test_a_pr_that_deletes_the_gate_script_is_still_judged(tmp_path) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/sneaky", base)
    head = repo.commit("feat: a module", {
        "backend/services/ledger.py": "x = 1\n",
        "scripts/lib/devb_gate.py": None,
    })
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "backend/services/ledger.py has no test_ledger.py" in log, log


def test_the_gates_task_runs_no_process_gate_code_from_the_branch() -> None:
    gates = _script("gates")
    assert "pr/scripts/lib" not in gates
    assert 'pg = os.path.join("pr", ".git", "process-gates")' in gates
    assert 'os.path.join(pg, "devb_gate.py")' in gates
    block = _inputs_block()
    assert 'git -C pr show "$BASE_SHA:scripts/lib/devb_gate.py"' in block
    assert 'git -C pr show "$BASE_SHA:scripts/deploy.sh"' in block
    assert ":scripts/" not in block.replace("$BASE_SHA:scripts/", "")


def test_develops_deploy_sh_changing_its_dev_d_turns_the_check_red(tmp_path) -> None:
    """The port of DEV-D lives here; a deploy.sh that no longer reads the way
    it was ported from must stop the check, not drift from it silently."""
    drifted = BASE_DEPLOY_SH.replace("--diff-filter=A HEAD~1 HEAD", "--diff-filter=AR HEAD~1 HEAD")
    repo, base = _develop(tmp_path, **{"scripts/deploy.sh": drifted})
    repo.branch("feat/x", base)
    head = repo.commit("docs", {"docs/a.md": "a\n"})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "deploy.sh" in log and "no longer" in log, log


# -- wiring --------------------------------------------------------------------

def test_the_pick_fetches_the_base_and_deepens_to_the_merge_base() -> None:
    pick = _script("pick")
    assert "refs/heads/$THEHUB_BRANCH" in pick
    assert 'git -C pr fetch -q --depth 1 "$REPO_URI" "$BASE_SHA"' in pick
    assert 'git -C pr merge-base "$SHA" "$BASE_SHA"' in pick
    assert '--deepen 50 "$REPO_URI" "$SHA" "$BASE_SHA"' in pick
    # The inputs are written after the merge base is known, in the task that
    # holds the credential and runs nothing from the branch.
    assert pick.index("merge-base") < pick.index("# -- process-gate inputs, begin")


def test_the_deploy_gates_still_run_and_both_verdicts_count() -> None:
    gates = _script("gates")
    assert 'bash pr/scripts/pr_deploy_gates.sh --mykronos "$PWD/live-pipeline"' in gates
    assert gates.index("PROCESS_RC") < gates.index("bash pr/scripts/pr_deploy_gates.sh")
