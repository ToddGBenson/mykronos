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

from tests.pipeline_steps import find

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"
JOB = "pr-gates"

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and shutil.which("bash")), reason="git and bash are required"
)


def _job() -> dict[str, Any]:
    doc = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    return next(j for j in doc["jobs"] if j["name"] == JOB)


def _script(task: str) -> str:
    step = find(_job()["plan"], task)
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
# sensitive path with neither trailer. Its pattern list is a SUBSET of the real
# gate's, the same anchored shapes (a fixed file, a directory of .py files);
# the full list is TheHub's and is tested there. What this file pins is how
# the pipeline hands paths and bodies to whichever list develop carries.
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
        "scripts/pr_deploy_gates.sh": (
            "#!/usr/bin/env bash\n# --audit-as\necho 'deploy gates: ok'\n"
        ),
        "backend/main.py": "app = None\n",
        "backend/api/notifications.py": "ROUTES = []\n",
        "backend/api/binnacle.py": "ROUTES = []\n",
        "backend/tests/unit/test_approval_spine.py": "def test_old(): pass\n",
    }
    files.update(extra)
    base = repo.commit("develop", files)
    return repo, base


def _python3_shim(tmp_path: Path, flags: str = "-X utf8") -> str:
    """The task image's `python3`, as this interpreter, ahead of anything else.
    In UTF-8 mode, as the image's is under its UTF-8 locale (-I ignores PYTHONUTF8)."""
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / "python3"
    exe = Path(sys.executable).as_posix()
    shim.write_text(f'#!/usr/bin/env bash\nexec "{exe}" {flags} "$@"\n', encoding="utf-8",
                    newline="\n")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(shim_dir)


def _pick_env(src: Repo, base: str, head: str) -> dict[str, str]:
    """The pick's variables, with `src` standing in for GitHub: served over
    file:// so a shallow or filtered fetch behaves as it does from GitHub."""
    src.git("config", "uploadpack.allowAnySHA1InWant", "true")
    src.git("config", "uploadpack.allowFilter", "true")
    path = _python3_shim(src.root) + os.pathsep + os.environ.get("PATH", "")
    return {**os.environ, "PATH": path, "REPO_URI": src.dir.as_uri(), "ssh_cmd": "",
            "SHA": head, "BASE_SHA": base, "NUM": "578", "THEHUB_BRANCH": "develop"}


def _judge(repo: Repo, base: str, head: str) -> tuple[int, str]:
    """`pick`'s input block, then the whole `gates` task, as Concourse runs them."""
    root = repo.root
    repo.git("checkout", "-q", "--detach", head)
    env = {**_pick_env(repo, base, head), "MERGE_BASE": repo.git("merge-base", head, base)}
    made = subprocess.run(["bash", "-euo", "pipefail", "-c", _inputs_block()], env=env, cwd=root,
                          capture_output=True, text=True, timeout=60)
    assert made.returncode == 0, made.stdout + made.stderr
    return _gates(root)


def _gates(root: Path, python_flags: str = "-X utf8",
           env: dict[str, str] | None = None) -> tuple[int, str]:
    """The whole `gates` task, as Concourse runs it, on the inputs under root/pr."""
    (root / "pr" / ".git" / "pr-number").write_text("531\n", encoding="utf-8")
    for d in ("hub_log", "live-pipeline"):
        (root / d).mkdir(exist_ok=True)
    path = _python3_shim(root, python_flags) + os.pathsep + os.environ.get("PATH", "")
    # From a file, not `bash -c`: Git Bash on Windows truncates a long argv,
    # and the task is ~10 KB since TheHub #62416.
    (root / "gates.sh").write_text(_script("gates"), encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", "-e", "gates.sh"],
                       env={**os.environ, **(env or {}), "PATH": path},
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

def test_the_pick_grades_the_range_on_the_whole_commit_graph() -> None:
    pick = _script("pick")
    block = _inputs_block()
    assert "refs/heads/$THEHUB_BRANCH" in pick
    assert 'git -C pr fetch -q --depth 1 "$REPO_URI" "$BASE_SHA"' in pick
    # [review of mykronos #1202] No deepening: a deepened clone cannot tell a
    # branch commit from a develop commit whose link to develop is still cut.
    assert "--deepen" not in pick
    # (A here-document in the block sits at the script's margin, so the
    # block's lines keep their own indentation: match the break, not its depth.)
    assert re.search(r'fetch -q --filter=blob:none \\\n\s+"\$REPO_URI" "\$SHA" "\$BASE_SHA"',
                     block)
    assert 'git -C "$graph" log --format=%B "$SHA" --not "$BASE_SHA" > "$pg/bodies"' in block
    # The paths come from the trees against every merge base, not per commit.
    assert 'git -C "$graph" merge-base --all "$SHA" "$BASE_SHA"' in block
    assert 'diff -z --name-only --no-renames "$mb" "$SHA"' in block
    assert "git -C \"$graph\" log --format= --name-only" not in block
    assert 'diff --name-only "$MERGE_BASE"' not in block and "$MERGE_BASE..$SHA" not in block
    # The graph is made in the task that holds the credential and is removed
    # before `export-pr`, which copies only process-gates/ and judge/.
    assert 'rm -rf "$graph"' in block
    assert "range-graph" not in _script("export-pr")


def test_the_deploy_gates_still_run_and_both_verdicts_count() -> None:
    gates = _script("gates")
    assert 'bash "$JUDGE/scripts/pr_deploy_gates.sh" --mykronos "$PWD/live-pipeline"' in gates
    assert gates.index("PROCESS_RC") < gates.index('bash "$JUDGE/scripts/pr_deploy_gates.sh"')


# -- [TheHub #578, #586, #595; review of mykronos #1202] the exact range -------
#
# The pull request's commits are `"$SHA" --not "$BASE_SHA"`, on the whole
# commit graph. The pick used to deepen a shallow clone to a merge base and
# grade merge-base..head, which took in develop's own commits:
#
# * #578, #586, #595: cut from an old develop, later merged with a newer one.
#   89 commits and 189 KB of bodies for #578's 13 commits and 9.5 KB. The
#   bodies travel in DEVB_COMMIT_MESSAGE, and Linux caps one environment
#   string at MAX_ARG_STRLEN, so DEV-B could not start: `[Errno 7] Argument
#   list too long`. Smaller, the same leak handed #595 19 develop trailers.
# * A branch cut from inside a develop merge's side branch that is longer than
#   the fetch depth.
# * A criss-cross history, where `git merge-base` names one base of two.
#
# These fetch the way the pick does (by sha, depth 1, from a repository served
# over file://), then run the pick's lines from the base's fetch to the end of
# its input block, and the gates task, as the pipeline holds them.

_MAX_ARG_STRLEN = 32 * 4096


def _range_block() -> str:
    """The lines of `pick` from the base's fetch to the end of the inputs."""
    body = re.search(
        r'\n([ \t]*GIT_SSH_COMMAND="\$ssh_cmd" git -C pr fetch -q --depth 1 '
        r'"\$REPO_URI" "\$BASE_SHA"\n.*?# -- process-gate inputs, end)\n',
        _script("pick"), re.S)
    assert body, "the pick's range lines moved"
    return textwrap.dedent(body.group(1)) + "\n"


def _old_branch_that_merged_develop(
    tmp_path: Path, old: int, old_body: str, pr_files: dict[str, str | None],
) -> tuple[Repo, str, str]:
    """#578's shape: `old` develop commits, a branch cut there, 60 more on
    develop, develop merged into the branch, then develop moves on again."""
    repo, _ = _develop(tmp_path / "src")
    for i in range(old):
        repo.commit(f"chore: old develop {i}\n\n{old_body}", {})
    repo.branch("feat/old", repo.git("rev-parse", "HEAD"))
    repo.commit("feat: the pull request's own commit", pr_files)
    repo.git("checkout", "-q", "develop")
    for i in range(60):
        repo.commit(f"chore: develop moves {i}", {})
    merged = repo.git("rev-parse", "HEAD")
    repo.git("checkout", "-q", "feat/old")
    repo.git("merge", "-q", "--no-ff", "-m", "Merge develop into feat/old", merged)
    head = repo.git("rev-parse", "HEAD")
    repo.git("checkout", "-q", "develop")
    base = repo.commit("chore: develop moves on", {})
    return repo, base, head


def _pick(src: Repo, base: str, head: str, tmp_path: Path,
          serve: Repo | None = None) -> subprocess.CompletedProcess[str]:
    """The pick from the head's fetch to the end of its inputs. `serve` is the
    repository the range lines fetch from, when it is not `src`."""
    env = _pick_env(serve or src, base, head)
    env["HEAD_URI"] = _pick_env(src, base, head)["REPO_URI"]
    root = tmp_path / "pick"
    root.mkdir()
    script = ('git init -q pr\n'
              'git -C pr fetch -q --depth 1 "$HEAD_URI" "$SHA"\n'
              'git -C pr checkout -q --detach "$SHA"\n'
              + _range_block())
    return subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, cwd=root,
                          capture_output=True, text=True, timeout=180)


def _judge_fetched(src: Repo, base: str, head: str, tmp_path: Path,
                   shallow: bool = True) -> tuple[int, str, str]:
    """The pick, fetching from `src`, then the gates task. `shallow`: the
    fixture must leave the pick's clone shallow (not for a small history
    whose flaw is not shallowness, which a deepening clone fetches whole)."""
    made = _pick(src, base, head, tmp_path)
    assert made.returncode == 0, made.stdout + made.stderr
    root = tmp_path / "pick"
    if shallow:
        assert (root / "pr" / ".git" / "shallow").is_file(), "the fixture must fetch shallow"
    bodies = (root / "pr" / ".git" / "process-gates" / "bodies").read_text(encoding="utf-8")
    rc, log = _gates(root)
    return rc, log, bodies


@pytest.mark.parametrize("old", [45, 80], ids=["history-reaches-the-root", "history-is-cut"])
def test_a_branch_that_merged_a_newer_develop_is_graded_on_its_own_commits(tmp_path, old) -> None:
    # 4 KB of develop body per old commit: 180 KB or more, past MAX_ARG_STRLEN,
    # if the range drags them in, as #578's did.
    padding = "OLD-DEVELOP-BODY " + "x" * 4000
    repo, base, head = _old_branch_that_merged_develop(tmp_path, old, padding, {"docs/a.md": "a\n"})
    assert old * len(padding) > _MAX_ARG_STRLEN
    rc, log, bodies = _judge_fetched(repo, base, head, tmp_path)
    assert "OLD-DEVELOP-BODY" not in bodies, "develop's history was graded as the branch's"
    assert "feat: the pull request's own commit" in bodies
    assert "Merge develop into feat/old" in bodies
    assert len(bodies.encode("utf-8")) < _MAX_ARG_STRLEN
    assert "Argument list too long" not in log, log
    assert "DEV-B: no sensitive path in this pull request" in log, log
    assert rc == 0, log


def test_a_trailer_in_develops_history_does_not_satisfy_the_branchs_dev_b(tmp_path) -> None:
    """The same cut, small bodies: develop's own Threat-Model-MD: trailers must
    not reach DEV-B as if a branch commit carried them."""
    trailer = "Threat-Model-MD: docs/threat-models/old.md"
    repo, base, head = _old_branch_that_merged_develop(
        tmp_path, 45, trailer, {"backend/main.py": "app = 1\n"})
    rc, log, bodies = _judge_fetched(repo, base, head, tmp_path)
    assert trailer not in bodies
    assert rc != 0, log
    assert "backend/main.py" in log, log


def test_a_branch_cut_from_a_long_develop_side_branch_gets_none_of_its_trailers(tmp_path) -> None:
    """Fable's reproduction. develop merged a side branch 71 commits long, and
    the pull request was cut from the side's first commit `c`, which carries a
    trailer. A deepened clone cannot see `c` is develop's (the side is cut near
    its tip) and no commit in the range is parentless, so `c`'s trailer passed
    the branch's untrailered backend/main.py."""
    trailer = "Threat-Model-MD: docs/threat-models/side.md"
    repo, _ = _develop(tmp_path / "src")
    a = repo.commit("chore: a", {})
    repo.branch("side", a)
    c = repo.commit(f"feat: side c\n\n{trailer}", {})
    for i in range(70):
        repo.commit(f"chore: side {i}", {})
    repo.git("checkout", "-q", "develop")
    repo.commit("chore: x", {})
    repo.git("merge", "-q", "--no-ff", "-m", "Merge side into develop", "side")
    merged = repo.git("rev-parse", "HEAD")
    repo.branch("feat/from-side", c)
    repo.commit("feat: wire a router", {"backend/main.py": "app = 1\n"})
    repo.git("merge", "-q", "--no-ff", "-m", "Merge develop into feat/from-side", merged)
    head = repo.git("rev-parse", "HEAD")
    repo.git("checkout", "-q", "develop")
    base = repo.commit("chore: develop moves on", {})
    rc, log, bodies = _judge_fetched(repo, base, head, tmp_path)
    assert trailer not in bodies, "develop's side commit was graded as the branch's"
    assert "feat: wire a router" in bodies and "Merge develop into feat/from-side" in bodies
    assert rc != 0, log
    assert "backend/main.py" in log, log


def test_a_criss_cross_history_gets_none_of_develops_trailers(tmp_path) -> None:
    """develop merged an early state of the branch while the branch merged an
    early develop: two merge bases, b1 and d1, and `git merge-base` names one.
    merge-base..head then holds the other, and each carries a trailer."""
    repo, start = _develop(tmp_path / "src")
    repo.branch("feat/cc", start)
    b1 = repo.commit("feat: b1\n\nThreat-Model-MD: docs/threat-models/b1.md", {"docs/b1.md": "b\n"})
    repo.git("checkout", "-q", "develop")
    d1 = repo.commit("feat: d1\n\nThreat-Model-MD: docs/threat-models/d1.md", {"docs/d1.md": "d\n"})
    repo.git("merge", "-q", "--no-ff", "-m", "Merge feat/cc at b1 into develop", b1)
    base = repo.git("rev-parse", "HEAD")
    repo.git("checkout", "-q", "feat/cc")
    repo.git("merge", "-q", "--no-ff", "-m", "Merge develop at d1 into feat/cc", d1)
    head = repo.commit("feat: a model", {"backend/models/m.py": "x = 1\n"})
    assert len(repo.git("merge-base", "--all", head, base).split()) == 2
    rc, log, bodies = _judge_fetched(repo, base, head, tmp_path, shallow=False)
    assert "Threat-Model-MD:" not in bodies, "a develop commit was graded as the branch's"
    assert "feat: a model" in bodies and "Merge develop at d1 into feat/cc" in bodies
    assert rc != 0, log
    assert "backend/models/m.py" in log, log


def test_a_change_made_in_a_merge_commit_is_graded(tmp_path) -> None:
    """A merge's own edit (in neither parent) is the branch's change."""
    repo, start = _develop(tmp_path)
    repo.branch("feat/evil", start)
    repo.commit("docs: a", {"docs/a.md": "a\n"})
    repo.git("checkout", "-q", "develop")
    base = repo.commit("docs: b", {"docs/b.md": "b\n"})
    repo.git("checkout", "-q", "feat/evil")
    repo.git("merge", "-q", "--no-ff", "--no-commit", base)
    head = repo.commit("Merge develop into feat/evil", {"backend/main.py": "app = 9\n"})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "backend/main.py" in log, log


def test_a_test_the_branch_added_and_deleted_does_not_count_for_dev_d(tmp_path) -> None:
    repo, base = _develop(tmp_path)
    repo.branch("feat/x", base)
    repo.commit("feat: ledger", {
        "backend/services/ledger.py": "x = 1\n",
        "backend/tests/unit/test_ledger.py": "def test_x(): pass\n",
    })
    head = repo.commit("chore: drop the test", {"backend/tests/unit/test_ledger.py": None})
    rc, log = _judge(repo, base, head)
    assert rc != 0, log
    assert "backend/services/ledger.py has no test_ledger.py" in log, log


def test_a_head_whose_graph_cannot_be_fetched_fails_closed(tmp_path) -> None:
    """The base can be fetched and the head cannot: no range, so no verdict."""
    repo, base = _develop(tmp_path / "src")
    repo.branch("feat/x", base)
    head = repo.commit("feat: x", {"docs/x.md": "x\n"})
    serve, _ = _develop(tmp_path / "other")
    serve.git("fetch", "-q", repo.dir.as_uri(), "develop")
    serve.git("reset", "-q", "--hard", "FETCH_HEAD")
    made = _pick(repo, base, head, tmp_path, serve=serve)
    assert made.returncode != 0, made.stdout + made.stderr
    assert "failing closed" in made.stdout, made.stdout + made.stderr
    assert not (tmp_path / "pick" / "pr" / ".git" / "process-gates" / "bodies").exists()


@pytest.mark.parametrize("how", ["checkout-the-branch-copy", "strategy-ours"])
def test_a_merge_that_keeps_the_branchs_copy_of_a_sensitive_file_is_graded(tmp_path, how) -> None:
    """[review of mykronos #1202, at e46cbda9] develop changed backend/main.py;
    the branch merged develop and kept its own old copy. The squash reverts
    develop's change to a sensitive file, so DEV-B must see backend/main.py,
    though no branch commit's own listing names it. develop's trailer on that
    change is develop's, not the branch's."""
    repo, start = _develop(tmp_path / "src")
    repo.branch("feat/keep", start)
    repo.commit("docs: a", {"docs/a.md": "a\n"})
    repo.git("checkout", "-q", "develop")
    base = repo.commit("feat: develop wires a router\n\nThreat-Model-MD: docs/threat-models/r.md",
                       {"backend/main.py": "app = 2\n"})
    repo.git("checkout", "-q", "feat/keep")
    if how == "strategy-ours":
        repo.git("merge", "-q", "-s", "ours", "-m", "Merge develop into feat/keep", base)
        head = repo.git("rev-parse", "HEAD")
    else:
        repo.git("merge", "-q", "--no-ff", "--no-commit", base)
        repo.git("checkout", "HEAD", "--", "backend/main.py")
        head = repo.commit("Merge develop into feat/keep", {})
    rc, log, bodies = _judge_fetched(repo, base, head, tmp_path, shallow=False)
    changed = (tmp_path / "pick" / "pr" / ".git" / "process-gates" / "changed").read_text(
        encoding="utf-8").split()
    assert sorted(changed) == ["backend/main.py", "docs/a.md"], changed
    assert "Threat-Model-MD:" not in bodies
    assert rc != 0, log
    assert "backend/main.py" in log, log


def test_a_head_that_shares_no_commit_with_develop_fails_closed(tmp_path) -> None:
    """No merge base: no squash to grade paths against, so no verdict."""
    repo, base = _develop(tmp_path / "src")
    repo.git("checkout", "-q", "--orphan", "lone")
    head = repo.commit("feat: lone", {"docs/x.md": "x\n"})
    made = _pick(repo, base, head, tmp_path)
    assert made.returncode != 0, made.stdout + made.stderr
    assert "shares no commit" in made.stdout, made.stdout + made.stderr
    assert not (tmp_path / "pick" / "pr" / ".git" / "process-gates" / "changed").exists()


# -- [TheHub #62156] path handling: NUL-separated file names -------------------
#
# Without -z, `git diff --name-only` C-quotes a name with non-ASCII or special
# characters ("docs/caf\303\251.md"), and devb_gate's anchored patterns grade
# that quoted text rather than the path. The pick lists every name with -z, so
# `changed` and `added` hold the exact, unquoted names, one per line, and a
# name the one-per-line list cannot carry fails closed.
#
# These names cannot all be checked out on every filesystem, so the fixture
# writes them through the index and the pick here stops short of the head's
# checkout, which its range lines do not read.


def _commit_names(repo: Repo, message: str, files: dict[str | bytes, str]) -> str:
    """A commit of `files` written through the index alone, so any name git
    can store is committed whatever the filesystem accepts. A bytes name is
    stored as those bytes."""
    entries = b""
    for name, content in files.items():
        blob = subprocess.run(["git", "-C", str(repo.dir), "hash-object", "-w", "--stdin"],
                              input=content.encode("utf-8"), capture_output=True,
                              check=True).stdout.strip()
        raw = name if isinstance(name, bytes) else name.encode("utf-8")
        entries += b"100644 " + blob + b"\t" + raw + b"\0"
    subprocess.run(["git", "-C", str(repo.dir), "-c", "core.protectNTFS=false",
                    "-c", "core.protectHFS=false", "update-index", "-z", "--index-info"],
                   input=entries, capture_output=True, check=True)
    repo.git("commit", "-q", "-m", message)
    return repo.git("rev-parse", "HEAD")


def _pick_names(
    tmp_path: Path, files: dict[str | bytes, str],
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """A pull request adding `files`, through the pick's range lines."""
    repo, base = _develop(tmp_path / "src")
    repo.branch("feat/names", base)
    head = _commit_names(repo, "feat: files with unusual names", files)
    repo.git("checkout", "-q", "develop")
    env = _pick_env(repo, base, head)
    root = tmp_path / "pick"
    root.mkdir()
    script = ('git init -q pr\n'
              'git -C pr fetch -q --depth 1 "$REPO_URI" "$SHA"\n'
              + _range_block())
    made = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env=env, cwd=root,
                          capture_output=True, text=True, encoding="utf-8", timeout=180)
    return made, root


def _path_list(root: Path, name: str) -> list[str]:
    raw = (root / "pr" / ".git" / "process-gates" / name).read_bytes().decode("utf-8")
    assert raw == "" or raw.endswith("\n"), repr(raw)
    return raw.split("\n")[:-1]


_UNUSUAL_NAMES = {
    "non-ascii": "docs/café résumé.md",
    "double-quote": 'docs/say "hi".md',
    "backslash": "docs/back\\slash.md",
    "tab": "docs/tab\there.md",
    "inner-no-break-space": "docs/no\u00a0break.md",
}


@pytest.mark.parametrize("name", list(_UNUSUAL_NAMES.values()), ids=list(_UNUSUAL_NAMES))
def test_an_unusual_file_name_is_listed_exactly_in_changed_and_added(tmp_path, name) -> None:
    made, root = _pick_names(tmp_path, {name: "x\n", "docs/plain.md": "p\n"})
    assert made.returncode == 0, made.stdout + made.stderr
    for listing in ("changed", "added"):
        names = _path_list(root, listing)
        assert name in names, (listing, names)
        assert "docs/plain.md" in names, (listing, names)
        assert not any(n.startswith('"') for n in names), (listing, names)


def test_a_sensitive_path_with_a_non_ascii_name_is_graded_by_dev_b(tmp_path) -> None:
    """The exact name matches devb_gate's anchored pattern; the quoted one did not."""
    name = "backend/models/café.py"
    made, root = _pick_names(tmp_path, {name: "x = 1\n"})
    assert made.returncode == 0, made.stdout + made.stderr
    assert _path_list(root, "changed") == [name]
    rc, log = _gates(root)
    assert rc != 0, log
    assert "DEV-B (#4944)" in log, log


@pytest.mark.parametrize("brk", ["\n", "\r", "\x0b", "\x1e", "\x85", " "],
                         ids=["lf", "cr", "vt", "rs", "nel", "line-separator"])
def test_a_name_with_a_line_break_fails_closed(tmp_path, brk) -> None:
    """devb_gate reads one name per line, so a name that breaks a line cannot
    be listed: no path lists, and the pick is red."""
    made, root = _pick_names(tmp_path, {f"backend/models/a{brk}b.py": "x = 1\n"})
    _assert_refused(made, root)


def _assert_refused(made: subprocess.CompletedProcess[str], root: Path) -> None:
    assert made.returncode != 0, made.stdout + made.stderr
    assert "failing closed" in made.stdout, made.stdout + made.stderr
    pg = root / "pr" / ".git" / "process-gates"
    assert not (pg / "changed").exists() and not (pg / "added").exists()
    assert not list(pg.glob("*.z"))


# Every kind of whitespace str.strip() removes changes the name the gates read.
@pytest.mark.parametrize("name", [
    " docs/lead.md", "docs/trail.md ", "docs/trail.md\t", "docs/trail.md\x1f",
    "docs/trail.md\u00a0", "\u2000docs/lead.md", "docs/trail.md\u200a", "docs/trail.md\u3000",
], ids=["lead-space", "trail-space", "trail-tab", "trail-unit-sep", "trail-nbsp",
        "lead-en-quad", "trail-hair-space", "trail-ideographic-space"])
def test_a_name_that_strip_would_change_fails_closed(tmp_path, name) -> None:
    assert name.strip() != name
    made, root = _pick_names(tmp_path, {name: "x\n", "docs/plain.md": "p\n"})
    _assert_refused(made, root)


@pytest.mark.parametrize("raw", [
    b"docs/\xff.md", b"docs/cut\xc3.md", b"docs/\xed\xa0\x80.md", b"docs/\xc0\xaf.md",
], ids=["invalid-byte", "truncated", "surrogate", "overlong"])
def test_a_name_that_is_not_utf8_fails_closed(tmp_path, raw) -> None:
    with pytest.raises(UnicodeDecodeError):
        raw.decode("utf-8")
    made, root = _pick_names(tmp_path, {raw: "x\n", "docs/plain.md": "p\n"})
    _assert_refused(made, root)


def test_the_gates_hand_devb_gate_its_paths_as_utf8_whatever_the_locale(tmp_path) -> None:
    """The gate's child reads stdin as UTF-8, so the gates encode it as UTF-8
    themselves, not in the parent's locale encoding. Here the parent's is not
    UTF-8 (UTF-8 mode off, a C locale), and the name has a character outside
    both ASCII and cp1252: without encoding="utf-8" the hand-off fails, red."""
    name = "docs/\u0151.md"
    made, root = _pick_names(tmp_path, {name: "x\n"})
    assert made.returncode == 0, made.stdout + made.stderr
    rc, log = _gates(root, python_flags="-X utf8=0", env={"LC_ALL": "C"})
    assert "DEV-B: no sensitive path in this pull request" in log, log
    assert rc == 0, log
