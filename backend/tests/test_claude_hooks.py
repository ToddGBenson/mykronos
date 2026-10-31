"""The harness guards in .claude/hooks/, driven as Claude Code drives them (TheHub #61099).

Three mistakes kept recurring because the lesson lived only in an agent's
memory: running `ruff format` (the tree was never formatted with it, one run
rewrites over a hundred files), committing, resetting or switching inside the
live TheHub checkout that the production deploy ships, and saving a
PowerShell script that does not parse. The hooks refuse the spellings of the
first two that are tested here, and report the third the moment the file is
written. They do not catch every spelling: the known gaps are listed in
.claude/hooks/estate_guard.py and tracked in TheHub #61108.

Every test pipes a real hook payload into the real hook through bash, the way
the harness runs it, and reads the exit code: 2 blocks, 0 allows.

keel and binnacle's selftest passed while four bypasses were live, because it
tried only the spellings the author had in mind. So most cases here are
bypass attempts: quoting, extra whitespace, other names for the same binary,
environment-variable paths, `cd` before the command, and the command handed
to another interpreter (`bash -c`, `cmd /c`, `pwsh -c`, a heredoc). Every
must-block list has a must-allow list next to it, so a guard that blocks
everything fails too.

The protected checkout is the one under a temporary user profile: the hooks
default to <profile>/Documents/Projects/TheHub-main, read from USERPROFILE or
HOME, and MYKRONOS_PROTECTED_CHECKOUTS replaces the default.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
HOOKS = ROOT / ".claude" / "hooks"
SETTINGS = ROOT / ".claude" / "settings.json"
IS_WINDOWS = os.name == "nt"


def _bash() -> str | None:
    """Git Bash on Windows (never system32's WSL bash), bash elsewhere."""
    found = shutil.which("bash")
    if found and IS_WINDOWS and ("system32" in found.lower() or "windowsapps" in found.lower()):
        found = None
    if found is None and IS_WINDOWS:
        for candidate in (
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Git" / "bin" / "bash.exe",
        ):
            if candidate.exists():
                return str(candidate)
    return found


BASH = _bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not on PATH")
PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not on PATH")

pytestmark = needs_bash


@dataclass
class Estate:
    profile: Path
    projects: Path
    hub: Path  # the protected live checkout
    worktree: Path  # a real worktree under it: allowed
    fake_worktree: Path  # a folder under .claude/worktrees with no .git: git would walk up
    sibling: Path  # TheHub-main-old: a name that merely starts the same
    mykronos: Path
    env: dict[str, str]

    def forms(self) -> dict[str, str]:
        """Placeholders a case may use, each a different spelling of a path."""
        hub = str(self.hub)
        out = {
            "<PW>": hub.replace("/", "\\"),
            "<PF>": hub.replace("\\", "/"),
            "<PU>": hub.replace("\\", "/").upper(),
            "<PT>": hub.replace("\\", "/") + "/",
            "<PROFILE>": str(self.profile).replace("\\", "/"),
            "<PROFILEW>": str(self.profile).replace("/", "\\"),
            "<PROJ>": str(self.projects).replace("\\", "/"),
            "<WT>": str(self.worktree).replace("\\", "/"),
            "<FAKEWT>": str(self.fake_worktree).replace("\\", "/"),
            "<SIB>": str(self.sibling).replace("\\", "/"),
            "<MYK>": str(self.mykronos).replace("\\", "/"),
        }
        if len(hub) > 1 and hub[1] == ":":
            out["<PM>"] = "/" + hub[0].lower() + hub[2:].replace("\\", "/")
        return out

    def fill(self, text: str) -> str:
        for key, value in sorted(self.forms().items(), key=lambda kv: -len(kv[0])):
            text = text.replace(key, value)
        return text


@pytest.fixture
def estate(tmp_path: Path) -> Estate:
    profile = tmp_path / "profile"
    projects = profile / "Documents" / "Projects"
    hub = projects / "TheHub-main"
    worktree = hub / ".claude" / "worktrees" / "wt1"
    fake = hub / ".claude" / "worktrees" / "notreal"
    sibling = projects / "TheHub-main-old"
    mykronos = projects / "mykronos"
    for d in (hub / "backend", hub / ".git", worktree, fake, sibling, mykronos):
        d.mkdir(parents=True, exist_ok=True)
    (worktree / ".git").write_text("gitdir: ../../../.git/worktrees/wt1\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("MYKRONOS_")}
    env["USERPROFILE"] = str(profile)
    env["HOME"] = str(profile)
    return Estate(profile, projects, hub, worktree, fake, sibling, mykronos, env)


def run_hook(
    hook: str, payload: dict[str, Any], env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(
        [BASH, str(HOOKS / hook)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=60,
    )


def bash_payload(command: str, cwd: str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
        "cwd": cwd,
    }


def assert_blocked(r: subprocess.CompletedProcess[str], what: str) -> None:
    assert r.returncode == 2, f"{what!r} was not blocked (exit {r.returncode}): {r.stderr}"
    assert "BLOCKED" in r.stderr, r.stderr


def assert_allowed(r: subprocess.CompletedProcess[str], what: str) -> None:
    assert r.returncode == 0, f"{what!r} was blocked (exit {r.returncode}): {r.stderr}"


TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def cases(rows: list[tuple[str, ...]]) -> list[Any]:
    """pytest params whose id is the row's case name."""
    return [pytest.param(*row, id=next(c for c in row if c not in TOOLS)) for row in rows]


def guard_bash(
    estate: Estate,
    command: str,
    cwd: str | None = None,
    tool: str = "Bash",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    payload = bash_payload(command, cwd or str(estate.mykronos), tool)
    return run_hook("guard-bash.sh", payload, env or estate.env)


def guard_write(
    estate: Estate, tool: str, path: str, cwd: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return run_hook("guard-write.sh", write_payload(tool, path, cwd), env or estate.env)


def _pwsh_encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


# ── 1. ruff format, in the spellings tested here ────────────────────────────

RUFF_FORMAT_BYPASSES = [
    ("bare", "ruff format"),
    ("with-path", "ruff format backend/"),
    ("double-space", "ruff  format ."),
    ("tab", "ruff\tformat ."),
    ("backslash-newline", "ruff \\\nformat ."),
    ("quoted-name", '"ruff" format .'),
    ("single-quoted-both", "'ruff' 'format'"),
    ("quoted-verb", 'ruff "format" backend'),
    ("split-quotes", "r''uff fo\"\"rmat ."),
    ("ansi-c-quote", "$'ruff' format"),
    ("escaped-letters", "\\ruff for\\mat"),
    ("upper-case", "RUFF FORMAT ."),
    ("exe", "ruff.exe format ."),
    ("abs-path", "/usr/local/bin/ruff format ."),
    ("win-path-quoted", '"C:\\tools\\ruff.exe" format .'),
    ("global-flag-first", "ruff --quiet format ."),
    ("python-m", "python -m ruff format ."),
    ("python3-m", "python3 -m ruff format backend"),
    ("py-launcher", "py -m ruff format"),
    ("python-m-packed", "python -mruff format"),
    ("venv-python", ".venv/Scripts/python.exe -m ruff format ."),
    ("uv-run", "uv run ruff format ."),
    ("uvx-pinned", "uvx ruff@0.6.9 format ."),
    ("env-wrapper", "env FOO=1 ruff format ."),
    ("assignment-prefix", "RUFF_CACHE_DIR=/tmp/x ruff format ."),
    ("after-cd", "cd backend && ruff format ."),
    ("after-check", "ruff check . && ruff format ."),
    ("after-semicolon", "ruff check .; ruff format"),
    ("after-or", "false || ruff format"),
    ("pipe", "echo x | ruff format -"),
    ("background", "ruff format . &"),
    ("subshell", "(cd backend; ruff format .)"),
    ("brace-group", "{ ruff format .; }"),
    ("dollar-subst", "x=$(ruff format .)"),
    ("backticks", "x=`ruff format .`"),
    ("subst-in-dquotes", 'echo "$(ruff format .)"'),
    ("bash-c", 'bash -c "ruff format ."'),
    ("bash-lc", "bash -lc 'ruff format'"),
    ("sh-c-chained", "sh -c 'cd backend; ruff format .'"),
    ("bash-c-nested", "bash -c \"sh -c 'ruff format .'\""),
    ("eval", 'eval "ruff format ."'),
    ("heredoc-to-bash", "bash <<'EOF'\nruff format .\nEOF"),
    ("cmd-c", "cmd /c ruff format ."),
    ("cmd-exe-quoted", 'cmd.exe /C "ruff format ."'),
    ("cmd-msys-slash", "cmd //c ruff format ."),
    ("cmd-caret", "cmd /c r^uff format ."),
    ("pwsh-c", 'pwsh -c "ruff format ."'),
    ("pwsh-command", "pwsh -NoProfile -Command 'ruff format'"),
    ("powershell-call-op", 'powershell.exe -Command "& ruff format ."'),
    ("pwsh-encoded", "pwsh -EncodedCommand " + _pwsh_encoded("ruff format .")),
    ("pwsh-backtick", "pwsh -c 'r`uff format .'"),
    ("xargs", "echo . | xargs ruff format"),
    ("name-in-variable", "R=ruff; $R format ."),
    ("check-flag", "ruff format --check ."),
]

RUFF_ALLOWED = [
    ("check", "ruff check backend/"),
    ("check-fix", "ruff check --fix backend/mykronos/x.py"),
    ("python-m-check", "python -m ruff check ."),
    ("file-named-format", "ruff check src/format.py"),
    ("commit-message", 'git commit -m "never run ruff format"'),
    (
        "heredoc-commit-message",
        "git commit -F - <<'EOF'\nfix: refuse ruff format\n\nruff format rewrites the tree.\nEOF",
    ),
    (
        "subst-heredoc-message",
        "git commit -m \"$(cat <<'EOF'\nguard: block `ruff format`\nEOF\n)\"",
    ),
    ("grep-docs", 'grep -rn "ruff format" docs/'),
    ("echo-quoted", "echo 'ruff format is refused here'"),
    ("other-format", "black --check . ; prettier --check ."),
]


@pytest.mark.parametrize(("case", "command"), cases(RUFF_FORMAT_BYPASSES))
def test_ruff_format_is_refused(estate: Estate, case: str, command: str) -> None:
    r = guard_bash(estate, command)
    assert_blocked(r, command)
    assert "ruff format" in r.stderr


@pytest.mark.parametrize(("case", "command"), cases(RUFF_ALLOWED))
def test_ordinary_ruff_and_mentions_pass(estate: Estate, case: str, command: str) -> None:
    assert_allowed(guard_bash(estate, command), command)


POWERSHELL_TOOL_RUFF = [
    ("bare", "ruff format ."),
    ("call-op", "& ruff format ."),
    ("call-op-quoted", "& 'ruff.exe' format ."),
    ("backtick", "r`uff format ."),
    ("after-semicolon", "Set-Location backend; ruff format ."),
    ("iex", "Invoke-Expression 'ruff format .'"),
    ("cmd-c", 'cmd /c "ruff format ."'),
]


@pytest.mark.parametrize(("case", "command"), cases(POWERSHELL_TOOL_RUFF))
def test_ruff_format_through_the_powershell_tool_is_refused(
    estate: Estate, case: str, command: str
) -> None:
    assert_blocked(guard_bash(estate, command, tool="PowerShell"), command)


def test_ruff_check_through_the_powershell_tool_passes(estate: Estate) -> None:
    r = guard_bash(estate, "ruff check backend", tool="PowerShell")
    assert_allowed(r, "ruff check")


# ── 2. git that moves the live checkout ─────────────────────────────────────

# The default checkout, relative to the user profile, in both slash directions.
REL = "Documents/Projects/TheHub-main"
REL_W = REL.replace("/", "\\")

# (case, command, cwd placeholder). Placeholders are filled from Estate.forms().
GIT_BYPASSES = [
    ("C-backslash", 'git -C "<PW>" commit -m x', "<MYK>"),
    ("C-forward", "git -C <PF> commit -m x", "<MYK>"),
    ("C-upper", "git -C <PU> commit -m x", "<MYK>"),
    ("C-trailing-slash", "git -C <PT> reset --hard", "<MYK>"),
    ("C-subdir", "git -C <PF>/backend checkout .", "<MYK>"),
    ("C-dotdot", "git -C <PROJ>/mykronos/../TheHub-main commit -m x", "<MYK>"),
    ("C-relative", "git -C ../TheHub-main commit -m x", "<MYK>"),
    ("C-single-quoted", "git -C '<PW>' stash", "<MYK>"),
    ("verb-reset", "git -C <PF> reset HEAD~1", "<MYK>"),
    ("verb-checkout", "git -C <PF> checkout develop", "<MYK>"),
    ("verb-stash", "git -C <PF> stash", "<MYK>"),
    ("verb-stash-push", "git -C <PF> stash push -u -m wip", "<MYK>"),
    ("verb-stash-pop", "git -C <PF> stash pop", "<MYK>"),
    ("verb-clean", "git -C <PF> clean -fdx", "<MYK>"),
    ("verb-restore", "git -C <PF> restore .", "<MYK>"),
    ("verb-switch", "git -C <PF> switch main", "<MYK>"),
    ("verb-upper", "git -C <PF> COMMIT -m x", "<MYK>"),
    ("git-exe", "git.exe -C <PF> commit -m x", "<MYK>"),
    ("git-abs-path", "/usr/bin/git -C <PF> commit -m x", "<MYK>"),
    ("git-quoted-path", '"C:\\Program Files\\Git\\cmd\\git.exe" -C <PF> commit -m x', "<MYK>"),
    ("git-quoted-name", "'git' -C <PF> commit -m x", "<MYK>"),
    ("c-option-first", "git -c core.autocrlf=false -C <PF> commit -m x", "<MYK>"),
    ("no-pager-first", "git --no-pager -C <PF> stash", "<MYK>"),
    ("two-C", "git -C <PROJ> -C TheHub-main commit -m x", "<MYK>"),
    ("cd-and", "cd <PF> && git commit -m x", "<MYK>"),
    ("cd-quoted-backslash", 'cd "<PW>"; git reset --hard', "<MYK>"),
    ("cd-two-steps", "cd <PROJ> && cd TheHub-main && git checkout .", "<MYK>"),
    ("cd-relative", "cd ../TheHub-main && git stash", "<MYK>"),
    ("pushd", "pushd <PF> && git stash", "<MYK>"),
    ("cwd-is-hub", "git commit -am x", "<PF>"),
    ("cwd-is-hub-subdir", "git restore .", "<PF>/backend"),
    ("git-dir-eq", "git --git-dir=<PF>/.git --work-tree=<PF> reset", "<MYK>"),
    ("git-dir-space", "git --git-dir <PF>/.git commit -m x", "<MYK>"),
    ("work-tree-only", "git --work-tree=<PF> checkout -- .", "<MYK>"),
    ("GIT_DIR-prefix", "GIT_DIR=<PF>/.git git commit -m x", "<MYK>"),
    ("GIT_WORK_TREE-prefix", "GIT_WORK_TREE=<PF> git checkout .", "<MYK>"),
    ("GIT_DIR-exported", "export GIT_DIR=<PF>/.git && git reset", "<MYK>"),
    ("env-USERPROFILE", 'git -C "$USERPROFILE/' + REL + '" commit -m x', "<MYK>"),
    ("env-HOME-braced", 'git -C "${HOME}/Documents/Projects/TheHub-main" reset', "<MYK>"),
    ("tilde", "git -C ~/Documents/Projects/TheHub-main commit -m x", "<MYK>"),
    ("cd-tilde", "cd ~/Documents/Projects/TheHub-main && git stash", "<MYK>"),
    ("shell-var", 'T=<PF>; git -C "$T" commit -m x', "<MYK>"),
    ("shell-var-exported", "export T=<PF> && git -C $T clean -fd", "<MYK>"),
    ("dotdot-out-of-worktrees", "git -C <WT>/../../../backend commit -m x", "<MYK>"),
    ("worktrees-folder-itself", "git -C <PF>/.claude/worktrees commit -m x", "<MYK>"),
    ("worktrees-not-a-worktree", "git -C <FAKEWT> commit -m x", "<MYK>"),
    ("subst", "x=$(git -C <PF> stash)", "<MYK>"),
    ("subshell", "(cd <PF> && git commit -m x)", "<MYK>"),
    ("bash-c", "bash -c \"cd '<PF>' && git commit -m x\"", "<MYK>"),
    ("sh-c-C", "sh -c 'git -C <PF> reset --hard'", "<MYK>"),
    ("cmd-c-cd", 'cmd /c "cd /d <PW> && git commit -m x"', "<MYK>"),
    ("cmd-c-percent-env", 'cmd /c "git -C %USERPROFILE%\\' + REL_W + ' commit"', "<MYK>"),
    ("pwsh-c-set-location", "pwsh -c \"Set-Location '<PW>'; git commit -m x\"", "<MYK>"),
    ("pwsh-c-env", "pwsh -c 'git -C $env:USERPROFILE\\" + REL_W + " commit'", "<MYK>"),
    ("pwsh-encoded", "pwsh -EncodedCommand <ENC>", "<MYK>"),
    ("pwsh-working-directory", 'pwsh -wd <PF> -c "git commit -m x"', "<MYK>"),
    ("heredoc-to-bash", "bash <<'EOF'\ncd <PF>\ngit commit -m x\nEOF", "<MYK>"),
    ("eval", "eval 'git -C <PF> commit -m x'", "<MYK>"),
]

GIT_ALLOWED = [
    ("status", "git -C <PF> status", "<MYK>"),
    ("log", "git -C <PF> log --oneline -3", "<MYK>"),
    ("diff", "git -C <PF> diff", "<MYK>"),
    ("fetch", "git -C <PF> fetch origin", "<MYK>"),
    ("rev-parse", "git -C <PF> rev-parse HEAD", "<MYK>"),
    ("stash-list", "git -C <PF> stash list", "<MYK>"),
    ("stash-show", "git -C <PF> stash show -p", "<MYK>"),
    ("cd-then-status", "cd <PF> && git status", "<MYK>"),
    ("cwd-hub-status", "git status", "<PF>"),
    ("worktree-commit", "git -C <WT> commit -m x", "<MYK>"),
    ("worktree-reset", "cd <WT> && git reset --hard origin/main", "<MYK>"),
    ("cwd-worktree-commit", "git commit -m x", "<WT>"),
    ("worktree-add", "git -C <PF> worktree list", "<MYK>"),
    ("sibling-name", "git -C <SIB> commit -m x", "<MYK>"),
    ("elsewhere-commit", "git commit -m x", "<MYK>"),
    ("message-mentions", 'git commit -m "do not commit in <PF>"', "<MYK>"),
    (
        "heredoc-message-mentions",
        "git commit -F - <<'EOF'\nNever run git -C <PF> commit.\nEOF",
        "<MYK>",
    ),
    ("ls-hub", "ls <PF>", "<MYK>"),
    ("cd-back-out", "cd <PF> && cd <MYK> && git commit -m x", "<MYK>"),
]


def _git_case(estate: Estate, command: str, cwd: str) -> tuple[str, str]:
    command = estate.fill(command)
    if "<ENC>" in command:
        command = command.replace(
            "<ENC>", _pwsh_encoded(f"git -C '{estate.forms()['<PW>']}' commit -m x")
        )
    return command, estate.fill(cwd)


@pytest.mark.parametrize(("case", "command", "cwd"), cases(GIT_BYPASSES))
def test_git_that_moves_the_live_checkout_is_refused(
    estate: Estate, case: str, command: str, cwd: str
) -> None:
    command, cwd = _git_case(estate, command, cwd)
    assert_blocked(guard_bash(estate, command, cwd), command)


@pytest.mark.parametrize(("case", "command", "cwd"), cases(GIT_ALLOWED))
def test_reading_the_live_checkout_and_working_in_worktrees_pass(
    estate: Estate, case: str, command: str, cwd: str
) -> None:
    command, cwd = _git_case(estate, command, cwd)
    assert_allowed(guard_bash(estate, command, cwd), command)


# In a protected checkout git is allow-listed: the read-only verbs, fetch, and a
# fast-forward-only merge. Everything else is refused, including verbs this file does
# not name. Review of #1051: pull, rebase, cherry-pick and the rest were outside the
# first deny-list and walked straight through.
PROTECTED_DENIED = [
    ("pull", "pull"),
    ("pull-ff-only", "pull --ff-only"),  # pull can still rebase (pull.rebase, -r)
    ("pull-rebase", "pull --rebase origin develop"),
    ("merge", "merge origin/develop"),
    ("merge-no-ff", "merge --no-ff origin/develop"),
    ("merge-ff-only-then-no-ff", "merge --ff-only --no-ff origin/develop"),
    ("merge-ff-only-squash", "merge --ff-only --squash origin/develop"),
    ("merge-ff-only-then-ff", "merge --ff-only --ff origin/develop"),
    ("rebase", "rebase origin/develop"),
    ("cherry-pick", "cherry-pick abc123"),
    ("revert", "revert HEAD"),
    ("am", "am patch.mbox"),
    ("apply", "apply fix.diff"),
    ("rm", "rm deploy.sh"),
    ("mv", "mv a.py b.py"),
    ("commit", "commit -m x"),
    ("reset", "reset --hard"),
    ("checkout", "checkout ."),
    ("switch", "switch main"),
    ("restore", "restore ."),
    ("clean", "clean -fdx"),
    ("stash-bare", "stash"),
    ("stash-push", "stash push"),
    ("stash-drop", "stash drop"),
    ("branch-create", "branch topic"),
    ("branch-delete", "branch -D topic"),
    ("branch-list-then-delete", "branch -D topic --list"),
    ("tag", "tag v1"),
    ("config-set", "config core.hooksPath /tmp/x"),
    ("config-unset", "config --unset user.name"),
    ("remote-add", "remote add evil https://example.invalid/x.git"),
    ("worktree-remove", "worktree remove wt1"),
    ("submodule-update", "submodule update --init"),
    ("gc", "gc --prune=now"),
    ("update-ref", "update-ref refs/heads/main HEAD~1"),
    ("unknown-verb", "frobnicate"),
    ("no-verb", ""),
    ("alias-via-c", "-c alias.x=reset x --hard"),
    ("alias-configured", "ci -m x"),
    ("c-config-runs-code", "-c core.fsmonitor=evil status"),
]

PROTECTED_ALLOWED = [
    ("status", "status"),
    ("log", "log --oneline -5"),
    ("diff", "diff HEAD~1"),
    ("show", "show HEAD"),
    ("fetch", "fetch origin"),
    ("branch-bare", "branch"),
    ("branch-list", "branch --list"),
    ("branch-all-verbose", "branch -a -vv"),
    ("branch-show-current", "branch --show-current"),
    ("rev-parse", "rev-parse HEAD"),
    ("ls-files", "ls-files"),
    ("blame", "blame deploy.sh"),
    ("describe", "describe --tags"),
    ("worktree-list", "worktree list"),
    ("worktree-add", "worktree add .claude/worktrees/wt2 -b wt2"),
    ("worktree-prune", "worktree prune"),
    ("stash-list", "stash list"),
    ("stash-show", "stash show -p"),
    ("config-get", "config --get remote.origin.url"),
    ("remote-v", "remote -v"),
    ("merge-ff-only", "merge --ff-only origin/develop"),
    ("merge-no-ff-then-ff-only", "merge --no-ff --ff-only origin/develop"),
    ("version", "--version"),
    ("c-display-setting", "-c color.ui=never status"),
]


@pytest.mark.parametrize(("case", "args"), cases(PROTECTED_DENIED))
def test_in_the_live_checkout_git_is_allow_listed(estate: Estate, case: str, args: str) -> None:
    command = estate.fill("git -C <PF> " + args).rstrip()
    r = guard_bash(estate, command)
    assert_blocked(r, command)
    # The same command with the live checkout as the working directory.
    assert_blocked(guard_bash(estate, ("git " + args).rstrip(), str(estate.hub)), args)


@pytest.mark.parametrize(("case", "args"), cases(PROTECTED_ALLOWED))
def test_in_the_live_checkout_read_only_git_passes(estate: Estate, case: str, args: str) -> None:
    command = estate.fill("git -C <PF> " + args)
    assert_allowed(guard_bash(estate, command), command)
    assert_allowed(guard_bash(estate, "git " + args, str(estate.hub)), args)


def test_outside_the_live_checkout_git_is_not_restricted(estate: Estate) -> None:
    for args in ("pull --rebase", "rebase origin/main", "cherry-pick abc", "ci -m x"):
        assert_allowed(guard_bash(estate, "git " + args), args)


def test_monitor_commands_are_guarded_too(estate: Estate) -> None:
    # Monitor runs a shell command as Bash does, with the same tool_input.command.
    assert_blocked(guard_bash(estate, "ruff format .", tool="Monitor"), "ruff format")
    command = estate.fill("git -C <PF> reset --hard")
    assert_blocked(guard_bash(estate, command, tool="Monitor"), command)
    assert_allowed(guard_bash(estate, "ruff check .", tool="Monitor"), "ruff check")


@pytest.mark.skipif(not IS_WINDOWS, reason="the /c/... spelling is Git Bash's, on a drive path")
def test_git_with_the_msys_drive_spelling_is_refused(estate: Estate) -> None:
    for command in ("git -C <PM> commit -m x", "cd <PM> && git stash"):
        command = estate.fill(command)
        assert_blocked(guard_bash(estate, command), command)


POWERSHELL_TOOL_GIT = [
    ("env-path", "git -C $env:USERPROFILE\\Documents\\Projects\\TheHub-main commit -m x"),
    ("env-path-braced", "git -C ${env:USERPROFILE}/Documents/Projects/TheHub-main reset --hard"),
    ("set-location", "Set-Location '<PW>'; git reset --hard"),
    ("set-location-path", "Set-Location -Path <PW> ; git stash"),
    ("push-location", "Push-Location <PW>; git checkout ."),
    ("call-op-exe", "& 'git.exe' -C '<PW>' stash"),
    ("cmd-percent", 'cmd /c "git -C %USERPROFILE%\\Documents\\Projects\\TheHub-main commit"'),
    ("ps-variable", "$t = '<PW>'; git -C $t commit -m x"),
]


@pytest.mark.parametrize(("case", "command"), cases(POWERSHELL_TOOL_GIT))
def test_git_through_the_powershell_tool_is_refused(
    estate: Estate, case: str, command: str
) -> None:
    command = estate.fill(command)
    assert_blocked(guard_bash(estate, command, tool="PowerShell"), command)


def test_git_status_through_the_powershell_tool_passes(estate: Estate) -> None:
    command = estate.fill("Set-Location '<PW>'; git status; git log -1")
    assert_allowed(guard_bash(estate, command, tool="PowerShell"), command)


def test_the_protected_checkout_comes_from_the_environment(estate: Estate, tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / "live"
    other.mkdir(parents=True)
    env = {**estate.env, "MYKRONOS_PROTECTED_CHECKOUTS": str(other)}
    blocked = f'git -C "{other}" commit -m x'
    assert_blocked(guard_bash(estate, blocked, env=env), blocked)
    # The setting replaces the default; it does not add to it.
    default = estate.fill("git -C <PF> commit -m x")
    assert_allowed(guard_bash(estate, default, env=env), default)


def test_several_protected_checkouts_separated_by_semicolons(
    estate: Estate, tmp_path: Path
) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    env = {**estate.env, "MYKRONOS_PROTECTED_CHECKOUTS": f"{a};{b}"}
    for target in (a, b):
        command = f'git -C "{target}" reset --hard'
        assert_blocked(guard_bash(estate, command, env=env), command)


def test_the_block_message_names_the_checkout_and_the_way_out(estate: Estate) -> None:
    r = guard_bash(estate, estate.fill("git -C <PF> commit -m x"))
    assert_blocked(r, "commit")
    assert "TheHub-main" in r.stderr
    assert "worktree" in r.stderr


# ── 3. Write and Edit inside the live checkout ──────────────────────────────

WRITE_BYPASSES = [
    ("Write", "backslash", "<PW>\\backend\\main.py", "<MYK>"),
    ("Write", "forward", "<PF>/backend/main.py", "<MYK>"),
    ("Write", "upper", "<PU>/BACKEND/MAIN.PY", "<MYK>"),
    ("Write", "top-level-file", "<PF>/deploy.sh", "<MYK>"),
    ("Write", "dotdot-in", "<PROJ>/mykronos/../TheHub-main/deploy.sh", "<MYK>"),
    ("Write", "dotdot-out-of-worktrees", "<WT>/../../settings.json", "<MYK>"),
    ("Write", "claude-settings", "<PF>/.claude/settings.json", "<MYK>"),
    ("Write", "relative-from-cwd", "backend/main.py", "<PF>"),
    ("Write", "relative-dotdot", "../TheHub-main/backend/main.py", "<MYK>"),
    ("Write", "tilde", "~/Documents/Projects/TheHub-main/x.py", "<MYK>"),
    ("Write", "env-var", "$USERPROFILE/Documents/Projects/TheHub-main/x.py", "<MYK>"),
    ("Write", "percent-env", "%USERPROFILE%\\Documents\\Projects\\TheHub-main\\x.py", "<MYK>"),
    ("Edit", "edit", "<PW>\\frontend\\sw.js", "<MYK>"),
    ("MultiEdit", "multiedit", "<PF>/backend/models.py", "<MYK>"),
    ("NotebookEdit", "notebook", "<PF>/notes.ipynb", "<MYK>"),
]

WRITE_ALLOWED = [
    ("Write", "worktree", "<WT>/backend/main.py", "<MYK>"),
    ("Edit", "worktree-backslash", "<WT>\\backend\\main.py", "<MYK>"),
    ("Write", "worktree-relative", "backend/main.py", "<WT>"),
    ("Write", "sibling-name", "<SIB>/deploy.sh", "<MYK>"),
    ("Write", "mykronos", "<MYK>/backend/x.py", "<MYK>"),
    ("Edit", "elsewhere", "<PROFILE>/notes.md", "<MYK>"),
]


def write_payload(tool: str, path: str, cwd: str) -> dict[str, Any]:
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    tool_input: dict[str, Any] = {key: path}
    if tool == "Write":
        tool_input["content"] = "x = 1\n"
    elif tool == "Edit":
        tool_input.update(old_string="a", new_string="b")
    elif tool == "MultiEdit":
        tool_input["edits"] = [{"old_string": "a", "new_string": "b"}]
    else:
        tool_input["new_source"] = "x = 1"
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd,
    }


@pytest.mark.parametrize(("tool", "case", "path", "cwd"), cases(WRITE_BYPASSES))
def test_writing_inside_the_live_checkout_is_refused(
    estate: Estate, tool: str, case: str, path: str, cwd: str
) -> None:
    assert_blocked(guard_write(estate, tool, estate.fill(path), estate.fill(cwd)), path)


@pytest.mark.parametrize(("tool", "case", "path", "cwd"), cases(WRITE_ALLOWED))
def test_writing_in_worktrees_and_elsewhere_passes(
    estate: Estate, tool: str, case: str, path: str, cwd: str
) -> None:
    assert_allowed(guard_write(estate, tool, estate.fill(path), estate.fill(cwd)), path)


@pytest.mark.skipif(not IS_WINDOWS, reason="the /c/... spelling is Git Bash's, on a drive path")
def test_writing_with_the_msys_drive_spelling_is_refused(estate: Estate) -> None:
    path = estate.fill("<PM>/backend/main.py")
    assert_blocked(guard_write(estate, "Write", path, str(estate.mykronos)), path)


# ── Without Python the guards still refuse the obvious forms ────────────────


def test_without_python_the_bash_guard_falls_back_to_refusing(estate: Estate) -> None:
    env = {**estate.env, "MYKRONOS_HOOK_PYTHON": str(estate.profile / "no-such-python")}
    for command in ("ruff format .", estate.fill("git -C <PF> commit -m x")):
        assert_blocked(guard_bash(estate, command, env=env), command)
    assert_allowed(guard_bash(estate, "ruff check .", env=env), "ruff check")


def test_without_python_the_write_guard_falls_back_to_refusing(estate: Estate) -> None:
    env = {**estate.env, "MYKRONOS_HOOK_PYTHON": str(estate.profile / "no-such-python")}
    myk = str(estate.mykronos)
    blocked = estate.fill("<PW>\\backend\\main.py")
    assert_blocked(guard_write(estate, "Write", blocked, myk, env=env), blocked)
    allowed = estate.fill("<WT>/backend/main.py")
    assert_allowed(guard_write(estate, "Write", allowed, myk, env=env), allowed)


# ── 4. Every .ps1 an agent writes is parsed ─────────────────────────────────


def ps1_payload(path: Path, tool: str = "Write") -> dict[str, Any]:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": tool,
        "tool_input": {"file_path": str(path)},
        "tool_response": {"filePath": str(path), "success": True},
        "cwd": str(path.parent),
    }


@needs_pwsh
@pytest.mark.parametrize("tool", ["Write", "Edit", "MultiEdit"])
def test_a_ps1_that_does_not_parse_is_reported_to_the_agent(
    estate: Estate, tmp_path: Path, tool: str
) -> None:
    script = tmp_path / "Broken.ps1"
    script.write_text("$x = 1\nif ($x -eq 1 {\n  Write-Output 'one'\n}\n", encoding="utf-8")
    r = run_hook("check-ps1.sh", ps1_payload(script, tool), estate.env)
    assert r.returncode == 2, r.stderr
    assert "Broken.ps1" in r.stderr
    assert ":2:" in r.stderr  # the line the parser points at


@needs_pwsh
@pytest.mark.parametrize("name", ["Good.ps1", "Module.psm1", "UPPER.PS1", "with space.ps1"])
def test_a_ps1_that_parses_passes(estate: Estate, tmp_path: Path, name: str) -> None:
    script = tmp_path / name
    script.write_text("param([string]$Name = 'x')\nWrite-Output \"hi $Name\"\n", encoding="utf-8")
    r = run_hook("check-ps1.sh", ps1_payload(script), estate.env)
    assert r.returncode == 0, r.stderr


@needs_pwsh
def test_a_hostile_file_name_is_data_not_code(estate: Estate, tmp_path: Path) -> None:
    # The path reaches pwsh through the environment, never spliced into -Command.
    marker = tmp_path / "pwned.txt"
    name = "a'; Set-Content -Path pwned.txt -Value x; '.ps1"
    if IS_WINDOWS:
        name = "a'$(Set-Content -Path pwned.txt -Value x)'.ps1"
    script = tmp_path / name
    script.write_text("if ( {\n", encoding="utf-8")
    payload = ps1_payload(script)
    assert BASH is not None
    r = subprocess.run(
        [BASH, str(HOOKS / "check-ps1.sh")],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=estate.env,
        cwd=tmp_path,
        timeout=60,
    )
    assert r.returncode == 2, r.stderr
    assert not marker.exists()


def test_a_non_powershell_file_is_not_parsed(estate: Estate, tmp_path: Path) -> None:
    other = tmp_path / "notes.py"
    other.write_text("if ( {\n", encoding="utf-8")
    assert run_hook("check-ps1.sh", ps1_payload(other), estate.env).returncode == 0


def test_a_missing_ps1_is_not_an_error(estate: Estate, tmp_path: Path) -> None:
    assert run_hook("check-ps1.sh", ps1_payload(tmp_path / "gone.ps1"), estate.env).returncode == 0


# ── Wiring ──────────────────────────────────────────────────────────────────


def _commands(event: str, matcher_has: str) -> list[str]:
    settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
    out: list[str] = []
    for group in settings["hooks"][event]:
        if matcher_has in group.get("matcher", "").split("|"):
            out += [h["command"] for h in group["hooks"]]
    return out


@pytest.mark.parametrize(
    ("event", "tool", "hook"),
    [
        ("PreToolUse", "Bash", "guard-bash.sh"),
        ("PreToolUse", "PowerShell", "guard-bash.sh"),
        ("PreToolUse", "Monitor", "guard-bash.sh"),
        ("PreToolUse", "Write", "guard-write.sh"),
        ("PreToolUse", "Edit", "guard-write.sh"),
        ("PreToolUse", "MultiEdit", "guard-write.sh"),
        ("PreToolUse", "NotebookEdit", "guard-write.sh"),
        ("PostToolUse", "Write", "check-ps1.sh"),
        ("PostToolUse", "Edit", "check-ps1.sh"),
        ("PostToolUse", "MultiEdit", "check-ps1.sh"),
    ],
)
def test_the_project_settings_wire_each_guard(event: str, tool: str, hook: str) -> None:
    commands = _commands(event, tool)
    assert any(f"$CLAUDE_PROJECT_DIR/.claude/hooks/{hook}" in c for c in commands), commands


@pytest.mark.parametrize(
    "name", ["guard-bash.sh", "guard-write.sh", "check-ps1.sh", "_guard-common.sh"]
)
def test_the_hook_scripts_have_unix_line_endings(name: str) -> None:
    # A Windows checkout with core.autocrlf turns LF into CRLF unless .gitattributes
    # says otherwise, and bash then fails on $'\r' before it reaches a rule.
    assert b"\r" not in (HOOKS / name).read_bytes()
