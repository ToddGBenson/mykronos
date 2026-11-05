r"""Harness guards for this estate: the logic behind guard-bash.sh, guard-write.sh and
check-ps1.sh (TheHub #61099, #61108).

Four mistakes kept recurring because the lesson lived only in an agent's memory:

  1. `ruff format`. The tree was never formatted with it; one run rewrites over a
     hundred files and buries the real diff.
  2. git that changes the live TheHub checkout. The production deploy ships that
     working tree, so moving it moves production. Inside it git is allow-listed:
     read-only verbs, `fetch`, and `merge --ff-only`; every other verb, an unknown
     verb and any alias is refused. Its own `.claude/worktrees/<name>` folders are
     separate worktrees and are not restricted.
  3. Writing inside that checkout: with the Write, Edit, MultiEdit and NotebookEdit
     tools, and (#61108) from the shell: a redirection (`>`, `>>`, `2>`, `&>`,
     `*>`), `sed -i`, `perl -i`, `tee`, `cp`, `mv`, `rm`, `touch`, `mkdir`, `dd of=`,
     `Set-Content`, `Add-Content`, `Out-File`, `Tee-Object`, `Copy-Item`,
     `Move-Item`, `Remove-Item`, `New-Item` and their aliases, and cmd's `copy`,
     `move` and `del`. A copy out of the checkout is a read and passes.
  4. (PostToolUse) Saving a PowerShell script that does not parse.

Pattern: keel's .claude/hooks/guard-bash.sh. A PreToolUse hook that exits 2 refuses
the call and its stderr goes back to the agent.

What it reads. keel and binnacle's selftest passed while four bypasses were live,
because a regex over the command text cannot tell quoted text from a word. This splits
on the real separators; follows `$(...)`, backticks, subshells and heredocs; removes
quoting the way bash, cmd or PowerShell does, decoding `$'\x67it'`; expands the
variables it can see (environment, `~`, `${x:-default}`, and assignments earlier in
the same command); follows `cd`, `pushd`, `Set-Location`, `env -C` and the payload's
cwd; unwraps `env`, `nice`, `command`, `exec`, `time`, `sudo`, `timeout` and `xargs`
with their flags; and re-reads a command passed to `bash -c`, `sh -c`, `eval`,
`cmd /c`, `pwsh -c`, `pwsh -EncodedCommand`, `Invoke-Expression` or a `<<<` here-string.

A command piped into an interpreter (`| bash`, `| sh`, `| iex`, `| pwsh`) is judged by
what the pipe carries: the text of an `echo`, `printf`, `Write-Output` or a PowerShell
string, or the file a `cat` or `Get-Content` reads. Anything else (`curl`, a filter, a
variable) is refused, since nothing here can say what it will run.

A command word it cannot resolve (`$(...)`, an unset `$X`, `${x/a/b}`, `{a,b}`, a
PowerShell `& $var`) is refused when the working directory or any argument is inside
a protected checkout, and passes elsewhere. A write target only partly resolvable
("$HUB/$f", `$HUB/{a,b}`, `<projects>/TheHub-ma$X`) is judged by the working directory
and by the directory its resolvable prefix names. A redirection to a command
substitution (`> $(echo p)`) is judged by what an `echo` or `printf` there prints, and
refused when that cannot be known. Inside bash's `[[ ... ]]`, `>` and `<` compare
strings and are not redirections.

Paths are compared after canonicalisation: case, `\` or `/`, `..`, the MSYS
`/c/...` spelling, `\\?\`, `\\.\` and `\\localhost\c$` (also `127.0.0.1` and this
computer's name), trailing dots and spaces (which Windows drops), 8.3 short names
(`THEHUB~1`, matched both by the real short name and by its pattern), globs (a
component that could match the checkout counts as the checkout), and junctions and
symlinks through realpath.

What it still does not catch. This guards against an agent's ordinary mistakes, not a
determined bypass. Known gaps: `~user`; a script run by file name (`bash x.sh`,
`pwsh -File x.ps1`, `python x.py`); writes by other programs (python, node, git
apply from elsewhere with --directory); `Invoke-Command`/`ForEach-Object` script
blocks, `Start-Process` and `find -exec`; and a path built at run time.

When a hook cannot block. Claude Code refuses a tool call only when the hook exits 2.
Any other outcome is a non-blocking error and the call runs:
  * The hook times out. settings.json gives each guard a `timeout` (30 s), and the
    guard keeps its own deadline inside it (DEFAULT_DEADLINE_SECONDS, 20 s; override
    with MYKRONOS_HOOK_DEADLINE_SECONDS). Past the deadline it refuses (exit 2), so a
    slow read, such as realpath on a hung network path, fails closed instead of
    timing out open.
  * bash is missing. Each hook command is `bash "<script>"`; when bash is not on PATH
    the command cannot start (exit 127) and nothing inside the hook runs to stop the
    call. This cannot fail closed from here. Claude Code on Windows itself needs Git
    for Windows' bash, so check `bash --version` after any reinstall.
  * Python is missing or crashes. The wrapper sees an exit other than 0 or 2 and
    applies its coarse fallback, which fails closed on the obvious forms.

The protected checkouts are MYKRONOS_PROTECTED_CHECKOUTS (separated by ';'), or by
default <user profile>/Documents/Projects/TheHub-main, the profile read from
USERPROFILE, then HOME.

Usage (stdin is the hook payload):  python estate_guard.py bash|write|ps1
Exit 0 allows, 2 blocks (stderr to the agent), 3 is an internal error: the shell
wrapper then applies its coarse fallback, so a bug here fails closed on the obvious
forms rather than open.
"""

from __future__ import annotations

import base64
import fnmatch
import functools
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

IS_WINDOWS = os.name == "nt"
PROTECTED_ENV = "MYKRONOS_PROTECTED_CHECKOUTS"
DEFAULT_CHECKOUT = ("Documents", "Projects", "TheHub-main")
# Inside a protected checkout git is allow-listed (review of #1051): these verbs, plus
# the argument-checked ones in git_allowed(). Anything else, an unknown verb or an
# alias included, is refused. `pull` is not here: it can rebase (--rebase, -r, or a
# pull.rebase setting), so fetch then merge --ff-only.
GIT_READ_ONLY = frozenset({
    "status", "log", "diff", "show", "fetch", "rev-parse", "ls-files", "blame",
    "describe", "shortlog", "rev-list", "ls-tree", "ls-remote", "cat-file",
    "for-each-ref", "show-ref", "merge-base", "name-rev", "grep", "help", "version",
    "check-ignore",
})
GIT_INFO_FLAGS = frozenset({"--version", "--help", "-h", "--html-path", "--man-path",
                            "--info-path"})
BRANCH_WRITE_FLAGS = frozenset({
    "--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream",
    "--edit-description", "--track", "--no-track", "--create-reflog", "--recurse-submodules",
})
BRANCH_VALUE_FLAGS = frozenset({"--contains", "--no-contains", "--merged", "--no-merged",
                                "--points-at", "--sort", "--format"})
CONFIG_READ_FLAGS = frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch",
                               "--list", "-l"})
CONFIG_WRITE_FLAGS = frozenset({"--unset", "--unset-all", "--add", "--replace-all",
                                "--rename-section", "--remove-section", "--edit", "-e"})
# `git -c key=value` in a protected checkout: only display settings. An alias, a
# hook path, a pager or an fsmonitor can run a command.
SAFE_CONFIG_PREFIXES = ("color.", "core.quotepath=")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "busybox"}
POWERSHELLS = {"pwsh", "powershell", "pwsh-preview"}
CD_COMMANDS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
# Words that only introduce the command after them. `exec`, `command`, `nice`, `time`,
# `sudo` and `doas` take flags, so they are unwrapped in check_words() instead.
PREFIX_WORDS = {
    "{", "}", "(", ")", "!", "&", ".", "call", "then", "do", "else", "if", "elif", "while",
    "until", "nohup", "builtin", "noglob",
}
# Inside the deadline Claude Code gives the hook (settings.json `timeout`), so the guard
# refuses on its own before the harness times it out and lets the call run.
DEFAULT_DEADLINE_SECONDS = 20.0
DEADLINE_ENV = "MYKRONOS_HOOK_DEADLINE_SECONDS"
# Redirection targets that are not files.
NOT_FILES = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/zero",
                       "nul", "nul:", "con", "con:", "$null"})
GLOB_CHARS = re.compile(r"[*?\[]")
SHORT_NAME = re.compile(r"^([^~]{1,6})~\d{1,6}(?:\.[^.]{0,3})?$")
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
PS_ASSIGN = re.compile(r"^\$(?:\{)?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?$", re.I)
MAX_DEPTH = 8


class BlockedError(Exception):
    pass


_deadline = float("inf")


def _tick() -> None:
    """Refuse once the guard's own deadline has passed (see "When a hook cannot block")."""
    if time.monotonic() >= _deadline:
        raise BlockedError(
            "the guard ran out of time before it finished reading this command, and a "
            "guard that times out would let it run. Split the command up and retry."
        )


def start_deadline(hook: str) -> None:
    """Start the guard's deadline, and a backstop that refuses if the guard hangs past it
    (in realpath on a dead network path, say) without reaching a _tick()."""
    global _deadline
    try:
        seconds = float(os.environ.get(DEADLINE_ENV) or DEFAULT_DEADLINE_SECONDS)
    except ValueError:
        seconds = DEFAULT_DEADLINE_SECONDS
    _deadline = time.monotonic() + seconds

    def expire() -> None:
        block(hook, "the guard did not finish within its deadline, and a hook that times "
                    "out would let the call run. Split the command up and retry.")
        sys.stderr.flush()
        os._exit(2)

    timer = threading.Timer(max(seconds, 0.0) + 1.0, expire)
    timer.daemon = True
    timer.start()


# ── Paths ───────────────────────────────────────────────────────────────────


def profile_dir() -> str:
    return os.environ.get("USERPROFILE") or os.environ.get("HOME") or os.path.expanduser("~")


def home_dir() -> str:
    return os.environ.get("HOME") or os.environ.get("USERPROFILE") or os.path.expanduser("~")


def _local_hosts() -> set[str]:
    names = {"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}
    for name in (os.environ.get("COMPUTERNAME", ""), platform.node()):
        if name:
            names.add(name.lower())
            names.add(name.split(".", 1)[0].lower())
    return names


def _unc_to_drive(p: str) -> str:
    """`//?/C:/x`, `//./C:/x`, `//?/UNC/localhost/c$/x` and `//localhost/c$/x` as C:/x.

    A share on another machine is left as it is: it is not this checkout.
    """
    if not p.startswith("//"):
        return p
    m = re.match(r"^//[?.]/([A-Za-z]:(?:/.*)?)$", p)
    if m:
        return m.group(1)
    m = re.match(r"^//[?.]/unc/(.*)$", p, re.I)
    if m:
        p = "//" + m.group(1)
    m = re.match(r"^//([^/]+)/([A-Za-z])\$(/.*)?$", p)
    if m and m.group(1).lower() in _local_hosts():
        return f"{m.group(2)}:{m.group(3) or '/'}"
    return p


def norm(path: str, base: str | None) -> str:
    """An absolute, '/'-separated path with . and .. resolved. Case is kept."""
    p = _unc_to_drive(path.strip().replace("\\", "/"))
    if IS_WINDOWS:
        m = re.match(r"^/(?:mnt/|cygdrive/)?([A-Za-z])(?=/|$)(.*)$", p)
        if m:
            p = f"{m.group(1)}:{m.group(2) or '/'}"
    if re.match(r"^[A-Za-z]:(?!/)", p):  # C: or a drive-relative C:foo
        p = p[:2] + "/" + p[2:]
    if not (p.startswith("/") or re.match(r"^[A-Za-z]:/", p)):
        p = (norm(base, None) if base else norm(profile_dir(), None)) + "/" + p
    drive, rest = (p[:2], p[2:]) if re.match(r"^[A-Za-z]:", p) else ("", p)
    parts: list[str] = []
    for part in rest.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return drive + "/" + "/".join(parts)


def protected_roots() -> list[str]:
    raw = os.environ.get(PROTECTED_ENV, "").strip()
    if raw:
        items = [i.strip() for i in re.split(r"[;\n]", raw) if i.strip()]
        return [norm(expand_vars(i, {}), profile_dir()) for i in items]
    return [norm("/".join((profile_dir().replace("\\", "/"), *DEFAULT_CHECKOUT)), None)]


def _plain(component: str) -> str:
    """A path component as Windows reads it: case folded, trailing dots and spaces gone."""
    stripped = component.rstrip(". ")
    return (stripped or component).lower()


def _same_component(candidate: str, real: str) -> bool:
    """Whether `candidate` can name the component `real`: equal, a glob that matches
    it, or an 8.3 short name (THEHUB~1) whose stem it starts with."""
    c, r = _plain(candidate), real.lower()
    if c == r:
        return True
    if GLOB_CHARS.search(c) and fnmatch.fnmatchcase(r, c):
        return True
    m = SHORT_NAME.match(c)
    return m is not None and re.sub(r"[ .]", "", r).startswith(m.group(1))


def _split(path: str) -> tuple[str, list[str]]:
    drive, rest = (path[:2].lower(), path[2:]) if re.match(r"^[A-Za-z]:", path) else ("", path)
    return drive, [p for p in rest.split("/") if p]


def _below(path: str, root: str) -> list[str] | None:
    """The components of `path` below `root`, or None if it is not inside it."""
    pd, pp = _split(path)
    rd, rp = _split(root)
    if pd != rd or len(pp) < len(rp):
        return None
    if all(_same_component(c, r) for c, r in zip(pp, rp, strict=False)):
        return pp[len(rp):]
    return None


@functools.lru_cache(maxsize=256)
def _realpath(path: str) -> str | None:
    """The path with links, junctions and short names resolved, or None if it cannot be."""
    if GLOB_CHARS.search(path) or not os.path.isabs(path):
        return None
    _tick()
    try:
        return norm(os.path.realpath(path), None)
    except (OSError, ValueError):
        return None


def _spellings(path: str) -> list[str]:
    real = _realpath(path)
    return [path] if real is None or real.lower() == path.lower() else [path, real]


def protected_root_for(path: str, *, for_git: bool) -> str | None:
    """The protected checkout this normalised path is in, or None.

    `<root>/.claude/worktrees/<name>/...` is a separate worktree and is not protected.
    For git it must also be one: a folder there without a .git entry makes git walk
    up to the live checkout. Both the path as written and its realpath are compared,
    against both spellings of each root; any match that is not a worktree protects it.
    """
    _tick()
    for root in protected_roots():
        for r in _spellings(root):
            for candidate in _spellings(path):
                rel = _below(candidate, r)
                if rel is None:
                    continue
                if len(rel) >= 3 and _plain(rel[0]) == ".claude" and _plain(rel[1]) == "worktrees":
                    if not for_git:
                        continue
                    worktree = r.rstrip("/") + "/" + "/".join(rel[:3])
                    if os.path.isdir(worktree) and not os.path.exists(worktree + "/.git"):
                        return root
                    continue
                return root
    return None


def refuse_write(path: str, what: str) -> None:
    """Refuse `what` if it writes `path` (normalised) inside a protected checkout."""
    root = protected_root_for(path, for_git=False)
    if root:
        raise BlockedError(
            f"`{what}` writes {path}, which is inside the live checkout {root}. The "
            "production deploy ships that working tree. Make the change in a worktree "
            "under its .claude/worktrees/ folder and open a pull request."
        )


# ── Words ───────────────────────────────────────────────────────────────────


def lookup(name: str, local: dict[str, str]) -> str | None:
    for k, v in local.items():
        if k.lower() == name.lower():
            return v
    if name in os.environ:
        return os.environ[name]
    for k, v in os.environ.items():
        if k.lower() == name.lower():
            return v
    return None


def expand_vars(word: str, local: dict[str, str]) -> str:
    def sub(m: re.Match[str]) -> str:
        value = lookup(m.group(1), local)
        return m.group(0) if value is None else value

    def default(m: re.Match[str]) -> str:
        # ${x:-word} ${x-word} ${x:=word} ${x=word} ${x:+word} ${x+word}
        value = lookup(m.group(1), local)
        op, alt = m.group(2), expand_vars(m.group(3), local)
        is_set = value is not None and (value != "" or ":" not in op)
        if op[-1] in "-=":
            return value if is_set and value is not None else alt
        return alt if is_set else ""

    w = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-=+])([^{}]*)\}", default, word)
    w = re.sub(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}", sub, w, flags=re.I)
    w = re.sub(r"\$env:([A-Za-z_][A-Za-z0-9_]*)", sub, w, flags=re.I)
    w = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, w)
    w = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", sub, w)
    w = re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%", sub, w)
    if w == "~" or w.startswith(("~/", "~\\")):
        w = home_dir() + w[1:]
    return w


def basename(word: str) -> str:
    """The program a word names: last path component, lower case, no .exe."""
    b = word.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".com"):
        if b.endswith(ext):
            b = b[: -len(ext)]
    return b


ANSI_C_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
ANSI_C_ESCAPE = re.compile(
    r"\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|c.|.)", re.S
)
ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
                 "r": "\r", "t": "\t", "v": "\v"}


def _ansi_c(m: re.Match[str]) -> str:
    """bash's $'...' quoting, decoded and re-quoted as a plain '...' string."""

    def esc(e: re.Match[str]) -> str:
        code = e.group(1)
        if code[0] in "xuU" and len(code) > 1:
            return chr(int(code[1:], 16))
        if code[0] in "01234567":
            return chr(int(code, 8) & 0xFF)
        if code[0] == "c" and len(code) == 2:
            return chr(ord(code[1].upper()) ^ 0x40)
        return ANSI_C_SIMPLE.get(code, code)

    body = ANSI_C_ESCAPE.sub(esc, m.group(1))
    return "'" + body.replace("'", "'\\''") + "'"


def unresolved(word: str, mode: str) -> bool:
    """Whether a word still holds something only the shell can work out at run time:
    a command substitution, a variable it could not expand, or a brace expansion."""
    if "__SUBST__" in word or "`" in word and mode == "bash":
        return True
    if re.search(r"\$(?:[A-Za-z_{(]|env:)", word, re.I):
        return True
    if mode == "bash" and re.search(r"\{[^{}]*,[^{}]*\}", word):
        return True
    return mode == "cmd" and bool(re.search(r"%[A-Za-z_][A-Za-z0-9_]*%", word))


def split_words(text: str, mode: str) -> list[str]:
    """Words as the shell passes them to the program, quoting removed."""
    if mode == "bash":
        text = ANSI_C_QUOTE.sub(_ansi_c, text).replace('$"', '"')
        try:
            return shlex.split(text, posix=True)
        except ValueError:
            return text.replace('"', " ").replace("'", " ").split()
    if mode == "cmd":
        text = text.replace("^", "")
        quotes = '"'
    else:  # pwsh: the backtick is the escape character
        text = re.sub(r"`(.)", r"\1", text, flags=re.S)
        quotes = "'\""
    lex = shlex.shlex(text, posix=True)
    lex.whitespace_split = True
    lex.escape = ""
    lex.quotes = quotes
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return text.replace('"', " ").replace("'", " ").split()


# ── Command structure ───────────────────────────────────────────────────────


@dataclass
class Segment:
    text: str
    heredocs: list[str] = field(default_factory=list)
    # The raw target of each output redirection (>, >>, 2>, &>, *>), quoting kept.
    redirects: list[str] = field(default_factory=list)
    # The text of the command piped into this one (`a | b`: a's text, on b), if any.
    piped_from: str | None = None


@dataclass
class Parsed:
    segments: list[Segment] = field(default_factory=list)
    nested: list[Parsed] = field(default_factory=list)


def _read_heredoc_word(s: str, i: int) -> tuple[str, bool, bool, int]:
    """At s[i:] == '<<': the delimiter, whether it was quoted, whether <<-, and the end."""
    j = i + 2
    dash = j < len(s) and s[j] == "-"
    if dash:
        j += 1
    while j < len(s) and s[j] in " \t":
        j += 1
    k = j
    while k < len(s) and s[k] not in " \t\n;&|<>()":
        k += 1
    raw = s[j:k]
    word = raw.replace("'", "").replace('"', "").replace("\\", "")
    return word, raw != word, dash, k


def _read_target(s: str, j: int, mode: str) -> tuple[str, int, list[Parsed]]:
    """The raw word at s[j:] that a redirection writes to, where it ends, and the
    command substitutions inside it (`> $(echo x)` is one word, not `$` then a
    subshell)."""
    k, quote = j, None
    nested: list[Parsed] = []
    while k < len(s):
        c = s[k]
        if quote != "'" and mode in ("bash", "pwsh") and s.startswith("$(", k):
            sub, k = parse(s, mode, k + 2, ")")
            nested.append(sub)
            continue
        if quote != "'" and mode == "bash" and c == "`":
            sub, k = parse(s, mode, k + 1, "`")
            nested.append(sub)
            continue
        if quote:
            if c == quote:
                quote = None
        elif (mode == "bash" and c == "\\" or mode == "pwsh" and c == "`") and k + 1 < len(s):
            k += 1
        elif c in "'\"" and (c == '"' or mode != "cmd"):
            quote = c
        elif c in " \t\n;&|()<>":
            break
        k += 1
    return s[j:k], k, nested


def parse(s: str, mode: str, i: int = 0, closer: str | None = None) -> tuple[Parsed, int]:
    """Split s into simple commands. Returns at an unmatched `closer` (')' or '`')."""
    out = Parsed()
    cur: list[str] = []
    heredocs: list[str] = []
    redirects: list[str] = []
    piped_from: str | None = None
    pending: list[tuple[str, bool, bool]] = []
    quote: str | None = None
    depth = 0
    n = len(s)
    at_word_start = True
    in_test = False  # inside bash's [[ ... ]], where > compares strings

    def flush() -> None:
        nonlocal cur, heredocs, redirects, piped_from
        text = "".join(cur)
        if text.strip() or heredocs or redirects:
            out.segments.append(Segment(text, heredocs, redirects, piped_from))
        cur, heredocs, redirects, piped_from = [], [], [], None

    while i < n:
        c = s[i]
        if quote == "'":
            cur.append(c)
            if c == "'":
                quote = None
            i += 1
            continue
        if mode == "bash" and c == "\\" and i + 1 < n:
            cur.append(s[i : i + 2])
            i += 2
            at_word_start = False
            continue
        if mode == "pwsh" and c == "`" and i + 1 < n:
            cur.append(s[i : i + 2])
            i += 2
            continue
        if mode in ("bash", "pwsh") and c == "$" and s.startswith("(", i + 1):
            sub, i = parse(s, mode, i + 2, ")")
            out.nested.append(sub)
            cur.append("__SUBST__")
            continue
        if mode == "bash" and c == "$" and s.startswith("{", i + 1):
            j = s.find("}", i)
            j = n - 1 if j < 0 else j
            cur.append(s[i : j + 1])
            i = j + 1
            continue
        if mode == "bash" and c == "`":
            if closer == "`" and quote is None:
                flush()
                return out, i + 1
            sub, i = parse(s, mode, i + 1, "`")
            out.nested.append(sub)
            cur.append("__SUBST__")
            continue
        if quote == '"':
            cur.append(c)
            if c == '"':
                quote = None
            i += 1
            continue
        # Unquoted from here on.
        if c == "'" and mode != "cmd":
            quote = "'"
            cur.append(c)
            i += 1
            continue
        if c == '"':
            quote = '"'
            cur.append(c)
            i += 1
            continue
        if c == "#" and at_word_start and mode in ("bash", "pwsh"):
            j = s.find("\n", i)
            i = n if j < 0 else j
            continue
        if mode == "bash" and s.startswith("<<<", i):  # a here-string: the next word
            cur.append("<<<")
            i += 3
            continue
        if mode == "bash" and s.startswith("<<", i):
            word, quoted, dash, k = _read_heredoc_word(s, i)
            if word:
                pending.append((word, quoted, dash))
            cur.append(s[i:k])
            i = k
            continue
        if c == "\n" and pending:
            i += 1
            for word, quoted, dash in pending:
                lines: list[str] = []
                while i < n:
                    j = s.find("\n", i)
                    line = s[i:] if j < 0 else s[i:j]
                    i = n if j < 0 else j + 1
                    if (line.lstrip("\t") if dash else line) == word:
                        break
                    lines.append(line)
                body = "\n".join(lines)
                heredocs.append(body)
                if not quoted:  # an unquoted heredoc still runs $(...) and backticks
                    out.nested.extend(_substitutions(body))
            pending = []
            flush()
            at_word_start = True
            continue
        if mode == "bash" and at_word_start and re.match(r"\[\[(?=[ \t\n])", s[i:]):
            in_test = True
            cur.append("[[")
            i += 2
            continue
        if in_test and s.startswith("]]", i):
            in_test = False
            cur.append("]]")
            i += 2
            at_word_start = False
            continue
        if in_test and c in "<>":  # a string comparison, not a redirection
            cur.append(c)
            i += 1
            at_word_start = False
            continue
        if c == ">" and not (mode == "bash" and s.startswith("(", i + 1)):  # not >(...)
            # An fd or stream written against the operator (2>, &>, *>) is not a word.
            k = len(cur)
            while k > 0 and (cur[k - 1].isdigit() or cur[k - 1] in ("&", "*")):
                k -= 1
            if k == 0 or cur[k - 1] in (" ", "\t"):
                del cur[k:]
            j = i + 1
            if j < n and s[j] in ">|":
                j += 1
            if j < n and s[j] == "&":
                m = re.match(r"\d+-?|-", s[j + 1 :])
                if m:  # 2>&1, >&2, >&-: a descriptor, not a file
                    i = j + 1 + m.end()
                    continue
                j += 1
            while j < n and s[j] in " \t":
                j += 1
            target, i, target_subs = _read_target(s, j, mode)
            out.nested.extend(target_subs)
            if target:
                redirects.append(target)
            at_word_start = True
            continue
        if c == "&" and s.startswith(">", i + 1):  # &> and &>>
            cur.append(c)
            i += 1
            continue
        if c == "(":
            depth += 1
            flush()
            i += 1
            at_word_start = True
            continue
        if c == ")":
            if depth > 0:
                depth -= 1
            elif closer == ")":
                flush()
                return out, i + 1
            flush()
            i += 1
            at_word_start = True
            continue
        if s.startswith(("&&", "||"), i):
            flush()
            i += 2
            at_word_start = True
            continue
        if c == "|":
            source = "".join(cur)
            flush()
            piped_from = source
            i += 2 if (mode == "bash" and s.startswith("|&", i)) else 1
            at_word_start = True
            continue
        if c == "&" and mode == "pwsh":  # the call operator (or a trailing job &)
            cur.append(" & ")
            i += 1
            at_word_start = True
            continue
        if c in ";&\n":
            flush()
            i += 1
            at_word_start = True
            continue
        cur.append(c)
        at_word_start = c in " \t"
        i += 1
    flush()
    return out, n


def _substitutions(body: str) -> list[Parsed]:
    found: list[Parsed] = []
    i = 0
    while i < len(body):
        if body[i] == "\\":
            i += 2
            continue
        if body.startswith("$(", i):
            sub, i = parse(body, "bash", i + 2, ")")
            found.append(sub)
            continue
        if body[i] == "`":
            sub, i = parse(body, "bash", i + 1, "`")
            found.append(sub)
            continue
        i += 1
    return found


# ── Rules ───────────────────────────────────────────────────────────────────


@dataclass
class Context:
    cwd: str
    vars: dict[str, str] = field(default_factory=dict)

    def child(self) -> Context:
        return Context(self.cwd, dict(self.vars))


def check_text(text: str, mode: str, ctx: Context, depth: int = 0) -> None:
    _tick()
    if depth > MAX_DEPTH:
        raise BlockedError("a command nested more than eight interpreters deep, which this "
                      "guard does not read. Run the inner command directly.")
    if mode == "bash":
        text = text.replace("\\\r\n", " ").replace("\\\n", " ")
    parsed, _ = parse(text, mode)
    check_parsed(parsed, mode, ctx, depth)


def check_parsed(parsed: Parsed, mode: str, ctx: Context, depth: int) -> None:
    for sub in parsed.nested:
        check_parsed(sub, mode, ctx.child(), depth + 1)
    for seg in parsed.segments:
        check_redirects(seg.redirects, mode, ctx)
        check_words(
            split_words(seg.text, mode), seg.heredocs, mode, ctx, depth, seg.piped_from
        )


def _first_unresolved(word: str, mode: str) -> int:
    """Where the first part of `word` that only the shell can work out begins."""
    found = [m.start() for m in [re.search(r"__SUBST__|\$(?:[A-Za-z_{(]|env:)", word, re.I)]
             if m]
    if mode == "bash":
        found += [m.start() for m in [re.search(r"`|\{[^{}]*,[^{}]*\}", word)] if m]
    if mode == "cmd":
        found += [m.start() for m in [re.search(r"%[A-Za-z_][A-Za-z0-9_]*%", word)] if m]
    return min(found, default=len(word))


def refuse_unresolved_write(path: str, what: str, mode: str, ctx: Context) -> None:
    """Refuse `what` if a path the shell finishes at run time could land in a protected
    checkout. It is judged by the working directory (a relative path) and by the
    directory its resolvable prefix names: "$HUB/$f" and $HUB/{a,b} are inside $HUB.
    A partial last component counts too: <projects>/TheHub-ma$X could be the checkout."""
    refuse_write(ctx.cwd, what)
    prefix = path[: _first_unresolved(path, mode)].replace("\\", "/")
    if "/" not in prefix:
        return
    head, partial = prefix.rsplit("/", 1)
    directory = norm(head or "/", ctx.cwd)
    refuse_write(directory, what)
    partial = _plain(partial) if partial else ""
    if not partial:
        return
    for root in protected_roots():
        rel = _below(root, directory)
        if rel and _plain(rel[0]).startswith(partial):
            raise BlockedError(
                f"`{what}` writes a path that starts {prefix} and is finished only at run "
                f"time, so it could land in the live checkout {root}. Write the path out."
            )


def _substituted_target(raw: str, mode: str, ctx: Context) -> str | None:
    """A redirection target that starts with a command substitution, `> $(echo p)`,
    with the substitution replaced by what it prints when that can be known."""
    m = re.match(r'^"?(\$\(|`)', raw)
    if not m or (m.group(1) == "`" and mode != "bash"):
        return None
    inner, end = parse(raw, mode, m.end(), ")" if m.group(1) == "$(" else "`")
    known = None
    if len(inner.segments) == 1 and not inner.nested:
        known = _stdin_text(inner.segments[0].text, mode, ctx)
    if known is None or not known.strip():
        raise BlockedError(
            f"`> {raw}`: a redirection to a path that a command prints at run time, which "
            "this guard cannot read, so it cannot tell whether it is inside the live "
            "checkout. Write the path out."
        )
    rest = raw[end:]
    if raw.startswith('"') and rest.startswith('"'):
        rest = rest[1:]
    rest_words = split_words(rest, mode) if rest.strip() else []
    return known.strip() + (rest_words[0] if rest_words else "")


def check_redirects(targets: list[str], mode: str, ctx: Context) -> None:
    for raw in targets:
        substituted = _substituted_target(raw, mode, ctx)
        if substituted is not None:
            target = substituted
        else:
            words = split_words(raw, mode)
            if not words:
                continue
            target = words[0]
        target = expand_vars(target, ctx.vars)
        low = target.lower()
        if low in NOT_FILES or low.startswith("/dev/fd/"):
            continue
        if unresolved(target, mode):  # a target only the shell can name
            refuse_unresolved_write(target, f"> {raw}", mode, ctx)
            continue
        refuse_write(norm(target, ctx.cwd), f"> {raw}")


def _stdin_text(source: str, mode: str, ctx: Context) -> str | None:
    """What the command `source` writes to a pipe, when that can be known without
    running it: the text of echo/printf/Write-Output or a PowerShell string, or the
    contents of the files cat/Get-Content reads. None when it cannot be known."""
    text = source.strip()
    if not text or "__SUBST__" in text:
        return None
    words = [expand_vars(w, ctx.vars) for w in split_words(text, mode)]
    if not words or any(unresolved(w, mode) for w in words):
        return None
    if mode == "pwsh" and len(words) == 1 and text[:1] in "'\"":
        return words[0]
    name, args = basename(words[0]), words[1:]
    if name in ("echo", "printf", "write-output", "write"):
        while name == "echo" and args and re.fullmatch(r"-[neE]+", args[0]):
            args = args[1:]
        out = " ".join(args)
        return out.replace("\\n", "\n").replace("\\t", "\t") if name == "printf" else out
    if name in ("cat", "type", "get-content", "gc"):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return None
        parts: list[str] = []
        for f in files:
            path = norm(f, ctx.cwd)
            try:
                if os.path.getsize(path) > 1_000_000:
                    return None
                with open(path, encoding="utf-8", errors="replace") as fh:
                    parts.append(fh.read())
            except OSError:
                return None
        return "\n".join(parts)
    return None


def check_stdin(source: str, mode: str, interpreter: str, ctx: Context, depth: int) -> None:
    """A command piped into an interpreter: judge what the pipe carries."""
    pwsh_like = interpreter in POWERSHELLS or interpreter in ("iex", "invoke-expression")
    inner_mode = "pwsh" if pwsh_like else "bash"
    text = _stdin_text(source, mode, ctx)
    if text is None:
        raise BlockedError(
            f"`{source.strip() or '(...)'} | {interpreter}`: a command piped into "
            f"{interpreter} from something this guard cannot read, so it cannot tell what "
            "will run. Run the commands directly, or pass them with -c."
        )
    check_text(text, inner_mode, ctx.child(), depth + 1)


def _rejoin(words: list[str]) -> list[str]:
    """The text an interpreter re-reads from these words, in the two ways it may."""
    plain = " ".join(words)
    quoted = " ".join(f'"{w}"' if (" " in w or "\t" in w) else w for w in words)
    return [plain] if plain == quoted else [plain, quoted]


def _path_args(args: list[str]) -> list[str]:
    """The arguments that could be paths: every operand, and the value of --x=value."""
    out: list[str] = []
    for a in args:
        if a.startswith("-"):
            if "=" in a:
                out.append(a.split("=", 1)[1])
            continue
        out.append(a)
    return out


def refuse_unresolved(head: str, args: list[str], ctx: Context) -> None:
    """A command word only the shell can resolve, run next to a protected checkout."""
    root = protected_root_for(ctx.cwd, for_git=False)
    if root is None:
        for a in _path_args(args):
            if a and not unresolved(a, "bash"):
                root = protected_root_for(norm(a, ctx.cwd), for_git=False)
                if root:
                    break
    if root:
        raise BlockedError(
            f"`{head}` as a command next to the live checkout {root}: this guard cannot "
            "tell what that word will run, so it refuses rather than guess. Write the "
            "command name out."
        )


def _strip_flags(rest: list[str], takes_value: set[str]) -> list[str]:
    """Drop a wrapper's leading flags (and the values of those that take one)."""
    while rest and rest[0].startswith("-") and rest[0] != "-":
        flag = rest[0]
        if flag == "--":
            return rest[1:]
        rest = rest[2:] if flag in takes_value else rest[1:]
    return rest


def check_words(
    raw: list[str],
    heredocs: list[str],
    mode: str,
    ctx: Context,
    depth: int,
    piped_from: str | None = None,
) -> None:
    words = list(raw)
    # PowerShell assignment: $t = 'path'  /  $env:T = 'path'
    if len(words) >= 3 and words[1] == "=" and PS_ASSIGN.match(words[0]):
        m = PS_ASSIGN.match(words[0])
        assert m is not None
        ctx.vars[m.group(1)] = expand_vars(words[2], ctx.vars)
        words = words[2:]
    called = False  # PowerShell runs a variable or (...) only after & or .
    while words and words[0].lower() in PREFIX_WORDS:
        called = called or words[0] in ("&", ".")
        words = words[1:]
    local: dict[str, str] = {}
    while words and ASSIGN.match(words[0]):
        m = ASSIGN.match(words[0])
        assert m is not None
        local[m.group(1)] = expand_vars(m.group(2), {**ctx.vars, **local})
        words = words[1:]
    if not words:
        ctx.vars.update(local)
        return
    env = {**ctx.vars, **local}
    words = [expand_vars(w, env) for w in words]
    head = words[0]
    name = basename(head)
    args = words[1:]

    def inner(rest: list[str], sub: Context | None = None) -> None:
        if rest:
            check_words(rest, heredocs, mode, sub or ctx, depth, piped_from)

    if unresolved(head, mode) and (mode != "pwsh" or called):
        check_ruff(words)
        refuse_unresolved(head, args, ctx)
        return

    if name in ("export", "declare", "typeset", "local", "readonly", "set", "setx"):
        for w in args:
            m = ASSIGN.match(w)
            if m:
                ctx.vars[m.group(1)] = m.group(2)
        return
    if name == "env":
        rest, chdir = list(args), None
        while rest:
            a = rest[0]
            if a in ("-C", "--chdir") and len(rest) > 1:
                chdir, rest = rest[1], rest[2:]
            elif a.startswith("--chdir="):
                chdir, rest = a.split("=", 1)[1], rest[1:]
            elif a.startswith("-C") and len(a) > 2:
                chdir, rest = a[2:], rest[1:]
            elif a in ("-S", "--split-string") and len(rest) > 1:
                rest = split_words(rest[1], "bash") + rest[2:]
            elif a.startswith("--split-string="):
                rest = split_words(a.split("=", 1)[1], "bash") + rest[1:]
            elif a.startswith("-S") and len(a) > 2:
                rest = split_words(a[2:], "bash") + rest[1:]
            elif a in ("-u", "--unset") and len(rest) > 1:
                rest = rest[2:]
            elif a == "--":
                rest = rest[1:]
                break
            elif a.startswith("-"):
                rest = rest[1:]
            else:
                break
        sub = None
        if chdir is not None:
            sub = ctx.child()
            sub.cwd = norm(chdir, ctx.cwd)
        inner(rest, sub)
        return
    if name == "nice":
        inner(_strip_flags(list(args), {"-n", "--adjustment"}))
        return
    if name == "command":
        lead: list[str] = []
        for a in args:
            if not a.startswith("-") or a == "--":
                break
            lead.append(a)
        if any("v" in a[1:] or "V" in a[1:] for a in lead):
            return  # command -v / -V only looks the name up
        inner(_strip_flags(list(args), set()))
        return
    if name == "exec":
        rest = list(args)
        while rest and rest[0].startswith("-") and rest[0] != "-":
            flag, rest = rest[0], rest[1:]
            if flag == "--":
                break
            if flag.endswith("a") and rest:  # -a NAME, also packed as -cla NAME
                rest = rest[1:]
        inner(rest)
        return
    if name == "time":
        rest = list(args)
        while rest and rest[0].startswith("-") and rest[0] != "-":
            flag, rest = rest[0], rest[1:]
            if flag == "--":
                break
            if flag in ("-o", "--output") and rest:  # GNU time writes its report there
                refuse_write(norm(rest[0], ctx.cwd), f"time {flag} {rest[0]}")
                rest = rest[1:]
            elif flag.startswith("--output="):
                value = flag.split("=", 1)[1]
                refuse_write(norm(value, ctx.cwd), f"time {flag}")
            elif flag in ("-f", "--format") and rest:
                rest = rest[1:]
        inner(rest)
        return
    if name in ("sudo", "doas"):
        inner(_strip_flags(list(args), {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U",
                                        "-T", "-R"}))
        return
    if name in ("timeout", "xargs", "watch", "nohup", "stdbuf"):
        rest = list(args)
        while rest and rest[0].startswith("-"):
            takes = rest[0] in ("-I", "-n", "-L", "-P", "-d", "-a", "-E", "-s", "-k", "-n")
            rest = rest[2:] if takes else rest[1:]
        if name == "timeout" and rest:
            rest = rest[1:]
        inner(rest)
        return

    if name in CD_COMMANDS:
        target = next((a for a in args if not a.startswith("-") and a.lower() != "/d"), None)
        if target is None and not args:
            ctx.cwd = norm(home_dir(), None)
        elif target is not None and target != "-":
            ctx.cwd = norm(target, ctx.cwd)
        return

    if name in SHELLS:
        for k, a in enumerate(args):
            if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", a) and k + 1 < len(args):
                check_text(args[k + 1], "bash", ctx.child(), depth + 1)
                return
        here: list[str] = []
        operands: list[str] = []
        reads_stdin = False
        k = 0
        while k < len(args):
            a = args[k]
            if a == "<<<":
                here += args[k + 1 : k + 2]
                k += 2
                continue
            if a.startswith("<<<"):
                here.append(a[3:])
            elif a.startswith("-") and not a.startswith("--") and "s" in a[1:]:
                reads_stdin = True
            elif not a.startswith("-"):
                operands.append(a)
            k += 1
        for text in here + heredocs:
            check_text(text, "bash", ctx.child(), depth + 1)
        if piped_from is not None and not here and not heredocs and (
            reads_stdin or not operands
        ):
            check_stdin(piped_from, mode, name, ctx, depth)
        return
    if name == "eval":
        check_text(" ".join(args), "bash", ctx, depth + 1)
        return
    if name in ("invoke-expression", "iex"):
        rest = [a for a in args if a.lower() not in ("-command", "-c")]
        if rest:
            for text in _rejoin(rest):
                check_text(text, "pwsh", ctx, depth + 1)
        elif piped_from is not None:
            check_stdin(piped_from, mode, name, ctx, depth)
        return
    if name == "cmd":
        for k, a in enumerate(args):
            if a.lower() in ("/c", "/k", "//c", "//k", "/r", "//r"):
                for text in _rejoin(args[k + 1 :]):
                    check_text(text, "cmd", ctx.child(), depth + 1)
                return
        return
    if name in POWERSHELLS:
        reads_stdin = check_powershell(name, args, heredocs, ctx, depth)
        if reads_stdin and piped_from is not None and not heredocs:
            check_stdin(piped_from, mode, name, ctx, depth)
        return

    check_ruff(words)
    if name == "git":
        check_git(words, ctx, env)
    check_writes(name, args, mode, ctx)


def check_powershell(
    name: str, args: list[str], heredocs: list[str], ctx: Context, depth: int
) -> bool:
    """Judge the command a pwsh or powershell call runs. True when it reads the
    command from stdin (no command given, or -Command -)."""
    sub = ctx.child()
    k = 0
    while k < len(args):
        a = args[k]
        flag = a.lstrip("-/").lower() if a[:1] in "-/" else None
        if a == "-":
            return True
        if flag is None:  # first positional: powershell.exe reads it as the command
            rest = args[k:]
            if name == "pwsh" and rest[0].lower().endswith(".ps1"):
                return False
            for text in _rejoin(rest):
                check_text(text, "pwsh", sub, depth + 1)
            return False
        if flag and "command".startswith(flag):
            if args[k + 1 : k + 2] == ["-"] or k + 1 >= len(args):
                return True
            for text in _rejoin(args[k + 1 :]):
                check_text(text, "pwsh", sub, depth + 1)
            return False
        if flag in ("e", "ec") or (len(flag) >= 2 and "encodedcommand".startswith(flag)):
            if k + 1 < len(args):
                try:
                    decoded = base64.b64decode(args[k + 1]).decode("utf-16-le")
                except ValueError as exc:
                    raise BlockedError("a pwsh -EncodedCommand this guard cannot decode. "
                                  "Pass the command with -Command.") from exc
                check_text(decoded, "pwsh", sub, depth + 1)
            return False
        if flag and ("file".startswith(flag) and flag[:1] == "f"):
            return args[k + 1 : k + 2] == ["-"]
        if flag in ("wd",) or (len(flag) >= 2 and "workingdirectory".startswith(flag)):
            if k + 1 < len(args):
                sub.cwd = norm(args[k + 1], sub.cwd)
            k += 2
            continue
        if flag in ("ex", "ep", "executionpolicy", "w", "windowstyle", "of", "outputformat",
                    "if", "inputformat", "settingsfile", "configurationname", "version",
                    "custompipename", "psconsolefile"):
            k += 2
            continue
        k += 1
    for body in heredocs:
        check_text(body, "pwsh", sub, depth + 1)
    return True


# ── Writes from the shell (TheHub #61108) ───────────────────────────────────

# Unix tools whose every operand is written (or removed).
UNIX_WRITE_ALL = {"rm", "rmdir", "touch", "mkdir", "truncate", "shred", "unlink", "mv"}
# ... whose first operand is a mode or owner and the rest are written.
UNIX_WRITE_AFTER_FIRST = {"chmod", "chown", "chgrp"}
# ... that write only their destination: -t DIR, or the last operand.
UNIX_WRITE_DEST = {"cp", "install", "ln", "rsync", "scp"}
UNIX_VALUE_FLAGS = {
    "cp": {"-S", "--suffix", "-t", "--target-directory"},
    "mv": {"-S", "--suffix", "-t", "--target-directory"},
    "ln": {"-S", "--suffix", "-t", "--target-directory"},
    "install": {"-m", "-o", "-g", "-S", "-t", "--mode", "--owner", "--group", "--suffix",
                "--target-directory"},
    "rsync": {"-e", "--rsh", "-f", "--filter", "--exclude", "--include", "-T", "--temp-dir",
              "--log-file"},
    "scp": {"-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J"},
    "truncate": {"-s", "--size", "-r", "--reference"},
    "touch": {"-d", "--date", "-t", "-r", "--reference"},
    "mkdir": {"-m", "--mode"},
    "chmod": {"--reference"},
    "chown": {"--reference", "--from"},
    "sed": {"-e", "--expression", "-f", "--file", "-l", "--line-length"},
    "perl": {"-e", "-E", "-M", "-I", "-m"},
    "ruby": {"-e", "-I", "-r"},
}
# cmd.exe's own commands.
CMD_WRITE_ALL = {"del", "erase", "rd", "rmdir", "md", "mkdir", "move", "ren", "rename"}
CMD_WRITE_DEST = {"copy", "xcopy"}

# PowerShell cmdlets that write: (positional parameters in order, parameters that are
# written). A named parameter takes the next word unless it is a switch.
PS_WRITERS: dict[str, tuple[tuple[str, ...], frozenset[str]]] = {
    "set-content": (("path", "value"), frozenset({"path", "literalpath", "pspath", "lp"})),
    "add-content": (("path", "value"), frozenset({"path", "literalpath", "pspath", "lp"})),
    "clear-content": (("path",), frozenset({"path", "literalpath", "pspath", "lp"})),
    "out-file": (("filepath", "encoding"), frozenset({"filepath", "literalpath", "path",
                                                       "lp", "pspath"})),
    "tee-object": (("filepath",), frozenset({"filepath", "literalpath", "path", "lp"})),
    "new-item": (("path",), frozenset({"path", "literalpath"})),
    "remove-item": (("path",), frozenset({"path", "literalpath", "pspath", "lp"})),
    "rename-item": (("path", "newname"), frozenset({"path", "literalpath", "pspath", "lp"})),
    "move-item": (("path", "destination"), frozenset({"path", "literalpath", "pspath", "lp",
                                                       "destination"})),
    "copy-item": (("path", "destination"), frozenset({"destination"})),
    "expand-archive": (("path", "destinationpath"), frozenset({"destinationpath"})),
    "compress-archive": (("path", "destinationpath"), frozenset({"destinationpath"})),
    "export-csv": (("path",), frozenset({"path", "literalpath"})),
    "export-clixml": (("path",), frozenset({"path", "literalpath"})),
    "invoke-webrequest": (("uri",), frozenset({"outfile"})),
    "invoke-restmethod": (("uri",), frozenset({"outfile"})),
}
PS_ALIASES = {
    "sc": "set-content", "ac": "add-content", "clc": "clear-content", "ni": "new-item",
    "md": "new-item", "mkdir": "new-item", "ri": "remove-item", "rm": "remove-item",
    "del": "remove-item", "erase": "remove-item", "rd": "remove-item",
    "rmdir": "remove-item", "rni": "rename-item", "ren": "rename-item", "mi": "move-item",
    "mv": "move-item", "move": "move-item", "cpi": "copy-item", "cp": "copy-item",
    "copy": "copy-item", "tee": "tee-object", "iwr": "invoke-webrequest",
    "irm": "invoke-restmethod", "epcsv": "export-csv",
}
PS_VALUE_PARAMS = ("value", "encoding", "itemtype", "name", "filter", "include", "exclude",
                   "stream", "inputobject", "width", "credential", "erroraction",
                   "warningaction", "uri", "method", "headers", "body", "newname")
PS_SWITCHES = ("recurse", "force", "whatif", "confirm", "append", "noclobber",
               "nonewline", "passthru", "container", "verbose", "debug", "asjob",
               "usebasicparsing", "notypeinformation")


def _ps_bind(args: list[str], positions: tuple[str, ...],
             written: frozenset[str]) -> dict[str, list[str]]:
    """PowerShell parameter binding, enough to find the paths a cmdlet writes."""
    known = list(positions) + sorted(written) + list(PS_VALUE_PARAMS)
    bound: dict[str, list[str]] = {}
    positional: list[str] = []
    k = 0
    while k < len(args):
        a = args[k]
        if a.startswith("-") and len(a) > 1 and not re.match(r"^-\d", a):
            flag, colon, inline = a[1:].partition(":")
            flag = flag.lower()
            full = next((p for p in known if p == flag), None) or next(
                (p for p in known if p.startswith(flag)), None)
            if colon:
                if full:
                    bound.setdefault(full, []).append(inline)
                k += 1
                continue
            if full is None or flag in PS_SWITCHES:
                k += 1  # a switch, or a parameter this does not know: takes no value
                continue
            if k + 1 < len(args):
                bound.setdefault(full, []).append(args[k + 1])
            k += 2
            continue
        positional.append(a)
        k += 1
    free = [p for p in positions if p not in bound]
    for p, v in zip(free, positional, strict=False):
        bound.setdefault(p, []).append(v)
    return bound


def _operands(args: list[str], value_flags: set[str]) -> tuple[list[str], dict[str, str]]:
    """A Unix command's operands, and the values of the flags that take one."""
    operands: list[str] = []
    values: dict[str, str] = {}
    k = 0
    while k < len(args):
        a = args[k]
        if a == "--":
            operands += args[k + 1 :]
            break
        if a.startswith("--") and "=" in a:
            name, value = a.split("=", 1)
            values[name] = value
        elif a.startswith("-") and a != "-":
            if a in value_flags and k + 1 < len(args):
                values[a] = args[k + 1]
                k += 1
            elif a[:2] in value_flags and len(a) > 2 and not a.startswith("--"):
                values[a[:2]] = a[2:]  # packed: -tDIR
        else:
            operands.append(a)
        k += 1
    return operands, values


def _written_paths(name: str, args: list[str], mode: str) -> list[str]:
    """The paths a command writes, as written. Empty for a command that does not."""
    if mode == "pwsh" and (name in PS_ALIASES or name in PS_WRITERS):
        positions, written = PS_WRITERS[PS_ALIASES.get(name, name)]
        bound = _ps_bind(args, positions, written)
        return [v for p in written for value in bound.get(p, []) for v in value.split(",")]
    if mode == "cmd" and (name in CMD_WRITE_ALL or name in CMD_WRITE_DEST):
        operands = [a for a in args if not re.match(r"^/[A-Za-z?\-:]{1,4}$", a)]
        if name in CMD_WRITE_DEST:
            return operands[-1:] if len(operands) > 1 else []
        return operands
    if name == "robocopy":
        operands = [a for a in args if not a.startswith("/")]
        return operands[1:2]
    flags = UNIX_VALUE_FLAGS.get(name, set())
    if name in ("sed", "perl", "ruby"):
        in_place = any(re.match(r"^-[A-Za-z]*i", a) or a.startswith("--in-place")
                       for a in args if not a.startswith("--") or a.startswith("--in-place"))
        if not in_place:
            return []
        operands, values = _operands(args, flags)
        has_script = any(f in values for f in ("-e", "--expression", "-f", "--file"))
        return operands if has_script else operands[1:]
    if name == "tee":
        return _operands(args, set())[0]
    if name == "dd":
        return [a[3:] for a in args if a.startswith("of=")]
    if name in UNIX_WRITE_ALL:
        operands, values = _operands(args, flags)
        return operands + [v for f, v in values.items() if f in ("-t", "--target-directory")]
    if name in UNIX_WRITE_AFTER_FIRST:
        operands, values = _operands(args, flags)
        return operands if "--reference" in values else operands[1:]
    if name in UNIX_WRITE_DEST:
        operands, values = _operands(args, flags)
        target = values.get("-t") or values.get("--target-directory")
        if target:
            return [target]
        return operands[-1:] if len(operands) > 1 else []
    return []


def check_writes(name: str, args: list[str], mode: str, ctx: Context) -> None:
    for path in _written_paths(name, args, mode):
        path = path.strip()
        if not path:
            continue
        if unresolved(path, mode):
            refuse_unresolved_write(path, f"{name} {path}", mode, ctx)
            continue
        refuse_write(norm(path, ctx.cwd), f"{name} {path}")


def check_ruff(words: list[str]) -> None:
    for k, w in enumerate(words):
        b = basename(w)
        is_ruff = b == "ruff" or b.startswith(("ruff@", "ruff==")) or w.lower() == "-mruff"
        if is_ruff and any(x.lower() == "format" for x in words[k + 1 :]):
            raise BlockedError(
                    "`ruff format`. This tree was never formatted with it: one run rewrites "
                    "over a hundred files and buries the real diff. Use `ruff check` (with "
                    "--fix for a lint fix) on the files you changed, and format by hand."
                )


def check_git(words: list[str], ctx: Context, env: dict[str, str]) -> None:
    d = ctx.cwd
    git_dir = lookup("GIT_DIR", env)
    work_tree = lookup("GIT_WORK_TREE", env)
    i, sub = 1, None
    config: list[str] = []
    global_flags: list[str] = []
    while i < len(words):
        w = words[i]
        lw = w.lower()
        if w == "-C" and i + 1 < len(words):
            d = norm(words[i + 1], d)
            i += 2
            continue
        if w == "-c" or lw == "--config-env":
            config.append(words[i + 1] if i + 1 < len(words) else "")
            i += 2
            continue
        if lw in ("--namespace", "--exec-path", "--super-prefix") and "=" not in w:
            i += 2
            continue
        if lw.startswith(("--git-dir", "--work-tree")):
            if "=" in w:
                value = w.split("=", 1)[1]
            else:
                value = words[i + 1] if i + 1 < len(words) else ""
                i += 1
            if lw.startswith("--git-dir"):
                git_dir = value
            else:
                work_tree = value
            i += 1
            continue
        if w.startswith("-"):
            global_flags.append(lw)
            i += 1
            continue
        sub = lw
        break
    targets = [d]
    if git_dir:
        targets.append(norm(git_dir, d))
    if work_tree:
        targets.append(norm(work_tree, d))
    root = next((r for t in targets if (r := protected_root_for(t, for_git=True))), None)
    if root is None:
        return
    rest = words[i + 1 :] if sub is not None else []
    unsafe_config = [c for c in config if not c.lower().startswith(SAFE_CONFIG_PREFIXES)]
    if unsafe_config:
        why = f"git -c {unsafe_config[0]}"  # an alias, a hook path, a pager: it can run code
    elif sub is None:
        if global_flags and all(f in GIT_INFO_FLAGS for f in global_flags):
            return
        why = "git with no verb"
    elif git_allowed(sub, rest):
        return
    else:
        why = f"git {sub}"
    raise BlockedError(
        f"`{why}` in the live checkout {root}. The production deploy ships that working "
        "tree, so changing it changes production. Inside it git is limited to read-only "
        "verbs (status, log, diff, show, branch --list, rev-parse, ls-files, blame, "
        "describe, stash list/show, config --get, remote -v, worktree list/add/prune), "
        "fetch, and merge --ff-only. Make the change from a worktree under its "
        ".claude/worktrees/ folder, or ask the operator."
    )


def _positionals(args: list[str], takes_value: frozenset[str] = frozenset()) -> list[str]:
    out: list[str] = []
    k = 0
    while k < len(args):
        a = args[k]
        if a == "--":
            out += args[k + 1 :]
            break
        if a.startswith("-"):
            k += 2 if (a.lower() in takes_value and "=" not in a) else 1
            continue
        out.append(a.lower())
        k += 1
    return out


def git_allowed(sub: str, rest: list[str]) -> bool:
    """True if `git <sub> <rest>` may run in a protected checkout. Default: no."""
    flags = [a.lower() for a in rest if a.startswith("-")]
    if sub in GIT_READ_ONLY:
        return True
    if sub == "branch":
        for f in flags:
            name = f.split("=", 1)[0]
            if name in BRANCH_WRITE_FLAGS:
                return False
            if not f.startswith("--") and set(f[1:]) & set("dDmMcCfu"):
                return False
        listing = "--list" in flags or "-l" in flags
        return listing or not _positionals(rest, BRANCH_VALUE_FLAGS)
    if sub == "stash":
        pos = _positionals(rest)
        return bool(pos) and pos[0] in ("list", "show")
    if sub == "worktree":
        pos = _positionals(rest)
        return bool(pos) and pos[0] in ("list", "add", "prune")
    if sub == "config":
        if any(f.split("=", 1)[0] in CONFIG_WRITE_FLAGS for f in flags):
            return False
        pos = _positionals(rest)
        return any(f.split("=", 1)[0] in CONFIG_READ_FLAGS for f in flags) or (
            bool(pos) and pos[0] in ("get", "list")
        )
    if sub == "remote":
        pos = _positionals(rest)
        return (not pos and all(f in ("-v", "--verbose") for f in flags)) or (
            bool(pos) and pos[0] in ("show", "get-url")
        )
    if sub == "merge":
        # git takes the last of --ff / --no-ff / --ff-only; --squash writes the index.
        ff = [f for f in flags if f in ("--ff", "--no-ff", "--ff-only")]
        return bool(ff) and ff[-1] == "--ff-only" and "--squash" not in flags
    return False


# ── Entry points ────────────────────────────────────────────────────────────


def block(hook: str, reason: str) -> int:
    sys.stderr.write(f"BLOCKED by .claude/hooks/{hook}: {reason}\n\n"
                     "This is a harness control (TheHub #61099), not a suggestion. Do not "
                     "work around it; if it is wrong, say so and file it.\n")
    return 2


def guard_bash(payload: dict[str, Any]) -> int:
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") or ""
    if not isinstance(command, str) or not command.strip():
        return 0
    mode = "pwsh" if str(payload.get("tool_name", "")).lower() == "powershell" else "bash"
    cwd = payload.get("cwd") or os.getcwd()
    try:
        check_text(command, mode, Context(norm(str(cwd), None)))
    except BlockedError as exc:
        return block("guard-bash.sh", str(exc))
    return 0


def guard_write(payload: dict[str, Any]) -> int:
    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path")
    if not isinstance(path, str) or not path.strip():
        return 0
    cwd = payload.get("cwd") or os.getcwd()
    target = norm(expand_vars(path, {}), norm(str(cwd), None))
    try:
        root = protected_root_for(target, for_git=False)
    except BlockedError as exc:
        return block("guard-write.sh", str(exc))
    if root:
        return block(
            "guard-write.sh",
            f"writing {path}, which is inside the live checkout {root}. The production "
            "deploy ships that working tree. Make the change in a worktree under its "
            ".claude/worktrees/ folder and open a pull request.",
        )
    return 0


PS1_SUFFIXES = (".ps1", ".psm1", ".psd1")
PARSE_SCRIPT = (
    "$errs = $null; $toks = $null; "
    "$null = [System.Management.Automation.Language.Parser]::ParseFile("
    "$env:MYKRONOS_PS1_PARSE_PATH, [ref]$toks, [ref]$errs); "
    "foreach ($e in $errs) { '{0}:{1}: {2}' -f "
    "$e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message }"
)


def check_ps1(payload: dict[str, Any]) -> int:
    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or ""
    if not isinstance(path, str) or not path.lower().endswith(PS1_SUFFIXES):
        return 0
    if IS_WINDOWS:
        path = norm(path, str(payload.get("cwd") or os.getcwd()))
    if not os.path.isfile(path):
        return 0
    exe = shutil.which("pwsh") or shutil.which("powershell")
    if exe is None:
        sys.stderr.write("check-ps1.sh: no pwsh or powershell on PATH; parse check skipped\n")
        return 0
    # The path reaches PowerShell through the environment, never spliced into the
    # command text, so a file name cannot run code.
    env = {**os.environ, "MYKRONOS_PS1_PARSE_PATH": path}
    try:
        r = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", PARSE_SCRIPT],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, timeout=60, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        sys.stderr.write(f"check-ps1.sh: the PowerShell parser did not run ({exc})\n")
        return 0
    errors = [line for line in r.stdout.splitlines() if line.strip()]
    if not errors:
        return 0
    sys.stderr.write(
        f"PowerShell parse errors in {path} (the file was saved; fix it before running it):\n"
        + "".join(f"  {path}:{line}\n" for line in errors)
    )
    return 2


def main(argv: list[str]) -> int:
    mode = argv[1] if len(argv) > 1 else ""
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        sys.stderr.write("estate_guard.py: the hook payload is not JSON\n")
        return 3
    if not isinstance(payload, dict):
        return 3
    if mode == "bash":
        start_deadline("guard-bash.sh")
        return guard_bash(payload)
    if mode == "write":
        start_deadline("guard-write.sh")
        return guard_write(payload)
    if mode == "ps1":
        return check_ps1(payload)
    sys.stderr.write(f"estate_guard.py: unknown mode {mode!r}\n")
    return 3


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:  # any bug must reach the wrapper's fallback
        sys.stderr.write(f"estate_guard.py: internal error: {exc!r}\n")
        sys.exit(3)
