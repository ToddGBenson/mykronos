"""Harness guards for this estate: the logic behind guard-bash.sh, guard-write.sh and
check-ps1.sh (TheHub #61099).

Three mistakes kept recurring because the lesson lived only in an agent's memory:

  1. `ruff format`. The tree was never formatted with it; one run rewrites over a
     hundred files and buries the real diff.
  2. git commit, reset, checkout, switch, stash, clean or restore in the live TheHub
     checkout. The production deploy ships that working tree, so moving it moves
     production. Its own `.claude/worktrees/<name>` folders are separate worktrees and
     stay allowed.
  3. Writing or editing a file inside that live checkout, for the same reason.
  4. (PostToolUse) Saving a PowerShell script that does not parse.

Pattern: keel's .claude/hooks/guard-bash.sh. A prompt is advisory; a PreToolUse hook
that exits 2 makes the action impossible, and its stderr goes back to the agent.

Why Python and not keel's sed: keel and binnacle's selftest passed while four bypasses
were live, because a regex over the command text cannot tell quoted text from a word.
This reads the command the way the shell will: it splits on the real separators,
follows `$(...)`, backticks, subshells and heredocs, removes quoting the way bash (or
cmd, or PowerShell) does, expands the variables it can see, follows `cd`, and re-reads
any command handed to `bash -c`, `sh -c`, `eval`, `cmd /c`, `pwsh -c`,
`pwsh -EncodedCommand` or `Invoke-Expression`. A deny rule may over-block on a reading
the shell would not take; it must never under-block on one it would.

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
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

IS_WINDOWS = os.name == "nt"
PROTECTED_ENV = "MYKRONOS_PROTECTED_CHECKOUTS"
DEFAULT_CHECKOUT = ("Documents", "Projects", "TheHub-main")
GIT_VERBS = {"commit", "reset", "checkout", "switch", "stash", "clean", "restore"}
READ_ONLY_STASH = {"list", "show"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "ash", "busybox"}
POWERSHELLS = {"pwsh", "powershell", "pwsh-preview"}
CD_COMMANDS = {"cd", "chdir", "pushd", "set-location", "sl", "push-location"}
PREFIX_WORDS = {
    "{", "}", "(", ")", "!", "&", ".", "call", "then", "do", "else", "if", "elif", "while",
    "until", "time", "nohup", "exec", "command", "builtin", "sudo", "doas", "nice", "noglob",
}
ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
PS_ASSIGN = re.compile(r"^\$(?:\{)?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?$", re.I)
MAX_DEPTH = 8


class BlockedError(Exception):
    pass


# ── Paths ───────────────────────────────────────────────────────────────────


def profile_dir() -> str:
    return os.environ.get("USERPROFILE") or os.environ.get("HOME") or os.path.expanduser("~")


def home_dir() -> str:
    return os.environ.get("HOME") or os.environ.get("USERPROFILE") or os.path.expanduser("~")


def norm(path: str, base: str | None) -> str:
    """An absolute, '/'-separated path with . and .. resolved. Case is kept."""
    p = path.strip().replace("\\", "/")
    if p.startswith("//?/"):
        p = p[4:]
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


def protected_root_for(path: str, *, for_git: bool) -> str | None:
    """The protected checkout this normalised path is in, or None.

    `<root>/.claude/worktrees/<name>/...` is a separate worktree and is not protected.
    For git it must also be one: a folder there without a .git entry makes git walk
    up to the live checkout.
    """
    low = path.lower()
    for root in protected_roots():
        r = root.lower().rstrip("/")
        if low != r and not low.startswith(r + "/"):
            continue
        rel = path[len(r):].strip("/")
        parts = rel.split("/") if rel else []
        if len(parts) >= 3 and parts[0].lower() == ".claude" and parts[1].lower() == "worktrees":
            if not for_git:
                continue
            worktree = path[: len(r)] + "/" + "/".join(parts[:3])
            if os.path.isdir(worktree) and not os.path.exists(worktree + "/.git"):
                return root
            continue
        return root
    return None


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

    w = re.sub(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}", sub, word, flags=re.I)
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


def split_words(text: str, mode: str) -> list[str]:
    """Words as the shell passes them to the program, quoting removed."""
    if mode == "bash":
        text = text.replace("$'", "'").replace('$"', '"')
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


def parse(s: str, mode: str, i: int = 0, closer: str | None = None) -> tuple[Parsed, int]:
    """Split s into simple commands. Returns at an unmatched `closer` (')' or '`')."""
    out = Parsed()
    cur: list[str] = []
    heredocs: list[str] = []
    pending: list[tuple[str, bool, bool]] = []
    quote: str | None = None
    depth = 0
    n = len(s)
    at_word_start = True

    def flush() -> None:
        nonlocal cur, heredocs
        text = "".join(cur)
        if text.strip() or heredocs:
            out.segments.append(Segment(text, heredocs))
        cur, heredocs = [], []

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
        if mode == "bash" and s.startswith("<<", i) and not s.startswith("<<<", i):
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
        if c in ";&|\n":
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
        check_words(split_words(seg.text, mode), seg.heredocs, mode, ctx, depth)


def _rejoin(words: list[str]) -> list[str]:
    """The text an interpreter re-reads from these words, in the two ways it may."""
    plain = " ".join(words)
    quoted = " ".join(f'"{w}"' if (" " in w or "\t" in w) else w for w in words)
    return [plain] if plain == quoted else [plain, quoted]


def check_words(
    raw: list[str], heredocs: list[str], mode: str, ctx: Context, depth: int
) -> None:
    words = list(raw)
    # PowerShell assignment: $t = 'path'  /  $env:T = 'path'
    if len(words) >= 3 and words[1] == "=" and PS_ASSIGN.match(words[0]):
        m = PS_ASSIGN.match(words[0])
        assert m is not None
        ctx.vars[m.group(1)] = expand_vars(words[2], ctx.vars)
        words = words[2:]
    while words and words[0].lower() in PREFIX_WORDS:
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
    name = basename(words[0])
    args = words[1:]

    if name in ("export", "declare", "typeset", "local", "readonly", "set", "setx"):
        for w in args:
            m = ASSIGN.match(w)
            if m:
                ctx.vars[m.group(1)] = m.group(2)
        return
    if name == "env":
        rest = list(args)
        while rest and (rest[0].startswith("-") or ASSIGN.match(rest[0])):
            if rest[0] in ("-u", "--unset", "-C", "--chdir", "-S") and len(rest) > 1:
                rest = rest[1:]
            rest = rest[1:]
        if rest:
            check_words(rest, heredocs, mode, ctx, depth)
        return
    if name in ("timeout", "xargs", "watch", "nohup", "stdbuf"):
        rest = list(args)
        while rest and rest[0].startswith("-"):
            takes = rest[0] in ("-I", "-n", "-L", "-P", "-d", "-a", "-E", "-s", "-k", "-n")
            rest = rest[2:] if takes else rest[1:]
        if name == "timeout" and rest:
            rest = rest[1:]
        if rest:
            check_words(rest, heredocs, mode, ctx, depth)
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
        for body in heredocs:
            check_text(body, "bash", ctx.child(), depth + 1)
        return
    if name == "eval":
        check_text(" ".join(args), "bash", ctx, depth + 1)
        return
    if name in ("invoke-expression", "iex"):
        rest = [a for a in args if a.lower() not in ("-command", "-c")]
        for text in _rejoin(rest):
            check_text(text, "pwsh", ctx, depth + 1)
        return
    if name == "cmd":
        for k, a in enumerate(args):
            if a.lower() in ("/c", "/k", "//c", "//k", "/r", "//r"):
                for text in _rejoin(args[k + 1 :]):
                    check_text(text, "cmd", ctx.child(), depth + 1)
                return
        return
    if name in POWERSHELLS:
        check_powershell(name, args, heredocs, ctx, depth)
        return

    check_ruff(words)
    if name == "git":
        check_git(words, ctx, env)


def check_powershell(
    name: str, args: list[str], heredocs: list[str], ctx: Context, depth: int
) -> None:
    sub = ctx.child()
    k = 0
    while k < len(args):
        a = args[k]
        flag = a.lstrip("-/").lower() if a[:1] in "-/" else None
        if flag is None:  # first positional: powershell.exe reads it as the command
            rest = args[k:]
            if name == "pwsh" and rest[0].lower().endswith(".ps1"):
                return
            for text in _rejoin(rest):
                check_text(text, "pwsh", sub, depth + 1)
            return
        if flag and "command".startswith(flag):
            for text in _rejoin(args[k + 1 :]):
                check_text(text, "pwsh", sub, depth + 1)
            return
        if flag in ("e", "ec") or (len(flag) >= 2 and "encodedcommand".startswith(flag)):
            if k + 1 < len(args):
                try:
                    decoded = base64.b64decode(args[k + 1]).decode("utf-16-le")
                except ValueError as exc:
                    raise BlockedError("a pwsh -EncodedCommand this guard cannot decode. "
                                  "Pass the command with -Command.") from exc
                check_text(decoded, "pwsh", sub, depth + 1)
            return
        if flag and ("file".startswith(flag) and flag[:1] == "f"):
            return
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
    while i < len(words):
        w = words[i]
        lw = w.lower()
        if w == "-C" and i + 1 < len(words):
            d = norm(words[i + 1], d)
            i += 2
            continue
        if w == "-c" or lw in ("--namespace", "--exec-path", "--config-env", "--super-prefix"):
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
            i += 1
            continue
        sub = lw
        break
    if sub not in GIT_VERBS:
        return
    if sub == "stash":
        nxt = next((x.lower() for x in words[i + 1 :] if not x.startswith("-")), None)
        if nxt in READ_ONLY_STASH:
            return
    targets = [d]
    if git_dir:
        targets.append(norm(git_dir, d))
    if work_tree:
        targets.append(norm(work_tree, d))
    for t in targets:
        root = protected_root_for(t, for_git=True)
        if root:
            raise BlockedError(
                f"`git {sub}` in the live checkout {root}. The production deploy ships "
                "that working tree, so moving it moves production. Read it freely "
                "(status, log, diff, fetch); change it from a worktree under its "
                ".claude/worktrees/ folder, or ask the operator."
            )


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
    root = protected_root_for(target, for_git=False)
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
        return guard_bash(payload)
    if mode == "write":
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
