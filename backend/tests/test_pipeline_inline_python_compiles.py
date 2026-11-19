"""Every inline Python program in a Concourse pipeline compiles (TheHub post-merge red since #1177).

mykronos #1177 rewrote TheHub post-merge's `report-verdict` step and left
the old step's body behind under the new program's final
`sys.exit(exit_code)`, two spaces deeper. That code could never run, but
`python -c` compiles the whole program before running any of it, so the
step died with `IndentationError: unexpected indent` on every build and
post-merge reported develop red whatever the tests said. Nothing checked
that the pipeline's Python parses: the pipeline tests read the YAML, and a
program inside a block scalar is just a string to them.

This test reads each pipeline as Concourse does (YAML loaded, anchors and
merge keys resolved) and compiles every program handed to the interpreter
inline:

* a task whose `run.path` is python or python3 and whose args carry `-c`
  (with or without other flags such as `-I` before it): the argument after
  `-c` is the program;
* a `python -c` / `python3 -c` inside a shell script a task runs: the shell
  word after `-c`, unquoted as the shell would unquote it;
* a `python [flags] - <<'TAG'` here-document in a shell script, which fails
  the same way (pr-gates' process gates, `<<'PROCESS'`, are one), including
  one whose command runs over several lines with backslash continuations (the
  osv-scanner manifest check in mykronos.yml) (TheHub #62133 N1);
* a program written to a `.py` file by `cat > FILE.py <<'TAG'` and run
  later - the ZAP `hook.py` files and the `check.py` programs - which
  fails when it is run rather than when it is written (#62133 N2);
* a program indirected through a variable - `python -c "$MEMORY_GUARD"`,
  `"$HEAD_SHA` + more code, or `exec(os.environ["HEAD_SHA"])` - is compiled
  with the variable's value from the step's own `params` (or its config's)
  substituted, which is where the pipeline defines it.

A program that still holds a shell expansion the YAML does not define is a
value only known at run time; it is listed in RUNTIME_ONLY with its reason
and skipped, and an entry there that no longer matches anything fails, so
the list cannot go stale.

How many programs each pipeline holds is pinned (PROGRAM_COUNTS, #62133
N3), so an extractor that silently stops seeing a site fails rather than
compiling less. And each named site is mutated in memory and must turn
this test red, so a blind spot cannot hide behind a green run.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PIPELINE_DIR = ROOT / "deploy" / "concourse" / "pipelines"
PIPELINES = ("mykronos", "thehub", "personal-soc")

PYTHONS = {"python", "python3"}

# A `python` or `python3` command word, its flags, then `-c` and whitespace.
INLINE = re.compile(r"(?<![\w./-])python3?((?:\s+-[A-Za-z]+)*?)\s+-c\s+")
EXPANSION = re.compile(r"\$(?:\{(\w+)\}|(\w+))")
# `python [flags] - [args] <<'TAG'`: the program is the here-document.
# The arguments may run over several lines with backslash continuations (#62133 N1).
_ARGS = r"""(?:[^\n\\]|\\\n|\\.)"""
HEREDOC = re.compile(
    r"""(?<![\w./-])python3?(?:\s+-[A-Za-z]+)*\s+-(?:\s"""
    + _ARGS
    + r"""*?)?<<(-?)\s*(['"]?)(\w+)\2[^\n]*\n"""
)
# `cat > FILE.py <<'TAG'`: a program written now and run later (#62133 N2).
# The same three groups as HEREDOC, so _heredoc reads both.
PY_FILE_HEREDOC = re.compile(
    r"""(?<![\w./-])cat\s+>\s*(?:"[^"\n]*\.py"|'[^'\n]*\.py'|[^\s;|&<>"']*\.py)\s+"""
    r"""<<(-?)\s*(['"]?)(\w+)\2[^\n]*\n"""
)
EXEC_ENV = re.compile(r"""exec\(os\.environ\[["'](\w+)["']\]\)""")

# (pipeline, task, first program line) -> why it cannot be compiled here.
RUNTIME_ONLY: dict[tuple[str, str, str], str] = {}

# How many inline programs each pipeline holds (#62133 N3). A change that adds
# or removes one updates this on purpose; an extractor that stops seeing one
# fails here instead of compiling less.
PROGRAM_COUNTS = {"mykronos": 21, "thehub": 41, "personal-soc": 6}


def _tasks(node: Any, name: str = "") -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Yield (task name, merged params, run) for every inline task config."""
    if isinstance(node, dict):
        config = node.get("config")
        if isinstance(config, dict) and isinstance(config.get("run"), dict):
            params: dict[str, Any] = {}
            params.update(config.get("params") or {})
            params.update(node.get("params") or {})
            yield str(node.get("task") or name or "?"), params, config["run"]
        for value in node.values():
            yield from _tasks(value, str(node.get("task") or node.get("name") or name))
    elif isinstance(node, list):
        for item in node:
            yield from _tasks(item, name)


def _substitution_end(text: str, i: int) -> int:
    """The index just past the `$( ... )` or `` `...` `` starting at `i`.

    Quotes, and further substitutions, nest inside it as the shell nests
    them, so a `"` inside `$( )` does not end the double-quoted word around
    it (#62133 N4).
    """
    if text[i] == "`":
        j = i + 1
        while text[j] != "`":
            j += 2 if text[j] == "\\" else 1
        return j + 1
    depth, j = 1, i + 2
    while depth:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "'":
            j = text.index("'", j + 1) + 1
            continue
        if ch == '"':
            j += 1
            while text[j] != '"':
                if text[j] == "\\":
                    j += 2
                elif text.startswith("$(", j) or text[j] == "`":
                    j = _substitution_end(text, j)
                else:
                    j += 1
            j += 1
            continue
        if text.startswith("$(", j) or ch == "`":
            j = _substitution_end(text, j)
            continue
        depth += {"(": 1, ")": -1}.get(ch, 0)
        j += 1
    return j


def _shell_word(text: str, start: int) -> str:
    """The shell word at `start`, unquoted as the shell unquotes it.

    Expansions inside double quotes or unquoted are kept as written
    (`$NAME`), so the caller can substitute what the YAML defines; inside
    single quotes `$` is literal and is marked so it is never substituted.
    A command substitution is kept whole, nested quotes and all.
    """
    out: list[str] = []
    i = start
    while i < len(text):
        ch = text[i]
        if ch == "'":
            end = text.index("'", i + 1)
            out.append(text[i + 1 : end].replace("$", "\0"))
            i = end + 1
        elif ch == '"':
            i += 1
            while text[i] != '"':
                if text[i] == "\\" and text[i + 1] in '$`"\\\n':
                    nxt = text[i + 1]
                    out.append("" if nxt == "\n" else ("\0" if nxt == "$" else nxt))
                    i += 2
                elif text.startswith("$(", i) or text[i] == "`":
                    end = _substitution_end(text, i)
                    out.append(text[i:end])
                    i = end
                else:
                    out.append(text[i])
                    i += 1
            i += 1
        elif ch == "\\":
            out.append(text[i + 1])
            i += 2
        elif text.startswith("$(", i) or ch == "`":
            end = _substitution_end(text, i)
            out.append(text[i:end])
            i = end
        elif ch.isspace() or ch in ";|&()<>":
            break
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _substitute(program: str, params: dict[str, Any]) -> tuple[str, list[str]]:
    """Expand `$NAME` from the step's params; return what stays unexpanded.

    A `$` the shell keeps literal arrives here as NUL and is restored.
    """
    unresolved: list[str] = []

    def one(match: re.Match[str]) -> str:
        var = match.group(1) or match.group(2)
        value = params.get(var)
        if isinstance(value, str):
            return value
        unresolved.append(var)
        return match.group(0)

    return EXPANSION.sub(one, program).replace("\0", "$"), unresolved


def _heredoc(script: str, match: re.Match[str], params: dict[str, Any]) -> tuple[str, list[str]]:
    """The here-document's body as the shell feeds it to Python.

    It ends at a line that is exactly the delimiter (`<<-` strips leading
    tabs first), as the shell ends it. One that never ends comes back as a
    line that cannot compile, since the shell would hand Python the rest of
    the script. A quoted delimiter keeps `$` literal; an unquoted one
    expands it.
    """
    strip_tabs, quoted, tag = match.group(1), match.group(2), match.group(3)
    body: list[str] = []
    for raw in script[match.end() :].split("\n"):
        line = raw.lstrip("\t") if strip_tabs else raw
        if line == tag:
            break
        body.append(line)
    else:
        return f"<here-document {tag} is never closed>\n", []
    program = "\n".join(body) + "\n"
    return (program, []) if quoted else _substitute(program, params)


def _text(pipeline: str) -> str:
    return (PIPELINE_DIR / f"{pipeline}.yml").read_text(encoding="utf-8")


def _programs(
    pipeline: str, text: str | None = None
) -> Iterator[tuple[str, str, str, list[str]]]:
    """Yield (where, task, program, unexpanded vars) for every inline program."""
    doc = yaml.safe_load(_text(pipeline) if text is None else text)
    for task, params, run in _tasks(doc):
        path = str(run.get("path") or "")
        args = [a for a in (run.get("args") or []) if isinstance(a, str)]
        found: list[tuple[str, list[str]]] = []
        if Path(path).name in PYTHONS:
            for index, arg in enumerate(args[:-1]):
                if arg.startswith("-") and not arg.startswith("--") and arg.endswith("c"):
                    found.append((args[index + 1], []))
                    break
        else:
            for arg in args:
                for match in INLINE.finditer(arg):
                    found.append(_substitute(_shell_word(arg, match.end()), params))
                for match in HEREDOC.finditer(arg):
                    found.append(_heredoc(arg, match, params))
                for match in PY_FILE_HEREDOC.finditer(arg):
                    found.append(_heredoc(arg, match, params))
        for program, unresolved in found:
            yield f"{pipeline}.yml task {task}", task, program, unresolved
            for var in EXEC_ENV.findall(program):
                value = params.get(var)
                if isinstance(value, str):
                    yield f"{pipeline}.yml task {task} param {var}", task, value, []


def _first_line(program: str) -> str:
    return next((line.strip() for line in program.splitlines() if line.strip()), "")


def _all() -> list[tuple[str, str, str, str, list[str]]]:
    return [(pipeline, *row) for pipeline in PIPELINES for row in _programs(pipeline)]


def test_finds_the_inline_programs_this_test_exists_for() -> None:
    """The extractor sees report-verdict, its HEAD_SHA, the memory guard and the heredocs."""
    rows = _all()
    tasks = {(pipeline, task) for pipeline, _, task, _, _ in rows}
    assert ("thehub", "report-verdict") in tasks
    assert ("thehub", "export-tree") in tasks
    assert ("thehub", "gates") in tasks  # pr-gates' `python3 -I - <<'PROCESS'`
    assert any("param HEAD_SHA" in where for _, where, _, _, _ in rows)
    assert any("MEMORY_GUARD_DIR" in program for _, _, _, program, _ in rows)
    for pipeline in PIPELINES:
        assert any(row[0] == pipeline for row in rows), f"no inline Python found in {pipeline}.yml"


def _failures(
    rows: list[tuple[str, str, str, str, list[str]]],
) -> tuple[list[str], set[tuple[str, str, str]]]:
    """What does not compile, and which RUNTIME_ONLY entries were used."""
    failures: list[str] = []
    used: set[tuple[str, str, str]] = set()
    for pipeline, where, task, program, unresolved in rows:
        key = (pipeline, task, _first_line(program))
        if unresolved:
            if key in RUNTIME_ONLY:
                used.add(key)
                continue
            failures.append(f"{where}: ${unresolved[0]} is not set in the YAML: {key[2][:80]!r}")
            continue
        try:
            compile(program, f"<{where}>", "exec")
        except SyntaxError as exc:
            text = (exc.text or "").strip()
            failures.append(
                f"{where}: {type(exc).__name__}: {exc.msg} at line {exc.lineno}: {text!r}"
            )
    return failures, used


def test_every_inline_pipeline_program_compiles() -> None:
    failures, used = _failures(_all())
    stale = set(RUNTIME_ONLY) - used
    assert not failures, "inline Python that `python -c` refuses before running a line:\n" + (
        "\n".join(failures)
    )
    assert not stale, f"RUNTIME_ONLY entries that match nothing any more: {sorted(stale)}"


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("python -c 'print(1)' && x", "print(1)"),
        ('python3 -I -c "import os; print(\\"$X\\")"', 'import os; print("X1")'),
        ('A="$(python -c "$HEAD_SHA\nprint(1)")"', "def f(): pass\n\nprint(1)"),
        ("python -c 'a = \"$HOME\"'", 'a = "$HOME"'),
    ],
)
def test_shell_unquoting(script: str, expected: str) -> None:
    match = INLINE.search(script)
    assert match is not None
    params = {"X": "X1", "HEAD_SHA": "def f(): pass\n"}
    program, unresolved = _substitute(_shell_word(script, match.end()), params)
    assert (program, unresolved) == (expected, [])


def test_a_quoted_heredoc_keeps_dollar_literal_and_an_unclosed_one_fails() -> None:
    script = "python3 -I - <<'PY' || rc=$?\nprint('$X')\nPY\necho done\n"
    match = HEREDOC.search(script)
    assert match is not None
    assert _heredoc(script, match, {}) == ("print('$X')\n", [])
    unclosed = "python - <<'PY'\nprint(1)\n  PY\n"
    match = HEREDOC.search(unclosed)
    assert match is not None
    with pytest.raises(SyntaxError):
        compile(_heredoc(unclosed, match, {})[0], "<unclosed>", "exec")


# -- #62133: the blind spots, closed and kept closed --------------------------


def test_each_pipeline_holds_its_pinned_number_of_programs() -> None:
    """N3. A site the extractor stops seeing fails here, not as a quieter green."""
    counts = {pipeline: sum(1 for _ in _programs(pipeline)) for pipeline in PIPELINES}
    assert counts == PROGRAM_COUNTS


#: (pipeline, the opening line of a named site, the task it is in). Each is the
#: here-document whose body a mutation breaks.
NAMED_SITES = [
    # N1: the command runs over five lines before its `<<'PY'`.
    ("mykronos", "deploy/zap/requirements.txt <<'PY' || manifests_rc=$?", "osv-scanner"),
    # N2: programs written to a file and run later.
    ("personal-soc", "cat > check.py <<'PY'", "check-skills"),
    ("thehub", "cat > \"$ACCESS_DIR/hook.py\" <<'PY'", "zap-baseline"),
    ("thehub", "cat > \"$SEED_DIR/hook.py\" <<'PY'", "zap-baseline"),
    ("thehub", "cat > \"$SIGNER_DIR/hook.py\" <<'PY'", "zap-baseline-edge"),
    ("thehub", "cat > check.py <<'PY'", "model-inventory"),
]


def _mutated(pipeline: str, opener: str) -> str:
    """The pipeline with a line Python cannot parse at the top of the site's body."""
    lines = _text(pipeline).split("\n")
    (at,) = [i for i, line in enumerate(lines) if line.strip() == opener.strip()]
    body = next(line for line in lines[at + 1 :] if line.strip())
    indent = body[: len(body) - len(body.lstrip())]
    return "\n".join([*lines[: at + 1], f"{indent}def (:", *lines[at + 1 :]])


@pytest.mark.parametrize(("pipeline", "opener", "task"), NAMED_SITES)
def test_a_broken_program_at_each_named_site_turns_this_test_red(
    pipeline: str, opener: str, task: str | None
) -> None:
    """The AC of #62133: each site is really compiled, so breaking it fails."""
    rows = [(pipeline, *row) for row in _programs(pipeline, _mutated(pipeline, opener))]
    failures, _ = _failures(rows)

    assert len(failures) == 1, failures
    assert "def (:" in failures[0]
    if task is not None:
        assert f"task {task}:" in failures[0], failures[0]
    # The mutation adds a line, not a program: the pin still holds.
    assert len(rows) == PROGRAM_COUNTS[pipeline]


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        # N4: a quote inside $( ) inside a double-quoted program.
        (
            'python3 -c "import os; v = \'$(printf "%s" "$X")\'; print(1)" && done',
            "import os; v = '$(printf \"%s\" \"$X\")'; print(1)",
        ),
        # ... and inside backticks.
        (
            'python -c "v = \'`printf "%s" a`\'; print(2)"; echo',
            "v = '`printf \"%s\" a`'; print(2)",
        ),
        # Nested substitutions, a ) inside quotes, and an unquoted one.
        (
            'python -c "v = \'$(a "$(b ")")")\'; print(3)" x',
            "v = '$(a \"$(b \")\")\")'; print(3)",
        ),
    ],
)
def test_a_quote_nested_in_a_substitution_does_not_end_the_word(
    script: str, expected: str
) -> None:
    """N4. `_shell_word` used to stop at the first `"` inside `$( )` or
    backticks, so it compiled a fragment and the rest of the program went
    unchecked."""
    match = INLINE.search(script)
    assert match is not None
    assert _shell_word(script, match.end()) == expected


def test_code_after_a_nested_quote_is_still_compiled() -> None:
    """N4 as a mutation: the broken code sits after a nested quote holding a
    space, where the old word ended, so it was never compiled."""
    task = {
        "task": "t",
        "config": {
            "run": {
                "path": "sh",
                "args": ["-ec", 'python3 -c "v = \'$(printf "%s %s" a b)\'\ndef (:" || true\n'],
            }
        },
    }
    rows = [("x", *row) for row in _programs("x", yaml.safe_dump({"jobs": [{"plan": [task]}]}))]
    failures, _ = _failures(rows)
    assert len(rows) == 1 and len(failures) == 1, (rows, failures)
    assert "def (:" in failures[0]


def test_a_heredoc_command_over_several_lines_is_found() -> None:
    """N1 in isolation: continuations between `python -` and `<<'PY'`."""
    script = "python - a.json \\\n  b.txt \\\n  c.txt <<'PY' || rc=$?\nimport sys\nPY\n"
    match = HEREDOC.search(script)
    assert match is not None
    assert _heredoc(script, match, {}) == ("import sys\n", [])


@pytest.mark.parametrize(
    "opener",
    ["cat > check.py <<'PY'", 'cat > "$D/hook.py" <<PY', "cat >'x y.py' <<-'PY'"],
)
def test_a_program_written_to_a_py_file_is_found(opener: str) -> None:
    """N2 in isolation, quoted, unquoted and `<<-` forms."""
    script = f"{opener}\nimport os\nPY\npython3 check.py\n"
    match = PY_FILE_HEREDOC.search(script)
    assert match is not None
    assert _heredoc(script, match, {})[0] == "import os\n"


def test_a_heredoc_to_another_file_is_not_python() -> None:
    assert PY_FILE_HEREDOC.search("cat > tests.ps1 <<'PS'\nWrite-Host 1\nPS\n") is None
    assert PY_FILE_HEREDOC.search("cat > \"$ACCESS_SCRIPT\" <<'JS'\nvar a;\nJS\n") is None
