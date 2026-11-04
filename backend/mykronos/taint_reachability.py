"""Can request input reach this sink? Semgrep taint mode, for a named list of
rules, with the import graph kept as the floor (TheHub #60745, #60736 option A).

`reachability.py` answers a narrower question — does anything import this
file — and says so. For most findings that is still the only answer this
platform has. For a short, named list of Semgrep audit rules it can now do
better: those rules fire on *any* non-constant argument to a dangerous call
(`shell=True`, `eval`, `exec`), whatever the argument came from, and a taint
run with known sources and sinks can say whether a web request's input is
what reaches it.

The rule throughout #60736 is that a model proposes and something
deterministic decides. Nothing here involves a model: the verdict is a lookup
of the taint run's matches by rule, path and line.

**What each verdict means, and what it never means**

* ``reachable`` — Semgrep found a flow from a request source to this rule's
  sink, on the finding's lines, in a file something imports. The trace (source,
  intermediate variables, sink) is cited with the verdict.
* ``unreachable`` — only ever the import floor's answer: the file is orphaned.
  Taint never produces it on its own. Semgrep OSS taint is intraprocedural, so
  "no trace" includes every flow through a helper function in another file,
  and turning that into "unreachable" would discount live findings, which is
  the one failure mode reachability must not have (spec 19 §2.1).
* ``unknown`` — everything else, including every case where Semgrep failed,
  timed out, was not installed, or reported an error for the file. A failure
  is never evidence of absence.

A rule with no taint spec keeps exactly the floor's verdict, so adding this
changed nothing for any rule outside :data:`TAINT_SPECS`.

**Runner-side, like the import graph.** The analysis needs the checkout; the
platform stores what the runner reports (`TaintRun.as_submission`) and decides
each finding's verdict when it is read (`verdict_for`). Matches carry paths,
lines, and the source and sink expressions — never file contents.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Verdict = Literal["reachable", "unreachable", "unknown"]
Basis = Literal["taint", "import_floor"]

#: How long one Semgrep taint run may take before it is a failure. Generous:
#: the job's own timeout is 90 minutes and the rule packs run first.
DEFAULT_TIMEOUT_SECONDS = 600

#: Attacker input as Semgrep sees it: the Flask request object, and any
#: parameter of a function registered as a route (Flask, FastAPI and the
#: like). Deliberately not `sys.argv`, `input()` or the environment: those are
#: the operator's input, and calling them attacker-controlled would mark every
#: CLI and every configured command reachable.
_REQUEST_SOURCES: list[dict[str, Any]] = [
    {"pattern": "flask.request.$ANY"},
    {
        "patterns": [
            {
                "pattern-inside": (
                    "@$ROUTER.$VERB(...)\n"
                    "def $HANDLER(..., $PARAM, ...):\n"
                    "  ...\n"
                )
            },
            {
                "metavariable-regex": {
                    "metavariable": "$VERB",
                    "regex": "^(route|get|post|put|patch|delete|api_route)$",
                }
            },
            {"focus-metavariable": "$PARAM"},
        ]
    },
]

#: The taint rules, by id. Each is a Semgrep rule body in taint mode.
TAINT_RULES: dict[str, dict[str, Any]] = {
    "mykronos-taint-shell-command": {
        "message": "request input reaches a shell command",
        "pattern-sources": _REQUEST_SOURCES,
        # Quoting is what makes a shell argument safe; a quoted value is not
        # a flow anybody needs to act on.
        "pattern-sanitizers": [{"pattern": "shlex.quote(...)"}],
        "pattern-sinks": [
            {
                "patterns": [
                    {"pattern": "subprocess.$FUNC($CMD, ..., shell=True, ...)"},
                    {"focus-metavariable": "$CMD"},
                ]
            }
        ],
    },
    "mykronos-taint-code-eval": {
        "message": "request input reaches eval or exec",
        "pattern-sources": _REQUEST_SOURCES,
        "pattern-sinks": [
            {
                "patterns": [
                    {
                        "pattern-either": [
                            {"pattern": "eval($CODE, ...)"},
                            {"pattern": "exec($CODE, ...)"},
                        ]
                    },
                    {"focus-metavariable": "$CODE"},
                ]
            }
        ],
    },
}

#: The named list: a reported rule id → the taint rule that decides it. These
#: are audit rules from `p/security-audit` that fire on any non-constant
#: argument, which is exactly where knowing the argument's origin changes the
#: answer. A rule absent here gets the import floor's verdict, unchanged.
TAINT_SPECS: dict[str, str] = {
    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": (
        "mykronos-taint-shell-command"
    ),
    "python.lang.security.audit.eval-detected.eval-detected": "mykronos-taint-code-eval",
    "python.lang.security.audit.exec-detected.exec-detected": "mykronos-taint-code-eval",
}

NO_TRACE_REASON = (
    "no taint flow from a request source reaches this sink. Not proof of no "
    "flow: Semgrep OSS taint is intraprocedural, so input passed through a "
    "function in another file is not seen"
)


def semgrep_config() -> dict[str, Any]:
    """The taint rules as one Semgrep config (JSON is valid YAML)."""
    return {
        "rules": [
            {
                "id": rule_id,
                "mode": "taint",
                "languages": ["python"],
                "severity": "INFO",
                **body,
            }
            for rule_id, body in TAINT_RULES.items()
        ]
    }


def normalise_path(path: str | None) -> str:
    text = str(path or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


@dataclass(frozen=True)
class TaintMatch:
    """One source-to-sink flow Semgrep found."""

    taint_rule: str
    path: str
    start_line: int
    end_line: int
    trace: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "taint_rule": self.taint_rule,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "trace": self.trace,
        }


@dataclass
class TaintRun:
    """What one taint run established. `status` is the whole story when it is
    not `ok`: every covered finding is then `unknown`."""

    status: Literal["ok", "failed", "not_run"]
    reason: str = ""
    matches: list[TaintMatch] = field(default_factory=list)
    #: Files Semgrep reported an error for (a per-file timeout, a parse
    #: failure). Their covered findings are `unknown`, not "no trace".
    failed_paths: set[str] = field(default_factory=set)
    semgrep_version: str = ""

    @classmethod
    def failed(cls, reason: str) -> TaintRun:
        return cls(status="failed", reason=reason)

    def as_submission(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason[:1000],
            "semgrep_version": self.semgrep_version,
            "rules": sorted(TAINT_SPECS),
            "matches": [m.as_dict() for m in self.matches],
            "failed_paths": sorted(self.failed_paths),
        }

    @classmethod
    def from_submission(cls, body: dict[str, Any] | None) -> TaintRun | None:
        if not body:
            return None
        status = body.get("status")
        if status not in ("ok", "failed", "not_run"):
            return cls.failed(f"unrecognised taint status {status!r}")
        return cls(
            status=status,
            reason=str(body.get("reason") or ""),
            semgrep_version=str(body.get("semgrep_version") or ""),
            failed_paths={normalise_path(p) for p in body.get("failed_paths") or []},
            matches=[
                TaintMatch(
                    taint_rule=str(m.get("taint_rule") or ""),
                    path=normalise_path(m.get("path")),
                    start_line=int(m.get("start_line") or 0),
                    end_line=int(m.get("end_line") or m.get("start_line") or 0),
                    trace=dict(m.get("trace") or {}),
                )
                for m in body.get("matches") or []
            ],
        )


@dataclass(frozen=True)
class ReachabilityVerdict:
    verdict: Verdict
    basis: Basis
    reason: str
    trace: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "basis": self.basis,
            "reason": self.reason,
            "trace": self.trace,
        }


# --------------------------------------------------------------------------
# Running Semgrep
# --------------------------------------------------------------------------


def _location(node: Any) -> dict[str, Any] | None:
    """`["CliLoc", [loc, content]]` → `{path, line, content}`.

    A `CliCall` (a flow through a call) nests a `CliLoc` first; the outermost
    location is the one a reader needs.
    """
    if not isinstance(node, list) or len(node) != 2:
        return None
    kind, value = node
    if kind == "CliLoc" and isinstance(value, list) and len(value) == 2:
        loc, content = value
        return {
            "path": normalise_path(loc.get("path")),
            "line": int((loc.get("start") or {}).get("line") or 0),
            "content": str(content)[:200],
        }
    if kind == "CliCall" and isinstance(value, list) and value:
        return _location(["CliLoc", value[0]]) if isinstance(value[0], list) else None
    return None


def _trace(rule: str, raw: dict[str, Any] | None) -> dict[str, Any]:
    raw = raw or {}
    return {
        "taint_rule": rule,
        "source": _location(raw.get("taint_source")),
        "intermediate": [
            {
                "path": normalise_path((v.get("location") or {}).get("path")),
                "line": int(((v.get("location") or {}).get("start") or {}).get("line") or 0),
                "content": str(v.get("content") or "")[:200],
            }
            for v in (raw.get("intermediate_vars") or [])[:20]
            if isinstance(v, dict)
        ],
        "sink": _location(raw.get("taint_sink")),
    }


def parse_semgrep_output(text: str) -> TaintRun:
    """Semgrep's `--json --dataflow-traces` output as a `TaintRun`."""
    try:
        body = json.loads(text)
    except (ValueError, TypeError) as exc:
        return TaintRun.failed(f"semgrep output was not JSON: {exc}")
    if not isinstance(body, dict) or not isinstance(body.get("results"), list):
        return TaintRun.failed("semgrep output had no results list")

    known = set(TAINT_RULES)
    matches: list[TaintMatch] = []
    for result in body["results"]:
        # Semgrep prefixes a rule id with the config file's directories.
        rule = str(result.get("check_id") or "").rsplit(".", 1)[-1]
        if rule not in known:
            continue
        path = normalise_path(result.get("path"))
        start = int((result.get("start") or {}).get("line") or 0)
        end = int((result.get("end") or {}).get("line") or start)
        matches.append(
            TaintMatch(
                taint_rule=rule,
                path=path,
                start_line=start,
                end_line=max(start, end),
                trace=_trace(rule, (result.get("extra") or {}).get("dataflow_trace")),
            )
        )

    failed_paths = {
        normalise_path(error.get("path"))
        for error in body.get("errors") or []
        if isinstance(error, dict) and error.get("path")
    }
    return TaintRun(
        status="ok",
        matches=matches,
        failed_paths=failed_paths,
        semgrep_version=str(body.get("version") or ""),
    )


Runner = Callable[..., Any]


def run_semgrep(
    root: str | os.PathLike[str],
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    command: Iterable[str] = ("semgrep",),
    runner: Runner = subprocess.run,
) -> TaintRun:
    """Run the taint rules over `root`. Any failure is a failed run.

    The config is written locally and passed by path: no registry pack, and
    `--metrics off`, so neither the rules nor the source leave the runner.
    """
    with tempfile.TemporaryDirectory(prefix="mykronos-taint-") as scratch:
        config = Path(scratch) / "taint.json"
        config.write_text(json.dumps(semgrep_config()), encoding="utf-8")
        cmd = [
            *command,
            "scan",
            "--config",
            str(config),
            "--json",
            "--dataflow-traces",
            "--metrics",
            "off",
            "--quiet",
            "--timeout",
            "30",
            # Run from the root at ".", so every path Semgrep reports is
            # already repo-relative, like the import graph's.
            ".",
        ]
        try:
            done = runner(
                cmd,
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return TaintRun.failed(f"semgrep timed out after {timeout}s")
        except OSError as exc:
            return TaintRun.failed(f"semgrep could not start: {exc}")

    # 0 is clean and 1 is "findings"; anything else is Semgrep failing.
    if done.returncode not in (0, 1):
        tail = (done.stderr or "").strip().splitlines()[-1:] or [""]
        return TaintRun.failed(f"semgrep exited {done.returncode}: {tail[0][:300]}")
    return parse_semgrep_output(done.stdout or "")


# --------------------------------------------------------------------------
# Deciding
# --------------------------------------------------------------------------


def floor_verdict(path: str | None, orphaned: set[str]) -> ReachabilityVerdict:
    """The import graph's answer, exactly as spec 19 §2.1 gives it today.

    Orphaned is `unreachable`. Anything else is `unknown`: an imported file is
    not proven reachable, and a file the graph does not cover (anything not
    Python) is not in the answer at all.
    """
    p = normalise_path(path)
    if p.endswith(".py") and p in {normalise_path(o) for o in orphaned}:
        return ReachabilityVerdict(
            "unreachable",
            "import_floor",
            f"{p} is imported by nothing in the repository and is not an entry point",
        )
    return ReachabilityVerdict(
        "unknown",
        "import_floor",
        "import reachability does not prove a file is reached, only that it is "
        "or is not imported",
    )


def verdict_for(
    rule_id: str,
    path: str | None,
    line_start: int | None,
    line_end: int | None = None,
    *,
    orphaned: set[str],
    taint: TaintRun | None,
) -> ReachabilityVerdict:
    """The reachability verdict for one finding."""
    taint_rule = TAINT_SPECS.get(str(rule_id or ""))
    if taint_rule is None:
        return floor_verdict(path, orphaned)

    p = normalise_path(path)
    if taint is None or taint.status == "not_run":
        return ReachabilityVerdict("unknown", "taint", "taint analysis has not run")
    if taint.status != "ok":
        return ReachabilityVerdict(
            "unknown", "taint", f"taint analysis failed: {taint.reason or 'no reason given'}"
        )
    if p in taint.failed_paths:
        return ReachabilityVerdict(
            "unknown", "taint", f"semgrep reported an error analysing {p}"
        )
    if not p.endswith(".py"):
        return ReachabilityVerdict("unknown", "taint", "taint rules cover Python only")

    floor = floor_verdict(p, orphaned)
    if floor.verdict == "unreachable":
        return floor

    start = int(line_start or 0)
    end = max(start, int(line_end or start))
    for match in taint.matches:
        if (
            match.taint_rule == taint_rule
            and match.path == p
            and match.start_line <= end
            and start <= match.end_line
        ):
            return ReachabilityVerdict(
                "reachable",
                "taint",
                f"request input reaches this sink ({taint_rule})",
                match.trace or {"taint_rule": taint_rule},
            )
    return ReachabilityVerdict("unknown", "taint", NO_TRACE_REASON)
