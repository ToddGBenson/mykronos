# Sourced by guard-bash.sh, guard-write.sh and check-ps1.sh (TheHub #61099).
#
# The rules live in estate_guard.py, which reads the command the way the shell will.
# These wrappers find a Python, hand it the payload, and pass its verdict through.
# When Python cannot start at all (not found, or exit 126/127), each guard applies a
# coarse fallback of its own, so a missing interpreter fails closed on the obvious
# forms instead of silently allowing everything. When Python starts and exits with
# anything but 0 or 2, the guards block outright (TheHub #61831): a policy engine that
# crashed on this input has not judged it, and the fallback is too coarse to.
#
# MYKRONOS_HOOK_PYTHON names the interpreter; otherwise the first of python3, python
# and py on PATH. Works under Git Bash on Windows and bash on Linux.
#
# TheHub #61831: FAIL CLOSED, after keel's guard-bash.sh (keel #179, TheHub #61794).
# guard-bash.sh and guard-write.sh call guard_fail_closed before they read anything.
# The fallbacks read the payload through tr, grep and sed inside $(...) captures and
# `printf ... | grep -q` tests, and nothing checked that those helpers ran: one that
# failed left a capture empty, no rule matched, and the hook reached `exit 0`. A
# failing cat or dirname did the same even with Python present (an empty payload, or
# no _guard-common.sh at all). Four things close it:
#
# 1. Helpers run through wrappers that record a real error in a fault file, and the
#    EXIT trap turns an allow into a block when the file holds one. Wrappers are
#    functions, so they reach every subshell, pipeline and capture. grep's 1 (no
#    match) is not a fault; neither is 141 (SIGPIPE), which also returns 0 so that a
#    writer whose reader stopped early never flips a pipeline's status.
#
# 2. No early exits. grep -q stops at its first match; under pipefail the writer
#    feeding it can then die of SIGPIPE and the pipeline reports 141, so a MATCH reads
#    as "no match" on a command larger than the pipe buffer. The grep wrapper drops -q
#    and discards its output instead, and head drains what it does not print, so every
#    reader consumes all its input.
#
# 3. The hook allows only by exiting 0 and blocks only by exiting 2. Claude Code treats
#    any other code as a non-blocking error and runs the call, so the EXIT trap makes
#    every other code (an unbound variable, a failed fork, a crash) a block. The fault
#    file starts with a sentinel line, so one emptied or removed behind the hook's back
#    reads as a fault, not as "no faults". The trap uses bash builtins only.
#
# 4. PATH is pinned for the helpers. Python is resolved first, on the PATH the hook
#    inherited, and runs with that PATH (estate_guard.py resolves command words and
#    pwsh with it); then PATH becomes /usr/bin:/bin, so a tr or grep planted earlier
#    on PATH (in ~/bin, say) cannot answer for the real one.
#
# MYKRONOS_HOOK_FAULT_INJECT (tests only): a space-separated list of helper names that
# the wrappers treat as failed (exit 2) without running them. It can only make a
# helper fail, so the worst it can do is block a call. With PATH pinned it is the only
# way a test can make a helper fail.

guard_here="${BASH_SOURCE[0]}"
case "$guard_here" in
  */* | *\\*) guard_here="${guard_here%[/\\]*}" ;;
  *) guard_here=. ;;
esac
hook_dir="$(cd "$guard_here" && pwd)" || hook_dir="$guard_here"
[ -n "$hook_dir" ] || hook_dir="$guard_here"
guard_faults=""

# guard_find_python: sets guard_python to the interpreter's path, or "" when there is
# none. `hash` and BASH_CMDS are builtins and need no subshell, so a failed fork cannot
# pass for "no Python".
guard_find_python() {
  local c
  guard_python=""
  if [ -n "${MYKRONOS_HOOK_PYTHON:-}" ]; then
    guard_python="$MYKRONOS_HOOK_PYTHON"
    case "$guard_python" in
      */* | *\\*) ;;
      *) hash -- "$guard_python" 2>/dev/null && guard_python="${BASH_CMDS[$guard_python]:-$guard_python}" ;;
    esac
    return 0
  fi
  for c in python3 python py; do
    if hash -- "$c" 2>/dev/null && [ -n "${BASH_CMDS[$c]:-}" ]; then
      guard_python="${BASH_CMDS[$c]}"
      return 0
    fi
  done
  return 0
}

guard_fault() { # $1: tool, $2: its exit status
  [ -n "$guard_faults" ] || return 0
  printf '%s exited %s\n' "$1" "$2" >> "$guard_faults" 2>/dev/null
}
guard_run() { # $1: tool, $2: highest exit status that is not an error; the rest: its args
  local t=$1 ok=$2 rc
  shift 2
  case " ${MYKRONOS_HOOK_FAULT_INJECT:-} " in
    *" $t "*) rc=2 ;;
    *)
      command "$t" "$@"
      rc=$?
      ;;
  esac
  [ "$rc" -eq 141 ] && return 0
  [ "$rc" -gt "$ok" ] && guard_fault "$t" "$rc"
  return "$rc"
}
# shellcheck disable=SC2317  # the wrappers are called indirectly, by name, from the rules
grep() { # -q (and --quiet/--silent) dropped, output discarded: grep reads all its input
  local a args=() quiet=0 opts=1
  for a in "$@"; do
    if [ "$opts" -eq 1 ]; then
      case "$a" in
        --) opts=0 ;;
        --quiet | --silent)
          quiet=1
          continue
          ;;
        --*) ;;
        -*q*)
          quiet=1
          a="${a//q/}"
          [ "$a" = "-" ] && continue
          ;;
        -*) ;;
        *) opts=0 ;;
      esac
    fi
    args+=("$a")
  done
  if [ "$quiet" -eq 1 ]; then guard_run grep 1 "${args[@]}" >/dev/null; else guard_run grep 1 "${args[@]}"; fi
}
# shellcheck disable=SC2317
head() {
  guard_run head 0 "$@"
  command cat >/dev/null 2>&1
  return 0
}
# shellcheck disable=SC2317
sed() { guard_run sed 0 "$@"; }
# shellcheck disable=SC2317
awk() { guard_run awk 0 "$@"; }
# shellcheck disable=SC2317
tr() { guard_run tr 0 "$@"; }
# shellcheck disable=SC2317
cat() { guard_run cat 0 "$@"; }
# shellcheck disable=SC2317
cut() { guard_run cut 0 "$@"; }

# guard_fail_closed <hook name>: resolve Python on the inherited PATH, pin PATH for the
# helpers, create the fault file and set the EXIT trap. Called before the payload is read.
guard_fail_closed() {
  guard_hook=$1
  guard_inherited_path=$PATH
  guard_find_python
  PATH=/usr/bin:/bin
  export PATH
  guard_sentinel="$guard_hook fault file $$"
  guard_faults="$(guard_run mktemp 0 2>/dev/null)" && [ -n "$guard_faults" ] \
    && printf '%s\n' "$guard_sentinel" > "$guard_faults" 2>/dev/null || {
    echo "BLOCKED by .claude/hooks/$guard_hook — internal error: cannot create its fault file, so it cannot tell whether its own checks ran. Retry the call." >&2
    exit 2
  }
  trap guard_exit EXIT
}

# shellcheck disable=SC2317  # run by the EXIT trap
guard_exit() { # builtins only: a broken helper must not be able to hide its own fault
  local rc=$? why="" lines=()
  [ -f "$guard_faults" ] && mapfile -t lines < "$guard_faults" 2>/dev/null
  if [ "$rc" -ne 2 ]; then
    if [ "${#lines[@]}" -eq 0 ] || [ "${lines[0]}" != "$guard_sentinel" ]; then
      why="its fault file was emptied or removed while it ran"
    elif [ "${#lines[@]}" -gt 1 ]; then
      why="a helper it reads the payload with failed (${lines[*]:1:3})"
    elif [ "$rc" -ne 0 ]; then
      why="it stopped with exit $rc before reaching a verdict"
    fi
  fi
  command rm -f "$guard_faults" 2>/dev/null
  if [ -n "$why" ]; then
    {
      echo "BLOCKED by .claude/hooks/$guard_hook — internal error: $why, so it cannot tell whether the call is allowed."
      echo ""
      echo "This is the guard failing closed (TheHub #61831), not a rule. Retry the call; if it"
      echo "keeps happening, the host is short of a tool or of resources."
    } >&2
    exit 2
  fi
  exit "$rc"
}

# run_guard <bash|write|ps1>: the payload is in $payload; returns the guard's exit code.
# guard_python_started tells the caller whether Python ran at all.
run_guard() {
  local rc
  [ -n "${guard_python+x}" ] || guard_find_python
  guard_python_started=0
  [ -n "$guard_python" ] || return 3
  printf '%s' "$payload" | PATH="${guard_inherited_path:-$PATH}" "$guard_python" -I "$hook_dir/estate_guard.py" "$1"
  rc=$?
  case "$rc" in 126 | 127) ;; *) guard_python_started=1 ;; esac
  return "$rc"
}

# guard_judge_or_fall_back <rc>: Python's verdict (0 or 2) is final. Any other exit from
# a Python that started blocks. Only a Python that could not start returns, so the
# caller's coarse fallback runs.
guard_judge_or_fall_back() {
  case "$1" in 0 | 2) exit "$1" ;; esac
  if [ "${guard_python_started:-1}" -ne 0 ]; then
    {
      echo "BLOCKED by .claude/hooks/$guard_hook — internal error: its policy engine (estate_guard.py) exited $1 without a verdict, so it cannot tell whether the call is allowed."
      echo ""
      echo "This is the guard failing closed (TheHub #61831), not a rule. Retry the call; if it"
      echo "keeps happening, run the guard by hand to see Python's error."
    } >&2
    exit 2
  fi
  return 0
}

# The lower-cased last path component of each protected checkout, for the fallbacks.
protected_names() {
  local raw="${MYKRONOS_PROTECTED_CHECKOUTS:-TheHub-main}" item
  local IFS=';'
  for item in $raw; do
    item="${item//\\//}"
    item="${item%/}"
    item="${item##*/}"
    [ -n "$item" ] && printf '%s\n' "$item" | tr '[:upper:]' '[:lower:]'
  done
}

fallback_block() {
  echo "BLOCKED by .claude/hooks/$1: $2" >&2
  echo "" >&2
  echo "Python could not run, so this is the coarse fallback check; it refuses anything" >&2
  echo "that looks like the action. Fix the interpreter (MYKRONOS_HOOK_PYTHON) and retry." >&2
  exit 2
}
