# Sourced by guard-bash.sh, guard-write.sh and check-ps1.sh (TheHub #61099).
#
# The rules live in estate_guard.py, which reads the command the way the shell will.
# These wrappers find a Python, hand it the payload, and pass its verdict through.
# When Python cannot run at all (exit other than 0 or 2), each wrapper applies a
# coarse fallback of its own, so a missing interpreter fails closed on the obvious
# forms instead of silently allowing everything.
#
# MYKRONOS_HOOK_PYTHON names the interpreter; otherwise the first of python3, python
# and py on PATH. Works under Git Bash on Windows and bash on Linux.

hook_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_python() {
  if [ -n "${MYKRONOS_HOOK_PYTHON:-}" ]; then
    printf '%s' "$MYKRONOS_HOOK_PYTHON"
    return
  fi
  local c
  for c in python3 python py; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return
    fi
  done
}

# run_guard <bash|write|ps1>: the payload is in $payload; returns the guard's exit code.
run_guard() {
  local py
  py="$(find_python)"
  [ -n "$py" ] || return 3
  printf '%s' "$payload" | "$py" -I "$hook_dir/estate_guard.py" "$1"
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
