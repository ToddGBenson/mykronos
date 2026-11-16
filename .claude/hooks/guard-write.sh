#!/usr/bin/env bash
# PreToolUse hook for Write, Edit, MultiEdit and NotebookEdit (TheHub #61099). After
# keel's guard-write.sh.
#
# Refuses any path inside the live TheHub checkout (MYKRONOS_PROTECTED_CHECKOUTS, by
# default <profile>/Documents/Projects/TheHub-main): the production deploy ships that
# working tree. Its .claude/worktrees/<name> folders are separate worktrees and stay
# allowed.
#
# This covers the file tools; shell writes into the checkout (sed -i, echo >, cp,
# tee, Set-Content, Out-File) are refused by guard-bash.sh. Paths are canonicalised
# first (8.3 short names, UNC and device paths, a trailing dot, globs, junctions and
# symlinks): see estate_guard.py (TheHub #61108).
#
# Contract: the hook payload on stdin; exit 2 blocks and stderr goes to the agent.

set -uo pipefail
# TheHub #61831: load the shared wrappers and fail closed before anything is read (see
# _guard-common.sh). No dirname: a helper that fails here would lose the wrappers.
case "${BASH_SOURCE[0]}" in
  */* | *\\*) guard_dir="${BASH_SOURCE[0]%[/\\]*}" ;;
  *) guard_dir=. ;;
esac
# shellcheck source=_guard-common.sh
. "$guard_dir/_guard-common.sh" && guard_fail_closed guard-write.sh || {
  echo "BLOCKED by .claude/hooks/guard-write.sh — internal error: it could not load _guard-common.sh, so it cannot judge the call. Retry the call." >&2
  exit 2
}
payload="$(cat)"

run_guard write
guard_judge_or_fall_back $?

# Fallback: Python could not start. Judge the path field, coarsely and closed.
path="$(printf '%s' "$payload" \
  | sed -nE 's/.*"(file_path|notebook_path)"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)".*/\2/p' \
  | tr '[:upper:]\\' '[:lower:]/')"
[ -n "$path" ] || exit 0
while IFS= read -r name; do
  [ -n "$name" ] || continue
  case "$path" in
    *"/$name/"* | *"/$name")
      if ! printf '%s' "$path" | grep -qE -- "/${name}/+\.claude/+worktrees/+[^/.][^/]*/" \
        || printf '%s' "$path" | grep -qF '/../'; then
        fallback_block guard-write.sh "writing inside the live checkout $name."
      fi
      ;;
  esac
done < <(protected_names)
exit 0
