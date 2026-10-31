#!/usr/bin/env bash
# PreToolUse hook for Write, Edit, MultiEdit and NotebookEdit (TheHub #61099). After
# keel's guard-write.sh.
#
# Refuses any path inside the live TheHub checkout (MYKRONOS_PROTECTED_CHECKOUTS, by
# default <profile>/Documents/Projects/TheHub-main): the production deploy ships that
# working tree. Its .claude/worktrees/<name> folders are separate worktrees and stay
# allowed.
#
# Contract: the hook payload on stdin; exit 2 blocks and stderr goes to the agent.

set -uo pipefail
payload="$(cat)"
# shellcheck source=_guard-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_guard-common.sh"

run_guard write
rc=$?
case "$rc" in 0 | 2) exit "$rc" ;; esac

# Fallback: Python did not run. Judge the path field, coarsely and closed.
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
