#!/usr/bin/env bash
# PreToolUse hook for Bash and PowerShell (TheHub #61099). After keel's guard-bash.sh.
#
# Refuses, in any spelling and through any interpreter:
#   * `ruff format`: this tree was never formatted with it;
#   * git commit / reset / checkout / switch / stash / clean / restore whose target is
#     the live TheHub checkout (MYKRONOS_PROTECTED_CHECKOUTS, by default
#     <profile>/Documents/Projects/TheHub-main). Its .claude/worktrees/<name> folders
#     are separate worktrees and stay allowed.
#
# Contract: the hook payload on stdin; exit 2 blocks and stderr goes to the agent.
# The rules are in estate_guard.py; the tests, which are bypass attempts first, are
# backend/tests/test_claude_hooks.py.

set -uo pipefail
payload="$(cat)"
# shellcheck source=_guard-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_guard-common.sh"

run_guard bash
rc=$?
case "$rc" in 0 | 2) exit "$rc" ;; esac

# Fallback: Python did not run. Judge the raw payload, coarsely and closed.
lc="$(printf '%s' "$payload" | tr '[:upper:]' '[:lower:]')"
if printf '%s' "$lc" | grep -qE 'ruff[^a-z0-9_]{1,12}format'; then
  fallback_block guard-bash.sh "a command that looks like \`ruff format\`."
fi
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if printf '%s' "$lc" | grep -qF -- "$name" \
    && printf '%s' "$lc" | grep -qE '(^|[^a-z])(commit|reset|checkout|switch|stash|clean|restore)([^a-z]|$)'; then
    fallback_block guard-bash.sh "a git command that names the live checkout $name."
  fi
done < <(protected_names)
exit 0
