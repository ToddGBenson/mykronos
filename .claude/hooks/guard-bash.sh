#!/usr/bin/env bash
# PreToolUse hook for Bash, PowerShell and Monitor (TheHub #61099, #61108). After
# keel's guard-bash.sh.
#
# Refuses the tested spellings of:
#   * `ruff format`: this tree was never formatted with it;
#   * git that changes the live TheHub checkout (MYKRONOS_PROTECTED_CHECKOUTS, by
#     default <profile>/Documents/Projects/TheHub-main). Inside it git is
#     allow-listed: read-only verbs, fetch and merge --ff-only. Its
#     .claude/worktrees/<name> folders are separate worktrees and are not restricted;
#   * shell writes into that checkout: redirection, sed -i, tee, cp, mv, rm,
#     Set-Content, Out-File, Copy-Item, Move-Item and the rest;
#   * a command piped into bash, sh, iex or pwsh whose text it cannot read, and a
#     command word it cannot resolve next to the checkout.
#
# It guards against ordinary mistakes, not a determined bypass. What it reads, the
# gaps that remain, and when a hook cannot block at all (a timeout, a missing bash)
# are in estate_guard.py's docstring.
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
    && printf '%s' "$lc" | grep -qE '(^|[^a-z])(commit|reset|checkout|switch|stash|clean|restore|pull|merge|rebase|cherry-pick|revert|am|apply|rm|mv|tag|branch|config|remote|submodule|gc|update-ref)([^a-z]|$)'; then
    fallback_block guard-bash.sh "a git command that names the live checkout $name."
  fi
  # Shell writes (TheHub #61108): a redirection, sed -i, or a writing command or cmdlet.
  if printf '%s' "$lc" | grep -qF -- "$name" \
    && printf '%s' "$lc" | grep -qE '>|sed[^|;&]*[[:space:]]-[a-z]*i|(^|[^a-z-])(tee|cp|mv|rm|touch|mkdir|dd|copy|move|del|set-content|add-content|out-file|tee-object|copy-item|move-item|remove-item|new-item|rename-item|clear-content)([^a-z-]|$)'; then
    fallback_block guard-bash.sh "a shell write that names the live checkout $name."
  fi
done < <(protected_names)
exit 0
