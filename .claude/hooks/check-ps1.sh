#!/usr/bin/env bash
# PostToolUse hook for Write, Edit and MultiEdit (TheHub #61099).
#
# When the file written is a PowerShell script (.ps1, .psm1, .psd1), runs the
# PowerShell parser over it (pwsh -NoProfile, Parser::ParseFile) and returns every
# parse error to the agent: exit 2, with line and column on stderr. The file has
# already been saved; this makes the agent see the error now instead of when the
# operator runs the script. Any other file, a missing file, or no pwsh: exit 0.

set -uo pipefail
payload="$(cat)"
# shellcheck source=_guard-common.sh
. "$(dirname "${BASH_SOURCE[0]}")/_guard-common.sh"

run_guard ps1
rc=$?
case "$rc" in 2) exit 2 ;; esac
exit 0
