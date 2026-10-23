"""Ask Mykronos for a risk decision on one pull request (TheHub #60927).

Run by `.github/workflows/pr-gate.yml` on every pull request that opens, moves
or reopens. It replaces `mykronos-oracle.yml`, which did this until the
Concourse migration deleted it (766ca5f, mykronos#340). Concourse builds
`main` only, so from 2026-09-05 no pull request here got a `pr_gate` decision.

What it does:

1. POSTs `{decision_type: pr_gate, commit_sha, pr_number}` to
   `/api/oracle/evaluate` with the repository's ingestion token. The platform
   records the decision and posts `Mykronos / risk decision` on the head commit
   through its GitHub App, the same check run keel and binnacle show.
2. Fails (exit 1) on a block verdict: the decision says this commit introduced
   an open critical or high finding (`introduced_blocking`, D-048). The
   composite score is printed, never decisive: it describes the whole backlog,
   and a gate on it refuses every change regardless of content.
3. Fails when it cannot tell. No token, no answer, or an `introduced_blocking`
   that is not exactly true or false is a red job, never a green one.

Standard library only: it runs on a bare runner before anything is installed.
Environment: MYKRONOS_URL, MYKRONOS_INGESTION_TOKEN, PR_NUMBER, HEAD_SHA, and
GITHUB_STEP_SUMMARY when GitHub provides it.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

EVALUATE_PATH = "/api/oracle/evaluate"
TIMEOUT_SECONDS = 120

Post = Callable[[str, str, dict[str, Any]], dict[str, Any]]


def request_body(head_sha: str, pr_number: int) -> dict[str, Any]:
    """The evaluate request. No repository: the platform takes it from the token."""
    return {"decision_type": "pr_gate", "commit_sha": head_sha, "pr_number": pr_number}


def http_post(url: str, token: str, body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
        loaded: dict[str, Any] = json.loads(response.read().decode("utf-8"))
        return loaded


def verdict(decision: Mapping[str, Any]) -> tuple[bool, list[str]]:
    """(refuse, lines to print). Refuses on an introduced blocking finding or
    on an answer it cannot read."""
    lines: list[str] = []
    recommendation = decision.get("recommendation")
    score = decision.get("overall_risk_score")
    lines.append(f"Risk decision: {recommendation} (score {score}/100).")
    reasoning = decision.get("reasoning")
    if reasoning:
        lines.append(str(reasoning))

    recorded_as = decision.get("decision_type")
    if recorded_as != "pr_gate":
        lines.append(
            f"::warning::The platform recorded this as {recorded_as!r}, not 'pr_gate'. "
            "The request named a pull request, so this caller needs a look (#275)."
        )

    if decision.get("check_run_id") is None:
        error = decision.get("check_run_error")
        if error:
            lines.append(f"::warning::Decision recorded, but the check run was not posted: {error}")
        else:
            lines.append(
                "::warning::Decision recorded, but no check run was posted: the platform "
                "has no App installation to post it through."
            )

    if recommendation == "no_go":
        lines.append(
            f"::warning::The repository scores no_go at {score}/100. That is the standing "
            "backlog, not this change (D-048), so it does not fail this check."
        )

    introduced = decision.get("introduced") or {}
    critical = int(introduced.get("critical", 0) or 0)
    high = int(introduced.get("high", 0) or 0)
    flag = decision.get("introduced_blocking")
    if flag is True:
        lines.append(
            f"::error::This pull request introduced {critical} critical and {high} high "
            "open finding(s). The floor is no new criticals and no new highs: fix them, or "
            "disposition them (an accepted risk with a reason does not block)."
        )
        return True, lines
    if flag is False:
        lines.append(f"Introduced by this pull request: {critical} critical, {high} high.")
        return False, lines
    lines.append(
        f"::error::The decision has introduced_blocking={flag!r}, not true or false. The "
        "gate cannot tell whether this change introduced a blocking finding, so it does "
        "not pass."
    )
    return True, lines


def _summary(environ: Mapping[str, str], lines: list[str]) -> None:
    path = environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("## Mykronos risk decision\n\n")
        for line in lines:
            handle.write(line.split("::", 2)[-1] + "\n\n")


def main(environ: Mapping[str, str] | None = None, post: Post = http_post) -> int:
    environ = os.environ if environ is None else environ
    token = environ.get("MYKRONOS_INGESTION_TOKEN", "")
    if not token:
        print(
            "::error::No ingestion token. A fork's or Dependabot's run gets no repository "
            "secret, so no risk decision was asked for and none was recorded."
        )
        return 1
    try:
        pr_number = int(environ.get("PR_NUMBER", ""))
    except ValueError:
        print("::error::PR_NUMBER is not a pull request number.")
        return 1
    head_sha = environ.get("HEAD_SHA", "")
    if not head_sha:
        print("::error::HEAD_SHA is empty.")
        return 1

    url = environ.get("MYKRONOS_URL", "").rstrip("/") + EVALUATE_PATH
    try:
        decision = post(url, token, request_body(head_sha, pr_number))
    except (OSError, urllib.error.URLError, ValueError) as exc:
        # The reason only: an HTTPError's body is the platform's own message,
        # and nothing here echoes the request or its headers.
        print(f"::error::Could not get a risk decision: {type(exc).__name__}: {exc}")
        return 1

    refuse, lines = verdict(decision)
    for line in lines:
        print(line)
    _summary(environ, lines)
    return 1 if refuse else 0


if __name__ == "__main__":
    sys.exit(main())
