#!/usr/bin/env python3
"""Ask the platform to grade the detector benchmark, and exit with its verdict (TheHub #60742).

The `bench` Concourse job runs this on every mykronos main commit that passes
`unit`. A Concourse task has no lake, so the grade is taken inside the
platform (`POST /api/ingest/bench-run`, `mykronos.bench`), which stores the run
whether or not it could be graded. This script's job is the other half of
"never an empty success": the lane is green only for a run the platform
reports as `graded`.

Exit codes, as `bench_grade.py` speaks them: 0 graded, 2 usage, 3 not
measured (the platform said `not_measured` or `manifest_invalid`, answered
something that is not a run, or could not be reached).

Standard library only, so it runs on the stock python image with no install.

Usage:

    MYKRONOS_URL=... MYKRONOS_TOKEN=... python scripts/bench_run.py \\
        --bench-repo owner/mykronos-bench --platform-commit "$SHA"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NOT_MEASURED = 3

Post = Callable[[str, dict[str, Any], str], Any]


def _post(url: str, body: dict[str, Any], token: str) -> Any:
    request = urllib.request.Request(  # noqa: S310 - the URL is the pipeline's own var
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        text = response.read().decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def _summary(run: Mapping[str, Any]) -> str:
    lines = [
        f"Benchmark run {run.get('id', '?')}: {run.get('status')} "
        f"(corpus {run.get('bench_repo', '?')} at {run.get('bench_commit') or 'no commit'}).",
        str(run.get("reason") or ""),
    ]
    for cap in run.get("capabilities") or []:
        lines.append(
            f"  {cap.get('capability', '?'):<12} {cap.get('seeded_detected')}/"
            f"{cap.get('seeded_total')} seeded detected, recall {cap.get('recall')}"
        )
    for rule in run.get("rules") or []:
        lines.append(
            f"  {rule.get('capability', '?')}:{rule.get('rule_id', '?')}  "
            f"recall {rule.get('recall')}  precision floor {rule.get('precision_floor')}  "
            f"({rule.get('matched')}/{rule.get('findings')} findings matched a seed)"
        )
    return "\n".join(line for line in lines if line)


def main(
    argv: list[str] | None = None,
    *,
    post: Post = _post,
    env: Mapping[str, str] | None = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bench-repo", required=True)
    parser.add_argument("--platform-commit", required=True)
    parser.add_argument("--run-url", default=None)
    args = parser.parse_args(argv)
    env = os.environ if env is None else env

    base = (env.get("MYKRONOS_URL") or "").rstrip("/")
    token = env.get("MYKRONOS_TOKEN") or ""
    if not base or not token:
        print("::error::bench: MYKRONOS_URL and MYKRONOS_TOKEN must be set.", file=sys.stderr)
        return EXIT_USAGE

    body: dict[str, Any] = {
        "bench_repo": args.bench_repo,
        "platform_commit": args.platform_commit,
    }
    if args.run_url:
        body["run_url"] = args.run_url

    try:
        run = post(f"{base}/api/ingest/bench-run", body, token)
    except Exception as exc:  # noqa: BLE001 - every way of not asking is one verdict
        print(
            f"::error::bench NOT MEASURED: the platform could not be asked ({exc}). "
            "No grade was taken.",
            file=sys.stderr,
        )
        return EXIT_NOT_MEASURED

    if not isinstance(run, Mapping) or "status" not in run:
        print(
            "::error::bench NOT MEASURED: the platform answered something that is not "
            f"a benchmark run: {str(run)[:300]!r}",
            file=sys.stderr,
        )
        return EXIT_NOT_MEASURED

    print(_summary(run))
    if run.get("status") == "graded":
        return EXIT_OK
    reason = run.get("reason") or "no reason given"
    print(f"::error::bench NOT MEASURED ({run.get('status')}): {reason}", file=sys.stderr)
    return EXIT_NOT_MEASURED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
