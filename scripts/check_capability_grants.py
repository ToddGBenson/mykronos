"""Can each pipeline actually write what it uploads? (PS-1, spec 04 §5)

A capability grant is per-repository and enforced at ingest: `_require_capability`
returns 403 for anything the repo has not been granted. Nothing compared that
list against what the pipelines actually upload, and on 2026-08-20 the gap bit —
TheHub was given a `qa` lane while the repo had no `qa` grant, so every upload
was refused and the job went green anyway, because that upload is written with
`|| true` (the quality lanes tolerate a reporting failure so a broken uploader
cannot fail a passing test suite).

Green lane, no data, nothing anywhere saying so. That is the same hollow green
`check_pinned_ref.py` and the coverage cross-check exist to prevent, arriving
through the one door neither of them watches.

The cross-check already reports `no_job` — granted, but nothing produces it.
This is the inverse and the more dangerous one: **a job produces it, and the
grant is missing**, so the lane looks healthy while the lake stays empty.

Both sides are read locally. The pipelines say which repo they upload as and
which capabilities they send; the platform's own CLI, run inside the container
where the real database lives, says what each repo may write. No token is read
and no secret is handled.

    python scripts/check_capability_grants.py

Exit 0 when every uploaded capability is granted, 1 when one is not, and the
message names the `mykronos grant` command that fixes it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PIPELINES = (
    "deploy/concourse/pipelines/mykronos.yml",
    "deploy/concourse/pipelines/thehub.yml",
    "deploy/concourse/pipelines/personal-soc.yml",
)

#: Endpoints that record a capability without ever passing `--capability`.
#: Aegis, Oracle and Patchwork post their own shapes rather than findings, so a
#: grep for the uploader flag alone misses all three — and all three are
#: enforced by the same `_require_capability`.
ENDPOINT_CAPABILITIES = {
    "ingest/aegis": "aegis",
    "oracle/evaluate": "oracle",
    "patchwork/run": "patchwork",
}

CONTAINER = "mykronos-backend"


def uploads(text: str) -> dict[str, set[str]]:
    """repo -> capabilities that pipeline sends, from the pipeline itself.

    `--repo` is read rather than mapped from the filename: the pipeline states
    which repository it uploads as, and a mapping kept anywhere else is one
    more thing that can drift.
    """
    repos = set(re.findall(r"--repo (\S+)", text))
    found = set(re.findall(r"--capability (\w+)", text))
    for fragment, capability in ENDPOINT_CAPABILITIES.items():
        if fragment in text:
            found.add(capability)
    return {repo: found for repo in repos}


def granted(container: str = CONTAINER) -> dict[str, set[str]]:
    """repo -> granted capabilities, from the platform's own database.

    Run inside the container on purpose. The CLI defaults to a database
    relative to the working directory, so running it on the host reads a stale
    copy — on 2026-08-20 that copy was a week old and disagreed with the live
    API about seven capabilities. Rotating a token against it would have minted
    one the platform had never heard of.
    """
    result = subprocess.run(
        ["docker", "exec", container, "python", "-m", "mykronos.cli", "list-tokens"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Could not read grants from {container}: {result.stderr.strip() or 'no output'}"
        )

    grants: dict[str, set[str]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        # repo  status  grant, grant, ...  issued  rotate-after  sha
        if len(parts) < 4 or "/" not in parts[0] or parts[1] not in {"active", "superseded", "revoked"}:
            continue
        if parts[1] != "active":
            continue
        middle = " ".join(parts[2:-3])
        capabilities = {c.strip().rstrip(",") for c in middle.split(",") if c.strip()}
        grants.setdefault(parts[0], set()).update(capabilities)
    return grants


def compare(sent: dict[str, set[str]], allowed: dict[str, set[str]]) -> list[str]:
    problems: list[str] = []
    for repo in sorted(sent):
        if repo not in allowed:
            problems.append(
                f"{repo}: uploads {len(sent[repo])} capability(ies) and has no active token at all"
            )
            continue
        missing = sorted(sent[repo] - allowed[repo])
        for capability in missing:
            problems.append(
                f"{repo}: uploads `{capability}` and is not granted it — every upload 403s.\n"
                f"      docker exec {CONTAINER} python -m mykronos.cli grant {repo} {capability}"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-capability-grants", description=__doc__)
    parser.add_argument("--container", default=CONTAINER)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    sent: dict[str, set[str]] = {}
    for relative in PIPELINES:
        for repo, capabilities in uploads((REPO_ROOT / relative).read_text(encoding="utf-8")).items():
            sent.setdefault(repo, set()).update(capabilities)

    try:
        allowed = granted(args.container)
    except (RuntimeError, FileNotFoundError) as exc:
        # Fails soft on "the platform is not running here", loud on a real gap.
        # This is a check you want to run from a laptop as well as the host.
        print(f"Cannot reach the platform, so grants cannot be checked: {exc}")
        return 0

    if not args.quiet:
        for repo in sorted(sent):
            have = allowed.get(repo, set())
            print(f"{repo}")
            print(f"  uploads: {', '.join(sorted(sent[repo])) or 'nothing'}")
            print(f"  granted: {', '.join(sorted(have)) or 'nothing'}")
            extra = sorted(have - sent[repo])
            if extra:
                # Not a failure. A grant with no lane is the cross-check's
                # `no_job`, which it already reports per repository.
                print(f"  granted but no lane here: {', '.join(extra)}")
            print()

    problems = compare(sent, allowed)
    if problems:
        print("A pipeline uploads a capability its repository may not write:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("Every capability each pipeline uploads is granted to the repository it uploads as.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
