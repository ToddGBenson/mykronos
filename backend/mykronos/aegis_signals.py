"""Runner-side insider-risk signal collection (spec 06 §2).

Runs inside the onboarded repo's Actions runner, where the git history and the
pull-request diff are. It *observes* — which paths were touched, whether the
author has contributed before, how this commit compares to their own baseline —
and reports those observations. It deliberately does not score them: the
weights, the caps and the thresholds live in the platform (`mykronos.aegis`)
so they are one definition rather than one per repo running whichever version
of the action it last synced.

Lives in this package for the same reason the adapters do (spec 04 §4): a
second copy of the submission schema that could drift from the server's is a
worse trade than the directory layout.

Every function here is pure over its inputs. The only I/O is in `main`, which
is what makes the signals testable without a runner or a network.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

#: A first contribution is worth noting, not accusing. The score is at the
#: bottom of `access_anomaly`'s range on purpose: everybody has a first pull
#: request, and the signal only becomes interesting next to another one.
FIRST_CONTRIBUTION_SCORE = 12.0

#: Full weight, because this is the signal spec 06 §2 actually cares about:
#: somebody with write access touching auth, secrets config or CI definitions.
SENSITIVE_PATH_SCORE = 30.0

#: Deviation from an author's own volume baseline. Capped low — a big pull
#: request is usually a big pull request.
BASELINE_DEVIATION_SCORE = 15.0

#: How many of an author's own prior commits define their baseline. Below this
#: there is not enough history to deviate from, and spec 06 §7 requires the
#: signal be *skipped* rather than defaulted to an extreme.
MIN_BASELINE_COMMITS = 5


@dataclass(frozen=True)
class PullRequestFacts:
    """Everything the signals are computed from, gathered once."""

    author_login: str
    changed_files: list[str]
    files_changed_count: int
    #: Commits this author has previously landed on the default branch.
    author_prior_commits: int
    #: Median files-per-commit across those commits, or None when there is not
    #: enough history to say.
    author_median_files: float | None
    pr_body: str


def matches_glob(path: str, pattern: str) -> bool:
    """Whether `path` matches `pattern`, treating a leading `**/` as optional.

    `fnmatch` alone gets the important case wrong. `**/.github/workflows/**`
    does not match `.github/workflows/ci.yml`, because the leading `**/`
    requires a literal slash before `.github` — so the single most sensitive
    path in any repository, the one that defines what CI runs, silently fails
    to match the default pattern that exists to catch it.

    Git reports repo-relative paths with no leading slash, so a top-level
    directory has nothing before it. Stripping the prefix and trying again is
    what "at any depth, including the root" actually means. The same applies to
    a trailing `/**`, which otherwise requires the directory to have a child
    path segment beyond itself.
    """
    candidates = [pattern]
    if pattern.startswith("**/"):
        candidates.append(pattern[3:])
    for candidate in list(candidates):
        if candidate.endswith("/**"):
            candidates.append(candidate[:-3])
    return any(fnmatch.fnmatch(path, candidate) for candidate in candidates)


def sensitive_path_signal(
    changed_files: list[str], patterns: list[str]
) -> dict[str, Any] | None:
    """Which touched paths match this repo's sensitive globs (spec 06 §5)."""
    matched = sorted(
        {
            path
            for path in changed_files
            for pattern in patterns
            if matches_glob(path, pattern)
        }
    )
    if not matched:
        return None

    shown = ", ".join(matched[:3])
    more = f" and {len(matched) - 3} more" if len(matched) > 3 else ""
    return {
        "key": "sensitive_path",
        "score": SENSITIVE_PATH_SCORE,
        "rationale": (
            f"Touches {len(matched)} path(s) this repository marks sensitive: "
            f"{shown}{more}."
        ),
    }


def access_anomaly_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """First-ever contribution from someone who can already write here."""
    if facts.author_prior_commits > 0:
        return None
    return {
        "key": "access_anomaly",
        "score": FIRST_CONTRIBUTION_SCORE,
        "rationale": (
            "First contribution to this repository from this account. Worth a "
            "look on its own terms — everybody has a first pull request — and "
            "more so if another signal also fired."
        ),
    }


def baseline_deviation_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """How far this change is from the author's own usual size.

    Returns None when there is too little history, per spec 06 §7: defaulting
    to an extreme score for a new contributor is the false positive this
    capability can least afford.
    """
    if (
        facts.author_prior_commits < MIN_BASELINE_COMMITS
        or facts.author_median_files is None
        or facts.author_median_files <= 0
    ):
        return None

    ratio = facts.files_changed_count / facts.author_median_files
    if ratio < 5:
        return None

    return {
        "key": "author_baseline",
        "score": BASELINE_DEVIATION_SCORE,
        "rationale": (
            f"Changes {facts.files_changed_count} files against a usual "
            f"{facts.author_median_files:.0f} for this author "
            f"({ratio:.0f}× their median across {facts.author_prior_commits} "
            "prior commits)."
        ),
    }


def collect(facts: PullRequestFacts, sensitive_paths: list[str]) -> list[dict[str, Any]]:
    """Every signal that fired, in a stable order.

    Ordering is fixed rather than incidental so two runs over the same facts
    produce byte-identical output — the same determinism requirement the rest
    of the platform has.
    """
    candidates = [
        sensitive_path_signal(facts.changed_files, sensitive_paths),
        access_anomaly_signal(facts),
        baseline_deviation_signal(facts),
    ]
    return [signal for signal in candidates if signal is not None]


def discloses_ai(pr_body: str) -> bool:
    """Whether the pull-request description mentions AI assistance.

    Substring matching, deliberately generous. The cost of a false "yes" is a
    signal that does not fire; the cost of a false "no" is telling a reviewer
    somebody concealed something when they did not, which is much worse.
    """
    lowered = pr_body.lower()
    return any(
        phrase in lowered
        for phrase in (
            "ai-generated",
            "ai generated",
            "ai-assisted",
            "ai assisted",
            "generated with",
            "copilot",
            "claude",
            "chatgpt",
            "gpt-4",
            "llm",
        )
    )


# --------------------------------------------------------------------------
# Runner entry point
# --------------------------------------------------------------------------


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    ).stdout.strip()


def _median(values: list[int]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def gather_facts(
    author_login: str, base_ref: str, head_ref: str, pr_body: str
) -> PullRequestFacts:
    """Read the facts out of the checked-out repository.

    The only impure function in this module. Failures degrade to "no history"
    rather than raising: a shallow clone or a missing base ref should cost the
    baseline signal, not the whole assessment.
    """
    diff = _git("diff", "--name-only", f"{base_ref}...{head_ref}")
    changed_files = [line for line in diff.splitlines() if line]

    # `--author` matches substrings of name and email, which is why the login
    # is passed rather than a display name.
    log = _git(
        "log",
        f"--author={author_login}",
        "--pretty=format:%H",
        "--no-merges",
        base_ref,
    )
    commits = [line for line in log.splitlines() if line]

    per_commit: list[int] = []
    for sha in commits[:50]:
        files = _git("show", "--name-only", "--pretty=format:", sha)
        per_commit.append(len([line for line in files.splitlines() if line]))

    return PullRequestFacts(
        author_login=author_login,
        changed_files=changed_files,
        files_changed_count=len(changed_files),
        author_prior_commits=len(commits),
        author_median_files=_median(per_commit),
        pr_body=pr_body,
    )


def main(argv: list[str] | None = None) -> int:
    """Emit an `InsiderRiskSubmission` body on stdout.

    The workflow POSTs whatever this prints. It never contacts Mykronos itself,
    so a scoring change is a platform deploy rather than a resync across every
    onboarded repo.
    """
    parser = argparse.ArgumentParser(
        prog="mykronos-aegis-signals", description=__doc__
    )
    parser.add_argument("--pr-number", type=int, required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--author", required=True, help="PR author's GitHub login")
    parser.add_argument("--base-ref", default="origin/HEAD")
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument(
        "--sensitive-path",
        action="append",
        default=[],
        help="Glob marking a sensitive path. Repeatable.",
    )
    parser.add_argument(
        "--pr-body-file",
        default=None,
        help="File holding the PR description, for AI-disclosure checking.",
    )
    args = parser.parse_args(argv)

    pr_body = ""
    if args.pr_body_file and os.path.exists(args.pr_body_file):
        with open(args.pr_body_file, encoding="utf-8", errors="replace") as handle:
            pr_body = handle.read()

    facts = gather_facts(args.author, args.base_ref, args.head_ref, pr_body)

    payload = {
        "pr_number": args.pr_number,
        "commit_sha": args.commit_sha,
        "author_login": args.author,
        "signals": collect(facts, args.sensitive_path),
        # Null, always, from this scorer. Classification requires sending the
        # diff to a configured endpoint, which is opt-in and not something a
        # local heuristic can stand in for — reporting false here would claim
        # "we checked, it is human" (spec 06 §3, §5).
        "ai_authorship_flag": None,
    }
    json.dump(payload, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
