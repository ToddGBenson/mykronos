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
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
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

# --- Review integrity (spec 06 §2a) ----------------------------------------
#
# These describe how a change was reviewed. Nothing here compares one person
# to another or accumulates across pull requests; each is a fact about this
# change, disputable on its own terms.

#: The only unambiguous one: the approving login either equals the author's or
#: it does not. Heaviest of the four for that reason, and still incapable of
#: recommending a block on its own (`mykronos.aegis.SIGNAL_CAP`).
SELF_APPROVAL_SCORE = 30.0

#: One approval on a change touching a sensitive path. Not suspicious by
#: itself — most teams review with one pair of eyes — which is why it only
#: fires in combination with a sensitive path and scores modestly.
SOLE_APPROVER_SCORE = 20.0

#: An approval that arrived faster than the diff could plausibly have been
#: read. Evidence that review did not happen, not that anyone conspired.
FAST_APPROVAL_SCORE = 15.0

#: AI-authored, disclosed or detected, with no reviewer stating what they
#: checked. The concrete form of "human/AI collusion" that is actually
#: observable: nobody verified the machine's work.
UNVERIFIED_AI_SCORE = 20.0

#: Elevated org access (spec 20 §2). Weighted with `self_approval` as the
#: heaviest pair, matching `SIGNAL_CAP` — like that one it is a fact rather
#: than a heuristic (GitHub either reports the role or it does not), and like
#: that one it still cannot block on its own.
PRIVILEGE_ADJACENT_SCORE = 30.0

#: The GitHub org roles that count as elevated. `write`/`triage`/`read` are
#: ordinary contributor access and deliberately absent: the signal is about
#: somebody who can change the rules the review process relies on, not about
#: anybody who can open a pull request.
ELEVATED_ROLES = frozenset({"admin", "maintain"})

#: Lines a careful reviewer gets through per second. Deliberately generous —
#: 20 lines/second is roughly 1200 lines a minute, far faster than anyone
#: reads for meaning — so the signal fires only on approvals that could not
#: have involved reading at all.
LINES_READ_PER_SECOND = 20.0

#: Below this, no approval is fast enough to be evidence of anything. A
#: three-line typo fix genuinely can be approved in four seconds.
MIN_LINES_FOR_FAST_APPROVAL = 50

#: Phrases a reviewer uses when stating what they actually checked. Matching
#: is deliberately loose: the signal is "nobody wrote anything resembling
#: verification", and a false negative (someone verified and phrased it oddly)
#: is much better than nagging a reviewer who did the work.
VERIFICATION_PHRASES = (
    "verified",
    "i checked",
    "i ran",
    "i tested",
    "traced",
    "reproduced",
    "confirmed",
    "stepped through",
)


@dataclass(frozen=True)
class ReviewFact:
    """One submitted review, reduced to what the signals need.

    Deliberately not the whole review object. The body is kept only to look
    for a verification claim, and no other reviewer attribute reaches the
    lake — spec 06 §9 scores changes, not people.
    """

    reviewer_login: str
    state: str
    seconds_after_head_commit: int | None = None
    body: str = ""


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

    # --- Review integrity (spec 06 §2a) ------------------------------------
    #
    # Empty when the workflow ran before any review existed, which is the
    # normal case on `pull_request: opened`. Every signal below returns None
    # for empty reviews rather than firing: "not reviewed yet" and "reviewed
    # by nobody independent" are different facts, and only the second is worth
    # a prompt.

    #: One entry per submitted review.
    reviews: tuple[ReviewFact, ...] = ()
    #: Lines added plus removed, for judging whether an approval could have
    #: involved reading.
    diff_lines: int = 0
    #: True when the PR discloses AI authorship, or a classifier flagged it.
    ai_authored: bool = False
    #: The author's role in the repository's org, as GitHub reports it, or
    #: None when it could not be resolved — an external contributor, or a
    #: permissions gap. None is *absent*, never "ordinary": claiming somebody
    #: is unprivileged because the lookup failed is the wrong direction to be
    #: wrong in (spec 20 §2.2).
    author_role: str | None = None


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


def _approvals(facts: PullRequestFacts) -> list[ReviewFact]:
    return [r for r in facts.reviews if r.state.upper() == "APPROVED"]


def self_approval_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """The only approval came from the author (spec 06 §2a).

    The unambiguous member of this group: the approving login either equals
    the author's or it does not. No heuristic, no threshold, nothing to
    calibrate — which is why it carries the most weight and still cannot
    recommend a block on its own.
    """
    approvals = _approvals(facts)
    if not approvals:
        return None
    if any(r.reviewer_login.lower() != facts.author_login.lower() for r in approvals):
        return None

    return {
        "key": "self_approval",
        "score": SELF_APPROVAL_SCORE,
        "rationale": (
            "Every approving review on this pull request came from its own "
            "author. Nobody independent has agreed to this change."
        ),
    }


def sole_approver_signal(
    facts: PullRequestFacts, sensitive_paths: list[str]
) -> dict[str, Any] | None:
    """One approval, on a change touching a sensitive path (spec 06 §2a).

    Only fires in combination. One approval is how most teams work and is not
    worth remarking on; one approval on the file that defines what CI runs is
    worth a second pair of eyes.
    """
    independent = [
        r for r in _approvals(facts)
        if r.reviewer_login.lower() != facts.author_login.lower()
    ]
    if len(independent) != 1:
        return None

    touched = [
        path
        for path in facts.changed_files
        if any(matches_glob(path, pattern) for pattern in sensitive_paths)
    ]
    if not touched:
        return None

    return {
        "key": "sole_approver",
        "score": SOLE_APPROVER_SCORE,
        "rationale": (
            f"One independent approval, on a change touching {touched[0]}. "
            "Sensitive paths are worth a second reviewer; this is a prompt to "
            "ask for one, not a judgement about the reviewer."
        ),
    }


def fast_approval_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """An approval that arrived faster than the diff could be read (§2a).

    Evidence that review did not happen, which is a statement about elapsed
    time and line count, not about the reviewer's intent. Small changes are
    excluded entirely: a three-line fix genuinely can be approved in seconds.
    """
    if facts.diff_lines < MIN_LINES_FOR_FAST_APPROVAL:
        return None

    timed = [
        r
        for r in _approvals(facts)
        if r.seconds_after_head_commit is not None
        and r.reviewer_login.lower() != facts.author_login.lower()
    ]
    if not timed:
        return None

    quickest = min(r.seconds_after_head_commit or 0 for r in timed)
    plausible = facts.diff_lines / LINES_READ_PER_SECOND
    if quickest >= plausible:
        return None

    return {
        "key": "fast_approval",
        "score": FAST_APPROVAL_SCORE,
        "rationale": (
            f"{facts.diff_lines} changed lines were approved {quickest}s after "
            f"the head commit. Reading that closely takes at least "
            f"{plausible:.0f}s at a generous 20 lines a second."
        ),
    }


def unverified_ai_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """AI-authored, with no reviewer stating what they verified (§2a).

    The observable form of "human/AI collusion": not that anyone conspired,
    but that a machine wrote the change and no person checked it. Matching is
    loose on purpose — a reviewer who verified and phrased it unusually should
    slip through, because nagging somebody who did the work is how a signal
    gets switched off.
    """
    if not facts.ai_authored:
        return None

    independent = [
        r for r in _approvals(facts)
        if r.reviewer_login.lower() != facts.author_login.lower()
    ]
    if not independent:
        # Covered by self_approval or by having no review at all. Two signals
        # for one absence would double-count the same missing person.
        return None

    if any(
        phrase in (r.body or "").lower()
        for r in independent
        for phrase in VERIFICATION_PHRASES
    ):
        return None

    return {
        "key": "unverified_ai",
        "score": UNVERIFIED_AI_SCORE,
        "rationale": (
            "This change is AI-authored and no reviewer stated what they "
            "checked independently. An approval on generated code that says "
            "only that it looks fine is not review."
        ),
    }


def privilege_adjacent_signal(facts: PullRequestFacts) -> dict[str, Any] | None:
    """The author already has more access than the review process assumes.

    A narrow, cheap reading of "privilege-adjacent" (spec 20 §2.2): GitHub org
    role, which the App can already read, rather than the HR/personnel feed
    spec 06 §2 imagined and nobody has. An org admin is somebody who can
    change branch protection, add a deploy key, or approve their own way past
    the controls the other signals measure — which is what makes their change
    worth a second look, not anything about them.

    Absent, not zero, when the role is unknown. A failed lookup is not
    evidence of ordinary access.
    """
    if facts.author_role is None or facts.author_role not in ELEVATED_ROLES:
        return None
    return {
        "key": "privilege_adjacent",
        "score": PRIVILEGE_ADJACENT_SCORE,
        "rationale": (
            f"The author holds `{facts.author_role}` on this repository, so "
            "they can change the controls the rest of this assessment relies "
            "on. Not a judgement about them — the same change from an "
            "ordinary contributor is reviewed by a process they cannot alter."
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
        self_approval_signal(facts),
        sole_approver_signal(facts, sensitive_paths),
        fast_approval_signal(facts),
        unverified_ai_signal(facts),
        privilege_adjacent_signal(facts),
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


def parse_reviews(
    payload: object, head_commit_iso: str | None = None
) -> tuple[ReviewFact, ...]:
    """Reduce GitHub's reviews payload to what the signals need.

    Pure, and tolerant: a shape that does not parse yields no reviews rather
    than raising. The review-integrity signals all no-op on an empty list, so
    the failure mode is "Aegis did not comment on review integrity" and not "a
    broken Aegis run".

    Only four fields survive: who approved, the state, how long after the head
    commit it arrived, and the body — the last only so a verification claim
    can be looked for. Nothing else about a reviewer reaches the lake
    (spec 06 §9).
    """
    if not isinstance(payload, list):
        return ()

    head_at = _parse_iso(head_commit_iso)
    reviews: list[ReviewFact] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        login = str((entry.get("user") or {}).get("login") or "").strip()
        state = str(entry.get("state") or "").strip()
        if not login or not state:
            continue

        seconds: int | None = None
        submitted = _parse_iso(entry.get("submitted_at"))
        if head_at is not None and submitted is not None:
            delta = int((submitted - head_at).total_seconds())
            # A review timestamped before the commit it reviews means the
            # author pushed again afterwards. The elapsed time is then
            # meaningless rather than suspicious, so it is dropped.
            seconds = delta if delta >= 0 else None

        reviews.append(
            ReviewFact(
                reviewer_login=login,
                state=state,
                seconds_after_head_commit=seconds,
                body=str(entry.get("body") or "")[:2000],
            )
        )
    return tuple(reviews)


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def gather_facts(
    author_login: str,
    base_ref: str,
    head_ref: str,
    pr_body: str,
    *,
    reviews: tuple[ReviewFact, ...] = (),
    ai_authored: bool = False,
    author_role: str | None = None,
) -> PullRequestFacts:
    """Read the facts out of the checked-out repository.

    The only impure function in this module. Failures degrade to "no history"
    rather than raising: a shallow clone or a missing base ref should cost the
    baseline signal, not the whole assessment.
    """
    diff = _git("diff", "--name-only", f"{base_ref}...{head_ref}")
    changed_files = [line for line in diff.splitlines() if line]

    # Added plus removed, for judging whether an approval could have involved
    # reading. `--shortstat` is one line to parse and does not need the diff
    # itself, which stays off the runner's stdout.
    diff_lines = 0
    shortstat = _git("diff", "--shortstat", f"{base_ref}...{head_ref}")
    for count, kind in re.findall(r"(\d+) (insertion|deletion)", shortstat):
        del kind
        diff_lines += int(count)

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
        reviews=reviews,
        diff_lines=diff_lines,
        ai_authored=ai_authored,
        author_role=author_role,
    )


def _head_commit_time(head_ref: str) -> str | None:
    """Committer date of the head commit, ISO-8601, or None."""
    stamp = _git("show", "-s", "--format=%cI", head_ref).strip()
    return stamp or None


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
    parser.add_argument(
        "--author-role",
        default=None,
        help=(
            "The author's role on this repository, as GitHub's collaborator "
            "permission endpoint reports it. Omit when it could not be "
            "fetched: the `privilege_adjacent` signal then stays silent "
            "rather than treating an unreadable role as ordinary access."
        ),
    )
    parser.add_argument(
        "--reviews-file",
        default=None,
        help=(
            "File holding the GitHub reviews payload for this PR. Absent or "
            "empty means no review has been submitted yet, which is the "
            "normal case when the workflow runs on `pull_request: opened` — "
            "the review-integrity signals stay silent rather than firing."
        ),
    )
    args = parser.parse_args(argv)

    pr_body = ""
    if args.pr_body_file and os.path.exists(args.pr_body_file):
        with open(args.pr_body_file, encoding="utf-8", errors="replace") as handle:
            pr_body = handle.read()

    reviews: tuple[ReviewFact, ...] = ()
    if args.reviews_file and os.path.exists(args.reviews_file):
        with open(args.reviews_file, encoding="utf-8", errors="replace") as handle:
            try:
                payload = json.load(handle)
            except json.JSONDecodeError:
                # A truncated fetch costs the review-integrity signals, not
                # the whole assessment.
                payload = None
        reviews = parse_reviews(payload, _head_commit_time(args.head_ref))

    # Disclosure only. A local heuristic must never claim a change is *not*
    # AI-authored — that is what the configured classifier is for (spec 06 §5)
    # — but a PR that says so itself is a fact, and it is the input the
    # `unverified_ai` signal needs.
    facts = gather_facts(
        args.author,
        args.base_ref,
        args.head_ref,
        pr_body,
        reviews=reviews,
        ai_authored=discloses_ai(pr_body),
        author_role=args.author_role or None,
    )

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
