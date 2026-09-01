"""The regression-test line on a fix pull request (spec 31 §2, B-011).

Spec 31 names three ways a test gets pinned to a finding. Two existed: a
person using the disposition endpoint, and `demonstrated` from verification.
The middle one — *"a fix pull request: Patchwork's PR body gains a line, if you
add a regression test, name it here, parsed on merge"* — had no production
code at all. `demonstrated` was written in exactly one place in the whole
repository, `tests/test_regression_coverage.py`, so every link that existed in
a running system was hand-crafted by an HTTP request in a test.

This is the missing producer. It is deliberately the same shape as
`rejection.py`, which asks the closer of an unmerged draft why: a marked block
in the body, one line somebody edits, parsed on the webhook that already
fires. **The person writing the regression test is the person merging the fix**,
and that is the cheapest moment anyone will ever be asked.

**What this can and cannot establish.** It produces `asserted` links — somebody
said this test covers that finding. It does not produce `demonstrated`, and
saying so is the point rather than an omission: spec 31 §2 defines
`demonstrated` as the platform having watched the named test *fail against the
vulnerable code and pass against the fixed code*, which means running the new
test against the pre-fix ref.

That cannot be done with what exists here. The test is added **in the fix pull
request**, so it is not present on the parent commit at all — an ordinary lane
run there cannot exercise it, and a lane that went red-to-green across the
merge is evidence about the lane, not about this test. Establishing the
stronger claim needs a lane invocation that takes a ref, and
`dispatch(repo_full_name, capability)` takes no commit. Spec 31 §8 already
contemplates this case for a pre-fix ref that no longer builds: *"`demonstrated`
cannot be established; the link stays `asserted` and says why."* The same
sentence covers this one.

So an `asserted` link is the honest grade for a link made here, and inflating
it would corrupt the single number spec 31 exists to make trustworthy —
`demonstrated` is weighted above `asserted` in Oracle precisely because it
means more (spec 26 §2, spec 31 §6).
"""

from __future__ import annotations

import re

#: Marks the block, so the parser is not searching a reviewer's prose for
#: something that looks like a test name. Same device and same reason as
#: `rejection.REJECTION_MARKER`.
REGRESSION_MARKER = "<!-- mykronos:regression-test -->"

#: `test: <identifier>` on its own line, the code fence optional because
#: people add backticks and people forget to.
_TEST = re.compile(r"^\s*test:\s*`?([^`\n]+?)`?\s*$", re.IGNORECASE | re.MULTILINE)

#: The lane the named test lives in, when somebody says. Optional: `unit` is
#: overwhelmingly right and demanding the field would be answered with
#: whatever dismisses the form fastest.
_LANE = re.compile(r"^\s*lane:\s*`?(unit|functional|qa)`?\s*$", re.IGNORECASE | re.MULTILINE)

#: What a body says when nobody edited the line. Not an error, and by far the
#: common case — most fix PRs will merge with this untouched.
UNSTATED = ""

DEFAULT_LANE = "unit"


def regression_prompt() -> str:
    """The block Patchwork appends to every draft it opens.

    Phrased as a request rather than a requirement. Spec 31 §2 makes the
    person's route optional on the grounds that *"a mandatory field here would
    be answered with garbage"*, and a pull request template is exactly where
    that happens.
    """
    return (
        f"{REGRESSION_MARKER}\n"
        "### If you add a regression test\n"
        "\n"
        "Name it here before you merge and Mykronos will pin it to this "
        "finding:\n"
        "\n"
        "`test: ` — the test that would fail if this came back, and "
        "optionally\n"
        f"`lane: unit` — which lane it runs in (`unit`, `functional` or `qa`; "
        f"defaults to `{DEFAULT_LANE}`).\n"
        "\n"
        "Optional. An unnamed test is recorded as no link rather than guessed "
        "at — spec 31 §2.1 refuses to infer one from a name, because a test "
        "called `test_sql_injection` is not thereby a test for *this* SQL "
        "injection, and a wrong link is counted as coverage for ever."
    )


def parse_regression_test(body: str | None) -> tuple[str, str]:
    """`(test_identifier, lane)` from a merged pull request's body.

    Returns `(UNSTATED, DEFAULT_LANE)` when nobody named a test, which is the
    common case and is not a failure.

    Only the first stated test is read. A body naming two is somebody who
    edited carelessly, and taking the first is the rule `parse_rejection`
    already applies for the same reason.
    """
    if not body:
        return (UNSTATED, DEFAULT_LANE)

    match = _TEST.search(body)
    if match is None:
        return (UNSTATED, DEFAULT_LANE)

    identifier = match.group(1).strip()
    # The prompt ships with the value empty (`test: `), so an unedited body
    # matches the pattern with nothing in it. That is "not answered", not a
    # test called nothing.
    if not identifier:
        return (UNSTATED, DEFAULT_LANE)

    lane_match = _LANE.search(body)
    lane = lane_match.group(1).lower() if lane_match else DEFAULT_LANE
    return (identifier, lane)
