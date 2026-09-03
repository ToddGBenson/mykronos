"""Consult the Champion — ask this platform what it knows about a repository.

Every surface here answers one question well and none of them answer *"what
should I know about this repository right now"*, which is the question somebody
actually arrives with. Nine tabs is a filing system, not an answer.

**This is not a chatbot, and the difference is deliberate.** There is no model
behind it and no free-text box. What it does is answer a fixed set of questions
from the platform's own records, cite what each answer came from, and — the
part that matters — name the questions it *cannot* answer and say why.

Two reasons for that shape rather than a language model:

**No credential.** This repository holds no model API key and must not (spec 12
§2). A chat window that needs one is blocked on the operator, exactly as the
notifier is (B-035), and shipping the box before the credential would be a
feature that fails on first use.

**Grounding is the hard half anyway.** A model answering "what should I fix
first here" is only as good as the facts handed to it, and those facts are what
this module is. When a key arrives, the model is a phrasing layer over the same
`Facts` — B-043 — and every answer it gives will still have to carry the
citations built here. Building the phrasing first and the grounding later is
how assistants end up confidently wrong.

**What it will not do.** It cannot act. No dispositions, no acceptances, no
scans started, no pull requests opened. Everything it says is a read, and every
answer names the tab where the reader can go and disagree with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Facts:
    """Everything the answers are built from, gathered by the caller.

    Plain numbers rather than query results, so the phrasing below is testable
    without a lake and cannot quietly start doing its own arithmetic.
    """

    repo_full_name: str
    open_findings: int = 0
    critical: int = 0
    high: int = 0
    #: Findings whose lane cannot close them — a broken lane freezes findings
    #: open however well the code was fixed, and this is the first thing worth
    #: saying about any open count.
    blocked_by_lane: int = 0
    stalled_lanes: tuple[str, ...] = ()
    unowned: int = 0
    owner_source: str | None = None
    accepted: int = 0
    accepted_unqualified: int = 0
    test_kinds_observed: int = 0
    test_kinds_total: int = 0
    coverage_measured: bool = False
    ssdf_met: int = 0
    ssdf_total: int = 0
    libraries: int = 0
    vulnerable_libraries: int = 0
    risk_profile_confirmed: bool = False


@dataclass
class Answer:
    key: str
    question: str
    answer: str
    #: Where the reader goes to check it. Every answer is falsifiable on a tab.
    tab: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Unanswerable:
    """A question people will ask that this platform cannot answer.

    Listed rather than omitted, and with the reason, because the failure mode
    of an assistant is not saying "I do not know" — it is answering anyway. A
    reader who knows what it cannot do can trust what it does.
    """

    question: str
    why: str


#: Named in the order somebody hits them. The first three are the questions
#: that stop work; the rest are the ones asked once a week.
UNANSWERABLE: tuple[Unanswerable, ...] = (
    Unanswerable(
        "Is this vulnerability exploitable in our environment?",
        "That needs a confirmed risk profile — whether this service is internet "
        "facing, what data it holds, whether it authenticates. Until somebody "
        "confirms one, every environmental input is unknown and the honest "
        "answer is the base score with nothing subtracted.",
    ),
    Unanswerable(
        "Why did that test fail?",
        "The test lanes record suite totals, not case names (D-046). This knows "
        "a lane went red and cannot know which assertion did.",
    ),
    Unanswerable(
        "How long will this take to fix?",
        "Nothing here measures effort. A fix with a published patched version "
        "is cheaper than one without, which is what the remediation ordering "
        "uses, but that is a ranking and not an estimate.",
    ),
    Unanswerable(
        "Is this a false positive?",
        "Only somebody who reads the code can say. What this can do is show "
        "every previous dismissal of the same rule and the reasons given.",
    ),
    Unanswerable(
        "What does this code do?",
        "This platform reads scan output, not source. It knows a finding's file "
        "and line and has never opened the file.",
    ),
    Unanswerable(
        "Should we ship?",
        "The risk gate is advisory here by decision (D-102), and the call "
        "belongs to whoever owns the consequence of a blocked release. This can "
        "tell you what the gate would have said.",
    ),
)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def build(facts: Facts) -> list[Answer]:
    """The questions this platform can answer about one repository.

    Each answer is a sentence built from records, plus the tab where the reader
    can check it. Where a number would mislead on its own it is qualified in
    the same sentence rather than in a footnote — the footnote is the thing
    nobody reads.
    """
    answers: list[Answer] = []

    # 1. The question everybody opens with, and the one where a bare count is
    #    most often wrong: a frozen lane holds findings open regardless of
    #    whether anybody fixed them.
    if facts.blocked_by_lane:
        headline = (
            f"{_plural(facts.open_findings, 'finding')} open, but "
            f"{facts.blocked_by_lane} of them cannot close because "
            f"{'a lane is' if len(facts.stalled_lanes) == 1 else 'lanes are'} "
            f"not reporting ({', '.join(facts.stalled_lanes) or 'unknown'}). "
            "Fix the lane before reading the number."
        )
    elif facts.open_findings:
        headline = (
            f"{_plural(facts.open_findings, 'finding')} open, "
            f"{facts.critical} critical and {facts.high} high. "
            "Every lane that reports is closing findings normally."
        )
    else:
        headline = "Nothing is open. Every lane that reports has come back clean."

    answers.append(
        Answer(
            key="open",
            question="What is outstanding here?",
            answer=headline,
            tab="findings",
            evidence=[
                "A finding closes only after two consecutive successful scans "
                "see it gone, so a lane that is failing freezes its findings "
                "open however well the code was fixed."
            ],
        )
    )

    # 2. Ownership, with how it was resolved — the ladder matters, because an
    #    owner inherited from the repository account is a different fact from
    #    one read out of CODEOWNERS.
    if facts.unowned:
        owner_answer = (
            f"{_plural(facts.unowned, 'finding')} here have no owner. "
            "An unowned finding is a decision nobody has been asked to make."
        )
    elif facts.owner_source:
        owner_answer = (
            f"Everything here is owned, resolved from {facts.owner_source}."
            + (
                " That is the repository account rather than a team, which means "
                "nobody in particular."
                if facts.owner_source == "repo account"
                else ""
            )
        )
    else:
        owner_answer = "Everything open here has an owner."

    answers.append(
        Answer(
            key="ownership",
            question="Who is answerable for this?",
            answer=owner_answer,
            tab="findings",
        )
    )

    # 3. Accepted risk. The count alone reads as governance; the unqualified
    #    share is the part that is actually a problem.
    if facts.accepted:
        if facts.accepted_unqualified:
            accepted_answer = (
                f"{_plural(facts.accepted, 'finding')} accepted rather than "
                f"fixed, and {facts.accepted_unqualified} of those carry no "
                "review date and no reason — an acceptance with neither is "
                "indistinguishable from having stopped looking."
            )
        else:
            accepted_answer = (
                f"{_plural(facts.accepted, 'finding')} accepted rather than "
                "fixed, each with a reason and a review date."
            )
    else:
        accepted_answer = "Nothing here has been accepted rather than fixed."

    answers.append(
        Answer(
            key="accepted",
            question="What have we decided to live with?",
            answer=accepted_answer,
            tab="decisions",
        )
    )

    # 4. Testing, which is the question nobody asks and everybody should.
    if facts.test_kinds_total:
        missing = facts.test_kinds_total - facts.test_kinds_observed
        test_answer = (
            f"{facts.test_kinds_observed} of {facts.test_kinds_total} kinds of "
            f"testing are evidenced here; {_plural(missing, 'kind')} "
            f"{'is' if missing == 1 else 'are'} not done at all."
        )
        if not facts.coverage_measured:
            test_answer += (
                " No lane writes a coverage document, so coverage here is "
                "unmeasured rather than low."
            )
        answers.append(
            Answer(
                key="testing",
                question="What testing does this have?",
                answer=test_answer,
                tab="harness",
            )
        )

    # 5. What can be shown to an assessor.
    if facts.ssdf_total:
        answers.append(
            Answer(
                key="adherence",
                question="What can we evidence to an assessor?",
                answer=(
                    f"{facts.ssdf_met} of {facts.ssdf_total} SSDF practices are "
                    "evidenced by something this platform observed. The rest are "
                    "listed with what would evidence them."
                ),
                tab="adherence",
                evidence=[
                    "Evidenced means observed, not enabled — a lane that is "
                    "switched on and silent evidences nothing."
                ],
            )
        )

    # 6. Dependencies.
    if facts.libraries:
        answers.append(
            Answer(
                key="dependencies",
                question="What is this built on?",
                answer=(
                    f"{_plural(facts.libraries, 'library')} in the current SBOM, "
                    f"{facts.vulnerable_libraries} of them carrying a known "
                    "vulnerability."
                ),
                tab="sscs",
            )
        )

    # 7. The one that gates most of the others, and the only answer here that
    #    is about the platform rather than the repository.
    if not facts.risk_profile_confirmed:
        answers.append(
            Answer(
                key="profile",
                question="Why is every score the worst case?",
                answer=(
                    "No risk profile has been confirmed for this repository. "
                    "Environmental scoring defaults every unknown to the worst "
                    "case by design, so the scores you see are an upper bound "
                    "and not a measurement."
                ),
                tab="threat-model",
                evidence=[
                    "The platform can propose a profile from what it has "
                    "observed; confirming it is a human decision."
                ],
            )
        )

    return answers
