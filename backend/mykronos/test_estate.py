"""What testing exists here, and what kinds of it do not.

The Harness tab answers "did the suite pass". This answers the question behind
it: **which kinds of testing does this repository actually have evidence of,
and which kinds is it simply not doing?** A repository with a green unit lane
and no performance, accessibility or contract testing anywhere is not a
well-tested repository, and nothing on this platform said so.

**Same rule as everywhere else: evidence, never intent.** A kind is present
only if the platform watched something produce it. An enabled and silent lane
evidences no testing, exactly as it evidences no SSDF practice.

**Absent is a finding, not a blank.** The kinds nothing here evidences are
listed by name with what would evidence them, rather than omitted. A test view
that shows only what exists can never tell you what is missing, and what is
missing is the entire question.

**Coverage is three states, not a number.** `reported`, `never reported` and
`no test lane at all` are different facts, and the middle one is the trap: a
repository with 227 unit runs and no coverage figure is not at 0%, and
rendering it as 0% would be a fabricated measurement of a real suite. Across
this estate on 2026-09-03 every run was in that middle state — the adapter
parses Cobertura and JaCoCo, the lake has the columns, and no pipeline was
writing a coverage document. Nothing said so, because nothing asked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

#: `observed` — the platform watched this happen. `absent` — nothing here
#: produces it. There is deliberately no "probably" between them.
Presence = Literal["observed", "absent"]

#: Test lanes, as opposed to security lanes. A failing test is a defect and
#: never a finding (D-046), which is why these are counted apart.
TEST_LANES: tuple[str, ...] = ("unit", "functional", "qa")


@dataclass(frozen=True)
class TestKind:
    """One kind of testing, and what would evidence it here.

    `capabilities` names the *observation*, not the tool. Which runner a
    repository uses is its own business — the platform's question is whether
    anything at all reported this kind of testing having happened.
    """

    key: str
    name: str
    why: str
    #: Capabilities whose reporting evidences this kind.
    capabilities: tuple[str, ...] = ()
    how_to_evidence: str = ""


#: Ordered from the innermost loop outwards — a unit test runs in seconds
#: against a function, a post-deploy smoke test runs in production against the
#: whole system — because that is the order a team adds them in, and therefore
#: the order in which a gap is worth reading.
KINDS: tuple[TestKind, ...] = (
    TestKind(
        "unit",
        "Unit",
        "Does each piece behave on its own?",
        capabilities=("unit",),
        how_to_evidence="Enable the unit lane and give it a command.",
    ),
    TestKind(
        "quality",
        "Lint, types and contract",
        "Would a reviewer have caught this without running anything?",
        capabilities=("qa",),
        how_to_evidence=(
            "Enable the qa lane. mykronos.junit_stage turns pass/fail commands "
            "- ruff, mypy, an OpenAPI diff - into a report this platform reads."
        ),
    ),
    TestKind(
        "functional",
        "Functional and integration",
        "Do the pieces work once assembled?",
        capabilities=("functional",),
        how_to_evidence="Enable the functional lane and give it a command.",
    ),
    TestKind(
        "security_regression",
        "Security regression",
        "Would a fixed vulnerability be caught coming back?",
        # Not a lane. Evidenced by regression links (spec 31), which the caller
        # supplies as a count rather than through scan health.
        how_to_evidence=(
            "Link a test to the finding it protects, and let the platform watch it "
            "fail against the vulnerable code and pass against the fix."
        ),
    ),
    TestKind(
        "dynamic",
        "Dynamic, against a running app",
        "Does it hold up when it is actually running?",
        capabilities=("dast",),
        how_to_evidence="Enable the dast lane against a deployed environment.",
    ),
    TestKind(
        "contract",
        "Contract",
        "Will a consumer break when this ships?",
        how_to_evidence=(
            "Publish the API schema each build and diff it against the last. The qa "
            "lane can carry this - this platform's own OpenAPI diff is exactly it."
        ),
    ),
    TestKind(
        "end_to_end",
        "End-to-end journeys",
        "Can a person still complete the task the product exists for?",
        how_to_evidence=(
            "Drive the deployed UI through its primary journeys and report the "
            "result as JUnit to the functional lane."
        ),
    ),
    TestKind(
        "performance",
        "Performance and load",
        "Does it still answer under the load it will actually see?",
        how_to_evidence=(
            "Run a load profile against a deployed environment and report pass/fail "
            "against a stated budget. A number with no budget is not a test."
        ),
    ),
    TestKind(
        "accessibility",
        "Accessibility",
        "Can everybody use it?",
        how_to_evidence=(
            "Run an automated audit (axe, Lighthouse) over the rendered pages and "
            "report it as JUnit. Automated checks catch perhaps a third of real "
            "barriers, so a green lane here is a floor and not a pass."
        ),
    ),
    TestKind(
        "resilience",
        "Resilience",
        "What happens when a dependency is down?",
        how_to_evidence=(
            "Assert the degraded path: take a dependency away in a test environment "
            "and check the system fails visibly rather than silently."
        ),
    ),
    TestKind(
        "smoke",
        "Post-deploy smoke",
        "Did the thing that just shipped actually come up?",
        how_to_evidence=(
            "Probe the deployed environment after each release and report the "
            "result. Distinct from dynamic scanning: this asks whether it is alive, "
            "not whether it is safe."
        ),
    ),
)


@dataclass
class KindResult:
    key: str
    name: str
    why: str
    presence: Presence
    evidence: list[str] = field(default_factory=list)
    how_to_evidence: str = ""


@dataclass
class LaneHealth:
    """One test lane's record. Coverage is a state, never a bare number."""

    capability: str
    enabled: bool
    runs: int
    succeeded: int
    failed: int
    last_run_at: str | None
    #: `reported`, `never_reported`, or `no_runs`.
    coverage_state: str
    line_coverage: float | None


def lane_health(scan_health: list[dict[str, Any]], enabled: set[str]) -> list[LaneHealth]:
    """The three test lanes, whether or not they have ever run.

    A lane that has never run is a row saying so, not an absence. Today a
    repository with no tests looks identical to one this platform has not been
    pointed at, and those are not the same problem.
    """
    by_capability = {str(row.get("capability")): row for row in scan_health}
    lanes: list[LaneHealth] = []

    for capability in TEST_LANES:
        row: dict[str, Any] = by_capability.get(capability, {})
        runs = int(row.get("runs") or 0)
        coverage = row.get("line_coverage")
        if coverage is not None:
            state = "reported"
        elif runs:
            # The state this whole estate was in. Emphatically not 0%.
            state = "never_reported"
        else:
            state = "no_runs"

        lanes.append(
            LaneHealth(
                capability=capability,
                enabled=capability in enabled,
                runs=runs,
                succeeded=int(row.get("succeeded") or 0),
                failed=int(row.get("failed") or 0),
                last_run_at=(
                    str(row["last_run_at"]) if row.get("last_run_at") is not None else None
                ),
                coverage_state=state,
                line_coverage=float(coverage) if coverage is not None else None,
            )
        )

    return lanes


def assess(
    *,
    reporting_capabilities: set[str],
    demonstrated_regressions: int = 0,
) -> list[KindResult]:
    """Which kinds of testing this repository has evidence of.

    `reporting_capabilities` is lanes that have *reported*, not lanes that are
    enabled — an enabled lane that has never produced a run evidences no
    testing, and counting it would let a repository claim a test kind by
    flipping a toggle.

    `demonstrated_regressions` counts regression links the platform *watched*
    fail against the vulnerable code and pass against the fix (spec 31).
    Asserted links deliberately do not count: a link somebody typed is a claim
    about a test, and this view is about evidence.
    """
    results: list[KindResult] = []

    for kind in KINDS:
        evidence: list[str] = []

        for capability in kind.capabilities:
            if capability in reporting_capabilities:
                evidence.append(f"the {capability} lane is reporting runs")

        if kind.key == "security_regression" and demonstrated_regressions:
            noun = "test" if demonstrated_regressions == 1 else "tests"
            evidence.append(
                f"{demonstrated_regressions} regression {noun} demonstrated "
                "against the vulnerable code"
            )

        results.append(
            KindResult(
                key=kind.key,
                name=kind.name,
                why=kind.why,
                presence="observed" if evidence else "absent",
                evidence=evidence,
                how_to_evidence=kind.how_to_evidence,
            )
        )

    return results


def summarise(results: list[KindResult]) -> dict[str, int]:
    """Counts, not a score.

    Deliberately no "test maturity" number: the kinds are not equally
    applicable — a library needs no post-deploy smoke test — so a repository
    could only ever lose points for correctly not doing something.
    """
    return {
        "observed": sum(1 for r in results if r.presence == "observed"),
        "absent": sum(1 for r in results if r.presence == "absent"),
    }
