"""The regression link a merged fix pull request produces (spec 31 §2, B-011).

Spec 31 names three sources for a finding-to-test link. Before this, only one
could write a row in a running system, and it was not one of the three: every
`demonstrated` link that existed anywhere was written by
`tests/test_regression_coverage.py`, by hand-crafting an HTTP request. The
producer the spec describes — Patchwork's PR body, parsed on merge — had no
production code at all, so the number the whole incentive design rests on
could not move outside the test suite.

These cover the producer itself. The guard that it stays a producer, rather
than becoming another fixture, is `TestTheProducerIsNotAFixture` below.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from mykronos import regression
from mykronos.lake.catalog import Catalog
from mykronos.patchwork import outcomes
from mykronos.patchwork.regression_prompt import (
    DEFAULT_LANE,
    REGRESSION_MARKER,
    UNSTATED,
    parse_regression_test,
    regression_prompt,
)
from mykronos.schemas import utcnow

REPO = "acme/widgets"
PR_NUMBER = 41
FINDING_ID = "f" * 64


@pytest.fixture
def seeded_event(buffer, run_compaction) -> dict[str, Any]:
    """One Patchwork draft, open, waiting on a close.

    `record_pr_outcome` finds its row by (repo, pr_number), so a link cannot
    be produced without one -- which is the point: this only ever fires for a
    pull request Patchwork itself opened.
    """
    buffer.append(
        "remediation_events",
        [
            {
                "event_id": "event-1",
                "repo_full_name": REPO,
                "finding_id": FINDING_ID,
                "toxic_combination_id": None,
                "contributing_finding_ids": "[]",
                "pipeline_stage_reached": "pr_opened",
                "triage_classification": "true_positive",
                "fix_pr_number": PR_NUMBER,
                "fix_pr_url": f"https://github.com/{REPO}/pull/{PR_NUMBER}",
                "pr_status": "open",
                "rationale": "a deterministic fixer matched this finding",
                "verification_commit_sha": None,
                "verification_outcome": None,
                "fixer_name": "pin-dependency",
                "rejection_reason_code": None,
                "rejection_reason": None,
                "created_at": utcnow(),
                "updated_at": utcnow(),
            }
        ],
    )
    run_compaction()
    return {"repo": REPO, "pr_number": PR_NUMBER, "finding_id": FINDING_ID}


class TestTheParser:
    def test_an_unedited_prompt_names_no_test(self) -> None:
        """The common case by far, and not a failure. The block ships with an
        empty value, so an untouched body matches the pattern with nothing in
        it — that is "not answered", not a test called nothing."""
        assert parse_regression_test(regression_prompt()) == (UNSTATED, DEFAULT_LANE)

    def test_an_empty_body_names_no_test(self) -> None:
        assert parse_regression_test("") == (UNSTATED, DEFAULT_LANE)
        assert parse_regression_test(None) == (UNSTATED, DEFAULT_LANE)

    def test_it_reads_the_test_somebody_named(self) -> None:
        body = f"{REGRESSION_MARKER}\ntest: tests/test_orders.py::test_injection_is_refused"
        identifier, lane = parse_regression_test(body)

        assert identifier == "tests/test_orders.py::test_injection_is_refused"
        assert lane == DEFAULT_LANE

    def test_backticks_are_optional_because_people_add_them(self) -> None:
        assert parse_regression_test("test: `tests/test_a.py::test_b`")[0] == (
            "tests/test_a.py::test_b"
        )

    def test_a_stated_lane_is_used(self) -> None:
        body = "test: tests/test_login.py::test_lockout\nlane: functional"

        assert parse_regression_test(body) == (
            "tests/test_login.py::test_lockout",
            "functional",
        )

    def test_an_unknown_lane_falls_back_rather_than_failing(self) -> None:
        """`lane: smoke` is somebody being helpful about a lane this platform
        does not run (D-046). Taking the default keeps their test name, which
        is the valuable half; refusing the whole link over it would not."""
        body = "test: tests/test_a.py::test_b\nlane: smoke"

        assert parse_regression_test(body) == ("tests/test_a.py::test_b", DEFAULT_LANE)

    def test_only_the_first_named_test_is_read(self) -> None:
        """Two is somebody who edited carelessly. Taking the first is the rule
        `parse_rejection` already applies for the same reason."""
        body = "test: first::one\ntest: second::two"

        assert parse_regression_test(body)[0] == "first::one"

    def test_it_survives_the_whole_prompt_plus_a_rejection_block(self) -> None:
        """Both blocks are in every body Patchwork opens. Neither parser may
        read the other's line."""
        from mykronos.patchwork.rejection import UNSTATED as REJ_UNSTATED
        from mykronos.patchwork.rejection import parse_rejection

        body = (
            f"{regression_prompt()}\n\ntest: tests/test_x.py::test_y\n\n"
            "<!-- mykronos:rejection -->\n### If you close this without merging\n"
        )

        assert parse_regression_test(body)[0] == "tests/test_x.py::test_y"
        assert parse_rejection(body)[0] == REJ_UNSTATED


class TestTheProducerIsNotAFixture:
    """B-011's own acceptance criterion, as a test.

    The defect this entry was filed against was not that `demonstrated` was
    hard to produce. It was that the only thing producing *any* link in a
    running system lived under `backend/tests/`, so the number moved only when
    the suite ran. A fixture can never again be the only writer.
    """

    def test_the_linker_lives_in_the_package_not_the_suite(self) -> None:
        source_file = Path(inspect.getsourcefile(outcomes._link_regression_test) or "")

        assert source_file.is_file()
        assert "tests" not in source_file.parts, (
            f"the producer is at {source_file}, inside the test suite - which "
            "is the exact defect B-011 was filed against"
        )
        assert source_file.parts[-2:] == ("patchwork", "outcomes.py")

    def test_the_merge_path_calls_it(self) -> None:
        """A producer nothing calls is a fixture with a different address."""
        source = inspect.getsource(outcomes.record_pr_outcome)

        assert "_link_regression_test(" in source

    def test_the_prompt_is_in_every_pull_request_body(self) -> None:
        """The parser is worthless if nobody is ever asked the question."""
        from mykronos.patchwork import pipeline

        assert "regression_prompt()" in inspect.getsource(pipeline.render_pr_body)


class TestLinkingOnMerge:
    """The behaviour, through `record_pr_outcome`, against a real buffer."""

    @staticmethod
    def _links(catalog: Catalog) -> list[dict[str, Any]]:
        if not catalog.all_files("finding_tests"):
            return []
        rows = catalog.query(
            "SELECT finding_id, test_identifier, capability, evidence, linked_by "
            "FROM finding_tests"
        )
        return [
            {
                "finding_id": r[0],
                "test_identifier": r[1],
                "capability": r[2],
                "evidence": r[3],
                "linked_by": r[4],
            }
            for r in rows
        ]

    def test_a_named_test_on_a_merge_becomes_an_asserted_link(
        self, catalog, buffer, run_compaction, seeded_event
    ) -> None:
        outcomes.record_pr_outcome(
            catalog,
            buffer,
            seeded_event["repo"],
            seeded_event["pr_number"],
            merged=True,
            pr_body="test: tests/test_orders.py::test_injection_refused",
        )
        run_compaction()

        links = self._links(catalog)
        assert len(links) == 1
        assert links[0]["test_identifier"] == "tests/test_orders.py::test_injection_refused"
        assert links[0]["capability"] == "unit"
        assert links[0]["finding_id"] == seeded_event["finding_id"]

    def test_the_link_is_asserted_and_never_demonstrated(
        self, catalog, buffer, run_compaction, seeded_event
    ) -> None:
        """The honest grade. The test arrives *in* this pull request, so it is
        absent from the parent commit and nothing has watched it fail against
        the vulnerable code. Claiming otherwise would corrupt the one number
        spec 31 exists to make trustworthy, since Oracle weights
        `demonstrated` above `asserted` precisely because it means more."""
        outcomes.record_pr_outcome(
            catalog,
            buffer,
            seeded_event["repo"],
            seeded_event["pr_number"],
            merged=True,
            pr_body="test: tests/test_a.py::test_b",
        )
        run_compaction()

        assert self._links(catalog)[0]["evidence"] == regression.ASSERTED

    def test_a_close_without_merge_links_nothing(
        self, catalog, buffer, run_compaction, seeded_event
    ) -> None:
        """A test named on a fix nobody took is a claim about code that is not
        in the repository."""
        outcomes.record_pr_outcome(
            catalog,
            buffer,
            seeded_event["repo"],
            seeded_event["pr_number"],
            merged=False,
            pr_body="test: tests/test_a.py::test_b",
        )
        run_compaction()

        assert self._links(catalog) == []

    def test_an_unedited_body_links_nothing(
        self, catalog, buffer, run_compaction, seeded_event
    ) -> None:
        outcomes.record_pr_outcome(
            catalog,
            buffer,
            seeded_event["repo"],
            seeded_event["pr_number"],
            merged=True,
            pr_body=regression_prompt(),
        )
        run_compaction()

        assert self._links(catalog) == []

    def test_a_redelivered_webhook_does_not_inflate_the_count(
        self, catalog, buffer, run_compaction, seeded_event
    ) -> None:
        """GitHub redelivers. The link id is keyed on (repo, finding, test) so
        the second delivery updates one row rather than adding a second."""
        for _ in range(2):
            outcomes.record_pr_outcome(
                catalog,
                buffer,
                seeded_event["repo"],
                seeded_event["pr_number"],
                merged=True,
                pr_body="test: tests/test_a.py::test_b",
            )
        run_compaction()

        assert len(self._links(catalog)) == 1
