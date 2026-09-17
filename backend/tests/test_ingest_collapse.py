"""Does ingest say when two submissions become one finding? (#397)

THE DEFECT THIS PINS. ZAP raised three Medium CSP alerts against one URL --
`Wildcard Directive`, `script-src unsafe-inline`, `style-src unsafe-inline`.
All three carry pluginid 10055 and cweid 693, so all three became the same
`rule_id`; `compute_finding_id` does not take `title`, which was the only field
that differed. Three submissions, one finding, last write wins, and the
survivor was chosen by JSON array order (#395).

`scan_runs.finding_count` recorded all of them, because the adapter counted
what it produced. The findings table held fewer. Both numbers were published
and they disagreed, and nothing anywhere compared them.

The same mechanism, with a constant for the snippet, turned 34 gitleaks
detections into 13 findings (#396).
"""

from __future__ import annotations

import logging

from mykronos.api.ingest import _warn_on_collapse


def _row(finding_id: str, title: str) -> dict[str, object]:
    return {"finding_id": finding_id, "title": title}


class TestTheSignalThatMatters:
    def test_different_titles_under_one_id_warn(self, caplog) -> None:
        """The ZAP case, reproduced. This is the one worth waking somebody
        for: two findings that are not the same finding."""
        rows = [
            _row("abc", "CSP: Wildcard Directive at GET /"),
            _row("abc", "CSP: script-src unsafe-inline at GET /"),
            _row("abc", "CSP: style-src unsafe-inline at GET /"),
        ]

        with caplog.at_level(logging.WARNING):
            _warn_on_collapse(rows, "dast", "ToddGBenson/TheHub", "run-1")

        assert "merged DIFFERENT findings" in caplog.text
        assert "script-src unsafe-inline" in caplog.text

    def test_identical_titles_do_not_warn(self, caplog) -> None:
        """ZAP enumerates a site root as both `http://host` and
        `http://host/`; both normalise to `/`, and merging them is correct.
        Warning here would fail an honest scan into the noise."""
        rows = [_row("abc", "Non-Storable Content at GET /")] * 2

        with caplog.at_level(logging.WARNING):
            _warn_on_collapse(rows, "dast", "ToddGBenson/TheHub", "run-1")

        assert "merged DIFFERENT findings" not in caplog.text

    def test_identical_titles_are_still_counted_at_info(self, caplog) -> None:
        """Not silent — just not alarming. The count is what makes
        `finding_count` and the findings table reconcilable at all."""
        rows = [_row("abc", "same")] * 3

        with caplog.at_level(logging.INFO):
            _warn_on_collapse(rows, "secrets", "ToddGBenson/TheHub", "run-1")

        assert "2 duplicate submission(s) merged" in caplog.text

    def test_no_collapse_says_nothing(self, caplog) -> None:
        rows = [_row("a", "one"), _row("b", "two")]

        with caplog.at_level(logging.INFO):
            _warn_on_collapse(rows, "sast", "ToddGBenson/keel", "run-1")

        assert caplog.text == ""

    def test_the_counts_reconcile(self, caplog) -> None:
        """`5 submission(s) collapsed into 3 finding(s)` is the sentence that
        explains a `finding_count` the findings table cannot match."""
        rows = [
            _row("a", "x"), _row("a", "y"),
            _row("b", "p"), _row("b", "q"),
            _row("c", "solo"),
        ]

        with caplog.at_level(logging.WARNING):
            _warn_on_collapse(rows, "dast", "ToddGBenson/TheHub", "run-1")

        assert "5 submission(s) collapsed into 3 finding(s)" in caplog.text

    def test_a_hostile_title_cannot_forge_a_log_line(self, caplog) -> None:
        """Titles are scanner output crossing into a log record. A newline in
        one ends the record early and starts one a reader has no reason to
        doubt."""
        rows = [
            _row("abc", "real finding"),
            _row("abc", "fake\nINFO: nothing to see here"),
        ]

        with caplog.at_level(logging.WARNING):
            _warn_on_collapse(rows, "dast", "ToddGBenson/TheHub", "run-1")

        assert "\nINFO: nothing to see here" not in caplog.text
        assert "\n" in caplog.text
