"""A lane that reports success over code it cannot read (B-051).

`keel` recorded 47 successful SAST runs and zero findings, ever. That reads as
a well-kept repository. Its analyser is CodeQL, CodeQL implements no shell
language at all, and 69% of keel is shell -- so 219 KB has never been read by
anything and every run over it reported success.

This is the platform's own thesis one level down. It leads with silent lanes
because a lane that reports nothing looks exactly like a clean repository. A
lane that reports nothing *because it cannot read the language* looks the same
and is worse: it reports `success`, so it appears in no stalled-lane section,
no scan health, and no gap anywhere.
"""

from __future__ import annotations

from mykronos import briefing
from mykronos.analysers import NOT_SOURCE, SAST_LANGUAGES, describe, readability

#: GitHub's byte counts for the estate, read 2026-09-09.
KEEL = {"Shell": 219000, "Python": 66000, "JavaScript": 28000}
PERSONAL_SOC = {"PowerShell": 30000}
MYKRONOS = {"Python": 800000, "TypeScript": 120000, "PowerShell": 40000, "Jinja": 10000}
BINNACLE = {"Shell": 210000, "Python": 72000, "JavaScript": 28000}


class TestWhatTheAnalyserCanRead:
    def test_the_estate_reproduces_the_entry(self) -> None:
        """The four numbers B-051 was filed on, computed rather than quoted."""
        assert round(readability("keel", KEEL, "codeql").share_unread, 2) == 0.70
        assert readability("personal-soc", PERSONAL_SOC, "codeql").share_unread == 1.0
        assert round(readability("binnacle", BINNACLE, "codeql").share_unread, 2) == 0.68
        assert round(readability("mykronos", MYKRONOS, "codeql").share_unread, 2) == 0.04

    def test_codeql_implements_no_shell_of_any_kind(self) -> None:
        """The absence that is the whole entry, asserted rather than left to
        be rediscovered from an empty result."""
        assert "Shell" not in SAST_LANGUAGES["codeql"]
        assert "PowerShell" not in SAST_LANGUAGES["codeql"]

    def test_a_fully_readable_repository_is_not_reported(self) -> None:
        reading = readability("x", {"Python": 100, "TypeScript": 50}, "codeql")

        assert reading.blind is False
        assert reading.unread == []

    def test_any_unread_source_counts_rather_than_a_threshold(self) -> None:
        """A percentage invites an argument about where the line goes. The
        honest statement is that some of this is read by nothing."""
        reading = readability("mykronos", MYKRONOS, "codeql")

        assert reading.blind is True
        assert reading.share_unread < 0.05

    def test_configuration_is_not_counted_as_unread_source(self) -> None:
        """A Dockerfile is read by `containers` and HCL by `iac`. Reporting
        them as unanalysed source would produce a page of gaps nobody should
        act on, which is how a real one stops being read."""
        reading = readability("x", {"Python": 100, "Dockerfile": 900, "HCL": 900}, "codeql")

        assert reading.blind is False
        assert {"Dockerfile", "HCL"} <= NOT_SOURCE

    def test_a_broader_analyser_closes_the_gap(self) -> None:
        """Semgrep covers bash, so pointing keel at it is a real answer rather
        than a second green lane over the same unread bytes."""
        assert readability("keel", KEEL, "semgrep").blind is False

    def test_an_unknown_tool_reads_nothing(self) -> None:
        """The safe direction. A tool with no language list here should say so
        rather than be assumed comprehensive."""
        assert readability("x", {"Python": 100}, "some-new-scanner").share_unread == 1.0

    def test_a_repository_with_no_languages_is_unknown_not_clean(self) -> None:
        """A new or empty repository must not report as a coverage gap on its
        first day, and must not report as fully analysed either."""
        reading = readability("x", {}, "codeql")

        assert reading.known is False
        assert reading.blind is False
        assert "nothing was measured" in describe(reading)


class TestWhatTheSentenceSays:
    def test_it_names_the_share_and_the_languages(self) -> None:
        """"30% analysed" without saying what the other 70% is leaves the
        reader unable to choose a tool."""
        sentence = describe(readability("ToddGBenson/keel", KEEL, "codeql"))

        assert "70%" in sentence
        assert "Shell" in sentence
        assert "codeql" in sentence


class TestInTheBriefing:
    def test_the_worst_repository_is_first(self) -> None:
        rows = briefing.unread_code(
            {"keel": KEEL, "personal-soc": PERSONAL_SOC, "mykronos": MYKRONOS}
        )

        assert [row.repo_full_name for row in rows] == ["personal-soc", "keel", "mykronos"]

    def test_no_re_run_is_offered(self) -> None:
        """Every other lane row on that page offers a dispatch. Running this
        one again reads the same bytes with the same tool and reports success
        again."""
        row = briefing.unread_code({"keel": KEEL})[0]

        assert row.action.method == "GET"
        assert "reports success again" in row.action.effect

    def test_the_configured_tool_is_used(self) -> None:
        assert briefing.unread_code({"keel": KEEL}, {"keel": "semgrep"}) == []

    def test_no_language_data_reports_nothing(self) -> None:
        """A caller with no GitHub client passes nothing. Not knowing what a
        repository is made of is different from knowing it is analysed."""
        assert briefing.unread_code(None) == []
        assert briefing.unread_code({}) == []

    def test_the_section_renders_with_the_share(self, catalog) -> None:
        report = briefing.build(catalog, languages={"ToddGBenson/keel": KEEL})
        rendered = briefing.render(report)

        assert "CODE NO ANALYSER HERE CAN READ" in rendered
        assert "70% unread" in rendered

    def test_a_clean_estate_renders_no_section(self, catalog) -> None:
        """A heading with nothing under it trains people to skip the heading."""
        rendered = briefing.render(briefing.build(catalog, languages={"x": {"Python": 10}}))

        assert "CODE NO ANALYSER HERE CAN READ" not in rendered

    def test_scoping_to_one_repository_keeps_it(self, catalog) -> None:
        scoped = briefing.build(
            catalog,
            asset_id="ToddGBenson/keel",
            languages={"ToddGBenson/keel": KEEL, "ToddGBenson/mykronos": MYKRONOS},
        )

        assert [row.repo_full_name for row in scoped.unread] == ["ToddGBenson/keel"]
