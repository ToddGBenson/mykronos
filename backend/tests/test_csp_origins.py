"""The CSP origin comparison — mykronos#290.

Two kinds of test live here and they are not the same kind of claim:

* `TestClassification`, `TestPolicy`, `TestComparison`, `TestReporting` and
  `TestTheHubToday` are **evidence**. Each one fails against a tree without
  the detector, the fallback rule or the verdict it names — that is what makes
  it worth having.
* `TestGuards` are **guards**. They lock in a property that could silently
  stop holding: that a wildcarded directive never produces a finding, that a
  missing header raises instead of reporting the whole policy as broken, and
  that the environment can never be left unnamed. They are green the moment
  the code is written and they are not evidence that anything was fixed.
"""

from __future__ import annotations

import pytest

from mykronos.csp_origins import (
    compare,
    format_report,
    main,
    normalise_origin,
    parse_policy,
    references_in,
    scan_repository,
    source_matches,
    to_sarif,
)

#: TheHub's live policy, read from the running production backend (:8000) on
#: 2026-09-18. Identical on demo (:8002) that day and **not** identical on
#: staging (:8081) — see `STAGING_POLICY`.
THEHUB_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
    "https://fonts.googleapis.com https://static.cloudflareinsights.com "
    "https://cdn.teller.io; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data: blob: https://*.wikimedia.org https://*.seatgeekstatic.com "
    "https://*.ticketmaster.com https://*.livenation.com https://i.scdn.co "
    "https://*.spotifycdn.com https://*.mzstatic.com https://*.discogs.com "
    "https://*.googleapis.com https://*.gstatic.com https:; "
    "connect-src 'self' https://cloudflareinsights.com https://cdn.jsdelivr.net "
    "https://cdn.teller.io https://api.teller.io; "
    "frame-src 'self' https://cdn.teller.io https://teller.io; "
    "media-src 'self' https://*.cloudfront.net; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


#: Staging's live policy on the same day, read from :8081. It diverges from
#: production in two places and nothing in the estate reported either:
#: `connect-src` also permits `https://api.datamuse.com`, and `img-src` ends
#: in `*` rather than `https:`. So the rhyme lookup works on staging and is
#: blocked on production and demo, which is the exact shape of the Teller
#: break the issue was filed about — caught this time by measuring.
STAGING_POLICY = THEHUB_POLICY.replace(
    "https://*.gstatic.com https:;", "https://*.gstatic.com *;"
).replace("https://api.teller.io;", "https://api.teller.io https://api.datamuse.com;")


def thehub_policy(environment: str = "production") -> object:
    return parse_policy(
        THEHUB_POLICY, environment=environment, read_from="http://127.0.0.1:8000/"
    )


def directives_for(text: str, path: str = "app.js") -> dict[str, set[str]]:
    """`{origin: {directive or "" for ungoverned}}` for a blob of source."""
    out: dict[str, set[str]] = {}
    for reference in references_in(text, path):
        out.setdefault(reference.origin, set()).add(reference.directive or "")
    return out


# --------------------------------------------------------------------------
# Evidence: a hit is not a use
# --------------------------------------------------------------------------


class TestClassification:
    def test_an_anchor_is_not_a_load(self) -> None:
        found = references_in('<a href="https://www.google.com/search">g</a>', "index.html")
        assert [(r.origin, r.directive) for r in found] == [("https://www.google.com", None)]

    def test_a_fetch_of_a_literal_is_connect_src(self) -> None:
        found = references_in("await fetch('https://api.datamuse.com/words');", "a.js")
        assert [(r.origin, r.directive) for r in found] == [
            ("https://api.datamuse.com", "connect-src")
        ]

    def test_a_fetch_of_a_bound_template_literal_is_connect_src(self) -> None:
        """The Datamuse shape: the URL is in a ternary, the fetch takes a name.

        A `fetch\\('https://...'\\)` pattern misses this entirely, and this is
        one of the two breaks the issue was filed about.
        """
        source = (
            "const endpoint = type === 'near'\n"
            "    ? `https://api.datamuse.com/words?rel_nry=${word}`\n"
            "    : `https://api.datamuse.com/words?rel_rhy=${word}`;\n"
            "const response = await fetch(endpoint);\n"
        )
        found = references_in(source, "lyric-tools.js")
        assert {r.directive for r in found} == {"connect-src"}
        assert [r.line for r in found] == [2, 3]
        assert all("endpoint" in r.evidence for r in found)

    def test_a_dynamically_created_script_is_script_src(self) -> None:
        """The Teller shape: `createElement('script')` then `.src = '...'`."""
        source = (
            "const script = document.createElement('script');\n"
            "script.src = 'https://cdn.teller.io/connect/connect.js';\n"
        )
        found = references_in(source, "finances.js")
        assert [(r.origin, r.directive) for r in found] == [
            ("https://cdn.teller.io", "script-src")
        ]

    def test_a_src_assignment_on_an_unidentifiable_element_is_not_claimed(self) -> None:
        """An element whose type we never saw is honestly unclassified.

        Guessing `script-src` here would be the defect this module exists to
        name: asserting a directive that was never measured.
        """
        found = references_in("thing.src = 'https://cdn.example-host.test/x.js';", "a.js")
        assert [r.directive for r in found] == [None]
        assert "unknown type" in found[0].evidence

    def test_markup_detectors_run_inside_javascript_template_literals(self) -> None:
        source = 'el.innerHTML = `<img src="https://i.scdn.co/image/abc">`;'
        assert directives_for(source) == {"https://i.scdn.co": {"img-src"}}

    def test_a_stylesheet_link_is_style_src_and_a_preconnect_is_not_governed(self) -> None:
        source = (
            '<link rel="preconnect" href="https://fonts.gstatic.com">\n'
            '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
        )
        assert directives_for(source, "index.html") == {
            "https://fonts.gstatic.com": {""},
            "https://fonts.googleapis.com": {"style-src"},
        }

    def test_an_iframe_is_frame_src_and_a_form_action_is_form_action(self) -> None:
        source = (
            '<iframe src="https://teller.io/connect"></iframe>'
            '<form action="https://forms.teller.io/x"></form>'
        )
        assert directives_for(source, "p.html") == {
            "https://teller.io": {"frame-src"},
            "https://forms.teller.io": {"form-action"},
        }

    def test_a_font_face_url_is_font_src(self) -> None:
        source = "@font-face { font-family: X; src: url('https://fonts.gstatic.com/s/a.woff2'); }"
        assert directives_for(source, "a.css") == {"https://fonts.gstatic.com": {"font-src"}}

    def test_an_unattributable_url_is_recorded_as_unclassified_not_dropped(self) -> None:
        found = references_in("// see https://docs.teller.io/guide for details", "a.js")
        assert [(r.origin, r.evidence) for r in found] == [
            ("https://docs.teller.io", "unclassified")
        ]

    def test_a_placeholder_is_not_an_origin(self) -> None:
        source = "fetch('https://...'); fetch('https://YOUR_HOST/api'); fetch('https://jobs.example.com')"
        assert references_in(source, "a.js") == []

    def test_scan_skips_vendored_trees_and_unloadable_files(self, tmp_path) -> None:
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "a.js").write_text("fetch('https://api.datamuse.com/w')")
        (tmp_path / "frontend" / "README.md").write_text("https://readme-only.test/x")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "b.js").write_text("fetch('https://vendored.test/x')")
        origins = {r.origin for r in scan_repository(tmp_path)}
        assert origins == {"https://api.datamuse.com"}


class TestOriginNormalisation:
    def test_case_path_and_default_port_are_dropped(self) -> None:
        assert normalise_origin("https://CDN.Teller.io:443/connect.js?v=1") == "https://cdn.teller.io"

    def test_a_non_default_port_is_part_of_the_origin(self) -> None:
        assert normalise_origin("http://hub.internal.test:8081/x") == (
            "http://hub.internal.test:8081"
        )

    def test_a_hardcoded_address_is_an_origin_like_any_other(self) -> None:
        """A LAN address in a frontend is a real load and a real CSP entry."""
        assert normalise_origin("http://10.0.0.5:8081/x") == "http://10.0.0.5:8081"

    def test_reserved_documentation_names_are_not_loads(self) -> None:
        assert normalise_origin("https://example.com/x") is None
        assert normalise_origin("https://api.example.com/x") is None


class TestSourceMatching:
    @pytest.mark.parametrize(
        ("source", "origin", "expected"),
        [
            ("https://cdn.teller.io", "https://cdn.teller.io", True),
            ("https://cdn.teller.io", "https://api.teller.io", False),
            ("https://*.gstatic.com", "https://fonts.gstatic.com", True),
            ("https://*.gstatic.com", "https://gstatic.com", True),
            ("https://*.gstatic.com", "https://evilgstatic.com", False),
            ("https:", "https://anything.test", True),
            ("https:", "http://anything.test", False),
            ("*", "https://anything.test", True),
            ("'self'", "https://cdn.teller.io", False),
            ("'unsafe-inline'", "https://cdn.teller.io", False),
            ("cdn.teller.io", "https://cdn.teller.io", True),
            ("https://hub.test:8081", "https://hub.test", False),
        ],
    )
    def test_source_grammar(self, source: str, origin: str, expected: bool) -> None:
        assert source_matches(source, origin) is expected


class TestPolicy:
    def test_frame_src_falls_back_through_child_src_to_default_src(self) -> None:
        policy = parse_policy(
            "default-src 'self' https://d.test; child-src https://c.test",
            environment="test",
            read_from="fixture",
        )
        assert policy.effective_sources("frame-src") == ("child-src", "https://c.test")
        assert policy.effective_sources("img-src") == ("default-src", "'self' https://d.test")

    def test_form_action_does_not_fall_back_to_default_src(self) -> None:
        policy = parse_policy("default-src 'self'", environment="test", read_from="fixture")
        assert policy.effective_sources("form-action") is None

    def test_a_directive_with_a_scheme_source_is_wildcarded(self) -> None:
        policy = thehub_policy()
        assert policy.is_wildcarded("img-src") == "https:"
        assert policy.is_wildcarded("connect-src") is None

    def test_the_first_occurrence_of_a_directive_wins(self) -> None:
        policy = parse_policy(
            "connect-src 'self'; connect-src https://late.test",
            environment="test",
            read_from="fixture",
        )
        assert policy.directives["connect-src"] == ("'self'",)


# --------------------------------------------------------------------------
# Evidence: both directions of the join
# --------------------------------------------------------------------------


class TestComparison:
    def test_a_governed_load_the_policy_omits_is_an_omission(self) -> None:
        references = references_in("await fetch('https://api.datamuse.com/w');", "a.js")
        result = compare(references, thehub_policy())
        assert [(o.origin, o.directive) for o in result.omissions] == [
            ("https://api.datamuse.com", "connect-src")
        ]
        assert result.omissions[0].governing_directive == "connect-src"

    def test_an_ungoverned_reference_to_an_omitted_origin_is_not_an_omission(self) -> None:
        references = references_in('<a href="https://api.datamuse.com/w">x</a>', "a.html")
        assert compare(references, thehub_policy()).omissions == ()

    def test_a_permitted_load_is_not_an_omission(self) -> None:
        source = (
            "const s = document.createElement('script');\n"
            "s.src = 'https://cdn.teller.io/connect/connect.js';\n"
        )
        assert compare(references_in(source, "a.js"), thehub_policy()).omissions == ()

    def test_self_is_resolved_only_against_declared_self_origins(self) -> None:
        references = references_in("fetch('https://hub.toddbenson.test/api');", "a.js")
        policy = thehub_policy()
        assert len(compare(references, policy).omissions) == 1
        widened = compare(
            references, policy, self_origins=frozenset({"https://hub.toddbenson.test"})
        )
        assert widened.omissions == ()

    def test_an_allowance_nothing_references_is_unreferenced(self) -> None:
        result = compare([], thehub_policy())
        unused = {(u.directive, u.source): u.verdict for u in result.unused}
        assert unused[("connect-src", "https://api.teller.io")] == "unreferenced"

    def test_an_allowance_referenced_only_in_a_link_is_ungoverned_only(self) -> None:
        references = references_in('<a href="https://teller.io">t</a>', "a.html")
        result = compare(references, thehub_policy())
        verdicts = {(u.directive, u.source): u.verdict for u in result.unused}
        assert verdicts[("frame-src", "https://teller.io")] == "ungoverned-only"

    def test_an_allowance_used_under_another_directive_says_which(self) -> None:
        source = (
            "const s = document.createElement('script');\n"
            "s.src = 'https://cdn.teller.io/connect/connect.js';\n"
        )
        result = compare(references_in(source, "a.js"), thehub_policy())
        by_key = {(u.directive, u.source): u for u in result.unused}
        assert by_key[("connect-src", "https://cdn.teller.io")].verdict == "other-directive"
        assert by_key[("connect-src", "https://cdn.teller.io")].seen_as == ("script-src",)
        assert ("script-src", "https://cdn.teller.io") not in by_key

    def test_a_wildcarded_directive_is_reported_as_unevaluable_not_as_findings(self) -> None:
        """#329: `img-src` ends in a bare `https:`, so its named origins are
        decorative. Say that once; do not report ten tidy unused allowances
        that would be equally true of any hostname in the world."""
        source = '<img src="https://never.permitted.test/x.png">'
        result = compare(references_in(source, "a.html"), thehub_policy())
        wildcarded = {w.directive: w for w in result.wildcarded}
        assert set(wildcarded) == {"img-src"}
        assert wildcarded["img-src"].wildcard == "https:"
        assert "https://i.scdn.co" in wildcarded["img-src"].named_sources
        assert [o.directive for o in result.omissions] == []
        assert [u.directive for u in result.unused if u.directive == "img-src"] == []

    def test_a_scheme_wildcard_still_blocks_the_other_scheme(self) -> None:
        """`img-src ... https:` permits every https host and no http one.

        Skipping a wildcarded directive wholesale would swallow the single
        load it really does block.
        """
        source = '<img src="http://insecure.test/x.png">'
        result = compare(references_in(source, "a.html"), thehub_policy())
        assert [(o.origin, o.directive) for o in result.omissions] == [
            ("http://insecure.test", "img-src")
        ]


# --------------------------------------------------------------------------
# Evidence: the environment travels with every claim
# --------------------------------------------------------------------------


class TestReporting:
    def test_every_sarif_result_names_the_environment_and_the_policy_source(self) -> None:
        references = references_in("fetch('https://api.datamuse.com/w');", "a.js")
        result = compare(references, thehub_policy("production"), scanned_paths=("frontend",))
        sarif = to_sarif(result)
        run = sarif["runs"][0]  # type: ignore[index]
        assert run["properties"]["environment"] == "production"
        assert run["properties"]["policySource"] == "http://127.0.0.1:8000/"
        assert run["results"]
        for entry in run["results"]:
            assert entry["properties"]["environment"] == "production"
            assert "environment: production" in entry["message"]["text"]

    def test_only_omissions_carry_a_repository_location(self) -> None:
        references = references_in("fetch('https://api.datamuse.com/w');", "a.js")
        run = to_sarif(compare(references, thehub_policy()))["runs"][0]  # type: ignore[index]
        located = [r for r in run["results"] if "locations" in r]
        assert {r["ruleId"] for r in located} == {"mykronos-csp/origin-not-permitted"}
        assert located[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.js"

    def test_the_report_names_the_environment_the_paths_and_both_directions(self) -> None:
        references = references_in("fetch('https://api.datamuse.com/w');", "a.js")
        report = format_report(
            compare(references, thehub_policy("staging"), scanned_paths=("frontend",))
        )
        assert "Environment : staging" in report
        assert "Paths read  : frontend" in report
        assert "USED BUT NOT PERMITTED (1)" in report
        assert "PERMITTED BUT UNUSED" in report
        assert "NOT EVALUABLE" in report

    def test_the_unused_message_says_it_is_an_argument_from_absence(self) -> None:
        run = to_sarif(compare([], thehub_policy()))["runs"][0]  # type: ignore[index]
        unused = [r for r in run["results"] if r["ruleId"] == "mykronos-csp/allowance-unused"]
        assert unused
        assert all("argument from absence" in r["message"]["text"] for r in unused)


class TestTheHubToday:
    """The shape TheHub is actually in, as a fixture rather than a live call.

    Reproduces the two call sites the issue names plus the one it does not,
    against the live production policy. A change to either half should make
    this fail loudly rather than quietly re-derive a different answer.
    """

    SOURCE = {
        "frontend/js/music/utils/lyric-tools.js": (
            "const endpoint = type === 'near'\n"
            "    ? `https://api.datamuse.com/words?rel_nry=${word}`\n"
            "    : `https://api.datamuse.com/words?rel_rhy=${word}`;\n"
            "const response = await fetch(endpoint);\n"
        ),
        "frontend/js/dashboard/finances.js": (
            "const script = document.createElement('script');\n"
            "script.src = 'https://cdn.teller.io/connect/connect.js';\n"
            "// <a href=\"https://teller.io\">teller.io</a>\n"
        ),
        "frontend/workbooks/workbook-viewer.html": (
            "const r = await fetch('https://api.openai.com/v1/chat/completions', {});\n"
        ),
        "frontend/index.html": (
            '<link rel="preconnect" href="https://fonts.gstatic.com">\n'
            '<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">\n'
            '<script src="https://cdn.jsdelivr.net/npm/marked@11.1.1/marked.min.js"></script>\n'
        ),
    }

    def result(self):  # type: ignore[no-untyped-def]
        references = [r for path, text in self.SOURCE.items() for r in references_in(text, path)]
        return compare(references, thehub_policy("production"), scanned_paths=("frontend",))

    def test_the_teller_script_load_is_permitted_now(self) -> None:
        """TheHub#309's fix is present in the live policy: this must not be an
        omission, or the tool is re-reporting a break that was repaired."""
        assert "https://cdn.teller.io" not in {o.origin for o in self.result().omissions}

    def test_the_rhyme_lookup_is_still_blocked(self) -> None:
        omissions = {(o.origin, o.directive) for o in self.result().omissions}
        assert ("https://api.datamuse.com", "connect-src") in omissions

    def test_a_third_break_the_issue_does_not_mention(self) -> None:
        """`workbook-viewer.html` fetches the OpenAI API directly. Not in the
        issue, not in the policy, and blocked on every environment."""
        omissions = {(o.origin, o.directive) for o in self.result().omissions}
        assert ("https://api.openai.com", "connect-src") in omissions

    def test_jsdelivr_and_google_fonts_are_permitted_where_they_are_used(self) -> None:
        origins = {o.origin for o in self.result().omissions}
        assert origins == {"https://api.datamuse.com", "https://api.openai.com"}

    def test_the_same_tree_gets_a_different_answer_on_staging(self) -> None:
        """Which is the whole reason the environment has to be named.

        Staging permits `api.datamuse.com` and production does not, so "is the
        rhyme lookup blocked?" has two correct answers and they depend on a
        fact no finding used to carry.
        """
        references = [r for path, text in self.SOURCE.items() for r in references_in(text, path)]
        staging = compare(
            references,
            parse_policy(
                STAGING_POLICY, environment="staging", read_from="http://127.0.0.1:8081/"
            ),
        )
        assert {o.origin for o in staging.omissions} == {"https://api.openai.com"}
        assert {o.origin for o in self.result().omissions} != {o.origin for o in staging.omissions}
        assert staging.policy.environment == "staging"


# --------------------------------------------------------------------------
# Guards — invariants, not evidence of a fix
# --------------------------------------------------------------------------


class TestGuards:
    def test_the_environment_cannot_be_left_unnamed(self) -> None:
        """Required, not defaulted. A comparison against 'the CSP' with three
        backends serving three policies reproduces the bug it was built to
        catch (the issue's fourth checkbox)."""
        with pytest.raises(SystemExit):
            main(["--policy-header", "default-src 'self'"])

    def test_a_policy_source_must_be_given(self) -> None:
        with pytest.raises(SystemExit):
            main(["--environment", "production"])

    def test_the_cli_runs_end_to_end_and_writes_sarif(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        (repo / "frontend").mkdir(parents=True)
        (repo / "frontend" / "a.js").write_text("fetch('https://api.datamuse.com/w');")
        output = tmp_path / "out" / "csp.sarif"
        code = main(
            [
                "--repo-root",
                str(repo),
                "--path",
                "frontend",
                "--environment",
                "production",
                "--policy-header",
                THEHUB_POLICY,
                "--output",
                str(output),
            ]
        )
        assert code == 0
        assert output.exists()
        assert "api.datamuse.com" in output.read_text()

    def test_an_empty_policy_never_reports_the_whole_tree_as_broken(self) -> None:
        """A policy that parsed to nothing restricts nothing. Reporting every
        origin as an omission is how a failed read becomes a wall of noise."""
        references = references_in("fetch('https://api.datamuse.com/w');", "a.js")
        result = compare(references, parse_policy("", environment="e", read_from="f"))
        assert result.omissions == ()
        assert result.unused == ()

    def test_a_wildcarded_directive_can_never_produce_a_finding(self) -> None:
        policy = parse_policy(
            "default-src 'self'; img-src 'self' https://named.test https:",
            environment="e",
            read_from="f",
        )
        references = references_in('<img src="https://anything.test/x.png">', "a.html")
        result = compare(references, policy)
        assert result.omissions == ()
        assert [u for u in result.unused if u.directive == "img-src"] == []
        assert [w.directive for w in result.wildcarded] == ["img-src"]

    def test_scanning_a_tree_with_no_external_origins_finds_nothing(self) -> None:
        assert references_in("fetch('/api/teller/status');", "a.js") == []
