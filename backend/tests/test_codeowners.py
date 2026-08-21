"""CODEOWNERS parsing and resolution (spec 24 §1)."""

from __future__ import annotations

from mykronos.codeowners import parse, resolve


class TestParse:
    def test_drops_comments_and_blanks(self) -> None:
        rules = parse("# owners\n\n*.py @team\n")
        assert [r.pattern for r in rules] == ["*.py"]

    def test_drops_a_line_with_no_owner(self) -> None:
        # GitHub reads this as "explicitly nobody", which is indistinguishable
        # from unresolved here.
        assert parse("docs/\n") == []

    def test_keeps_file_order(self) -> None:
        rules = parse("* @default\nbackend/ @backend\n")
        assert [r.pattern for r in rules] == ["*", "backend/"]

    def test_accepts_handles_teams_and_emails(self) -> None:
        rules = parse("* @user @org/team dev@example.com\n")
        assert rules[0].owners == ("@user", "@org/team", "dev@example.com")

    def test_rejects_junk_on_the_line(self) -> None:
        rules = parse("* @user notanowner\n")
        assert rules[0].owners == ("@user",)

    def test_records_the_line_number(self) -> None:
        rules = parse("# header\n\n* @user\n")
        assert rules[0].line == 3


class TestResolve:
    def test_last_match_wins(self) -> None:
        rules = parse("* @default\nbackend/ @backend\n")
        assert resolve("backend/api.py", rules) == ("@backend", "codeowners")

    def test_earlier_rule_applies_when_later_does_not_match(self) -> None:
        rules = parse("* @default\nbackend/ @backend\n")
        assert resolve("frontend/page.tsx", rules) == ("@default", "codeowners")

    def test_no_rules_is_unresolved(self) -> None:
        assert resolve("a.py", []) == (None, "unresolved")

    def test_no_path_is_unresolved(self) -> None:
        # A dependency finding has no file. Spec 24 §1.2 sends it down the
        # manifest/profile path instead; this function does not guess.
        assert resolve(None, parse("* @team\n")) == (None, "unresolved")

    def test_no_matching_pattern_is_unresolved(self) -> None:
        assert resolve("a.py", parse("docs/ @docs\n")) == (None, "unresolved")

    def test_only_the_first_owner_is_stored(self) -> None:
        assert resolve("a.py", parse("* @first @second\n")) == ("@first", "codeowners")


class TestPatterns:
    def test_star_does_not_cross_a_separator(self) -> None:
        rules = parse("*.py @py\n")
        assert resolve("a.py", rules)[0] == "@py"
        # Bare `*.py` matches by basename at any depth, which is gitignore's
        # rule and GitHub's.
        assert resolve("deep/nested/a.py", rules)[0] == "@py"

    def test_anchored_pattern_does_not_match_deeper(self) -> None:
        rules = parse("/backend/*.py @be\n")
        assert resolve("backend/a.py", rules)[0] == "@be"
        assert resolve("other/backend/a.py", rules)[0] is None

    def test_directory_pattern_matches_everything_under_it(self) -> None:
        rules = parse("backend/ @be\n")
        assert resolve("backend/deep/nested/a.py", rules)[0] == "@be"
        assert resolve("backendish/a.py", rules)[0] is None

    def test_directory_pattern_does_not_match_the_bare_name(self) -> None:
        # `backend/` names a directory's contents; a file called `backend`
        # is not in it.
        assert resolve("backend", parse("backend/ @be\n"))[0] is None

    def test_double_star_crosses_separators(self) -> None:
        rules = parse("docs/**/*.md @docs\n")
        assert resolve("docs/a.md", rules)[0] == "@docs"
        assert resolve("docs/deep/nested/a.md", rules)[0] == "@docs"

    def test_question_mark_matches_one_character(self) -> None:
        assert resolve("a1.py", parse("a?.py @x\n"))[0] == "@x"
        assert resolve("a12.py", parse("a?.py @x\n"))[0] is None

    def test_catch_all_matches_anything(self) -> None:
        rules = parse("* @all\n")
        assert resolve("any/depth/of/path.tsx", rules)[0] == "@all"

    def test_leading_slash_on_the_path_is_tolerated(self) -> None:
        assert resolve("/backend/a.py", parse("backend/ @be\n"))[0] == "@be"

    def test_dots_are_literal(self) -> None:
        # A regex translation that forgot to escape would match `axpy`.
        assert resolve("axpy", parse("*.py @py\n"))[0] is None
