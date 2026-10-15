"""A failed stage whose log is coloured still reports as a failed stage.

`next build` writes ANSI colour codes, and ESC (0x1b) is not a legal XML 1.0
character. ElementTree escapes `<` and `&` but writes ESC through, so the
frontend lane's failing build on 2026-10-15 (Concourse frontend 390) produced
a report the junit adapter could not parse: "not well-formed (invalid token):
line 1, column 273". That uploads as a *broken scan* (partial_failure) rather
than a failed build -- the distinction junit_stage exists to keep.
"""

from __future__ import annotations

from pathlib import Path

from mykronos.adapters.base import ScanContext
from mykronos.adapters.tests_junit import normalize
from mykronos.junit_stage import main
from mykronos.schemas import ScanStatus

# Verbatim shape of the next build failure, plus the other C0 controls a
# tool might emit (NUL, form feed, vertical tab, backspace).
COLOURED_LOG = (
    "\x1b[31mError while looking up import map: next/font/google queries have exactly "
    "one entry\x1b[39m\n\x1b[1mImport trace:\x1b[22m\n  ./app/layout.tsx\n"
    "a\x00b\x0cc\x0bd\x08e <tag> & done\n"
)


def _context() -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability="qa",
        tool_name="junit",
        tool_version="",
        commit_sha="0" * 40,
        branch="main",
    )


def _write_report(tmp_path: Path) -> bytes:
    log = tmp_path / "build.txt"
    log.write_text(COLOURED_LOG, encoding="utf-8")
    out = tmp_path / "frontend.xml"
    main(["--out", str(out), "--suite", "frontend", "--case", "lint:0", "--case", f"build:1:{log}"])
    return out.read_bytes()


def test_a_coloured_failure_log_is_a_parseable_failed_suite(tmp_path: Path) -> None:
    result = normalize(_write_report(tmp_path), _context())

    assert result.scan_status is ScanStatus.FAILURE, result.warnings
    assert any("1 of 2 test(s) failed" in w for w in result.warnings), result.warnings


def test_the_log_text_survives_without_its_control_characters(tmp_path: Path) -> None:
    body = _write_report(tmp_path).decode("utf-8")

    assert "next/font/google queries have exactly one entry" in body
    assert "./app/layout.tsx" in body
    assert "&lt;tag&gt; &amp; done" in body
    for ch in ("\x1b", "\x00", "\x0c", "\x0b", "\x08"):
        assert ch not in body, repr(ch)
    # The colour codes go entirely, not just their ESC byte.
    assert "[31m" not in body
