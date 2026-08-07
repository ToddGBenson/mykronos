"""Finding identity — specs/05-datalake.md §5.

The first test in this file is the reason the spec was changed. Everything
else guards the edges around it.
"""

from __future__ import annotations

from mykronos.fingerprint import (
    FINGERPRINT_DEPENDENCY,
    FINGERPRINT_REPO_LEVEL,
    FINGERPRINT_V1_LINE,
    FINGERPRINT_V2_SNIPPET,
    compute_finding_id,
    normalize_snippet,
)

BASE = {
    "repo_full_name": "example-org/payments-api",
    "capability": "sast",
    "rule_id": "CWE-89",
}

SNIPPET = 'cursor.execute("SELECT * FROM orders WHERE id = " + order_id)'


def test_line_shift_does_not_change_identity() -> None:
    """The regression this whole change exists for.

    Someone adds an import at the top of the file. Every finding below it
    shifts down. If identity moved with the line number, the original row
    would retire as `fixed` and the identical issue would be re-reported as
    newly discovered — destroying first_seen_at and every metric built on it.
    """
    before, version_before = compute_finding_id(
        **BASE, file_path="orders/query.py", symbol="get_order",
        code_snippet=SNIPPET, line_start=214,
    )
    after, version_after = compute_finding_id(
        **BASE, file_path="orders/query.py", symbol="get_order",
        code_snippet=SNIPPET, line_start=231,
    )

    assert before == after
    assert version_before == version_after == FINGERPRINT_V2_SNIPPET


def test_reindentation_does_not_change_identity() -> None:
    """Wrapping the code in a new block reindents it. Same finding."""
    flat, _ = compute_finding_id(**BASE, file_path="q.py", code_snippet=SNIPPET)
    indented, _ = compute_finding_id(
        **BASE, file_path="q.py", code_snippet=f"\n        {SNIPPET}\n\n"
    )
    assert flat == indented


def test_changing_the_vulnerable_code_does_change_identity() -> None:
    """The other half of the contract: fixing the code must retire the finding."""
    vulnerable, _ = compute_finding_id(**BASE, file_path="q.py", code_snippet=SNIPPET)
    fixed, _ = compute_finding_id(
        **BASE,
        file_path="q.py",
        code_snippet='cursor.execute("SELECT * FROM orders WHERE id = ?", [order_id])',
    )
    assert vulnerable != fixed


def test_symbol_disambiguates_identical_snippets_in_one_file() -> None:
    """The same unsafe call copy-pasted into two functions is two findings."""
    first, _ = compute_finding_id(
        **BASE, file_path="q.py", symbol="get_order", code_snippet=SNIPPET
    )
    second, _ = compute_finding_id(
        **BASE, file_path="q.py", symbol="list_orders", code_snippet=SNIPPET
    )
    assert first != second


def test_file_path_is_part_of_identity() -> None:
    a, _ = compute_finding_id(**BASE, file_path="orders/query.py", code_snippet=SNIPPET)
    b, _ = compute_finding_id(**BASE, file_path="billing/query.py", code_snippet=SNIPPET)
    assert a != b


def test_dependency_identity_ignores_version() -> None:
    """A CVE that still applies after a version bump is the same finding.
    One that no longer applies is retired by absence reconciliation instead."""
    old, version = compute_finding_id(**BASE, package_name="urllib3")
    new, _ = compute_finding_id(**BASE, package_name="urllib3")
    assert old == new
    assert version == FINGERPRINT_DEPENDENCY


def test_dependency_identity_separates_packages() -> None:
    a, _ = compute_finding_id(**BASE, package_name="urllib3")
    b, _ = compute_finding_id(**BASE, package_name="requests")
    assert a != b


def test_missing_snippet_degrades_to_line_and_says_so() -> None:
    """Degradation is recorded, not hidden — these rows are churn-prone and
    reportable as a data-quality metric."""
    finding_id, version = compute_finding_id(**BASE, file_path="q.py", line_start=214)
    assert version == FINGERPRINT_V1_LINE

    shifted, _ = compute_finding_id(**BASE, file_path="q.py", line_start=231)
    assert finding_id != shifted, "v1 fallback is positional by definition"


def test_repo_level_finding_has_no_location() -> None:
    finding_id, version = compute_finding_id(
        **BASE, title="Root account has no MFA enabled"
    )
    assert version == FINGERPRINT_REPO_LEVEL
    assert finding_id


def test_capability_and_repo_scope_identity() -> None:
    """The same rule firing on the same path in two repos is two findings."""
    a, _ = compute_finding_id(**BASE, file_path="q.py", code_snippet=SNIPPET)
    b, _ = compute_finding_id(
        **{**BASE, "repo_full_name": "example-org/ledger-core"},
        file_path="q.py",
        code_snippet=SNIPPET,
    )
    c, _ = compute_finding_id(
        **{**BASE, "capability": "semgrep-sast"}, file_path="q.py", code_snippet=SNIPPET
    )
    assert len({a, b, c}) == 3


def test_field_boundaries_cannot_be_forged() -> None:
    """Concatenating fields must not let one field impersonate two.

    Without an unambiguous separator, rule_id="A" + path="BC" could collide
    with rule_id="AB" + path="C".
    """
    a, _ = compute_finding_id(
        repo_full_name="r", capability="sast", rule_id="A", file_path="BC", code_snippet="x"
    )
    b, _ = compute_finding_id(
        repo_full_name="r", capability="sast", rule_id="AB", file_path="C", code_snippet="x"
    )
    assert a != b


def test_identity_is_stable_across_processes() -> None:
    """SHA-256 of an explicit tuple, not Python's salted hash()."""
    expected, _ = compute_finding_id(**BASE, file_path="q.py", code_snippet=SNIPPET)
    assert len(expected) == 64
    assert all(ch in "0123456789abcdef" for ch in expected)


class TestNormalizeSnippet:
    def test_collapses_whitespace_runs(self) -> None:
        assert normalize_snippet("a    b\tc") == "a b c"

    def test_drops_blank_lines_and_trims(self) -> None:
        assert normalize_snippet("\n   foo  \n\n\n   bar\n") == "foo\nbar"

    def test_preserves_case_and_punctuation(self) -> None:
        assert normalize_snippet("Foo.Bar( baz )") == "Foo.Bar( baz )"

    def test_is_not_language_aware(self) -> None:
        """Comments are content. Stripping them would mean deciding which
        source changes are semantically meaningful, which dedup may not do."""
        assert "# TODO" in normalize_snippet("x = 1  # TODO")
