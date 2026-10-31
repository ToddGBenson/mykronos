r"""[#256] Every atlas finding was reported as having no published fix.

`guidance` and `supply_chain` both derived the patched version with
`re.compile(r"Fixed Version:\s*(\S+)")` -- Trivy's message format. osv-scanner
never writes that string; its result message is only

    Package 'js-yaml@4.3.0' is vulnerable to 'GHSA-5p4m-2wfm-xmqj'.

so the match failed and every dependency finding was classed unactionable. On
2026-09-11 the briefing printed "auto-remediation can pin these" and "4 of these
have no published fix" in the same block, and all four had patches -- including
`next` 16.3.0, a critical unauthenticated RCE fixed in 16.3.3.

The remediation was in the SARIF the whole time, in the *rule* rather than the
result, as a markdown table. These tests pin the parse, the version choice, and
the two consumers preferring the resolved value.
"""

from __future__ import annotations

import json
from pathlib import Path

from mykronos.adapters import atlas_osv
from mykronos.adapters.base import ScanContext
from mykronos.guidance import _containers, _for
from mykronos.supply_chain import _fixed_version

OSV_223 = Path(__file__).parent / "data" / "osv-scanner-2.2.3-requirements.sarif"

HELP = """## Remediation

To fix these vulnerabilities, update the vulnerabilities past the listed fixed
versions below.

### Fixed Versions

| Vulnerability ID | Package Name | Fixed Version |
| --- | --- | --- |
| GHSA-5p4m-2wfm-xmqj | js-yaml | 3.15.1, 4.3.1 |

If you believe these vulnerabilities do not affect your code ...
"""


def _sarif(rule_id: str = "GHSA-5p4m-2wfm-xmqj", package: str = "js-yaml@4.3.0") -> bytes:
    return json.dumps(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "osv-scanner",
                            "rules": [{"id": rule_id, "help": {"markdown": HELP}}],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "warning",
                            "message": {
                                "text": f"Package '{package}' is vulnerable to '{rule_id}'."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "package-lock.json"}
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    ).encode()


def _ctx() -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability="atlas",
        tool_name="osv-scanner",
        tool_version="1",
        commit_sha="abc",
        branch="main",
    )


def test_the_fixed_version_is_read_out_of_the_rule_not_the_message():
    table = atlas_osv._fixed_versions(_sarif())
    assert table == {("GHSA-5p4m-2wfm-xmqj", "js-yaml"): "3.15.1, 4.3.1"}


def test_the_fix_chosen_matches_the_installed_release_line():
    """osv-scanner names one fix per affected major. Handing a 3.x consumer
    4.3.1 is a major upgrade wearing a patch's clothes."""
    assert atlas_osv._pick_fix("4.3.0", "3.15.1, 4.3.1") == "4.3.1"
    assert atlas_osv._pick_fix("3.14.0", "3.15.1, 4.3.1") == "3.15.1"
    # the finding that prompted this issue
    assert atlas_osv._pick_fix("16.3.0", "15.5.24, 16.3.3") == "16.3.3"


def test_an_unknown_installed_version_takes_the_smallest_candidate():
    assert atlas_osv._pick_fix(None, "3.15.1, 4.3.1") == "3.15.1"
    assert atlas_osv._pick_fix("", "3.15.1, 4.3.1") == "3.15.1"


def test_normalize_attaches_the_fix_to_the_finding():
    out = atlas_osv.normalize(_sarif(), _ctx())
    assert len(out.findings) == 1
    assert out.findings[0].raw_finding_json["fixed_version"] == "4.3.1"


def test_a_scanner_with_no_remediation_table_attaches_nothing():
    """Absence has to stay distinguishable from "not looked up"."""
    doc = json.loads(_sarif())
    doc["runs"][0]["tool"]["driver"]["rules"][0]["help"] = {"markdown": "no table here"}
    out = atlas_osv.normalize(json.dumps(doc).encode(), _ctx())
    assert "fixed_version" not in (out.findings[0].raw_finding_json or {})


def test_supply_chain_prefers_the_resolved_field_over_the_trivy_regex():
    raw = json.dumps(
        {"message": {"text": "Package 'js-yaml@4.3.0' is vulnerable to 'X'."},
         "fixed_version": "4.3.1"}
    )
    assert _fixed_version(raw) == "4.3.1"


def test_supply_chain_still_reads_trivy_when_no_field_is_present():
    raw = json.dumps({"message": {"text": "Fixed Version: 1.2.3\nLink: http://x"}})
    assert _fixed_version(raw) == "1.2.3"


def test_guidance_advises_the_upgrade_instead_of_calling_it_unfixable():
    raw = {
        "message": {"text": "Package 'js-yaml@4.3.0' is vulnerable to 'X'."},
        "fixed_version": "4.3.1",
    }
    advice, source, kind = _containers(raw)
    assert kind == "upgrade"
    assert "4.3.1" in advice


# --------------------------------------------------------------------------
# TheHub #60909: the table names the alias, the finding names the rule
# --------------------------------------------------------------------------
#
# osv-scanner 2.x names the rule (and so the finding's `rule_id`) after the
# CVE or PYSEC id of an alias group, and writes the fix under the GHSA alias.
# Keyed on the row id alone, the lookup missed, `fixed_version` stayed unset,
# and the briefing said "no published fix -- nothing to upgrade to" for
# pypdf and certifi findings Dependabot was already offering upgrades for.

_REMEDIATION = (
    "## Remediation\n\nIf you believe these vulnerabilities do not affect your "
    "code and wish to ignore them, add them to the ignore list.\n"
)


def _help_for(row_id: str, package: str, fixed: str) -> str:
    return (
        "## Remediation\n\nTo fix these vulnerabilities, update the "
        "vulnerabilities past the listed fixed versions below.\n\n"
        "### Fixed Versions\n\n"
        "| Vulnerability ID | Package Name | Fixed Version |\n"
        "| --- | --- | --- |\n"
        f"| {row_id} | {package} | {fixed} |\n\n"
        "If you believe these vulnerabilities do not affect your code ...\n"
    )


def _scan(*rules: tuple[str, list[str], str, str]) -> bytes:
    """Rules as (rule id, deprecatedIds, package@version, help markdown)."""
    return json.dumps(
        {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "osv-scanner",
                            "rules": [
                                {
                                    "id": rid,
                                    "deprecatedIds": aliases,
                                    "help": {"markdown": markdown},
                                }
                                for rid, aliases, _, markdown in rules
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": rid,
                            "level": "warning",
                            "message": {
                                "text": f"Package '{spec}' is vulnerable to '{rid}'."
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "docs/sbom/latest-python.cdx.json"
                                        }
                                    }
                                }
                            ],
                        }
                        for rid, aliases, spec, _ in rules
                    ],
                }
            ]
        }
    ).encode()


def _fixes(raw_output: bytes) -> dict[str, object]:
    out = atlas_osv.normalize(raw_output, _ctx())
    return {
        f.rule_id: (f.raw_finding_json or {}).get("fixed_version", "<unset>")
        for f in out.findings
    }


def test_a_fix_published_under_the_alias_reaches_the_finding():
    """The shape of TheHub's open pypdf finding, from the archived SARIF."""
    raw = _scan(
        (
            "CVE-2026-115572",
            ["CVE-2026-115572", "GHSA-6c7f-9265-g8fw"],
            "pypdf@6.21.1",
            _help_for("GHSA-6c7f-9265-g8fw", "pypdf", "6.21.2"),
        )
    )
    assert _fixes(raw) == {"CVE-2026-115572": "6.21.2"}


def test_a_pysec_rule_finds_its_ghsa_fix_without_deprecated_ids():
    """certifi's PYSEC-2026-4320: the rule's own table answers for it even
    where the SARIF carries no alias list."""
    raw = _scan(
        (
            "PYSEC-2026-4320",
            [],
            "certifi@2026.10.18",
            _help_for("GHSA-6q48-6c7w-9gw2", "certifi", "2026.10.19"),
        )
    )
    assert _fixes(raw) == {"PYSEC-2026-4320": "2026.10.19"}


def test_every_rule_in_a_scan_is_read_not_only_the_first():
    """The table loop stopped at the blank line under each heading once any
    earlier rule had produced a row, so the second rule onward read nothing."""
    raw = _scan(
        ("GHSA-aaaa-aaaa-aaaa", [], "a@1.0.0", _help_for("GHSA-aaaa-aaaa-aaaa", "a", "1.0.1")),
        ("GHSA-bbbb-bbbb-bbbb", [], "b@2.0.0", _help_for("GHSA-bbbb-bbbb-bbbb", "b", "2.0.5")),
    )
    assert _fixes(raw) == {"GHSA-aaaa-aaaa-aaaa": "1.0.1", "GHSA-bbbb-bbbb-bbbb": "2.0.5"}


def test_a_remediation_with_no_fixed_versions_is_recorded_as_none_published():
    """osv-scanner omits the table when OSV records no fix. That is a known
    absence, and the empty value is how the record says so."""
    raw = _scan(("CVE-2026-93687", ["GHSA-vfj7-8cjw-p6xm"], "braces@3.0.3", _REMEDIATION))
    assert _fixes(raw) == {"CVE-2026-93687": ""}


def test_the_archived_osv_scanner_fixture_resolves_every_fix():
    """Real osv-scanner 2.2.3 output: both rules are CVE-named with the fix
    under PYSEC and GHSA rows. Before #60909 neither finding got one."""
    fixes = _fixes(OSV_223.read_bytes())
    assert fixes == {"CVE-2025-66471": "2.6.0", "CVE-2026-21441": "2.6.3"}


def test_aliases_naming_different_fixes_take_the_one_that_satisfies_both():
    assert atlas_osv._pick_fix("2.5.0", "2.6.0, 2.6.1") == "2.6.1"
    assert atlas_osv._pick_fix("2.5.0", "2.6.10, 2.6.9") == "2.6.10"


class TestUnknownIsNotNone:
    """The briefing's "N of these have no published fix" counts effort
    `no_fix`. Only an established absence may land there."""

    MESSAGE = {"text": "Package 'pypdf@6.21.1' is vulnerable to 'CVE-2026-115572'."}

    def test_an_atlas_record_with_no_fix_on_record_is_not_called_unfixable(self):
        fix, _, effort = _for("atlas", {"message": self.MESSAGE}, "x")
        assert effort != "no_fix"
        assert "not known to be unfixable" in fix
        assert "pypdf" in fix

    def test_an_atlas_record_osv_says_has_no_fix_is_unfixable(self):
        fix, _, effort = _for("atlas", {"message": self.MESSAGE, "fixed_version": ""}, "x")
        assert effort == "no_fix"
        assert "No fixed version published for pypdf" in fix

    def test_an_atlas_record_with_a_fix_says_upgrade_and_names_the_package(self):
        fix, _, effort = _for(
            "atlas", {"message": self.MESSAGE, "fixed_version": "6.21.2"}, "x"
        )
        assert effort == "upgrade"
        assert fix.startswith("Upgrade pypdf to 6.21.2")

    def test_a_container_record_keeps_its_meaning_of_absence(self):
        """Trivy writes `Fixed Version` whenever one exists, so for containers
        a missing one is still the answer."""
        _, _, effort = _for("containers", {"message": {"text": "Package: zlib"}}, "x")
        assert effort == "no_fix"
