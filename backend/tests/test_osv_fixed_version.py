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

from mykronos.adapters import atlas_osv
from mykronos.adapters.base import ScanContext
from mykronos.guidance import _containers
from mykronos.supply_chain import _fixed_version

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
