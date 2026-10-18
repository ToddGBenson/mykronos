"""Advisory CVSS vectors, and which vector a finding is scored from (TheHub #60824).

D1 of the environmental-rescoring epic: CVSS 3.1 is primary, v4.0 is stored and
shown but never rescored -- this platform implements v3's environmental formula
and not v4's, and feeding a v4 vector to a v3 formula would produce a number in
the right range and the wrong units.

Where each tool puts its vectors was read off real output, not assumed. The
fixtures are unedited except where noted:

- Trivy 0.73.0 (`trivy/debian10.sarif`) and 0.76.0
  (`trivy/trivy-0.76.0-requirements.sarif`) write `cvssv2_vector`,
  `cvssv3_vector` and, from 0.76, `cvssv40_vector` as *rule* properties, with
  a `_baseScore` (`_score` for v2) beside each.
- grype 0.87.0 and 0.120.1 SARIF carry `security-severity` and no vector.
- osv-scanner 2.2.3 SARIF (trimmed to two rules) carries `security-severity`
  and no vector.

So grype's and osv-scanner's SARIF findings get no `cvss_vectors` key at all:
absent says "the tool published none", which is the truth.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mykronos import cvss_vectors
from mykronos.adapters import atlas_grype, atlas_osv, containers_trivy
from mykronos.adapters.base import ScanContext
from mykronos.fingerprint import compute_finding_id, identity_rule_of, image_of

DATA = Path(__file__).parent / "data"
TRIVY_073 = DATA / "trivy" / "debian10.sarif"
TRIVY_076 = DATA / "trivy" / "trivy-0.76.0-requirements.sarif"
GRYPE_087 = DATA / "grype-0.87.0-requirements.sarif"
GRYPE_0120 = DATA / "grype-0.120.1-requirements.sarif"
OSV_223 = DATA / "osv-scanner-2.2.3-requirements.sarif"

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"


def _ctx(capability: str, tool: str, version: str) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/mykronos",
        capability=capability,
        tool_name=tool,
        tool_version=version,
        commit_sha="a" * 40,
        branch="main",
    )


class TestVersionOf:
    @pytest.mark.parametrize(
        ("vector", "version"),
        [(V31, "3.1"), (V30, "3.0"), (V40, "4.0"), (V2, "2.0")],
    )
    def test_reads_the_version_from_the_vector_itself(self, vector, version) -> None:
        """From the string, not the property name it arrived under: a tool
        that files a 3.0 vector under `cvssv3_vector` is still a 3.0 vector."""
        assert cvss_vectors.version_of(vector) == version

    @pytest.mark.parametrize("vector", ["", "CVSS:9.9/AV:N", "garbage", "CVSS:3.1"])
    def test_anything_else_has_no_version(self, vector) -> None:
        assert cvss_vectors.version_of(vector) is None


class TestWhereEachToolPutsItsVectors:
    def test_trivy_073_writes_v3_and_v2_as_rule_properties(self) -> None:
        table = cvss_vectors.sarif_rule_vectors(TRIVY_073.read_bytes(), source="trivy")

        assert table["CVE-2019-8457"] == [
            {"version": "3.1", "vector": V31, "source": "trivy", "base_score": 9.8},
            {"version": "2.0", "vector": V2, "source": "trivy", "base_score": 7.5},
        ]
        assert table["CVE-2023-45853"] == [
            {"version": "3.1", "vector": V31, "source": "trivy", "base_score": 9.8},
        ]

    def test_trivy_076_adds_v40(self) -> None:
        table = cvss_vectors.sarif_rule_vectors(TRIVY_076.read_bytes(), source="trivy")

        versions = [entry["version"] for entry in table["CVE-2020-14343"]]
        assert versions == ["4.0", "3.1"]
        v4 = table["CVE-2020-14343"][0]
        assert v4["vector"] == V40
        assert v4["base_score"] == 9.3

    @pytest.mark.parametrize("fixture", [GRYPE_087, GRYPE_0120, OSV_223])
    def test_grype_and_osv_scanner_sarif_carry_no_vector(self, fixture) -> None:
        """Checked against real output so the empty answer is a finding about
        the tools, not a gap in the parser."""
        assert b"CVSS:" not in fixture.read_bytes()
        assert cvss_vectors.sarif_rule_vectors(fixture.read_bytes(), source="x") == {}

    def test_unreadable_output_is_an_empty_table(self) -> None:
        assert cvss_vectors.sarif_rule_vectors(b"not json", source="trivy") == {}
        assert cvss_vectors.sarif_rule_vectors(b"[]", source="trivy") == {}

    def test_a_vector_with_no_recognisable_version_is_dropped(self) -> None:
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "CVE-1",
                                    "properties": {
                                        "cvssv3_vector": "nonsense",
                                        "cvssv40_vector": 7,
                                    },
                                }
                            ]
                        }
                    }
                }
            ]
        }
        assert cvss_vectors.sarif_rule_vectors(json.dumps(sarif).encode(), source="t") == {}


class TestTheAdaptersKeepThem:
    def test_trivy_findings_carry_their_rules_vectors(self) -> None:
        outcome = containers_trivy.normalize(
            TRIVY_076.read_bytes(), _ctx("containers", "trivy", "0.76.0")
        )

        by_rule = {f.rule_id: f for f in outcome.findings}
        vectors = by_rule["CVE-2020-14343"].raw_finding_json["cvss_vectors"]
        assert {"version": "3.1", "vector": V31, "source": "trivy", "base_score": 9.8} in vectors
        assert any(entry["version"] == "4.0" for entry in vectors)

    def test_every_trivy_073_finding_with_a_vector_keeps_it(self) -> None:
        outcome = containers_trivy.normalize(
            TRIVY_073.read_bytes(), _ctx("containers", "trivy", "0.73.0")
        )

        assert outcome.findings
        for finding in outcome.findings:
            assert finding.raw_finding_json["cvss_vectors"][0]["vector"] == V31

    @pytest.mark.parametrize(
        ("adapter", "fixture", "capability", "tool"),
        [
            (atlas_grype, GRYPE_087, "atlas", "grype"),
            (atlas_grype, GRYPE_0120, "atlas", "grype"),
            (atlas_osv, OSV_223, "atlas", "osv-scanner"),
        ],
    )
    def test_no_vector_in_the_output_means_no_key(
        self, adapter, fixture, capability, tool
    ) -> None:
        outcome = adapter.normalize(fixture.read_bytes(), _ctx(capability, tool, "x"))

        assert outcome.findings
        assert all("cvss_vectors" not in f.raw_finding_json for f in outcome.findings)

    def test_finding_identity_does_not_change(self) -> None:
        """`raw_finding_json` feeds identity through `image` and the identity
        marker only. Pinned here so a vector list can never re-key a finding."""
        context = _ctx("containers", "trivy", "0.73.0")
        sarif = json.loads(TRIVY_073.read_text(encoding="utf-8"))
        with_vectors = containers_trivy.normalize(json.dumps(sarif).encode(), context)
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            rule["properties"] = {
                k: v for k, v in rule["properties"].items() if "cvss" not in k
            }
        without = containers_trivy.normalize(json.dumps(sarif).encode(), context)

        def ids(outcome) -> list[tuple[str, str]]:
            return [
                compute_finding_id(
                    repo_full_name=context.repo_full_name,
                    capability=context.capability,
                    rule_id=f.rule_id,
                    file_path=f.file_path,
                    symbol=f.symbol,
                    code_snippet=f.code_snippet,
                    line_start=f.line_start,
                    package_name=f.package_name,
                    title=f.title,
                    image=image_of(f.raw_finding_json),
                    identity_rule=identity_rule_of(f.raw_finding_json),
                )
                for f in outcome.findings
            ]

        assert all("cvss_vectors" in f.raw_finding_json for f in with_vectors.findings)
        assert all("cvss_vectors" not in f.raw_finding_json for f in without.findings)
        assert ids(with_vectors) == ids(without)


class TestChooseVector:
    """NVD 3.1/3.0 > advisory 3.1/3.0 > v4.0 (shown, not rescored)."""

    def test_nvd_v3_wins_over_everything(self) -> None:
        choice = cvss_vectors.choose_vector(
            nvd_v3=V30,
            nvd_v4=V40,
            advisory=[{"version": "3.1", "vector": V31, "source": "trivy"}],
        )

        assert choice == cvss_vectors.VectorChoice(
            vector=V30, version="3.0", source="nvd", rescored=True
        )

    def test_advisory_v31_when_nvd_has_no_v3(self) -> None:
        choice = cvss_vectors.choose_vector(
            nvd_v3=None,
            nvd_v4=V40,
            advisory=[
                {"version": "3.0", "vector": V30, "source": "trivy"},
                {"version": "3.1", "vector": V31, "source": "trivy"},
            ],
        )

        assert choice is not None
        assert (choice.vector, choice.version, choice.source, choice.rescored) == (
            V31,
            "3.1",
            "advisory",
            True,
        )

    def test_advisory_v30_when_that_is_all_the_advisory_has(self) -> None:
        choice = cvss_vectors.choose_vector(
            nvd_v3=None, advisory=[{"version": "3.0", "vector": V30, "source": "trivy"}]
        )

        assert choice is not None and choice.version == "3.0" and choice.rescored

    def test_v4_only_is_shown_and_not_rescored(self) -> None:
        choice = cvss_vectors.choose_vector(nvd_v3=None, nvd_v4=V40, nvd_v4_base_score=9.3)

        assert choice == cvss_vectors.VectorChoice(
            vector=V40, version="4.0", source="nvd", rescored=False, base_score=9.3
        )

    def test_nvd_v4_is_preferred_over_an_advisory_v4(self) -> None:
        other = V40.replace("VA:H", "VA:N")
        choice = cvss_vectors.choose_vector(
            nvd_v3=None,
            nvd_v4=V40,
            advisory=[{"version": "4.0", "vector": other, "source": "trivy"}],
        )

        assert choice is not None and choice.vector == V40 and choice.source == "nvd"

    def test_an_advisory_v4_with_its_published_score(self) -> None:
        choice = cvss_vectors.choose_vector(
            nvd_v3=None,
            advisory=[{"version": "4.0", "vector": V40, "source": "trivy", "base_score": 9.3}],
        )

        assert choice == cvss_vectors.VectorChoice(
            vector=V40, version="4.0", source="advisory", rescored=False, base_score=9.3
        )

    def test_v2_is_never_chosen(self) -> None:
        assert (
            cvss_vectors.choose_vector(
                nvd_v3=None, advisory=[{"version": "2.0", "vector": V2, "source": "trivy"}]
            )
            is None
        )

    def test_nothing_is_none(self) -> None:
        assert cvss_vectors.choose_vector(nvd_v3=None) is None

    def test_an_unparseable_v3_falls_through_rather_than_failing(self) -> None:
        """A malformed advisory 3.1 must not hide a usable one behind it, and
        must not hide a v4 to show either."""
        broken = "CVSS:3.1/AV:N/AC:L"
        choice = cvss_vectors.choose_vector(
            nvd_v3=broken,
            nvd_v4=V40,
            advisory=[
                {"version": "3.1", "vector": broken, "source": "trivy"},
                {"version": "3.0", "vector": V30, "source": "trivy"},
            ],
        )

        assert choice is not None and choice.vector == V30 and choice.source == "advisory"

    def test_the_version_is_read_from_the_vector_not_the_label(self) -> None:
        """An entry labelled 3.1 holding a v4 vector is a v4 vector."""
        choice = cvss_vectors.choose_vector(
            nvd_v3=None, advisory=[{"version": "3.1", "vector": V40, "source": "trivy"}]
        )

        assert choice is not None and choice.version == "4.0" and not choice.rescored

    @pytest.mark.parametrize("junk", [None, "x", 3, {"vector": 3}, {"no": "vector"}])
    def test_junk_advisory_entries_are_ignored(self, junk) -> None:
        assert cvss_vectors.choose_vector(nvd_v3=None, advisory=[junk]) is None  # type: ignore[list-item]
