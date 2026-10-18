"""[#322] Installed versions against declared constraints.

osv-scanner runs `--no-resolve`, so atlas assesses the version a requirement
declares. TheHub declared `redis>=8.1.0` while a transitive cap left 6.4.0
installed: atlas assessed 8.1.0, production ran 6.4.0, and nothing compared
the two. These tests pin the comparison, the lane-health fact it produces, the
`resolved` basis on findings from an SBOM scan, and the pipeline wiring that
puts both scans in one upload.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from mykronos import atlas_constraints
from mykronos.adapters import atlas_osv
from mykronos.adapters.base import ScanContext
from mykronos.atlas_constraints import (
    constraint_violations,
    installed_versions,
    npm_satisfies,
    pep440_satisfies,
)
from mykronos.upload import build_parser

PIPELINE = Path(__file__).resolve().parents[2] / "deploy" / "concourse" / "pipelines" / "thehub.yml"


def _component(name: str, version: str, purl_type: str = "pypi", **extra: object) -> dict:
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:{purl_type}/{name}@{version}",
        **extra,
    }


def _sbom(path: Path, *components: dict) -> Path:
    path.write_text(
        json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": list(components)}
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def thehub(tmp_path: Path) -> Path:
    """TheHub on 2026-09-12: the floor two majors above what runs."""
    workspace = tmp_path / "repo"
    (workspace / "backend").mkdir(parents=True)
    (workspace / "backend" / "requirements.txt").write_text(
        "# comment\nredis>=8.1.0\ncelery[redis]>=5.6.3  # Task queue\nnumpy>=1.24.0\n",
        encoding="utf-8",
    )
    return workspace


def _ctx(workspace: Path | None, *sboms: Path) -> ScanContext:
    return ScanContext(
        repo_full_name="ToddGBenson/TheHub",
        capability="atlas",
        tool_name="osv-scanner",
        tool_version="2.5.0",
        commit_sha="a" * 40,
        branch="main",
        workspace=workspace,
        sbom_paths=tuple(sboms),
    )


def _sarif(uri: str, package: str = "redis@6.4.0", rule_id: str = "GHSA-test-0000-0000") -> bytes:
    return json.dumps(
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "osv-scanner", "rules": [{"id": rule_id}]}},
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "warning",
                            "message": {
                                "text": f"Package '{package}' is vulnerable to '{rule_id}'."
                            },
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                        }
                    ],
                }
            ]
        }
    ).encode()


_EMPTY_SARIF = json.dumps(
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner"}}, "results": []}]}
).encode()


# ---------------------------------------------------------------------------
# The fact
# ---------------------------------------------------------------------------


class TestConstraintFact:
    def test_redis_below_its_floor_is_reported(self, thehub: Path, tmp_path: Path) -> None:
        sbom = _sbom(
            tmp_path / "latest-python.cdx.json",
            _component("redis", "6.4.0"),
            _component("celery", "5.6.3"),
            _component("numpy", "2.5.3"),
        )

        violations = constraint_violations(thehub, [sbom])

        assert [(v.name, v.installed, v.spec, v.file) for v in violations] == [
            ("redis", ("6.4.0",), ">=8.1.0", "backend/requirements.txt")
        ]

    def test_the_adapter_puts_the_fact_first_on_the_scan(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        sbom = _sbom(tmp_path / "latest-python.cdx.json", _component("redis", "6.4.0"))

        result = atlas_osv.normalize(_EMPTY_SARIF, _ctx(thehub, sbom))

        # Only warnings[0] reaches the ScanRun's `detail`, cut at 200 chars.
        assert result.warnings, "no lane-health fact for an installed version below its floor"
        head = result.warnings[0][:200]
        assert "redis 6.4.0" in head and ">=8.1.0" in head
        assert "#322" in result.warnings[0]
        # A fact, not a finding, and not a failed scan.
        assert result.findings == []
        assert result.scan_status.value == "success"

    def test_skipped_without_an_sbom(self, thehub: Path) -> None:
        result = atlas_osv.normalize(_EMPTY_SARIF, _ctx(thehub))
        assert result.warnings == []
        assert constraint_violations(thehub, []) == []

    def test_skipped_when_the_sbom_is_unreadable(self, thehub: Path, tmp_path: Path) -> None:
        missing = tmp_path / "gone.cdx.json"
        result = atlas_osv.normalize(_EMPTY_SARIF, _ctx(thehub, missing))
        assert result.warnings == []

    def test_a_floor_behind_what_runs_is_not_reported(self, thehub: Path, tmp_path: Path) -> None:
        # numpy >=1.24.0 with 2.5.3 installed: drift the safe way, normal and
        # healthy. Flagging it would bury the one that matters.
        sbom = _sbom(tmp_path / "s.cdx.json", _component("numpy", "2.5.3"))
        assert constraint_violations(thehub, [sbom]) == []

    def test_a_cap_exceeded_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\ndependencies = ["Redis_Py.Client<6.5"]\n', encoding="utf-8"
        )
        sbom = _sbom(tmp_path / "s.cdx.json", _component("redis-py-client", "7.0.0"))
        [violation] = constraint_violations(tmp_path, [sbom])
        assert violation.name == "redis-py-client" and violation.file == "pyproject.toml"

    def test_npm_constraint_violation(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {"dependencies": {"js-yaml": "^4.1.0"}, "devDependencies": {"next": "16.3.3"}}
            ),
            encoding="utf-8",
        )
        sbom = _sbom(
            tmp_path / "s.cdx.json",
            _component("js-yaml", "3.14.1", "npm"),
            _component("next", "16.3.3", "npm"),
        )
        assert [v.name for v in constraint_violations(tmp_path, [sbom])] == ["js-yaml"]

    def test_a_syft_transcribed_pin_is_not_evidence_of_installation(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        # Syft writes `==` pins from requirements.txt into the SBOM with the
        # file as their location. That is the declaration, not the install.
        transcribed = _component(
            "redis",
            "6.4.0",
            properties=[{"name": "syft:location:0:path", "value": "\\backend\\requirements.txt"}],
        )
        from_lock = _component(
            "numpy", "1.0.0", properties=[{"name": "syft:location:0:path", "value": "/uv.lock"}]
        )
        index = installed_versions({"components": [transcribed, from_lock]})
        assert ("pypi", "redis") not in index
        assert index[("pypi", "numpy")] == {"1.0.0"}

    def test_the_generated_sbom_is_preferred(self, thehub: Path, tmp_path: Path) -> None:
        generated = _sbom(tmp_path / "generated.cdx.json", _component("redis", "8.2.0"))
        committed = _sbom(tmp_path / "latest-python.cdx.json", _component("redis", "6.4.0"))
        assert constraint_violations(thehub, [generated, committed]) == []
        assert [v.sbom for v in constraint_violations(thehub, [committed, generated])] == [
            "latest-python.cdx.json"
        ]

    def test_dependencies_of_dependencies_are_not_walked(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        vendored = thehub / "node_modules" / "x"
        vendored.mkdir(parents=True)
        (vendored / "requirements.txt").write_text("redis>=99\n", encoding="utf-8")
        sbom = _sbom(tmp_path / "s.cdx.json", _component("redis", "8.1.0"))
        assert constraint_violations(thehub, [sbom]) == []


# ---------------------------------------------------------------------------
# Findings from the SBOM scan
# ---------------------------------------------------------------------------


class TestSbomFindingBasis:
    def test_a_finding_on_an_installed_version_is_resolved(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        sbom = _sbom(tmp_path / "latest-python.cdx.json", _component("redis", "6.4.0"))
        result = atlas_osv.normalize(_sarif("docs/sbom/latest-python.cdx.json"), _ctx(thehub, sbom))
        [finding] = result.findings
        assert (finding.package_name, finding.package_version) == ("redis", "6.4.0")
        assert finding.version_basis == "resolved"

    def test_without_the_sbom_the_basis_is_not_claimed(self, thehub: Path) -> None:
        # Reprocessing an archived scan: the SBOM is not on disk, and a wrong
        # `resolved` is the reading B-063 exists to prevent.
        [finding] = atlas_osv.normalize(
            _sarif("tmp/sbom/generated.cdx.json"), _ctx(thehub)
        ).findings
        assert finding.version_basis is None

    def test_a_transcribed_pin_in_the_sbom_is_not_resolved(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        sbom = _sbom(
            tmp_path / "generated.cdx.json",
            _component(
                "redis",
                "6.4.0",
                properties=[{"name": "syft:location:0:path", "value": "/backend/requirements.txt"}],
            ),
        )
        [finding] = atlas_osv.normalize(
            _sarif("tmp/sbom/generated.cdx.json"), _ctx(thehub, sbom)
        ).findings
        assert finding.version_basis is None

    def test_a_manifest_finding_is_still_marked_declared(
        self, thehub: Path, tmp_path: Path
    ) -> None:
        sbom = _sbom(tmp_path / "s.cdx.json", _component("redis", "6.4.0"))
        [finding] = atlas_osv.normalize(
            _sarif("backend/requirements.txt", package="redis@8.1.0"), _ctx(thehub, sbom)
        ).findings
        assert finding.version_basis == "declared_floor"

    def test_the_uploader_carries_every_sbom_in_order(self) -> None:
        args = build_parser().parse_args(
            [
                "--capability", "atlas", "--tool", "osv-scanner", "--results-path", "r",
                "--ingestion-url", "http://x", "--token", "t", "--repo", "o/r",
                "--commit-sha", "a" * 40, "--branch", "main",
                "--sbom", "/tmp/sbom/generated.cdx.json",
                "--sbom", "docs/sbom/latest-python.cdx.json",
            ]
        )  # fmt: skip
        assert args.sbom == ["/tmp/sbom/generated.cdx.json", "docs/sbom/latest-python.cdx.json"]
        assert build_parser().parse_args(
            ["--capability", "atlas", "--tool", "t", "--results-path", "r", "--ingestion-url", "u",
             "--token", "t", "--repo", "o/r", "--commit-sha", "a", "--branch", "b"]
        ).sbom == []  # fmt: skip


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("installed", "spec", "expected"),
    [
        ("6.4.0", ">=8.1.0", False),
        ("6.4.0", ">=6.4.0,<6.5", True),
        ("6.5.0", ">=6.4.0,<6.5", False),
        ("6.4", "==6.4.0", True),  # PEP 440 zero-padding
        ("2.0.0rc1", ">=2.0.0", False),  # a prerelease sorts before its release
        ("2.0.0rc1", ">=2.0.0rc1", True),
        ("2.0.post1", "==2.0", False),
        ("2.0+local.1", "==2.0", True),  # local labels ignored by ==
        ("1!0.5", ">=2.0", True),  # epoch outranks the release
        ("1.4.2", "~=1.4", True),
        ("2.0.0", "~=1.4", False),
        ("1.0", "!=1.0", False),
        ("not-a-version", ">=1", None),
        ("1.0", ">=>1", None),
    ],
)
def test_pep440(installed: str, spec: str, expected: bool | None) -> None:
    assert pep440_satisfies(installed, spec) is expected


@pytest.mark.parametrize(
    ("installed", "spec", "expected"),
    [
        ("4.1.0", "^4.0.0", True),
        ("5.0.0", "^4.0.0", False),
        ("3.14.1", "^4.1.0", False),
        ("0.2.9", "^0.2.3", True),
        ("0.3.0", "^0.2.3", False),
        ("0.0.3", "^0.0.3", True),
        ("0.0.4", "^0.0.3", False),
        ("0.9.0", "^0.x", True),
        ("1.0.0", "^0", False),
        ("1.2.9", "~1.2.3", True),
        ("1.3.0", "~1.2.3", False),
        ("1.9.0", "~1", True),
        ("1.2.7", "1.2.x", True),
        ("1.3.0", "1.2", False),
        ("7.0.0", "*", True),
        ("7.0.0", "", True),
        ("1.5.0", "1.2.3 - 2.3", True),
        ("2.3.9", "1.2.3 - 2.3", True),
        ("2.4.0", "1.2.3 - 2.3", False),
        ("2.3.5", "1.2.3 - 2.3.4", False),
        ("2.1.0", ">= 1.0.0 < 2.0.0 || >=2.1.0", True),
        ("1.9.9", ">=1.0.0 <2.0.0", True),
        ("2.0.0", ">=1.0.0 <2.0.0", False),
        ("1.2.0", ">1.1", True),
        ("1.1.9", ">1.1", False),
        ("1.1.9", "<=1.1", True),
        ("16.3.3", "16.3.3", True),
        ("16.3.2", "=16.3.3", False),
        ("v1.0.0", "1.0.0", True),
        ("1.0.0-beta.2", ">=1.0.0-beta.10", False),  # numeric identifiers compare numerically
        ("1.0.0-beta", "<1.0.0", True),
        ("1.0.0", ">1.0.0-rc.1", True),
        # Not ranges: unknowable, never reported.
        ("1.0.0", "latest", None),
        ("1.0.0", "git+https://github.com/x/y.git", None),
        ("1.0.0", "file:../local", None),
        ("1.0.0", "npm:other@^1", None),
        ("1.0.0", "workspace:*", None),
        ("not-semver", "^1.0.0", None),
    ],
)
def test_npm_semver(installed: str, spec: str, expected: bool | None) -> None:
    assert npm_satisfies(installed, spec) is expected


def test_purl_names_are_normalised_per_ecosystem() -> None:
    index = installed_versions(
        {
            "components": [
                {"name": "core", "version": "1.0.0", "purl": "pkg:npm/%40angular/core@1.0.0"},
                {"name": "PyJWT", "version": "2.13.0", "purl": "pkg:pypi/PyJWT@2.13.0"},
                {"name": "nopurl", "version": "1.0.0"},
            ]
        }
    )
    assert index == {("npm", "@angular/core"): {"1.0.0"}, ("pypi", "pyjwt"): {"2.13.0"}}
    assert atlas_constraints.normalise_name("pypi", "Zope.Interface__x") == "zope-interface-x"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _dependencies_scripts() -> dict[str, str]:
    pipeline = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    [job] = [j for j in pipeline["jobs"] if j["name"] == "dependencies"]
    return {
        step["task"]: step["config"]["run"]["args"][-1]
        for step in job["plan"]
        if "task" in step and "config" in step
    }


def test_the_sbom_scan_shares_the_declared_scans_upload() -> None:
    scripts = _dependencies_scripts()
    osv = scripts["osv-scanner"]
    # osv-scanner 2.5.0 takes an SBOM through -L and detects it by name.
    assert "osv-scanner scan source $OSV_SBOM_ARGS" in osv
    assert 'OSV_SBOM_ARGS="$OSV_SBOM_ARGS -L $f"' in osv
    assert "/tmp/results/osv-sbom.sarif" in osv
    # Generated SBOM preferred, committed environment SBOM second.
    assert osv.index("/tmp/sbom/generated.cdx.json") < osv.index("docs/sbom/latest-python.cdx.json")
    # Syft is checksummed where it now runs.
    assert "sha256sum -c -" in osv[osv.index("syft.tar.gz") :]
    # One upload, one tool tag: a second osv-scanner ScanRun per commit would
    # halve the reconcile guarantee (B-051).
    uploads = [s for s in scripts.values() if "python -m mykronos.upload" in s]
    assert len(uploads) == 1
    assert "--tool osv-scanner" in uploads[0] and "$UPLOAD_SBOM_ARGS" in uploads[0]
    # The SBOM scan comes before the upload that carries it.
    assert osv.index("osv-sbom.sarif") < osv.index("python -m mykronos.upload")


def test_the_evidence_task_still_refuses_a_missing_sbom() -> None:
    evidence = _dependencies_scripts()["sbom-and-evidence"]
    assert "syft scan" not in evidence
    assert 'if [ ! -s "sbom-out/sbom-${SHORT}.cdx.json" ]' in evidence
    assert "SBOM has no components" in evidence
