"""An atlas finding says what it was read out of, and how old that is
(TheHub #60921).

Observed 2026-10-29: TheHub's open critical PYSEC-2026-4320 was located at
`docs/sbom/latest-python.cdx.json`, a committed CycloneDX document dated
2026-10-21 that listed certifi 2026.10.18. `backend/requirements.txt` had
changed at least twice since and pinned `certifi>=2026.10.19`. The finding was
right only by coincidence, and nothing on it said whether it described the
manifest, a stale document, or what runs.

The SARIF below is osv-scanner 2.5.0's shape for an SBOM scanned with `-L`,
copied from an archived lane run with the build directory renamed: an
absolute `file://` URI under the runner's checkout, the alias group as the
rule, and the fix under the GHSA alias.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mykronos import atlas_source, weekly_briefing
from mykronos.adapters import atlas_osv
from mykronos.adapters.base import ScanContext
from mykronos.agent_work import _finding_caveats
from tests.conftest import REPO, finding_payload, post_findings, post_scan

SBOM = "docs/sbom/latest-python.cdx.json"
BUILD = "/tmp/build/0a1b2c3d/source"
SCANNED = datetime(2026, 10, 30, 4, 44, tzinfo=UTC)

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

HELP = """**Your dependency is vulnerable to [PYSEC-2026-4320](https://osv.dev/PYSEC-2026-4320)**.

---

### Affected Packages

| Source | Package Name | Package Version |
| --- | --- | --- |
| sbom:{build}/docs/sbom/latest-python.cdx.json | certifi | 2026.10.18 |

## Remediation

To fix these vulnerabilities, update the vulnerabilities past the listed fixed versions below.

### Fixed Versions

| Vulnerability ID | Package Name | Fixed Version |
| --- | --- | --- |
| GHSA-0000-1111-2222 | certifi | 2026.10.19 |

If you believe these vulnerabilities do not affect your code and wish to ignore them, add
them to the ignore list in an `osv-scanner.toml` file.
"""


def _sarif(uri: str) -> bytes:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "osv-scanner",
                            "version": "2.5.0",
                            "rules": [
                                {
                                    "id": "PYSEC-2026-4320",
                                    "name": "PYSEC-2026-4320",
                                    "deprecatedIds": ["PYSEC-2026-4320", "GHSA-0000-1111-2222"],
                                    "shortDescription": {
                                        "text": "PYSEC-2026-4320: certifi: removed root"
                                    },
                                    "help": {"markdown": HELP.format(build=BUILD)},
                                    "properties": {"security-severity": "9.1"},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "PYSEC-2026-4320",
                            "ruleIndex": 0,
                            "kind": "fail",
                            "level": "error",
                            "message": {
                                "text": "Package 'certifi@2026.10.18' is vulnerable to "
                                "'PYSEC-2026-4320' (also known as 'GHSA-0000-1111-2222')."
                            },
                            "locations": [
                                {
                                    "id": -1,
                                    "physicalLocation": {
                                        "artifactLocation": {"index": -1, "uri": uri}
                                    },
                                }
                            ],
                            "partialFingerprints": {"primaryLocationLineHash": "c5d5e3"},
                        }
                    ],
                }
            ],
        }
    ).encode()


def _cyclonedx(timestamp: str | None = "2026-10-21T13:22:00+00:00") -> str:
    document: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "certifi",
                "version": "2026.10.18",
                "purl": "pkg:pypi/certifi@2026.10.18",
            }
        ],
    }
    if timestamp:
        document["metadata"] = {"timestamp": timestamp}
    return json.dumps(document)


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str, when: str) -> str:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    env = {**os.environ, "GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
    _git(
        repo,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-qm",
        message,
        env=env,
    )
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "-q")
    return repo


def _context(workspace: Path | None) -> ScanContext:
    return ScanContext(
        repo_full_name=REPO,
        capability="atlas",
        tool_name="osv-scanner",
        tool_version="2.5.0",
        commit_sha="0" * 40,
        branch="develop",
        workspace=workspace,
    )


def _normalize(workspace: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(atlas_source, "_now", lambda: SCANNED)
    uri = "file://" + str(workspace).replace("\\", "/") + "/" + SBOM
    if not uri.startswith("file:///"):
        uri = uri.replace("file://", "file:///", 1)
    outcome = atlas_osv.normalize(_sarif(uri), _context(workspace))
    assert len(outcome.findings) == 1
    return outcome.findings[0]


# -- The adapter -------------------------------------------------------------


@needs_git
class TestAFindingFromACommittedSbomSaysSo:
    def test_the_document_is_dated_and_the_manifest_change_is_named(
        self, checkout: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The TheHub case: document of 10-21, requirements changed after it."""
        _commit(
            checkout,
            {SBOM: _cyclonedx(), "backend/requirements.txt": "certifi>=2026.10.18\n"},
            "sbom",
            "2026-10-21T13:30:00+00:00",
        )
        later = _commit(
            checkout,
            {"backend/requirements.txt": "certifi>=2026.10.19\n"},
            "pin certifi",
            "2026-10-27T20:20:00+00:00",
        )

        finding = _normalize(checkout, monkeypatch)

        raw = finding.raw_finding_json
        assert finding.file_path == SBOM
        assert raw["source_kind"] == "sbom_document"
        document = raw["source_document"]
        assert document["format"] == "cyclonedx"
        assert document["created_at"].startswith("2026-10-21T13:22")
        assert document["age_days"] == 8
        assert document["manifests_changed_after"] is True
        assert document["manifests_changed"] == [
            {
                "file": "backend/requirements.txt",
                "commit": later,
                "committed_at": "2026-10-27T20:20:00+00:00",
            }
        ]
        # Nothing about severity moves.
        assert finding.severity.value in ("critical", "high")
        assert raw["fixed_version"] == "2026.10.19"

        note = atlas_source.note_for(raw)
        assert note == (
            "From a committed SBOM document dated 2026-10-21 (8 days before this "
            "scan; backend/requirements.txt has changed since), not from this "
            "commit's manifest. Check what runs before acting on it."
        )

    def test_an_unchanged_manifest_is_said_to_be_unchanged(
        self, checkout: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _commit(
            checkout,
            {"backend/requirements.txt": "certifi>=2026.10.18\n"},
            "deps",
            "2026-10-20T10:00:00+00:00",
        )
        _commit(checkout, {SBOM: _cyclonedx()}, "sbom", "2026-10-21T13:30:00+00:00")
        # A manifest of another ecosystem changing says nothing about this one.
        _commit(
            checkout,
            {"frontend/package.json": '{"dependencies": {}}\n'},
            "frontend",
            "2026-10-25T10:00:00+00:00",
        )

        document = _normalize(checkout, monkeypatch).raw_finding_json["source_document"]

        assert document["manifests_changed_after"] is False
        assert "no manifest has changed since" in atlas_source.note_for(
            {"source_kind": "sbom_document", "source_document": document}
        )

    def test_an_undated_document_is_called_undated(
        self, checkout: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _commit(checkout, {SBOM: _cyclonedx(None)}, "sbom", "2026-10-21T13:30:00+00:00")

        raw = _normalize(checkout, monkeypatch).raw_finding_json

        assert raw["source_document"]["created_at"] is None
        assert raw["source_document"]["age_days"] is None
        assert "with no recorded date" in str(atlas_source.note_for(raw))


def test_a_manifest_finding_is_a_manifest_and_carries_no_document() -> None:
    outcome = atlas_osv.normalize(_sarif("backend/requirements.txt"), _context(None))

    raw = outcome.findings[0].raw_finding_json
    assert raw["source_kind"] == "manifest"
    assert "source_document" not in raw
    assert atlas_source.note_for(raw) is None


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("frontend/package-lock.json", "manifest"),
        ("requirements-dev.txt", "manifest"),
        ("go.mod", "manifest"),
        ("docs/sbom/app.spdx.json", "sbom_document"),
        ("bom.json", "sbom_document"),
        ("vendor/thing.tar", "other"),
        (None, "other"),
    ],
)
def test_source_kind_is_read_from_the_file_name(path: str | None, kind: str) -> None:
    assert atlas_source.source_kind(path) == kind


def test_spdx_dates_itself_in_creation_info() -> None:
    fmt, created, ecosystems = atlas_source.describe_document(
        {
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"created": "2026-10-01T00:00:00Z"},
            "packages": [
                {
                    "name": "left-pad",
                    "externalRefs": [{"referenceLocator": "pkg:npm/left-pad@1.3.0"}],
                }
            ],
        }
    )
    assert fmt == "spdx"
    assert created == datetime(2026, 10, 1, tzinfo=UTC)
    assert ecosystems == {"npm"}


# -- The surfaces ------------------------------------------------------------

RAW = {
    "source_kind": "sbom_document",
    "fixed_version": "2026.10.19",
    "source_document": {
        "path": SBOM,
        "created_at": "2026-10-21T13:22:00+00:00",
        "age_days": 9,
        "manifests_changed_after": True,
        "manifests_changed": [{"file": "backend/requirements.txt"}],
    },
}


def _row(raw: dict) -> dict:
    return {
        "finding_id": "f1",
        "capability": "atlas",
        "rule_id": "PYSEC-2026-4320",
        "title": "certifi",
        "severity": "critical",
        "package_name": "certifi",
        "package_version": "2026.10.18",
        # What the lane records today: the committed document is also the SBOM
        # it is "resolved" against.
        "version_basis": "resolved",
        "file_path": SBOM,
        "raw_finding_json": json.dumps(raw),
        "shipped": True,
    }


def test_the_weekly_briefing_line_says_where_the_version_came_from() -> None:
    section = weekly_briefing._advisories(  # noqa: SLF001
        weekly_briefing.Inputs(
            repo_full_name=REPO, repo_id="r", findings=[_row(RAW)], intel={}
        ),
        since=datetime(2026, 10, 26),
        now=datetime(2026, 10, 30),
    )
    item = section.items[0]
    assert "From a committed SBOM document dated 2026-10-21 (9 days before this scan" in (
        item.so_what
    )
    assert "Check what runs" in item.so_what
    # A document resolved against itself is not an observation of what runs.
    assert item.confidence == "inferred"
    assert item.severity == "critical"


def test_a_manifest_finding_keeps_its_briefing_line() -> None:
    raw = {"source_kind": "manifest", "fixed_version": "2026.10.19"}
    row = {**_row(raw), "file_path": "uv.lock"}
    section = weekly_briefing._advisories(  # noqa: SLF001
        weekly_briefing.Inputs(repo_full_name=REPO, repo_id="r", findings=[row], intel={}),
        since=datetime(2026, 10, 26),
        now=datetime(2026, 10, 30),
    )
    assert "SBOM" not in section.items[0].so_what
    assert section.items[0].confidence == "observed"


def test_the_agent_work_queue_carries_the_note_as_a_caveat() -> None:
    note = atlas_source.note_for(RAW)
    caveats = _finding_caveats(
        {"capability": "atlas", "source_note": note}, lane_frozen=False
    )
    assert [c.code for c in caveats] == ["sbom_document"]
    assert caveats[0].detail == note


def test_the_finding_detail_says_it_to_every_reader(
    client, auth, admin_auth, viewer_auth, catalog, run_compaction
) -> None:
    """Including a viewer, who is never sent the raw record (spec 12 §5)."""
    post_scan(client, auth)
    post_findings(
        client,
        auth,
        [
            finding_payload(
                file_path=SBOM,
                package_name="certifi",
                package_version="2026.10.18",
                raw_finding_json=RAW,
            )
        ],
    )
    run_compaction()
    finding_id = str(catalog.query("SELECT finding_id FROM findings")[0][0])

    for headers in (admin_auth, viewer_auth):
        body = client.get(f"/api/dashboard/findings/{finding_id}", headers=headers).json()
        assert body["source_kind"] == "sbom_document"
        assert body["source_note"] == atlas_source.note_for(RAW)
        assert body["severity"] == "critical"
    viewed = client.get(f"/api/dashboard/findings/{finding_id}", headers=viewer_auth).json()
    assert viewed["raw_finding_json"] is None
