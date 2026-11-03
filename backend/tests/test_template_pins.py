"""The workflow templates are refreshed from the pins the estate already runs
(TheHub #60876, the first half of #376).

#897 stopped an install pull request from moving a pin backwards: the target's
newer pin is kept and named in the pull request body. That fixed the symptom
and left the cause. Nothing moves the *templates* forward -- Dependabot does
not parse `.j2` -- so every install still renders a stale pin and relies on
the reconcile step to throw it away. On 2026-11-03 the `sast` template pinned
CodeQL v3.37.9 while keel and binnacle both ran v3.39.0, which Dependabot had
moved them to.

`mykronos.installer.template_pins` is the refresh: given workflow files whose
pins someone keeps current (this repository's own, which Dependabot watches,
or an onboarded repository's), it moves each template pin forward to the
newest same-major release those files carry, and never backwards.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mykronos.installer.pins import parse_version
from mykronos.installer.template_pins import (
    collect_source_pins,
    refresh_template,
    refresh_templates,
)

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "workflow-templates"
SCRIPT = ROOT / "scripts" / "refresh_template_pins.py"

OLD = "1" * 40
NEW = "2" * 40
OTHER = "3" * 40

TEMPLATE = (
    "steps:\n"
    f"  - uses: actions/checkout@{OLD}  # v4.4.0\n"
    f"  - uses: github/codeql-action/init@{OLD}  # v3.37.9\n"
    f"  - uses: github/codeql-action/analyze@{OLD}  # v3.37.9\n"
    "  - uses: << upload_action_ref >>\n"
)


def _source(*lines: str) -> dict[str, str]:
    body = "".join(f"  - uses: {line}\n" for line in lines)
    return {".github/workflows/ci.yml": "steps:\n" + body}


class TestRefresh:
    def test_a_newer_same_major_pin_moves_the_template_forward(self) -> None:
        best, _ = collect_source_pins(_source(f"actions/checkout@{NEW} # v4.5.1"))

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        # The template's own two-space comment layout is kept.
        assert f"actions/checkout@{NEW}  # v4.5.1\n" in content
        assert f"actions/checkout@{OLD}" not in content
        assert [(c.action, c.old_version, c.new_version) for c in changes] == [
            ("actions/checkout", "v4.4.0", "v4.5.1")
        ]
        assert changes[0].source == ".github/workflows/ci.yml"

    def test_an_older_pin_never_moves_the_template_back(self) -> None:
        best, _ = collect_source_pins(_source(f"actions/checkout@{NEW} # v4.3.0"))

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert content == TEMPLATE
        assert changes == []

    def test_a_new_major_is_reported_not_applied(self) -> None:
        """A major can change runner requirements (#376 item 3); that is a
        tested change, not a pin refresh."""
        best, _ = collect_source_pins(_source(f"actions/checkout@{NEW} # v7.0.1"))

        content, changes, skips = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert content == TEMPLATE
        assert changes == []
        assert [(s.action, s.source_version) for s in skips] == [("actions/checkout", "v7.0.1")]
        assert "major" in skips[0].reason

    def test_allow_major_applies_it(self) -> None:
        best, _ = collect_source_pins(_source(f"actions/checkout@{NEW} # v7.0.1"))

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best, allow_major=True)

        assert f"actions/checkout@{NEW}  # v7.0.1" in content
        assert len(changes) == 1

    def test_sub_actions_of_one_repository_move_together(self) -> None:
        """init and analyze are one release of one repository. A source that
        only uses init must still move analyze, or the template would run two
        CodeQL versions in one job."""
        best, _ = collect_source_pins(_source(f"github/codeql-action/init@{NEW} # v3.39.0"))

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert f"github/codeql-action/init@{NEW}  # v3.39.0" in content
        assert f"github/codeql-action/analyze@{NEW}  # v3.39.0" in content
        assert {c.action for c in changes} == {
            "github/codeql-action/init",
            "github/codeql-action/analyze",
        }

    def test_the_newest_release_across_sources_wins(self) -> None:
        best, _ = collect_source_pins(
            {
                "a/ci.yml": f"- uses: actions/checkout@{OTHER} # v4.4.2\n",
                "b/ci.yml": f"- uses: actions/checkout@{NEW} # v4.5.1\n",
            }
        )

        content, _, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert f"actions/checkout@{NEW}  # v4.5.1" in content

    def test_a_new_major_elsewhere_does_not_hide_a_same_major_bump(self) -> None:
        """This repository runs checkout v7 while the onboarded repositories
        run v4. Comparing only the newest release per repository would see
        v7, refuse it as a major, and never apply the v4 patch beside it."""
        best, _ = collect_source_pins(
            {
                "mykronos/ci.yml": f"- uses: actions/checkout@{OTHER} # v7.0.1\n",
                "keel/ci.yml": f"- uses: actions/checkout@{NEW} # v4.5.1\n",
            }
        )

        content, changes, skips = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert f"actions/checkout@{NEW}  # v4.5.1" in content
        assert [c.new_version for c in changes] == ["v4.5.1"]
        assert [s.source_version for s in skips] == ["v7.0.1"]

    def test_two_shas_for_one_release_is_not_guessed(self) -> None:
        """A moved tag looks exactly like this. Picking either SHA would be
        guessing which one is the compromise."""
        best, conflicts = collect_source_pins(
            {
                "a/ci.yml": f"- uses: actions/checkout@{NEW} # v4.5.1\n",
                "b/ci.yml": f"- uses: actions/checkout@{OTHER} # v4.5.1\n",
            }
        )

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert content == TEMPLATE
        assert changes == []
        assert len(conflicts) == 1 and "actions/checkout" in conflicts[0]

    def test_same_release_with_a_different_sha_is_reported_not_applied(self) -> None:
        best, _ = collect_source_pins(_source(f"actions/checkout@{NEW} # v4.4.0"))

        content, changes, skips = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert content == TEMPLATE
        assert changes == []
        assert [s.action for s in skips] == ["actions/checkout"]

    @pytest.mark.parametrize(
        "line",
        [
            f"actions/checkout@{NEW}",
            f"actions/checkout@{NEW} # v4.9.0-rc.1",
            "actions/checkout@v4.9.0",
            f"actions/checkout@{NEW} # main",
        ],
    )
    def test_a_source_pin_without_a_sha_and_a_release_is_ignored(self, line: str) -> None:
        best, _ = collect_source_pins(_source(line))

        content, changes, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert content == TEMPLATE
        assert changes == []

    def test_crlf_sources_are_read(self) -> None:
        source = _source(f"actions/checkout@{NEW} # v4.5.1")
        best, _ = collect_source_pins({k: v.replace("\n", "\r\n") for k, v in source.items()})

        content, _, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert f"actions/checkout@{NEW}  # v4.5.1\n" in content

    def test_the_installers_upload_ref_is_never_touched(self) -> None:
        best, _ = collect_source_pins(
            _source(f"ToddGBenson/mykronos/actions/upload-results@{NEW} # v9.0.0")
        )

        content, _, _ = refresh_template("sast.yml.j2", TEMPLATE, best)

        assert "uses: << upload_action_ref >>" in content


def _pins(path: Path) -> dict[str, tuple[str, tuple[int, int, int] | None]]:
    out = {}
    for match in re.finditer(
        r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([0-9a-f]{40})\s+#\s*(\S+)",
        path.read_text(encoding="utf-8"),
    ):
        out[match.group(1)] = (match.group(2), parse_version(match.group(3)))
    return out


class TestTheShippedTemplates:
    def test_no_template_is_behind_this_repositorys_own_pins(self) -> None:
        """Dependabot keeps `.github/workflows/` and `actions/` current. When
        it moves a pin the templates share at the same major, this fails
        until `python scripts/refresh_template_pins.py` is run on that
        branch -- the same shape as the lock-file check (#270)."""
        sources = {
            str(p.relative_to(ROOT)): p.read_text(encoding="utf-8")
            for base in (ROOT / ".github" / "workflows", ROOT / "actions")
            for p in sorted(base.rglob("*.y*ml"))
        }
        templates = {
            p.name: p.read_text(encoding="utf-8") for p in sorted(TEMPLATES.glob("*.j2"))
        }

        refreshed, changes, _, _ = refresh_templates(templates, sources)

        assert changes == [], "\n".join(c.describe() for c in changes)
        assert refreshed == templates

    def test_codeql_is_at_least_what_the_estate_runs(self) -> None:
        """Measured 2026-11-03: keel and binnacle run codeql-action v3.39.0
        (`ce5e7eea...`, the commit the annotated tag v3.39.0 points at).
        A template below that is the downgrade #376 is about."""
        pins = _pins(TEMPLATES / "sast.yml.j2")
        for action in ("init", "autobuild", "analyze"):
            sha, version = pins[f"github/codeql-action/{action}"]
            assert version is not None and version >= (3, 39, 0), (action, version)
            assert version[0] == 3, "v4 is a tested change, not a pin refresh (#376)"


@pytest.fixture(scope="module")
def script():
    spec = importlib.util.spec_from_file_location("refresh_template_pins", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules["refresh_template_pins"] = module
    spec.loader.exec_module(module)
    return module


class TestTheScript:
    def _tree(self, tmp_path: Path, source_version: str) -> tuple[Path, Path]:
        templates = tmp_path / "templates"
        templates.mkdir()
        (templates / "sast.yml.j2").write_text(TEMPLATE, encoding="utf-8")
        source = tmp_path / "estate" / ".github" / "workflows"
        source.mkdir(parents=True)
        (source / "ci.yml").write_text(
            f"steps:\n  - uses: github/codeql-action/init@{NEW} # {source_version}\n",
            encoding="utf-8",
        )
        return templates, tmp_path / "estate"

    def test_check_reports_drift_and_writes_nothing(self, script, tmp_path: Path, capsys) -> None:
        templates, estate = self._tree(tmp_path, "v3.39.0")

        code = script.main(["--templates", str(templates), "--source", str(estate), "--check"])

        assert code == 1
        assert (templates / "sast.yml.j2").read_text(encoding="utf-8") == TEMPLATE
        assert "v3.37.9 -> v3.39.0" in capsys.readouterr().out

    def test_refresh_writes_then_check_is_clean(self, script, tmp_path: Path) -> None:
        templates, estate = self._tree(tmp_path, "v3.39.0")

        assert script.main(["--templates", str(templates), "--source", str(estate)]) == 0
        written = (templates / "sast.yml.j2").read_bytes()
        assert f"github/codeql-action/analyze@{NEW}  # v3.39.0".encode() in written
        assert b"\r\n" not in written
        assert script.main(["--templates", str(templates), "--source", str(estate), "--check"]) == 0

    def test_a_missing_source_is_an_error_not_a_clean_pass(self, script, tmp_path: Path) -> None:
        """A typo'd path would otherwise read as 'nothing to refresh'."""
        templates, _ = self._tree(tmp_path, "v3.39.0")

        code = script.main(
            ["--templates", str(templates), "--source", str(tmp_path / "nope"), "--check"]
        )

        assert code == 2

    def test_it_runs_as_a_program(self, tmp_path: Path) -> None:
        templates, estate = self._tree(tmp_path, "v3.37.9")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--templates", str(templates)]
            + ["--source", str(estate), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
