"""Install and resync never move a pinned action backwards (#376).

Measured on keel: Dependabot bumped CodeQL in the rendered workflow, the next
install pull request put the template's older pin back, and 48 installer tests
passed over it because none of them looked at a pin. These do.
"""

from __future__ import annotations

import re

import pytest

from mykronos.installer.pins import parse_version, reconcile_pins

INIT = "github/codeql-action/init"
OLD_SHA = "1" * 40
NEW_SHA = "2" * 40


def _template_pin(content: str, action: str = INIT) -> tuple[str, str]:
    """(sha, version label) the rendered template pins `action` to."""
    match = re.search(
        rf"uses: {re.escape(action)}@([0-9a-f]{{40}})\s+#\s*(\S+)", content
    )
    assert match, f"template does not pin {action}"
    return match.group(1), match.group(2)


def _bump(version: str, delta: int) -> str:
    major, minor, patch = parse_version(version)  # type: ignore[misc]
    return f"v{major}.{minor}.{patch + delta}" if patch + delta >= 0 else f"v{major}.{minor - 1}.99"


def _repin(content: str, action: str, sha: str, label: str) -> str:
    """What Dependabot does to a rendered file: one pin moved, nothing else."""
    return re.sub(
        rf"(uses: {re.escape(action)}@)[0-9a-f]{{40}}(\s+#\s*)\S+",
        rf"\g<1>{sha}\g<2>{label}",
        content,
    )


class TestReconcile:
    RENDERED = (
        "steps:\n"
        "  - uses: actions/checkout@" + OLD_SHA + "  # v4.4.0\n"
        "  - uses: ToddGBenson/mykronos/actions/upload-results@v1\n"
    )

    def test_target_newer_keeps_the_target_pin_and_reports(self) -> None:
        current = self.RENDERED.replace(OLD_SHA + "  # v4.4.0", NEW_SHA + "  # v4.5.1")

        content, decisions = reconcile_pins("wf.yml", self.RENDERED, current)

        assert NEW_SHA + "  # v4.5.1" in content
        assert OLD_SHA not in content
        assert [(d.outcome, d.target_version, d.template_version) for d in decisions] == [
            ("kept_target", "v4.5.1", "v4.4.0")
        ]

    def test_template_newer_is_applied(self) -> None:
        current = self.RENDERED.replace(OLD_SHA + "  # v4.4.0", NEW_SHA + "  # v4.3.0")

        content, decisions = reconcile_pins("wf.yml", self.RENDERED, current)

        assert content == self.RENDERED
        assert [d.outcome for d in decisions] == ["upgraded"]

    @pytest.mark.parametrize(
        "label",
        ["", "# v4.5.0-rc.1", "# latest", "# main"],
    )
    def test_an_unreadable_target_version_is_not_guessed(self, label: str) -> None:
        current = self.RENDERED.replace(OLD_SHA + "  # v4.4.0", f"{NEW_SHA}  {label}".rstrip())

        content, decisions = reconcile_pins("wf.yml", self.RENDERED, current)

        assert f"actions/checkout@{NEW_SHA}" in content
        assert [d.outcome for d in decisions] == ["kept_target"]
        assert "not guessing" in decisions[0].reason

    def test_the_installers_own_upload_ref_is_never_held_back(self) -> None:
        """Its `with:` block is derived from the same string; keeping an old
        `uses:` would split the action from the package it installs."""
        current = self.RENDERED.replace("upload-results@v1", "upload-results@v9")

        content, decisions = reconcile_pins("wf.yml", self.RENDERED, current)

        assert content == self.RENDERED
        assert decisions == []

    def test_a_new_file_or_new_step_is_left_as_rendered(self) -> None:
        assert reconcile_pins("wf.yml", self.RENDERED, None) == (self.RENDERED, [])
        assert reconcile_pins("wf.yml", self.RENDERED, "steps: []\n") == (self.RENDERED, [])

    def test_crlf_in_the_target_still_compares(self) -> None:
        current = self.RENDERED.replace(OLD_SHA + "  # v4.4.0", NEW_SHA + "  # v4.5.1")

        content, _ = reconcile_pins("wf.yml", self.RENDERED, current.replace("\n", "\r\n"))

        assert NEW_SHA + "  # v4.5.1\n" in content
