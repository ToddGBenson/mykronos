"""A second analyser is a second lane, not a second capability (B-051).

The adapters and templates for ShellCheck and PSScriptAnalyzer shipped before
anything could install them: the installer requires a template per capability,
and `sast-shell` is a template with no capability of that name. So the lanes
existed and were unreachable — the "capability ahead of its wiring" failure
this platform keeps filing against other people's repositories, arriving in
its own installer.

They are chosen in the capability's own config now:

    {"sast": {"extra_analysers": ["shellcheck"]}}

The installer half of this lives in `test_installer.py`, beside the fixtures
that render against the real shipped template library.
"""

from __future__ import annotations

import pytest

from mykronos.adapters.registry import get_adapter
from mykronos.capabilities import CapabilityConfigError, validate_config
from mykronos.installer.extra_lanes import EXTRA_LANES, lanes_for


class TestChoosingALane:
    def test_a_tool_resolves_to_its_template(self) -> None:
        assert lanes_for("sast", {"extra_analysers": ["shellcheck"]}) == ["sast-shell"]

    def test_both_analysers_at_once(self) -> None:
        lanes = lanes_for("sast", {"extra_analysers": ["shellcheck", "psscriptanalyzer"]})

        assert lanes == ["sast-powershell", "sast-shell"]

    def test_the_capability_is_part_of_the_key(self) -> None:
        """Without it, `extra_analysers` on any capability would install a
        `sast` workflow — an `iac` config could hand a repository a ShellCheck
        lane uploading a capability its own config never mentioned."""
        assert lanes_for("iac", {"extra_analysers": ["shellcheck"]}) == []

    def test_no_config_asks_for_nothing(self) -> None:
        assert lanes_for("sast", {}) == []
        assert lanes_for("sast", None) == []

    def test_a_config_of_the_wrong_shape_asks_for_nothing(self) -> None:
        """`plan()` is called with configs straight out of the database, which
        holds whatever an older schema wrote. Raising here would take the
        install down; installing nothing extra is the safe reading."""
        assert lanes_for("sast", {"extra_analysers": "shellcheck"}) == []

    def test_the_order_is_stable(self) -> None:
        """A re-render of an unchanged configuration must produce
        byte-identical files, or a re-save shows as churn on somebody's open
        pull request."""
        first = lanes_for("sast", {"extra_analysers": ["shellcheck", "psscriptanalyzer"]})
        second = lanes_for("sast", {"extra_analysers": ["psscriptanalyzer", "shellcheck"]})

        assert first == second


class TestValidation:
    def test_a_tool_with_a_lane_is_accepted(self) -> None:
        saved = validate_config("sast", {"extra_analysers": ["shellcheck"]})

        assert saved["extra_analysers"] == ["shellcheck"]

    def test_duplicates_collapse(self) -> None:
        saved = validate_config("sast", {"extra_analysers": ["shellcheck", "shellcheck"]})

        assert saved["extra_analysers"] == ["shellcheck"]

    def test_a_tool_with_no_lane_is_refused(self) -> None:
        """Semgrep has an adapter and no extra-lane template. Accepting it
        would save a configuration that installs nothing and never runs —
        which is the shape of failure this platform exists to report."""
        with pytest.raises(CapabilityConfigError) as caught:
            validate_config("sast", {"extra_analysers": ["semgrep"]})

        assert "no workflow lane for semgrep" in str(caught.value)

    def test_the_refusal_says_what_is_available(self) -> None:
        """A person reading "semgrep is not allowed" learns nothing about what
        is. The two tools that do work are a short enough list to just say."""
        with pytest.raises(CapabilityConfigError) as caught:
            validate_config("sast", {"extra_analysers": ["semgrep"]})

        assert "shellcheck" in str(caught.value)


class TestTheRegistryHangsTogether:
    @pytest.mark.parametrize("tool", sorted(EXTRA_LANES))
    def test_every_registered_tool_has_an_adapter(self, tool: str) -> None:
        """A lane whose output nothing can read uploads into a 422, and the
        repository sees a green workflow reporting nothing."""
        capability, _ = EXTRA_LANES[tool]

        assert get_adapter(capability, tool) is not None

    @pytest.mark.parametrize("tool", sorted(EXTRA_LANES))
    def test_every_registered_tool_has_a_template(self, tool: str) -> None:
        """The defect this whole change exists to fix, asserted so it cannot
        come back: a lane in the table that the installer cannot render."""
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        _, template = EXTRA_LANES[tool]
        library = TemplateLibrary(get_settings().workflow_templates_dir)

        assert template in library.available
