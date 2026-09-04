"""Several named quality checks in one `qa` lane — spec 32 §5.1.

`qa` is the one test lane that is routinely several *different* commands.
`mykronos.yml` runs four jobs — `lint-and-types`, `frontend`, `qa-spec-links`,
`api-inventory` — all reporting as `qa`, which `ci.py` calls "a richer answer
rather than a collision": quality stages carry no findings, so several runs
per commit cannot overwrite one another.

The failure these guard is the one the migration would otherwise cause
silently. Chaining four checks into one `command` with `&&` renders a green
workflow that runs all four — right up until the first one fails, after which
the other three never execute and the lake records one run where there were
four. Nothing errors; coverage just quietly narrows.

The second failure is narrower and worse: a configured command lands in YAML,
so one containing a colon or a quote can end the scalar early and change the
document's shape rather than its content.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mykronos.capabilities import CapabilityConfigError, validate_config
from mykronos.installer.templates import TemplateLibrary

TEMPLATES = Path(__file__).resolve().parents[2] / "workflow-templates"

RENDER = dict(
    repo_full_name="ToddGBenson/mykronos",
    default_branch="main",
    ingestion_api_url="https://mykronos.example",
    token_secret_name="MYKRONOS_INGESTION_TOKEN",
    upload_action_ref="ToddGBenson/mykronos/actions/upload-results@v2",
)

CHECKS = [
    {
        "name": "lint-and-types",
        "command": "python -m ruff check . && python -m mypy mykronos",
        "setup": ["cd backend", "pip install -e '.[dev]'"],
    },
    {"name": "frontend", "command": "npx tsc --noEmit"},
    {"name": "spec-links", "command": "python scripts/check_spec_links.py"},
]


@pytest.fixture
def library() -> TemplateLibrary:
    return TemplateLibrary(TEMPLATES)


def _job(library: TemplateLibrary, config: dict) -> dict:
    rendered = library.render("qa", config=config, **RENDER)
    return dict(yaml.safe_load(rendered.content)["jobs"]["qa"])


class TestConfig:
    def test_checks_are_accepted(self) -> None:
        out = validate_config("qa", {"checks": CHECKS})
        assert [c["name"] for c in out["checks"]] == [
            "lint-and-types",
            "frontend",
            "spec-links",
        ]

    def test_a_duplicate_name_is_refused(self) -> None:
        """Two legs with one name render two jobs GitHub cannot tell apart,
        and two runs a person reading the Harness tab cannot either."""
        with pytest.raises(CapabilityConfigError):
            validate_config(
                "qa",
                {"checks": [{"name": "lint", "command": "a"}, {"name": "lint", "command": "b"}]},
            )

    def test_a_newline_in_a_command_is_refused(self) -> None:
        """The same guard `TestLaneConfig.command` has, for the same reason: a
        newline in a value rendered into YAML is a new line and potentially a
        new step."""
        with pytest.raises(CapabilityConfigError):
            validate_config("qa", {"checks": [{"name": "lint", "command": "a\nrm -rf /"}]})

    def test_an_empty_command_is_refused(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("qa", {"checks": [{"name": "lint", "command": ""}]})

    def test_a_name_that_is_not_a_job_title_is_refused(self) -> None:
        with pytest.raises(CapabilityConfigError):
            validate_config("qa", {"checks": [{"name": "Lint & Types", "command": "a"}]})


class TestRendering:
    def test_one_matrix_leg_per_check(self, library: TemplateLibrary) -> None:
        job = _job(library, {"checks": CHECKS})

        legs = job["strategy"]["matrix"]["check"]
        assert [leg["name"] for leg in legs] == ["lint-and-types", "frontend", "spec-links"]

    def test_a_failing_check_does_not_cancel_the_others(
        self, library: TemplateLibrary
    ) -> None:
        """The property that chaining with `&&` would lose."""
        job = _job(library, {"checks": CHECKS})

        assert job["strategy"]["fail-fast"] is False

    def test_setup_is_joined_at_render_time(self, library: TemplateLibrary) -> None:
        job = _job(library, {"checks": CHECKS})

        leg = job["strategy"]["matrix"]["check"][0]
        assert leg["setup"] == "cd backend\npip install -e '.[dev]'"
        assert job["strategy"]["matrix"]["check"][1]["setup"] == ""

    def test_a_command_with_yaml_metacharacters_survives(
        self, library: TemplateLibrary
    ) -> None:
        """A colon and a quote in a command must stay data.

        Without `tojson` this ends the YAML scalar early: the document still
        parses, into a different shape, and the workflow runs something other
        than what was configured.
        """
        hostile = 'npx tsc --noEmit: "quoted: colon" # trailing'
        job = _job(library, {"checks": [{"name": "frontend", "command": hostile}]})

        assert job["strategy"]["matrix"]["check"][0]["command"] == hostile

    def test_the_command_is_never_interpolated_into_the_script(
        self, library: TemplateLibrary
    ) -> None:
        """Bound to env and invoked from there, so `${{ }}` substitution can
        never change the script's syntax — the rule the upload action's own
        comment argues for at length."""
        job = _job(library, {"checks": CHECKS})

        suite = next(step for step in job["steps"] if step.get("id") == "suite")
        assert suite["env"]["MYKRONOS_CHECK_COMMAND"] == "${{ matrix.check.command }}"
        assert "${{ matrix.check.command }}" not in suite["run"]
        # Piped into one shell, not two. Both values reach bash on stdin, so a
        # quote or a `;` in a configured command stays data rather than being
        # parsed as syntax by the outer script.
        assert '"$MYKRONOS_CHECK_SETUP" "$MYKRONOS_CHECK_COMMAND"' in suite["run"]
        assert "| bash -e" in suite["run"]

    def test_setup_and_command_share_a_shell(self, library: TemplateLibrary) -> None:
        """The bug a live run found: two `bash -c` invocations discard
        everything the setup established, so a `cd backend` in setup left the
        command running from the workspace root with none of the tools it had
        just installed on its path. `unit` and `functional` never had this —
        `_test_lane.yml.j2` emits setup and command as consecutive lines of a
        single `run:` block."""
        job = _job(library, {"checks": CHECKS})

        suite = next(step for step in job["steps"] if step.get("id") == "suite")
        assert 'bash -c "$MYKRONOS_CHECK_SETUP"' not in suite["run"]
        assert suite["run"].count("| bash -e") == 1

    def test_the_job_name_names_the_check(self, library: TemplateLibrary) -> None:
        job = _job(library, {"checks": CHECKS})

        assert job["name"] == "qa (${{ matrix.check.name }})"


class TestSingleCommandIsUnchanged:
    """The form every other repository already has must not move.

    `checks` is additive; a repository with one quality check should render
    what it rendered before this existed.
    """

    def test_no_matrix(self, library: TemplateLibrary) -> None:
        job = _job(library, {"command": "pytest -q"})

        assert "strategy" not in job
        assert job["name"] == "qa"

    def test_the_command_is_still_baked_in(self, library: TemplateLibrary) -> None:
        job = _job(library, {"command": "pytest -q --junitxml=$MYKRONOS_RESULTS/qa.xml"})

        suite = next(step for step in job["steps"] if step.get("id") == "suite")
        assert "pytest -q --junitxml=$MYKRONOS_RESULTS/qa.xml" in suite["run"]
        assert "MYKRONOS_CHECK_COMMAND" not in suite.get("env", {})

    def test_the_other_test_lanes_are_untouched(self, library: TemplateLibrary) -> None:
        """`checks` is a `qa` field. `unit` and `functional` share the same
        parent template, so a mistake in the shared block would surface here
        rather than in production."""
        for capability in ("unit", "functional"):
            rendered = library.render(capability, config={"command": "pytest -q"}, **RENDER)
            job = yaml.safe_load(rendered.content)["jobs"][capability]
            assert "strategy" not in job
            assert "pytest -q" in job["steps"][2]["run"]
