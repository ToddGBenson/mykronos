"""Container scanning (spec 04 §3).

The first version ran `trivy filesystem`, which reads the working tree and
never builds or pulls anything — so it could not see the base image's OS
packages or anything a RUN line installs, which is most of what container
scanning is for. It also duplicated two other capabilities: `--scanners
misconfig` overlaps Checkov and `--scanners secret` overlaps Gitleaks, so a
repo with all three enabled reported the same problem three times under three
rule ids.

These tests are about the rendered workflow rather than the adapter. Trivy
emits SARIF and goes through the shared converter, so there is no
container-specific parsing to test — the risk is all in what the workflow
tells Trivy to look at.
"""

from __future__ import annotations

import pytest
import yaml

from mykronos.config import get_settings
from mykronos.installer import TemplateLibrary


@pytest.fixture
def rendered() -> str:
    library = TemplateLibrary(get_settings().workflow_templates_dir)
    return library.render(
        "containers",
        repo_full_name="example-org/repo",
        default_branch="main",
        ingestion_api_url="https://example.invalid",
        token_secret_name="MYKRONOS_INGESTION_TOKEN",
        upload_action_ref="example-org/repo/actions/upload-results@v1",
        mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
    ).content


class TestWhatItScans:
    def test_it_scans_an_image_not_the_filesystem(self, rendered: str) -> None:
        """The whole point of the rewrite."""
        assert "trivy" in rendered.lower()
        assert "image " in rendered
        assert "filesystem /repo" not in rendered

    def test_it_builds_before_scanning(self, rendered: str) -> None:
        assert "docker build" in rendered

    def test_it_asks_only_for_vulnerabilities(self, rendered: str) -> None:
        """Dockerfile misconfiguration belongs to iac and repository secrets
        belong to secrets. Asking for all three here means a repo with all
        three enabled sees every finding three times."""
        assert "--scanners vuln" in rendered
        assert "misconfig" not in rendered.split("{% endblock %}")[0]
        assert "--scanners vuln,misconfig,secret" not in rendered


class TestWhenThereIsNothingToScan:
    def test_no_dockerfile_still_writes_a_result(self, rendered: str) -> None:
        """spec 04 §6: "scanned, found nothing" and "never ran" must stay
        distinguishable in the lake. An absent results file is the second, and
        the adapter treats it as a failure — correctly, which is why the
        workflow has to write the empty one itself."""
        assert "trivy-empty.sarif" in rendered
        assert '"results":[]' in rendered

    def test_a_build_failure_does_not_fail_the_scan(self, rendered: str) -> None:
        """The repository's own CI owns whether the image builds. A security
        check that goes red because a Dockerfile is broken is a check people
        learn to ignore."""
        assert "continue-on-error: true" in rendered
        assert "skipping it" in rendered

    def test_every_build_failing_still_produces_a_result(self, rendered: str) -> None:
        assert "No image was scannable" in rendered


class TestDiscovery:
    def test_vendored_dockerfiles_are_excluded(self, rendered: str) -> None:
        """A vendored example Dockerfile produces vulnerabilities in an image
        this repository never builds and never ships."""
        for excluded in ("node_modules", "vendor", "testdata", ".venv"):
            assert excluded in rendered

    def test_it_handles_more_than_one_dockerfile(self, rendered: str) -> None:
        """TheHub has Dockerfile and Dockerfile.hardened. One SARIF per image,
        named after its Dockerfile, so a finding can be traced to the image it
        came from rather than landing in an undifferentiated pile."""
        assert "while IFS= read -r DOCKERFILE" in rendered
        assert "trivy-$SAFE.sarif" in rendered

    def test_it_avoids_the_jinja_comment_collision(self) -> None:
        """Bash array-length syntax opens a Jinja comment that never closes,
        and the template fails to compile pointing at an unrelated line."""
        source = (
            get_settings().workflow_templates_dir / "containers.yml.j2"
        ).read_text(encoding="utf-8")

        assert "${" + "#" not in source


class TestItIsAValidWorkflow:
    def test_it_parses_as_yaml(self, rendered: str) -> None:
        document = yaml.safe_load(rendered)
        assert document["jobs"]

    def test_it_runs_on_a_schedule(self, rendered: str) -> None:
        """The capability where a schedule matters most: the image does not
        change, and what is known about it does."""
        document = yaml.safe_load(rendered)
        triggers = document[True] if True in document else document["on"]
        assert "schedule" in triggers

    def test_it_passes_the_ref_it_was_rendered_with(self, rendered: str) -> None:
        assert "mykronos-ref: v1" in rendered
