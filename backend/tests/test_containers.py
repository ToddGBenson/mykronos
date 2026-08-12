"""Container scanning (spec 04 §3).

The first version ran `trivy filesystem`, which reads the working tree and
never builds or pulls anything — so it could not see the base image's OS
packages or anything a RUN line installs, which is most of what container
scanning is for. It also duplicated two other capabilities: `--scanners
misconfig` overlaps Checkov and `--scanners secret` overlaps Gitleaks, so a
repo with all three enabled reported the same problem three times under three
rule ids.

Most of these are about the rendered workflow rather than the adapter,
because that is where the risk was: what the workflow tells Trivy to look at.

The adapter tests came later, from the first real run. It produced 118
findings with no package on any of them, and with every finding from every
image recording the same path — so the same CVE in Dockerfile and
Dockerfile.hardened collapsed into one row.
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


TRIVY_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "Trivy", "rules": [
                {"id": "CVE-2026-42496",
                 "shortDescription": {"text": "perl-archive-tar path traversal"}}
            ]}},
            "results": [
                {
                    "ruleId": "CVE-2026-42496",
                    "level": "error",
                    "message": {
                        "text": (
                            "Package: perl-modules-5.40\n"
                            "Installed Version: 5.40.1-6\n"
                            "Vulnerability CVE-2026-42496\n"
                            "Severity: CRITICAL\n"
                            "Fixed Version: 5.40.1-7\n"
                        )
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": "library/mykronos-scan/backend-dockerfile"
                                }
                            }
                        }
                    ],
                }
            ],
        }
    ],
}


class TestTheTrivyAdapter:
    def _normalize(self, document=None):
        import json as _json

        from mykronos.adapters.base import ScanContext
        from mykronos.adapters.containers_trivy import normalize

        return normalize(
            _json.dumps(document or TRIVY_SARIF).encode(),
            ScanContext(
                repo_full_name="ToddGBenson/TheHub",
                capability="containers",
                tool_name="trivy",
                tool_version="0.58.1",
                commit_sha="a" * 40,
                branch="develop",
            ),
        )

    def test_the_package_is_extracted(self) -> None:
        """The first real container scan produced 118 findings with no
        package on any of them. A CVE with no package cannot be acted on."""
        finding = self._normalize().findings[0]

        assert finding.package_name == "perl-modules-5.40"
        assert finding.package_version == "5.40.1-6"

    def test_the_fixed_version_is_captured(self) -> None:
        """Patchwork reads it from the raw record (spec 08 §4), and it is the
        difference between "vulnerable" and "rebuild and it is not"."""
        finding = self._normalize().findings[0]

        assert finding.raw_finding_json["fixed_version"] == "5.40.1-7"

    def test_an_unfixed_vulnerability_records_no_fixed_version(self) -> None:
        """Trivy leaves the field present but empty when no fix exists. That
        is a different answer from unknown: an OS package with no fix cannot
        be remediated by rebuilding, and a fix proposed for one never works."""
        import copy

        document = copy.deepcopy(TRIVY_SARIF)
        document["runs"][0]["results"][0]["message"]["text"] = (
            "Package: perl\nInstalled Version: 5.40.1-6\nFixed Version: \n"
        )

        finding = self._normalize(document).findings[0]

        assert "fixed_version" not in (finding.raw_finding_json or {})


class TestFindingsStayAttributableToTheirImage:
    def test_two_images_do_not_collapse_into_one_finding(self) -> None:
        """The defect the first real run exposed.

        Every image was tagged `mykronos-scan:<sha>-N`, so Trivy wrote the
        same `library/mykronos-scan` into every SARIF. Finding identity
        includes the path (spec 05 §5), so the same CVE in Dockerfile and
        Dockerfile.hardened became one row — 600 results stored as 118, with
        no way to tell whether the hardened image had fixed anything.
        """
        import copy

        plain = copy.deepcopy(TRIVY_SARIF)
        hardened = copy.deepcopy(TRIVY_SARIF)
        hardened["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"] = "library/mykronos-scan/backend-dockerfile-hardened"

        first = self._ids(plain)
        second = self._ids(hardened)

        assert first != second, (
            "the same CVE in two different images must not share an identity"
        )

    @staticmethod
    def _ids(document):
        import json as _json

        from mykronos.adapters.base import ScanContext
        from mykronos.adapters.containers_trivy import normalize
        from mykronos.fingerprint import compute_finding_id

        result = normalize(
            _json.dumps(document).encode(),
            ScanContext(
                repo_full_name="ToddGBenson/TheHub",
                capability="containers",
                tool_name="trivy",
                tool_version="0.58.1",
                commit_sha="a" * 40,
                branch="develop",
            ),
        )
        finding = result.findings[0]
        return compute_finding_id(
            repo_full_name="ToddGBenson/TheHub",
            capability="containers",
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            symbol=finding.symbol,
            code_snippet=finding.code_snippet,
            line_start=finding.line_start,
        )

    def test_the_template_tags_each_image_after_its_dockerfile(self) -> None:
        from mykronos.config import get_settings
        from mykronos.installer import TemplateLibrary

        rendered = TemplateLibrary(get_settings().workflow_templates_dir).render(
            "containers",
            repo_full_name="example-org/repo",
            default_branch="main",
            ingestion_api_url="https://example.invalid",
            token_secret_name="MYKRONOS_INGESTION_TOKEN",
            upload_action_ref="example-org/repo/actions/upload-results@v1",
            mykronos_package_spec="mykronos @ git+https://example.invalid@v1",
        ).content

        assert 'TAG="mykronos-scan/${SAFE}:' in rendered
        assert "mykronos-scan:${{ github.sha }}-$INDEX" not in rendered
