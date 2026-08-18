"""The `ai` capability's default tool — spec 17 §6, D-047."""

from __future__ import annotations

import json

from mykronos.ai_pin_check import scan, to_sarif


class TestRequirementsTxt:
    def test_an_exact_pin_is_not_flagged(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("anthropic==0.34.0\n")
        assert scan(tmp_path) == []

    def test_a_floating_constraint_is_flagged(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("anthropic>=0.30\n")
        findings = scan(tmp_path)
        assert len(findings) == 1
        assert findings[0].package == "anthropic"
        assert findings[0].ecosystem == "pip"
        assert findings[0].line == 1

    def test_a_bare_name_with_no_version_is_flagged(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("openai\n")
        findings = scan(tmp_path)
        assert [f.package for f in findings] == ["openai"]

    def test_a_non_ai_package_is_ignored_whatever_its_pin(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\nurllib3\n")
        assert scan(tmp_path) == []

    def test_comments_and_blank_lines_are_skipped(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "# AI deps\n\nanthropic==0.34.0\n-e ./local-pkg\n"
        )
        assert scan(tmp_path) == []

    def test_line_numbers_point_at_the_real_line(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n\nopenai>=1.0\n")
        findings = scan(tmp_path)
        assert findings[0].line == 3


class TestPackageJson:
    def test_an_exact_version_is_not_flagged(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"@anthropic-ai/sdk": "0.34.0"}})
        )
        assert scan(tmp_path) == []

    def test_a_caret_range_is_flagged(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"@anthropic-ai/sdk": "^0.34.0"}})
        )
        findings = scan(tmp_path)
        assert [f.package for f in findings] == ["@anthropic-ai/sdk"]

    def test_latest_is_flagged(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"devDependencies": {"openai": "latest"}})
        )
        findings = scan(tmp_path)
        assert [f.package for f in findings] == ["openai"]

    def test_an_unrelated_package_is_ignored(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )
        assert scan(tmp_path) == []

    def test_malformed_json_does_not_raise(self, tmp_path) -> None:
        (tmp_path / "package.json").write_text("{not json")
        assert scan(tmp_path) == []


class TestScanIgnoresVendoredDirectories:
    def test_node_modules_is_skipped(self, tmp_path) -> None:
        nested = tmp_path / "node_modules" / "some-pkg"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(
            json.dumps({"dependencies": {"openai": "^1.0.0"}})
        )
        assert scan(tmp_path) == []


class TestSarifOutput:
    def test_no_findings_is_valid_empty_sarif(self, tmp_path) -> None:
        document = to_sarif([])
        assert document["runs"][0]["results"] == []
        assert document["version"] == "2.1.0"

    def test_a_finding_becomes_one_sarif_result(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("anthropic>=0.30\n")
        document = to_sarif(scan(tmp_path))
        results = document["runs"][0]["results"]

        assert len(results) == 1
        assert results[0]["ruleId"] == "mykronos-ai-pin/pip-unpinned"
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
            "requirements.txt"
        )
        assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1

    def test_rules_are_deduplicated_across_findings(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("anthropic>=0.30\nopenai>=1.0\n")
        document = to_sarif(scan(tmp_path))
        rule_ids = [r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["mykronos-ai-pin/pip-unpinned"]
