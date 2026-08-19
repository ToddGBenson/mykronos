"""npm and Go dependency pinning — spec 19 §3.1.

One fixer per manifest format rather than one generic dependency fixer, so
these are tested per format too: the restraint each one shows about what
counts as a security fix is different, and that difference is the point.
"""

from __future__ import annotations

import json

from mykronos.patchwork import fixers

REQUIREMENTS = "requirements.txt"


class TestNpm:
    def test_it_pins_an_exact_dependency(self) -> None:
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }
        content = json.dumps({"dependencies": {"lodash": "4.17.20"}}, indent=2) + "\n"

        fix = fixers.pin_npm_dependency(finding, content)

        assert fix is not None
        assert json.loads(fix.files["package.json"])["dependencies"]["lodash"] == "4.17.21"

    def test_it_leaves_a_caret_range_alone(self) -> None:
        """`^4.17.20` is the project's stated tolerance for updates.
        Narrowing it is a dependency-policy change, not a security fix — the
        same line `pin_python_requirement` already draws for `>=`."""
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }
        content = json.dumps({"dependencies": {"lodash": "^4.17.20"}}, indent=2)

        assert fixers.pin_npm_dependency(finding, content) is None

    def test_it_leaves_a_tag_alone(self) -> None:
        """`latest` is not a version this fixer can reason about."""
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }
        content = json.dumps({"dependencies": {"lodash": "latest"}}, indent=2)

        assert fixers.pin_npm_dependency(finding, content) is None

    def test_it_reaches_dev_dependencies(self) -> None:
        finding = {
            "package_name": "mocha",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "10.2.0"},
        }
        content = json.dumps({"devDependencies": {"mocha": "10.1.0"}}, indent=2)

        fix = fixers.pin_npm_dependency(finding, content)

        assert fix is not None
        assert json.loads(fix.files["package.json"])["devDependencies"]["mocha"] == "10.2.0"

    def test_unparseable_package_json_is_not_guessed_at(self) -> None:
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }

        assert fixers.pin_npm_dependency(finding, "{not json") is None

    def test_the_review_note_names_the_lockfile(self) -> None:
        """A pin without `npm install` changes nothing at install time, and a
        reviewer who does not know that will merge a fix that does not fix."""
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }
        content = json.dumps({"dependencies": {"lodash": "4.17.20"}}, indent=2)

        fix = fixers.pin_npm_dependency(finding, content)

        assert fix is not None
        assert any("package-lock.json" in note for note in fix.review_notes)


class TestGo:
    def test_it_pins_a_module(self) -> None:
        finding = {
            "package_name": "golang.org/x/net",
            "file_path": "go.mod",
            "raw_finding_json": {"fixed_version": "v0.23.0"},
        }
        content = "module example\n\nrequire golang.org/x/net v0.17.0\n"

        fix = fixers.pin_go_module(finding, content)

        assert fix is not None
        assert "golang.org/x/net v0.23.0" in fix.files["go.mod"]

    def test_it_keeps_the_indirect_marker(self) -> None:
        """Dropping `// indirect` changes what `go mod tidy` believes about
        the module, and makes the diff more than the version."""
        finding = {
            "package_name": "golang.org/x/text",
            "file_path": "go.mod",
            "raw_finding_json": {"fixed_version": "v0.14.0"},
        }
        content = "require golang.org/x/text v0.13.0 // indirect\n"

        fix = fixers.pin_go_module(finding, content)

        assert fix is not None
        assert fix.files["go.mod"] == "require golang.org/x/text v0.14.0 // indirect\n"

    def test_it_leaves_other_modules_untouched(self) -> None:
        finding = {
            "package_name": "golang.org/x/net",
            "file_path": "go.mod",
            "raw_finding_json": {"fixed_version": "v0.23.0"},
        }
        content = "require golang.org/x/net v0.17.0\nrequire example.com/other v1.2.3\n"

        fix = fixers.pin_go_module(finding, content)

        assert fix is not None
        assert "example.com/other v1.2.3" in fix.files["go.mod"]

    def test_the_review_note_names_go_sum(self) -> None:
        """Without `go mod tidy` the build refuses the new version's
        checksum, which is a confusing way to discover an incomplete fix."""
        finding = {
            "package_name": "golang.org/x/net",
            "file_path": "go.mod",
            "raw_finding_json": {"fixed_version": "v0.23.0"},
        }

        fix = fixers.pin_go_module(finding, "require golang.org/x/net v0.17.0\n")

        assert fix is not None
        assert any("go.sum" in note for note in fix.review_notes)


class TestTheyStayInTheirLane:
    def test_a_manifest_a_fixer_does_not_own_returns_none(self) -> None:
        """None means "not mine", never "unfixable" — `_attempt_fix` reads
        the two differently, and a fixer claiming a file it cannot parse
        would stop the one that can from being tried."""
        finding = {
            "package_name": "urllib3",
            "file_path": REQUIREMENTS,
            "raw_finding_json": {"fixed_version": "2.2.2"},
        }

        assert fixers.pin_npm_dependency(finding, "{}") is None
        assert fixers.pin_go_module(finding, "require x v1.0.0\n") is None

    def test_no_fixed_version_means_no_fix(self) -> None:
        """An advisory with no known fix cannot be fixed by pinning."""
        for path, content in (
            ("package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}})),
            ("go.mod", "require golang.org/x/net v0.17.0\n"),
        ):
            finding = {"package_name": "lodash", "file_path": path}
            assert fixers.pin_npm_dependency(finding, content) is None
            assert fixers.pin_go_module(finding, content) is None

    def test_generate_dispatches_to_the_right_fixer(self) -> None:
        """The registry is ordered and first-match-wins, so a new fixer that
        over-claims would silently shadow an existing one."""
        finding = {
            "package_name": "lodash",
            "file_path": "package.json",
            "raw_finding_json": {"fixed_version": "4.17.21"},
        }
        content = json.dumps({"dependencies": {"lodash": "4.17.20"}}, indent=2)

        result = fixers.generate(finding, content)

        assert result is not None
        assert result[0] == "pin-npm-dependency"
