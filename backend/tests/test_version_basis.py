"""A finding says whether its version is one this repository runs (B-063).

`--no-resolve` is deliberate and permanent here: transitive resolution calls
deps.dev, which returns an internal error for any requirements.txt containing
sqlalchemy, and an extractor error fails the whole lane. The choice was
between a lane that reports declared floors and a lane that reports nothing,
and floors won.

What was missing is that the platform never said which it was looking at.
TheHub carried four HIGH advisories against `cryptography@42.0.0` while every
container ran 50.0.1, which has none. Those findings were true about the floor
and false about the deployment, and a reader could not tell, because the
finding named a version that appears nowhere except a lower bound. They were
reported here and in mykronos#216 as live HIGH vulnerabilities on an
internet-facing application, and corrected only after somebody read
`cryptography.__version__` inside the running containers.

A floor is still a real thing to assess -- a rebuild that resolves differently
installs it -- so this labels them rather than suppressing them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mykronos.adapters.atlas_osv import _basis


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(
        "cryptography==42.0.0\n"
        "urllib3>=2.0\n"
        "requests\n"
        "pyjwt[crypto]>=2.9\n"
        "# jinja2==3.1.0 -- commented out\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        '{\n  "dependencies": {\n'
        '    "left-pad": "1.3.0",\n'
        '    "lodash": "^4.17.0",\n'
        '    "next": "~16.3",\n'
        '    "sharp": "*"\n'
        "  }\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text("# lock\n", encoding="utf-8")
    return tmp_path


class TestALockfileIsAboutRunningSoftware:
    def test_a_lockfile_names_the_installed_version(self, repo: Path) -> None:
        assert _basis("poetry.lock", "anything", repo) == "resolved"

    def test_the_file_kind_alone_settles_it(self) -> None:
        """A lockfile pins by definition, so this answer needs no source and
        no package -- which matters, because the source is not always on disk
        by the time a finding is normalised."""
        assert _basis("frontend/package-lock.json", None, None) == "resolved"

    @pytest.mark.parametrize(
        "path",
        ["yarn.lock", "go.sum", "Cargo.lock", "Gemfile.lock", "sub/dir/pnpm-lock.yaml"],
    )
    def test_every_ecosystem_s_lockfile(self, path: str) -> None:
        assert _basis(path, "x", None) == "resolved"


class TestAManifestIsAboutWhatIsPermitted:
    def test_an_open_bound_is_a_declared_floor(self, repo: Path) -> None:
        """The shape the entry is about: the version assessed is the oldest
        the repository accepts, and nothing says it is installed."""
        assert _basis("requirements.txt", "urllib3", repo) == "declared_floor"

    def test_an_extra_marker_does_not_hide_the_bound(self, repo: Path) -> None:
        """`pyjwt[crypto]>=2.9` was one of the four mykronos floors carrying an
        advisory."""
        assert _basis("requirements.txt", "pyjwt", repo) == "declared_floor"

    def test_a_bare_requirement_permits_anything(self, repo: Path) -> None:
        assert _basis("requirements.txt", "requests", repo) == "declared_floor"

    def test_an_exact_pin_is_not_a_floor(self, repo: Path) -> None:
        """A pinned requirement names the version that gets installed, so
        calling it a floor would be its own false statement."""
        assert _basis("requirements.txt", "cryptography", repo) == "declared_pin"

    def test_a_commented_requirement_is_not_read(self, repo: Path) -> None:
        assert _basis("requirements.txt", "jinja2", repo) is None


class TestNpmReadsTheValueNotTheLine:
    def test_an_exact_version_is_a_pin(self, repo: Path) -> None:
        assert _basis("package.json", "left-pad", repo) == "declared_pin"

    @pytest.mark.parametrize("package", ["lodash", "next", "sharp"])
    def test_a_range_is_a_floor(self, repo: Path, package: str) -> None:
        assert _basis("package.json", package, repo) == "declared_floor"

    def test_a_neighbour_s_pin_does_not_decide_this_package(self, tmp_path: Path) -> None:
        """The bug the first version had: a `package.json` written on one line
        let `left-pad`'s exact pin answer for `lodash`."""
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"left-pad": "1.3.0", "lodash": "^4.17.0"}}', encoding="utf-8"
        )

        assert _basis("package.json", "lodash", tmp_path) == "declared_floor"
        assert _basis("package.json", "left-pad", tmp_path) == "declared_pin"


class TestWhenNothingIsEstablished:
    def test_an_unrecognised_file_claims_nothing(self, repo: Path) -> None:
        assert _basis("README.md", "x", repo) is None

    def test_a_manifest_with_no_source_on_disk_claims_nothing(self) -> None:
        """A manifest means "a declaration", but a pin and a floor are both
        declarations, and guessing between them is the error this prevents."""
        assert _basis("requirements.txt", "urllib3", None) is None

    def test_a_missing_file_claims_nothing(self, tmp_path: Path) -> None:
        assert _basis("requirements.txt", "urllib3", tmp_path) is None

    def test_a_package_not_in_the_manifest_claims_nothing(self, repo: Path) -> None:
        assert _basis("requirements.txt", "not-declared-here", repo) is None

    def test_no_path_claims_nothing(self, repo: Path) -> None:
        assert _basis("", "urllib3", repo) is None
