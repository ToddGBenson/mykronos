"""The backend's dependency locks stay true to pyproject.toml.

backend/requirements.txt is what the image installs, `--require-hashes`, and
what the `dependencies` lane's osv-scanner reads. backend/requirements-dev.txt
is what the unit, coverage and lint-and-types lanes install. Both are generated
by `python scripts/lock_backend.py` and never edited by hand.

A lock is only worth having while it agrees with the manifest it came from. If
someone adds a dependency to pyproject.toml and does not re-lock, the image
builds without it and fails at import; if someone raises a floor past the
pinned version, the lock silently ships the version the floor was raised to
get away from. These tests catch both without network access, so they run on
every lane; re-locking is the fix for any of them.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
RUNTIME_LOCK = BACKEND / "requirements.txt"
DEV_LOCK = BACKEND / "requirements-dev.txt"
DOCKERFILE = BACKEND / "Dockerfile"
PIPELINE = ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"
BACKEND_PR = ROOT / ".github" / "workflows" / "backend-pr.yml"
LOCK_SCRIPT = ROOT / "scripts" / "lock_backend.py"

FIX = "re-lock with `python scripts/lock_backend.py` (backend/README.md)"

#: What uv writes for a package pyproject.toml asks for directly.
_DIRECT = "mykronos (pyproject.toml)"
#: The dev lock is constrained by the runtime one (scripts/lock_backend.py).
_CONSTRAINT = "-c requirements.txt"

_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>\S+)\s*\\?\s*$")


class Locked:
    """One package's entry in a uv-compiled, hashed requirements file."""

    def __init__(self, name: str, version: str) -> None:
        self.name = name
        self.version = version
        self.hashes: list[str] = []
        self.via: set[str] = set()


def _parse(path: Path) -> dict[str, Locked]:
    entries: dict[str, Locked] = {}
    current: Locked | None = None
    in_via = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not raw.startswith((" ", "\t")):
            if line.startswith("#"):
                continue
            match = _PIN.match(line)
            assert match, f"{path.name}: not an exact pin: {raw!r} -- {FIX}"
            current = Locked(canonicalize_name(match["name"]), match["version"])
            assert current.name not in entries, f"{path.name}: {current.name} twice"
            entries[current.name] = current
            in_via = False
            continue
        assert current is not None, f"{path.name}: indented line before any pin: {raw!r}"
        if line.startswith("--hash="):
            current.hashes.append(line.removeprefix("--hash=").rstrip(" \\"))
        elif line == "# via":
            in_via = True
        elif line.startswith("# via "):
            current.via.add(line.removeprefix("# via ").strip())
            in_via = False
        elif in_via and line.startswith("#   "):
            current.via.add(line.removeprefix("#   ").strip())
        else:
            raise AssertionError(f"{path.name}: unexpected line {raw!r}")
    return entries


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    with (BACKEND / "pyproject.toml").open("rb") as handle:
        loaded: dict[str, Any] = tomllib.load(handle)
    return loaded


@pytest.fixture(scope="module")
def runtime() -> dict[str, Locked]:
    return _parse(RUNTIME_LOCK)


@pytest.fixture(scope="module")
def dev() -> dict[str, Locked]:
    return _parse(DEV_LOCK)


def _requirements(pyproject: dict[str, Any], *extras: str) -> list[Requirement]:
    """pyproject's requirements for the base set plus `extras`, self-references
    (`mykronos[mcp]`) expanded rather than listed."""
    project = pyproject["project"]
    found = [Requirement(r) for r in project["dependencies"]]
    pending = list(extras)
    seen: set[str] = set()
    while pending:
        extra = pending.pop()
        if extra in seen:
            continue
        seen.add(extra)
        for text in project["optional-dependencies"][extra]:
            requirement = Requirement(text)
            if canonicalize_name(requirement.name) == canonicalize_name(project["name"]):
                pending.extend(requirement.extras)
            else:
                found.append(requirement)
    return found


def _assert_satisfied(lock: dict[str, Locked], wanted: list[Requirement], name: str) -> None:
    for requirement in wanted:
        key = canonicalize_name(requirement.name)
        assert key in lock, f"{requirement} is in pyproject.toml but not in {name} -- {FIX}"
        version = lock[key].version
        assert requirement.specifier.contains(version, prereleases=True), (
            f"{name} pins {key}=={version}, which pyproject.toml's {requirement} excludes -- {FIX}"
        )


def _direct(lock: dict[str, Locked]) -> set[str]:
    """Packages in the lock only because pyproject.toml names them."""
    return {
        name
        for name, entry in lock.items()
        if _DIRECT in entry.via and entry.via <= {_DIRECT, _CONSTRAINT}
    }


# ---------------------------------------------------------------------------
# The locks agree with pyproject.toml
# ---------------------------------------------------------------------------


def test_every_runtime_dependency_is_locked_at_a_version_it_allows(
    pyproject: dict[str, Any], runtime: dict[str, Locked]
) -> None:
    _assert_satisfied(runtime, _requirements(pyproject), RUNTIME_LOCK.name)


def test_every_dev_dependency_is_locked_at_a_version_it_allows(
    pyproject: dict[str, Any], dev: dict[str, Locked]
) -> None:
    _assert_satisfied(dev, _requirements(pyproject, "dev"), DEV_LOCK.name)


def test_nothing_is_locked_for_a_dependency_pyproject_no_longer_names(
    pyproject: dict[str, Any], runtime: dict[str, Locked], dev: dict[str, Locked]
) -> None:
    """A dependency removed from pyproject.toml must leave the lock too, or
    the image keeps shipping -- and the scan keeps reporting -- code nothing
    asks for."""
    for lock, wanted, name in (
        (runtime, _requirements(pyproject), RUNTIME_LOCK.name),
        (dev, _requirements(pyproject, "dev"), DEV_LOCK.name),
    ):
        declared = {canonicalize_name(r.name) for r in wanted}
        stale = _direct(lock) - declared
        assert not stale, f"{name} still locks {sorted(stale)} -- {FIX}"


def test_the_runtime_lock_carries_no_dev_only_package(
    pyproject: dict[str, Any], runtime: dict[str, Locked]
) -> None:
    runtime_names = {canonicalize_name(r.name) for r in _requirements(pyproject)}
    dev_only = {
        canonicalize_name(r.name) for r in _requirements(pyproject, "dev")
    } - runtime_names
    assert not dev_only & set(runtime), sorted(dev_only & set(runtime))


def test_the_dev_lock_tests_the_versions_that_ship(
    runtime: dict[str, Locked], dev: dict[str, Locked]
) -> None:
    """Every runtime package is in the dev lock at the same version, so the
    unit lane exercises the dependency set the image installs."""
    for name, entry in runtime.items():
        assert name in dev, f"{name} is in {RUNTIME_LOCK.name} but not {DEV_LOCK.name} -- {FIX}"
        assert dev[name].version == entry.version, (
            f"{name}: {entry.version} ships, {dev[name].version} is tested -- {FIX}"
        )


def test_every_locked_package_carries_a_sha256(
    runtime: dict[str, Locked], dev: dict[str, Locked]
) -> None:
    """`--require-hashes` refuses a package without one, so a hand-added line
    fails the image build; this fails it first."""
    for lock in (runtime, dev):
        for entry in lock.values():
            assert entry.hashes, f"{entry.name} has no hash -- {FIX}"
            for digest in entry.hashes:
                assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest), (entry.name, digest)


def test_the_locks_were_compiled_for_the_image(pyproject: dict[str, Any]) -> None:
    """The image is `python:3.13-slim` on x86_64 Linux; a lock resolved for
    another interpreter or platform installs a different set, or fails."""
    images = re.findall(r"^FROM python:(\d+\.\d+)-slim", DOCKERFILE.read_text("utf-8"), re.M)
    assert images and set(images) == {"3.13"}, images
    for lock in (RUNTIME_LOCK, DEV_LOCK):
        header = lock.read_text(encoding="utf-8").splitlines()[1]
        assert header.lstrip("# ").startswith("uv pip compile pyproject.toml"), header
        assert "--generate-hashes" in header
        assert "--python-version 3.13" in header
        assert "--python-platform x86_64-manylinux_2_28" in header
    assert '"--python-version", "3.13"' in LOCK_SCRIPT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# What installs the locks
# ---------------------------------------------------------------------------


def test_the_image_installs_the_lock_and_resolves_nothing() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    runtime_stage = dockerfile[dockerfile.index("AS runtime") :]
    assert "COPY backend/requirements.txt" in runtime_stage
    install = re.search(r"RUN pip install[^\n]*\\\n[^\n]*-r /tmp/requirements\.txt", runtime_stage)
    assert install, "the runtime stage must install backend/requirements.txt"
    assert "--require-hashes" in install.group(0)
    assert "--only-binary :all:" in install.group(0)
    wheel = re.search(r"RUN pip install[^\n]*/tmp/\*\.whl", runtime_stage)
    assert wheel and "--no-deps" in wheel.group(0)
    # Dependencies before the project, so the wheel resolves nothing.
    assert runtime_stage.index("-r /tmp/requirements.txt") < runtime_stage.index("/tmp/*.whl")


def _jobs() -> dict[str, str]:
    pipeline = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
    scripts: dict[str, str] = {}
    for job in pipeline["jobs"]:
        scripts[job["name"]] = "\n".join(
            str(step["config"]["run"]["args"][-1])
            for step in job["plan"]
            if "config" in step and "run" in step["config"]
        )
    return scripts


@pytest.mark.parametrize("job", ["unit", "coverage", "lint-and-types"])
def test_the_test_lanes_install_the_dev_lock(job: str) -> None:
    script = _jobs()[job]
    assert "pip install --quiet --require-hashes -r requirements-dev.txt" in script
    assert "pip install --quiet --no-deps -e ." in script
    assert '".[dev]"' not in script, "an unlocked install resolves against PyPI"


def test_no_pipeline_job_installs_the_backend_unlocked_from_its_checkout() -> None:
    for job, script in _jobs().items():
        for line in script.splitlines():
            if re.search(r"pip install\b.*\s-e\s", line):
                assert "--no-deps" in line, f"{job}: {line.strip()}"


def test_the_backend_pr_check_installs_the_dev_lock() -> None:
    text = BACKEND_PR.read_text(encoding="utf-8")
    assert "pip install --quiet --require-hashes -r requirements-dev.txt" in text
    assert "pip install --quiet --no-deps -e ." in text
    assert '".[dev]"' not in re.sub(r"#.*", "", text)


def test_the_dependencies_lane_reads_the_runtime_lock() -> None:
    """osv-scanner finds the lock by walking the checkout and matching
    `requirements*.txt`. Scanning a narrower path, or renaming the lock to
    something it does not match, would drop the backend from the scan
    without failing anything -- which is how it went unscanned before."""
    script = _jobs()["dependencies"]
    scans = re.findall(r"osv-scanner scan source [^|]*?\.(?= \|\|)", script, re.S)
    assert len(scans) == 2, scans
    for scan in scans:
        assert "--recursive" in scan
        assert scan.rstrip().endswith(" ."), "the scan root must be the checkout"
    assert re.fullmatch(r"requirements.*\.txt", RUNTIME_LOCK.name)
    # The verdict is unchanged: 1 is a result, above 1 is a failure.
    assert 'if [ "$rc" -gt 1 ]; then' in script
