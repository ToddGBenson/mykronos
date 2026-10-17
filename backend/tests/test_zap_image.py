"""The ZAP the demo-and-dast lane runs is our build, from one pinned digest.

Every container finding the lake held against MyKronos was in the upstream
ZAP image, and no upstream tag is better. So `deploy/zap/Dockerfile` takes the
pinned weekly, applies Debian's fixes and removes what our usage never runs.
A nightly workflow builds that recipe and publishes it, and
`deploy/zap-pinned/Dockerfile` adopts one published date by digest.
These hold what makes that safe to rely on: each FROM is one exact pin
(D-114/D-128), what was removed stays removed, the recipe's baseline is the
image in use, and the containers lane scans the image the lane actually runs,
under the name its findings already carry.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from mykronos.estate_images import annotate_reports, derive, main

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "deploy" / "zap" / "Dockerfile"
PINNED = REPO_ROOT / "deploy" / "zap-pinned" / "Dockerfile"
DEMO_COMPOSE = REPO_ROOT / "deploy" / "demo" / "docker-compose.yml"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "demo-and-dast.yml"
REBUILD = REPO_ROOT / "deploy" / "demo" / "Invoke-DemoRebuild.ps1"
PIPELINE = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"

PINNED_FROM = re.compile(r"^ghcr\.io/zaproxy/zaproxy:[\w.-]+@sha256:[0-9a-f]{64}$")
#: What the nightly workflow publishes, held at one digest.
PUBLISHED_FROM = re.compile(
    r"^ghcr\.io/[a-z0-9-]+/mykronos-zap:weekly-p\d{8}@sha256:[0-9a-f]{64}$"
)


def _instructions(dockerfile: Path = DOCKERFILE) -> list[tuple[str, str]]:
    """(INSTRUCTION, argument) pairs, continuation lines joined, comments dropped."""
    text = dockerfile.read_text(encoding="utf-8")
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not buffer and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        logical.append(buffer + line)
        buffer = ""
    pairs = []
    for line in logical:
        word, _, rest = line.partition(" ")
        pairs.append((word.upper(), rest.strip()))
    return pairs


def _run_body() -> str:
    return " ".join(arg for word, arg in _instructions() if word == "RUN")


def _zap_service() -> dict:
    return yaml.safe_load(DEMO_COMPOSE.read_text(encoding="utf-8"))["services"]["zap"]


class TestTheDockerfile:
    def test_there_is_one_from_and_it_is_the_pinned_digest(self) -> None:
        froms = [arg for word, arg in _instructions() if word == "FROM"]
        assert len(froms) == 1, froms
        assert PINNED_FROM.match(froms[0]), f"FROM {froms[0]!r} is not held at one digest"

    def test_debian_s_fixes_are_applied(self) -> None:
        body = _run_body()
        assert "apt-get update" in body
        assert re.search(r"apt-get -y [^;]*upgrade", body)
        assert "rm -rf /var/lib/apt/lists/*" in body

    def test_what_our_usage_never_runs_is_purged(self) -> None:
        """Each of these carried HIGH findings and nothing in the lane uses it:
        no AJAX spider (browser, X server), no SSH, no PostScript, no compiler,
        no wget. Purged, with their orphans, in the same layer as the upgrade."""
        body = _run_body()
        purge = body[body.index("purge --auto-remove") :]
        for package in (
            "firefox-esr",
            "xvfb",
            "xserver-common",
            "openssh-client",
            "libgs10",
            "linux-libc-dev",
            "python3.13-dev",
            "libexpat1-dev",
            "wget",
            "openjdk-21-jdk",
        ):
            assert re.search(rf"(?<![\w.-]){re.escape(package)}(?![\w.-])", purge), package

    def test_webswing_is_removed_and_the_build_proves_it(self) -> None:
        """Webswing is ZAP's GUI-in-a-browser. Nothing here runs it, and its
        bundled jetty and lz4 jars were the last five HIGH findings Debian
        could not fix (2026-10-15), so it goes - and a build that kept it
        fails rather than shipping it."""
        body = _run_body()
        assert re.search(r"rm -rf /zap/webswing(?![\w/-])", body)
        assert re.search(r"\[ -e /zap/webswing \]; then [^;]*; exit 1", body)

    def test_the_jre_zap_runs_on_is_kept(self) -> None:
        """Dropping the JDK must not take the headless JRE with it."""
        assert "apt-mark manual openjdk-21-jre-headless" in _run_body()

    def test_the_build_fails_if_a_purged_package_survived(self) -> None:
        body = _run_body()
        assert "still installed" in body and "exit 1" in body
        assert "java -version" in body
        assert "import zapv2" in body

    def test_it_runs_as_zap_not_root(self) -> None:
        users = [arg for word, arg in _instructions() if word == "USER"]
        assert users and users[-1] == "zap"


class TestTheLaneRunsOnePublishedBuild:
    """The recipe is rebuilt nightly; every commit runs one adopted date of it."""

    def test_the_pinned_file_is_one_from_and_it_is_a_published_digest(self) -> None:
        instructions = _instructions(PINNED)
        froms = [arg for word, arg in instructions if word == "FROM"]
        assert len(froms) == 1, froms
        assert PUBLISHED_FROM.match(froms[0]), f"FROM {froms[0]!r} is not a published date"

    def test_the_pinned_file_changes_nothing_in_the_image(self) -> None:
        """A RUN, COPY or ADD here would make the scanned image something the
        nightly lane never compared, and the pin a second recipe."""
        words = {word for word, _ in _instructions(PINNED)}
        assert words <= {"FROM", "HEALTHCHECK", "USER"}, words
        users = [arg for word, arg in _instructions(PINNED) if word == "USER"]
        assert users == ["zap"]

    def test_the_recipe_is_compared_against_the_image_in_use(self) -> None:
        """A baseline of upstream's image would publish every night's rebuild,
        since any rebuild beats upstream, whether or not it beats what runs."""
        froms = [arg for word, arg in _instructions(PINNED) if word == "FROM"]
        assert _zap_service()["x-mykronos-build"]["baseline"] == froms[0]

    def test_the_pin_is_of_what_the_recipe_publishes(self) -> None:
        """Same repository name, so adopting a date never adopts another image."""
        froms = [arg for word, arg in _instructions(PINNED) if word == "FROM"]
        published = _zap_service()["x-mykronos-build"]["publish"].split(":", 1)[0]
        assert froms[0].split("@", 1)[0].rsplit(":", 1)[0].endswith("/" + published)

    def test_the_recipe_is_still_the_derivative(self) -> None:
        recipe = _zap_service()["x-mykronos-build"]["context"]
        assert (DEMO_COMPOSE.parent / recipe).resolve() == DOCKERFILE.parent.resolve()


class TestTheDemoStackRunsIt:
    def test_compose_builds_zap_from_the_pinned_dockerfile(self) -> None:
        zap = _zap_service()
        build = zap.get("build")
        assert isinstance(build, dict), "the zap service no longer builds the pin"
        assert (DEMO_COMPOSE.parent / build["context"]).resolve() == PINNED.parent.resolve()
        assert build.get("dockerfile", "Dockerfile") == "Dockerfile"

    def test_the_built_image_has_a_local_name_never_the_upstream_one(self) -> None:
        """Tagging a build as `ghcr.io/zaproxy/zaproxy` would let a pull replace
        it with the unpatched image, and a registry host would let a pull fetch
        somebody else's."""
        image = str(_zap_service()["image"])
        assert "zaproxy" not in image
        assert "/" not in image.split(":", 1)[0]

    def test_compose_never_pulls_over_the_build(self) -> None:
        assert _zap_service().get("pull_policy") == "build"

    def test_the_lane_s_pull_skips_what_compose_builds(self) -> None:
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        steps = workflow["jobs"]["demo-and-dast"]["steps"]
        stand_up = next(step for step in steps if step.get("name") == "Stand up the demo stack")
        assert "pull --quiet --ignore-buildable" in stand_up["run"]

    def test_the_local_rebuild_pull_skips_it_too(self) -> None:
        text = REBUILD.read_text(encoding="utf-8")
        assert '@("pull", "--quiet", "--ignore-buildable")' in text


class TestTheContainersLaneScansIt:
    def test_the_derivative_is_derived_as_a_build_not_an_upstream_image(self) -> None:
        derivation = derive(REPO_ROOT)
        assert not [image for image in derivation.images() if "zaproxy" in image]
        builds = {build.name: build for build in derivation.builds()}
        assert "mykronos-zap" in builds, builds
        assert builds["mykronos-zap"].context == "deploy/zap-pinned"
        assert builds["mykronos-zap"].dockerfile == "deploy/zap-pinned/Dockerfile"
        assert builds["mykronos-zap"].role == "tool"

    def test_the_build_list_is_a_file_the_pipeline_reads(self, tmp_path: Path) -> None:
        (tmp_path / "zap").mkdir()
        (tmp_path / "zap" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tmp_path / "demo").mkdir()
        (tmp_path / "demo" / "docker-compose.yml").write_text(
            "services:\n"
            "  zap:\n    image: mykronos-zap:local\n    build:\n      context: ../zap\n"
            "  db:\n    image: postgres:15\n",
            encoding="utf-8",
        )
        out = tmp_path / "builds.txt"
        assert main(["--root", str(tmp_path), "--output", "-", "--builds-output", str(out)]) == 0
        assert out.read_text(encoding="utf-8") == "mykronos-zap zap zap/Dockerfile\n"

    def test_a_build_context_outside_the_tree_is_not_built(self, tmp_path: Path) -> None:
        (tmp_path / "docker-compose.yml").write_text(
            "services:\n  x:\n    image: x:1\n    build: ../../elsewhere\n", encoding="utf-8"
        )
        derivation = derive(tmp_path)
        assert derivation.builds() == []
        assert any("outside" in warning for warning in derivation.warnings)

    def test_the_containers_job_builds_and_scans_the_derived_builds(self) -> None:
        document = yaml.safe_load(PIPELINE.read_text(encoding="utf-8"))
        job = next(j for j in document["jobs"] if j["name"] == "containers")
        tasks = {step["task"]: step for step in job["plan"] if "task" in step}

        derive_body = "\n".join(tasks["derive-estate-images"]["config"]["run"]["args"])
        assert "--builds-output estate/builds.txt" in derive_body

        build = tasks["build-tool-images"]
        build_body = "\n".join(build["config"]["run"]["args"])
        assert "estate/builds.txt" in build_body
        assert "/kaniko/executor" in build_body
        assert '--destination "${REGISTRY}/${name}:${SHA}"' in build_body
        assert "built/images.txt" in build_body

        scan_body = "\n".join(tasks["scan-images"]["config"]["run"]["args"])
        assert "done < built/images.txt" in scan_body
        assert 'results/trivy-built-${safe}.sarif' in scan_body
        assert {"name": "built"} in tasks["scan-images"]["config"]["inputs"]

    def test_the_scanned_derivative_is_marked_a_tool(self, tmp_path: Path) -> None:
        """Its report names `<registry>/mykronos-zap:<sha>`, which no compose
        file says; the role still has to reach it (#666)."""
        (tmp_path / "zap").mkdir()
        (tmp_path / "zap" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tmp_path / "docker-compose.yml").write_text(
            "x-mykronos-role: tool\nservices:\n"
            "  zap:\n    image: mykronos-zap:local\n    build: ./zap\n",
            encoding="utf-8",
        )
        results = tmp_path / "results"
        results.mkdir()
        for name, image in (
            ("trivy-built-zap.sarif", "192.0.2.1:5000/mykronos-zap:abc123"),
            ("trivy-mykronos-backend.sarif", "192.0.2.1:5000/mykronos-backend:abc123"),
        ):
            (results / name).write_text(
                json.dumps({"runs": [{"properties": {"imageName": image}}]}), encoding="utf-8"
            )

        counts = annotate_reports(derive(tmp_path), results)

        assert counts == {"reports": 2, "tool_reports": 1}
        zap = json.loads((results / "trivy-built-zap.sarif").read_text(encoding="utf-8"))
        assert zap["runs"][0]["properties"]["mykronosRole"] == "tool"
