"""The ZAP the demo-and-dast lane runs is our build, from one pinned digest.

Every container finding the lake held against MyKronos was in the upstream
ZAP image, and no upstream tag is better; with a current Trivy DB even the
patched Debian derivative kept 76 HIGH that Debian has no fix for. So
`deploy/zap/Dockerfile` copies ZAP out of the pinned weekly and runs it on a
slim Alpine JRE, with only what our usage needs installed. A nightly workflow
builds that recipe and publishes it, and `deploy/zap-pinned/Dockerfile` adopts
one published date by digest. These hold what makes that safe to rely on: each
FROM is one exact pin (D-114/D-128), no Debian and nothing our usage never
runs reaches the image, the recipe's baseline is the image in use, and the
containers lane scans the image the lane actually runs, under the name its
findings already carry.
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
REQUIREMENTS = DOCKERFILE.parent / "requirements.txt"

PINNED_FROM = re.compile(r"^ghcr\.io/zaproxy/zaproxy:[\w.-]+@sha256:[0-9a-f]{64}$")
#: The runtime base: a JRE 21 on Alpine, held at one digest.
JRE_FROM = re.compile(r"^eclipse-temurin:21[\w.-]*-jre-alpine[\w.-]*@sha256:[0-9a-f]{64}$")
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


def _stages() -> list[tuple[str, list[tuple[str, str]]]]:
    """(FROM argument, that stage's instructions), in order."""
    stages: list[tuple[str, list[tuple[str, str]]]] = []
    for word, arg in _instructions():
        if word == "FROM":
            stages.append((arg, []))
        elif stages:
            stages[-1][1].append((word, arg))
    return stages


def _image(name: str) -> str:
    """`ref AS name` -> `ref`."""
    return name.split()[0]


def _runtime() -> list[tuple[str, str]]:
    """The last stage: what is actually shipped."""
    return _stages()[-1][1]


def _run_body(instructions: list[tuple[str, str]] | None = None) -> str:
    pairs = _instructions() if instructions is None else instructions
    return " ".join(arg for word, arg in pairs if word == "RUN")


def _zap_service() -> dict:
    return yaml.safe_load(DEMO_COMPOSE.read_text(encoding="utf-8"))["services"]["zap"]


class TestTheDockerfile:
    def test_zap_comes_from_one_stage_and_it_is_the_pinned_digest(self) -> None:
        """The estate's one ZAP pin (D-128): ZAP is taken from upstream's
        weekly at one digest, the digest TheHub's `zap` resource also pins."""
        zap = [_image(ref) for ref, _ in _stages() if "zaproxy" in ref]
        assert len(zap) == 1, zap
        assert PINNED_FROM.match(zap[0]), f"FROM {zap[0]!r} is not held at one digest"

    def test_every_from_is_held_at_one_digest(self) -> None:
        froms = [_image(ref) for ref, _ in _stages()]
        assert len(froms) == 2, froms
        assert all("@sha256:" in ref for ref in froms), froms

    def test_what_ships_is_a_slim_jre_not_debian(self) -> None:
        """The Debian derivative kept 76 HIGH with no Debian fix (python3.13,
        util-linux, curl, perl, ncurses, systemd), several in Essential
        packages no purge can remove. The shipped stage is a JRE on Alpine,
        and upstream's image is only a source of files."""
        base = _image(_stages()[-1][0])
        assert JRE_FROM.match(base), f"the runtime FROM {base!r} is not the pinned Alpine JRE"
        assert "apt-get" not in _run_body(_runtime())
        copies = [arg for word, arg in _runtime() if word == "COPY" and "--from=" in arg]
        assert copies, "ZAP is no longer copied from the pinned stage"
        assert all("--from=upstream" in arg for arg in copies), copies

    def test_alpine_s_fixes_are_applied(self) -> None:
        assert "apk upgrade --no-cache" in _run_body(_runtime())

    def test_only_what_our_usage_runs_is_installed(self) -> None:
        """bash for zap.sh, curl for the healthchecks, python3 for the wrapper
        scripts, and pip only for as long as it takes to install their
        libraries. No browser, X server, compiler, SSH client or wget."""
        body = _run_body(_runtime())
        added = re.findall(r"apk add --no-cache ([^;]+);", body)
        assert added, "no apk add in the runtime stage"
        packages = {name for line in added for name in line.split()}
        assert packages == {"bash", "curl", "python3", "py3-pip"}, packages
        assert "apk del --no-cache py3-pip" in body
        assert re.search(r"pip --version[^;]*; then [^;]*; exit 1", body), "pip may survive"

    def test_the_python_libraries_are_pinned_by_hash(self) -> None:
        """pip installs exactly the reviewed files and compiles nothing."""
        body = _run_body(_runtime())
        assert "--require-hashes" in body and "--only-binary :all:" in body
        text = REQUIREMENTS.read_text(encoding="utf-8")
        requirements = re.findall(r"(?m)^([A-Za-z0-9_.-]+)==(\S+) \\\r?$", text)
        names = {name.lower() for name, _ in requirements}
        assert {"zaproxy", "pyyaml", "requests", "six"} <= names, names
        assert text.count("--hash=sha256:") >= len(requirements)

    def test_webswing_is_removed_and_the_build_proves_it(self) -> None:
        """Webswing is ZAP's GUI-in-a-browser. Nothing here runs it, and its
        bundled jetty and lz4 jars were the last five HIGH findings Debian
        could not fix (2026-10-15), so it goes - and a build that kept it
        fails rather than shipping it."""
        body = _run_body()
        assert re.search(r"rm -rf /zap/webswing(?![\w/-])", body)
        assert re.search(r"\[ -e /zap/webswing \]; then [^;]*; exit 1", body)

    def test_the_launcher_the_wrapper_scripts_use_is_kept(self) -> None:
        """zap_common.py starts every zap-baseline.py and zap-api-scan.py run
        through /zap/zap-x.sh; deleting it as a GUI launcher fails every scan
        with "Failed to start ZAP"."""
        body = _run_body()
        assert not re.search(r"rm [^;]*/zap/zap-x\.sh", body)
        assert "test -x /zap/zap-x.sh" in body

    def test_the_build_fails_if_java_or_the_client_is_missing(self) -> None:
        body = _run_body()
        assert "java -version" in body
        assert "import zapv2" in body
        assert "curl --version" in body

    def test_it_runs_as_zap_uid_1000_not_root(self) -> None:
        """Upstream's user and ids: the DAST lane chowns /zap/wrk to 1000."""
        users = [arg for word, arg in _instructions() if word == "USER"]
        assert users and users[-1] == "zap"
        body = _run_body(_runtime())
        assert "addgroup -g 1000 zap" in body
        assert re.search(r"adduser [^;]*-u 1000 -G zap -h /home/zap\b", body)

    def test_upstream_s_environment_and_entrypoint(self) -> None:
        """`docker run <image> zap-api-scan.py` must run the script, not
        Temurin's entrypoint, and ZAP_PORT is what the HEALTHCHECK reads."""
        runtime = _runtime()
        env = " ".join(arg for word, arg in runtime if word == "ENV")
        assert "ZAP_PORT=8080" in env and "IS_CONTAINERIZED=true" in env
        assert "HOME=/home/zap/" in env and "/zap/" in env.split("PATH=", 1)[1]
        assert ("ENTRYPOINT", "[]") in runtime
        assert any(word == "HEALTHCHECK" and "${ZAP_PORT}" in arg for word, arg in runtime)


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
