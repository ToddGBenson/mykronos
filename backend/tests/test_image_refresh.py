"""The image-refresh verdict: what gets rebuilt, and when a rebuild counts as better."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mykronos import image_refresh as ir

COMPOSE = """
services:
  postgres:
    image: ${REGISTRY:-localhost:5000}/thehub-postgres:0.8.7-pg16-trixie-p20261011
    x-thehub-build:
      context: ./postgres
      refresh_arg: APT_DATE
  postgres-staging:
    image: ${REGISTRY:-localhost:5000}/thehub-postgres:0.8.7-pg16-trixie-p20261011
    x-thehub-build:
      context: ./postgres
      refresh_arg: APT_DATE
  redis:
    image: ${REGISTRY:-r:5000}/thehub-redis:7.4.11-alpine-p${THEHUB_DEMO_PATCH_DATE:-20261011}
    x-thehub-build:
      context: ./docker/apk-upgrade
      refresh_arg: APK_REFRESH
      args:
        BASE_IMAGE: redis:7.4.11-alpine@sha256:abc
  backend:
    image: ${THEHUB_IMAGE:-thehub:latest}
"""


def _write(tmp_path: Path, text: str = COMPOSE) -> Path:
    (tmp_path / "docker-compose.yml").write_text(text, encoding="utf-8")
    return tmp_path


def _trivy(*pairs: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "Results": [
            {
                "Vulnerabilities": [
                    {"VulnerabilityID": v, "PkgName": p, "Severity": s} for v, p, s in pairs
                ]
            }
        ]
    }


def test_plan_dedupes_recipes_and_rebases_the_date(tmp_path: Path) -> None:
    recipes = ir.plan(_write(tmp_path), "20261014", "192.168.0.14:5000")
    assert [r.current for r in recipes] == [
        "192.168.0.14:5000/thehub-postgres:0.8.7-pg16-trixie-p20261011",
        "192.168.0.14:5000/thehub-redis:7.4.11-alpine-p20261011",
    ]
    postgres, redis = recipes
    assert postgres.candidate.endswith("-p20261014")
    assert len(postgres.services) == 2
    assert postgres.build_args == (("APT_DATE", "20261014"),)
    assert redis.context == "docker/apk-upgrade"
    assert redis.build_args == (
        ("BASE_IMAGE", "redis:7.4.11-alpine@sha256:abc"),
        ("APK_REFRESH", "20261014"),
    )
    assert "--build-arg=APK_REFRESH=20261014" in redis.tsv()


def test_plan_reads_the_demo_date_variable_when_it_is_set(tmp_path: Path) -> None:
    recipes = ir.plan(
        _write(tmp_path), "20261020", "r:5000", env={"THEHUB_DEMO_PATCH_DATE": "20261014"}
    )
    assert "r:5000/thehub-redis:7.4.11-alpine-p20261014" in [r.current for r in recipes]


def test_plan_refuses_an_untagged_recipe(tmp_path: Path) -> None:
    bad = COMPOSE.replace("trixie-p20261011", "trixie", 1)
    with pytest.raises(ValueError, match="no -pYYYYMMDD"):
        ir.plan(_write(tmp_path, bad), "20261014", "r:5000")


def test_plan_refuses_a_malformed_date(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        ir.plan(_write(tmp_path), "2026-10-14", "r:5000")


def test_removing_findings_and_adding_none_is_improved() -> None:
    c = ir.compare(
        "a",
        "b",
        _trivy(("CVE-1", "libx", "HIGH"), ("CVE-2", "liby", "CRITICAL")),
        _trivy(("CVE-2", "liby", "CRITICAL"), ("CVE-9", "libz", "MEDIUM")),
    )
    assert c.removed == [("CVE-1", "libx")] and c.added == [] and c.kept == 1
    assert ir.decide([c]) == "improved"


def test_a_new_high_is_a_regression_even_when_the_count_falls() -> None:
    c = ir.compare(
        "a",
        "b",
        _trivy(("CVE-1", "libx", "HIGH"), ("CVE-2", "liby", "HIGH"), ("CVE-3", "libw", "HIGH")),
        _trivy(("CVE-4", "libv", "HIGH")),
    )
    assert ir.decide([c]) == "regressed"


def test_one_regressed_image_outweighs_another_improved_one() -> None:
    better = ir.compare("a", "b", _trivy(("CVE-1", "x", "HIGH")), _trivy())
    worse = ir.compare("c", "d", _trivy(), _trivy(("CVE-2", "y", "CRITICAL")))
    assert ir.decide([better, worse]) == "regressed"


def test_identical_findings_are_unchanged() -> None:
    same = _trivy(("CVE-1", "x", "HIGH"))
    assert ir.decide([ir.compare("a", "b", same, same)]) == "unchanged"


def test_a_missing_report_fails_rather_than_reading_as_clean() -> None:
    c = ir.compare("a", "b", _trivy(("CVE-1", "x", "HIGH")), None)
    assert c.error and ir.decide([c]) == "failed"
    assert ir.decide([]) == "failed"


def test_an_empty_report_fails_rather_than_reading_as_clean() -> None:
    c = ir.compare("a", "b", _trivy(("CVE-1", "x", "HIGH")), {"ArtifactName": "b"})
    assert c.error == "the candidate image's report is empty"
    assert ir.decide([c]) == "failed"


def test_cli_plan_then_decide(tmp_path: Path) -> None:
    root = _write(tmp_path)
    build_list = tmp_path / "plan.tsv"
    assert ir.main(["plan", "--root", str(root), "--date", "20261014",
                    "--registry", "r:5000", "--output", str(build_list)]) == 0
    reports = tmp_path / "reports"
    reports.mkdir()
    for line in build_list.read_text(encoding="utf-8").splitlines():
        current, candidate = line.split("\t")[:2]
        (reports / ir.report_name(current)).write_text(
            json.dumps(_trivy(("CVE-1", "libx", "HIGH"))), encoding="utf-8"
        )
        (reports / ir.report_name(candidate)).write_text(json.dumps(_trivy()), encoding="utf-8")
    verdict = tmp_path / "verdict.json"
    assert ir.main(["decide", "--plan", str(build_list), "--reports", str(reports),
                    "--output", str(verdict)]) == 0
    document = json.loads(verdict.read_text(encoding="utf-8"))
    assert document["verdict"] == "improved"
    assert len(document["images"]) == 2


REPO_ROOT = Path(__file__).resolve().parents[2]
THEHUB_PIPELINE = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "thehub.yml"


def test_the_kaniko_build_loop_keeps_its_own_shell_tools() -> None:
    """Kaniko's --cleanup deletes the container's filesystem after each build,
    and on Concourse that includes /busybox: build 2 (2026-10-14) built the
    first image, then the loop's next `sed` was "not found". A loop of builds
    must tell kaniko to leave /busybox alone."""
    import yaml

    config = yaml.safe_load(THEHUB_PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in config["jobs"] if j["name"] == "image-refresh")
    build = next(s for s in job["plan"] if s.get("task") == "build")
    script = build["config"]["run"]["args"][-1]
    assert "--cleanup" in script
    assert "--ignore-path=/busybox" in script


# -- MyKronos's own images (`x-mykronos-build`) ----------------------------------

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64

MYKRONOS_COMPOSE = """
x-worker: &worker
  image: concourse/concourse:8.3.1@sha256:aaa
  x-mykronos-build:
    context: ../images/apk-upgrade
    base: concourse/concourse:8.3.1@sha256:aaa
    publish: concourse/concourse:8.3.1
    refresh_arg: APK_REFRESH
services:
  concourse:
    image: concourse/concourse:8.3.1@sha256:aaa
    x-mykronos-build:
      context: ../images/apk-upgrade
      base: concourse/concourse:8.3.1@sha256:aaa
      publish: concourse/concourse:8.3.1
      refresh_arg: APK_REFRESH
  worker-1:
    <<: *worker
  vault:
    image: hashicorp/vault:2.1.2@sha256:bbb
    x-mykronos-build:
      context: ../images/apk-upgrade
      base: hashicorp/vault:2.1.2@sha256:bbb
      publish: hashicorp/vault:2.1.2
      refresh_arg: APK_REFRESH
      args: { RUN_AS: vault }
  minio:
    image: pgsty/silo:distroless
""".replace("sha256:aaa", DIGEST_A).replace("sha256:bbb", DIGEST_B)


def _mykronos_tree(tmp_path: Path, compose: str = MYKRONOS_COMPOSE) -> Path:
    (tmp_path / "deploy" / "concourse").mkdir(parents=True)
    (tmp_path / "deploy" / "images" / "apk-upgrade").mkdir(parents=True)
    (tmp_path / "deploy" / "images" / "apk-upgrade" / "Dockerfile").write_text(
        "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n", encoding="utf-8"
    )
    (tmp_path / "deploy" / "concourse" / "docker-compose.yml").write_text(
        compose, encoding="utf-8"
    )
    return tmp_path


def test_mykronos_plan_publishes_under_the_vendor_path(tmp_path: Path) -> None:
    recipes = ir.plan_mykronos(_mykronos_tree(tmp_path), "20261016", "r:5000")
    assert [r.candidate for r in recipes] == [
        "r:5000/concourse/concourse:8.3.1-p20261016",
        "r:5000/hashicorp/vault:2.1.2-p20261016",
    ]
    concourse, vault = recipes
    # Web and worker (through the YAML anchor) are one build.
    assert len(concourse.services) == 2
    # Before adoption the baseline is the vendor image the service runs.
    assert concourse.current == f"concourse/concourse:8.3.1@{DIGEST_A}"
    # The context is resolved from the compose file to the repository root.
    assert concourse.context == "deploy/images/apk-upgrade"
    assert vault.build_args == (
        ("RUN_AS", "vault"),
        ("BASE_IMAGE", f"hashicorp/vault:2.1.2@{DIGEST_B}"),
        ("APK_REFRESH", "20261016"),
    )


def test_mykronos_plan_refuses_two_recipes_for_one_publish(tmp_path: Path) -> None:
    clash = MYKRONOS_COMPOSE.replace(
        "    refresh_arg: APK_REFRESH\nservices:", "    refresh_arg: APT_REFRESH\nservices:", 1
    )
    with pytest.raises(ValueError, match="different recipe"):
        ir.plan_mykronos(_mykronos_tree(tmp_path, clash), "20261016", "r:5000")


@pytest.mark.parametrize(
    ("publish", "reason"),
    [
        ("hashicorp/vault", "repository:tag"),
        ("hashicorp/vault:2.1.2-p20261011", "-p date"),
    ],
)
def test_mykronos_plan_refuses_a_bad_publish(tmp_path: Path, publish: str, reason: str) -> None:
    bad = MYKRONOS_COMPOSE.replace("publish: hashicorp/vault:2.1.2", f"publish: {publish}")
    with pytest.raises(ValueError, match=reason):
        ir.plan_mykronos(_mykronos_tree(tmp_path, bad), "20261016", "r:5000")


def test_mykronos_plan_refuses_a_context_outside_the_repository(tmp_path: Path) -> None:
    bad = MYKRONOS_COMPOSE.replace(
        "context: ../images/apk-upgrade\n      base: hashicorp",
        "context: ../../../elsewhere\n      base: hashicorp",
    )
    with pytest.raises(ValueError, match="leaves the repository"):
        ir.plan_mykronos(_mykronos_tree(tmp_path, bad), "20261016", "r:5000")


def test_the_estate_recipes_keep_each_images_finding_identity() -> None:
    """The point of publishing under the vendor's path: container finding
    identity drops the registry host and the tag, so a derivative's findings
    are the image's findings and the acceptances against them keep covering
    what a rebuild did not fix. A Docker Hub official image needs `library/`
    spelled out, because the host is dropped before `library/` is added."""
    import yaml

    from mykronos.fingerprint import image_repository

    recipes = ir.plan_mykronos(REPO_ROOT, "20261016", "registry.example:5000")
    assert recipes, "no x-mykronos-build recipes in the estate's compose files"
    for name in ir.MYKRONOS_COMPOSE_FILES:
        services = yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8"))["services"]
        for service, definition in services.items():
            build = definition.get("x-mykronos-build")
            if not build:
                continue
            candidate = next(r.candidate for r in recipes if f"{name}::{service}" in r.services)
            image = str(definition["image"])
            # An image compose builds is scanned as `<registry>/<name>:<sha>`
            # by the containers lane, so that is the identity to keep.
            scanned = f"registry.example:5000/{image}" if "build" in definition else image
            assert image_repository(candidate) == image_repository(scanned), (name, service)


def test_one_regressed_image_holds_back_only_itself(tmp_path: Path) -> None:
    plan_file = tmp_path / "plan.tsv"
    plan_file.write_text("a:1\tr/a:1-p2\tctx\t\nb:1\tr/b:1-p2\tctx\t\n", encoding="utf-8")
    reports = tmp_path / "reports"
    reports.mkdir()
    findings: dict[str, list[tuple[str, str, str]]] = {
        "a:1": [("CVE-1", "liba", "HIGH")],
        "r/a:1-p2": [],
        "b:1": [("CVE-2", "libb", "HIGH")],
        "r/b:1-p2": [("CVE-3", "libb", "CRITICAL")],
    }
    for ref, pairs in findings.items():
        (reports / ir.report_name(ref)).write_text(json.dumps(_trivy(*pairs)), encoding="utf-8")
    verdict = tmp_path / "verdict.json"
    publish = tmp_path / "publish.txt"
    assert ir.main(["decide", "--plan", str(plan_file), "--reports", str(reports),
                    "--output", str(verdict), "--publish-list", str(publish)]) == 0
    document = json.loads(verdict.read_text(encoding="utf-8"))
    assert document["verdict"] == "regressed"
    assert document["publish"] == ["r/a:1-p2"]
    assert publish.read_text(encoding="utf-8") == "r/a:1-p2\n"
    assert [i["outcome"] for i in document["images"]] == ["improved", "regressed"]
    # TheHub's publish step greps for this string; a per-image outcome must
    # never satisfy it when the set as a whole did not improve.
    assert '"verdict": "improved"' not in verdict.read_text(encoding="utf-8")


MYKRONOS_PIPELINE = REPO_ROOT / "deploy" / "concourse" / "pipelines" / "mykronos.yml"


def test_mykronos_image_refresh_never_pushes_to_find_out() -> None:
    """Build to a tarball, push only the published list: the registry has
    deletes disabled, so every speculative push would stay forever."""
    import yaml

    config = yaml.safe_load(MYKRONOS_PIPELINE.read_text(encoding="utf-8"))
    job = next(j for j in config["jobs"] if j["name"] == "image-refresh")
    steps = {s.get("task"): s for s in job["plan"] if s.get("task")}
    build = steps["build"]["config"]["run"]["args"][-1]
    assert "--no-push" in build and "--tar-path" in build
    assert "--cleanup" in build and "--ignore-path=/busybox" in build
    assert "--recipes mykronos" in steps["plan"]["config"]["run"]["args"][-1]
    publish = steps["publish"]["config"]["run"]["args"][-1]
    assert "verdict/publish.txt" in publish
    # Nothing in the job deploys or touches what runs.
    text = yaml.safe_dump(job)
    assert "docker compose" not in text and "deploy.ps1" not in text


def test_mykronos_plan_refuses_a_base_that_is_not_a_digest(tmp_path: Path) -> None:
    """The Dockerfile is `FROM ${BASE_IMAGE}`, so the recipe's base IS the
    image's version: checkov cannot see it (CKV_DOCKER_7), and only this
    check stops a floating tag from being rebuilt and published."""
    floating = MYKRONOS_COMPOSE.replace(
        "base: hashicorp/vault:2.1.2@sha256:" + "b" * 64, "base: hashicorp/vault:2.1.2"
    )
    with pytest.raises(ValueError, match="vault: base .* is not pinned by digest"):
        ir.plan_mykronos(_mykronos_tree(tmp_path, floating), "20261016", "r:5000")


def test_mykronos_plan_refuses_a_missing_base(tmp_path: Path) -> None:
    missing = MYKRONOS_COMPOSE.replace(
        "      base: hashicorp/vault:2.1.2@sha256:" + "b" * 64 + "\n", ""
    )
    assert "base: hashicorp/vault" not in missing
    with pytest.raises(ValueError, match="vault: base .* is not pinned by digest"):
        ir.plan_mykronos(_mykronos_tree(tmp_path, missing), "20261016", "r:5000")


def test_every_real_recipe_base_is_a_digest() -> None:
    """The repository's own recipes, not a fixture: what the nightly job builds."""
    root = Path(__file__).resolve().parents[2]
    recipes = ir.plan_mykronos(root, "20261016", "r:5000")
    assert recipes, "no x-mykronos-build recipes found"
