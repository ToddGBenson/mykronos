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
