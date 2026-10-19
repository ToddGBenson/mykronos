"""Patchwork's bump-image-date fixer (`patchwork/image_date.py`).

A container finding in a patched `<name>:<version>-p<YYYYMMDD>` image becomes
one draft pull request per image and date, moving the compose pins to a newer
package snapshot - but only when image-refresh has already published that
snapshot to the registry. The fixtures name no real registry: the host is a
reserved `.test` name, and the compose files are this estate's shape, not its
content.
"""

from __future__ import annotations

import asyncio
import json

import httpx2
import pytest

from mykronos.patchwork import fixers, image_date
from mykronos.patchwork.image_date import PatchedImage, parse_image, propose, rewrite
from tests.conftest import REPO, finding_payload, issue_token, post_findings, post_scan
from tests.test_onboarding import onboard

HOST = "registry.example.test:5000"
OLD = f"{HOST}/hub-redis:7.4.11-alpine-p20261011"

PROD = """services:
  redis:
    # `x-thehub-build` and pushes the pinned tag; bump the tag to refresh.
    image: ${REGISTRY:-localhost:5000}/hub-redis:7.4.11-alpine-p20261011
    x-thehub-build:
      context: ./docker/apk-upgrade
  redis-staging:
    image: "${REGISTRY:-localhost:5000}/hub-redis:7.4.11-alpine-p20261011"
    x-thehub-build:
      context: ./docker/apk-upgrade
  nginx:
    image: ${REGISTRY:-localhost:5000}/hub-nginx:1.31.6-alpine-p20261011
    x-thehub-build:
      context: ./docker/apk-upgrade
"""

DEMO = """services:
  demo-redis:
    image: ${REGISTRY:-localhost:5000}/hub-redis:7.4.11-alpine-p${THEHUB_DEMO_PATCH_DATE:-20261011}
    x-thehub-build:
      context: ./docker/apk-upgrade
"""

FILES = {"docker-compose.yml": PROD, "docker-compose.demo.yml": DEMO}
TAGS = [
    "7.4.11-alpine-p20261011",
    "7.4.11-alpine-p20261014",
    "7.4.11-alpine-p20261019",
]


def image() -> PatchedImage:
    parsed = parse_image(OLD)
    assert parsed is not None
    return parsed


def member(finding_id: str, rule: str, package: str = "busybox") -> dict:
    return {
        "finding_id": finding_id,
        "rule_id": rule,
        "title": f"{rule} in {package}",
        "severity": "high",
        "package_name": package,
        "package_version": "1.37.0-r18",
        "capability": "containers",
        "raw_finding_json": {"image": OLD},
    }


class TestParse:
    def test_a_patched_registry_image_parses(self) -> None:
        assert image() == PatchedImage(HOST, "hub-redis", "7.4.11-alpine", "20261011")

    @pytest.mark.parametrize(
        "reference",
        [
            "hub-redis:7.4.11-alpine-p20261011",  # no host: Docker Hub
            "docker.io/library/redis:7.4.11-alpine-p20261011",  # public
            "ghcr.io/example/zap:weekly-p20261017",  # public
            f"{HOST}/hub-redis:7.4.11-alpine",  # no date
            f"{HOST}/hub-redis:7.4.11-alpine-p20261399",  # not a date
        ],
    )
    def test_anything_else_does_not(self, reference: str) -> None:
        assert parse_image(reference) is None


class TestTheFixApplies:
    def test_newer_tag_moves_every_pin_and_the_matching_demo_default(self) -> None:
        plan = propose(
            image(),
            tags=TAGS,
            files=FILES,
            findings=[member("f1", "CVE-2026-0001")],
            observed_in_newer=None,
        )

        assert not isinstance(plan, str), plan
        assert plan.new_date == "20261019", "the newest strictly newer tag wins"
        after_prod = PROD.replace(
            "hub-redis:7.4.11-alpine-p20261011", "hub-redis:7.4.11-alpine-p20261019"
        )
        after_demo = DEMO.replace(":-20261011}", ":-20261019}")
        assert plan.fix.files == {
            "docker-compose.yml": after_prod,
            "docker-compose.demo.yml": after_demo,
        }
        # Nothing else moved: the nginx pin and the comment are untouched.
        assert "hub-nginx:1.31.6-alpine-p20261011" in plan.fix.files["docker-compose.yml"]
        assert [c.kind for c in plan.rewrite.changes] == ["demo default", "pin", "pin"]

    def test_a_demo_default_that_differs_from_production_is_left_alone(self) -> None:
        demo = DEMO.replace(":-20261011}", ":-20261014}")
        plan = propose(
            image(),
            tags=TAGS,
            files={"docker-compose.yml": PROD, "docker-compose.demo.yml": demo},
            findings=[member("f1", "CVE-2026-0001")],
            observed_in_newer=None,
        )

        assert not isinstance(plan, str), plan
        assert set(plan.fix.files) == {"docker-compose.yml"}
        assert len(plan.rewrite.untouched_defaults) == 1
        body = image_date.render_pr_body(plan)
        assert "Left alone: `docker-compose.demo.yml:3`" in body

    def test_crlf_files_keep_their_line_endings(self) -> None:
        crlf = {k: v.replace("\n", "\r\n") for k, v in FILES.items()}
        edit = rewrite(crlf, image(), "20261019")

        assert not isinstance(edit, str), edit
        for text in edit.files.values():
            assert "\r\n" in text and "\n" not in text.replace("\r\n", "")

    def test_the_pr_body_says_what_a_reviewer_needs(self) -> None:
        plan = propose(
            image(),
            tags=TAGS,
            files=FILES,
            findings=[member("f1", "CVE-2026-0001"), member("f2", "CVE-2026-0002")],
            observed_in_newer=None,
        )
        assert not isinstance(plan, str)
        body = image_date.render_pr_body(plan)

        assert f"Old: `{OLD}`" in body
        assert f"New: `{HOST}/hub-redis:7.4.11-alpine-p20261019`" in body
        assert "CVE-2026-0001" in body and "CVE-2026-0002" in body
        assert "only on an `improved` verdict" in body
        assert "publish-patched-images.sh" in body and "already present" in body
        assert "Production moves only when a person merges this" in body
        assert "Not verified against a scan" in body
        assert plan.fix.confidence < 1.0


class TestItRefuses:
    def _refusal(self, *, tags=TAGS, files=FILES) -> str:
        plan = propose(
            image(),
            tags=tags,
            files=files,
            findings=[member("f1", "CVE-2026-0001")],
            observed_in_newer=None,
        )
        assert isinstance(plan, str), "expected a refusal"
        return plan

    def test_no_newer_tag(self) -> None:
        assert "no tag" in self._refusal(tags=["7.4.11-alpine-p20261011"])

    def test_a_newer_tag_with_a_different_prefix(self) -> None:
        reason = self._refusal(
            tags=["7.4.12-alpine-p20261019", "7.4.11-trixie-p20261019", "7.4.11-alpine"]
        )
        assert "no tag" in reason

    def test_only_older_tags(self) -> None:
        assert "no tag" in self._refusal(tags=["7.4.11-alpine-p20261001"])

    def test_the_old_tag_string_is_absent(self) -> None:
        files = {
            "docker-compose.yml": PROD.replace("-p20261011", "-p20261014"),
            "docker-compose.demo.yml": DEMO,
        }
        reason = self._refusal(files=files)
        assert "No compose file pins hub-redis:7.4.11-alpine-p20261011 exactly" in reason

    def test_a_demo_default_alone_is_not_a_production_pin(self) -> None:
        assert "No compose file pins" in self._refusal(
            files={"docker-compose.demo.yml": DEMO}
        )

    def test_production_pins_that_disagree(self) -> None:
        files = {
            "docker-compose.yml": PROD.replace(
                '"${REGISTRY:-localhost:5000}/hub-redis:7.4.11-alpine-p20261011"',
                '"${REGISTRY:-localhost:5000}/hub-redis:7.4.11-alpine-p20261014"',
            )
        }
        assert "disagree" in self._refusal(files=files)

    def test_a_digest_pinned_tag(self) -> None:
        files = {
            "docker-compose.yml": PROD.replace(
                "alpine-p20261011\n", "alpine-p20261011@sha256:" + "a" * 64 + "\n", 1
            )
        }
        assert "pinned by digest" in self._refusal(files=files)

    def test_a_line_on_another_registry_is_not_this_image(self) -> None:
        files = {"docker-compose.yml": PROD.replace("${REGISTRY:-localhost:5000}/", "")}
        assert "No compose file pins" in self._refusal(files=files)


class TestTheLakeIsConsulted:
    def test_a_finding_the_newer_tag_still_carries_is_not_claimed(self) -> None:
        plan = propose(
            image(),
            tags=TAGS,
            files=FILES,
            findings=[member("f1", "CVE-2026-0001"), member("f2", "CVE-2026-0002")],
            observed_in_newer={("CVE-2026-0002", "busybox")},
        )

        assert not isinstance(plan, str)
        assert [f["finding_id"] for f in plan.clears] == ["f1"]
        assert [f["finding_id"] for f in plan.persists] == ["f2"]
        assert plan.verified and plan.fix.confidence == 1.0
        assert "still carries (1)" in image_date.render_pr_body(plan)

    def test_nothing_to_clear_means_no_pull_request(self) -> None:
        plan = propose(
            image(),
            tags=TAGS,
            files=FILES,
            findings=[member("f1", "CVE-2026-0001")],
            observed_in_newer={("CVE-2026-0001", "busybox")},
        )
        assert isinstance(plan, str) and "would clear nothing" in plan


class TestTheRegistryRead:
    def test_tags_are_paged_and_a_missing_repository_is_empty(self) -> None:
        seen: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(str(request.url))
            if "missing" in request.url.path:
                return httpx2.Response(404)
            if "last=" in str(request.url):
                return httpx2.Response(200, json={"tags": ["b"]})
            return httpx2.Response(
                200,
                json={"tags": ["a"]},
                headers={"Link": '</v2/hub-redis/tags/list?n=1000&last=a>; rel="next"'},
            )

        client = image_date.RegistryTags(
            "http://registry.example.test:5000", transport=httpx2.MockTransport(handler)
        )

        assert asyncio.run(client.tags("hub-redis")) == ["a", "b"]
        assert asyncio.run(client.tags("missing")) == []
        assert seen[0] == "http://registry.example.test:5000/v2/hub-redis/tags/list?n=1000"

    def test_an_unreachable_registry_is_none_not_empty(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        client = image_date.RegistryTags(
            "http://registry.example.test:5000", transport=httpx2.MockTransport(handler)
        )
        assert asyncio.run(client.tags("hub-redis")) is None

    def test_unconfigured_is_none(self) -> None:
        class Unset:
            patchwork_image_registry = ""

        assert image_date.RegistryTags.from_settings(Unset()) is None


class TestItIsRegistered:
    def test_it_is_in_the_fixer_table_and_generate_never_runs_it(self) -> None:
        entry = dict(fixers.FIXERS)["bump-image-date"]
        assert isinstance(entry, fixers.RepositoryFixer)
        assert entry.module == image_date.__name__
        finding = member("f1", "CVE-2026-0001")
        assert fixers.generate(finding, PROD) is None


# --------------------------------------------------------------------------
# Through the pipeline: one pull request per image and date
# --------------------------------------------------------------------------


class FakeTags:
    def __init__(self, tags: dict[str, list[str]]) -> None:
        self._tags = tags
        self.asked: list[str] = []

    async def tags(self, repository: str) -> list[str] | None:
        self.asked.append(repository)
        return self._tags.get(repository, [])


def container_finding(rule: str, package: str, image_ref: str = OLD, **overrides):
    payload = {
        "rule_id": rule,
        "title": f"{rule} in {package}",
        "severity": "high",
        "file_path": "hub-redis",
        "line_start": None,
        "line_end": None,
        "symbol": None,
        "code_snippet": None,
        "package_name": package,
        "package_version": "1.0",
        "raw_finding_json": {"image": image_ref, "fixed_version": "1.1"},
    }
    payload.update(overrides)
    return finding_payload(**payload)


@pytest.fixture
def containers_auth(client) -> dict[str, str]:
    token = issue_token(client, REPO, "containers", "patchwork")
    return {"Authorization": f"Bearer {token}"}


def seed_containers(client, auth, run_compaction, findings) -> None:
    post_scan(
        client, auth, scan_run_id="scan-c1", capability="containers", tool_name="trivy",
        finding_count=len(findings),
    )
    response = post_findings(client, auth, findings, scan_run_id="scan-c1", capability="containers")
    assert response.status_code in (200, 201, 202), response.text
    run_compaction()


def put_compose(github) -> None:
    repo = github.repos[REPO]
    for path, text in FILES.items():
        repo.files[path] = text
        repo.branches.setdefault("main", {})[path] = text


class TestThroughThePipeline:
    def test_several_findings_in_one_image_open_one_pull_request(
        self, client, admin_auth, containers_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_compose(github)
        registry = FakeTags({"hub-redis": TAGS})
        client.app.state.image_registry = registry
        seed_containers(
            client,
            containers_auth,
            run_compaction,
            [
                container_finding("CVE-2026-0001", "busybox"),
                container_finding("CVE-2026-0002", "musl"),
                container_finding("CVE-2026-0003", "zlib"),
            ],
        )

        body = client.post("/api/patchwork/run", json={}, headers=containers_auth).json()

        assert body["draft_prs_opened"] == 1, body
        assert body["by_stage"].get("pr_opened") == 3, body
        assert registry.asked == ["hub-redis"], "one registry read per image"
        pulls = github.repos[REPO].pull_requests
        assert len(pulls) == 1 and pulls[0].draft is True
        branch = github.repos[REPO].branches[pulls[0].head_branch]
        assert "hub-redis:7.4.11-alpine-p20261019" in branch["docker-compose.yml"]
        assert ":-20261019}" in branch["docker-compose.demo.yml"]
        text = github.pull_request_bodies[pulls[0].number]
        for rule in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"):
            assert rule in text

        run_compaction()
        rows = client.app.state.catalog.query(
            "SELECT DISTINCT fix_pr_number, fixer_name FROM remediation_events "
            "WHERE pipeline_stage_reached = 'pr_opened'"
        )
        assert rows == [(pulls[0].number, "bump-image-date")]

    def test_a_second_run_does_not_open_a_second_pull_request(
        self, client, admin_auth, containers_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_compose(github)
        client.app.state.image_registry = FakeTags({"hub-redis": TAGS})
        seed_containers(
            client, containers_auth, run_compaction, [container_finding("CVE-2026-0001", "busybox")]
        )

        client.post("/api/patchwork/run", json={}, headers=containers_auth)
        again = client.post("/api/patchwork/run", json={}, headers=containers_auth).json()

        assert again["draft_prs_opened"] == 0, again
        assert len(github.repos[REPO].pull_requests) == 1

    def test_no_newer_tag_records_the_reason_and_opens_nothing(
        self, client, admin_auth, containers_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_compose(github)
        client.app.state.image_registry = FakeTags({"hub-redis": ["7.4.11-alpine-p20261011"]})
        seed_containers(
            client, containers_auth, run_compaction, [container_finding("CVE-2026-0001", "busybox")]
        )

        body = client.post("/api/patchwork/run", json={}, headers=containers_auth).json()
        run_compaction()

        assert body["draft_prs_opened"] == 0
        assert github.repos[REPO].pull_requests == []
        (rationale,) = client.app.state.catalog.query(
            "SELECT rationale FROM remediation_events"
        )[0]
        assert "has not published a strictly better rebuild" in rationale

    def test_an_unconfigured_registry_says_so(
        self, client, admin_auth, containers_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_compose(github)
        client.app.state.image_registry = None
        seed_containers(
            client, containers_auth, run_compaction, [container_finding("CVE-2026-0001", "busybox")]
        )

        client.post("/api/patchwork/run", json={}, headers=containers_auth)
        run_compaction()

        (rationale,) = client.app.state.catalog.query(
            "SELECT rationale FROM remediation_events"
        )[0]
        assert "MYKRONOS_PATCHWORK_IMAGE_REGISTRY" in rationale

    def test_the_preview_proposes_without_opening(
        self, client, admin_auth, containers_auth, run_compaction, github
    ) -> None:
        onboard(client, admin_auth)
        put_compose(github)
        client.app.state.image_registry = FakeTags({"hub-redis": TAGS})
        seed_containers(
            client, containers_auth, run_compaction, [container_finding("CVE-2026-0001", "busybox")]
        )
        (finding_id,) = client.app.state.catalog.query("SELECT finding_id FROM findings")[0]

        response = client.post(
            f"/api/patchwork/findings/{finding_id}/preview", headers=admin_auth
        )

        assert response.status_code == 200, response.text
        payload = response.json()
        assert "bump-image-date" in json.dumps(payload)
        assert github.repos[REPO].pull_requests == []
