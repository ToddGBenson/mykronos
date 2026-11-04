"""bump-base-image: a newer base in the same series, pinned by a verified
digest, or no pull request at all (TheHub #60746)."""

from __future__ import annotations

import hashlib
import json

import httpx2
import pytest

from mykronos.patchwork import base_image
from tests.conftest import REPO, finding_payload, post_findings, post_scan
from tests.test_onboarding import onboard
from tests.test_patchwork import patchwork_auth  # noqa: F401 - fixture

DOCKERFILE = "backend/Dockerfile"
HOST = "registry.example.test:5000"
CONTENT = (
    "# syntax=docker/dockerfile:1\n"
    f"FROM --platform=linux/amd64 {HOST}/library/python:3.12.4-slim AS build\n"
    "RUN pip install --no-cache-dir -r requirements.txt\n"
    f"FROM {HOST}/library/python:3.12.4-slim\n"
    "COPY --from=build /app /app\n"
)
TAGS = ["3.12.4-slim", "3.12.5-slim", "3.12.7-slim", "3.12.9-alpine", "3.13.0-slim", "latest"]
MANIFEST = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json"})
DIGEST = "sha256:" + hashlib.sha256(MANIFEST.encode()).hexdigest()


def finding(line: int = 2, **overrides):
    record = {
        "finding_id": "f" * 64,
        "capability": "iac",
        "rule_id": "DS-0001",
        "file_path": DOCKERFILE,
        "line_start": line,
    }
    record.update(overrides)
    return record


class TestTheSeries:
    def test_a_later_patch_in_the_same_minor_and_variant(self) -> None:
        assert base_image.newer_tag("3.12.4-slim", TAGS) == "3.12.7-slim"

    def test_never_a_new_minor_or_another_variant(self) -> None:
        assert base_image.newer_tag("3.12.7-slim", TAGS) is None
        assert base_image.newer_tag("3.12.9-alpine", ["3.12.10-slim", "3.13.1-alpine"]) is None

    def test_a_patched_image_moves_by_date(self) -> None:
        tags = ["7.4.11-alpine-p20261011", "7.4.11-alpine-p20261020", "7.4.12-alpine-p20261030"]
        assert base_image.newer_tag("7.4.11-alpine-p20261011", tags) == "7.4.11-alpine-p20261020"

    def test_a_moving_tag_has_no_series(self) -> None:
        assert base_image.newer_tag("latest", TAGS) is None
        assert base_image.newer_tag("3.12", TAGS) is None


class TestTheFromLine:
    def test_it_reads_the_line_the_finding_names(self) -> None:
        image = base_image.from_line(finding(line=4), CONTENT)

        assert isinstance(image, base_image.BaseImage)
        assert (image.repository, image.tag, image.line) == ("library/python", "3.12.4-slim", 4)

    def test_not_a_dockerfile_or_not_a_from_line_does_not_apply(self) -> None:
        assert base_image.from_line(finding(file_path="src/app.py"), CONTENT) is None
        assert base_image.from_line(finding(line=3), CONTENT) is None

    def test_a_public_image_is_refused_with_a_reason(self) -> None:
        content = "FROM python:3.12.4-slim\n"
        refusal = base_image.from_line(finding(line=1), content)

        assert isinstance(refusal, str) and "not on the registry" in refusal


class TestTheEdit:
    def test_only_the_named_line_moves_and_it_is_pinned_by_digest(self) -> None:
        image = base_image.from_line(finding(line=2), CONTENT)
        assert isinstance(image, base_image.BaseImage)

        fix = base_image.propose(image, CONTENT, tags=TAGS, digest=DIGEST)

        assert not isinstance(fix, str)
        after = fix.files[DOCKERFILE].splitlines(keepends=True)
        before = CONTENT.splitlines(keepends=True)
        assert [i for i, (a, b) in enumerate(zip(before, after, strict=True)) if a != b] == [1]
        assert after[1] == (
            f"FROM --platform=linux/amd64 {HOST}/library/python:3.12.7-slim@{DIGEST} AS build\n"
        )

    def test_an_existing_digest_is_replaced_not_kept(self) -> None:
        content = f"FROM {HOST}/library/python:3.12.4-slim@sha256:{'a' * 64}\n"
        image = base_image.from_line(finding(line=1), content)
        assert isinstance(image, base_image.BaseImage)

        fix = base_image.propose(image, content, tags=TAGS, digest=DIGEST)

        assert not isinstance(fix, str)
        assert fix.files[DOCKERFILE] == f"FROM {HOST}/library/python:3.12.7-slim@{DIGEST}\n"

    @pytest.mark.parametrize("digest", [None, "sha256:short", "md5:" + "0" * 32])
    def test_no_verified_digest_means_no_fix(self, digest) -> None:
        image = base_image.from_line(finding(line=2), CONTENT)
        assert isinstance(image, base_image.BaseImage)

        refusal = base_image.propose(image, CONTENT, tags=TAGS, digest=digest)

        assert isinstance(refusal, str) and "no pull request" in refusal

    def test_an_unreadable_tag_listing_means_no_fix(self) -> None:
        image = base_image.from_line(finding(line=2), CONTENT)
        assert isinstance(image, base_image.BaseImage)

        assert isinstance(base_image.propose(image, CONTENT, tags=None, digest=DIGEST), str)


class TestTheDigestRead:
    @staticmethod
    def _client(handler) -> base_image.RegistryDigests:
        return base_image.RegistryDigests(
            f"http://{HOST}", transport=httpx2.MockTransport(handler)
        )

    async def test_a_digest_matching_the_bytes_is_returned(self) -> None:
        seen: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(request)
            return httpx2.Response(
                200, content=MANIFEST.encode(), headers={"Docker-Content-Digest": DIGEST}
            )

        assert await self._client(handler).digest("library/python", "3.12.7-slim") == DIGEST
        assert seen[0].url.path == "/v2/library/python/manifests/3.12.7-slim"
        assert "application/vnd.oci.image.index.v1+json" in seen[0].headers["accept"]

    async def test_a_header_the_bytes_do_not_hash_to_is_refused(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                200, content=b"{}", headers={"Docker-Content-Digest": DIGEST}
            )

        assert await self._client(handler).digest("library/python", "3.12.7-slim") is None

    async def test_no_header_is_refused(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=MANIFEST.encode())

        assert await self._client(handler).digest("library/python", "3.12.7-slim") is None

    @pytest.mark.parametrize("status", [401, 404, 500])
    async def test_a_failed_lookup_is_refused(self, status: int) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(status)

        assert await self._client(handler).digest("library/python", "3.12.7-slim") is None

    async def test_an_unreachable_registry_is_refused(self) -> None:
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        assert await self._client(handler).digest("library/python", "3.12.7-slim") is None


class FakeTags:
    def __init__(self, tags: dict[str, list[str]] | None) -> None:
        self._tags = tags

    async def tags(self, repository: str) -> list[str] | None:
        return None if self._tags is None else self._tags.get(repository, [])


class FakeDigests:
    def __init__(self, digest: str | None) -> None:
        self._digest = digest
        self.asked: list[tuple[str, str]] = []

    async def digest(self, repository: str, tag: str) -> str | None:
        self.asked.append((repository, tag))
        return self._digest


class TestThroughThePipeline:
    def _seed(self, client, admin_auth, auth, run_compaction, github) -> None:
        onboard(client, admin_auth)
        repo = github.repos[REPO]
        repo.files[DOCKERFILE] = CONTENT
        repo.branches.setdefault("main", {})[DOCKERFILE] = CONTENT
        post_scan(client, auth, scan_run_id="scan-df", capability="sast", tool_name="semgrep")
        payload = finding_payload(
            rule_id="dockerfile.security.base-image-outdated",
            title="Base image has a newer patch release",
            severity="high",
            file_path=DOCKERFILE,
            line_start=4,
            line_end=4,
            symbol=None,
            code_snippet=None,
            raw_finding_json={"ruleId": "dockerfile.security.base-image-outdated"},
        )
        response = post_findings(client, auth, [payload], scan_run_id="scan-df")
        assert response.status_code in (200, 201, 202), response.text
        run_compaction()

    def test_a_verified_digest_opens_one_draft_pinned_by_digest(
        self, client, admin_auth, patchwork_auth, run_compaction, github  # noqa: F811
    ) -> None:
        self._seed(client, admin_auth, patchwork_auth, run_compaction, github)
        client.app.state.image_registry = FakeTags({"library/python": TAGS})
        digests = FakeDigests(DIGEST)
        client.app.state.image_digests = digests

        body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()

        assert body["draft_prs_opened"] == 1, body
        assert digests.asked == [("library/python", "3.12.7-slim")]
        (pr,) = github.repos[REPO].pull_requests
        assert pr.draft is True
        dockerfile = github.repos[REPO].branches[pr.head_branch][DOCKERFILE]
        assert dockerfile.splitlines()[3] == f"FROM {HOST}/library/python:3.12.7-slim@{DIGEST}"
        assert dockerfile.splitlines()[1] == CONTENT.splitlines()[1], "only the named FROM moves"

    @pytest.mark.parametrize(
        ("tags", "digest"),
        [
            (None, DIGEST),  # the tag listing failed
            ({"library/python": TAGS}, None),  # the digest lookup failed or did not verify
        ],
    )
    def test_a_registry_lookup_failure_opens_nothing(
        self, tags, digest, client, admin_auth, patchwork_auth, run_compaction, github  # noqa: F811
    ) -> None:
        self._seed(client, admin_auth, patchwork_auth, run_compaction, github)
        client.app.state.image_registry = FakeTags(tags)
        client.app.state.image_digests = FakeDigests(digest)

        body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()

        assert body["draft_prs_opened"] == 0, body
        assert github.repos[REPO].pull_requests == []
        assert not [c for c in github.calls if c[0] in ("create_branch", "commit_files")]
        assert body["by_stage"].get("no_fix_available") == 1, body
        run_compaction()
        rows = client.app.state.catalog.query(
            "SELECT pipeline_stage_reached, rationale FROM remediation_events"
        )
        assert rows and rows[0][0] == "no_fix_available"
        assert "no pull request" in rows[0][1]

    def test_no_registry_configured_opens_nothing(
        self, client, admin_auth, patchwork_auth, run_compaction, github  # noqa: F811
    ) -> None:
        self._seed(client, admin_auth, patchwork_auth, run_compaction, github)
        client.app.state.image_registry = None
        client.app.state.image_digests = None

        body = client.post("/api/patchwork/run", json={}, headers=patchwork_auth).json()

        assert body["draft_prs_opened"] == 0, body
        assert github.repos[REPO].pull_requests == []
