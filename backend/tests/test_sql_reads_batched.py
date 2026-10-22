"""The briefing read TheHub's SQL one file at a time (TheHub #60908).

`analysers.read_sql_files` decides how much of a repository's SQL is schema
rather than code (D-138), and it fetched every `.sql` file with its own
contents call. TheHub has a migration file per schema change - several
hundred - so one `mykronos briefing` (run by deploy.ps1 after every deploy)
spent ~426 GitHub calls on it, and httpx2 logged each one at INFO.

The files are now read in batches through one GraphQL query each, and
httpx2's per-request line is DEBUG.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from mykronos import analysers, logsafe
from mykronos.github.client import FakeGitHubClient, RestGitHubClient

REPO = "ToddGBenson/TheHub"


def _estate(files: int) -> FakeGitHubClient:
    github = FakeGitHubClient()
    contents = {
        f"backend/migrations/{n:04d}_change.sql": "CREATE TABLE t (id int);"
        for n in range(files)
    }
    contents["backend/migrations/9999_fn.sql"] = (
        "CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE plpgsql;"
    )
    contents["README.md"] = "# hub"
    github.add_repo(REPO, files=contents)
    return github


class TestTheFilesAreReadInBatches:
    @pytest.mark.asyncio
    async def test_no_file_is_read_on_its_own(self) -> None:
        github = _estate(424)

        found = await analysers.read_sql_files(github, REPO)

        assert found is not None
        assert len(found) == 425
        kinds = [kind for kind, _ in github.calls]
        assert "get_file" not in kinds
        batches = kinds.count("get_files")
        assert 1 <= batches <= 5, batches
        assert len(github.calls) <= 8, "repo + tree + a handful of batches"

    @pytest.mark.asyncio
    async def test_the_split_is_unchanged(self) -> None:
        github = _estate(3)

        found = await analysers.read_sql_files(github, REPO)

        assert found is not None
        assert sum(analysers.is_procedural_sql(t) for t in found.values()) == 1

    @pytest.mark.asyncio
    async def test_a_missing_file_is_still_all_or_nothing(self) -> None:
        github = _estate(3)

        async def gone(*_a: Any, **_k: Any) -> dict[str, str | None]:
            return {"backend/migrations/0000_change.sql": None}

        github.get_files = gone  # type: ignore[method-assign]

        assert await analysers.read_sql_files(github, REPO) is None


class FakeRest(RestGitHubClient):
    """The live client with its transport replaced: only the batching and the
    response handling are under test."""

    def __init__(self, blobs: dict[str, dict[str, Any] | None]) -> None:
        self.blobs = blobs
        self.queries: list[dict[str, Any]] = []
        self.fallbacks: list[str] = []

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        assert (method, path) == ("POST", "/graphql")
        variables = kwargs["json"]["variables"]
        self.queries.append(variables)
        repo: dict[str, Any] = {}
        for key, expression in variables.items():
            if key.startswith("e"):
                repo["f" + key[1:]] = self.blobs.get(expression.split(":", 1)[1])
        return {"data": {"repository": repo}}

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        self.fallbacks.append(path)
        return "-- fetched whole"


class TestTheGraphqlBatch:
    @pytest.mark.asyncio
    async def test_paths_are_batched(self) -> None:
        paths = [f"m/{n}.sql" for n in range(250)]
        client = FakeRest({p: {"text": p, "isTruncated": False} for p in paths})

        got = await client.get_files(REPO, paths, "develop")

        assert got == {p: p for p in paths}
        assert len(client.queries) == 3
        assert client.queries[0]["owner"] == "ToddGBenson"
        assert client.queries[0]["name"] == "TheHub"
        assert client.queries[0]["e0"] == "develop:m/0.sql"

    @pytest.mark.asyncio
    async def test_a_missing_path_is_none(self) -> None:
        client = FakeRest({})

        assert await client.get_files(REPO, ["gone.sql"], "main") == {"gone.sql": None}

    @pytest.mark.asyncio
    async def test_a_truncated_blob_is_fetched_whole(self) -> None:
        client = FakeRest({"big.sql": {"text": "part", "isTruncated": True}})

        got = await client.get_files(REPO, ["big.sql"], "main")

        assert got == {"big.sql": "-- fetched whole"}
        assert client.fallbacks == ["big.sql"]


class TestTheRequestLogIsDebug:
    def test_httpx2_request_lines_are_not_info(self, caplog) -> None:
        logsafe.demote_http_request_logs()
        caplog.set_level(logging.INFO)

        logging.getLogger("httpx2").info('HTTP Request: GET https://api.github.com/x "200"')

        assert not [r for r in caplog.records if r.name == "httpx2"]

    def test_they_still_show_at_debug(self, caplog) -> None:
        logsafe.demote_http_request_logs()
        caplog.set_level(logging.DEBUG)

        logging.getLogger("httpx2").info("HTTP Request: GET x")

        [record] = [r for r in caplog.records if r.name == "httpx2"]
        assert record.levelno == logging.DEBUG

    def test_warnings_are_untouched(self, caplog) -> None:
        logsafe.demote_http_request_logs()
        caplog.set_level(logging.INFO)

        logging.getLogger("httpx2").warning("retrying")

        assert [r.levelno for r in caplog.records if r.name == "httpx2"] == [logging.WARNING]

    def test_installing_twice_adds_one_filter(self) -> None:
        logsafe.demote_http_request_logs()
        logsafe.demote_http_request_logs()

        filters = logging.getLogger("httpx2").filters
        assert sum(isinstance(f, logsafe.DemoteToDebug) for f in filters) == 1
