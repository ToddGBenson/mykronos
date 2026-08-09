"""GitHub API surface the platform actually uses (spec 02, spec 03).

Kept deliberately narrow. Only the operations the Workflow Installer and
onboarding need appear here, so the App's permission set stays reviewable
against a short list rather than against "whatever the client library can do".

`FakeGitHubClient` is a real in-memory implementation, not a stub of
convenience: it enforces the same preconditions the API does — a workflow
file write requires `workflows: write`, a secret write requires
`secrets: write`, a branch must exist before you commit to it. Installer
logic tested against it is tested against the rules that actually bite.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx2

from mykronos.github.auth import AppCredentials, InstallationTokenCache
from mykronos.github.secrets import RepoPublicKey
from mykronos.schemas import utcnow

GITHUB_API = "https://api.github.com"

#: The permission set spec 02 §4 requires, after D-008. `workflows` and
#: `secrets` were both missing from the original spec and are both mandatory:
#: without them the installer cannot commit a workflow file or provision the
#: ingestion secret.
REQUIRED_PERMISSIONS = {
    "contents": "write",
    "workflows": "write",
    "secrets": "write",
    "pull_requests": "write",
    "checks": "write",
    "actions": "write",
    "metadata": "read",
}

WORKFLOW_PATH_PREFIX = ".github/workflows/"


class GitHubError(RuntimeError):
    """A GitHub API call failed in a way the caller must handle."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class PermissionDeniedError(GitHubError):
    """The installation lacks a permission the operation requires.

    Raised separately because this is the D-008 failure mode: it means the App
    is registered wrong, and no amount of retrying will help.
    """


@dataclass
class FileChange:
    """One staged file addition, update or deletion."""

    path: str
    content: str | None
    """None means delete."""

    @property
    def is_delete(self) -> bool:
        return self.content is None

    @property
    def is_workflow(self) -> bool:
        return self.path.startswith(WORKFLOW_PATH_PREFIX)


@dataclass
class PullRequest:
    number: int
    url: str
    head_branch: str
    state: str = "open"
    merged: bool = False
    #: Patchwork's pull requests are always draft (spec 08 §3). Recorded on
    #: the object so a test can assert it rather than trusting the caller.
    draft: bool = False


class GitHubClient(Protocol):
    """What the platform needs from GitHub. Nothing more."""

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]: ...

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        """Return file contents, or None if it does not exist."""

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None: ...

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        """Commit staged changes to a branch. Returns the commit SHA."""

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None: ...

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest: ...

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest: ...

    # NOTE: there is deliberately no `merge_pull_request` here, and there must
    # never be one added casually.
    #
    # spec 08 §3 makes "Patchwork never merges anything" a hard constraint.
    # That cannot be enforced by GitHub permissions — merging needs
    # `contents: write`, which the App already holds so the Workflow Installer
    # can commit workflow files at all (D-008). The constraint is enforced
    # here instead: there is no method to call, in this protocol or in either
    # implementation, and `tests/test_patchwork.py` fails if one appears.
    #
    # Adding merge support is therefore a visible change to a shared interface
    # with a failing test attached, rather than a config flag somebody flips.

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        """Close without merging, explaining why in a comment."""

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey: ...

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None: ...

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None: ...

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        """Publish a Check Run. Returns its id.

        This is the only Mykronos surface most developers ever see, so the
        summary is the product, not a log line.
        """

    async def get_installation(self, installation_id: int) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Fake
# ---------------------------------------------------------------------------


@dataclass
class FakeRepo:
    full_name: str
    default_branch: str = "main"
    files: dict[str, str] = field(default_factory=dict)
    branches: dict[str, dict[str, str]] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    pull_requests: list[PullRequest] = field(default_factory=list)
    check_runs: list[dict[str, Any]] = field(default_factory=list)


class FakeGitHubClient:
    """In-memory GitHub, enforcing the preconditions that actually bite.

    `permissions` defaults to the correct post-D-008 set. Narrowing it is how
    the tests prove the installer fails loudly — and says why — when the App
    is registered without `workflows: write` or `secrets: write`.
    """

    def __init__(
        self,
        repos: dict[str, FakeRepo] | None = None,
        permissions: dict[str, str] | None = None,
    ) -> None:
        self.repos = repos or {}
        self.permissions = dict(REQUIRED_PERMISSIONS if permissions is None else permissions)
        self.calls: list[tuple[str, str]] = []
        #: Bodies by PR number, so a test can assert what a reviewer would
        #: actually read rather than only that a PR was opened.
        self.pull_request_bodies: dict[int, str] = {}
        self._next_pr_number = 1
        self.installations: dict[int, dict[str, Any]] = {}

    # -- helpers --------------------------------------------------------

    def add_repo(self, full_name: str, **kwargs: Any) -> FakeRepo:
        repo = FakeRepo(full_name=full_name, **kwargs)
        repo.branches.setdefault(repo.default_branch, dict(repo.files))
        self.repos[full_name] = repo
        return repo

    def _repo(self, full_name: str) -> FakeRepo:
        try:
            return self.repos[full_name]
        except KeyError:
            raise GitHubError(f"Repository {full_name} not found", status=404) from None

    def _require(self, permission: str, level: str, operation: str) -> None:
        held = self.permissions.get(permission)
        if held != level and not (level == "read" and held == "write"):
            raise PermissionDeniedError(
                f"{operation} requires '{permission}: {level}'. The Mykronos GitHub App "
                f"holds '{permission}: {held or 'none'}'. See spec 02 §4 — the App must be "
                "re-registered with the corrected permission set (D-008).",
                status=403,
            )

    # -- protocol -------------------------------------------------------

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]:
        self.calls.append(("get_repo", repo_full_name))
        repo = self._repo(repo_full_name)
        return {"full_name": repo.full_name, "default_branch": repo.default_branch}

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        self.calls.append(("get_file", f"{repo_full_name}:{path}@{ref}"))
        repo = self._repo(repo_full_name)
        return repo.branches.get(ref, repo.files).get(path)

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None:
        self.calls.append(("create_branch", f"{repo_full_name}:{branch}"))
        self._require("contents", "write", "Creating a branch")
        repo = self._repo(repo_full_name)
        if from_ref not in repo.branches:
            raise GitHubError(f"Base ref {from_ref} does not exist", status=422)
        repo.branches[branch] = dict(repo.branches[from_ref])

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        self.calls.append(("commit_files", f"{repo_full_name}:{branch}"))
        self._require("contents", "write", "Committing files")
        if any(change.is_workflow for change in changes):
            # The D-008 failure: GitHub gates .github/workflows/ behind its own
            # permission and refuses a contents-only token for those paths.
            self._require("workflows", "write", "Committing a GitHub Actions workflow file")

        repo = self._repo(repo_full_name)
        if branch not in repo.branches:
            raise GitHubError(f"Branch {branch} does not exist", status=422)

        tree = repo.branches[branch]
        for change in changes:
            if change.is_delete:
                tree.pop(change.path, None)
            else:
                assert change.content is not None
                tree[change.path] = change.content
        return f"sha-{abs(hash((branch, len(tree), message))) % 10**7:07d}"

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None:
        self.calls.append(("find_open_pull_request", repo_full_name))
        repo = self._repo(repo_full_name)
        for pr in repo.pull_requests:
            if pr.state == "open" and pr.head_branch.startswith(head_branch_prefix):
                return pr
        return None

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest:
        self.calls.append(("create_pull_request", repo_full_name))
        self._require("pull_requests", "write", "Opening a pull request")
        repo = self._repo(repo_full_name)
        self.pull_request_bodies[self._next_pr_number] = body
        pr = PullRequest(
            number=self._next_pr_number,
            url=f"https://github.com/{repo_full_name}/pull/{self._next_pr_number}",
            head_branch=head,
            draft=draft,
        )
        self._next_pr_number += 1
        repo.pull_requests.append(pr)
        return pr

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest:
        self.calls.append(("update_pull_request", f"{repo_full_name}#{number}"))
        self._require("pull_requests", "write", "Updating a pull request")
        repo = self._repo(repo_full_name)
        for pr in repo.pull_requests:
            if pr.number == number:
                return pr
        raise GitHubError(f"Pull request #{number} not found", status=404)

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        self.calls.append(("close_pull_request", f"{repo_full_name}#{number}"))
        self._require("pull_requests", "write", "Closing a pull request")
        for pr in self._repo(repo_full_name).pull_requests:
            if pr.number == number:
                pr.state = "closed"
                pr.merged = False
                return
        raise GitHubError(f"Pull request #{number} not found", status=404)

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey:
        self.calls.append(("get_actions_public_key", repo_full_name))
        self._require("secrets", "write", "Reading the Actions public key")
        self._repo(repo_full_name)
        # A fixed, published test key. Real sealing is exercised in
        # tests/test_github.py against a generated keypair.
        return RepoPublicKey(
            key_id="568250167242549743",
            key_base64="2Sg8iYjAxxmI2LvUXpJjkYrMxURPc8r+dB7TJyvvcCU=",
        )

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None:
        self.calls.append(("put_actions_secret", f"{repo_full_name}:{name}"))
        self._require("secrets", "write", "Creating an Actions secret")
        self._repo(repo_full_name).secrets[name] = encrypted_value

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None:
        self.calls.append(("delete_actions_secret", f"{repo_full_name}:{name}"))
        self._require("secrets", "write", "Deleting an Actions secret")
        self._repo(repo_full_name).secrets.pop(name, None)

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        self.calls.append(("create_check_run", f"{repo_full_name}@{head_sha}"))
        self._require("checks", "write", "Posting a check run")
        repo = self._repo(repo_full_name)
        check_id = f"check-{len(repo.check_runs) + 1}"
        repo.check_runs.append(
            {
                "id": check_id,
                "name": name,
                "head_sha": head_sha,
                "conclusion": conclusion,
                "title": title,
                "summary": summary,
            }
        )
        return check_id

    async def get_installation(self, installation_id: int) -> dict[str, Any]:
        self.calls.append(("get_installation", str(installation_id)))
        try:
            return self.installations[installation_id]
        except KeyError:
            raise GitHubError(f"Installation {installation_id} not found", status=404) from None


# ---------------------------------------------------------------------------
# Real
# ---------------------------------------------------------------------------


class RestGitHubClient:
    """The live client. Mints installation tokens on demand and caches them.

    Not exercised by the test suite — there is nothing meaningful to assert
    about it without a registered App, and asserting against a mocked
    transport would only test the mock. It is covered by the permission smoke
    test in spec 02 §8, which is a Phase 1 entry gate precisely because this
    code cannot be proven correct any other way.
    """

    def __init__(
        self,
        credentials: AppCredentials,
        installation_id: int,
        cache: InstallationTokenCache | None = None,
        base_url: str = GITHUB_API,
    ) -> None:
        self.credentials = credentials
        self.installation_id = installation_id
        self.cache = cache or InstallationTokenCache()
        self.base_url = base_url

    async def _token(self) -> str:
        cached = self.cache.get(self.installation_id)
        if cached is not None:
            return cached

        async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
            response = await http.post(
                f"/app/installations/{self.installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {self.credentials.app_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if response.status_code >= 400:
            raise GitHubError(
                f"Could not mint an installation token: {response.text}",
                status=response.status_code,
            )
        payload = response.json()
        expires = payload.get("expires_at", "")
        expires_at = (
            __import__("datetime").datetime.fromisoformat(expires.replace("Z", "+00:00"))
            .replace(tzinfo=None)
            if expires
            else utcnow()
        )
        self.cache.put(self.installation_id, payload["token"], expires_at)
        return str(payload["token"])

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx2.Response:
        token = await self._token()
        async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
            response = await http.request(
                method,
                path,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                **kwargs,
            )
        if response.status_code == 401:
            # The cached token was revoked or rotated early; drop it so the
            # next attempt mints a fresh one rather than looping on a dead one.
            self.cache.invalidate(self.installation_id)
        if response.status_code == 403 and "workflow" in response.text.lower():
            raise PermissionDeniedError(
                "GitHub refused a workflow-file write. The App is missing "
                "'workflows: write' (spec 02 §4, D-008).",
                status=403,
            )
        return response

    async def _json(self, method: str, path: str, **kwargs: Any) -> Any:
        response = await self._request(method, path, **kwargs)
        if response.status_code >= 400:
            raise GitHubError(
                f"{method} {path} -> {response.status_code}: {response.text[:400]}",
                status=response.status_code,
            )
        return response.json() if response.content else {}

    # -- protocol -------------------------------------------------------

    async def get_repo(self, repo_full_name: str) -> dict[str, Any]:
        return dict(await self._json("GET", f"/repos/{repo_full_name}"))

    async def get_file(self, repo_full_name: str, path: str, ref: str) -> str | None:
        response = await self._request(
            "GET", f"/repos/{repo_full_name}/contents/{path}", params={"ref": ref}
        )
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GitHubError(
                f"Reading {path}@{ref} failed: {response.text[:200]}",
                status=response.status_code,
            )
        payload = response.json()
        if payload.get("encoding") != "base64":
            return str(payload.get("content", ""))
        return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")

    async def create_branch(self, repo_full_name: str, branch: str, from_ref: str) -> None:
        base = await self._json("GET", f"/repos/{repo_full_name}/git/ref/heads/{from_ref}")
        await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": base["object"]["sha"]},
        )

    async def commit_files(
        self, repo_full_name: str, branch: str, message: str, changes: list[FileChange]
    ) -> str:
        """One commit for the whole change set, via the Git Data API.

        Deliberately not the Contents API, which commits per file: a
        multi-capability install would land as several commits, and a failure
        halfway would leave the branch in a state that is neither the old
        capability set nor the new one.
        """
        head = await self._json("GET", f"/repos/{repo_full_name}/git/ref/heads/{branch}")
        head_sha = head["object"]["sha"]
        commit = await self._json("GET", f"/repos/{repo_full_name}/git/commits/{head_sha}")

        tree_entries: list[dict[str, Any]] = []
        for change in changes:
            if change.is_delete:
                # A null sha is how the Git Data API expresses a deletion.
                blob_sha = None
            else:
                blob = await self._json(
                    "POST",
                    f"/repos/{repo_full_name}/git/blobs",
                    json={"content": change.content, "encoding": "utf-8"},
                )
                blob_sha = blob["sha"]
            tree_entries.append(
                {"path": change.path, "mode": "100644", "type": "blob", "sha": blob_sha}
            )

        tree = await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/trees",
            json={"base_tree": commit["tree"]["sha"], "tree": tree_entries},
        )
        new_commit = await self._json(
            "POST",
            f"/repos/{repo_full_name}/git/commits",
            json={"message": message, "tree": tree["sha"], "parents": [head_sha]},
        )
        await self._json(
            "PATCH",
            f"/repos/{repo_full_name}/git/refs/heads/{branch}",
            json={"sha": new_commit["sha"], "force": True},
        )
        return str(new_commit["sha"])

    async def find_open_pull_request(
        self, repo_full_name: str, head_branch_prefix: str
    ) -> PullRequest | None:
        payload = await self._json(
            "GET",
            f"/repos/{repo_full_name}/pulls",
            params={"state": "open", "per_page": 100},
        )
        for item in payload:
            ref = (item.get("head") or {}).get("ref", "")
            if ref.startswith(head_branch_prefix):
                return PullRequest(
                    number=int(item["number"]),
                    url=str(item["html_url"]),
                    head_branch=ref,
                    state=str(item.get("state", "open")),
                    merged=bool(item.get("merged_at")),
                )
        return None

    async def create_pull_request(
        self,
        repo_full_name: str,
        *,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False,
    ) -> PullRequest:
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/pulls",
            json={
                "head": head,
                "base": base,
                "title": title,
                "body": body,
                "draft": draft,
            },
        )
        return PullRequest(
            number=int(item["number"]),
            url=str(item["html_url"]),
            head_branch=head,
            draft=bool(item.get("draft", draft)),
        )

    async def update_pull_request(
        self, repo_full_name: str, number: int, *, title: str, body: str
    ) -> PullRequest:
        item = await self._json(
            "PATCH",
            f"/repos/{repo_full_name}/pulls/{number}",
            json={"title": title, "body": body},
        )
        return PullRequest(
            number=int(item["number"]),
            url=str(item["html_url"]),
            head_branch=(item.get("head") or {}).get("ref", ""),
        )

    async def close_pull_request(
        self, repo_full_name: str, number: int, *, comment: str = ""
    ) -> None:
        if comment:
            # Comment before closing, so the explanation is already there for
            # anyone who reads the close notification.
            await self._json(
                "POST",
                f"/repos/{repo_full_name}/issues/{number}/comments",
                json={"body": comment},
            )
        await self._json(
            "PATCH", f"/repos/{repo_full_name}/pulls/{number}", json={"state": "closed"}
        )

    async def get_actions_public_key(self, repo_full_name: str) -> RepoPublicKey:
        payload = await self._json(
            "GET", f"/repos/{repo_full_name}/actions/secrets/public-key"
        )
        return RepoPublicKey(key_id=str(payload["key_id"]), key_base64=str(payload["key"]))

    async def put_actions_secret(
        self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
    ) -> None:
        await self._json(
            "PUT",
            f"/repos/{repo_full_name}/actions/secrets/{name}",
            json={"encrypted_value": encrypted_value, "key_id": key_id},
        )

    async def delete_actions_secret(self, repo_full_name: str, name: str) -> None:
        response = await self._request(
            "DELETE", f"/repos/{repo_full_name}/actions/secrets/{name}"
        )
        # 404 is success for our purposes: the secret is gone either way.
        if response.status_code not in (204, 404):
            raise GitHubError(
                f"Deleting secret {name} failed: {response.text[:200]}",
                status=response.status_code,
            )

    async def create_check_run(
        self,
        repo_full_name: str,
        *,
        name: str,
        head_sha: str,
        conclusion: str,
        title: str,
        summary: str,
    ) -> str:
        item = await self._json(
            "POST",
            f"/repos/{repo_full_name}/check-runs",
            json={
                "name": name,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": {
                    "title": title,
                    # GitHub truncates past 65535; do it ourselves so the cut
                    # is at a sensible place rather than mid-sentence.
                    "summary": summary[:60000],
                },
            },
        )
        return str(item["id"])

    async def get_installation(self, installation_id: int) -> dict[str, Any]:
        """Installation metadata, for the daily reconciliation (spec 02 §5.6).

        Authenticates with the App JWT rather than an installation token:
        asking an installation token whether its own installation still exists
        is circular, and it stops working at exactly the moment the answer
        becomes interesting.
        """
        async with httpx2.AsyncClient(base_url=self.base_url, timeout=30.0) as http:
            response = await http.get(
                f"/app/installations/{installation_id}",
                headers={
                    "Authorization": f"Bearer {self.credentials.app_jwt()}",
                    "Accept": "application/vnd.github+json",
                },
            )
        if response.status_code >= 400:
            raise GitHubError(
                f"Installation {installation_id} lookup failed: {response.text[:200]}",
                status=response.status_code,
            )
        return dict(response.json())
