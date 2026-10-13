"""GitHub App auth, secret sealing, and the fake's fidelity — spec 02, spec 03 §4a."""

from __future__ import annotations

import base64
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from nacl import encoding, public

from mykronos.github import (
    AppCredentials,
    FakeGitHubClient,
    FileChange,
    InstallationTokenCache,
    seal_secret,
)
from mykronos.github.client import GitHubError, PermissionDeniedError
from mykronos.schemas import utcnow

REPO = "example-org/payments-api"


@pytest.fixture
def private_key_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


@pytest.fixture
def credentials(private_key_pem: str) -> AppCredentials:
    return AppCredentials(app_id="123456", private_key_pem=private_key_pem)


class TestAppJwt:
    def test_signs_with_rs256_and_the_app_id(
        self, credentials: AppCredentials, private_key_pem: str
    ) -> None:
        token = credentials.app_jwt()
        public_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None
        ).public_key()
        claims = jwt.decode(token, public_key, algorithms=["RS256"], options={"verify_exp": True})
        assert claims["iss"] == "123456"

    def test_iat_is_backdated_against_clock_skew(self, credentials: AppCredentials) -> None:
        """GitHub rejects a JWT issued in the future, and a slightly fast local
        clock is an otherwise baffling cause of 401s."""
        now = 1_800_000_000
        claims = jwt.decode(
            credentials.app_jwt(now=now), options={"verify_signature": False}
        )
        assert claims["iat"] < now

    def test_expiry_is_inside_githubs_ten_minute_ceiling(
        self, credentials: AppCredentials
    ) -> None:
        now = 1_800_000_000
        claims = jwt.decode(
            credentials.app_jwt(now=now), options={"verify_signature": False}
        )
        assert claims["exp"] - claims["iat"] < 600


class TestTokenCache:
    def test_returns_a_live_token(self) -> None:
        cache = InstallationTokenCache()
        cache.put(42, "ghs_live", utcnow() + timedelta(hours=1))
        assert cache.get(42) == "ghs_live"

    def test_refuses_a_token_about_to_expire(self) -> None:
        """A token with two minutes left could die mid-request. Re-mint early
        rather than fail a scan for a credential we knew was nearly dead."""
        cache = InstallationTokenCache()
        cache.put(42, "ghs_nearly_dead", utcnow() + timedelta(minutes=2))
        assert cache.get(42) is None

    def test_unknown_installation_is_a_miss(self) -> None:
        assert InstallationTokenCache().get(999) is None

    def test_invalidate_forces_a_refresh(self) -> None:
        cache = InstallationTokenCache()
        cache.put(42, "ghs_live", utcnow() + timedelta(hours=1))
        cache.invalidate(42)
        assert cache.get(42) is None

    def test_tokens_are_isolated_per_installation(self) -> None:
        cache = InstallationTokenCache()
        cache.put(1, "one", utcnow() + timedelta(hours=1))
        cache.put(2, "two", utcnow() + timedelta(hours=1))
        assert cache.get(1) == "one"
        assert cache.get(2) == "two"


class TestSealing:
    def test_ciphertext_decrypts_back_to_the_plaintext(self) -> None:
        """spec 03 §4a: a plaintext secret never crosses the wire."""
        private = public.PrivateKey.generate()
        public_b64 = private.public_key.encode(encoding.Base64Encoder()).decode()

        sealed = seal_secret(public_b64, "mykronos-ingestion-token-value")

        opened = public.SealedBox(private).decrypt(base64.b64decode(sealed))
        assert opened.decode() == "mykronos-ingestion-token-value"

    def test_ciphertext_does_not_contain_the_plaintext(self) -> None:
        private = public.PrivateKey.generate()
        public_b64 = private.public_key.encode(encoding.Base64Encoder()).decode()
        sealed = seal_secret(public_b64, "SUPER-SECRET-VALUE")
        assert "SUPER-SECRET-VALUE" not in sealed
        assert "SUPER-SECRET-VALUE" not in base64.b64decode(sealed).decode("latin-1")

    def test_sealing_is_non_deterministic(self) -> None:
        """Sealed boxes carry an ephemeral key, so identical plaintexts do not
        produce identical ciphertexts — an observer cannot tell that two repos
        were given the same value."""
        private = public.PrivateKey.generate()
        public_b64 = private.public_key.encode(encoding.Base64Encoder()).decode()
        assert seal_secret(public_b64, "same") != seal_secret(public_b64, "same")


class TestFakeEnforcesRealPreconditions:
    """The fake is only useful if it fails where GitHub fails."""

    @pytest.fixture
    def client(self) -> FakeGitHubClient:
        github = FakeGitHubClient()
        github.add_repo(REPO, files={"README.md": "# payments"})
        return github

    async def test_workflow_commit_needs_workflows_write(self) -> None:
        """The D-008 failure, reproduced: an App holding only contents:write
        is refused for .github/workflows/ paths."""
        github = FakeGitHubClient(
            permissions={"contents": "write", "pull_requests": "write", "metadata": "read"}
        )
        github.add_repo(REPO)
        await github.create_branch(REPO, "mykronos/enable", "main")

        with pytest.raises(PermissionDeniedError) as excinfo:
            await github.commit_files(
                REPO,
                "mykronos/enable",
                "add sast",
                [FileChange(".github/workflows/mykronos-sast.yml", "on: push")],
            )

        assert "workflows: write" in str(excinfo.value)
        assert "D-008" in str(excinfo.value)

    async def test_non_workflow_commit_needs_only_contents_write(self) -> None:
        github = FakeGitHubClient(permissions={"contents": "write"})
        github.add_repo(REPO)
        await github.create_branch(REPO, "docs", "main")
        await github.commit_files(REPO, "docs", "note", [FileChange("NOTES.md", "hi")])
        assert github.repos[REPO].branches["docs"]["NOTES.md"] == "hi"

    async def test_secret_write_needs_secrets_write(self) -> None:
        """The other half of D-008: no create-only tier exists."""
        github = FakeGitHubClient(permissions={"contents": "write", "workflows": "write"})
        github.add_repo(REPO)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await github.get_actions_public_key(REPO)
        assert "secrets: write" in str(excinfo.value)

    async def test_committing_to_a_missing_branch_fails(
        self, client: FakeGitHubClient
    ) -> None:
        with pytest.raises(Exception, match="does not exist"):
            await client.commit_files(REPO, "nope", "m", [FileChange("a.txt", "x")])

    async def test_branch_is_forked_from_its_base(self, client: FakeGitHubClient) -> None:
        await client.create_branch(REPO, "feature", "main")
        assert client.repos[REPO].branches["feature"]["README.md"] == "# payments"

    async def test_deleting_a_file(self, client: FakeGitHubClient) -> None:
        await client.create_branch(REPO, "cleanup", "main")
        await client.commit_files(
            REPO, "cleanup", "remove", [FileChange("README.md", None)]
        )
        assert "README.md" not in client.repos[REPO].branches["cleanup"]

    async def test_get_file_reads_the_named_ref(self, client: FakeGitHubClient) -> None:
        await client.create_branch(REPO, "wip", "main")
        await client.commit_files(REPO, "wip", "add", [FileChange("new.txt", "content")])
        assert await client.get_file(REPO, "new.txt", "wip") == "content"
        assert await client.get_file(REPO, "new.txt", "main") is None

    async def test_open_pull_requests_are_findable_by_branch_prefix(
        self, client: FakeGitHubClient
    ) -> None:
        """What the installer's idempotency check relies on (spec 03 §4)."""
        await client.create_branch(REPO, "mykronos/enable-workflows-123", "main")
        created = await client.create_pull_request(
            REPO, head="mykronos/enable-workflows-123", base="main", title="t", body="b"
        )
        found = await client.find_open_pull_request(REPO, "mykronos/enable-workflows-")
        assert found is not None and found.number == created.number

    async def test_unrelated_open_prs_are_not_matched(
        self, client: FakeGitHubClient
    ) -> None:
        await client.create_branch(REPO, "someone-elses-feature", "main")
        await client.create_pull_request(
            REPO, head="someone-elses-feature", base="main", title="t", body="b"
        )
        assert await client.find_open_pull_request(REPO, "mykronos/enable-workflows-") is None

    async def test_unknown_repo_is_an_error(self, client: FakeGitHubClient) -> None:
        with pytest.raises(Exception, match="not found"):
            await client.get_repo("example-org/does-not-exist")


class TestDispatchWorkflow:
    """spec 17 §2.5 — on-demand scan dispatch."""

    @pytest.fixture
    def client(self) -> FakeGitHubClient:
        github = FakeGitHubClient()
        github.add_repo(REPO)
        return github

    async def test_records_the_dispatch(self, client: FakeGitHubClient) -> None:
        await client.dispatch_workflow(REPO, "mykronos-sast.yml", "main")

        assert client.repos[REPO].dispatched_workflows == [
            {"workflow_file": "mykronos-sast.yml", "ref": "main", "inputs": {}}
        ]

    async def test_needs_actions_write(self) -> None:
        github = FakeGitHubClient(
            permissions={"contents": "write", "pull_requests": "write", "metadata": "read"}
        )
        github.add_repo(REPO)
        with pytest.raises(PermissionDeniedError) as excinfo:
            await github.dispatch_workflow(REPO, "mykronos-sast.yml", "main")
        assert "actions: write" in str(excinfo.value)

    async def test_unknown_repo_is_an_error(self, client: FakeGitHubClient) -> None:
        with pytest.raises(GitHubError, match="not found"):
            await client.dispatch_workflow(
                "example-org/does-not-exist", "mykronos-sast.yml", "main"
            )
