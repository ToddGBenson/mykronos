"""The ingestion token reaches Dependabot secrets as well as Actions secrets
(TheHub #60855).

A Dependabot-triggered Actions run reads a separate secret store. MyKronos
sealed `MYKRONOS_INGESTION_TOKEN` into each repository's *Actions* secrets and
nothing wrote the Dependabot copy, so every Dependabot pull request's lanes
died with a blank token -- and nobody could paste the value by hand, because
only its SHA-256 is stored.

Three claims, each tested against a fake GitHub:

- wherever the Actions secret is written (the installer's first seal and the
  rotation job's rotate/resync), the same plaintext is sealed into the
  Dependabot store under the Dependabot public key;
- when the App lacks the Dependabot-secrets permission, the Actions write
  still lands and the gap is *recorded* on the token with its reason;
- once the permission is granted, the sweep delivers without anyone pasting,
  and never rotates on evidence short of that.

Where a person sees the recorded gap (work queue, briefing, platform health)
is the follow-up pull request, with its own tests.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator

import pytest
from nacl import encoding, public
from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.config import get_settings
from mykronos.db import Database
from mykronos.db.models import IngestionToken, Organization, RepoOnboarding
from mykronos.github import FakeGitHubClient
from mykronos.github.client import (
    OPTIONAL_PERMISSIONS,
    REQUIRED_PERMISSIONS,
    GitHubError,
    RepoPublicKey,
)
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.github.secrets import dependabot_gap_reason
from mykronos.installer import DEFAULT_SECRET_NAME, TemplateLibrary, WorkflowInstaller
from mykronos.jobs import rotate_ingestion_tokens
from tests.test_jobs import INSTALLATION, age_token, onboard

REPO = "example-org/payments-api"

#: Every permission the App holds today, and nothing for Dependabot secrets:
#: the state of every installation until the operator grants it.
WITHOUT_DEPENDABOT = {
    name: level
    for name, level in {**REQUIRED_PERMISSIONS, **OPTIONAL_PERMISSIONS}.items()
    if name != "dependabot_secrets"
}


def _keypair() -> tuple[public.PrivateKey, RepoPublicKey]:
    private = public.PrivateKey.generate()
    key = RepoPublicKey(
        key_id=str(id(private)),
        key_base64=private.public_key.encode(encoding.Base64Encoder).decode("ascii"),
    )
    return private, key


def _unseal(private: public.PrivateKey, ciphertext_base64: str) -> str:
    return public.SealedBox(private).decrypt(base64.b64decode(ciphertext_base64)).decode()


def _active_token(db: Database, repo: str = REPO) -> IngestionToken:
    with db.session() as session:
        token = (
            session.query(IngestionToken)
            .filter(IngestionToken.repo_full_name == repo)
            .filter(IngestionToken.status == "active")
            .one()
        )
        session.expunge(token)
        return token


# ---------------------------------------------------------------------------
# The installer's first seal


@pytest.fixture
def session(tmp_path) -> Iterator[Session]:
    db = Database(f"sqlite:///{(tmp_path / 'installer.db').as_posix()}")
    db.create_all()
    with db.session() as s:
        yield s
    db.close()


@pytest.fixture
def onboarding(session: Session) -> RepoOnboarding:
    org = Organization(github_org_login="example-org")
    session.add(org)
    session.flush()
    row = RepoOnboarding(
        org_id=org.id,
        github_repo_full_name=REPO,
        github_installation_id=INSTALLATION,
        status="pending_install",
        enabled_capabilities=[],
        default_branch="main",
        onboarded_by="tgb",
        scanned_by="github_actions",
    )
    session.add(row)
    session.flush()
    return row


def _installer(github: FakeGitHubClient) -> WorkflowInstaller:
    return WorkflowInstaller(
        github,
        TemplateLibrary(get_settings().workflow_templates_dir),
        ingestion_api_url="https://mykronos.internal",
        upload_action_ref="ToddGBenson/mykronos/actions/upload-results@v1",
    )


async def _install(github: FakeGitHubClient, session: Session, onboarding: RepoOnboarding):
    installer = _installer(github)
    registry = TokenRegistry(session)
    plan = await installer.plan(onboarding, {"sast"})
    result = await installer.apply(session, onboarding, plan, actor="tgb", registry=registry)
    return result, registry


class TestTheInstallerSealsBothStores:
    async def test_the_same_token_is_sealed_under_each_stores_own_key(
        self, session: Session, onboarding: RepoOnboarding
    ) -> None:
        """Criterion 1. Decrypted, not merely present: a secret sealed under
        the wrong store's key is accepted by GitHub's fake and rejected by the
        real one, so presence alone would prove nothing."""
        actions_private, actions_key = _keypair()
        dependabot_private, dependabot_key = _keypair()
        github = FakeGitHubClient()
        github.add_repo(
            REPO,
            files={"README.md": "# payments"},
            actions_public_key=actions_key,
            dependabot_public_key=dependabot_key,
        )

        result, registry = await _install(github, session, onboarding)

        assert result.secret_provisioned
        repo = github.repos[REPO]
        actions_plaintext = _unseal(actions_private, repo.secrets[DEFAULT_SECRET_NAME])
        dependabot_plaintext = _unseal(
            dependabot_private, repo.dependabot_secrets[DEFAULT_SECRET_NAME]
        )
        assert actions_plaintext == dependabot_plaintext
        # And it is this repository's active token, not some other value.
        resolution = registry.resolve(dependabot_plaintext)
        assert resolution is not None and resolution.repo_full_name == REPO

        token = registry.active_token_for(REPO)
        assert token is not None
        assert token.secret_synced
        assert token.dependabot_secret_synced
        assert token.dependabot_sync_blocker == ""

    async def test_without_the_permission_the_actions_write_still_lands(
        self, session: Session, onboarding: RepoOnboarding
    ) -> None:
        """Criterion 2. Today every installation is in this state. The
        Actions half must not be held hostage to the Dependabot half, and the
        gap must be written down where somebody will read it."""
        github = FakeGitHubClient(permissions=WITHOUT_DEPENDABOT)
        github.add_repo(REPO, files={"README.md": "# payments"})

        result, registry = await _install(github, session, onboarding)

        assert result.secret_provisioned
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        assert DEFAULT_SECRET_NAME not in github.repos[REPO].dependabot_secrets

        token = registry.active_token_for(REPO)
        assert token is not None
        assert token.secret_synced
        assert not token.dependabot_secret_synced
        reason = token.dependabot_sync_blocker
        assert "Dependabot secrets" in reason
        assert "403" in reason
        assert "Read and write" in reason

    async def test_a_404_from_the_dependabot_endpoint_is_the_same_gap(
        self, session: Session, onboarding: RepoOnboarding
    ) -> None:
        """GitHub answers 404 rather than 403 for an endpoint an installation
        cannot see at all, and the remedy is the same permission grant."""

        class NotFound(FakeGitHubClient):
            async def get_dependabot_public_key(self, repo_full_name: str) -> RepoPublicKey:
                self.calls.append(("get_dependabot_public_key", repo_full_name))
                raise GitHubError("GET .../dependabot/secrets/public-key -> 404", status=404)

        github = NotFound()
        github.add_repo(REPO, files={"README.md": "# payments"})

        result, registry = await _install(github, session, onboarding)

        assert result.secret_provisioned
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        token = registry.active_token_for(REPO)
        assert token is not None
        assert not token.dependabot_secret_synced
        assert "404" in token.dependabot_sync_blocker
        assert "Read and write" in token.dependabot_sync_blocker


# ---------------------------------------------------------------------------
# The rotation job


@pytest.fixture
def db(tmp_path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


def _github(permissions: dict[str, str] | None = None) -> FakeGitHubClient:
    client = FakeGitHubClient(permissions=permissions)
    client.add_repo(REPO)
    client.installations[INSTALLATION] = {"id": INSTALLATION, "suspended_at": None}
    return client


def _issue_actions_synced(db: Database, *, dependabot_synced: bool) -> str:
    """A repository as production has it: Actions secret delivered, and the
    Dependabot copy either delivered too or never written."""
    with db.session() as session:
        registry = TokenRegistry(session)
        plaintext = registry.issue(REPO)
        registry.mark_secret_synced(REPO)
        if dependabot_synced:
            registry.mark_dependabot_synced(REPO)
    return plaintext


class TestTheRotationJobSealsBothStores:
    async def test_a_due_rotation_writes_both_stores(self, db: Database) -> None:
        github = _github()
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=True)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == [REPO]
        assert result.dependabot_blocked == []
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        assert DEFAULT_SECRET_NAME in github.repos[REPO].dependabot_secrets
        token = _active_token(db)
        assert token.secret_synced and token.dependabot_secret_synced

    async def test_a_due_rotation_without_the_permission_still_rotates_actions(
        self, db: Database
    ) -> None:
        """The Actions write is what keeps the repository scanning; it goes
        ahead, and the Dependabot gap is recorded on the new token."""
        github = _github(WITHOUT_DEPENDABOT)
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == [REPO]
        assert result.failed == []
        assert [repo for repo, _reason in result.dependabot_blocked] == [REPO]
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        assert DEFAULT_SECRET_NAME not in github.repos[REPO].dependabot_secrets
        token = _active_token(db)
        assert token.secret_synced
        assert not token.dependabot_secret_synced
        assert "Read and write" in token.dependabot_sync_blocker
        assert "dependabot blocked 1" in result.summary()

    async def test_a_missing_dependabot_copy_does_not_churn_a_working_token(
        self, db: Database
    ) -> None:
        """The only way to deliver is to rotate, because the plaintext is not
        stored. Rotating on every run while the permission is missing would
        churn every repository's credential daily for nothing, so the sweep
        asks GitHub for the Dependabot key first and rotates only when the
        write can land. Until then: recorded, reported, left alone."""
        github = _github(WITHOUT_DEPENDABOT)
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        before = _active_token(db).token_sha256

        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == [] and result.resynced == []
        assert [repo for repo, _reason in result.dependabot_blocked] == [REPO]
        assert _active_token(db).token_sha256 == before
        assert not any(call[0] == "put_actions_secret" for call in github.calls)
        assert "Read and write" in _active_token(db).dependabot_sync_blocker

    async def test_once_the_permission_is_granted_the_sweep_delivers(self, db: Database) -> None:
        """Criterion 4: after the operator's one-time grant, the next sweep
        writes the Dependabot copy without anyone pasting a value. That takes
        a resync rotation, once, and it writes both stores."""
        github = _github()
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, "403 last time")
        before = _active_token(db).token_sha256

        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.resynced == [REPO]
        assert result.dependabot_blocked == []
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        assert DEFAULT_SECRET_NAME in github.repos[REPO].dependabot_secrets
        token = _active_token(db)
        assert token.token_sha256 != before
        assert token.secret_synced and token.dependabot_secret_synced
        assert token.dependabot_sync_blocker == ""

    async def test_a_concourse_scanned_repo_is_left_alone(self, db: Database) -> None:
        """D-086 still holds: the job writes nothing to a repository it does
        not drive, and a missing Dependabot copy there is not a reason to
        start. It is also not an `unverified` token: its Actions delivery
        is confirmed."""
        github = _github()
        onboard(db, scanned_by="concourse")
        _issue_actions_synced(db, dependabot_synced=False)

        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == [] and result.resynced == []
        assert result.unverified == [] and result.deferred == []
        assert github.calls == []

    async def test_a_read_only_grant_never_rotates(self, db: Database) -> None:
        """Independent review of #1142: `dependabot_secrets: read` lets the
        key be read and the secret not be written. A probe that only reads
        the key therefore passes, rotates, fails the PUT, records the
        blocker, and does the same on every sweep. The sweep must read the
        installation's grant, not the key, and a Read-only grant is the gap."""
        github = _github({**WITHOUT_DEPENDABOT, "dependabot_secrets": "read"})
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        before = _active_token(db).token_sha256

        for _ in range(3):
            result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))
            assert result.rotated == [] and result.resynced == []
            assert [repo for repo, _reason in result.dependabot_blocked] == [REPO]

        assert _active_token(db).token_sha256 == before
        assert not any(call[0] == "put_actions_secret" for call in github.calls)
        assert "Read and write" in _active_token(db).dependabot_sync_blocker

    @pytest.mark.parametrize("status", [403, 422])
    async def test_a_write_that_keeps_failing_under_the_grant_is_not_retried_by_rotation(
        self, db: Database, status: int
    ) -> None:
        """The grant is held and the PUT still fails (SSO, a rate limit, a
        malformed key). One rotation to find that out is the price of
        delivery; a second is churn. The reviewer measured three sweeps as
        four active tokens on the previous head."""

        class RefusesTheWrite(FakeGitHubClient):
            async def put_dependabot_secret(
                self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
            ) -> None:
                self.calls.append(("put_dependabot_secret", f"{repo_full_name}:{name}"))
                raise GitHubError(f"PUT .../dependabot/secrets/{name} -> {status}", status=status)

        github = RefusesTheWrite()
        github.add_repo(REPO)
        github.installations[INSTALLATION] = {"id": INSTALLATION, "suspended_at": None}
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        before = _active_token(db).token_sha256

        for _ in range(3):
            result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))
            assert [repo for repo, _reason in result.dependabot_blocked] == [REPO]

        actions_writes = [call for call in github.calls if call[0] == "put_actions_secret"]
        assert len(actions_writes) == 1, "one rotation delivers or fails; more is churn"
        token = _active_token(db)
        assert token.token_sha256 != before
        assert not token.dependabot_secret_synced
        assert str(status) in token.dependabot_sync_blocker
        assert "holds" in token.dependabot_sync_blocker

    def test_a_permission_gap_reason_keeps_githubs_detail(self) -> None:
        """A 403 is also what a secondary rate limit or an SSO enforcement
        answers; the reason names the usual remedy and still quotes what
        GitHub actually said."""
        reason = dependabot_gap_reason(403, "GET ... -> 403: secondary rate limit")
        assert "Read and write" in reason
        assert "secondary rate limit" in reason
