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
  still lands and the gap is *recorded* on the token with its reason, then
  shown in the work queue, the briefing and the platform-health page;
- once the permission is granted, the sweep delivers without anyone pasting.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from datetime import timedelta

import pytest
from nacl import encoding, public
from sqlalchemy.orm import Session

from mykronos import platform_health
from mykronos.auth import TokenRegistry
from mykronos.briefing import TokenDelivery
from mykronos.config import get_settings
from mykronos.db import Database
from mykronos.db.models import IngestionToken, Organization, RepoOnboarding
from mykronos.dependabot_remedy import remedy_for
from mykronos.github import FakeGitHubClient
from mykronos.github.client import (
    OPTIONAL_PERMISSIONS,
    REQUIRED_PERMISSIONS,
    GitHubError,
    RepoPublicKey,
)
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.github.secrets import (
    dependabot_gap_reason,
    permission_not_held_reason,
    write_failed_under_grant,
)
from mykronos.installer import DEFAULT_SECRET_NAME, TemplateLibrary, WorkflowInstaller
from mykronos.jobs import deliveries_awaiting_operator, rotate_ingestion_tokens
from mykronos.schemas import utcnow
from tests.test_agent_work import _briefing, _build
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


# ---------------------------------------------------------------------------
# Where a person sees it


class TestAPersonCanSeeTheGap:
    def test_a_recorded_gap_is_put_in_front_of_a_person(self, db: Database) -> None:
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, "403 from the endpoint")

        waiting = deliveries_awaiting_operator(db)

        assert [(t.repo_full_name, t.state) for t in waiting] == [(REPO, "dependabot_unsynced")]
        assert waiting[0].reason == "403 from the endpoint"
        assert waiting[0].scanned_by == "github_actions"

    def test_a_copy_not_yet_attempted_is_not_yet_a_persons_work(self, db: Database) -> None:
        """Every token issued before this change has no Dependabot copy. The
        sweep attempts each on its next run; only a recorded refusal is work
        for a person."""
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)

        assert deliveries_awaiting_operator(db) == []

    def test_a_delivered_copy_leaves_the_page(self, db: Database) -> None:
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, PERMISSION_REASON)
        assert deliveries_awaiting_operator(db)

        with db.session() as session:
            TokenRegistry(session).mark_dependabot_synced(REPO)

        assert deliveries_awaiting_operator(db) == []

    def test_the_work_queue_item_names_the_grant_and_not_a_rotation(self) -> None:
        now = utcnow()
        token = TokenDelivery(
            repo_full_name=REPO,
            state="dependabot_unsynced",
            issued_at=now - timedelta(days=5),
            rotate_after=now + timedelta(days=85),
            scanned_by="github_actions",
            reason=PERMISSION_REASON,
        )

        [item] = _build(_briefing(tokens=[token])).items

        assert item.kind == "token_delivery"
        assert "dependabot" in item.item_id
        assert "Dependabot" in item.title
        assert token.reason in item.summary
        assert "Dependabot secrets" in item.done_when
        assert "do_not_rotate" not in {c.code for c in item.caveats}

    def test_the_rendered_briefing_does_not_call_it_unconfirmed_delivery(self) -> None:
        from mykronos import briefing as briefing_report

        now = utcnow()
        report = briefing_report.Briefing(
            generated_at=now,
            total_open=0,
            tokens=[
                TokenDelivery(
                    repo_full_name=REPO,
                    state="dependabot_unsynced",
                    issued_at=now,
                    rotate_after=now + timedelta(days=88),
                    scanned_by="github_actions",
                    reason=PERMISSION_REASON,
                )
            ],
        )

        text = briefing_report.render(report)

        assert "NOT IN DEPENDABOT SECRETS" in text
        assert "Read and write" in text
        assert "DELIVERY NEVER CONFIRMED" not in text

    def test_platform_health_passes_the_state_through(self, db: Database) -> None:
        """Not folded into `unverified`: that state's action is "do not
        rotate", and this one's is a permission grant."""
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, PERMISSION_REASON)

        rows = platform_health.credentials_needing_attention(db, now=utcnow())

        [row] = [r for r in rows if r.kind == "ingestion_token"]
        assert row.state == "dependabot_unsynced"
        assert "Dependabot secrets" in row.action
        assert "rotate" not in row.action.lower()


# ---------------------------------------------------------------------------
# One remedy per recorded reason (independent review of PR B)

CONCOURSE_REASON = (
    f"The Dependabot secret is not written: {REPO} is scanned by concourse, which this "
    "job cannot deliver to, so this job will not rotate to deliver it. Rotate by hand: "
    "repair-ingestion-token.ps1."
)
WRITE_FAILED_REASON = (
    "The Dependabot secret write failed although the installation holds "
    "'dependabot_secrets: write': GitHub answered 500: boom. Not retried by rotation."
)
PERMISSION_REASON = permission_not_held_reason(None)

# (reason, owner, text the remedy must contain, text it must not contain)
REASON_PATHS = [
    (PERMISSION_REASON, "operator", "Dependabot secrets: Read and write", "repair-ingestion"),
    (CONCOURSE_REASON, "hubops", "Rotate by hand: repair-ingestion-token.ps1", "grant the App"),
    (WRITE_FAILED_REASON, "hubops", "retried at the next due rotation", "grant the App"),
]


def _delivery(reason: str) -> TokenDelivery:
    now = utcnow()
    return TokenDelivery(
        repo_full_name=REPO,
        state="dependabot_unsynced",
        issued_at=now - timedelta(days=5),
        rotate_after=now + timedelta(days=85),
        scanned_by="github_actions",
        reason=reason,
        recorded_at=now - timedelta(hours=3),
    )


def _render(reason: str) -> str:
    from mykronos import briefing as briefing_report

    return briefing_report.render(
        briefing_report.Briefing(generated_at=utcnow(), total_open=0, tokens=[_delivery(reason)])
    )


class TestTheRemedyFollowsTheRecordedReason:
    @pytest.mark.parametrize(("reason", "owner", "must", "must_not"), REASON_PATHS)
    def test_work_queue_item(self, reason: str, owner: str, must: str, must_not: str) -> None:
        [item] = _build(_briefing(tokens=[_delivery(reason)])).items

        assert f"Owner: {owner}." in item.summary
        assert "Refusal recorded" in item.summary
        assert must in item.summary + item.done_when
        # The recorded reason may itself name a remedy; the item's own lines may not.
        assert must_not not in item.summary.replace(reason, "") + item.done_when

    @pytest.mark.parametrize(("reason", "owner", "must", "must_not"), REASON_PATHS)
    def test_briefing_line(self, reason: str, owner: str, must: str, must_not: str) -> None:
        text = _render(reason)
        arrow = [ln for ln in text.splitlines() if "→" in ln]

        assert f"owner: {owner}" in text
        assert "recorded " in text
        assert any(must in ln for ln in arrow)
        assert not any(must_not in ln for ln in arrow)

    @pytest.mark.parametrize(("reason", "owner", "must", "must_not"), REASON_PATHS)
    def test_platform_health_action(
        self, db: Database, reason: str, owner: str, must: str, must_not: str
    ) -> None:
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, reason)

        [row] = [
            r
            for r in platform_health.credentials_needing_attention(db, now=utcnow())
            if r.kind == "ingestion_token"
        ]

        assert row.reason == reason
        assert row.owner == owner
        assert must in row.action
        assert must_not not in row.action
        assert row.recorded_at is not None

    def test_an_unrecognised_reason_is_printed_alone(self) -> None:
        text = _render("Something else broke.")

        assert "Something else broke." in text
        assert "→ grant" not in text
        assert "Rotate by hand" not in text
        assert "owner:" not in text

    def test_the_as_of_survives_a_repeated_record_and_resets_on_a_new_reason(
        self, db: Database
    ) -> None:
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, "first")
        first = deliveries_awaiting_operator(db)[0].recorded_at
        assert first is not None
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_unsynced(REPO, "first")
        assert deliveries_awaiting_operator(db)[0].recorded_at == first
        with db.session() as session:
            TokenRegistry(session).mark_dependabot_synced(REPO)
        assert deliveries_awaiting_operator(db) == []


class TestWriteFailedUnderGrantTellsTheTruth:
    """The remedy for a write that failed under a held grant must agree with
    what the sweep does: it skips the repository until its next due rotation,
    so "re-run the sweep" would promise a retry that never happens."""

    async def test_the_remedy_and_the_sweep_agree(self, db: Database) -> None:
        class RefusesTheWrite(FakeGitHubClient):
            async def put_dependabot_secret(
                self, repo_full_name: str, name: str, encrypted_value: str, key_id: str
            ) -> None:
                raise GitHubError("PUT .../dependabot/secrets/x -> 500: boom", status=500)

        refusing = RefusesTheWrite()
        refusing.add_repo(REPO)
        refusing.installations[INSTALLATION] = {"id": INSTALLATION, "suspended_at": None}
        onboard(db)
        _issue_actions_synced(db, dependabot_synced=False)
        await rotate_ingestion_tokens(db, FakeGitHubClientFactory(refusing))
        recorded = _active_token(db).dependabot_sync_blocker
        assert write_failed_under_grant(recorded)

        # A re-run against a GitHub that would now accept the write.
        accepting = FakeGitHubClient()
        accepting.add_repo(REPO)
        accepting.installations[INSTALLATION] = {"id": INSTALLATION, "suspended_at": None}
        rerun = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(accepting))

        assert [repo for repo, _ in rerun.dependabot_blocked] == [REPO]
        assert not [c for c in accepting.calls if c[0] == "put_dependabot_secret"]
        assert _active_token(db).dependabot_sync_blocker == recorded

        [waiting] = deliveries_awaiting_operator(db)
        remedy = remedy_for(waiting.reason, waiting.rotate_after)
        assert f"{waiting.rotate_after:%Y-%m-%d}" in remedy.action
        assert "next due rotation" in remedy.action
        assert "re-running the sweep skips" in remedy.action
        assert "re-run the sweep" not in remedy.action.replace("re-running the sweep", "")
        assert f"{waiting.rotate_after:%Y-%m-%d}" in remedy.done_when
