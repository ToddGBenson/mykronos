"""The token-desync tripwire: it has to be able to reset, and to say what it
measured (#263).

Two defects, one shape. `secret_synced` is the platform's only tripwire for an
ingestion-token desync -- the failure that has already taken TheHub's scanning
down (D-097). It was written by exactly one event, a successful GitHub Actions
secret write, so a Concourse-scanned repository could never clear it: flagged
on the day it was onboarded and flagged forever. It therefore sat permanently
tripped on the single repository it had ever fired on for real, which spends
the signal that would catch the next occurrence.

And the rotation sweep walked `due | unsynced` into one bucket, so a repository
in the second set was announced in the language of the first: *"is due for
token rotation... rotate it by hand"* about a token with eighty-eight days left
on its clock. Following that advice is how the pipeline goes dark -- the token
changes, Vault keeps serving the old value, and the repository stops uploading
when the overlap expires. So the two halves are not both cosmetic: one is a
control that cannot return to a clean state, and the other is a status that
asserts more than it measured.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry
from mykronos.db import Database
from mykronos.db.models import IngestionToken
from mykronos.github import FakeGitHubClient
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.jobs import deliveries_awaiting_operator, rotate_ingestion_tokens
from mykronos.schemas import utcnow
from tests.conftest import REPO as API_REPO
from tests.test_jobs import INSTALLATION, FakeConcourse, age_token, onboard  # noqa: F401

REPO = "ToddGBenson/TheHub"


@pytest.fixture
def db(tmp_path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'tripwire.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def factory() -> FakeGitHubClientFactory:
    """Present so the signature is satisfied, and deliberately empty.

    Every repository in this file is one the sweep defers, and a deferral must
    not touch GitHub at all: reaching it would mean the job had decided to
    deliver a secret to a repository whose scanner reads the token from Vault.
    """
    return FakeGitHubClientFactory(FakeGitHubClient())


@pytest.fixture
def session(tmp_path) -> Iterator[Session]:
    database = Database(f"sqlite:///{(tmp_path / 'registry.db').as_posix()}")
    database.create_all()
    with database.session() as s:
        yield s
    database.close()


@pytest.fixture
def registry(session: Session) -> TokenRegistry:
    return TokenRegistry(session, overlap_hours=24)


class TestTheFlagCanBeCleared:
    """The half of #263 that is a stuck control."""

    def test_presenting_the_active_token_records_delivery(
        self, registry: TokenRegistry
    ) -> None:
        """The proof the platform already had and was not reading.

        Only the SHA-256 is ever stored, so presenting the active token is
        the only way to demonstrate possession of that exact value. TheHub
        has been supplying that proof several times a day while being
        reported as never having received it.
        """
        plaintext = registry.issue(REPO)
        assert registry.unsynced_repos() == [REPO]

        resolution = registry.resolve(plaintext)
        assert resolution is not None
        assert registry.confirm_delivery(resolution.token_sha256) is True

        assert registry.unsynced_repos() == []

    def test_delivery_carries_the_moment_it_was_observed(
        self, registry: TokenRegistry
    ) -> None:
        """A bare `True` cannot be aged and cannot be told apart from a value
        written at onboarding. The date is what makes it a measurement."""
        plaintext = registry.issue(REPO)
        before = utcnow()
        resolution = registry.resolve(plaintext)
        assert resolution is not None
        registry.confirm_delivery(resolution.token_sha256)

        token = registry.active_token_for(REPO)
        assert token is not None
        assert token.delivery_confirmed_at is not None
        assert token.delivery_confirmed_at >= before

    def test_a_superseded_token_does_not_count_as_delivery(
        self, registry: TokenRegistry
    ) -> None:
        """The guard that keeps this from being worse than the bug.

        A caller still presenting the *old* value is the exact failure the
        flag exists to catch: the rotation happened and the new secret never
        arrived. Confirming on it would clear the tripwire using the evidence
        that should trip it.
        """
        old = registry.issue(REPO)
        registry.mark_secret_synced(REPO)
        registry.rotate(REPO)  # active token is now a different value
        registry.session.flush()
        assert registry.unsynced_repos() == [REPO]

        resolution = registry.resolve(old)
        assert resolution is not None
        assert resolution.superseded is True
        assert registry.confirm_delivery(resolution.token_sha256) is False

        assert registry.unsynced_repos() == [REPO]

    def test_confirming_twice_changes_nothing(self, registry: TokenRegistry) -> None:
        """Called on every authenticated ingestion request, so the second
        call has to be cheap and has to be honest about having done nothing."""
        plaintext = registry.issue(REPO)
        resolution = registry.resolve(plaintext)
        assert resolution is not None
        assert registry.confirm_delivery(resolution.token_sha256) is True
        assert registry.confirm_delivery(resolution.token_sha256) is False

    def test_an_unknown_digest_confirms_nothing(self, registry: TokenRegistry) -> None:
        registry.issue(REPO)
        assert registry.confirm_delivery("0" * 64) is False
        assert registry.unsynced_repos() == [REPO]


class TestIngestionClearsIt:
    """End to end: the flag resets from a real request, without the sweep."""

    def test_an_authenticated_upload_clears_the_tripwire(
        self, client: TestClient, token: str
    ) -> None:
        """This is the path a Concourse repository actually has. No GitHub
        Actions secret is ever written for it, so before this the flag had no
        writer at all and `unsynced_repos()` named it forever."""
        db = client.app.state.db  # type: ignore[attr-defined]
        with db.session() as session:
            assert API_REPO in TokenRegistry(session).unsynced_repos()

        response = client.get(
            "/api/ingest/health", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 200

        with db.session() as session:
            assert API_REPO not in TokenRegistry(session).unsynced_repos()

    def test_a_rejected_token_clears_nothing(self, client: TestClient, token: str) -> None:
        """A 401 is not evidence of delivery. Pinned because the confirmation
        sits on the authentication path, where failing open would be silent."""
        db = client.app.state.db  # type: ignore[attr-defined]
        response = client.get(
            "/api/ingest/health", headers={"Authorization": "Bearer not-a-real-token"}
        )
        assert response.status_code == 401

        with db.session() as session:
            assert API_REPO in TokenRegistry(session).unsynced_repos()


class TestTheSweepSaysWhichStateItFound:
    """The half of #263 that is a status asserting more than it measured."""

    async def test_an_unsynced_repo_is_not_reported_as_due(
        self, db: Database, factory
    ) -> None:
        """`deferred` means "rotate this by hand". An unsynced repository that
        is three months from its rotation date must not land there, because
        acting on that word is what breaks the pipeline."""
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)  # never confirmed delivered
        # Deliberately not aged: eighty-eight days left, as in the report.

        result = await rotate_ingestion_tokens(db, factory)

        assert result.unverified == [REPO]
        assert result.deferred == []
        assert result.rotated == []

    async def test_a_genuinely_due_repo_is_still_reported_as_due(
        self, db: Database, factory
    ) -> None:
        """Splitting the lists must not lose the one that does need a person."""
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.deferred == [REPO]
        assert result.unverified == []

    async def test_a_both_readers_repo_splits_the_same_way(
        self, db: Database, factory
    ) -> None:
        """The second deferral path (D-097) had the same collapsed bucket."""
        onboard(db, repo=REPO, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)  # never confirmed delivered

        result = await rotate_ingestion_tokens(
            db, factory, concourse=FakeConcourse(has_pipeline=True)
        )

        assert result.unverified == [REPO]
        assert result.deferred == []

    async def test_the_summary_counts_the_two_apart(
        self, db: Database, factory
    ) -> None:
        """The one line an operator reads. `deferred 1` for an unsynced repo
        is the same false claim in a shorter form."""
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert "deferred 0" in result.summary()
        assert "unverified 1" in result.summary()

    async def test_the_warning_does_not_say_due_for_rotation(
        self, db: Database, factory, caplog
    ) -> None:
        """What a human actually reads in the container log."""
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)

        with caplog.at_level("WARNING"):
            await rotate_ingestion_tokens(db, factory)

        logged = caplog.text
        assert "due for token rotation" not in logged
        assert "NOT due for rotation" in logged
        assert "never presented its active ingestion token" in logged


class TestTheBriefingSurfacesIt:
    """It took thirty hours of container logs to find the deferral. #263's
    fourth acceptance criterion: put it on the page people already read."""

    def test_an_unverified_token_is_reported_as_not_due(self, db: Database) -> None:
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)

        waiting = deliveries_awaiting_operator(db)

        assert [(t.repo_full_name, t.state) for t in waiting] == [(REPO, "unverified")]
        # The number the log line omitted, and the one a reader checks.
        assert waiting[0].days_until_due > 80

    def test_a_due_token_is_reported_as_due(self, db: Database) -> None:
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO, days=95)

        waiting = deliveries_awaiting_operator(db)

        assert [(t.repo_full_name, t.state) for t in waiting] == [(REPO, "due")]
        assert waiting[0].days_until_due < 0

    def test_a_repo_the_sweep_can_deliver_to_is_not_put_in_front_of_a_person(
        self, db: Database
    ) -> None:
        """An Actions-scanned repository is resynced by the job itself, so
        naming it here would be work nobody has to do."""
        onboard(db, repo=REPO, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)

        assert deliveries_awaiting_operator(db) == []

    def test_a_confirmed_delivery_leaves_the_page(self, db: Database) -> None:
        """The whole point of the first half: once ingestion has proved the
        token arrived, the operator stops being asked about it."""
        onboard(db, repo=REPO, scanned_by="concourse")
        with db.session() as session:
            plaintext = TokenRegistry(session).issue(REPO)
        assert deliveries_awaiting_operator(db)

        with db.session() as session:
            registry = TokenRegistry(session)
            resolution = registry.resolve(plaintext)
            assert resolution is not None
            registry.confirm_delivery(resolution.token_sha256)

        assert deliveries_awaiting_operator(db) == []

    def test_the_rendered_briefing_tells_the_two_apart(self) -> None:
        """Rendered, because the defect was only ever visible in prose: a
        reader who is told "due for rotation" and finds December concludes the
        channel is noise."""
        from mykronos import briefing as briefing_report

        now = utcnow()
        report = briefing_report.Briefing(
            generated_at=now,
            total_open=0,
            tokens=[
                briefing_report.TokenDelivery(
                    repo_full_name=REPO,
                    state="unverified",
                    issued_at=now,
                    rotate_after=now + timedelta(days=88),
                    scanned_by="concourse",
                ),
                briefing_report.TokenDelivery(
                    repo_full_name="ToddGBenson/personal-soc",
                    state="due",
                    issued_at=now - timedelta(days=95),
                    rotate_after=now - timedelta(days=5),
                    scanned_by="concourse",
                ),
            ],
        )

        text = briefing_report.render(report)

        assert "DELIVERY NEVER CONFIRMED" in text
        assert "NOT due" in text
        assert "Do NOT" in text
        assert "ToddGBenson/personal-soc  — DUE" in text
        assert "rotate by hand" in text

    def test_an_unreadable_registry_does_not_read_as_nothing_waiting(self) -> None:
        """`None` is "could not ask", an empty list is "asked, nothing there".
        Rendering the two the same way is the shape this whole issue is."""
        from mykronos import briefing as briefing_report

        unknown = briefing_report.Briefing(generated_at=utcnow(), total_open=0)
        unknown.tokens_unknown = True

        assert "Could not read the token registry" in briefing_report.render(unknown)
        assert "Could not read the token registry" not in briefing_report.render(
            briefing_report.Briefing(generated_at=utcnow(), total_open=0)
        )


def test_the_column_survives_a_schema_upgrade(tmp_path) -> None:
    """`delivery_confirmed_at` is added to a table that already exists in
    every deployment, so the start-up migration has to add it rather than the
    model silently disagreeing with the database."""
    url = f"sqlite:///{(tmp_path / 'upgrade.db').as_posix()}"
    database = Database(url)
    database.create_all()
    with database.engine.begin() as connection:
        from sqlalchemy import text

        connection.execute(text("ALTER TABLE ingestion_tokens DROP COLUMN delivery_confirmed_at"))
    database.close()

    upgraded = Database(url)
    upgraded.create_all()
    with upgraded.session() as session:
        TokenRegistry(session).issue(REPO)
        session.flush()
        row = session.query(IngestionToken).one()
        assert row.delivery_confirmed_at is None
    upgraded.close()
