"""Scheduled jobs — spec 05 §4 §5, spec 02 §5.6.

These run unattended, so the tests are mostly about partial failure: what a
job leaves behind when it cannot finish.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest

from mykronos.auth import TokenRegistry
from mykronos.db import Database
from mykronos.db.models import IngestionToken, Organization, RepoOnboarding
from mykronos.github import FakeGitHubClient
from mykronos.github.client import GitHubError
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.installer import DEFAULT_SECRET_NAME
from mykronos.jobs import reconcile_installations, rotate_ingestion_tokens
from mykronos.lake import reconcile_absences
from mykronos.schemas import utcnow
from tests.conftest import CAPABILITY, REPO, finding_payload, post_findings, post_scan

INSTALLATION = 4242


@pytest.fixture
def db(tmp_path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'jobs.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


@pytest.fixture
def github() -> FakeGitHubClient:
    client = FakeGitHubClient()
    client.add_repo(REPO)
    client.installations[INSTALLATION] = {"id": INSTALLATION, "suspended_at": None}
    return client


@pytest.fixture
def factory(github: FakeGitHubClient) -> FakeGitHubClientFactory:
    return FakeGitHubClientFactory(github)


def onboard(db: Database, repo: str = REPO, status: str = "active") -> str:
    owner = repo.split("/")[0]
    with db.session() as session:
        # Reuse the org: github_org_login is unique, and two repos under one
        # owner is the normal case.
        org = (
            session.query(Organization)
            .filter(Organization.github_org_login == owner)
            .one_or_none()
        )
        if org is None:
            org = Organization(github_org_login=owner)
            session.add(org)
            session.flush()
        row = RepoOnboarding(
            org_id=org.id,
            github_repo_full_name=repo,
            github_installation_id=INSTALLATION,
            status=status,
            enabled_capabilities=["sast"],
            default_branch="main",
            onboarded_by="test",
        )
        session.add(row)
        session.flush()
        return str(row.id)


def age_token(db: Database, repo: str, days: int = 91) -> None:
    """Backdate the rotation clock so the token is due."""
    with db.session() as session:
        token = (
            session.query(IngestionToken)
            .filter(IngestionToken.repo_full_name == repo)
            .filter(IngestionToken.status == "active")
            .one()
        )
        token.rotate_after = utcnow() - timedelta(days=days - 90)


class TestRotation:
    async def test_rotates_a_due_token_and_writes_the_secret(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        onboard(db)
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.rotated == [REPO]
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets

    async def test_leaves_a_fresh_token_alone(self, db: Database, factory) -> None:
        onboard(db)
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.rotated == []
        assert result.resynced == []

    async def test_the_old_token_still_works_during_the_overlap(
        self, db: Database, factory
    ) -> None:
        """spec 05 §4: a job that read the old secret before the swap must
        still be able to post its findings."""
        onboard(db)
        with db.session() as session:
            old = TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        await rotate_ingestion_tokens(db, factory)

        with db.session() as session:
            assert TokenRegistry(session).resolve(old) is not None

    async def test_a_failed_secret_write_leaves_the_old_token_valid(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        """The ordering that makes rotation safe: nothing is stranded."""
        onboard(db)
        with db.session() as session:
            old = TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        # An App registered without secrets:write — the D-008 failure.
        github.permissions.pop("secrets")
        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == []
        assert len(result.failed) == 1
        with db.session() as session:
            assert TokenRegistry(session).resolve(old) is not None

    async def test_a_failed_write_is_retried_on_the_next_run(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        """The reason `secret_synced` exists.

        After a failed write the new token has a fresh 90-day clock, so a
        due-date check would never look at it again — and the repo would break
        silently when the old token's overlap expired.
        """
        onboard(db)
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        github.permissions.pop("secrets")
        await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        with db.session() as session:
            assert TokenRegistry(session).unsynced_repos() == [REPO]

        # Permission restored; the next sweep repairs it without waiting 90 days.
        github.permissions["secrets"] = "write"
        second = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert second.resynced == [REPO]
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets
        with db.session() as session:
            assert TokenRegistry(session).unsynced_repos() == []

    async def test_one_broken_repo_does_not_stop_the_others(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        onboard(db, REPO)
        onboard(db, "example-org/ledger-core")
        github.add_repo("example-org/ledger-core")
        with db.session() as session:
            registry = TokenRegistry(session)
            for repo in (REPO, "example-org/ledger-core"):
                registry.issue(repo)
                registry.mark_secret_synced(repo)
        age_token(db, REPO)
        age_token(db, "example-org/ledger-core")

        # Remove one repo from GitHub so its secret write 404s.
        del github.repos[REPO]
        result = await rotate_ingestion_tokens(db, FakeGitHubClientFactory(github))

        assert result.rotated == ["example-org/ledger-core"]
        assert [repo for repo, _ in result.failed] == [REPO]

    async def test_offboarded_repos_are_skipped(self, db: Database, factory) -> None:
        onboard(db, REPO, status="removed")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.rotated == []

    async def test_expired_superseded_tokens_are_purged(
        self, db: Database, factory
    ) -> None:
        """An overlap that never expires is not a rotation."""
        onboard(db)
        with db.session() as session:
            registry = TokenRegistry(session, overlap_hours=0)
            registry.issue(REPO)
            registry.mark_secret_synced(REPO)
            registry.rotate(REPO)
            registry.mark_secret_synced(REPO)

        result = await rotate_ingestion_tokens(db, factory, overlap_hours=0)

        assert result.purged == 1


class TestInstallationReconciliation:
    async def test_a_deleted_installation_marks_the_repo_removed(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        """spec 02 §5.6 — the fallback for a webhook that never arrived."""
        repo_id = onboard(db)
        github.installations.clear()

        result = await reconcile_installations(db, FakeGitHubClientFactory(github))

        assert result.removed == [REPO]
        with db.session() as session:
            assert session.get(RepoOnboarding, repo_id).status == "removed"

    async def test_a_live_installation_is_left_alone(
        self, db: Database, factory
    ) -> None:
        repo_id = onboard(db)
        result = await reconcile_installations(db, factory)

        assert result.removed == []
        with db.session() as session:
            row = session.get(RepoOnboarding, repo_id)
            assert row.status == "active"
            assert row.last_synced_at is not None

    async def test_suspension_is_detected(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        repo_id = onboard(db)
        github.installations[INSTALLATION]["suspended_at"] = "2026-08-08T00:00:00Z"

        result = await reconcile_installations(db, FakeGitHubClientFactory(github))

        assert result.suspended == [REPO]
        with db.session() as session:
            assert session.get(RepoOnboarding, repo_id).status == "suspended"

    async def test_a_transient_error_does_not_remove_the_repo(
        self, db: Database, github: FakeGitHubClient
    ) -> None:
        """Marking a repo removed because GitHub had a bad minute would stop
        its scans for no reason. Try again tomorrow."""
        repo_id = onboard(db)

        class Flaky(FakeGitHubClient):
            async def get_installation(self, installation_id: int):
                raise GitHubError("503 Service Unavailable", status=503)

        flaky = Flaky()
        result = await reconcile_installations(db, FakeGitHubClientFactory(flaky))

        assert result.unreachable == [REPO]
        assert result.removed == []
        with db.session() as session:
            assert session.get(RepoOnboarding, repo_id).status == "active"


class TestAbsenceReconciliation:
    """spec 05 §5 — two consecutive absences, not one."""

    def _scan(self, client, auth, run_id: str, findings: list[dict]) -> None:
        post_scan(client, auth, scan_run_id=run_id, scan_status="success")
        post_findings(client, auth, findings, scan_run_id=run_id)

    def test_one_absence_is_not_enough(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """A flaky scanner that misses something once must not close it —
        closing and reopening destroys resolved_at and MTTF."""
        self._scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        self._scan(client, auth, "run-2", [])
        run_compaction()

        reconcile_absences(catalog)

        assert catalog.query("SELECT status FROM findings") == [("open",)]

    def test_two_absences_close_the_finding(
        self, client, auth, catalog, run_compaction
    ) -> None:
        self._scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        self._scan(client, auth, "run-2", [])
        self._scan(client, auth, "run-3", [])
        run_compaction()

        result = reconcile_absences(catalog)

        assert result.total_fixed == 1
        status, resolved = catalog.query(
            "SELECT status, resolved_at FROM findings"
        )[0]
        assert status == "fixed"
        assert resolved is not None

    def test_a_still_reported_finding_stays_open(
        self, client, auth, catalog, run_compaction
    ) -> None:
        for run in ("run-1", "run-2", "run-3"):
            self._scan(client, auth, run, [finding_payload()])
        run_compaction()

        reconcile_absences(catalog)

        assert catalog.query("SELECT status FROM findings") == [("open",)]

    def test_failed_scans_do_not_confirm_absence(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """A scan that crashed and reported nothing is not evidence the
        finding is gone. Counting it would close findings whenever CI broke."""
        self._scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        for run in ("run-2", "run-3"):
            post_scan(client, auth, scan_run_id=run, scan_status="failure")
            post_findings(client, auth, [], scan_run_id=run)
        run_compaction()

        reconcile_absences(catalog)

        assert catalog.query("SELECT status FROM findings") == [("open",)]

    def test_human_dispositions_are_not_overwritten(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """false_positive is a decision. Absence does not turn it into
        'fixed', which would claim work nobody did."""
        from tests.test_lake import set_status

        self._scan(client, auth, "run-1", [finding_payload()])
        run_compaction()
        (finding_id,) = catalog.query("SELECT finding_id FROM findings")[0]
        set_status(catalog, finding_id, "false_positive")

        self._scan(client, auth, "run-2", [])
        self._scan(client, auth, "run-3", [])
        run_compaction()
        reconcile_absences(catalog)

        assert catalog.query("SELECT status FROM findings") == [("false_positive",)]

    def test_insufficient_history_is_reported_not_silent(
        self, client, auth, catalog, run_compaction
    ) -> None:
        """"We have not looked enough times" is different from "nothing to
        close", and an operator should be able to tell them apart."""
        self._scan(client, auth, "run-1", [finding_payload()])
        run_compaction()

        result = reconcile_absences(catalog)

        assert result.total_fixed == 0
        assert (REPO, CAPABILITY) in result.insufficient_history

    def test_an_empty_lake_is_a_no_op(self, catalog) -> None:
        catalog.initialise()
        assert reconcile_absences(catalog).total_fixed == 0
