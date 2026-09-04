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


def onboard(
    db: Database,
    repo: str = REPO,
    status: str = "active",
    scanned_by: str = "github_actions",
) -> str:
    """Onboard a repository for a job test.

    `scanned_by` defaults to `github_actions` here, and the default is the
    point: the rotation job's only delivery path is a GitHub Actions secret
    (D-086), so a test of that path has to be about a repository that uses it.
    The *model* defaults to `concourse`, which is what this estate actually
    runs — so before this parameter existed, every rotation test asserted the
    Actions write succeeded against a Concourse repo and passed. Saying so per
    test beats every test inheriting an assumption it does not state.
    """
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
            scanned_by=scanned_by,
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


class FakeConcourse:
    """Answers only the question the rotation job asks.

    Three states, because the real client has three: a pipeline exists, it
    does not, or Concourse could not be reached. The third is why this is not
    a bool (D-097).
    """

    def __init__(self, *, has_pipeline: bool | None) -> None:
        self._has_pipeline = has_pipeline
        self.asked: list[str] = []

    def has_pipeline_for(self, repo_full_name: str) -> bool | None:
        self.asked.append(repo_full_name)
        return self._has_pipeline


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

    async def test_a_concourse_repo_is_deferred_not_rotated(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """D-086. The job cannot deliver to Vault, and GitHub would happily
        accept a secret for a repo whose Actions lanes were retired — so the
        rotation is deferred rather than performed and abandoned. An
        un-rotated token keeps working; a rotated, undelivered one breaks the
        repository when its overlap expires."""
        onboard(db, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.deferred == [REPO]
        assert result.rotated == []
        assert DEFAULT_SECRET_NAME not in github.repos[REPO].secrets

    async def test_a_repo_scanned_by_both_systems_is_deferred(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """D-097, and the outage it came from. `scanned_by` holds one value,
        so a repository migrating from Concourse to Actions declares
        `github_actions` while a Concourse pipeline goes on reading the same
        token from Vault. It passed D-086's guard, rotated, delivered to
        Actions only, and broke four lanes on 2026-08-31 when the overlap
        expired. The question is who reads the token, not what the repo
        declares."""
        onboard(db, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(
            db, factory, concourse=FakeConcourse(has_pipeline=True)
        )

        assert result.deferred == [REPO]
        assert result.rotated == []
        assert DEFAULT_SECRET_NAME not in github.repos[REPO].secrets

    async def test_an_actions_only_repo_still_rotates(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """The check has to stay narrow. A repository with no Concourse
        pipeline has one reader, the job can reach it, and deferring every
        rotation would quietly end 90-day rotation altogether."""
        onboard(db, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(
            db, factory, concourse=FakeConcourse(has_pipeline=False)
        )

        assert result.rotated == [REPO]
        assert DEFAULT_SECRET_NAME in github.repos[REPO].secrets

    async def test_an_unreachable_concourse_defers_rather_than_assumes(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """"Could not check" is not "nobody else reads it", and only one of
        those is safe to rotate on. Failing open here would reproduce the
        outage on any day Concourse happened to be down."""
        onboard(db, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(
            db, factory, concourse=FakeConcourse(has_pipeline=None)
        )

        assert result.deferred == [REPO]
        assert result.rotated == []

    async def test_the_unsynced_sweep_cannot_rotate_a_both_systems_repo(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """The faster of the two triggers. An active token with
        `secret_synced = 0` is swept up and rotated *again* as a resync, on
        the job's ordinary interval rather than the 90-day clock — so a manual
        repair that reaches Vault but not Actions would arm the recurrence by
        itself."""
        onboard(db, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)  # never marked synced
        # Deliberately not aged: this is the unsynced path, not the due path.

        result = await rotate_ingestion_tokens(
            db, factory, concourse=FakeConcourse(has_pipeline=True)
        )

        assert result.deferred == [REPO]
        assert result.rotated == []
        assert result.resynced == []

    async def test_without_a_concourse_client_the_old_behaviour_stands(
        self, db: Database, factory, github: FakeGitHubClient
    ) -> None:
        """The parameter is optional so existing callers keep working. It is
        wired at both real call sites; this pins the default so a caller that
        forgets is a rotation that happens, not a silent deferral of every
        repository forever."""
        onboard(db, scanned_by="github_actions")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert result.rotated == [REPO]

    async def test_a_deferred_repo_keeps_a_working_token(
        self, db: Database, factory
    ) -> None:
        """The whole reason for deferring: nothing is superseded, so the
        credential the pipeline holds goes on working."""
        onboard(db, scanned_by="concourse")
        with db.session() as session:
            plaintext = TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        await rotate_ingestion_tokens(db, factory)

        with db.session() as session:
            assert TokenRegistry(session).resolve(plaintext) is not None

    async def test_the_deferral_is_reported_in_the_summary(
        self, db: Database, factory
    ) -> None:
        """A silent skip is the failure mode this replaces."""
        onboard(db, scanned_by="concourse")
        with db.session() as session:
            TokenRegistry(session).issue(REPO)
            TokenRegistry(session).mark_secret_synced(REPO)
        age_token(db, REPO)

        result = await rotate_ingestion_tokens(db, factory)

        assert "deferred 1" in result.summary()

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
