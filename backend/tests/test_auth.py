"""Ingestion token lifecycle — spec 05 §4, spec 12 §2, D-009."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from mykronos.auth import TokenRegistry, hash_token
from mykronos.db import Database
from mykronos.schemas import utcnow

REPO = "example-org/payments-api"
OTHER = "example-org/ledger-core"


@pytest.fixture
def session(tmp_path) -> Iterator[Session]:
    db = Database(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    db.create_all()
    with db.session() as s:
        yield s
    db.close()


@pytest.fixture
def registry(session: Session) -> TokenRegistry:
    return TokenRegistry(session, overlap_hours=24)


class TestIssuance:
    def test_plaintext_is_returned_once_and_never_stored(
        self, registry: TokenRegistry
    ) -> None:
        """spec 12 §2: only the hash is persisted."""
        plaintext = registry.issue(REPO)
        registry.session.flush()

        stored = registry.list_tokens()
        assert len(stored) == 1
        assert stored[0].token_sha256 == hash_token(plaintext)
        assert plaintext not in str(stored[0].__dict__)

    def test_token_resolves_to_its_repo(self, registry: TokenRegistry) -> None:
        plaintext = registry.issue(REPO)
        resolution = registry.resolve(plaintext)
        assert resolution is not None
        assert resolution.repo_full_name == REPO

    def test_a_fresh_token_grants_nothing(self, registry: TokenRegistry) -> None:
        """Issuing a credential does not by itself authorise anything —
        capabilities are granted separately and explicitly."""
        resolution = registry.resolve(registry.issue(REPO))
        assert resolution is not None
        assert resolution.granted_capabilities == frozenset()
        assert not resolution.permits("sast")

    def test_issuing_twice_rotates_rather_than_forking(
        self, registry: TokenRegistry
    ) -> None:
        """Two live credentials for one repo would be a credential leak with
        no way to tell which is in use."""
        first = registry.issue(REPO)
        second = registry.issue(REPO)
        assert first != second

        active = [t for t in registry.list_tokens() if t.status == "active"]
        assert len(active) == 1
        assert active[0].token_sha256 == hash_token(second)

    def test_unknown_token_resolves_to_none(self, registry: TokenRegistry) -> None:
        assert registry.resolve("never-issued") is None


class TestGrants:
    def test_grant_then_permit(self, registry: TokenRegistry) -> None:
        plaintext = registry.issue(REPO)
        registry.grant(REPO, "sast")

        resolution = registry.resolve(plaintext)
        assert resolution is not None
        assert resolution.permits("sast")
        assert not resolution.permits("secrets")

    def test_grant_is_idempotent(self, registry: TokenRegistry) -> None:
        assert registry.grant(REPO, "sast") is True
        assert registry.grant(REPO, "sast") is False
        assert registry.granted_capabilities(REPO) == {"sast"}

    def test_revoking_one_grant_leaves_the_rest(self, registry: TokenRegistry) -> None:
        """The property that makes a per-repo token acceptable: capability
        granularity survives even though the credential is shared."""
        plaintext = registry.issue(REPO)
        for capability in ("sast", "secrets", "iac"):
            registry.grant(REPO, capability)

        registry.revoke_grant(REPO, "secrets")

        resolution = registry.resolve(plaintext)
        assert resolution is not None
        assert resolution.granted_capabilities == frozenset({"sast", "iac"})

    def test_revocation_needs_no_github_call_so_cannot_half_apply(
        self, registry: TokenRegistry
    ) -> None:
        """Contrast with the superseded design, which had to delete a repo
        secret — an API call that can fail and leave a live credential."""
        registry.issue(REPO)
        registry.grant(REPO, "sast")
        assert registry.revoke_grant(REPO, "sast") is True
        assert registry.revoke_grant(REPO, "sast") is False
        assert registry.granted_capabilities(REPO) == set()

    def test_sync_reports_the_delta(self, registry: TokenRegistry) -> None:
        registry.issue(REPO)
        registry.sync_grants(REPO, {"sast", "secrets"})

        added, removed = registry.sync_grants(REPO, {"sast", "iac"})
        assert added == {"iac"}
        assert removed == {"secrets"}
        assert registry.granted_capabilities(REPO) == {"sast", "iac"}

    def test_grants_do_not_leak_between_repos(self, registry: TokenRegistry) -> None:
        mine = registry.issue(REPO)
        registry.issue(OTHER)
        registry.grant(OTHER, "sast")

        resolution = registry.resolve(mine)
        assert resolution is not None
        assert resolution.granted_capabilities == frozenset()


class TestRotation:
    def test_both_tokens_work_during_the_overlap(self, registry: TokenRegistry) -> None:
        """spec 05 §9. A job reads the secret when it starts and posts findings
        many minutes later; a naive swap would 401 it through no fault of the
        code under scan.
        """
        old = registry.issue(REPO)
        registry.grant(REPO, "sast")
        new = registry.rotate(REPO)

        assert registry.resolve(old) is not None, "in-flight workflow must survive"
        assert registry.resolve(new) is not None

    def test_the_old_token_is_flagged_so_it_is_diagnosable(
        self, registry: TokenRegistry
    ) -> None:
        old = registry.issue(REPO)
        new = registry.rotate(REPO)

        old_resolution = registry.resolve(old)
        new_resolution = registry.resolve(new)
        assert old_resolution is not None and old_resolution.superseded is True
        assert new_resolution is not None and new_resolution.superseded is False

    def test_the_old_token_stops_working_after_the_window(
        self, registry: TokenRegistry
    ) -> None:
        """The other half of the contract: an overlap that never expires is
        not a rotation."""
        old = registry.issue(REPO)
        new = registry.rotate(REPO)

        later = utcnow() + timedelta(hours=25)
        assert registry.resolve(old, as_of=later) is None
        assert registry.resolve(new, as_of=later) is not None

    def test_grants_survive_rotation(self, registry: TokenRegistry) -> None:
        """Grants hang off the repo, not the credential, so rotating must not
        silently disable every capability."""
        registry.issue(REPO)
        registry.grant(REPO, "sast")
        new = registry.rotate(REPO)

        resolution = registry.resolve(new)
        assert resolution is not None
        assert resolution.permits("sast")

    def test_zero_overlap_is_honoured(self, session: Session) -> None:
        """A deployment that wants a hard cutover can have one."""
        registry = TokenRegistry(session, overlap_hours=0)
        old = registry.issue(REPO)
        registry.rotate(REPO)
        assert registry.resolve(old) is None

    def test_due_for_rotation_finds_aged_tokens(self, registry: TokenRegistry) -> None:
        registry.issue(REPO)
        registry.session.flush()

        assert registry.due_for_rotation() == []
        assert registry.due_for_rotation(as_of=utcnow() + timedelta(days=91)) == [REPO]

    def test_purge_removes_only_expired_superseded_tokens(
        self, registry: TokenRegistry
    ) -> None:
        registry.issue(REPO)
        registry.rotate(REPO)
        registry.session.flush()
        assert len(registry.list_tokens()) == 2

        assert registry.purge_expired() == 0, "still inside the window"
        assert registry.purge_expired(as_of=utcnow() + timedelta(hours=25)) == 1

        remaining = registry.list_tokens()
        assert len(remaining) == 1
        assert remaining[0].status == "active"


class TestRevocation:
    def test_offboarding_kills_every_token_and_grant(
        self, registry: TokenRegistry
    ) -> None:
        old = registry.issue(REPO)
        new = registry.rotate(REPO)
        registry.grant(REPO, "sast")

        registry.revoke_repo(REPO)

        assert registry.resolve(old) is None
        assert registry.resolve(new) is None
        assert registry.granted_capabilities(REPO) == set()

    def test_revoking_one_repo_does_not_touch_another(
        self, registry: TokenRegistry
    ) -> None:
        mine = registry.issue(REPO)
        theirs = registry.issue(OTHER)
        registry.grant(OTHER, "sast")

        registry.revoke_repo(REPO)

        assert registry.resolve(mine) is None
        resolution = registry.resolve(theirs)
        assert resolution is not None
        assert resolution.permits("sast")

    def test_a_revoked_token_is_indistinguishable_from_an_unknown_one(
        self, registry: TokenRegistry
    ) -> None:
        """A caller learns only that this token does not work now, not whether
        it ever did."""
        plaintext = registry.issue(REPO)
        registry.revoke_repo(REPO)
        assert registry.resolve(plaintext) is None
        assert registry.resolve("never-issued") is None


class TestImmediateRotation:
    """A leaked credential needs revocation, not graceful rotation.

    `rotate` keeps the previous token valid for the overlap window, which is
    correct for a scheduled swap (spec 05 §4) and exactly wrong for a token
    somebody else has seen. A token disclosed by `fly set-pipeline` (D-043) was
    "rotated" and kept answering 200 for the rest of the day.
    """

    def test_the_default_keeps_the_old_token_alive(self, session) -> None:
        registry = TokenRegistry(session, overlap_hours=24)
        old = registry.issue("owner/repo")
        registry.rotate("owner/repo")
        assert registry.resolve(old) is not None, "graceful rotation still honours the old token"

    def test_immediate_kills_it_now(self, session) -> None:
        registry = TokenRegistry(session, overlap_hours=24)
        old = registry.issue("owner/repo")
        registry.rotate("owner/repo", immediate=True)
        assert registry.resolve(old) is None, "a revoked token must stop working at once"

    def test_the_replacement_works_either_way(self, session) -> None:
        registry = TokenRegistry(session, overlap_hours=24)
        registry.issue("owner/repo")
        fresh = registry.rotate("owner/repo", immediate=True)
        resolution = registry.resolve(fresh)
        assert resolution is not None
        assert resolution.repo_full_name == "owner/repo"

    def test_grants_survive_an_immediate_rotation(self, session) -> None:
        """Revoking a token must not silently revoke what the repo may write —
        that is a different decision and would turn a credential incident into
        an outage nobody understood."""
        registry = TokenRegistry(session, overlap_hours=24)
        registry.issue("owner/repo")
        registry.grant("owner/repo", "sast")
        fresh = registry.rotate("owner/repo", immediate=True)
        assert registry.resolve(fresh).permits("sast")

    def test_immediate_expires_tokens_superseded_earlier(self, session) -> None:
        """The case the first version of this missed.

        Rotate once (the leaked token becomes superseded, still inside its
        overlap), then rotate again with --immediate. If `immediate` only
        touches the *active* token it expires the replacement and leaves the
        disclosed value working — which is what happened live.
        """
        registry = TokenRegistry(session, overlap_hours=24)
        leaked = registry.issue("owner/repo")
        registry.rotate("owner/repo")                    # leaked -> superseded
        assert registry.resolve(leaked) is not None      # still inside overlap
        registry.rotate("owner/repo", immediate=True)
        assert registry.resolve(leaked) is None, "an earlier superseded token must die too"
