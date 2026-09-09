"""The ledger and the grant table cannot drift silently any more (B-062, D-119).

Four doors, each of which was open on 2026-09-05:

- a PATCH built from the dashboard's list revoked five grants the ledger
  never showed, and recorded `removed: []` -- now refused with a 409 naming
  them, unless the caller says `revoke_unlisted`;
- nothing reported the two tables disagreeing -- `grants.drift` reads both
  sides, and `grants.reconcile` widens them to the union and never revokes;
- the coverage cross-check walked the enabled set, so a job uploading a
  capability that was *not* enabled read as "not a fault" -- it is
  `job_not_enabled` now, and a problem;
- a refused upload was a 403 in a green build log -- it is a notification
  too, once per repository and capability per quiet window.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy import select

from mykronos import grants
from mykronos.api.refusals import REFUSAL_QUIET_SECONDS
from mykronos.auth import TokenRegistry
from mykronos.ci import Reporting, coverage
from mykronos.cli import _build_parser
from mykronos.db.models import AuditLogEntry, RepoOnboarding
from mykronos.notify import Notification
from tests.conftest import REPO, issue_token, scan_run_payload
from tests.test_onboarding import onboard


def _grant_directly(client: TestClient, repo: str, capability: str) -> None:
    """What `mykronos grant` does: the table moves, the ledger does not."""
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        TokenRegistry(session).grant(repo, capability)


def _granted(client: TestClient, repo: str) -> set[str]:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        return TokenRegistry(session).granted_capabilities(repo)


def _last_capabilities_audit(client: TestClient) -> dict:
    with client.app.state.db.session() as session:  # type: ignore[attr-defined]
        row = session.execute(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "repo.capabilities")
            .order_by(AuditLogEntry.created_at.desc())
        ).scalars().first()
        assert row is not None
        return dict(row.detail)


class TestThePatchRefusesToNarrowSilently:
    def test_a_grant_the_ledger_never_showed_is_not_revoked_by_omission(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """The exact call from 2026-09-05: the dashboard showed six, the
        table held eleven, the admin sent the six."""
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        _grant_directly(client, REPO, "dast")

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )

        assert response.status_code == 409
        assert "dast" in response.json()["detail"]
        assert "revoke_unlisted" in response.json()["detail"]
        # Nothing moved.
        assert _granted(client, REPO) == {"sast", "dast"}

    def test_including_the_grant_keeps_it(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        _grant_directly(client, REPO, "dast")

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "dast"], "install_workflows": False},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json()["removed"] == []
        assert _granted(client, REPO) == {"sast", "dast"}

    def test_saying_so_revokes_it_and_the_audit_says_what_went(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        _grant_directly(client, REPO, "dast")

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False, "revoke_unlisted": True},
            headers=admin_auth,
        )

        assert response.status_code == 200
        assert response.json()["removed"] == ["dast"]
        assert _granted(client, REPO) == {"sast"}
        # What was DONE, not what the ledger diff implied (B-062's first
        # acceptance criterion): the ledger never had dast, so a ledger diff
        # would have said `removed: []` here, as it did on the 5th.
        audit = _last_capabilities_audit(client)
        assert audit["removed"] == ["dast"]
        assert audit["ledger_removed"] == []

    def test_the_actions_path_is_guarded_the_same_way(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        _grant_directly(client, REPO, "dast")

        refused = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )
        assert refused.status_code == 409
        assert "dast" in refused.json()["detail"]

    def test_a_pending_capability_is_not_unlisted(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        """Withdrawing a capability before its PR merges is a legitimate
        narrowing: the grant is ahead of the ledger by design, and the
        caller could see it as pending."""
        repo_id = onboard(client, admin_auth).json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast", "dast"]},
            headers=admin_auth,
        )

        response = client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"]},
            headers=admin_auth,
        )

        assert response.status_code == 200


class TestDriftIsReadableAndReconcileNeverRevokes:
    def _set_up_drift(self, client: TestClient, admin_auth: dict[str, str]) -> None:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )
        _grant_directly(client, REPO, "dast")  # granted, not enabled
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            row = session.execute(
                select(RepoOnboarding).where(RepoOnboarding.github_repo_full_name == REPO)
            ).scalar_one()
            row.enabled_capabilities = ["sast", "iac"]  # enabled, not granted
            session.commit()

    def test_drift_names_both_directions(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        self._set_up_drift(client, admin_auth)

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            rows = grants.drift(session, TokenRegistry(session))

        (row,) = [r for r in rows if r.repo_full_name == REPO]
        assert row.drifted
        assert row.grant_only == {"dast"}
        assert row.ledger_only == {"iac"}

    def test_reconcile_widens_both_sides_and_revokes_nothing(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        self._set_up_drift(client, admin_auth)

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            before = grants.reconcile(session, TokenRegistry(session))
            session.commit()
        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            after = grants.drift(session, TokenRegistry(session))
            ledger = session.execute(
                select(RepoOnboarding.enabled_capabilities).where(
                    RepoOnboarding.github_repo_full_name == REPO
                )
            ).scalar_one()

        assert [r.repo_full_name for r in before] == [REPO]
        assert not any(r.drifted for r in after)
        assert _granted(client, REPO) == {"sast", "dast", "iac"}
        assert set(ledger) == {"sast", "dast", "iac"}

    def test_a_clean_estate_has_nothing_to_reconcile(
        self, client: TestClient, admin_auth: dict[str, str]
    ) -> None:
        repo_id = onboard(client, admin_auth, scanned_by="concourse").json()["id"]
        client.patch(
            f"/api/repos/{repo_id}/capabilities",
            json={"capabilities": ["sast"], "install_workflows": False},
            headers=admin_auth,
        )

        with client.app.state.db.session() as session:  # type: ignore[attr-defined]
            assert grants.reconcile(session, TokenRegistry(session)) == []

    def test_the_cli_knows_the_command(self) -> None:
        args = _build_parser().parse_args(["reconcile-grants", "--apply"])
        assert args.command == "reconcile-grants"
        assert args.apply is True


class TestTheCrossCheckSeesAJobForACapabilityNobodyEnabled:
    def _reporting(self, capability: str) -> list[Reporting]:
        now = datetime.now(UTC)
        return [Reporting(job=capability, capability=capability, built_at=now, scanned_at=now)]

    def test_a_job_for_an_unenabled_capability_is_a_problem(self) -> None:
        """The inverse of `no_job`: the lane runs, the upload is refused, the
        lane is green. `not_enabled` said "not a fault"."""
        rows = coverage({"sast"}, self._reporting("dast"))
        dast = next(r for r in rows if r.stage == "dast")

        assert dast.state == "job_not_enabled"
        assert dast.enabled is False
        assert dast.problem is True

    def test_not_enabled_with_no_job_is_still_not_a_fault(self) -> None:
        rows = coverage({"sast"}, self._reporting("sast"))
        dast = next(r for r in rows if r.stage == "dast")

        assert dast.state == "not_enabled"
        assert dast.problem is False

    def test_an_event_driven_capability_never_reads_as_a_stray_job(self) -> None:
        """Oracle has no lane; a Reporting row for it would be a bookkeeping
        artefact rather than a job, and must not turn a disabled Oracle red."""
        rows = coverage(set(), self._reporting("oracle"))
        oracle = next(r for r in rows if r.stage == "oracle")

        assert oracle.state == "not_enabled"


class _Recorder:
    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    async def send(self, note: Notification) -> bool:
        self.sent.append(note)
        return True


class TestARefusedUploadReachesAPerson:
    def test_the_403_is_unchanged_and_a_notification_goes_out(
        self, client: TestClient
    ) -> None:
        recorder = _Recorder()
        client.app.state.notifier = recorder  # type: ignore[attr-defined]
        token = issue_token(client, REPO, "sast")

        response = client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="dast"),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert response.json()["detail"].startswith(f"'dast' is not enabled for {REPO}.")
        assert "Currently granted: sast." in response.json()["detail"]
        assert len(recorder.sent) == 1
        note = recorder.sent[0]
        assert note.repo_full_name == REPO
        assert "dast" in note.title
        assert f"mykronos grant {REPO} dast" in note.detail

    def test_the_same_pair_is_quiet_inside_the_window(self, client: TestClient) -> None:
        """A scheduled lane that lost its grant must not become a channel
        somebody mutes."""
        recorder = _Recorder()
        client.app.state.notifier = recorder  # type: ignore[attr-defined]
        token = issue_token(client, REPO, "sast")

        for _ in range(3):
            client.post(
                "/api/ingest/scan-run",
                json=scan_run_payload(capability="dast"),
                headers={"Authorization": f"Bearer {token}"},
            )
        # A different capability on the same repository is a different event.
        client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="iac"),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert [n.title.split()[0] for n in recorder.sent] == ["dast", "iac"]
        assert REFUSAL_QUIET_SECONDS >= 600

    def test_the_window_expires(self, client: TestClient) -> None:
        recorder = _Recorder()
        client.app.state.notifier = recorder  # type: ignore[attr-defined]
        token = issue_token(client, REPO, "sast")
        client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="dast"),
            headers={"Authorization": f"Bearer {token}"},
        )
        client.app.state.refusals_seen[(REPO, "dast")] -= REFUSAL_QUIET_SECONDS + 1  # type: ignore[attr-defined]

        client.post(
            "/api/ingest/scan-run",
            json=scan_run_payload(capability="dast"),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert len(recorder.sent) == 2
