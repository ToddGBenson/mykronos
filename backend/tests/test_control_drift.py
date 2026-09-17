"""Control drift: noticing that a setting changed, not that a score did."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from mykronos import governance
from mykronos.db import Database
from mykronos.db.models import ControlDrift, Organization, RepoGovernance, RepoOnboarding
from mykronos.github.factory import FakeGitHubClientFactory
from mykronos.jobs import GovernanceSweepResult, sweep_governance


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(f"sqlite:///{(tmp_path / 'drift.db').as_posix()}")
    database.create_all()
    yield database
    database.close()


def _posture(**states: str) -> governance.Governance:
    return governance.Governance(
        repo_full_name="o/r",
        controls=[governance.Control(key=k, state=v) for k, v in states.items()],
        read_at=datetime(2026, 9, 3, 12, 0, 0),
        source="branch_protection",
    )


class TestFirstReading:
    def test_a_first_reading_files_no_drift(self, db: Database) -> None:
        """Otherwise onboarding a repository files one security regression per
        control, for a repository that has done nothing."""
        with db.session() as session:
            drift = governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        assert list(drift) == []

    def test_the_states_are_kept_so_the_next_read_can_compare(self, db: Database) -> None:
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()
            row = session.get(RepoGovernance, "o/r")
            assert row is not None
            assert row.control_states == {"pull_request_required": "on"}


class TestDetectingAChange:
    def test_a_control_coming_off_is_recorded(self, db: Database) -> None:
        """The event this whole story exists for. Governance was always read
        live, so the console always showed the truth — nothing compared one
        reading to the next, so a repository could quietly drop its review
        requirement and leave no trace but a score nobody watched."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        with db.session() as session:
            drift = governance.remember(session, _posture(pull_request_required="off"))
            session.commit()

        assert len(drift.drift) == 1
        assert drift.drift[0].control_key == "pull_request_required"
        assert (drift.drift[0].from_state, drift.drift[0].to_state) == ("on", "off")

    def test_an_unchanged_control_writes_nothing(self, db: Database) -> None:
        """Six-hourly sweeps mean this runs 1,460 times a year per repository.
        A row per read would bury the four that matter."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        for _ in range(3):
            with db.session() as session:
                drift = governance.remember(session, _posture(pull_request_required="on"))
                session.commit()
                assert list(drift) == []

        with db.session() as session:
            assert session.query(ControlDrift).count() == 0

    def test_a_control_being_turned_on_is_recorded_too(self, db: Database) -> None:
        """Drift is not only bad news. A team that fixed something should see
        that it landed."""
        with db.session() as session:
            governance.remember(session, _posture(signed_commits_required="off"))
            session.commit()

        with db.session() as session:
            drift = governance.remember(session, _posture(signed_commits_required="on"))
            session.commit()

        assert (drift.drift[0].from_state, drift.drift[0].to_state) == ("off", "on")


class TestWhatItRefusesToCallDrift:
    def test_a_control_becoming_unknown_is_not_drift(self, db: Database) -> None:
        """#264. This test previously asserted the opposite — that `on ->
        unknown` was filed as a `ControlDrift` row — and the two governance
        warnings this estate has ever sent were that row, on keel and binnacle,
        for a `codeowners_coverage` control that read `on` with a 4,468-byte
        CODEOWNERS in place the whole time.

        A revoked permission and a security regression must never look the
        same. It is reported, as an unreadable control, not as a regression."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        with db.session() as session:
            report = governance.remember(
                session, _posture(pull_request_required="unknown")
            )
            session.commit()

        assert report.drift == []
        assert report.unreadable == ["pull_request_required"]

        with db.session() as session:
            assert session.query(ControlDrift).count() == 0

    def test_a_control_recovering_from_unknown_is_not_drift(self, db: Database) -> None:
        """The other half of #264. `unknown -> on` is a read that started
        working, and reporting it as a control being switched on is a claim
        that it was off — which nobody ever observed."""
        with db.session() as session:
            governance.remember(session, _posture(codeowners_coverage="unknown"))
            session.commit()

        with db.session() as session:
            report = governance.remember(session, _posture(codeowners_coverage="on"))
            session.commit()

        assert report.drift == []
        assert report.unreadable == ["codeowners_coverage"]

        with db.session() as session:
            assert session.query(ControlDrift).count() == 0

    def test_a_failed_read_does_not_erase_the_last_known_state(self, db: Database) -> None:
        """The trap the #264 fix would otherwise set. If a read failure stored
        `unknown`, a repository that dropped its review requirement *while the
        read was broken* would come back as `unknown -> off` — which the fix
        suppresses, so a real regression would vanish.

        The stored row holds the last state each control was known to be in, so
        the transition that finally lands is `on -> off`."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="unknown"))
            session.commit()
            row = session.get(RepoGovernance, "o/r")
            assert row is not None
            assert row.control_states == {"pull_request_required": "on"}

        with db.session() as session:
            report = governance.remember(session, _posture(pull_request_required="off"))
            session.commit()

        assert len(report.drift) == 1
        assert (report.drift[0].from_state, report.drift[0].to_state) == ("on", "off")

    def test_a_real_regression_still_warns_alongside_an_unreadable_one(
        self, db: Database
    ) -> None:
        """Verified rather than assumed, per the acceptance criteria: the
        suppression is per control, not per read. A pass that loses one control
        to a failed read must still report the one that came off."""
        with db.session() as session:
            governance.remember(
                session,
                _posture(pull_request_required="on", codeowners_coverage="on"),
            )
            session.commit()

        with db.session() as session:
            report = governance.remember(
                session,
                _posture(pull_request_required="off", codeowners_coverage="unknown"),
            )
            session.commit()

        assert [(d.control_key, d.from_state, d.to_state) for d in report.drift] == [
            ("pull_request_required", "on", "off")
        ]
        assert report.unreadable == ["codeowners_coverage"]

    def test_a_control_appearing_for_the_first_time_is_not_drift(self, db: Database) -> None:
        """A control the App could not see before and can now is a change in
        permissions, not in how the repository is governed."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        with db.session() as session:
            drift = governance.remember(
                session,
                _posture(pull_request_required="on", signed_commits_required="off"),
            )
            session.commit()

        assert list(drift) == []


class TestReadingItBack:
    def test_recent_drift_is_newest_first_and_scopeable(self, db: Database) -> None:
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="off"))
            session.commit()

        with db.session() as session:
            scoped = governance.recent_drift(session, "o/r")
            estate = governance.recent_drift(session)
            other = governance.recent_drift(session, "other/repo")

        assert len(scoped) == 1
        assert len(estate) == 1
        assert other == []

    def test_rows_already_on_disk_that_cross_unknown_are_not_counted(
        self, db: Database
    ) -> None:
        """The #264 backfill. Two `codeowners_coverage on->unknown` rows are on
        disk for keel and binnacle, 2026-09-05 and 2026-09-09, and both were
        read failures — `_drift` no longer writes them, but the record still
        holds them and they are two of the three rows in it.

        Written here through the model rather than through `remember`, because
        `remember` is exactly what can no longer produce one."""
        with db.session() as session:
            session.add(
                ControlDrift(
                    repo_full_name="ToddGBenson/keel",
                    control_key="codeowners_coverage",
                    from_state="on",
                    to_state="unknown",
                    observed_at=datetime(2026, 9, 9, 22, 39, 42),
                )
            )
            session.add(
                ControlDrift(
                    repo_full_name="ToddGBenson/keel",
                    control_key="pull_request_required",
                    from_state="on",
                    to_state="off",
                    observed_at=datetime(2026, 9, 10, 1, 0, 0),
                )
            )
            session.commit()

        with db.session() as session:
            rows = governance.recent_drift(session, "ToddGBenson/keel")

        assert [(r.control_key, r.to_state) for r in rows] == [
            ("pull_request_required", "off")
        ]


def _onboard(db: Database, repo: str) -> None:
    with db.session() as session:
        org = Organization(github_org_login=repo.split("/")[0])
        session.add(org)
        session.flush()
        session.add(
            RepoOnboarding(
                org_id=org.id,
                github_repo_full_name=repo,
                github_installation_id=1,
                status="active",
                enabled_capabilities=["sast"],
                default_branch="main",
                onboarded_by="test",
            )
        )
        session.commit()


class TestTheSweepThatReportsIt:
    """`sweep_governance` is where #264 reached a person.

    `main.py` logs the sweep at `warning` when `result.drifted` is non-zero, on
    the stated grounds that a rationed channel only works if what gets through
    is real. Both alerts it has ever sent were failed reads.
    """

    async def _sweep(
        self, db: Database, monkeypatch: pytest.MonkeyPatch, states: dict[str, str]
    ) -> GovernanceSweepResult:
        async def fake_read(
            client: object, repo: str, branch: str
        ) -> governance.Governance:
            return governance.Governance(
                repo_full_name=repo,
                controls=[
                    governance.Control(key=k, state=v) for k, v in states.items()
                ],
                read_at=datetime(2026, 9, 9, 22, 39, 42),
                source="branch_protection",
            )

        monkeypatch.setattr(governance, "read", fake_read)
        return await sweep_governance(db, FakeGitHubClientFactory())

    async def test_a_failed_control_read_is_counted_but_is_not_drift(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The live 2026-09-09 line was `5 read, 0 unreadable, 2 control(s)
        changed: ... codeowners_coverage on->unknown`, which `main.py` sent at
        `warning`. `drifted` has to stay zero or that branch fires again.

        `unreadable` — the repository-level count — stays zero too, and that is
        the gap the issue names: the repository was readable, one control in it
        was not, and nothing counted the difference."""
        _onboard(db, "ToddGBenson/keel")
        await self._sweep(db, monkeypatch, {"codeowners_coverage": "on"})

        result = await self._sweep(db, monkeypatch, {"codeowners_coverage": "unknown"})

        assert result.drifted == 0
        assert result.changes == []
        assert result.unreadable == 0
        assert result.unreadable_controls == 1
        assert result.unreadable_reads == ["ToddGBenson/keel codeowners_coverage"]
        assert "control(s) changed" not in result.summary()
        assert result.summary() == (
            "1 read, 0 unreadable, nothing changed, could not read 1 control(s): "
            "ToddGBenson/keel codeowners_coverage"
        )

    async def test_a_control_coming_off_still_drifts(
        self, db: Database, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verified rather than assumed. A fix that silenced the false alert by
        silencing the real one would pass every other test here."""
        _onboard(db, "ToddGBenson/keel")
        await self._sweep(db, monkeypatch, {"pull_request_required": "on"})

        result = await self._sweep(db, monkeypatch, {"pull_request_required": "off"})

        assert result.drifted == 1
        assert result.changes == ["ToddGBenson/keel pull_request_required on->off"]
        assert result.unreadable_controls == 0
        assert "pull_request_required on->off" in result.summary()
