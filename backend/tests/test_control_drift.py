"""Control drift: noticing that a setting changed, not that a score did."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

from mykronos import governance
from mykronos.db import Database
from mykronos.db.models import ControlDrift, RepoGovernance


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

        assert drift == []

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

        assert len(drift) == 1
        assert drift[0].control_key == "pull_request_required"
        assert (drift[0].from_state, drift[0].to_state) == ("on", "off")

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
                assert drift == []

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

        assert (drift[0].from_state, drift[0].to_state) == ("off", "on")


class TestWhatItRefusesToCallDrift:
    def test_a_control_becoming_unknown_is_a_failed_read(self, db: Database) -> None:
        """Recorded, but as a transition to `unknown` — never conflated with a
        control being removed. One is a revoked permission and the other is a
        security regression, and telling somebody the wrong one sends them to
        the wrong place."""
        with db.session() as session:
            governance.remember(session, _posture(pull_request_required="on"))
            session.commit()

        with db.session() as session:
            drift = governance.remember(session, _posture(pull_request_required="unknown"))
            session.commit()

        assert drift[0].to_state == "unknown"

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

        assert drift == []


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
