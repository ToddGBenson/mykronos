"""The CLI refuses a database that is not there (TheHub #60907).

Run from a checkout, `mykronos briefing` read the default
`sqlite:///mykronos.db`, SQLite created that file empty in whatever directory
the command ran from, and the first query died 100 lines into a traceback
ending `no such table: repo_onboardings`. Nothing said the platform CLI runs
inside the container, or that the file it had just "opened" was its own
creation.

Now: one message naming the file and the way out, exit 2, no traceback, and no
file left behind. Commands that never touch the database are unaffected, and
the two that create the schema still do.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import mykronos.cli as cli
from mykronos.config import Settings


def _settings(tmp_path: Path, db: Path) -> Settings:
    return Settings(
        datalake_dir=tmp_path / "datalake",
        database_url=f"sqlite:///{db.as_posix()}",
        run_compaction_in_background=False,
        run_jobs_in_background=False,
        gate_token="",
        github_app_id="",
        github_app_private_key_path=None,
    )


def _use(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)


class TestAMissingFile:
    def test_briefing_exits_2_with_one_message_and_no_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        db = tmp_path / "mykronos.db"
        _use(monkeypatch, _settings(tmp_path, db))

        assert cli.main(["briefing"]) == 2

        out = capsys.readouterr()
        assert str(db.resolve()) in out.err
        assert "does not exist" in out.err
        assert "docker exec mykronos-backend mykronos briefing" in out.err
        assert "MYKRONOS_DATABASE_URL" in out.err
        assert "Traceback" not in out.err
        assert "OperationalError" not in out.err

    def test_it_does_not_create_the_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opening it is what created it. The next run then found a file,
        which is how an empty database came to look like a real one."""
        db = tmp_path / "mykronos.db"
        _use(monkeypatch, _settings(tmp_path, db))

        cli.main(["list-tokens"])

        assert not db.exists()

    def test_the_message_names_the_command_that_was_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        _use(monkeypatch, _settings(tmp_path, tmp_path / "mykronos.db"))

        assert cli.main(["list-tokens"]) == 2
        assert "docker exec mykronos-backend mykronos list-tokens" in capsys.readouterr().err


class TestAFileWithNoSchema:
    def test_an_empty_file_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """The state the first failed run left behind."""
        db = tmp_path / "mykronos.db"
        db.touch()
        _use(monkeypatch, _settings(tmp_path, db))

        assert cli.main(["briefing"]) == 2

        err = capsys.readouterr().err
        assert "no Mykronos schema" in err
        assert "repo_onboardings" in err
        assert "Traceback" not in err
        assert db.stat().st_size == 0

    def test_a_database_missing_a_core_table_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        db = tmp_path / "other.db"
        con = sqlite3.connect(db)
        con.execute("CREATE TABLE something_else (id INTEGER)")
        con.commit()
        con.close()
        _use(monkeypatch, _settings(tmp_path, db))

        assert cli.main(["list-tokens"]) == 2
        assert "no Mykronos schema" in capsys.readouterr().err


class TestWhatStillWorks:
    def test_a_real_database_is_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        db = tmp_path / "mykronos.db"
        _use(monkeypatch, _settings(tmp_path, db))
        assert cli.main(["init-lake"]) == 0
        capsys.readouterr()

        assert cli.main(["list-tokens"]) == 0
        assert "no usable database" not in capsys.readouterr().err

    def test_init_lake_still_creates_the_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The command whose job is to create it."""
        db = tmp_path / "fresh.db"
        _use(monkeypatch, _settings(tmp_path, db))

        assert cli.main(["init-lake"]) == 0
        assert cli.sqlite_database_problem(f"sqlite:///{db.as_posix()}") is None

    def test_a_command_that_never_touches_the_database_is_unaffected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """`query` reads the lake, not the operational database."""
        db = tmp_path / "mykronos.db"
        settings = _settings(tmp_path, db)
        _use(monkeypatch, settings)
        cli.Catalog(settings.datalake_dir).initialise()

        assert cli.main(["query", "SELECT 1 AS one"]) == 0
        assert "one" in capsys.readouterr().out
        assert not db.exists()


class TestTheCheck:
    @pytest.mark.parametrize(
        "url",
        ["postgresql://u@h/db", "sqlite://", "sqlite:///:memory:"],
    )
    def test_non_file_databases_are_not_checked(self, url: str) -> None:
        assert cli.sqlite_database_problem(url) is None
