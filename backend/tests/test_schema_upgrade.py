"""A column added to a model reaches databases that already exist (D-052).

The failure this replaces took production down while every signal said it was
fine. `scanned_by` was added to `RepoOnboarding`, shipped, and `create_all`
declined to touch a table it had already created — so the column existed in
every test database, which is built fresh, and in none of the deployed ones.
The container reported healthy, 1088 tests passed, and the repository list
returned 500 `no such column: repo_onboardings.scanned_by`.

The tests that matter here are the ones that fail *before* a deploy: the drift
guard below asserts every column the models declare can actually be added to a
table that already exists, which is the property the deploy needed and nobody
had checked.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from sqlalchemy import inspect, text

from mykronos.db.models import Base, RepoOnboarding
from mykronos.db.session import RETIRED_COLUMNS, Database


@pytest.fixture
def open_db(tmp_path):
    """Opens databases against one file and disposes every pool afterwards.

    Each `Database` here stands for a separate run of the process against the
    same file - which is the situation being tested - so there are several, and
    a pool left open surfaces as a ResourceWarning the suite treats as an error.
    """
    url = f"sqlite:///{tmp_path / 'ops.db'}"
    opened: list[Database] = []

    def _open() -> Database:
        db = Database(url)
        opened.append(db)
        return db

    yield _open

    for db in opened:
        db.close()


def columns(db: Database, table: str) -> set[str]:
    return {c["name"] for c in inspect(db.engine).get_columns(table)}


def add_column(db: Database, table: str, column: str) -> None:
    """Age the database back to when a since-retired column still existed.

    The mirror of `drop_column`: the model no longer declares these, so there
    is no metadata to build them from and the DDL is written out here.
    """
    with db.engine.begin() as connection:
        connection.execute(
            text(f"ALTER TABLE {table} ADD COLUMN {column} BOOLEAN DEFAULT 0 NOT NULL")
        )


def drop_column(db: Database, table: str, column: str) -> None:
    """Age the database back to before the column existed.

    Any index on the column goes first - SQLite leaves it dangling on DROP
    COLUMN, and a database from before the column existed had neither.
    """
    with db.engine.begin() as connection:
        for index in inspect(db.engine).get_indexes(table):
            if column in index["column_names"]:
                connection.execute(text(f"DROP INDEX {index['name']}"))
        connection.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))


class TestAColumnAddedLater:
    def test_it_is_added_to_a_database_that_already_exists(self, open_db) -> None:
        """The regression, exactly as it happened."""
        db = open_db()
        db.create_all()
        drop_column(db, "repo_onboardings", "scanned_by")
        assert "scanned_by" not in columns(db, "repo_onboardings")

        open_db().create_all()

        assert "scanned_by" in columns(open_db(), "repo_onboardings")

    def test_the_query_that_failed_in_production_works_again(self, open_db) -> None:
        """A column of the right name is not the point; serving the request is."""
        db = open_db()
        db.create_all()
        drop_column(db, "repo_onboardings", "scanned_by")

        open_db().create_all()

        with open_db().session() as session:
            assert session.query(RepoOnboarding).all() == []

    def test_rows_already_there_get_the_model_default(self, open_db) -> None:
        """Not NULL. A required column backfilled with nothing is the same
        outage one step later, and `concourse` is what the application would
        have written had the column existed."""
        db = open_db()
        db.create_all()
        with db.session() as session:
            session.add(
                RepoOnboarding(
                    org_id=_org(db),
                    github_repo_full_name="ToddGBenson/mykronos",
                    github_installation_id=1,
                )
            )
        drop_column(db, "repo_onboardings", "scanned_by")

        open_db().create_all()

        with open_db().session() as session:
            row = session.query(RepoOnboarding).one()
            assert row.scanned_by == "concourse"

    def test_it_says_what_it_changed(self, open_db) -> None:
        """A schema change that happens silently is only marginally better than
        one that does not happen."""
        db = open_db()
        db.create_all()
        drop_column(db, "repo_onboardings", "scanned_by")

        assert open_db().add_missing_columns() == ["repo_onboardings.scanned_by"]

    def test_an_index_comes_with_it(self, open_db) -> None:
        """An indexed column added later would otherwise be indexed on fresh
        databases and unindexed everywhere else - a performance difference that
        only appears in production."""
        db = open_db()
        db.create_all()
        drop_column(db, "ingestion_tokens", "status")

        open_db().create_all()

        names = {i["name"] for i in inspect(open_db().engine).get_indexes("ingestion_tokens")}
        assert any("status" in n for n in names)


class TestItIsSafeToRunEveryTime:
    def test_an_up_to_date_database_is_left_alone(self, open_db) -> None:
        db = open_db()
        db.create_all()

        assert open_db().add_missing_columns() == []

    def test_running_it_twice_changes_nothing_the_second_time(self, open_db) -> None:
        db = open_db()
        db.create_all()
        drop_column(db, "repo_onboardings", "scanned_by")

        first = open_db().add_missing_columns()
        second = open_db().add_missing_columns()

        assert first and second == []

    def test_existing_data_survives(self, open_db) -> None:
        db = open_db()
        db.create_all()
        org = _org(db)
        with db.session() as session:
            session.add(
                RepoOnboarding(
                    org_id=org,
                    github_repo_full_name="ToddGBenson/keel",
                    github_installation_id=7,
                    status="active",
                )
            )
        drop_column(db, "repo_onboardings", "scanned_by")

        open_db().create_all()

        with open_db().session() as session:
            row = session.query(RepoOnboarding).one()
            assert row.github_repo_full_name == "ToddGBenson/keel"
            assert row.status == "active"


#: Identity columns that shipped with their tables, before the upgrade
#: mechanism existed. They are in every database that has the table, so they
#: will never need adding later - and inventing defaults for them would be
#: worse than none (`audit_log.actor` defaulting to anything is a lie in an
#: audit log). Frozen: nothing is ever added here. A new column either brings
#: a default, or is nullable, or the guard below fails the build.
GRANDFATHERED = {
    "audit_log.actor",
    "audit_log.action",
    "audit_log.entity_type",
    "audit_log.entity_id",
    "capability_grants.repo_full_name",
    "capability_grants.capability",
    "ingestion_tokens.repo_full_name",
    "ingestion_tokens.rotate_after",
    "organizations.github_org_login",
    "repo_onboardings.org_id",
    "repo_onboardings.github_repo_full_name",
    "repo_onboardings.github_installation_id",
    "capability_configs.repo_onboarding_id",
    "capability_configs.capability",
    "workflow_install_events.repo_onboarding_id",
    "groomed_stories.repo_full_name",
    "groomed_stories.subject_type",
    "groomed_stories.subject_id",
    "groomed_stories.github_issue_number",
    "groomed_stories.github_issue_url",
    "groomed_stories.dev_ready",
    # The FK identifying which repo a profile is about (spec 21 §1.2) — the
    # same case as `workflow_install_events.repo_onboarding_id` above: a row
    # cannot exist without it, so there is no value to backfill an existing
    # row with, and inventing one would attach every old row to one repo.
    "risk_profiles.repo_onboarding_id",
    # And again for the import analysis (spec 19 §2.1). Identical case: a
    # reachability report is *about* a repository and cannot exist without
    # one, so there is nothing to backfill an existing row with. The table is
    # new, so no database has rows this would have to be added to.
    "reachability_reports.repo_onboarding_id",
    # Which repository a triage claim is about (spec 27 §3). The same case a
    # third time: a claim cannot exist without the repository it scopes to, so
    # there is no value an existing row could be backfilled with, and a
    # server-side default would attach every old row to the empty string —
    # which the queue would then read as a real repository. The table arrived
    # with #97, so no database has rows this would have to be added to.
    "triage_state.repo_full_name",
    # The controls register's three required columns (spec 28 §3). New table,
    # so nothing has rows these would be added to. Defaults would be worse
    # than absent for all three: a control with no repository belongs to
    # everybody, and one defaulted to a STRIDE category or a control kind is
    # a claim about a mitigation that nobody made — which is the one thing a
    # register of asserted controls must never contain.
    "repo_controls.repo_full_name",
    "repo_controls.stride",
    "repo_controls.kind",
    # The surface register's three required columns (B-029) — assets, entry
    # points and trust boundaries, the parts of a threat model `repo_controls`
    # does not cover. New table, so nothing has rows these would be added to,
    # and the argument against defaults is the one directly above, one step
    # stronger: a surface with no repository belongs to every repository; one
    # defaulted to `asset` asserts that something *is* an asset when nobody
    # said so; and an unnamed surface cannot be reviewed, which is why
    # `surfaces.declare` refuses one outright.
    #
    # `exposure` and `sensitivity` are deliberately absent from this list.
    # Both default to `unknown`, which is a real answer rather than a guess —
    # so both can be added to a populated table without asserting anything.
    "repo_surfaces.repo_full_name",
    "repo_surfaces.kind",
    "repo_surfaces.name",
}


class TestDriftGuard:
    def test_every_column_the_models_declare_can_be_added_later(self, open_db) -> None:
        """The guard that would have caught this before the deploy.

        Any column reachable by a future schema change has to be one that can
        be added to a table with rows already in it. A required column with no
        default cannot be, and SQLite says so only at the moment of upgrade -
        in production, on startup, long after the tests went green.
        """
        db = open_db()
        db.create_all()

        for table in Base.metadata.sorted_tables:
            for column in table.columns:
                if column.primary_key:
                    continue  # Never added later; the table is created with it.
                if f"{table.name}.{column.name}" in GRANDFATHERED:
                    continue
                db._add_column_sql(table.name, column)

    def test_the_grandfathered_list_does_not_grow(self, open_db) -> None:
        """Every entry must still be a violation. An entry that gains a default
        should leave the list; an entry for a column that no longer exists is
        dead weight hiding a real one."""
        db = open_db()
        db.create_all()

        actual = set()
        for table in Base.metadata.sorted_tables:
            for column in table.columns:
                if column.primary_key:
                    continue
                try:
                    db._add_column_sql(table.name, column)
                except RuntimeError:
                    actual.add(f"{table.name}.{column.name}")

        assert actual == GRANDFATHERED

    def test_a_required_column_with_no_default_is_refused_loudly(self, open_db) -> None:
        """Rather than being skipped. Skipping it would restore precisely the
        behaviour this whole change exists to remove."""
        from sqlalchemy import Column, String

        db = open_db()
        db.create_all()
        orphan = Column("needs_a_value", String(16), nullable=False)

        with pytest.raises(RuntimeError, match="no default"):
            db._add_column_sql("repo_onboardings", orphan)

    def test_a_hostile_name_cannot_ride_the_upgrade_path(self, open_db) -> None:
        """DDL cannot bind parameters, so the upgrade interpolates names. The
        names come from this application's own models - but that is an
        argument, and this is the check that replaces it. Flagged by SAST as
        avoid-sqlalchemy-text on 2026-08-15; the disposition rests on this
        test."""
        from sqlalchemy import Column, String

        db = open_db()
        db.create_all()
        hostile = Column("x; DROP TABLE repo_onboardings; --", String(8), nullable=True)

        with pytest.raises(ValueError, match="not a plain SQL identifier"):
            db._add_column_sql("repo_onboardings", hostile)

    def test_a_nullable_column_with_no_default_is_fine(self, open_db) -> None:
        """There is a correct value for the existing rows: unknown."""
        from sqlalchemy import Column, String

        db = open_db()
        db.create_all()
        optional = Column("maybe", String(16), nullable=True)

        assert "NOT NULL" not in db._add_column_sql("repo_onboardings", optional)


def _org(db: Database) -> str:
    from mykronos.db.models import Organization

    with db.session() as session:
        existing = session.query(Organization).first()
        if existing:
            return existing.id
        org = Organization(github_org_login="test")
        session.add(org)
        session.flush()
        return org.id


class TestARetiredColumn:
    """The inverse path: a column the models stopped declaring (D-095).

    `add_missing_columns` only ever adds, so a removed column would otherwise
    sit in every existing database forever — present in production, absent from
    every freshly-built test database, which is the same disagreement D-052 was
    written to end, pointing the other way.
    """

    def test_it_is_dropped_from_a_database_that_still_has_it(self, open_db) -> None:
        db = open_db()
        db.create_all()
        add_column(db, "repo_onboardings", "auto_merge_workflow_prs")
        assert "auto_merge_workflow_prs" in columns(db, "repo_onboardings")

        open_db().drop_retired_columns()

        assert "auto_merge_workflow_prs" not in columns(db, "repo_onboardings")

    def test_it_says_what_it_changed(self, open_db) -> None:
        db = open_db()
        db.create_all()
        add_column(db, "repo_onboardings", "auto_merge_workflow_prs")

        assert open_db().drop_retired_columns() == [
            "repo_onboardings.auto_merge_workflow_prs"
        ]

    def test_a_database_that_never_had_it_is_left_alone(self, open_db) -> None:
        db = open_db()
        db.create_all()

        assert open_db().drop_retired_columns() == []

    def test_running_it_twice_changes_nothing_the_second_time(self, open_db) -> None:
        db = open_db()
        db.create_all()
        add_column(db, "repo_onboardings", "auto_merge_workflow_prs")

        first = open_db().drop_retired_columns()
        second = open_db().drop_retired_columns()

        assert first and second == []

    def test_existing_data_survives(self, open_db) -> None:
        db = open_db()
        db.create_all()
        add_column(db, "repo_onboardings", "auto_merge_workflow_prs")
        org = _org(db)
        with db.session() as session:
            session.add(
                RepoOnboarding(
                    org_id=org,
                    github_repo_full_name="acme/keeps-its-rows",
                    github_installation_id=1,
                )
            )
            session.commit()

        open_db().drop_retired_columns()

        with open_db().session() as session:
            row = session.query(RepoOnboarding).one()
            assert row.github_repo_full_name == "acme/keeps-its-rows"

    def test_create_all_performs_the_retirement(self, open_db) -> None:
        """Not a script somebody has to remember: it runs on every start."""
        db = open_db()
        db.create_all()
        add_column(db, "repo_onboardings", "auto_merge_workflow_prs")

        open_db().create_all()

        assert "auto_merge_workflow_prs" not in columns(db, "repo_onboardings")

    def test_every_retired_column_is_gone_from_the_models(self, open_db) -> None:
        """A name cannot be in both lists. Re-declaring a retired column while
        it stays in RETIRED_COLUMNS would drop it on every single start."""
        for table_name, column_name in RETIRED_COLUMNS:
            table = Base.metadata.tables.get(table_name)
            if table is None:
                continue
            assert column_name not in table.columns, (
                f"{table_name}.{column_name} is declared on the model and also "
                "listed in RETIRED_COLUMNS. Every start would drop it and the "
                "next write would fail. Remove it from one of the two."
            )

    def test_a_hostile_name_cannot_ride_the_retirement_path(self, open_db) -> None:
        """Same guarantee `add_missing_columns` carries, on the way out.

        The name has to be one that really is on the table, or the "is it
        present?" guard skips it before any SQL is built and the check proves
        nothing. SQLite will accept it if it is quoted, which is exactly the
        shape `_identifier` exists to refuse.
        """
        hostile = "x; DROP TABLE repo_onboardings; --"
        db = open_db()
        db.create_all()
        with db.engine.begin() as connection:
            connection.execute(
                text(f'ALTER TABLE repo_onboardings ADD COLUMN "{hostile}" TEXT')
            )

        with (
            patch("mykronos.db.session.RETIRED_COLUMNS", (("repo_onboardings", hostile),)),
            pytest.raises(ValueError, match="not a plain SQL identifier"),
        ):
            db.drop_retired_columns()

        assert "repo_onboardings" in inspect(db.engine).get_table_names()
