"""Engine and session management."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import date, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, Engine, create_engine, event, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from mykronos.db.models import AuditLogEntry, Base

logger = logging.getLogger(__name__)

#: Columns deliberately retired, as `(table, column)`. Dropped on start by
#: `Database.drop_retired_columns` once the model no longer declares them.
#:
#: Append only when the removal has been decided somewhere a reader can find:
#: an entry here is a schema change, and the reason it happened does not live
#: in this list.
#:
#: - `repo_onboardings.auto_merge_workflow_prs` (D-095): a setting nothing
#:   could ever consume. Spec 08 §3 gives `GitHubClient` no merge method, so
#:   the option could not act even when set — and a toggle implying otherwise
#:   quietly contradicts a refusal the platform holds on purpose.
RETIRED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("repo_onboardings", "auto_merge_workflow_prs"),
)


class Database:
    """Owns the engine and hands out sessions."""

    def __init__(self, url: str) -> None:
        connect_args: dict[str, Any] = {}
        if url.startswith("sqlite"):
            # FastAPI serves requests from a threadpool; SQLite's default
            # same-thread check would reject those connections.
            connect_args["check_same_thread"] = False
            path = url.removeprefix("sqlite:///")
            if path and path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)

        self.engine: Engine = create_engine(url, connect_args=connect_args, future=True)

        if url.startswith("sqlite"):
            _enable_sqlite_pragmas(self.engine)

        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_all(self) -> None:
        Base.metadata.create_all(self.engine)
        self.add_missing_columns()
        self.drop_retired_columns()

    def add_missing_columns(self) -> list[str]:
        """Add columns the models declare and the database does not.

        `create_all` creates missing *tables*; by design it leaves a table that
        already exists alone. So a column added to an existing model appears in
        every database created after the change — including every test database,
        which is built fresh — and in none of the databases that already exist.
        The test suite therefore agrees with the model and disagrees with
        production, which is the worst arrangement available: nothing fails
        until a query names the column.

        That is not hypothetical. `repo_onboardings.scanned_by` was added to the
        model, shipped, and took the repository list down in production with
        `no such column` while the container reported healthy and 1088 tests
        passed.

        The lake already treats this as routine — `add_missing_columns` upgrades
        a Parquet partition as it is rewritten, because a column added after a
        partition was written is absent from it and the query fails pointing at
        the column rather than at the cause. The operational store has the same
        problem and, until now, no answer to it.

        Returns what it changed, so the caller can say so out loud. A migration
        that runs silently is only marginally better than one that never runs.
        """
        inspector = inspect(self.engine)
        existing_tables = set(inspector.get_table_names())
        applied: list[str] = []

        with self.engine.begin() as connection:
            for table in Base.metadata.sorted_tables:
                if table.name not in existing_tables:
                    continue  # create_all just built it, with every column.

                present = {c["name"] for c in inspector.get_columns(table.name)}
                for column in table.columns:
                    if column.name in present:
                        continue

                    # DDL cannot bind parameters, so these statements are
                    # built by interpolation - which is safe only because
                    # every interpolated name comes from this application's
                    # own model metadata, never from a request. _identifier
                    # makes that a checked property instead of an argument:
                    # anything that is not a plain SQL identifier refuses to
                    # deploy, so a hostile name in the metadata cannot ride
                    # the upgrade path even if one ever got there.
                    connection.execute(text(self._add_column_sql(table.name, column)))
                    applied.append(f"{table.name}.{column.name}")

                    # A column carrying index=True gets its index with the table
                    # on a fresh database. Added later, it would silently not.
                    for index in table.indexes:
                        if index.name is None:
                            continue  # Unnamed: nothing stable to create it as.
                        if {c.name for c in index.columns} == {column.name}:
                            connection.execute(
                                text(
                                    f"CREATE INDEX IF NOT EXISTS {_identifier(index.name)} "
                                    f"ON {_identifier(table.name)} ({_identifier(column.name)})"
                                )
                            )

        if applied:
            logger.warning("Schema upgrade: added %s", ", ".join(applied))
        return applied

    def drop_retired_columns(self) -> list[str]:
        """Drop the columns in `RETIRED_COLUMNS`, once they exist nowhere else.

        Deliberately an explicit list rather than the obvious inverse of
        `add_missing_columns` — "drop every column the models do not declare"
        would be a data-loss bug waiting for its first rollback. A deploy that
        briefly runs the previous image, or a container that starts against a
        database a newer version already touched, would drop live columns and
        then repopulate nothing. Naming each retirement means a column can only
        go when somebody decided it should.

        Idempotent: a column already gone is skipped, so this is safe to run on
        every start, which is what makes it a migration rather than a one-off
        script somebody has to remember to execute.

        Returns what it changed, for the same reason `add_missing_columns`
        does.
        """
        inspector = inspect(self.engine)
        existing_tables = set(inspector.get_table_names())
        dropped: list[str] = []

        with self.engine.begin() as connection:
            for table_name, column_name in RETIRED_COLUMNS:
                if table_name not in existing_tables:
                    continue

                present = {c["name"] for c in inspector.get_columns(table_name)}
                if column_name not in present:
                    continue  # Already retired, or never existed here.

                # Same interpolation rule as `add_missing_columns`: both names
                # are literals in this module, never request data, and
                # `_identifier` makes that a checked property.
                connection.execute(
                    text(
                        f"ALTER TABLE {_identifier(table_name)} "
                        f"DROP COLUMN {_identifier(column_name)}"
                    )
                )
                dropped.append(f"{table_name}.{column_name}")

        if dropped:
            logger.warning("Schema upgrade: dropped %s", ", ".join(dropped))
        return dropped

    def _add_column_sql(self, table_name: str, column: Column[Any]) -> str:
        """DDL for one added column, with the value existing rows should carry.

        SQLite cannot add a NOT NULL column without a default — there would be
        no value for the rows already there — so a required column has to bring
        one. The model's own default is the right value by definition: it is
        what the application would have written had the column existed.
        """
        type_sql = column.type.compile(self.engine.dialect)
        clause = (
            f"ALTER TABLE {_identifier(table_name)} "
            f"ADD COLUMN {_identifier(column.name)} {type_sql}"
        )

        default = self._default_literal(column)
        if default is not None:
            clause += f" DEFAULT {default}"
        elif not column.nullable:
            raise RuntimeError(
                f"Cannot add required column {table_name}.{column.name}: it has "
                "no default, so there is no value for the rows already in the "
                "table. Give it a default (or make it nullable) — this is "
                "checked by a test so it should never reach a running system."
            )

        # NOT NULL has to follow DEFAULT to be valid; UNIQUE is deliberately
        # dropped because SQLite rejects it on ADD COLUMN.
        return clause + ("" if column.nullable else " NOT NULL")

    def _default_literal(self, column: Column[Any]) -> str | None:
        """The column's default rendered as a SQL literal, if it has one."""
        # `server_default` may be a DefaultClause (has .arg) or a FetchedValue
        # (computed by the database, nothing to render); `default` may likewise
        # be a Sequence rather than a ColumnDefault. getattr narrows both
        # without enumerating SQLAlchemy's hierarchy.
        server_arg = getattr(column.server_default, "arg", None)
        if server_arg is not None:
            return str(server_arg)

        value = getattr(column.default, "arg", None)
        if value is None:
            return None
        if callable(value):
            # SQLAlchemy wraps zero-argument callables to take a context.
            try:
                value = value(None)
            except TypeError:
                return None

        if isinstance(column.type, JSON):
            return _quote(json.dumps(value))
        if isinstance(value, bool):
            return "1" if value else "0"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, datetime):
            return _quote(value.isoformat(sep=" "))
        if isinstance(value, date):
            return _quote(value.isoformat())
        if isinstance(value, str):
            return _quote(value)
        return None

    def close(self) -> None:
        """Dispose the connection pool.

        Called on shutdown. Without it, pooled SQLite connections are closed by
        the garbage collector rather than deliberately, which surfaces as a
        ResourceWarning — and a test suite that treats warnings as errors is
        right to object to a process that leaks handles.
        """
        self.engine.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def audit(
        self,
        session: Session,
        *,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        **detail: Any,
    ) -> AuditLogEntry:
        """Append an audit entry (spec 12 §7).

        Takes the caller's session so the log entry commits in the same
        transaction as the change it describes — an audit log that can be
        missing entries for changes that succeeded is worse than none.
        """
        entry = AuditLogEntry(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            detail=detail,
        )
        session.add(entry)
        return entry


def _quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(name: str) -> str:
    """A name that is provably just a name, or a refusal.

    The schema-upgrade DDL interpolates table, column and index names because
    DDL cannot bind parameters. Every caller passes names from this
    application's own model metadata - but "trust the caller" is an argument,
    and this is a check: anything that would need quoting to be a SQL
    identifier does not get into a statement at all.
    """
    if not _IDENTIFIER.match(name):
        raise ValueError(f"{name!r} is not a plain SQL identifier")
    return name


def _enable_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        # WAL lets the daily reconciliation job read while a request writes.
        cursor.execute("PRAGMA journal_mode=WAL")
        # SQLite does not enforce foreign keys unless asked.
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()
