"""Engine and session management."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from mykronos.db.models import AuditLogEntry, Base


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
