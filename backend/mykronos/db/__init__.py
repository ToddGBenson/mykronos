"""Operational state.

Deliberately *not* the data lake. The lake (spec 05) is append-mostly
analytical signal, queried with OLAP scans; this is small, transactional,
frequently-updated state — onboarding records, capability config, tokens,
audit log. DuckDB is the wrong engine for it and mixing the two would put
row-level updates in the path of the compaction job.

SQLite in v1, for the same reason the lake is local-first: zero
infrastructure. Everything goes through SQLAlchemy, so the swap to Postgres
is a URL change. See docs/DECISIONS.md D-010.
"""

from mykronos.db.models import (
    AuditLogEntry,
    Base,
    CapabilityConfig,
    CapabilityGrant,
    IngestionToken,
    Organization,
    RepoOnboarding,
    WorkflowInstallEvent,
)
from mykronos.db.session import Database

__all__ = [
    "AuditLogEntry",
    "Base",
    "CapabilityConfig",
    "CapabilityGrant",
    "Database",
    "IngestionToken",
    "Organization",
    "RepoOnboarding",
    "WorkflowInstallEvent",
]
