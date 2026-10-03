"""The TheHub deploy repairs collation drift before it acknowledges (TheHub #375).

`Invoke-TheHubDeploy.ps1` runs `compose up` on the whole project, which
recreates any database service whose image changed. Moving Postgres to a newer
glibc then leaves text indexes sorted by the old rules. These pin the three
properties the guard was verified against on a throwaway database: drift is
compared with IS DISTINCT FROM (production's recorded versions are NULL), a
NULL version is recorded directly (REFRESH refuses to start from NULL), and the
repair runs before the deploy is acknowledged.
"""

from __future__ import annotations

from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "thehub" / "Invoke-TheHubDeploy.ps1"


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_drift_is_compared_null_safely():
    src = _src()
    assert "datcollversion is distinct from pg_database_collation_actual_version(oid)" in src
    assert "datcollversion <> " not in src


def test_a_null_version_is_recorded_directly_not_refreshed():
    src = _src()
    assert "REINDEX DATABASE" in src
    assert "REFRESH COLLATION VERSION" in src
    assert "SET datcollversion = pg_database_collation_actual_version(oid)" in src
    assert "WHERE datname = current_database()" in src


def test_the_repair_runs_before_the_deploy_is_acknowledged():
    src = _src()
    body = src[src.index("if ($healthy) {"):]
    assert body.index("Repair-CollationDrift") < body.index("Set-Content -Path $stateFile")
