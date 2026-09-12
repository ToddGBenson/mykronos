"""The local data lake: DuckDB over Parquet on local disk (spec 05 §2).

Write path is one-way and single-entry:

    Ingestion API -> write-ahead JSONL buffer -> compaction -> Parquet

Nothing else writes to the Parquet partitions (spec 05 §9). Readers — the
dashboard query service and Oracle — go through the DuckDB catalog read-only.
"""

from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.carry_forward import CarryForwardResult, carry_forward
from mykronos.lake.catalog import Catalog
from mykronos.lake.compaction import CompactionResult, compact
from mykronos.lake.reconcile import ReconcileResult, reconcile_absences

__all__ = [
    "CarryForwardResult",
    "Catalog",
    "CompactionResult",
    "ReconcileResult",
    "WriteAheadBuffer",
    "carry_forward",
    "compact",
    "reconcile_absences",
]
