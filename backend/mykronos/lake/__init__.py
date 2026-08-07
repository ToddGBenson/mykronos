"""The local data lake: DuckDB over Parquet on local disk (spec 05 §2).

Write path is one-way and single-entry:

    Ingestion API -> write-ahead JSONL buffer -> compaction -> Parquet

Nothing else writes to the Parquet partitions (spec 05 §9). Readers — the
dashboard query service and Oracle — go through the DuckDB catalog read-only.
"""

from mykronos.lake.buffer import WriteAheadBuffer
from mykronos.lake.catalog import Catalog
from mykronos.lake.compaction import CompactionResult, compact

__all__ = ["Catalog", "CompactionResult", "WriteAheadBuffer", "compact"]
