#!/usr/bin/env python3
"""Write the backend's OpenAPI schema to a file.

The frontend's typed client is generated from this, so it is the contract
between the two halves of the platform. CI regenerates it and fails if the
committed types have drifted — a backend change that breaks the frontend
should fail the build, not surface as a runtime error in someone's browser.

    python scripts/dump_openapi.py frontend/openapi.json
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from mykronos.config import Settings  # noqa: E402
from mykronos.main import create_app  # noqa: E402


def main() -> int:
    destination = Path(sys.argv[1] if len(sys.argv) > 1 else "frontend/openapi.json")

    # A throwaway lake and database: building the app must not touch, create
    # or migrate anything real just to read its own route table.
    scratch = Path(tempfile.mkdtemp())
    app = create_app(
        Settings(
            datalake_dir=scratch / "datalake",
            database_url=f"sqlite:///{(scratch / 'schema.db').as_posix()}",
            run_compaction_in_background=False,
            run_jobs_in_background=False,
        )
    )

    schema = app.openapi()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {destination} — {len(schema['paths'])} paths")
    return 0


if __name__ == "__main__":
    sys.exit(main())
