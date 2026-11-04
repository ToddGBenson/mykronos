#!/usr/bin/env python3
"""Grade reachability verdicts on the seeded corpus (TheHub #60745).

Two methods over the same findings, both deterministic and neither a model:

* the import floor (`mykronos.reachability`, spec 19 §2.1) on its own, which
  is what every finding got before #60745;
* the taint verdict (`mykronos.taint_reachability.verdict_for`), which uses a
  Semgrep taint run for the rules in `TAINT_SPECS` and the floor otherwise.

**Precision** is graded on the taint-covered rules only: of the findings a
method gave a decisive verdict (`reachable` or `unreachable`), the share whose
verdict matches the manifest's `truth`. `unknown` is never wrong and never
counted as right; `decisive` is reported beside precision so a method cannot
look precise by deciding nothing.

The corpus is stored as `.py.txt` (see `bench/reachability/manifest.yaml`)
and copied out as `.py` into a temporary directory to be analysed.

Usage:

    python scripts/bench_reachability.py bench/reachability/manifest.yaml \\
        bench/reachability/corpus [--semgrep-json recorded.json]

Exit codes: 0 graded and taint precision is at least the floor's, 1 it is
lower, 3 the taint run failed (the grade could not be taken).
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from mykronos import reachability, taint_reachability  # noqa: E402
from mykronos.taint_reachability import (  # noqa: E402
    TAINT_SPECS,
    TaintRun,
    floor_verdict,
    verdict_for,
)

EXIT_GRADED = 0
EXIT_BELOW_FLOOR = 1
EXIT_NOT_MEASURED = 3


def _materialise(corpus: Path, into: Path) -> None:
    for source in sorted(corpus.iterdir()):
        if source.name.endswith(".py.txt"):
            shutil.copyfile(source, into / source.name[: -len(".txt")])


def _score(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    covered = [r for r in rows if r["rule_id"] in TAINT_SPECS]
    decisive = [r for r in covered if r[key] in ("reachable", "unreachable")]
    correct = [r for r in decisive if r[key] == r["truth"]]
    return {
        "findings": len(covered),
        "decisive": len(decisive),
        "correct": len(correct),
        "precision": (len(correct) / len(decisive)) if decisive else None,
    }


def grade(
    manifest: Path, corpus: Path, *, taint: TaintRun | None = None
) -> dict[str, Any]:
    """Grade both methods. With `taint` None, Semgrep is run on the corpus."""
    cases = (yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}).get("findings") or []
    with tempfile.TemporaryDirectory(prefix="mykronos-reach-bench-") as scratch:
        root = Path(scratch)
        _materialise(corpus, root)
        orphaned = set(reachability.orphaned(reachability.read_repository(str(root))))
        if taint is None:
            taint = taint_reachability.run_semgrep(root)

    rows: list[dict[str, Any]] = []
    for case in cases:
        floor = floor_verdict(case["path"], orphaned)
        verdict = verdict_for(
            case["rule_id"], case["path"], case["line"], orphaned=orphaned, taint=taint
        )
        rows.append(
            {
                "rule_id": case["rule_id"],
                "path": case["path"],
                "line": case["line"],
                "truth": case["truth"],
                "floor_verdict": floor.verdict,
                "taint_verdict": verdict.verdict,
                "basis": verdict.basis,
            }
        )

    return {
        "import_floor": _score(rows, "floor_verdict"),
        "taint": {
            **_score(rows, "taint_verdict"),
            "status": taint.status,
            "reason": taint.reason,
            "semgrep_version": taint.semgrep_version,
        },
        "orphaned": sorted(orphaned),
        "findings": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench_reachability", description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("corpus", type=Path)
    parser.add_argument(
        "--semgrep-json",
        type=Path,
        help="Grade a recorded `semgrep --json --dataflow-traces` run instead of running it.",
    )
    args = parser.parse_args(argv)

    taint = (
        taint_reachability.parse_semgrep_output(args.semgrep_json.read_text(encoding="utf-8"))
        if args.semgrep_json
        else None
    )
    result = grade(args.manifest, args.corpus, taint=taint)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")

    if result["taint"]["status"] != "ok":
        return EXIT_NOT_MEASURED
    floor, tainted = result["import_floor"]["precision"], result["taint"]["precision"]
    if floor is not None and (tainted is None or tainted < floor):
        return EXIT_BELOW_FLOOR
    return EXIT_GRADED


if __name__ == "__main__":
    raise SystemExit(main())
