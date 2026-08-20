"""Turn a pipeline stage's exit codes into a JUnit report (PS-1).

Spec 15 §3's quality gate is "unit · functional · QA · lint · types". Three of
those five reached the lake as ScanRuns and two did not, because they are not
test suites — `ruff`, `mypy`, an OpenAPI contract diff and an API-inventory
diff are pass/fail commands with no report format in common. A stage that
cannot report is a stage the coverage cross-check cannot vouch for (L0003),
and a green tick nothing outside Concourse can see is exactly the state
spec 15 §4a.1 calls `never_reported`.

So: one testcase per command, its captured output as the failure body. JUnit
because the `qa` capability has exactly one registered adapter and it reads
JUnit XML (`adapters/registry.py`) — inventing a tool name would fail the
upload with "No adapter for capability 'qa'".

Quality stages record a run and never a finding (D-046): a failing assertion
is not a vulnerability, and giving it a severity would let a broken lint raise
a security risk score.

    python -m mykronos.junit_stage --out results/lint.xml --suite lint-and-types \
        --case ruff:$rc_ruff:/tmp/ruff.txt --case mypy:$rc_mypy:/tmp/mypy.txt

In the package rather than in `scripts/`, and that is the difference between
one staleness mechanism and two. A repo script reaches a pipeline by raw URL
at `${MYKRONOS_REF}` and 404s when the pin predates it; a module reaches it
through the same `pip install ...@${MYKRONOS_REF}` every uploader call already
uses, and `check_pinned_ref.py` already asserts that every such module and its
flags exist at the pin. One tag to cut, one check that notices.

Written with ElementTree rather than printf on purpose. The captured output
goes inside an XML element, and one `<` or `&` in a mypy message would produce
a document the adapter cannot parse — which reports as a *broken scan* rather
than a failing lint, and those must stay distinguishable.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import xml.etree.ElementTree as ET

#: Enough of the tail to see what failed, bounded so one runaway log cannot
#: push a multi-megabyte document at the ingestion API.
MAX_LOG_CHARS = 4000


def build(suite_name: str, cases: list[tuple[str, int, str | None]]) -> ET.ElementTree:
    suite = ET.Element("testsuite", name=suite_name, tests=str(len(cases)))
    failures = 0
    for name, code, log_path in cases:
        case = ET.SubElement(suite, "testcase", classname=suite_name, name=name)
        if code == 0:
            continue
        failures += 1
        body = ""
        if log_path:
            path = pathlib.Path(log_path)
            if path.exists():
                body = path.read_text(errors="replace")[-MAX_LOG_CHARS:]
        failure = ET.SubElement(case, "failure", message=f"{name} exited {code}")
        failure.text = body
    suite.set("failures", str(failures))
    return ET.ElementTree(suite)


def parse_case(raw: str) -> tuple[str, int, str | None]:
    """`name:rc` or `name:rc:/path/to/log`."""
    parts = raw.split(":", 2)
    if len(parts) < 2:
        raise argparse.ArgumentTypeError(f"--case wants name:rc[:logfile], got {raw!r}")
    name, code = parts[0], parts[1]
    try:
        # An empty rc is a caller whose shell variable was unset. That is a
        # broken pipeline task, not a passing check, and it must not quietly
        # become one.
        value = int(code)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--case rc must be an integer, got {code!r}") from None
    return name, value, (parts[2] if len(parts) > 2 and parts[2] else None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Where to write the JUnit XML.")
    parser.add_argument("--suite", required=True, help="Suite name, normally the job name.")
    parser.add_argument(
        "--case",
        required=True,
        action="append",
        type=parse_case,
        help="name:rc[:logfile], repeatable — one per command the stage ran.",
    )
    args = parser.parse_args(argv)

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    build(args.suite, args.case).write(out, encoding="unicode")

    failed = [name for name, code, _ in args.case if code]
    tail = f": {', '.join(failed)}" if failed else ""
    print(f"{out}: {len(args.case)} case(s), {len(failed)} failed{tail}")
    # Always 0. This writes a report; whether the stage passed is the caller's
    # verdict to act on, and conflating the two would let a failing lint look
    # like a broken reporter.
    return 0


if __name__ == "__main__":
    sys.exit(main())
