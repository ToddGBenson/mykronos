/**
 * Coverage beside the pass rate (spec 31 §4).
 *
 * A green sparkline says the tests that exist passed. A repository with one
 * trivial test and a 100% pass rate renders identically to one with a real
 * suite, and this is what separates them.
 *
 * **Not a security metric, and it says so on the page.** The label is not a
 * disclaimer bolted on — it is the reason this is safe to show at all. 90%
 * coverage with zero regression links (spec 31 §3) means the tests are
 * thorough about something other than the things that have actually gone
 * wrong here, and a number displayed without that sentence beside it will be
 * read as a security score by the third person who sees it.
 */

import { RelativeTime } from "@/components/relative-time";
import type { ScanHealth } from "@/lib/api";

type Row = ScanHealth["capabilities"][number];

function percent(value: number) {
  return `${Math.round(value * 100)}%`;
}

export function TestCoverage({ row }: { row: Row | undefined }) {
  const line = row?.line_coverage ?? null;
  const branch = row?.branch_coverage ?? null;

  // Null is not zero. A lane whose runner never wrote a coverage report and a
  // lane measured at zero are different facts, and rendering both as 0% would
  // make the honest one look like the broken one.
  if (line === null && branch === null) {
    return (
      <p className="font-mono text-[12px] leading-relaxed text-ink-3">
        No coverage reported. Write a Cobertura or JaCoCo report into
        <span className="text-ink-2"> $MYKRONOS_RESULTS</span> and it appears
        here.
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
      {line !== null ? (
        <span className="flex items-baseline gap-1.5">
          <span className="tabular font-mono text-lg font-bold leading-none text-ink">
            {percent(line)}
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
            lines
          </span>
        </span>
      ) : null}

      {branch !== null ? (
        <span className="flex items-baseline gap-1.5">
          <span className="tabular font-mono text-lg font-bold leading-none text-ink-2">
            {percent(branch)}
          </span>
          <span className="font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
            branches
          </span>
        </span>
      ) : null}

      {row?.coverage_at ? (
        <span className="font-mono text-[11px] text-ink-3">
          measured <RelativeTime value={row.coverage_at} />
        </span>
      ) : null}

      <p className="w-full max-w-prose text-[12px] leading-relaxed text-ink-3">
        Not a security metric. It says how much of the code the suite executes,
        not whether it would catch anything that has gone wrong here — that is
        regression coverage, which counts fixed findings with a test pinned to
        them.
      </p>
    </div>
  );
}
