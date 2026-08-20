/**
 * Which files nothing in this repository imports (spec 19 §2.1).
 *
 * The only Oracle input that *lowers* a score, which is why it is on the page
 * at all. A penalty nobody can see gets investigated when somebody disputes
 * it; a discount nobody can see is never disputed, because the finding it
 * quietened is the one nobody looked at twice.
 *
 * Three states, and the difference between the first two is the whole point:
 *
 * - never analysed — nothing has looked
 * - analysed, nothing orphaned — something looked and everything is imported
 * - analysed, some orphaned — the discount applies, and these are the files
 *
 * The card refuses to let the first two look alike, because Oracle scores
 * them differently and a reader has to be able to tell which one they have.
 */

import { Label, Pill, RelativeTime } from "@/components/primitives";
import type { Reachability } from "@/lib/server";

export function ReachabilityCard({ report }: { report: Reachability }) {
  if (!report.analysed) {
    return (
      <div className="border border-dashed border-rule bg-paper-2 px-3 py-2">
        <Label>Import reachability</Label>
        <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-3">
          No import analysis has run for this repository. That is not the same
          as nothing being unreachable — nothing has looked, so Oracle reports
          the category as unavailable and it contributes nothing either way. It
          runs alongside the <span className="font-mono">sast</span> capability
          and covers Python only.
        </p>
      </div>
    );
  }

  const orphaned = report.orphaned_paths ?? [];

  return (
    <div className="border border-rule bg-paper-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-rule-soft px-3 py-2">
        <span className="text-[11px] font-bold">Import reachability</span>
        <Pill tone={orphaned.length > 0 ? "warn" : "pass"}>
          {orphaned.length === 0
            ? "everything is imported"
            : `${orphaned.length} orphaned`}
        </Pill>
        <span className="font-mono text-[10px] text-ink-3">
          {report.files_analysed} {report.language} file
          {report.files_analysed === 1 ? "" : "s"} analysed
          {report.commit_sha ? ` · ${report.commit_sha.slice(0, 7)}` : ""}
        </span>
        {report.updated_at ? (
          <span className="ml-auto whitespace-nowrap font-mono text-[10px] text-ink-3">
            <RelativeTime value={report.updated_at} />
          </span>
        ) : null}
      </div>

      {orphaned.length > 0 ? (
        <div className="px-3 py-2">
          <Label>Nothing in the repository imports these</Label>
          <ul className="mt-1.5 flex flex-col gap-0.5 font-mono text-[10px] text-ink-2">
            {/* Capped: a repository where hundreds of files are orphaned has a
                layout problem, and printing all of them would bury the number
                that matters. The count above is always complete. */}
            {orphaned.slice(0, 25).map((path) => (
              <li key={path}>{path}</li>
            ))}
          </ul>
          {orphaned.length > 25 ? (
            <p className="mt-1 font-mono text-[10px] text-ink-3">
              …and {orphaned.length - 25} more.
            </p>
          ) : null}
        </div>
      ) : null}

      {report.files_unparseable > 0 ? (
        <p className="border-t border-rule-soft px-3 py-2 text-[11px] leading-relaxed text-ink-3">
          {report.files_unparseable} file
          {report.files_unparseable === 1 ? "" : "s"} could not be parsed, so no
          file is reported orphaned at all: an unreadable file might have been
          the only thing importing something else, and the analysis will not
          guess in the direction of calling live code dead.
        </p>
      ) : null}

      <p className="max-w-prose border-t border-rule-soft px-3 py-2 text-[11px] leading-relaxed text-ink-3">
        {report.note}
      </p>
    </div>
  );
}
