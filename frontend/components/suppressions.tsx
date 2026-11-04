import { EmptyState, Pill } from "@/components/primitives";
import {
  expiryText,
  location,
  statusTone,
  type RepoSuppressions,
} from "@/lib/suppressions";

/**
 * Suppressed in the repository (TheHub #60963, decision #60815 option B).
 *
 * The other half of "what is not being fixed here". The acceptances above
 * are the platform's decisions, approved by someone independent. These are
 * the repository's own: a `# nosemgrep`, a `# checkov:skip=`, any result its
 * scanner reported as suppressed. They are not findings and never enter the
 * findings table (spec 05 s7), which is why they need a list of their own.
 * Each row shows the justification the author gave and the expiry, if any.
 * An undated one is flagged, because nobody revisits it.
 */
export function SuppressionsTable({ data }: { data: RepoSuppressions }) {
  if (data.suppressions.length === 0) {
    return (
      <EmptyState
        title="No scanner result is suppressed in this repository."
        detail="Nothing in the newest scans was silenced with a pragma or a scanner config entry."
      />
    );
  }
  const { expired, no_expiry: undated } = data.counts;
  return (
    <div className="overflow-x-auto border border-rule bg-paper-2">
      <table className="w-full min-w-[720px] border-collapse text-[13px]">
        <caption className="px-3 py-2 text-left text-[13px] text-ink-3">
          {data.suppressions.length} suppressed in {data.repo_full_name}
          {expired ? `, ${expired} expired` : ""}
          {undated ? `, ${undated} with no expiry` : ""}.
        </caption>
        <thead>
          <tr className="border-b border-rule text-left font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
            {["Tool", "Rule", "File", "Justification", "Expiry"].map((heading) => (
              <th key={heading} scope="col" className="px-3 py-1 font-normal">
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.suppressions.map((row) => (
            <tr
              key={`${row.tool}|${row.rule_id}|${location(row)}`}
              className="border-b border-rule align-top last:border-b-0"
            >
              <td className="px-3 py-1.5 font-mono text-[12px] text-ink-2">{row.tool}</td>
              <td className="break-all px-3 py-1.5 font-mono text-[12px] text-ink">{row.rule_id}</td>
              <td className="break-all px-3 py-1.5 font-mono text-[12px] text-ink-2">
                {location(row)}
              </td>
              <td className="px-3 py-1.5 text-ink-2">
                {row.justification || <span className="text-ink-3">none given</span>}
              </td>
              <td className="whitespace-nowrap px-3 py-1.5">
                <Pill tone={statusTone(row.status)}>{expiryText(row)}</Pill>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
