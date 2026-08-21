/**
 * Does Patchwork remove risk, or only open pull requests? (spec 25 §3)
 *
 * Until the verification loop shipped, those two were indistinguishable from
 * this platform: a fixer nobody merges and a fixer that silently removes real
 * risk every week both showed as `pr_opened` rows. The first is a machine
 * generating review load, and that load is paid by exactly the people this
 * platform exists to help.
 *
 * `verified` is the only column that says risk was removed, so it is the one
 * that carries colour. `unverified` is deliberately muted rather than warned:
 * merged-but-not-established is the scan failing to answer, not the fix
 * failing to work, and tinting it red would make an infrastructure problem
 * look like a bad fixer.
 */

import { Label, Pill, Section } from "@/components/primitives";
import type { FixEfficacy } from "@/lib/server";

type Row = FixEfficacy["by_fixer"][number];

function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 90) return `${seconds}s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

function EfficacyTable({ rows, keyLabel }: { rows: Row[]; keyLabel: string }) {
  if (rows.length === 0) {
    return (
      <p className="px-3 py-3 text-[11px] text-ink-3">
        Nothing recorded — no fix has been generated yet.
      </p>
    );
  }

  return (
    <div className="scroll-x">
      <table className="w-full min-w-[640px] border-collapse font-mono text-[11px]">
        <thead>
          <tr className="border-b border-rule text-left">
            {[keyLabel, "Attempts", "PRs", "Merged", "Verified", "Still open", "Unverified", "Median"].map(
              (heading) => (
                <th
                  key={heading}
                  className="whitespace-nowrap px-2 py-1.5 text-[9px] font-semibold uppercase tracking-[0.1em] text-ink-3"
                >
                  {heading}
                </th>
              ),
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            // Opened a lot, verified nothing: the shape worth spotting.
            const suspect = row.prs_opened >= 3 && row.verified === 0;
            return (
              <tr key={row.key} className="border-t border-rule-soft first:border-t-0">
                <td className="px-2 py-1.5 font-semibold text-ink">
                  {row.key}
                  {suspect ? (
                    <span className="ml-2">
                      <Pill
                        tone="warn"
                        title="Opened pull requests, and none of them has been verified to remove a finding"
                      >
                        unproven
                      </Pill>
                    </span>
                  ) : null}
                </td>
                <td className="tabular px-2 py-1.5 text-ink-2">{row.attempts}</td>
                <td className="tabular px-2 py-1.5 text-ink-2">{row.prs_opened}</td>
                <td className="tabular px-2 py-1.5 text-ink-2">{row.merged}</td>
                <td
                  className={`tabular px-2 py-1.5 font-bold ${
                    row.verified > 0 ? "text-pass" : "text-ink-3"
                  }`}
                >
                  {row.verified}
                </td>
                <td
                  className={`tabular px-2 py-1.5 ${
                    row.still_open > 0 ? "text-critical" : "text-ink-3"
                  }`}
                >
                  {row.still_open}
                </td>
                <td className="tabular px-2 py-1.5 text-ink-3">{row.unverified}</td>
                <td className="tabular px-2 py-1.5 text-ink-3">
                  {duration(row.median_seconds_to_verified)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function FixEfficacyPanel({ efficacy }: { efficacy: FixEfficacy }) {
  const verified = efficacy.by_fixer.reduce((sum, row) => sum + row.verified, 0);
  const merged = efficacy.by_fixer.reduce((sum, row) => sum + row.merged, 0);

  return (
    <div className="flex flex-col gap-3">
      <div className="border-l-2 border-accent bg-accent-wash px-3 py-2">
        <Label>Did the fixes work?</Label>
        <p className="mt-1 max-w-prose text-[11px] leading-relaxed text-ink-2">
          {efficacy.note}
        </p>
        {merged > 0 ? (
          <p className="mt-1.5 font-mono text-[10px] text-ink-3">
            {verified} of {merged} merged fix{merged === 1 ? "" : "es"} verified as
            removing the finding.
          </p>
        ) : null}
      </div>

      <Section title="By fixer" detail="which fixers actually work">
        <EfficacyTable rows={efficacy.by_fixer} keyLabel="Fixer" />
      </Section>

      <Section title="By rule" detail="which rules are fixable here">
        <EfficacyTable rows={efficacy.by_rule} keyLabel="Rule" />
      </Section>
    </div>
  );
}
