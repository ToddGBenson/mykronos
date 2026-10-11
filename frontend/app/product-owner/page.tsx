import Link from "next/link";

import { EmptyState, ErrorPanel, Pill } from "@/components/primitives";
import { getPoEstate, type PoEstate } from "@/lib/po-console";

export const dynamic = "force-dynamic";

/**
 * The estate roll-up of the Product Owner tab (spec 35 §8.7, D-148).
 *
 * One row per repository, and each row is that repository's own tab read,
 * so the two pages cannot disagree. A repository with no manifest is listed
 * as declaring no process. Leaving it out would answer "which repositories
 * have a process" with only the ones that do.
 */

type Row = PoEstate["rows"][number];

function processTone(row: Row): "pass" | "critical" | "warn" | "muted" {
  if (row.manifest_state === "valid") return "pass";
  if (row.manifest_state === "invalid") return "critical";
  if (row.manifest_state === "unreadable") return "warn";
  return "muted";
}

function cell(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : String(value);
}

export default async function ProductOwnerEstatePage() {
  const result = await getPoEstate();
  if (!result.ok) {
    return <ErrorPanel title="Product Owner estate unavailable" detail={result.error} />;
  }
  const { rows, totals } = result.data;
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold tracking-tight">Product Owner · estate</h1>
        <p className="max-w-prose text-[12px] text-ink-2">
          Every onboarded repository&rsquo;s declared process and sprint, read from its own{" "}
          <span className="font-mono">.sdlc/process.yaml</span> and from TheHub. Each row is
          that repository&rsquo;s Product Owner tab; open it for the detail.
        </p>
      </div>
      {rows.length === 0 ? (
        <EmptyState title="No repositories" detail="No repository is onboarded and active." />
      ) : (
        <div className="overflow-x-auto border border-rule bg-paper-2">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-rule text-left font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                <th className="px-3 py-2">Repository</th>
                <th className="px-3 py-2">Process</th>
                <th className="px-3 py-2 text-right">Sprint done / committed</th>
                <th className="px-3 py-2 text-right">Needs a human</th>
                <th className="px-3 py-2">Risk decision</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.repo_id} className="border-b border-rule-soft">
                  <td className="px-3 py-1.5">
                    <Link href={row.link} className="font-mono text-ink hover:text-accent">
                      {row.repo_full_name}
                    </Link>
                  </td>
                  <td className="px-3 py-1.5">
                    <Pill tone={processTone(row)} title={row.error ?? undefined}>
                      {row.process}
                    </Pill>
                    {row.manifest_name ? (
                      <span className="ml-2 font-mono text-[11px] text-ink-3">
                        {row.manifest_name}
                      </span>
                    ) : null}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono tabular">
                    {row.hub_connected ? (
                      `${cell(row.sprint_done)} / ${cell(row.sprint_committed)}`
                    ) : (
                      <span className="text-ink-3" title={row.error ?? undefined}>
                        TheHub not read
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 text-right font-mono tabular">
                    {cell(row.needs_human)}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px]">
                    {row.oracle_recommendation ? (
                      <span
                        className={
                          row.oracle_recommendation === "no_go" ? "text-critical" : "text-ink-2"
                        }
                      >
                        {row.oracle_recommendation}
                        {row.oracle_score !== null ? ` · ${row.oracle_score}` : ""}
                      </span>
                    ) : (
                      <span className="text-ink-3">none recorded</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
            <tfoot>
              <tr className="font-mono text-[12px] font-bold text-ink">
                <td className="px-3 py-2">{totals.repos} repositories</td>
                <td className="px-3 py-2 text-[11px] font-normal text-ink-2">
                  {totals.declared} declared · {totals.declares_no_process} declare no process
                  {totals.invalid_or_unreadable
                    ? ` · ${totals.invalid_or_unreadable} invalid or unreadable`
                    : ""}
                </td>
                <td className="px-3 py-2 text-right tabular">
                  {totals.sprint_done} / {totals.sprint_committed}
                </td>
                <td className="px-3 py-2 text-right tabular">{totals.needs_human}</td>
                <td className="px-3 py-2 text-[11px] font-normal text-ink-3">
                  {totals.rows_without_hub
                    ? `${totals.rows_without_hub} row(s) without TheHub, not counted`
                    : "sum of the rows"}
                </td>
              </tr>
            </tfoot>
          </table>
        </div>
      )}
    </div>
  );
}
