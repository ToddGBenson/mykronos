import { EmptyState, Pill, Section } from "@/components/primitives";
import type { RepoSuppressions, SuppressionRow } from "@/lib/api";

/**
 * Results this repository silenced at the source (TheHub #60963, decision
 * 60815 option B): `nosemgrep`, `checkov:skip`, any SARIF suppression. They
 * are not findings (spec 05 §7) and are never scored; this lists them so an
 * answer the author wrote into the code is visible, with its reason and how
 * long it was meant to last.
 */
export function ScannerSuppressions({ data }: { data: RepoSuppressions }) {
  const { suppressions, lane_health: laneHealth, counts } = data;

  return (
    <Section
      title="Suppressed in the repository"
      detail={
        suppressions.length
          ? `${suppressions.length} · ${counts?.expired ?? 0} expired · ${counts?.no_expiry ?? 0} with no expiry`
          : "none reported"
      }
    >
      {laneHealth.length ? (
        <ul className="border-b border-rule px-3 py-2 text-[13px] text-high">
          {laneHealth.map((fact) => (
            <li key={fact}>{fact}</li>
          ))}
        </ul>
      ) : null}
      {suppressions.length === 0 ? (
        <div className="p-3">
          <EmptyState
            title="No in-repo suppressions"
            detail="No scanner reported a result silenced at the source on its last clean scan."
          />
        </div>
      ) : (
        <div className="scroll-x px-3 py-2">
          <table className="w-full text-[13px]">
            <thead>
              <tr className="border-b border-rule text-left font-mono text-[11px] uppercase tracking-[0.08em] text-ink-3">
                <th className="py-1 pr-3 font-normal">Repo</th>
                <th className="py-1 pr-3 font-normal">Tool</th>
                <th className="py-1 pr-3 font-normal">Rule</th>
                <th className="py-1 pr-3 font-normal">File</th>
                <th className="py-1 pr-3 text-right font-normal">Line</th>
                <th className="py-1 pr-3 font-normal">Justification</th>
                <th className="py-1 font-normal">Expiry</th>
              </tr>
            </thead>
            <tbody>
              {suppressions.map((row, index) => (
                <tr
                  key={`${row.tool}:${row.branch}:${row.rule_id}:${row.file_path ?? ""}:${row.line ?? ""}:${index}`}
                  className="border-b border-rule-soft align-top"
                >
                  <td className="py-1 pr-3 whitespace-nowrap">{row.repo_full_name}</td>
                  <td className="py-1 pr-3 whitespace-nowrap">
                    {row.tool}
                    {row.branch ? (
                      <span className="block text-[12px] text-ink-3">{row.branch}</span>
                    ) : null}
                  </td>
                  <td className="py-1 pr-3 font-mono text-[12px] break-all">{row.rule_id}</td>
                  <td className="py-1 pr-3 font-mono text-[12px] break-all">
                    {row.file_path ?? "—"}
                  </td>
                  <td className="tabular py-1 pr-3 text-right">{row.line ?? "—"}</td>
                  <td className="py-1 pr-3">
                    {row.justification || <span className="text-ink-3">none given</span>}
                  </td>
                  <td className="py-1 whitespace-nowrap">
                    <Expiry row={row} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

function Expiry({ row }: { row: SuppressionRow }) {
  if (row.expiry_state === "no_expiry") {
    return (
      <Pill tone="warn" title="The suppression declares no expiry, so it silences the result indefinitely.">
        no expiry
      </Pill>
    );
  }
  if (row.expiry_state === "expired") {
    return (
      <Pill tone="critical" title="The declared expiry has passed; the pragma still silences the result.">
        expired {row.expires_at}
      </Pill>
    );
  }
  return <span>{row.expires_at}</span>;
}
